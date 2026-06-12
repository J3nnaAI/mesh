// Copyright 2026 J3nna Technologies, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

package kernel

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Embedder turns text into a vector. The host supplies it (embeddings come from
// a model API, not from this module). It may be nil, in which case retrieval
// falls back to literal matching + graph spread.
type Embedder interface {
	Embed(ctx context.Context, text string) ([]float32, error)
}

// Mode selects a cognition profile. All four read the same graph; they differ
// in which edges conduct and how far activation spreads — recall and creativity
// are one engine at different defocus.
type Mode string

const (
	ModeVerbatim Mode = "verbatim" // exact recall of stored text; no generation, no spread
	ModeRelevant Mode = "relevant" // associative recall: seed + tight spread
	ModeThematic Mode = "thematic" // generalizations: prefer concept/theme nodes
	ModeCreative Mode = "creative" // wide defocus: distant/analogical bridges
)

// Options configures an Engine.
type Options struct {
	Store    Store            // default: NewMemStore()
	Embedder Embedder         // optional; enables semantic seeding
	Now      func() time.Time // injectable clock; default time.Now
	Decay    float64          // activation decay per turn (default 0.85)
	// OwnerScope, if set, makes scope isolation KERNEL-ENFORCED on write: this engine may only write,
	// tombstone, or delete within this one scope; a write carrying a foreign scope is REJECTED (not just
	// hidden at read time). A persona opens its engine scoped to itself, so a bug or a compromised caller
	// can never poison or retire another tenant's memory. The shared/global KB uses an unscoped engine.
	OwnerScope Scope
}

// Engine is the living-memory engine. Safe for concurrent use.
type Engine struct {
	store Store
	emb   Embedder
	now   func() time.Time
	decay float64

	act *register // transient activation (working memory); decays, never persisted

	ownerScope Scope // if non-empty, the ONLY scope this engine may write/tombstone/delete (isolation)
}

// scopeOK reports whether a write/retire of the given scope is allowed for this engine. An unscoped engine
// (no OwnerScope) permits any scope (the global/authority engine); a scoped engine permits only its own.
func (e *Engine) scopeOK(s Scope) bool { return e.ownerScope.Kind == "" || s.Equal(e.ownerScope) }

// Open constructs an Engine.
func Open(o Options) *Engine {
	if o.Store == nil {
		o.Store = NewMemStore()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Decay <= 0 || o.Decay >= 1 {
		o.Decay = 0.85
	}
	return &Engine{store: o.Store, emb: o.Embedder, now: o.Now, decay: o.Decay, act: newRegister(), ownerScope: o.OwnerScope}
}

// Store exposes the underlying store (for snapshot/load and inspection).
func (e *Engine) Store() Store { return e.store }

// ─────────────────────────── ingest (write) ──────────────────────────────

// AddNode writes a node, assigning an ID and timestamps if unset. Returns the
// stored node (with ID populated).
func (e *Engine) AddNode(n Node) (Node, error) {
	now := e.now()
	if n.ID == "" {
		n.ID = newID("n")
	}
	if n.Scope.Kind == "" {
		if e.ownerScope.Kind != "" {
			n.Scope = e.ownerScope
		} else {
			n.Scope = GlobalScope
		}
	}
	if !e.scopeOK(n.Scope) {
		return Node{}, fmt.Errorf("kernel: scope-isolated engine (%s:%s) refuses write to foreign scope (%s:%s)", e.ownerScope.Kind, e.ownerScope.ID, n.Scope.Kind, n.Scope.ID)
	}
	// Also enforce on the STORED node (parity with Tombstone/DeleteNode): a scoped engine must not OVERWRITE
	// an existing node of the same ID that lives in a foreign scope — same-ID overwrite was the one write
	// path that read only the declared scope.
	if e.ownerScope.Kind != "" {
		if existing, ok := e.store.GetNode(n.ID); ok && !e.scopeOK(existing.Scope) {
			return Node{}, fmt.Errorf("kernel: scope-isolated engine refuses to overwrite a foreign-scope node (id %s)", n.ID)
		}
	}
	if n.Temporal.IngestedAt.IsZero() {
		n.Temporal.IngestedAt = now
	}
	if n.Temporal.ValidFrom.IsZero() {
		n.Temporal.ValidFrom = now
	}
	if n.Prov.At.IsZero() {
		n.Prov.At = now
	}
	return n, e.store.PutNode(n)
}

// AddEdge writes a typed relation, assigning an ID and timestamps if unset.
func (e *Engine) AddEdge(ed Edge) (Edge, error) {
	now := e.now()
	if ed.ID == "" {
		ed.ID = newID("e")
	}
	if ed.Scope.Kind == "" {
		if e.ownerScope.Kind != "" {
			ed.Scope = e.ownerScope
		} else {
			ed.Scope = GlobalScope
		}
	}
	if !e.scopeOK(ed.Scope) {
		return Edge{}, fmt.Errorf("kernel: scope-isolated engine refuses edge write to foreign scope (%s:%s)", ed.Scope.Kind, ed.Scope.ID)
	}
	if ed.Weight == 0 {
		ed.Weight = 0.5
	}
	if ed.Temporal.IngestedAt.IsZero() {
		ed.Temporal.IngestedAt = now
	}
	if ed.Temporal.ValidFrom.IsZero() {
		ed.Temporal.ValidFrom = now
	}
	if ed.Prov.At.IsZero() {
		ed.Prov.At = now
	}
	return ed, e.store.PutEdge(ed)
}

// IngestEpisode stores a turn/message verbatim as an Episode node — the
// non-lossy record retrieval can return exactly.
func (e *Engine) IngestEpisode(text string, scope Scope, vec []float32) (Node, error) {
	return e.AddNode(Node{
		Kind:      KindEpisode,
		Label:     truncate(text, 80),
		Body:      text,
		Scope:     scope,
		Embedding: vec,
		Base:      0.2,
		Prov:      Provenance{Source: "turn", Confidence: 1},
	})
}

// Tombstone retires a node by id — explicit-first: cheap, deterministic, and
// high-confidence. The fact is retained (ValidTo set, Tombstone recorded), so
// the graveyard stays queryable. Pass the superseding id (if any) in ts.
func (e *Engine) Tombstone(nodeID string, ts Tombstone) error {
	n, ok := e.store.GetNode(nodeID)
	if !ok {
		return errNotFound
	}
	if !e.scopeOK(n.Scope) {
		return fmt.Errorf("kernel: scope-isolated engine refuses to tombstone a foreign-scope node")
	}
	now := e.now()
	if ts.At.IsZero() {
		ts.At = now
	}
	n.Tombstone = &ts
	vt := now
	n.Temporal.ValidTo = &vt
	return e.store.PutNode(n)
}

// DeleteNode HARD-removes a node — for EPHEMERAL/observability data (trace records)
// only. Durable knowledge uses Tombstone (provenanced, queryable graveyard).
func (e *Engine) DeleteNode(id string) error {
	if e.ownerScope.Kind != "" {
		if n, ok := e.store.GetNode(id); ok && !e.scopeOK(n.Scope) {
			return fmt.Errorf("kernel: scope-isolated engine refuses to delete a foreign-scope node")
		}
	}
	return e.store.DeleteNode(id)
}

// ─────────────────────────── retrieve (read) ─────────────────────────────

// Query parameters for a single retrieval.
type Query struct {
	Mode    Mode
	Scope   Scope     // default GlobalScope
	Text    string    // natural-language cue
	Vector  []float32 // optional; if nil and an Embedder is set, Text is embedded
	Defocus float64   // 0..1 spread width override; <=0 uses the mode default
	K       int       // max hits; <=0 uses default
	At      time.Time // validity instant; zero uses now
}

// Hit is one surfaced node with its score and a human-readable reason — the
// provenance the inspector needs to make tuning legible.
type Hit struct {
	Node  Node
	Score float64
	Why   string
}

// Result of a retrieval.
type Result struct {
	Mode Mode
	Hits []Hit
}

// scoring weights (tunable; iterate behavior, not schema)
const (
	wSpread   = 1.0
	wBase     = 0.30
	wValue    = 0.20
	wRecency  = 0.15
	wPrime    = 0.05
	simThresh = 0.25
	litWeight = 0.50
	spreadAtt = 0.55
	scoreCut  = 0.20
	defaultK  = 12
)

// Retrieve runs activation for the query's mode and returns scored hits.
// It updates the activation register (priming carries to the next turn).
func (e *Engine) Retrieve(ctx context.Context, q Query) (Result, error) {
	at := q.At
	if at.IsZero() {
		at = e.now()
	}
	if q.Scope.Kind == "" {
		q.Scope = GlobalScope
	}
	if q.K <= 0 {
		q.K = defaultK
	}
	if q.Mode == "" {
		q.Mode = ModeRelevant
	}

	// Embed the cue if needed.
	if q.Vector == nil && q.Text != "" && e.emb != nil {
		if v, err := e.emb.Embed(ctx, q.Text); err == nil {
			q.Vector = v
		}
	}

	// Decay the working-memory register (attention fades; knowledge does not).
	e.act.decay(e.decay)

	mask := conductance(q.Mode)
	hops := hopsFor(q.Mode, q.Defocus)

	// Seed activation: semantic (cosine) + literal label/body match.
	seed := map[string]float64{}
	e.store.RangeNodes(func(n Node) bool {
		if !n.Live(at) || !n.Scope.InScope(q.Scope) {
			return true
		}
		s := 0.0
		if len(q.Vector) > 0 && len(n.Embedding) > 0 {
			if c := cosine(q.Vector, n.Embedding); c > simThresh {
				s = c
			}
		}
		if litMatch(q.Text, n) {
			if litWeight > s {
				s = litWeight
			}
		}
		// Thematic mode biases toward concept/theme nodes.
		if q.Mode == ModeThematic && n.Kind == KindConcept && s > 0 {
			s += 0.2
		}
		if s > 0 {
			seed[n.ID] = s
		}
		return true
	})

	// Spread activation over conducting edges, hop by hop.
	activation := map[string]float64{}
	for id, s := range seed {
		activation[id] += s
	}
	frontier := seed
	for h := 0; h < hops; h++ {
		next := map[string]float64{}
		for id, s := range frontier {
			e.spreadFrom(id, s, at, q.Scope, mask, next, activation)
		}
		frontier = next
		if len(frontier) == 0 {
			break
		}
	}

	// Score and collect live, in-scope nodes.
	hits := make([]Hit, 0, len(activation))
	for id, a := range activation {
		n, ok := e.store.GetNode(id)
		if !ok || !n.Live(at) {
			continue
		}
		rec := recency(n, at)
		prime := e.act.get(id)
		score := wSpread*a + wBase*n.Base + wValue*n.Value + wRecency*rec + wPrime*prime
		if score < scoreCut {
			continue
		}
		e.act.set(id, a) // prime for next turn
		hits = append(hits, Hit{Node: n, Score: score, Why: whyString(a, n.Base, rec, n.Kind)})
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].Score > hits[j].Score })
	if len(hits) > q.K {
		hits = hits[:q.K]
	}
	return Result{Mode: q.Mode, Hits: hits}, nil
}

// spreadFrom pushes activation s from node id across conducting edges in both
// directions (symmetric kinds flow either way; the mask gates kinds).
func (e *Engine) spreadFrom(id string, s float64, at time.Time, scope Scope, mask map[EdgeKind]bool, next, activation map[string]float64) {
	push := func(edge Edge, target string) {
		if !edge.Live(at) || !mask[edge.Kind] {
			return
		}
		t, ok := e.store.GetNode(target)
		if !ok || !t.Live(at) || !t.Scope.InScope(scope) {
			return
		}
		flow := s * edge.Weight * spreadAtt
		if flow < 0.02 {
			return
		}
		next[target] += flow
		activation[target] += flow
	}
	for _, edge := range e.store.EdgesFrom(id) {
		push(edge, edge.To)
	}
	for _, edge := range e.store.EdgesTo(id) {
		if symmetric(edge.Kind) {
			push(edge, edge.From)
		}
	}
}

// ─────────────────────────── snapshot / load ─────────────────────────────

// Snapshot serializes the whole graph.
func (e *Engine) Snapshot() ([]byte, error) { return e.store.Snapshot() }

// Load replaces the graph from a snapshot and clears working memory.
func (e *Engine) Load(data []byte) error {
	// SECURITY (fail-CLOSED): a scoped engine must not ingest a snapshot carrying foreign-scope nodes/edges —
	// an untrusted restore/fork/mesh-sync could otherwise inject cross-tenant or global poison that, being
	// durable, is IRREVERSIBLE. Validate in a THROWAWAY store first and replace the live graph ONLY on
	// success — a direct store.Load would have already swapped in the poison before we could reject it.
	if e.ownerScope.Kind != "" {
		tmp := NewMemStore()
		if err := tmp.Load(data); err != nil {
			return err
		}
		var bad string
		tmp.RangeNodes(func(n Node) bool {
			if !n.Scope.Equal(e.ownerScope) {
				bad = "node " + n.ID
				return false
			}
			return true
		})
		if bad == "" {
			tmp.RangeEdges(func(ed Edge) bool {
				if !ed.Scope.Equal(e.ownerScope) {
					bad = "edge " + ed.ID
					return false
				}
				return true
			})
		}
		if bad != "" {
			return fmt.Errorf("kernel: scope-isolated engine (%s:%s) refusing snapshot — it contains a foreign-scope element (%s); the live graph is unchanged", e.ownerScope.Kind, e.ownerScope.ID, bad)
		}
	}
	if err := e.store.Load(data); err != nil {
		return err
	}
	e.act = newRegister()
	return nil
}

// newID returns a short unique id with a kind prefix.
func newID(prefix string) string {
	var b [9]byte
	_, _ = rand.Read(b[:])
	return prefix + "_" + hex.EncodeToString(b[:])
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n]
}
