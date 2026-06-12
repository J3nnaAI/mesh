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

// Package kernel is an embeddable living-memory engine: a typed, bi-temporal
// knowledge graph with spreading-activation retrieval at tunable defocus.
//
// The vocabulary here is the schema commitment. It is deliberately complete up
// front (all node kinds, edge kinds, scope, bi-temporal validity, tombstones,
// provenance) so behavior can be grown without migrating the shape.
//
// Design invariants:
//
//   - Knowledge never decays. Only transient *activation* (attention) decays;
//     the nodes/edges themselves persist and are removed from view only by an
//     explicit, provenanced *tombstone* (supersession or correction).
//   - Tombstoning is itself knowledge: a tombstone records why, by what, and on
//     whose authority. The graveyard stays queryable; nothing is hard-deleted.
//   - Scope rides on nodes and edges, so the same mechanism does relevance
//     isolation (persona / domain) and, later, access control.
//   - Embeddings seed activation; edges propagate it. The graph is the geometry
//     a "defocus" knob searches over.
package kernel

import "time"

// NodeKind is the type of a graph node. The set is closed and stable.
type NodeKind string

const (
	// KindEntity is a person, place, thing, or named referent (e.g. a person or city).
	KindEntity NodeKind = "entity"
	// KindProposition is an atomic claim (e.g. "water boils at 100C").
	KindProposition NodeKind = "proposition"
	// KindEpisode is a timestamped happening, stored verbatim and non-lossy
	// (a turn, a message, an incident, a commit).
	KindEpisode NodeKind = "episode"
	// KindConcept is an abstraction or theme — typically materialized by
	// consolidation (the slow clock), e.g. "this user favors directness".
	KindConcept NodeKind = "concept"
	// KindGoal is a problem or objective, first-class so the graph can reframe
	// problems, not only recall facts. Also the substrate for an agent's own
	// goals/intents (Namespace "self").
	KindGoal NodeKind = "goal"
	// KindState is a point-in-time disposition (mood, posture, energy,
	// preoccupation) carried in Attrs and made historical by the bi-temporal
	// validity window — the interiority layer's self-state. Namespace "self".
	KindState NodeKind = "state"

	// ── reasoning-workspace kinds (CHARTER §5) ──────────────────────────────
	// The deliberate-cognition loop writes its trace as these, so the graph is a
	// reasoning workspace, not only long-term memory. Namespace typically "work".
	KindClaim      NodeKind = "claim"      // an assertion under evaluation; confidence in Attrs
	KindStep       NodeKind = "step"       // one reasoning/plan step (justified, dependency-linked)
	KindHypothesis NodeKind = "hypothesis" // a candidate explanation under test
	KindQuestion   NodeKind = "question"   // an open question / unknown driving inquiry
	KindEvidence   NodeKind = "evidence"   // a grounded fact bearing on a claim/hypothesis (provenance critical)
	KindPlan       NodeKind = "plan"       // a plan / sub-plan; preconditions + effects in Attrs
)

// EdgeKind is the relation type. The kind determines which retrieval/creative
// moves are expressible; the optional Label carries the specific predicate
// (e.g. EdgeRelational + Label "spouse_of", EdgeTemporal + Label "before").
type EdgeKind string

const (
	EdgeIsA         EdgeKind = "is_a"          // taxonomy backbone
	EdgePartOf      EdgeKind = "part_of"       // mereology backbone
	EdgeInstanceOf  EdgeKind = "instance_of"   // instantiation
	EdgeRelational  EdgeKind = "relational"    // labelled relation (spouse_of, works_with)
	EdgeCauses      EdgeKind = "causes"        // causal
	EdgeEnables     EdgeKind = "enables"       // causal (weaker)
	EdgeContradicts EdgeKind = "contradicts"   // tension — enables contradiction-resolution
	EdgeAnalogousTo EdgeKind = "analogous_to"  // analogy — the creative/cross-domain bridge
	EdgeTemporal    EdgeKind = "temporal"      // before/during in Label
	EdgeCoOccurs    EdgeKind = "co_occurs"     // weak associative (Hebbian)
	EdgeServes      EdgeKind = "serves"        // serves a goal
	EdgeBlocks      EdgeKind = "blocks"        // blocks a goal
	EdgeReframesAs  EdgeKind = "reframes_as"   // goal/problem reframing
	EdgeSupersedes  EdgeKind = "supersedes"    // points at knowledge this one tombstoned
	EdgeFeelsAbout  EdgeKind = "feels_about"   // affective (valence/arousal in Attrs)

	// ── reasoning-workspace relations (CHARTER §5) ──
	EdgeDecomposes EdgeKind = "decomposes" // parent → sub-question / sub-goal / sub-step
	EdgeDependsOn  EdgeKind = "depends_on" // step → step it requires
	EdgeJustifies  EdgeKind = "justifies"  // evidence/step → claim it supports as reasoning
	EdgeSupports   EdgeKind = "supports"   // evidence → hypothesis (raises its fit)
	EdgeRefutes    EdgeKind = "refutes"    // evidence/claim → hypothesis/claim (lowers/contradicts)
	EdgeAnswers    EdgeKind = "answers"    // claim/evidence → question it resolves
)

// Scope isolates a node/edge to an owner. "global" is visible to all. Isolation is enforced on BOTH ends:
// at READ time every query filters by InScope, and at WRITE time an engine opened with Options.OwnerScope
// refuses to write, tombstone, or delete any node/edge outside that scope (a foreign-scope write is
// rejected, not merely hidden). So a bug or a compromised caller cannot poison or retire another tenant's
// memory — which, being durable, would be irreversible. The shared/global KB uses an unscoped engine.
type Scope struct {
	Kind string `json:"kind"`         // "global" | "user" | "persona" | "domain"
	ID   string `json:"id,omitempty"` // owner id; empty for global
}

// GlobalScope is the default, owner-less scope.
var GlobalScope = Scope{Kind: "global"}

// Equal reports whether two scopes name the same owner.
func (s Scope) Equal(o Scope) bool { return s.Kind == o.Kind && s.ID == o.ID }

// Temporal is the bi-temporal validity of a fact: when it was true in the
// world (ValidFrom/ValidTo) and when the system learned it (IngestedAt). A nil
// ValidTo means "still valid". Setting ValidTo is how a fact is retired without
// being forgotten.
type Temporal struct {
	ValidFrom  time.Time  `json:"valid_from"`
	ValidTo    *time.Time `json:"valid_to,omitempty"`
	IngestedAt time.Time  `json:"ingested_at"`
}

// Tombstone marks a node/edge as retired. It is first-class knowledge: the
// death of a fact records its cause, so "why did we stop believing X?" is
// answerable by traversal. An empty InvalidatedBy means an explicit deletion
// rather than a supersession.
type Tombstone struct {
	At            time.Time `json:"at"`
	Reason        string    `json:"reason,omitempty"`
	Authority     string    `json:"authority,omitempty"`      // who/what retired it
	InvalidatedBy string    `json:"invalidated_by,omitempty"` // id of the superseding node/edge
}

// Provenance records where a fact came from and how trusted it is. Authority
// supports enterprise supersession (the system-of-record outranks a wiki note).
type Provenance struct {
	Source     string    `json:"source,omitempty"`     // turn id, doc, "explicit-correction", system-of-record
	Authority  string    `json:"authority,omitempty"`  // asserting authority
	Confidence float64   `json:"confidence,omitempty"` // 0..1
	At         time.Time `json:"at"`
}

// Node is a unit of knowledge. Persisted strength fields (Base, Value) live
// here; the *transient* activation charge does not — it lives in the runtime
// activation register so the stored graph stays free of attention state.
type Node struct {
	ID        string            `json:"id"`
	Kind      NodeKind          `json:"kind"`
	Label     string            `json:"label"`          // short human-readable handle
	Body      string            `json:"body,omitempty"` // content; for episodes this is verbatim
	Scope     Scope             `json:"scope"`
	Namespace string            `json:"ns,omitempty"` // layer that wrote it: "mem"|"self"|"diary"|… — collision-proofing, orthogonal to Scope (the owner)
	Embedding []float32         `json:"embedding,omitempty"` // seeds activation; compared by cosine
	Base      float64           `json:"base"`                // base strength — long-term importance, frequency-built
	Value     float64           `json:"value"`               // value weight — learned from revealed feedback
	Temporal  Temporal          `json:"temporal"`
	Tombstone *Tombstone        `json:"tombstone,omitempty"`
	Prov      Provenance        `json:"prov"`
	Attrs     map[string]string `json:"attrs,omitempty"` // extensible (affect valence, etc.)
	// Ephemeral marks a disposable operational/observability record (a trace, a
	// scheduler job, a connector registration) that MAY be hard-deleted. Durable
	// knowledge leaves this false (the zero value) and can be retired ONLY by a
	// provenanced Tombstone — never destroyed. This is what makes the kernel's
	// stated contract ("knowledge never decays; only tombstones retire facts")
	// an enforced invariant rather than a convention. See MemStore.DeleteNode.
	Ephemeral bool `json:"ephemeral,omitempty"`
}

// Edge is a typed, weighted, scoped, bi-temporal relation between two nodes.
// Weight is the conductance used when spreading activation; the defocus knob
// decides which EdgeKinds are allowed to conduct at all.
type Edge struct {
	ID        string     `json:"id"`
	Kind      EdgeKind   `json:"kind"`
	Label     string     `json:"label,omitempty"` // predicate for relational/temporal kinds
	From      string     `json:"from"`            // source node id
	To        string     `json:"to"`              // target node id
	Weight    float64    `json:"weight"`          // 0..1 conductance
	Scope     Scope      `json:"scope"`
	Namespace string     `json:"ns,omitempty"` // layer that wrote it (see Node.Namespace)
	Temporal  Temporal   `json:"temporal"`
	Tombstone *Tombstone `json:"tombstone,omitempty"`
	Prov      Provenance `json:"prov"`
}

// Live reports whether the node is currently valid at instant t: not
// tombstoned, and within its temporal validity window.
func (n Node) Live(t time.Time) bool { return n.Tombstone == nil && n.Temporal.liveAt(t) }

// Live reports whether the edge is currently valid at instant t.
func (e Edge) Live(t time.Time) bool { return e.Tombstone == nil && e.Temporal.liveAt(t) }

func (tm Temporal) liveAt(t time.Time) bool {
	if !tm.ValidFrom.IsZero() && t.Before(tm.ValidFrom) {
		return false
	}
	if tm.ValidTo != nil && !t.Before(*tm.ValidTo) {
		return false
	}
	return true
}

// InScope reports whether a node/edge scope is visible to a query scope.
// Global is visible to everyone; otherwise kind+id must match exactly.
func (s Scope) InScope(q Scope) bool {
	if s.Kind == "" || s.Kind == "global" {
		return true
	}
	return s.Kind == q.Kind && s.ID == q.ID
}
