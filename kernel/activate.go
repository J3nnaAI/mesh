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
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"
)

var errNotFound = errors.New("kernel: node not found")

// register is the transient activation store — working memory. It decays every
// turn and is never persisted; this is the "attention" layer, distinct from the
// durable Base strength on a node.
type register struct {
	mu sync.Mutex
	m  map[string]float64
}

func newRegister() *register { return &register{m: map[string]float64{}} }

// decay multiplies every charge by f and evicts the faint ones.
func (r *register) decay(f float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, v := range r.m {
		nv := v * f
		if nv < 0.05 {
			delete(r.m, k)
		} else {
			r.m[k] = nv
		}
	}
}

func (r *register) get(id string) float64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.m[id]
}

// set keeps the stronger of the existing and new charge (priming reinforces).
func (r *register) set(id string, v float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v > r.m[id] {
		r.m[id] = v
	}
}

// conductance is the defocus mask: which edge kinds may carry activation in a
// given mode. Tight modes conduct only structural+associative edges; creative
// opens analogical, causal, and contradiction edges (the distant bridges).
func conductance(m Mode) map[EdgeKind]bool {
	base := map[EdgeKind]bool{
		EdgeIsA:        true,
		EdgePartOf:     true,
		EdgeInstanceOf: true,
		EdgeRelational: true,
		EdgeCoOccurs:   true,
	}
	switch m {
	case ModeVerbatim:
		return map[EdgeKind]bool{} // seed only; no spread, no drift
	case ModeThematic:
		base[EdgeServes] = true
	case ModeCreative:
		for _, k := range []EdgeKind{EdgeAnalogousTo, EdgeContradicts, EdgeCauses, EdgeEnables, EdgeReframesAs, EdgeServes} {
			base[k] = true
		}
	}
	return base
}

// hopsFor is how far activation spreads. An explicit Defocus (0..1) overrides
// the mode default, mapping to 0..4 hops.
func hopsFor(m Mode, defocus float64) int {
	if defocus > 0 {
		h := int(defocus*4 + 0.5)
		if h > 4 {
			h = 4
		}
		return h
	}
	switch m {
	case ModeVerbatim:
		return 0
	case ModeCreative:
		return 3
	default:
		return 1
	}
}

// symmetric reports whether a relation conducts activation in both directions.
func symmetric(k EdgeKind) bool {
	switch k {
	case EdgeRelational, EdgeCoOccurs, EdgeAnalogousTo, EdgeContradicts:
		return true
	}
	return false
}

// cosine similarity of two vectors; 0 if either is degenerate or mismatched.
func cosine(a, b []float32) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}
	var dot, na, nb float64
	for i := range a {
		x, y := float64(a[i]), float64(b[i])
		dot += x * y
		na += x * x
		nb += y * y
	}
	if na == 0 || nb == 0 {
		return 0
	}
	return dot / (math.Sqrt(na) * math.Sqrt(nb))
}

// litMatch reports a literal token overlap between the cue and a node's
// label/body — the cheap seed that catches non-embedded nodes.
func litMatch(text string, n Node) bool {
	q := significantTokens(text)
	if len(q) == 0 {
		return false
	}
	hay := significantTokens(n.Label + " " + n.Body)
	if len(hay) == 0 {
		return false
	}
	set := make(map[string]struct{}, len(hay))
	for _, w := range hay {
		set[w] = struct{}{}
	}
	for _, w := range q {
		if _, ok := set[w]; ok {
			return true
		}
	}
	return false
}

func significantTokens(s string) []string {
	fields := strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9')
	})
	out := fields[:0]
	for _, f := range fields {
		if len(f) >= 4 {
			out = append(out, f)
		}
	}
	return out
}

// recency is an exponential decay over ~30 days from ingest. Fresh episodes
// score higher; this is a relevance signal, not a forgetting mechanism.
func recency(n Node, at time.Time) float64 {
	if n.Temporal.IngestedAt.IsZero() {
		return 0
	}
	days := at.Sub(n.Temporal.IngestedAt).Hours() / 24
	if days < 0 {
		days = 0
	}
	return math.Exp(-days / 30)
}

// whyString is the inspector-facing reason a node surfaced.
func whyString(act, base, rec float64, kind NodeKind) string {
	return fmt.Sprintf("act %.2f · base %.2f · rec %.2f · %s", act, base, rec, kind)
}
