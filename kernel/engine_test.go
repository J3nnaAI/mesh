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
	"testing"
)

func has(hits []Hit, id string) bool {
	for _, h := range hits {
		if h.Node.ID == id {
			return true
		}
	}
	return false
}

// Exercises the walking-skeleton path: seed by literal match, spread one hop
// over a relational edge, honor the mode mask (verbatim = no spread), and have
// an explicit tombstone remove a node from view.
func TestRelevantSpreadAndModesAndTombstone(t *testing.T) {
	ctx := context.Background()
	e := Open(Options{})

	amber, _ := e.AddNode(Node{Kind: KindEntity, Label: "Amber"})
	// "spouse fact" shares no token with the cue "Amber" — it can only surface
	// by spreading across the edge, which is the point of the test.
	wife, _ := e.AddNode(Node{Kind: KindProposition, Label: "spouse fact", Body: "she is the spouse"})
	e.AddEdge(Edge{Kind: EdgeRelational, Label: "spouse_of", From: amber.ID, To: wife.ID, Weight: 0.9})

	// relevant: cue seeds Amber, activation spreads to the spouse proposition.
	r, err := e.Retrieve(ctx, Query{Mode: ModeRelevant, Text: "Amber"})
	if err != nil {
		t.Fatal(err)
	}
	if !has(r.Hits, amber.ID) {
		t.Fatalf("relevant: expected Amber to be seeded; hits=%v", r.Hits)
	}
	if !has(r.Hits, wife.ID) {
		t.Fatalf("relevant: expected spouse fact to surface via spread; hits=%v", r.Hits)
	}

	// verbatim: no spread — the un-cued spouse fact must NOT surface.
	r, _ = e.Retrieve(ctx, Query{Mode: ModeVerbatim, Text: "Amber"})
	if !has(r.Hits, amber.ID) {
		t.Fatalf("verbatim: expected Amber; hits=%v", r.Hits)
	}
	if has(r.Hits, wife.ID) {
		t.Fatalf("verbatim: spouse fact must not spread in verbatim mode; hits=%v", r.Hits)
	}

	// tombstone the spouse fact (explicit correction) — it leaves view but is
	// retained in the graph.
	if err := e.Tombstone(wife.ID, Tombstone{Reason: "test correction", Authority: "test"}); err != nil {
		t.Fatal(err)
	}
	r, _ = e.Retrieve(ctx, Query{Mode: ModeRelevant, Text: "Amber"})
	if has(r.Hits, wife.ID) {
		t.Fatalf("tombstoned node must not surface; hits=%v", r.Hits)
	}
	if n, ok := e.Store().GetNode(wife.ID); !ok || n.Tombstone == nil {
		t.Fatalf("tombstoned node must be retained with a tombstone record")
	}
}

func TestSnapshotRoundTrip(t *testing.T) {
	e := Open(Options{})
	a, _ := e.AddNode(Node{Kind: KindEntity, Label: "Cabin"})
	b, _ := e.AddNode(Node{Kind: KindEpisode, Label: "fishing", Body: "dad taught fishing"})
	e.AddEdge(Edge{Kind: EdgeRelational, From: a.ID, To: b.ID, Weight: 0.7})

	snap, err := e.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	e2 := Open(Options{})
	if err := e2.Load(snap); err != nil {
		t.Fatal(err)
	}
	if _, ok := e2.Store().GetNode(a.ID); !ok {
		t.Fatal("node lost across snapshot")
	}
	if len(e2.Store().EdgesFrom(a.ID)) != 1 {
		t.Fatal("edge/adjacency lost across snapshot")
	}
}
