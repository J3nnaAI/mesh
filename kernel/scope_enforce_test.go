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

import "testing"

// TestScopeWriteEnforcement proves scope isolation is enforced on WRITE, not just read: a scoped engine
// refuses to write, tombstone, or delete outside its own scope — so a bug or compromised caller can never
// poison or retire another tenant's memory (which, being durable, would be irreversible).
func TestScopeWriteEnforcement(t *testing.T) {
	mine := Scope{Kind: "persona", ID: "alice"}
	theirs := Scope{Kind: "persona", ID: "bob"}
	e := Open(Options{OwnerScope: mine})

	// own-scope write: allowed
	own, err := e.AddNode(Node{Kind: KindProposition, Body: "mine", Scope: mine})
	if err != nil {
		t.Fatalf("own-scope write must be allowed: %v", err)
	}
	// empty scope defaults to the owner scope (not global)
	def, err := e.AddNode(Node{Kind: KindProposition, Body: "defaulted"})
	if err != nil || !def.Scope.Equal(mine) {
		t.Fatalf("empty scope must default to owner; got scope=%v err=%v", def.Scope, err)
	}
	// foreign-scope write: REJECTED
	if _, err := e.AddNode(Node{Kind: KindProposition, Body: "poison", Scope: theirs}); err == nil {
		t.Fatal("foreign-scope write was allowed (cross-tenant poison)")
	}
	// global write through a scoped engine: REJECTED
	if _, err := e.AddNode(Node{Kind: KindProposition, Body: "global", Scope: GlobalScope}); err == nil {
		t.Fatal("global write through a persona-scoped engine was allowed")
	}
	// tombstone of own node: allowed; of a foreign node: rejected
	if err := e.Tombstone(own.ID, Tombstone{Reason: "ok"}); err != nil {
		t.Fatalf("tombstone of own node must be allowed: %v", err)
	}
	// plant a foreign node via an UNSCOPED engine sharing the same store, then prove the scoped one can't retire it
	shared := NewMemStore()
	authority := Open(Options{Store: shared})
	foreign, _ := authority.AddNode(Node{Kind: KindProposition, Body: "bob's", Scope: theirs})
	scoped := Open(Options{Store: shared, OwnerScope: mine})
	if err := scoped.Tombstone(foreign.ID, Tombstone{Reason: "attack"}); err == nil {
		t.Fatal("scoped engine tombstoned a foreign-scope node")
	}
	if err := scoped.DeleteNode(foreign.ID); err == nil {
		t.Fatal("scoped engine deleted a foreign-scope node")
	}
	// same-ID overwrite of a foreign-scope node must also be rejected (AddNode stored-scope parity)
	if _, err := scoped.AddNode(Node{ID: foreign.ID, Kind: KindProposition, Body: "overwrite", Scope: mine}); err == nil {
		t.Fatal("scoped engine overwrote a foreign-scope node of the same id")
	}

	// an UNSCOPED (authority) engine may write any scope — the shared/global KB path
	if _, err := authority.AddNode(Node{Kind: KindProposition, Body: "kb", Scope: GlobalScope}); err != nil {
		t.Fatalf("unscoped authority engine must allow global writes: %v", err)
	}
}

// TestScopeSnapshotValidation proves a scoped engine refuses a snapshot carrying foreign-scope data — the
// irreversible cross-tenant poison vector via restore/fork/mesh-sync.
func TestScopeSnapshotValidation(t *testing.T) {
	mine := Scope{Kind: "persona", ID: "alice"}
	theirs := Scope{Kind: "persona", ID: "bob"}

	clean := Open(Options{})
	clean.AddNode(Node{Kind: KindProposition, Body: "mine only", Scope: mine})
	cleanSnap, _ := clean.Snapshot()

	src := Open(Options{})
	src.AddNode(Node{Kind: KindProposition, Body: "mine", Scope: mine})
	src.AddNode(Node{Kind: KindProposition, Body: "bob's poison", Scope: theirs})
	poisoned, _ := src.Snapshot()

	// a LIVE scoped engine with known-good state
	live := Open(Options{OwnerScope: mine})
	if err := live.Load(cleanSnap); err != nil {
		t.Fatalf("clean own-scope snapshot must load: %v", err)
	}
	before := countNodes(live)
	if before == 0 {
		t.Fatal("clean snapshot loaded no nodes")
	}

	// a rejected poisoned load must be FAIL-CLOSED: the live store is unchanged (not swapped-then-rejected)
	if err := live.Load(poisoned); err == nil {
		t.Fatal("scoped engine loaded a snapshot containing foreign-scope nodes")
	}
	if after := countNodes(live); after != before {
		t.Fatalf("rejected load CHANGED the live store: %d -> %d (FAIL-OPEN)", before, after)
	}
	found := false
	live.Store().RangeNodes(func(n Node) bool {
		if n.Body == "mine only" {
			found = true
		}
		return true
	})
	if !found {
		t.Fatal("rejected load destroyed the original clean data")
	}
}

func countNodes(e *Engine) int {
	n := 0
	e.Store().RangeNodes(func(Node) bool { n++; return true })
	return n
}
