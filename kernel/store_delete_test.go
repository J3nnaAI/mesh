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
	"testing"
)

// The kernel's foundational contract: durable knowledge never decays — it is
// retired only by a provenanced Tombstone, never destroyed. DeleteNode enforces
// this at the one sink every Store funnels through. Operational/observability
// records (Ephemeral) are the sole exception.
func TestDeleteNode_EnforcesDurableInvariant(t *testing.T) {
	m := NewMemStore()

	// A durable proposition cannot be hard-deleted.
	if err := m.PutNode(Node{ID: "p1", Kind: KindProposition, Body: "Amber is my wife.", Base: 1}); err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteNode("p1"); !errors.Is(err, ErrDurableDelete) {
		t.Fatalf("durable delete: want ErrDurableDelete, got %v", err)
	}
	if _, ok := m.GetNode("p1"); !ok {
		t.Fatal("durable knowledge must survive a refused hard-delete")
	}

	// A tombstoned node is still durable knowledge (kept, queryable) — also undeletable.
	n, _ := m.GetNode("p1")
	ts := Tombstone{Authority: "test", Reason: "superseded"}
	n.Tombstone = &ts
	if err := m.PutNode(n); err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteNode("p1"); !errors.Is(err, ErrDurableDelete) {
		t.Fatalf("tombstoned-but-durable delete: want ErrDurableDelete, got %v", err)
	}

	// An explicitly-ephemeral operational record CAN be hard-deleted.
	if err := m.PutNode(Node{ID: "e1", Kind: KindEntity, Ephemeral: true, Label: "job:x"}); err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteNode("e1"); err != nil {
		t.Fatalf("ephemeral delete: want nil, got %v", err)
	}
	if _, ok := m.GetNode("e1"); ok {
		t.Fatal("ephemeral node must be hard-deleted")
	}

	// Deleting a missing node is an idempotent no-op.
	if err := m.DeleteNode("does-not-exist"); err != nil {
		t.Fatalf("missing delete: want nil, got %v", err)
	}
}
