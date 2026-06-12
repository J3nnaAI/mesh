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
	"encoding/json"
	"errors"
	"sync"
)

// ErrDurableDelete is returned when a caller tries to hard-delete durable
// knowledge. Knowledge never decays — it is retired only by a provenanced
// Tombstone (which keeps the node, its history, and the reason for retirement).
// Only nodes explicitly marked Ephemeral (operational/observability records)
// may be destroyed. This makes the kernel's core contract enforceable at the
// one place every Store implementation funnels through.
var ErrDurableDelete = errors.New("kernel: refusing to hard-delete durable knowledge; retire it with Tombstone instead")

// Store is the persistence seam. The engine never assumes where the graph
// lives; this interface is the only contract. The default MemStore keeps the
// graph in memory with JSON snapshotting — small per-owner graphs fit in RAM,
// and it is WASM/gomobile-safe. A SQLite- or file-backed Store can be dropped
// in without touching engine logic.
//
// Implementations must be safe for concurrent use.
type Store interface {
	PutNode(n Node) error
	PutEdge(e Edge) error
	GetNode(id string) (Node, bool)
	GetEdge(id string) (Edge, bool)

	// DeleteNode HARD-removes a node and its incident edges. Knowledge is never
	// hard-deleted (use Tombstone); this is for EPHEMERAL/observability nodes
	// (e.g. trace records) where retention, not provenance, is the concern.
	DeleteNode(id string) error

	// EdgesFrom / EdgesTo return adjacency for spreading activation.
	EdgesFrom(nodeID string) []Edge
	EdgesTo(nodeID string) []Edge

	// Range iterates all nodes/edges (tombstoned included; callers filter).
	RangeNodes(fn func(Node) bool)
	RangeEdges(fn func(Edge) bool)

	// Snapshot / Load serialize the whole graph (for persistence + sync).
	Snapshot() ([]byte, error)
	Load(data []byte) error
}

// MemStore is the default in-memory Store with adjacency indexes and JSON
// snapshotting. Stdlib-only; no cgo; WASM-safe.
type MemStore struct {
	mu    sync.RWMutex
	nodes map[string]Node
	edges map[string]Edge
	out   map[string][]string // nodeID -> edge ids leaving it
	in    map[string][]string // nodeID -> edge ids entering it
}

// NewMemStore returns an empty in-memory store.
func NewMemStore() *MemStore {
	return &MemStore{
		nodes: map[string]Node{},
		edges: map[string]Edge{},
		out:   map[string][]string{},
		in:    map[string][]string{},
	}
}

func (m *MemStore) PutNode(n Node) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nodes[n.ID] = n
	return nil
}

// DeleteNode hard-removes a node and any edges incident to it.
func (m *MemStore) DeleteNode(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Enforce the kernel's foundational invariant: durable knowledge is never
	// destroyed, only tombstoned. Disposable operational records (Ephemeral)
	// are the sole exception. A missing node is a no-op (idempotent delete).
	if n, ok := m.nodes[id]; ok && !n.Ephemeral {
		return ErrDurableDelete
	}
	delete(m.nodes, id)
	for _, eid := range m.out[id] {
		delete(m.edges, eid)
	}
	for _, eid := range m.in[id] {
		delete(m.edges, eid)
	}
	delete(m.out, id)
	delete(m.in, id)
	return nil
}

func (m *MemStore) PutEdge(e Edge) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.edges[e.ID]; !exists {
		m.out[e.From] = append(m.out[e.From], e.ID)
		m.in[e.To] = append(m.in[e.To], e.ID)
	}
	m.edges[e.ID] = e
	return nil
}

func (m *MemStore) GetNode(id string) (Node, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n, ok := m.nodes[id]
	return n, ok
}

func (m *MemStore) GetEdge(id string) (Edge, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.edges[id]
	return e, ok
}

func (m *MemStore) EdgesFrom(nodeID string) []Edge {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ids := m.out[nodeID]
	out := make([]Edge, 0, len(ids))
	for _, id := range ids {
		if e, ok := m.edges[id]; ok {
			out = append(out, e)
		}
	}
	return out
}

func (m *MemStore) EdgesTo(nodeID string) []Edge {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ids := m.in[nodeID]
	out := make([]Edge, 0, len(ids))
	for _, id := range ids {
		if e, ok := m.edges[id]; ok {
			out = append(out, e)
		}
	}
	return out
}

func (m *MemStore) RangeNodes(fn func(Node) bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, n := range m.nodes {
		if !fn(n) {
			return
		}
	}
}

func (m *MemStore) RangeEdges(fn func(Edge) bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, e := range m.edges {
		if !fn(e) {
			return
		}
	}
}

// snapshot is the on-disk/on-wire shape.
type snapshot struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

func (m *MemStore) Snapshot() ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s := snapshot{
		Nodes: make([]Node, 0, len(m.nodes)),
		Edges: make([]Edge, 0, len(m.edges)),
	}
	for _, n := range m.nodes {
		s.Nodes = append(s.Nodes, n)
	}
	for _, e := range m.edges {
		s.Edges = append(s.Edges, e)
	}
	return json.Marshal(s)
}

func (m *MemStore) Load(data []byte) error {
	var s snapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nodes = make(map[string]Node, len(s.Nodes))
	m.edges = make(map[string]Edge, len(s.Edges))
	m.out = map[string][]string{}
	m.in = map[string][]string{}
	for _, n := range s.Nodes {
		m.nodes[n.ID] = n
	}
	for _, e := range s.Edges {
		m.edges[e.ID] = e
		m.out[e.From] = append(m.out[e.From], e.ID)
		m.in[e.To] = append(m.in[e.To], e.ID)
	}
	return nil
}
