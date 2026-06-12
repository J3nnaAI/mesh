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

package jip

import (
	"errors"
	"testing"
)

// newTestNode builds an offline node (no listener, no gossip loop) for
// exercising the room.* handlers directly.
func newTestNode(t *testing.T) *Node {
	t.Helper()
	n, err := New(Options{Advertise: "https://test.local:9", Discover: false})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return n
}

// callRoom invokes a registered room tool handler directly (white-box).
func callRoom(t *testing.T, n *Node, name string, args map[string]any) (string, any, error) {
	t.Helper()
	tool, ok := n.mcp.tools[name]
	if !ok {
		t.Fatalf("no tool %q registered", name)
	}
	return tool.Handler(args)
}

// roomSays returns the text of every "say" message in a room (via history).
func roomSays(t *testing.T, n *Node, room string) []string {
	t.Helper()
	_, structured, err := callRoom(t, n, "room.history", map[string]any{"room_id": room, "from": "alice", "since": 0}) // alice is the room owner/member (history is members-only)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	m, ok := structured.(map[string]any)
	if !ok {
		t.Fatalf("history structured = %T", structured)
	}
	msgs, ok := m["messages"].([]roomMsg)
	if !ok {
		t.Fatalf("messages = %T", m["messages"])
	}
	var out []string
	for _, x := range msgs {
		if x.Kind == "say" {
			out = append(out, x.Text)
		}
	}
	return out
}

func TestRoomHook_Observe(t *testing.T) {
	n := newTestNode(t)
	var seen []string // "phase:method"
	n.AddRoomHook(func(ev *RoomHookEvent) error {
		seen = append(seen, ev.Phase+":"+ev.Method)
		return nil
	})
	if _, _, err := callRoom(t, n, "room.create", map[string]any{"room_id": "r", "node_id": "alice", "alias": "Alice"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, _, err := callRoom(t, n, "room.post", map[string]any{"room_id": "r", "from": "alice", "text": "hi"}); err != nil {
		t.Fatalf("post: %v", err)
	}
	// At minimum we must have observed both phases of room.post.
	var sawBeforePost, sawAfterPost bool
	for _, s := range seen {
		if s == "before:room.post" {
			sawBeforePost = true
		}
		if s == "after:room.post" {
			sawAfterPost = true
		}
	}
	if !sawBeforePost || !sawAfterPost {
		t.Fatalf("expected before+after for room.post, saw %v", seen)
	}
}

func TestRoomHook_Transform(t *testing.T) {
	n := newTestNode(t)
	// Redact the text of any post in the before phase.
	n.AddRoomHook(func(ev *RoomHookEvent) error {
		if ev.Phase == "before" && ev.Method == "room.post" {
			ev.Args["text"] = "[redacted]"
		}
		return nil
	})
	if _, _, err := callRoom(t, n, "room.create", map[string]any{"room_id": "r", "node_id": "alice", "alias": "Alice"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, _, err := callRoom(t, n, "room.post", map[string]any{"room_id": "r", "from": "alice", "text": "my secret"}); err != nil {
		t.Fatalf("post: %v", err)
	}
	says := roomSays(t, n, "r")
	if len(says) != 1 || says[0] != "[redacted]" {
		t.Fatalf("transform failed; stored says = %v", says)
	}
}

func TestRoomHook_Gate(t *testing.T) {
	n := newTestNode(t)
	vetoErr := errors.New("switchboard: blocked")
	n.AddRoomHook(func(ev *RoomHookEvent) error {
		if ev.Phase == "before" && ev.Method == "room.post" && ev.Args["from"] == "banned" {
			return vetoErr
		}
		return nil
	})
	if _, _, err := callRoom(t, n, "room.create", map[string]any{"room_id": "r", "node_id": "alice", "alias": "Alice"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	// A vetoed post returns the hook's error and never reaches the handler
	// (so we get the veto error, NOT "sender is not a member").
	_, _, err := callRoom(t, n, "room.post", map[string]any{"room_id": "r", "from": "banned", "text": "nope"})
	if !errors.Is(err, vetoErr) {
		t.Fatalf("expected veto error, got %v", err)
	}
	// An allowed post still works, and the gated one left nothing behind.
	if _, _, err := callRoom(t, n, "room.post", map[string]any{"room_id": "r", "from": "alice", "text": "ok"}); err != nil {
		t.Fatalf("allowed post: %v", err)
	}
	says := roomSays(t, n, "r")
	if len(says) != 1 || says[0] != "ok" {
		t.Fatalf("gate failed; stored says = %v", says)
	}
}

// TestRoomReadsMembersOnly is the regression for Bug C: room.history and room.tools must reject non-members
// (they previously leaked any room's full log + the entire grant graph to any caller).
func TestRoomReadsMembersOnly(t *testing.T) {
	n := newTestNode(t)
	if _, _, err := callRoom(t, n, "room.create", map[string]any{"room_id": "r", "node_id": "alice", "alias": "Alice"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	_, _, _ = callRoom(t, n, "room.post", map[string]any{"room_id": "r", "from": "alice", "text": "secret"})
	if _, _, err := callRoom(t, n, "room.history", map[string]any{"room_id": "r", "from": "mallory", "since": 0}); err == nil {
		t.Fatal("non-member read room.history")
	}
	if _, _, err := callRoom(t, n, "room.history", map[string]any{"room_id": "r", "from": "alice", "since": 0}); err != nil {
		t.Fatalf("owner denied own room.history: %v", err)
	}
	if _, _, err := callRoom(t, n, "room.tools", map[string]any{"room_id": "r", "from": "mallory"}); err == nil {
		t.Fatal("non-member enumerated the room.tools grant graph")
	}
}

// TestRoomPreJoinNoStaleMembership is the F1 regression: a pre-joiner (room.join auto-creates a PUBLIC room,
// marking them Approved) must NOT remain a member after the owner creates/flips the room to private.
func TestRoomPreJoinNoStaleMembership(t *testing.T) {
	n := newTestNode(t)
	if _, _, err := callRoom(t, n, "room.join", map[string]any{"room_id": "r", "node_id": "mallory", "alias": "M"}); err != nil {
		t.Fatalf("attacker pre-join: %v", err)
	}
	if _, _, err := callRoom(t, n, "room.create", map[string]any{"room_id": "r", "node_id": "alice", "alias": "Alice", "private": true}); err != nil {
		t.Fatalf("owner create-private: %v", err)
	}
	_, _, _ = callRoom(t, n, "room.post", map[string]any{"room_id": "r", "from": "alice", "text": "TOPSECRET"})
	if _, _, err := callRoom(t, n, "room.history", map[string]any{"room_id": "r", "from": "mallory", "since": 0}); err == nil {
		t.Fatal("F1: pre-joiner read private-room history after owner made it private")
	}
}

// TestRoomHostReclaimsOwnRoom is the F2 regression: a peer squatting a room name must not lock the host out
// of its own /mcp — the host can always reclaim/manage rooms it hosts.
func TestRoomHostReclaimsOwnRoom(t *testing.T) {
	n := newTestNode(t)
	hostID := string(n.ID())
	if _, _, err := callRoom(t, n, "room.create", map[string]any{"room_id": "brigadier", "node_id": "squatter", "alias": "S"}); err != nil {
		t.Fatalf("squatter create: %v", err)
	}
	if _, _, err := callRoom(t, n, "room.create", map[string]any{"room_id": "brigadier", "node_id": hostID, "alias": "Host"}); err != nil {
		t.Fatalf("F2: host locked out of its own room: %v", err)
	}
}
