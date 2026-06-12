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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestRoomPostFanOutInheritsTrace proves the telemetry fan-out: when a room.post carries an inbound
// traceparent, each dialed member's outbound room.deliver inherits that SAME trace — so a host's N
// deliveries stitch into the originating post's trace in the monitor. The plain administrative broadcasts
// (join, roster) carry no trace, confirming the propagation is scoped to the operation that triggered it.
func TestRoomPostFanOutInheritsTrace(t *testing.T) {
	type delivery struct{ kind, trace string }
	got := make(chan delivery, 16)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Params struct {
				Trace     string `json:"trace"`
				Arguments struct {
					Event struct {
						Kind string `json:"kind"`
					} `json:"event"`
				} `json:"arguments"`
			} `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		got <- delivery{req.Params.Arguments.Event.Kind, req.Params.Trace}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`))
	}))
	defer srv.Close()

	n := newTestNode(t)
	if _, _, err := callRoom(t, n, "room.create", map[string]any{"room_id": "r", "node_id": "alice", "alias": "Alice"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	// bob joins WITH a reachable endpoint → broadcastLocked dials him (room.deliver), the fan-out path.
	if _, _, err := callRoom(t, n, "room.join", map[string]any{"room_id": "r", "node_id": "bob", "alias": "Bob", "endpoint": srv.URL, "mcp_path": "/mcp"}); err != nil {
		t.Fatalf("join: %v", err)
	}

	const tp = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
	// room.post the way dispatch invokes a room.* tool: the inbound trace injected under argTraceKey.
	if _, _, err := callRoom(t, n, "room.post", map[string]any{"room_id": "r", "from": "alice", "text": "hi", argTraceKey: tp}); err != nil {
		t.Fatalf("post: %v", err)
	}

	// Collect deliveries to bob until we see the post's "say", asserting it carries the trace and that any
	// administrative broadcast collected along the way carries none.
	var sayTraces, otherTraces []string
	deadline := time.After(2 * time.Second)
	for done := false; !done; {
		select {
		case d := <-got:
			if d.kind == "say" {
				sayTraces = append(sayTraces, d.trace)
				done = true
			} else {
				otherTraces = append(otherTraces, d.trace)
			}
		case <-deadline:
			t.Fatal("timed out waiting for the post delivery to bob")
		}
	}
	if len(sayTraces) != 1 || sayTraces[0] != tp {
		t.Fatalf("post fan-out did not inherit the trace: say deliveries = %v, want one == %q", sayTraces, tp)
	}
	for _, tr := range otherTraces {
		if tr != "" {
			t.Fatalf("a plain administrative broadcast leaked a trace: %q (want empty)", tr)
		}
	}
}
