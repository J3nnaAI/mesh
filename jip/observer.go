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
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"
)

// Event is one observed mesh operation — a single "touch". The mesh core emits an Event at every operation
// boundary (presence, admission, tool calls, room activity, gossip, grants); an Observer receives them. This
// is the full-telemetry surface: with an Observer set, every touch through the mesh is accountable. With no
// Observer, the core does nothing extra — telemetry is opt-in and zero-cost.
type Event struct {
	Ts      int64  `json:"ts"`                // unix milliseconds
	Node    string `json:"node,omitempty"`    // the node whose activity this is
	Kind    string `json:"kind"`              // see the Ev* constants
	Peer    string `json:"peer,omitempty"`    // the other party, if any
	Tool    string `json:"tool,omitempty"`    // tool name, for calls
	Room    string `json:"room,omitempty"`    // room id, for room activity
	Outcome string `json:"outcome,omitempty"` // ok | denied | error
	Detail  string `json:"detail,omitempty"`  // short human context
	Trace   string `json:"trace,omitempty"`   // W3C traceparent, propagated across hops
	Span    string `json:"span,omitempty"`    // this operation's span id
	DurMs   int64  `json:"dur_ms,omitempty"`  // duration, where meaningful
}

// Event kinds — stable identifiers a monitor or telemetry backend can switch on.
const (
	EvPresence = "presence" // a peer announced / refreshed presence
	EvAdmit    = "admit"    // a peer was admitted to the registry (authorized discovery)
	EvReject   = "reject"   // a peer's presence was rejected (no/invalid grant, revoked, …)
	EvCall     = "call"     // an inbound MCP tools/call was dispatched
	EvRoom     = "room"     // a room event (join, post, deliver, …)
	EvGossip   = "gossip"   // a gossip anti-entropy exchange
	EvGrant    = "grant"    // a grant was issued / renewed / revoked (console)
)

// Observer receives mesh events. Implementations MUST be non-blocking and safe for concurrent use: they sit
// on the hot path and the mesh never blocks, retries, or fails on telemetry. A slow or dead observer must
// drop events, never stall an operation.
type Observer interface {
	Observe(Event)
}

// emit sends e to o, tolerating a nil observer and stamping the timestamp. The single internal choke point
// the core calls; keeps the hot path a no-op when telemetry is off.
func emit(o Observer, e Event) {
	if o == nil {
		return
	}
	if e.Ts == 0 {
		e.Ts = time.Now().UnixMilli()
	}
	o.Observe(e)
}

// --- correlation ids (W3C Trace Context) ---

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// NewSpanID returns a fresh 64-bit span id (16 hex chars).
func NewSpanID() string { return randHex(8) }

// NewTraceparent returns a fresh W3C `traceparent` (version 00, sampled). Propagate this unchanged across
// peer hops so a telemetry backend can stitch a multi-hop operation into one trace.
func NewTraceparent() string { return "00-" + randHex(16) + "-" + randHex(8) + "-01" }

// --- reference HTTP observer ---

// NewHTTPObserver returns an Observer that POSTs each event as JSON to a collector URL (e.g. the mesh
// monitor). It is non-blocking: events queue on a buffered channel shipped by one background goroutine, and
// are dropped if the queue backs up — telemetry never stalls the mesh. Stdlib only. This is the reference
// emitter OSS ships; a fabric/enterprise build can supply its own Observer (OTLP, retention, accounting).
func NewHTTPObserver(url string) Observer {
	h := &httpObserver{ch: make(chan Event, 2048), url: url}
	go h.run()
	return h
}

type httpObserver struct {
	ch  chan Event
	url string
}

func (h *httpObserver) Observe(e Event) {
	if e.Ts == 0 {
		e.Ts = time.Now().UnixMilli()
	}
	select {
	case h.ch <- e:
	default: // queue full — drop rather than block the mesh
	}
}

func (h *httpObserver) run() {
	client := &http.Client{Timeout: 3 * time.Second}
	for e := range h.ch {
		b, err := json.Marshal(e)
		if err != nil {
			continue
		}
		req, err := http.NewRequest(http.MethodPost, h.url, bytes.NewReader(b))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		if resp, err := client.Do(req); err == nil {
			resp.Body.Close()
		}
	}
}
