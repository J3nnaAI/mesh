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

// Command room-view is a HUMAN front door to a mesh room. It is a small authorized peer that joins the
// mesh like any agent (multicast discovery), finds a room host, joins a room on a person's behalf, and
// serves a simple web chat UI so a human can read and post alongside agents — the dogfooding client that
// proves a person and agents share the same room over the same protocol. It hosts nothing; it joins.
//
// Part of J3nna Mesh. See docs/ARCHITECTURE.md for the model.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/J3nnaAI/mesh/agentkit"
	"github.com/J3nnaAI/mesh/jip"
)

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

// view holds the room-view's live join state, shared between the join loop and the HTTP handlers.
type view struct {
	mu      sync.RWMutex
	hostMCP string
	hostID  string
	joined  bool
	roster  agentkit.Roster
}

func (v *view) snapshot() (host, hostID string, joined bool, roster agentkit.Roster) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.hostMCP, v.hostID, v.joined, v.roster
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	room := envOr("ROOMVIEW_ROOM", "lobby")
	alias := envOr("ROOMVIEW_NAME", "guest")

	opts := agentkit.Options{
		Advertise:    envOr("ROOMVIEW_ADVERTISE", "http://127.0.0.1:8485"),
		Listen:       envOr("ROOMVIEW_LISTEN", "0.0.0.0:8485"),
		Caps:         []string{"human"},
		Discover:     envBool("ROOMVIEW_DISCOVER", true),
		InsecureTLS:  true,
		IdentityFile: envOr("ROOMVIEW_IDENTITY", "room-view.id"),
		Seeds:        envSeeds("ROOMVIEW_SEEDS"),
	}

	// Authorized discovery (opt-in). Preferred: self-enroll with the console (ROOMVIEW_CONSOLE). Else a
	// pre-supplied base64 root + grant file. Neither → open discovery (dev).
	console := strings.TrimSpace(os.Getenv("ROOMVIEW_CONSOLE"))
	if console != "" {
		grant, root, err := agentkit.Enroll(ctx, console, "room-view", opts.IdentityFile, 1, func(oob string) {
			log.Printf("room-view: APPROVE this enrollment in the console — out-of-band code %s", oob)
		})
		if err != nil {
			log.Fatalf("room-view: enroll: %v", err)
		}
		opts.AuthorityRoot, opts.Grant = root, grant
		log.Printf("room-view: enrolled — grant %s…", grant.ID[:8])
	} else if b64 := strings.TrimSpace(os.Getenv("ROOMVIEW_AUTHORITY_ROOT")); b64 != "" {
		root, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			log.Fatalf("room-view: ROOMVIEW_AUTHORITY_ROOT must be base64: %v", err)
		}
		opts.AuthorityRoot, opts.Grant = root, loadGrant(os.Getenv("ROOMVIEW_GRANT"))
	}

	m, err := agentkit.Open(ctx, opts)
	if err != nil {
		log.Fatalf("room-view: open mesh: %v", err)
	}
	defer m.Close()

	// Keep credentials fresh (CRL + grant renewal) so a person can stay in the room indefinitely.
	if console != "" && opts.AuthorityRoot != nil {
		go agentkit.KeepFresh(ctx, m, console, opts.AuthorityRoot, 30*time.Second)
	}

	v := &view{}
	// Join loop: discover a room host (a peer advertising "rooms"), join, and re-join if the host is lost.
	go func() {
		for ctx.Err() == nil {
			host, _, joined, _ := v.snapshot()
			if joined && hostStillPresent(m, host) {
				time.Sleep(2 * time.Second)
				continue
			}
			h, hid := discoverRoomHost(m)
			if h != "" {
				if roster, err := m.JoinRoom(ctx, h, room, alias); err == nil {
					v.mu.Lock()
					v.hostMCP, v.hostID, v.joined, v.roster = h, hid, true, roster
					v.mu.Unlock()
					log.Printf("room-view: joined #%s at %s as %q", room, h, alias)
				} else {
					log.Printf("room-view: join #%s failed: %v", room, err)
				}
			}
			time.Sleep(2 * time.Second)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	// Live state for the UI: who/where we are and the current roster.
	mux.HandleFunc("/api/state", func(w http.ResponseWriter, _ *http.Request) {
		host, hostID, joined, roster := v.snapshot()
		members := make([]map[string]string, 0, len(roster))
		for _, mem := range roster {
			members = append(members, map[string]string{"node_id": mem.NodeID, "alias": mem.Alias})
		}
		peers := make([]map[string]any, 0)
		for _, p := range m.Peers() {
			peers = append(peers, map[string]any{"id": p.ID, "caps": p.Caps})
		}
		writeJSON(w, map[string]any{
			"room": room, "alias": alias, "joined": joined,
			"host_mcp": host, "host_id": hostID, "self_id": m.ID(),
			"roster": members, "peers": peers,
		})
	})

	// Message history (seq > since).
	mux.HandleFunc("/api/messages", func(w http.ResponseWriter, r *http.Request) {
		host, _, joined, _ := v.snapshot()
		if !joined {
			writeJSON(w, map[string]any{"messages": []any{}, "joined": false})
			return
		}
		since := 0
		if s := strings.TrimSpace(r.URL.Query().Get("since")); s != "" {
			if n, e := strconv.Atoi(s); e == nil {
				since = n
			}
		}
		msgs, err := m.History(r.Context(), host, room, since)
		if err != nil {
			http.Error(w, "history: "+err.Error(), http.StatusBadGateway)
			return
		}
		writeJSON(w, map[string]any{"messages": msgs, "joined": true})
	})

	// Post a message as this person.
	mux.HandleFunc("/api/post", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		host, _, joined, _ := v.snapshot()
		if !joined {
			http.Error(w, "not in a room yet — still discovering a host", http.StatusServiceUnavailable)
			return
		}
		var b struct{ Text string }
		if json.NewDecoder(r.Body).Decode(&b) != nil || strings.TrimSpace(b.Text) == "" {
			http.Error(w, "text required", http.StatusBadRequest)
			return
		}
		if err := m.Post(r.Context(), host, room, b.Text); err != nil {
			http.Error(w, "post: "+err.Error(), http.StatusBadGateway)
			return
		}
		writeJSON(w, map[string]any{"posted": true})
	})

	if err := mountUI(mux); err != nil {
		log.Printf("room-view: UI not mounted: %v", err)
	}

	httpAddr := envOr("ROOMVIEW_HTTP", "127.0.0.1:8487")
	log.Printf("room-view up: id=%s — chat UI on http://%s (room #%s, authz=%v)", m.ID(), httpAddr, room, opts.AuthorityRoot != nil)
	srv := &http.Server{Addr: httpAddr, Handler: mux}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("room-view: serve: %v", err)
	}
}

// discoverRoomHost returns the MCP url + node id of a discovered peer advertising the "rooms" capability.
func discoverRoomHost(m *agentkit.Mesh) (mcp, id string) {
	for _, p := range m.Peers() {
		for _, c := range p.Caps {
			if c == "rooms" {
				return p.MCP, p.ID
			}
		}
	}
	return "", ""
}

// hostStillPresent reports whether the host we joined is still discoverable (so we re-join if it drops).
func hostStillPresent(m *agentkit.Mesh, hostMCP string) bool {
	for _, p := range m.Peers() {
		if p.MCP == hostMCP {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// loadGrant reads a grant JSON file (for the static, no-console path); returns nil on any failure.
func loadGrant(path string) *jip.Grant {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var g jip.Grant
	if json.Unmarshal(data, &g) != nil {
		return nil
	}
	return &g
}

// envSeeds parses a comma-separated list of bootstrap peer base URLs. On networks without UDP multicast
// (Docker bridges, Kubernetes pods) peers discover one another via these gossip seeds instead.
func envSeeds(k string) []string {
	var out []string
	for _, u := range strings.Split(os.Getenv(k), ",") {
		if u = strings.TrimSpace(u); u != "" {
			out = append(out, u)
		}
	}
	return out
}

// envBool reads a boolean env var (1/true/yes = true). Used to toggle multicast discovery off in cloud /
// Kubernetes environments where peers find each other via gossip seeds instead.
func envBool(k string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
}
