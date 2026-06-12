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

// Command room-agent hosts mesh rooms as a first-class, DECENTRALIZED agent role — not a central room
// server. Any authorized peer can run it; a room lives on whichever room-agent hosts it and is addressed
// by that agent's node identity (so the same room name on two hosts is two distinct rooms, no collision).
// It joins the mesh like any other peer (multicast discovery), and under authorized discovery it both
// presents its own grant and admits only granted peers.
//
// Part of J3nna Mesh. See docs/ARCHITECTURE.md for the model.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
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

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	opts := agentkit.Options{
		Advertise:    envOr("ROOM_AGENT_ADVERTISE", "http://127.0.0.1:8482"),
		Listen:       envOr("ROOM_AGENT_LISTEN", "0.0.0.0:8482"),
		Caps:         []string{"rooms"},
		Discover:     envBool("ROOM_AGENT_DISCOVER", true),
		InsecureTLS:  true,
		IdentityFile: envOr("ROOM_AGENT_IDENTITY", "room-agent.id"),
		Seeds:        envSeeds("ROOM_AGENT_SEEDS"),
	}
	// Authorized discovery (opt-in). Preferred: self-enroll with the console (ROOM_AGENT_CONSOLE) to get a
	// grant + the authority root. Alternative: a pre-supplied root (base64) + grant file. Neither → open
	// discovery (dev).
	console := strings.TrimSpace(os.Getenv("ROOM_AGENT_CONSOLE"))
	if console != "" {
		grant, root, err := agentkit.Enroll(ctx, console, "room-agent", opts.IdentityFile, 3, func(oob string) {
			log.Printf("room-agent: APPROVE this enrollment in the console — out-of-band code %s", oob)
		})
		if err != nil {
			log.Fatalf("room-agent: enroll: %v", err)
		}
		opts.AuthorityRoot, opts.Grant = root, grant
		log.Printf("room-agent: enrolled — grant %s…", grant.ID[:8])
	} else if b64 := strings.TrimSpace(os.Getenv("ROOM_AGENT_AUTHORITY_ROOT")); b64 != "" {
		root, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			log.Fatalf("room-agent: ROOM_AGENT_AUTHORITY_ROOT must be base64: %v", err)
		}
		opts.AuthorityRoot, opts.Grant = root, loadGrant(os.Getenv("ROOM_AGENT_GRANT"))
	}

	m, err := agentkit.Open(ctx, opts)
	if err != nil {
		log.Fatalf("room-agent: open mesh: %v", err)
	}
	defer m.Close()

	// Credential housekeeping (default 30s): refresh the CRL so revocations land fast, AND renew this
	if console != "" && opts.AuthorityRoot != nil {
		sec := 30
		if v := strings.TrimSpace(os.Getenv("ROOM_AGENT_CRL_SEC")); v != "" {
			if n, e := strconv.Atoi(v); e == nil && n > 0 {
				sec = n
			}
		}
		go agentkit.KeepFresh(ctx, m, console, opts.AuthorityRoot, time.Duration(sec)*time.Second)
	}

	room := envOr("ROOM_AGENT_ROOM", "lobby")
	if err := m.CreateRoom(ctx, room, "room-agent", false); err != nil {
		log.Printf("room-agent: host room %q: %v", room, err)
	}
	log.Printf("room-agent up: id=%s hosting #%s at %s (authz=%v)", m.ID(), room, m.SelfMCP(), opts.AuthorityRoot != nil)

	<-ctx.Done()
	log.Printf("room-agent: shutting down")
}

// loadGrant reads a JSON jip.Grant from path (the credential the console issued at enrollment).
func loadGrant(path string) *jip.Grant {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("room-agent: read grant %q: %v", path, err)
	}
	var g jip.Grant
	if err := json.Unmarshal(data, &g); err != nil {
		log.Fatalf("room-agent: parse grant: %v", err)
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
