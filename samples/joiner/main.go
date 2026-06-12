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

// Command joiner is a minimal sample agent showing the full authorized-collaboration loop on the mesh:
//
//	enroll with the console  ->  receive a signed grant + the authority root
//	open the mesh authorized ->  multicast discovery, presenting our grant
//	find a 'rooms' peer       ->  the room agent, discovered (not hardcoded)
//	join its room + post      ->  collaborate, all authorized
//
// Run the console and a room-agent first, then this; approve the enrollment in the console (match the
// out-of-band code it prints). See docs/QUICKSTART.md for the full walkthrough.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/J3nnaAI/mesh/agentkit"
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

	console := envOr("SAMPLE_CONSOLE", "http://127.0.0.1:8455")
	name := envOr("SAMPLE_NAME", "sample-joiner")
	idFile := envOr("SAMPLE_IDENTITY", "sample.id")
	room := envOr("SAMPLE_ROOM", "lobby")

	log.Printf("joiner: enrolling with console %s …", console)
	grant, root, err := agentkit.Enroll(ctx, console, name, idFile, 1, func(oob string) {
		log.Printf("joiner: APPROVE this enrollment in the console — out-of-band code %s", oob)
	})
	if err != nil {
		log.Fatalf("joiner: enroll: %v", err)
	}
	log.Printf("joiner: enrolled — grant %s…", grant.ID[:8])

	m, err := agentkit.Open(ctx, agentkit.Options{
		Advertise: envOr("SAMPLE_ADVERTISE", "http://127.0.0.1:8486"),
		Listen:    envOr("SAMPLE_LISTEN", "0.0.0.0:8486"),
		Caps: []string{"sample"}, Discover: envBool("SAMPLE_DISCOVER", true), InsecureTLS: true,
		IdentityFile: idFile, AuthorityRoot: root, Grant: grant,
		Seeds:     envSeeds("SAMPLE_SEEDS"),
	})
	if err != nil {
		log.Fatalf("joiner: open mesh: %v", err)
	}
	defer m.Close()

	// Stay credentialed while we're on the mesh: refresh the CRL and renew our short-lived grant before
	// it expires. Without this an authorized peer silently drops out of discovery one grant-TTL after
	// enrolling. The console is touched only on this background tick, never on the hot path.
	go agentkit.KeepFresh(ctx, m, console, root, 30*time.Second)

	// Discover a room agent (a peer advertising "rooms") — never hardcoded.
	var hostMCP string
	for i := 0; i < 30 && hostMCP == ""; i++ {
		for _, p := range m.Peers() {
			for _, c := range p.Caps {
				if c == "rooms" {
					hostMCP = p.MCP
				}
			}
		}
		if hostMCP == "" {
			time.Sleep(time.Second)
		}
	}
	if hostMCP == "" {
		log.Fatalf("joiner: no authorized room agent discovered on the mesh")
	}
	log.Printf("joiner: discovered room agent at %s — joining #%s", hostMCP, room)

	if _, err := m.JoinRoom(ctx, hostMCP, room, name); err != nil {
		log.Fatalf("joiner: join room: %v", err)
	}
	if err := m.Post(ctx, hostMCP, room, "hello from "+name+" — authorized and present."); err != nil {
		log.Fatalf("joiner: post: %v", err)
	}
	msgs, _ := m.History(ctx, hostMCP, room, 0)
	log.Printf("joiner: #%s has %d message(s):", room, len(msgs))
	for _, mm := range msgs {
		if strings.TrimSpace(mm.Text) != "" {
			log.Printf("joiner:   %s: %s", short(mm.From), mm.Text)
		}
	}
	log.Printf("joiner: collaboration loop complete — staying on the mesh (Ctrl-C to exit)")
	<-ctx.Done()
}

func short(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
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
