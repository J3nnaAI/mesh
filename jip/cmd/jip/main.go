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

// Command jip runs a standalone JIP node, or (in -mode agent) an
// intent-driven room participant. Built from the same module that
// archetyped embeds via jip.New — the binary is just a thin CLI over the
// library so behavior is identical whether embedded or standalone.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/J3nnaAI/mesh/jip"
)

func splitCSV(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

func main() {
	listen := flag.String("listen", ":9000", "HTTP listen address")
	advertise := flag.String("advertise", "", "Externally reachable URL; defaults to http://127.0.0.1<listen>")
	seeds := flag.String("seed", "", "Comma-separated bootstrap peer URLs")
	caps := flag.String("caps", "echo,clock", "Comma-separated capability labels to advertise")
	interval := flag.Duration("interval", 3*time.Second, "Gossip interval")
	ttl := flag.Duration("ttl", 30*time.Second, "Heartbeat TTL before a peer is expired")
	discover := flag.Bool("discover", true, "Enable UDP multicast peer discovery")
	group := flag.String("group", "239.42.42.42:9999", "Multicast group for discovery")
	beacon := flag.Duration("beacon", 5*time.Second, "Multicast ANNOUNCE cadence")
	restrict := flag.String("restrict", "", "Comma-separated capability names requiring an authorized caller")
	allow := flag.String("allow", "", "Comma-separated caller node UUIDs allowed to call restricted tools")
	supervisors := flag.String("supervisors", "", "Comma-separated node UUIDs that may boot members from any hosted room")
	mode := flag.String("mode", "node", "node | agent (intent-driven room participant)")
	agentHost := flag.String("host", "", "agent mode: room host base URL")
	agentRoom := flag.String("room", "lab", "agent mode: room id")
	agentID := flag.String("id", "jade-1", "agent mode: this participant's node id")
	agentAlias := flag.String("alias", "agent", "agent mode: display alias")
	agentSay := flag.String("say", "", "agent mode: seed a room_post intent with this text")
	agentListen := flag.Duration("listen-for", 4*time.Second, "agent mode: inbound listen duration")
	flag.Parse()

	if *mode == "agent" {
		if err := jip.RunAgent(jip.AgentConfig{
			Host: *agentHost, Room: *agentRoom, NodeID: jip.UUID(*agentID),
			Alias: *agentAlias, Say: *agentSay, ListenFor: *agentListen,
		}); err != nil {
			log.Fatalf("agent: %v", err)
		}
		return
	}

	adv := *advertise
	if adv == "" {
		h := *listen
		if strings.HasPrefix(h, ":") {
			h = "127.0.0.1" + h
		}
		adv = "http://" + h
	}

	node, err := jip.New(jip.Options{
		Advertise: adv, Caps: splitCSV(*caps), Seeds: splitCSV(*seeds),
		Interval: *interval, TTL: *ttl, Discover: *discover,
		MulticastGroup: *group, BeaconEvery: *beacon,
		Restrict: splitCSV(*restrict), Allow: splitCSV(*allow),
		Supervisors: splitCSV(*supervisors),
	})
	if err != nil {
		log.Fatalf("jip: %v", err)
	}

	mux := http.NewServeMux()
	node.RegisterHandlers(mux)
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	go func() {
		log.Printf("jip node %s listening on %s (advertise=%s)", node.ID(), *listen, adv)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("http: %v", err)
			cancel()
		}
	}()
	go func() {
		if err := node.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("jip run: %v", err)
		}
	}()
	<-ctx.Done()
	sh, c := context.WithTimeout(context.Background(), 3*time.Second)
	defer c()
	_ = srv.Shutdown(sh)
	log.Printf("jip node %s stopped", node.ID())
}
