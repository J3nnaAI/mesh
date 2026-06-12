// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// kernel-service is the shared MEMORY for the order-fulfillment example: a mesh peer that embeds the J3nna
// kernel (a typed node+edge graph) and exposes it as `mem.*` tools. The three Python agents read, enrich,
// and EVOLVE this one graph through these tools — orders, items, customers, inventory, allocations, and the
// edges between them. `mem.allocate` is the load-bearing one: an ATOMIC check-then-decrement (a service-wide
// mutex serializes it) so concurrent fulfilment never oversells inventory — which is what makes the
// "inventory conserved" invariant hold. Part of the example; not core mesh surface.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/J3nnaAI/mesh/agentkit"
	"github.com/J3nnaAI/mesh/jip"
	"github.com/J3nnaAI/mesh/kernel"
)

// waitForDeps blocks until the console and every gossip seed (the room-agent) answer, so this service only
// goes live once its dependencies are up — it won't announce presence into a mesh that can't route to it.
func waitForDeps(ctx context.Context, label, console string, seeds []string) {
	probe := func(url string) bool {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			return false
		}
		r.Body.Close()
		return true
	}
	targets := map[string]string{"console": console + "/authority"}
	for i, s := range seeds {
		targets[fmt.Sprintf("seed%d", i)] = strings.TrimRight(s, "/") + "/whoami"
	}
	for name, url := range targets {
		for !probe(url) {
			log.Printf("%s: waiting for dependency %s (%s)…", label, name, url)
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
		}
	}
}

func env(k, d string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return d
}

func envSeeds(k string) []string {
	var out []string
	for _, u := range strings.Split(os.Getenv(k), ",") {
		if u = strings.TrimSpace(u); u != "" {
			out = append(out, u)
		}
	}
	return out
}

var (
	store = kernel.NewMemStore()
	mu    sync.Mutex // serializes mutating ops — makes allocate/restock check-then-write atomic
	scope = kernel.Scope{Kind: "domain", ID: "fulfillment"}
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	console := env("KSVC_CONSOLE", "http://127.0.0.1:18455")
	idFile := env("KSVC_IDENTITY", "ksvc.id")
	waitForDeps(ctx, "kernel-service", console, envSeeds("KSVC_SEEDS"))
	if seed := env("KSVC_SEED", ""); seed != "" {
		if c, err := loadSeed(seed); err != nil {
			log.Printf("kernel-service: seed %s: %v", seed, err)
		} else {
			log.Printf("kernel-service: preloaded %d nodes from %s", c, seed)
		}
	}
	log.Printf("kernel-service: enrolling with console %s …", console)
	grant, root, err := agentkit.Enroll(ctx, console, "kernel-service", idFile, 1, func(oob string) {
		log.Printf("kernel-service: APPROVE enrollment — out-of-band code %s", oob)
	})
	if err != nil {
		log.Fatalf("kernel-service: enroll: %v", err)
	}
	m, err := agentkit.Open(ctx, agentkit.Options{
		Advertise:     env("KSVC_ADVERTISE", "http://127.0.0.1:18490"),
		Listen:        env("KSVC_LISTEN", "127.0.0.1:18490"),
		Caps:          []string{"memory"},
		Seeds:         envSeeds("KSVC_SEEDS"),
		InsecureTLS:   true,
		IdentityFile:  idFile,
		AuthorityRoot: root,
		Grant:         grant,
	})
	if err != nil {
		log.Fatalf("kernel-service: open: %v", err)
	}
	defer m.Close()
	go agentkit.KeepFresh(ctx, m, console, root, 30*time.Second)
	registerTools(m.Node())
	log.Printf("kernel-service: live — mem.* tools serving the shared kernel graph (node %s…)", m.ID()[:8])
	<-ctx.Done()
}

func registerTools(n *jip.Node) {
	str := map[string]any{"type": "string"}
	num := map[string]any{"type": "number"}
	obj := func(props map[string]any, req ...string) map[string]any {
		return map[string]any{"type": "object", "properties": props, "required": req}
	}
	n.RegisterTool("mem.put", "Create or update a graph node {id, kind, label, body(JSON string)}.",
		obj(map[string]any{"id": str, "kind": str, "label": str, "body": str}, "id"), false, memPut)
	n.RegisterTool("mem.get", "Fetch a node by id.",
		obj(map[string]any{"id": str}, "id"), false, memGet)
	n.RegisterTool("mem.query", "List nodes whose id starts with `prefix` (and optionally of `kind`).",
		obj(map[string]any{"prefix": str, "kind": str}), false, memQuery)
	n.RegisterTool("mem.link", "Create a labelled edge from->to with predicate `rel`.",
		obj(map[string]any{"from": str, "to": str, "rel": str}, "from", "to", "rel"), false, memLink)
	n.RegisterTool("mem.neighbors", "Traverse edges: nodes reachable from `id` via predicate `rel` (dir out|in).",
		obj(map[string]any{"id": str, "rel": str, "dir": str}, "id"), false, memNeighbors)
	n.RegisterTool("mem.allocate", "ATOMIC: if item.body.available >= qty, decrement and return ok; else backorder.",
		obj(map[string]any{"id": str, "qty": num}, "id", "qty"), false, memAllocate)
	n.RegisterTool("mem.restock", "ATOMIC: add qty to item.body.available.",
		obj(map[string]any{"id": str, "qty": num}, "id", "qty"), false, memRestock)
}

func gs(args map[string]any, k string) string  { v, _ := args[k].(string); return v }
func gf(args map[string]any, k string) float64 { v, _ := args[k].(float64); return v }

func nodeJSON(n kernel.Node) map[string]any {
	return map[string]any{"id": n.ID, "kind": string(n.Kind), "label": n.Label, "body": n.Body}
}

func bodyMap(n kernel.Node) map[string]any {
	m := map[string]any{}
	if n.Body != "" {
		_ = json.Unmarshal([]byte(n.Body), &m)
	}
	return m
}

func memPut(args map[string]any) (string, any, error) {
	id := gs(args, "id")
	if id == "" {
		return "", nil, fmt.Errorf("mem.put: id required")
	}
	kind := kernel.NodeKind(gs(args, "kind"))
	if kind == "" {
		kind = kernel.KindEntity
	}
	mu.Lock()
	defer mu.Unlock()
	err := store.PutNode(kernel.Node{ID: id, Kind: kind, Label: gs(args, "label"),
		Body: gs(args, "body"), Scope: scope, Namespace: "mem"})
	if err != nil {
		return "", nil, err
	}
	return "put " + id, map[string]any{"id": id}, nil
}

func memGet(args map[string]any) (string, any, error) {
	n, ok := store.GetNode(gs(args, "id"))
	if !ok {
		return "", nil, fmt.Errorf("mem.get: no node %q", gs(args, "id"))
	}
	return n.ID, nodeJSON(n), nil
}

func memQuery(args map[string]any) (string, any, error) {
	prefix, kind := gs(args, "prefix"), gs(args, "kind")
	out := []map[string]any{}
	store.RangeNodes(func(n kernel.Node) bool {
		if prefix != "" && !strings.HasPrefix(n.ID, prefix) {
			return true
		}
		if kind != "" && string(n.Kind) != kind {
			return true
		}
		out = append(out, nodeJSON(n))
		return true
	})
	return fmt.Sprintf("%d nodes", len(out)), map[string]any{"nodes": out}, nil
}

func memLink(args map[string]any) (string, any, error) {
	from, to, rel := gs(args, "from"), gs(args, "to"), gs(args, "rel")
	mu.Lock()
	defer mu.Unlock()
	e := kernel.Edge{ID: from + "|" + rel + "|" + to, Kind: kernel.EdgeRelational, Label: rel,
		From: from, To: to, Weight: 1, Scope: scope, Namespace: "mem"}
	if err := store.PutEdge(e); err != nil {
		return "", nil, err
	}
	return "linked", map[string]any{"id": e.ID}, nil
}

func memNeighbors(args map[string]any) (string, any, error) {
	id, rel, dir := gs(args, "id"), gs(args, "rel"), gs(args, "dir")
	var edges []kernel.Edge
	if dir == "in" {
		edges = store.EdgesTo(id)
	} else {
		edges = store.EdgesFrom(id)
	}
	out := []map[string]any{}
	for _, e := range edges {
		if rel != "" && e.Label != rel {
			continue
		}
		nid := e.To
		if dir == "in" {
			nid = e.From
		}
		if n, ok := store.GetNode(nid); ok {
			out = append(out, nodeJSON(n))
		}
	}
	return fmt.Sprintf("%d neighbors", len(out)), map[string]any{"nodes": out}, nil
}

func memAllocate(args map[string]any) (string, any, error) {
	id, qty := gs(args, "id"), gf(args, "qty")
	mu.Lock()
	defer mu.Unlock()
	n, ok := store.GetNode(id)
	if !ok {
		return "", nil, fmt.Errorf("mem.allocate: no item %q", id)
	}
	bm := bodyMap(n)
	avail, _ := bm["available"].(float64)
	if avail < qty {
		return "backorder", map[string]any{"ok": false, "available": avail, "requested": qty}, nil
	}
	bm["available"] = avail - qty
	b, _ := json.Marshal(bm)
	n.Body = string(b)
	_ = store.PutNode(n)
	return "allocated", map[string]any{"ok": true, "remaining": avail - qty}, nil
}

func memRestock(args map[string]any) (string, any, error) {
	id, qty := gs(args, "id"), gf(args, "qty")
	mu.Lock()
	defer mu.Unlock()
	n, ok := store.GetNode(id)
	if !ok {
		return "", nil, fmt.Errorf("mem.restock: no item %q", id)
	}
	bm := bodyMap(n)
	avail, _ := bm["available"].(float64)
	bm["available"] = avail + qty
	b, _ := json.Marshal(bm)
	n.Body = string(b)
	_ = store.PutNode(n)
	return "restocked", map[string]any{"available": avail + qty}, nil
}

// loadSeed preloads the shared graph from a JSONL file (one {"id","kind","label","body":{…}} per line) — the
// memory service's MASTER DATA (inventory + customers), owned here so the agents only create + evolve the
// transactional records (orders). Lines starting with // are skipped.
func loadSeed(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		var rec struct {
			ID    string          `json:"id"`
			Kind  string          `json:"kind"`
			Label string          `json:"label"`
			Body  json.RawMessage `json:"body"`
		}
		if json.Unmarshal([]byte(line), &rec) != nil || rec.ID == "" {
			continue
		}
		kind := kernel.NodeKind(rec.Kind)
		if kind == "" {
			kind = kernel.KindEntity
		}
		_ = store.PutNode(kernel.Node{ID: rec.ID, Kind: kind, Label: rec.Label,
			Body: string(rec.Body), Scope: scope, Namespace: "mem"})
		n++
	}
	return n, sc.Err()
}
