// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// inventory-svc is the SHARED MEMORY of the showcase: a mesh peer that embeds the J3nna kernel (a typed
// node graph) and exposes it as inventory.* tools. The quote and dispatch services never hold their own
// copy of stock — they read and mutate this one graph over the mesh, which is exactly the cooperative,
// shared-scope use the kernel is built for.
//
//	inventory.check    (open)       — read availability/weight/zone for a SKU
//	inventory.reserve  (RESTRICTED) — ATOMIC check-then-decrement; only an allow-listed caller with a
//	                                  valid CallProof may reserve, so stock can't be drawn down by anyone
//	                                  who merely reached the peer ("reachable" is not "authorized")
//	inventory.release  (open)       — return reserved stock
//
// The reserve mutex makes check-then-decrement atomic, so two concurrent dispatches can never oversell.
package main

import (
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

var (
	store = kernel.NewMemStore()
	mu    sync.Mutex // serializes reserve/release so check-then-write is atomic (no oversell)
	scope = kernel.Scope{Kind: "domain", ID: "showcase"}
)

// item is the body of an inventory node, stored as JSON in the kernel graph.
type item struct {
	Available int     `json:"available"`
	WeightKg  float64 `json:"weight_kg"`
	Zone      string  `json:"zone"`
}

// seed is the warehouse master data. GIZMO is intentionally out of stock so the demo can show a backorder.
var seed = map[string]item{
	"WIDGET": {Available: 5, WeightKg: 2.0, Zone: "B"},
	"GADGET": {Available: 2, WeightKg: 5.5, Zone: "C"},
	"GIZMO":  {Available: 0, WeightKg: 1.0, Zone: "A"},
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	console := env("INV_CONSOLE", "http://127.0.0.1:8455")
	idFile := env("INV_IDENTITY", "inventory.id")
	waitForDeps(ctx, "inventory-svc", console, seeds("INV_SEEDS"))
	loadSeed()

	log.Printf("inventory-svc: enrolling with console %s …", console)
	grant, root, err := agentkit.Enroll(ctx, console, "inventory-svc", idFile, 1, func(oob string) {
		log.Printf("inventory-svc: APPROVE enrollment — out-of-band code %s", oob)
	})
	if err != nil {
		log.Fatalf("inventory-svc: enroll: %v", err)
	}

	// Allow-list for the restricted inventory.reserve: explicit node ids (INV_ALLOW) plus any resolved
	// from a peer's /whoami (INV_ALLOW_URLS) — so a cluster authorizes the dispatch service by its
	// URL/DNS without having to know its node id ahead of time.
	allow := append(seeds("INV_ALLOW"), resolveAllow(ctx, seeds("INV_ALLOW_URLS"))...)

	m, err := agentkit.Open(ctx, agentkit.Options{
		Advertise:     env("INV_ADVERTISE", "http://127.0.0.1:8490"),
		Listen:        env("INV_LISTEN", "127.0.0.1:8490"),
		Caps:          []string{"inventory"},
		Seeds:         seeds("INV_SEEDS"),
		Discover:      env("INV_DISCOVER", "true") == "true",
		InsecureTLS:   true,
		IdentityFile:  idFile,
		AuthorityRoot: root,
		Grant:         grant,
		// inventory.reserve is restricted: only an allow-listed caller may reserve, and only with a
		// valid CallProof. Discovery + a grant make a peer visible; reserving stock takes an explicit,
		// per-call authorization on top.
		Restrict: []string{"inventory.reserve"},
		Allow:    allow,
	})
	if err != nil {
		log.Fatalf("inventory-svc: open: %v", err)
	}
	defer m.Close()
	go agentkit.KeepFresh(ctx, m, console, root, 30*time.Second)

	registerTools(m.Node())
	if len(allow) > 0 {
		log.Printf("inventory-svc: inventory.reserve restricted to %d allow-listed caller(s)", len(allow))
	} else {
		log.Printf("inventory-svc: WARNING — inventory.reserve is restricted but no callers are allow-listed (set INV_ALLOW or INV_ALLOW_URLS)")
	}
	log.Printf("inventory-svc: live — inventory.* tools serving the shared kernel (node %s…)", m.ID()[:8])
	<-ctx.Done()
}

func registerTools(n *jip.Node) {
	str := map[string]any{"type": "string"}
	num := map[string]any{"type": "number"}
	obj := func(props map[string]any, req ...string) map[string]any {
		return map[string]any{"type": "object", "properties": props, "required": req}
	}
	n.RegisterTool("inventory.check", "Availability, unit weight (kg), and delivery zone for a SKU.",
		obj(map[string]any{"sku": str}, "sku"), false, check)
	n.RegisterTool("inventory.reserve", "ATOMIC: reserve `qty` of `sku` if in stock (decrement); else backorder. Restricted.",
		obj(map[string]any{"sku": str, "qty": num}, "sku", "qty"), true, reserve)
	n.RegisterTool("inventory.release", "Return `qty` of `sku` to available stock.",
		obj(map[string]any{"sku": str, "qty": num}, "sku", "qty"), false, release)
}

func check(args map[string]any) (string, any, error) {
	sku := gs(args, "sku")
	it, ok := getItem(sku)
	if !ok {
		return "no such sku", map[string]any{"sku": sku, "found": false}, nil
	}
	return fmt.Sprintf("%s: %d available", sku, it.Available),
		map[string]any{"sku": sku, "found": true, "available": it.Available, "weight_kg": it.WeightKg, "zone": it.Zone}, nil
}

func reserve(args map[string]any) (string, any, error) {
	sku, qty := gs(args, "sku"), int(gf(args, "qty"))
	if qty <= 0 {
		return "", nil, fmt.Errorf("inventory.reserve: qty must be > 0")
	}
	mu.Lock()
	defer mu.Unlock()
	it, ok := getItem(sku)
	if !ok {
		return "", nil, fmt.Errorf("inventory.reserve: no such sku %q", sku)
	}
	if it.Available < qty {
		return "backorder", map[string]any{"ok": false, "sku": sku, "available": it.Available, "requested": qty}, nil
	}
	it.Available -= qty
	putItem(sku, it)
	return "reserved", map[string]any{"ok": true, "sku": sku, "reserved": qty, "remaining": it.Available}, nil
}

func release(args map[string]any) (string, any, error) {
	sku, qty := gs(args, "sku"), int(gf(args, "qty"))
	if qty <= 0 {
		return "", nil, fmt.Errorf("inventory.release: qty must be > 0")
	}
	mu.Lock()
	defer mu.Unlock()
	it, ok := getItem(sku)
	if !ok {
		return "", nil, fmt.Errorf("inventory.release: no such sku %q", sku)
	}
	it.Available += qty
	putItem(sku, it)
	return "released", map[string]any{"ok": true, "sku": sku, "available": it.Available}, nil
}

// ─── kernel-graph helpers (the shared store) ───

func nodeID(sku string) string { return "item:" + sku }

func getItem(sku string) (item, bool) {
	n, ok := store.GetNode(nodeID(sku))
	if !ok {
		return item{}, false
	}
	var it item
	_ = json.Unmarshal([]byte(n.Body), &it)
	return it, true
}

func putItem(sku string, it item) {
	b, _ := json.Marshal(it)
	_ = store.PutNode(kernel.Node{ID: nodeID(sku), Kind: kernel.KindEntity, Label: sku,
		Body: string(b), Scope: scope, Namespace: "inv"})
}

func loadSeed() {
	for sku, it := range seed {
		putItem(sku, it)
	}
}

// ─── env + dependency-wait helpers ───

func env(k, d string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return d
}

func seeds(k string) []string {
	var out []string
	for _, u := range strings.Split(os.Getenv(k), ",") {
		if u = strings.TrimSpace(u); u != "" {
			out = append(out, u)
		}
	}
	return out
}

func gs(args map[string]any, k string) string  { v, _ := args[k].(string); return v }
func gf(args map[string]any, k string) float64 { v, _ := args[k].(float64); return v }

// resolveAllow fetches the node id from each peer base URL's /whoami (the dispatch service), so the
// restricted-tool allow-list can be configured by URL/DNS instead of a node id known ahead of time.
// It retries until each peer answers, so startup order doesn't matter.
func resolveAllow(ctx context.Context, urls []string) []string {
	var ids []string
	for _, u := range urls {
		who := strings.TrimRight(u, "/") + "/whoami"
		for {
			if id := fetchID(ctx, who); id != "" {
				log.Printf("inventory-svc: allow-listing %s… (resolved from %s)", id[:8], who)
				ids = append(ids, id)
				break
			}
			log.Printf("inventory-svc: waiting for allow-list peer %s …", who)
			select {
			case <-ctx.Done():
				return ids
			case <-time.After(2 * time.Second):
			}
		}
	}
	return ids
}

func fetchID(ctx context.Context, url string) string {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer r.Body.Close()
	var m struct {
		ID string `json:"id"`
	}
	if json.NewDecoder(r.Body).Decode(&m) != nil {
		return ""
	}
	return m.ID
}

// waitForDeps blocks until the console (and every gossip seed) answers, so this peer only announces
// presence once the mesh can route to it.
func waitForDeps(ctx context.Context, label, console string, seedURLs []string) {
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
	for i, s := range seedURLs {
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
