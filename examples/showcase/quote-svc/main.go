// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// quote-svc prices a delivery. It owns NO inventory of its own — to quote a SKU it DISCOVERS the
// inventory service on the mesh (by its advertised "inventory" capability, never a hardcoded address),
// then INVOKES inventory.check on that peer directly (tools/call, with a CallProof attached for free).
// That round trip — discover a peer by capability, list/invoke its tool — is the heart of the mesh, and
// quote-svc is the smallest honest demonstration of it.
//
//	quote.price {sku, qty}  →  {sku, qty, available, unit_price, price, quote_id, deliverable}
//
// Pricing is a deterministic function of the unit weight and delivery zone the inventory service reports
// (no AI): base + weight*rate*qty + a per-zone surcharge.
package main

import (
	"context"
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
)

const (
	baseFee  = 5.00 // flat handling fee
	perKgFee = 1.50 // per kilogram, per unit
)

// zoneSurcharge is the deterministic distance cost — the further the zone, the more it costs.
var zoneSurcharge = map[string]float64{"A": 0, "B": 3, "C": 7, "D": 12}

var (
	mesh    *agentkit.Mesh
	counter struct {
		sync.Mutex
		n int
	}
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	console := env("QUOTE_CONSOLE", "http://127.0.0.1:8455")
	idFile := env("QUOTE_IDENTITY", "quote.id")
	waitForDeps(ctx, "quote-svc", console, seeds("QUOTE_SEEDS"))

	log.Printf("quote-svc: enrolling with console %s …", console)
	grant, root, err := agentkit.Enroll(ctx, console, "quote-svc", idFile, 1, func(oob string) {
		log.Printf("quote-svc: APPROVE enrollment — out-of-band code %s", oob)
	})
	if err != nil {
		log.Fatalf("quote-svc: enroll: %v", err)
	}

	mesh, err = agentkit.Open(ctx, agentkit.Options{
		Advertise:     env("QUOTE_ADVERTISE", "http://127.0.0.1:8491"),
		Listen:        env("QUOTE_LISTEN", "127.0.0.1:8491"),
		Caps:          []string{"quote"},
		Seeds:         seeds("QUOTE_SEEDS"),
		Discover:      env("QUOTE_DISCOVER", "true") == "true",
		InsecureTLS:   true,
		IdentityFile:  idFile,
		AuthorityRoot: root,
		Grant:         grant,
	})
	if err != nil {
		log.Fatalf("quote-svc: open: %v", err)
	}
	defer mesh.Close()
	go agentkit.KeepFresh(ctx, mesh, console, root, 30*time.Second)

	registerTools(mesh.Node())
	log.Printf("quote-svc: live — quote.price prices against the inventory peer (node %s…)", mesh.ID()[:8])
	<-ctx.Done()
}

func registerTools(n *jip.Node) {
	str := map[string]any{"type": "string"}
	num := map[string]any{"type": "number"}
	n.RegisterTool("quote.price", "Price a delivery of `qty` × `sku`, checking the inventory peer for weight/zone/availability.",
		map[string]any{"type": "object", "properties": map[string]any{"sku": str, "qty": num}, "required": []string{"sku"}},
		false, price)
}

func price(args map[string]any) (string, any, error) {
	sku := gs(args, "sku")
	qty := int(gf(args, "qty"))
	if qty <= 0 {
		qty = 1
	}

	// 1) DISCOVER the inventory peer by capability — not by a configured URL.
	invMCP, ok := findPeer("inventory")
	if !ok {
		return "", nil, fmt.Errorf("quote.price: no inventory peer discovered yet")
	}
	// 2) INVOKE its tool directly, peer-to-peer (CallPeer attaches a CallProof automatically).
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	inv, err := mesh.CallPeer(ctx, invMCP, "inventory.check", map[string]any{"sku": sku})
	if err != nil {
		return "", nil, fmt.Errorf("quote.price: inventory.check on %s: %w", invMCP, err)
	}
	if found, _ := inv["found"].(bool); !found {
		return "no such sku", map[string]any{"sku": sku, "deliverable": false, "reason": "unknown sku"}, nil
	}

	weight, _ := inv["weight_kg"].(float64)
	zone, _ := inv["zone"].(string)
	available := int(toF(inv["available"]))

	// 3) Price deterministically from what the inventory peer reported.
	unit := baseFee + weight*perKgFee + zoneSurcharge[zone]
	total := unit * float64(qty)

	counter.Lock()
	counter.n++
	id := fmt.Sprintf("Q%d", counter.n)
	counter.Unlock()

	return fmt.Sprintf("%s: %d×%s → $%.2f", id, qty, sku, total),
		map[string]any{
			"quote_id": id, "sku": sku, "qty": qty, "zone": zone, "weight_kg": weight,
			"available": available, "deliverable": available >= qty,
			"unit_price": round2(unit), "price": round2(total),
		}, nil
}

// findPeer returns the MCP URL of the first discovered peer advertising capability cap.
func findPeer(cap string) (string, bool) {
	for _, p := range mesh.Peers() {
		for _, c := range p.Caps {
			if c == cap {
				return p.MCP, true
			}
		}
	}
	return "", false
}

// ─── small helpers ───

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
func toF(v any) float64                         { f, _ := v.(float64); return f }
func round2(f float64) float64                  { return float64(int(f*100+0.5)) / 100 }

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
