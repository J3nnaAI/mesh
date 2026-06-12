// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// desk is the human-facing conductor of the showcase. It HOSTS a room (any peer can — a room is a
// decentralized role, not a server), posts a 1/2 menu, and reacts to what the human types in room-view.
// On a choice it runs the choreography over DIRECT peer tool calls — discovering quote-svc and dispatch-svc
// by capability and invoking their tools — and posts every step back into the room so the human watches the
// agents cooperate in real time. No AI: the desk is a deterministic router.
//
//	1) quote → dispatch : price first (quote.price), then ship (dispatch.ship) using that price
//	2) dispatch → quote : reserve+ship first (dispatch.ship), then price that shipment (quote.price)
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/J3nnaAI/mesh/agentkit"
)

const roomID = "desk"

var mesh *agentkit.Mesh

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	console := env("DESK_CONSOLE", "http://127.0.0.1:8455")
	idFile := env("DESK_IDENTITY", "desk.id")
	waitForDeps(ctx, "desk", console, seeds("DESK_SEEDS"))

	log.Printf("desk: enrolling with console %s …", console)
	grant, root, err := agentkit.Enroll(ctx, console, "desk", idFile, 1, func(oob string) {
		log.Printf("desk: APPROVE enrollment — out-of-band code %s", oob)
	})
	if err != nil {
		log.Fatalf("desk: enroll: %v", err)
	}

	mesh, err = agentkit.Open(ctx, agentkit.Options{
		Advertise:     env("DESK_ADVERTISE", "http://127.0.0.1:8493"),
		Listen:        env("DESK_LISTEN", "127.0.0.1:8493"),
		Caps:          []string{"rooms", "desk"}, // advertises "rooms" so room-view discovers + joins
		Seeds:         seeds("DESK_SEEDS"),
		Discover:      env("DESK_DISCOVER", "true") == "true",
		InsecureTLS:   true,
		IdentityFile:  idFile,
		AuthorityRoot: root,
		Grant:         grant,
	})
	if err != nil {
		log.Fatalf("desk: open: %v", err)
	}
	defer mesh.Close()
	go agentkit.KeepFresh(ctx, mesh, console, root, 30*time.Second)

	if err := mesh.CreateRoom(ctx, roomID, "desk", false); err != nil {
		log.Fatalf("desk: create room: %v", err)
	}
	// React to every post in the hosted room. The returned string is auto-posted as the desk's reply.
	mesh.AddRoomResponder(handle)
	go welcomeLoop(ctx) // (re)post the menu once peers are discovered

	log.Printf("desk: live — hosting room %q; open room-view and choose 1 or 2 (node %s…)", roomID, mesh.ID()[:8])
	<-ctx.Done()
}

// handle reacts to a human post. "1"/"2" run the choreography; anything else re-shows the menu.
func handle(ctx context.Context, room, from, text string) string {
	if from == "desk" { // ignore our own narration
		return ""
	}
	fields := strings.Fields(strings.TrimSpace(text))
	if len(fields) == 0 {
		return ""
	}
	choice := fields[0]
	sku, qty := "WIDGET", 1
	if len(fields) >= 2 {
		sku = strings.ToUpper(fields[1])
	}
	if len(fields) >= 3 {
		if n, e := strconv.Atoi(fields[2]); e == nil && n > 0 {
			qty = n
		}
	}
	switch choice {
	case "1":
		return quoteThenDispatch(ctx, sku, qty)
	case "2":
		return dispatchThenQuote(ctx, sku, qty)
	default:
		return menu()
	}
}

// 1) quote → dispatch: price first, then ship using that price (dispatch USES the quote's data).
func quoteThenDispatch(ctx context.Context, sku string, qty int) string {
	say("① pricing %d×%s …", qty, sku)
	q, err := call(ctx, "quote", "quote.price", map[string]any{"sku": sku, "qty": qty})
	if err != nil {
		return "✗ quote failed: " + err.Error()
	}
	say("   quote %v — $%v (zone %v, %v available)", q["quote_id"], q["price"], q["zone"], q["available"])
	if deliverable, _ := q["deliverable"].(bool); !deliverable {
		return "✗ not deliverable: " + str(q["reason"])
	}
	say("② dispatching (reserving stock, signing manifest, signalling carrier) …")
	d, err := call(ctx, "dispatch", "dispatch.ship", map[string]any{
		"sku": sku, "qty": qty, "price": q["price"], "quote_id": q["quote_id"],
	})
	if err != nil {
		return "✗ dispatch failed: " + err.Error()
	}
	if shipped, _ := d["shipped"].(bool); !shipped {
		return fmt.Sprintf("✗ %v (available: %v)", d["reason"], d["available"])
	}
	return fmt.Sprintf("✓ %v shipped — manifest signed %s…, carrier notified: %v",
		d["shipment_id"], short(str(d["signature"])), d["carrier_notified"])
}

// 2) dispatch → quote: reserve+ship first, then price that shipment (quote USES the dispatch draft).
func dispatchThenQuote(ctx context.Context, sku string, qty int) string {
	say("① reserving + shipping %d×%s (manifest signed, carrier signalled) …", qty, sku)
	d, err := call(ctx, "dispatch", "dispatch.ship", map[string]any{"sku": sku, "qty": qty})
	if err != nil {
		return "✗ dispatch failed: " + err.Error()
	}
	if shipped, _ := d["shipped"].(bool); !shipped {
		return fmt.Sprintf("✗ %v (available: %v)", d["reason"], d["available"])
	}
	say("   shipment %v — manifest signed %s…", d["shipment_id"], short(str(d["signature"])))
	say("② pricing shipment %v …", d["shipment_id"])
	q, err := call(ctx, "quote", "quote.price", map[string]any{"sku": sku, "qty": qty, "shipment_id": d["shipment_id"]})
	if err != nil {
		return "✗ quote failed: " + err.Error()
	}
	return fmt.Sprintf("✓ %v shipped and priced at $%v (quote %v)", d["shipment_id"], q["price"], q["quote_id"])
}

// call discovers the peer advertising `cap` and invokes `tool` on it (direct peer-to-peer tools/call).
func call(ctx context.Context, cap, tool string, args map[string]any) (map[string]any, error) {
	mcp, ok := findPeer(cap)
	if !ok {
		return nil, fmt.Errorf("no %q peer discovered", cap)
	}
	cctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	return mesh.CallPeer(cctx, mcp, tool, args)
}

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

func menu() string {
	return "🛎️  Delivery desk — reply with a number:\n" +
		"   1) quote → dispatch  (price first, then ship)\n" +
		"   2) dispatch → quote  (reserve+ship first, then price)\n" +
		"Default order is 1×WIDGET; customise as e.g.  “1 GADGET 2”."
}

// say posts a narration line into the room as the desk.
func say(format string, a ...any) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = mesh.Post(ctx, "", roomID, fmt.Sprintf(format, a...))
}

// welcomeLoop posts the menu once the quote+dispatch peers are discovered, so the human has something to do.
func welcomeLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
		_, q := findPeer("quote")
		_, d := findPeer("dispatch")
		if q && d {
			say("%s", menu())
			return
		}
	}
}

// ─── helpers ───

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

func str(v any) string {
	s, _ := v.(string)
	return s
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

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
