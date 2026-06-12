// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// dispatch-svc turns a priced order into a shipment. It exercises three things the mesh is built for, the
// canonical way:
//
//   - a RESTRICTED peer tool call: it reserves stock by invoking inventory.reserve on the inventory peer.
//     That tool is allow-listed, so the call carries a CallProof; a peer that merely discovered inventory
//     could not draw down stock.
//   - its OWN vault: it signs each shipment manifest with an HMAC key held in its own encrypted vault. The
//     key is decrypted in-process and never crosses the mesh — only the signature is published. (This is
//     how an agent uses vault: for its own secrets, at its own injection point — never as a signing oracle.)
//   - a signal: it publishes the signed manifest to the signal-bridge, which fans it out as an HMAC-signed
//     webhook to the external carrier.
//
//	dispatch.ship {sku, qty, price?, quote_id?}  →  reserve → sign → signal → {shipment_id, signature, …}
package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/J3nnaAI/mesh/vault"
)

const manifestKeyHandle = "manifest-hmac" // the signing key lives in THIS service's vault, by handle

var (
	mesh    *agentkit.Mesh
	vlt     *vault.Vault
	counter struct {
		sync.Mutex
		n int
	}
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// This service's OWN encrypted vault. Key derived from DISPATCH_VAULT_PASSPHRASE (PBKDF2); locked without it.
	v, err := vault.Open(env("DISPATCH_VAULT", "dispatch-vault.enc"), "DISPATCH_VAULT")
	if err != nil {
		log.Fatalf("dispatch-svc: open vault: %v", err)
	}
	vlt = v
	if vlt.Locked() {
		log.Fatalf("dispatch-svc: vault is LOCKED — set DISPATCH_VAULT_PASSPHRASE")
	}
	// Provision the manifest signing key once, generated locally; encrypted at rest, never logged or exposed.
	if _, err := vlt.Get(manifestKeyHandle); err != nil {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			log.Fatalf("dispatch-svc: generate signing key: %v", err)
		}
		if err := vlt.Put(manifestKeyHandle, hex.EncodeToString(key), "manifest HMAC signing key"); err != nil {
			log.Fatalf("dispatch-svc: provision signing key: %v", err)
		}
		log.Printf("dispatch-svc: provisioned manifest signing key (sealed in this service's vault)")
	}

	console := env("DISPATCH_CONSOLE", "http://127.0.0.1:8455")
	idFile := env("DISPATCH_IDENTITY", "dispatch.id")
	waitForDeps(ctx, "dispatch-svc", console, seeds("DISPATCH_SEEDS"))

	log.Printf("dispatch-svc: enrolling with console %s …", console)
	grant, root, err := agentkit.Enroll(ctx, console, "dispatch-svc", idFile, 1, func(oob string) {
		log.Printf("dispatch-svc: APPROVE enrollment — out-of-band code %s", oob)
	})
	if err != nil {
		log.Fatalf("dispatch-svc: enroll: %v", err)
	}

	mesh, err = agentkit.Open(ctx, agentkit.Options{
		Advertise:     env("DISPATCH_ADVERTISE", "http://127.0.0.1:8492"),
		Listen:        env("DISPATCH_LISTEN", "127.0.0.1:8492"),
		Caps:          []string{"dispatch"},
		Seeds:         seeds("DISPATCH_SEEDS"),
		Discover:      env("DISPATCH_DISCOVER", "true") == "true",
		InsecureTLS:   true,
		IdentityFile:  idFile,
		AuthorityRoot: root,
		Grant:         grant,
	})
	if err != nil {
		log.Fatalf("dispatch-svc: open: %v", err)
	}
	defer mesh.Close()
	go agentkit.KeepFresh(ctx, mesh, console, root, 30*time.Second)

	str := map[string]any{"type": "string"}
	num := map[string]any{"type": "number"}
	mesh.Node().RegisterTool("dispatch.ship",
		"Reserve stock for `qty`×`sku` (restricted inventory call), sign a manifest from this service's own vault, and signal the carrier.",
		map[string]any{"type": "object", "properties": map[string]any{"sku": str, "qty": num, "price": num, "quote_id": str}, "required": []string{"sku"}},
		false, ship)

	// This service's node id is what inventory-svc must allow-list for inventory.reserve.
	log.Printf("dispatch-svc: live — node id %s (allow-list this for inventory.reserve)", mesh.ID())
	<-ctx.Done()
}

func ship(args map[string]any) (string, any, error) {
	sku := gs(args, "sku")
	qty := int(gf(args, "qty"))
	if qty <= 0 {
		qty = 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1) RESTRICTED peer call: reserve stock. CallPeer attaches a CallProof; inventory-svc enforces the
	//    allow-list, so only this (allow-listed) service can reserve.
	invMCP, ok := findPeer("inventory")
	if !ok {
		return "", nil, fmt.Errorf("dispatch.ship: no inventory peer discovered")
	}
	reserved, err := mesh.CallPeer(ctx, invMCP, "inventory.reserve", map[string]any{"sku": sku, "qty": qty})
	if err != nil {
		return "", nil, fmt.Errorf("dispatch.ship: inventory.reserve: %w", err)
	}
	if okFlag, _ := reserved["ok"].(bool); !okFlag {
		avail := int(toF(reserved["available"]))
		return "backorder", map[string]any{"shipped": false, "sku": sku, "reason": "insufficient stock", "available": avail}, nil
	}

	// 2) Build + sign the manifest with THIS service's own vault key (HMAC). The key never leaves the vault.
	counter.Lock()
	counter.n++
	id := fmt.Sprintf("S%d", counter.n)
	counter.Unlock()
	manifest := map[string]any{
		"shipment_id": id, "sku": sku, "qty": qty,
		"price": round2(toF(args["price"])), "quote_id": gs(args, "quote_id"),
		"remaining": int(toF(reserved["remaining"])),
	}
	sig, err := signManifest(manifest)
	if err != nil {
		return "", nil, fmt.Errorf("dispatch.ship: sign manifest: %w", err)
	}

	// 3) Signal the carrier via the signal-bridge (best-effort — shipment still succeeds if no bridge is up).
	carrierNotified := false
	if sbMCP, ok := findPeer("signals"); ok {
		_, perr := mesh.CallPeer(ctx, sbMCP, "signal.publish", map[string]any{
			"topic": "shipment",
			"data":  map[string]any{"manifest": manifest, "signature": sig},
		})
		carrierNotified = perr == nil
		if perr != nil {
			log.Printf("dispatch.ship: signal.publish: %v (continuing)", perr)
		}
	}

	return fmt.Sprintf("%s shipped (%d×%s)", id, qty, sku),
		map[string]any{
			"shipped": true, "shipment_id": id, "sku": sku, "qty": qty,
			"remaining": manifest["remaining"], "signature": sig, "carrier_notified": carrierNotified,
		}, nil
}

// signManifest HMAC-SHA256s the canonical JSON of the manifest with the vault-held key. Only the signature
// is ever returned; the key is read in-process and discarded.
func signManifest(manifest map[string]any) (string, error) {
	keyHex, err := vlt.Get(manifestKeyHandle)
	if err != nil {
		return "", err
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return "", err
	}
	body, _ := json.Marshal(manifest) // Go sorts map keys → canonical, reproducible
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil)), nil
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
