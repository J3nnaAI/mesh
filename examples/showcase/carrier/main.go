// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// carrier is the EXTERNAL system in the showcase — deliberately NOT a mesh peer. It is a plain HTTP
// endpoint that the signal-bridge calls with an HMAC-signed outbound webhook when a shipment is dispatched.
// It verifies the signature against the shared subscription secret (fail-closed) and logs the handoff. This
// is the mesh's edge: an in-mesh event crossing, authenticated, to a system that knows nothing about JIP.
//
// Pure standard library — no mesh dependency at all.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	addr := envOr("CARRIER_LISTEN", "127.0.0.1:8494")
	secret := resolveSecret()
	if len(secret) == 0 {
		log.Printf("carrier: WARNING — no HMAC secret (set CARRIER_HMAC_SECRET or CARRIER_HMAC_SECRET_FILE); every webhook will be rejected")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("/hook", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		// Verify the signal-bridge signature: X-Signal-Signature: sha256=<hex of HMAC-SHA256(body, secret)>.
		mac := hmac.New(sha256.New, secret)
		mac.Write(body)
		want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		got := r.Header.Get("X-Signal-Signature")
		if len(secret) == 0 || !hmac.Equal([]byte(got), []byte(want)) {
			log.Printf("carrier: ✗ REJECTED webhook (bad/missing signature) topic=%q", r.Header.Get("X-Signal-Topic"))
			http.Error(w, "signature mismatch", http.StatusUnauthorized)
			return
		}
		log.Printf("carrier: ✓ accepted signed %q webhook — %s", r.Header.Get("X-Signal-Topic"), compact(body))
		w.WriteHeader(http.StatusNoContent)
	})

	log.Printf("carrier: external endpoint live on http://%s/hook (verifying HMAC-signed shipment webhooks)", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("carrier: %v", err)
	}
}

func envOr(k, d string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return d
}

// resolveSecret returns the HMAC secret from CARRIER_HMAC_SECRET, or from the file named by
// CARRIER_HMAC_SECRET_FILE (waiting for the registrar to write it — the cluster/compose path).
func resolveSecret() []byte {
	if s := strings.TrimSpace(os.Getenv("CARRIER_HMAC_SECRET")); s != "" {
		return []byte(s)
	}
	path := strings.TrimSpace(os.Getenv("CARRIER_HMAC_SECRET_FILE"))
	if path == "" {
		return nil
	}
	for i := 0; i < 120; i++ {
		if b, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(b))) > 0 {
			return []byte(strings.TrimSpace(string(b)))
		}
		log.Printf("carrier: waiting for webhook secret at %s …", path)
		time.Sleep(2 * time.Second)
	}
	return nil
}

// compact trims a JSON body to a single readable log line.
func compact(b []byte) string {
	s := strings.Join(strings.Fields(string(b)), " ")
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}
