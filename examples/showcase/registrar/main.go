// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// registrar is a one-shot used only in the container/cluster path: it waits for the signal-bridge, registers
// the outbound webhook that points at the carrier, and writes the returned HMAC secret to a shared file the
// carrier reads. (The signal-bridge generates the secret and shows it once — this is the supported way to get
// it to the receiver without baking a shared secret into images.) Pure standard library.
package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	signal := envOr("REGISTRAR_SIGNAL", "http://signal-bridge:8484")
	carrier := envOr("REGISTRAR_CARRIER_URL", "http://carrier:8494/hook")
	topic := envOr("REGISTRAR_TOPIC", "shipment")
	out := envOr("REGISTRAR_SECRET_FILE", "/shared/carrier.secret")

	// If the secret file already holds a secret (a previous run), do nothing — idempotent restarts.
	if b, err := os.ReadFile(out); err == nil && len(strings.TrimSpace(string(b))) > 0 {
		log.Printf("registrar: secret already present at %s — nothing to do", out)
		return
	}

	waitHealthy(signal + "/healthz")
	body, _ := json.Marshal(map[string]string{"topic": topic, "url": carrier})
	var secret string
	for i := 0; i < 60; i++ {
		resp, err := http.Post(signal+"/webhooks", "application/json", bytes.NewReader(body))
		if err == nil && resp.StatusCode/100 == 2 {
			var r struct {
				Secret string `json:"secret"`
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			_ = json.Unmarshal(b, &r)
			if r.Secret != "" {
				secret = r.Secret
				break
			}
		}
		if resp != nil {
			resp.Body.Close()
		}
		log.Printf("registrar: registering webhook → %s (retry %d) …", carrier, i)
		time.Sleep(2 * time.Second)
	}
	if secret == "" {
		log.Fatalf("registrar: could not register the carrier webhook with %s", signal)
	}
	if err := os.WriteFile(out, []byte(secret), 0o600); err != nil {
		log.Fatalf("registrar: write secret %s: %v", out, err)
	}
	log.Printf("registrar: registered %q webhook → %s; secret written to %s", topic, carrier, out)
}

func waitHealthy(url string) {
	for {
		if r, err := http.Get(url); err == nil {
			r.Body.Close()
			return
		}
		log.Printf("registrar: waiting for signal-bridge %s …", url)
		time.Sleep(2 * time.Second)
	}
}

func envOr(k, d string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return d
}
