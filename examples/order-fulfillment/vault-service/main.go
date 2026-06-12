// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// vault-service holds the SECRETS for the order-fulfillment example: a mesh peer that embeds the J3nna
// encrypted vault (export-grade DES-56 at rest by default, passphrase-derived key; AES-256-GCM via vault.WithCipher) and exposes ONE tool, `secret.sign`. It
// signs a shipment-authorization with the carrier HMAC key BY HANDLE and returns only the signature — the
// key itself is decrypted in-process and NEVER crosses the mesh, which is the whole point of the vault: a
// secret is used, never handed out. Fulfillment calls this to authorize each shipment. Part of the example.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/J3nnaAI/mesh/agentkit"
	"github.com/J3nnaAI/mesh/vault"
)

// waitForDeps blocks until the console and every gossip seed (the room-agent) answer, so this service only
// goes live once its dependencies are up.
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

const carrierHandle = "carrier-hmac"

var vlt *vault.Vault

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

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Encrypted secret store. The key is derived from OFX_VAULT_PASSPHRASE (PBKDF2); without it the vault
	// stays locked and refuses to serve.
	v, err := vault.Open(env("VSVC_VAULT", "ofx-vault.enc"), "OFX_VAULT")
	if err != nil {
		log.Fatalf("vault-service: open vault: %v", err)
	}
	vlt = v
	if vlt.Locked() {
		log.Fatalf("vault-service: vault is LOCKED — set OFX_VAULT_PASSPHRASE")
	}
	// Provision the carrier signing key once (encrypted at rest). Never logged.
	if _, err := vlt.Get(carrierHandle); err != nil {
		if err := vlt.Put(carrierHandle, env("VSVC_CARRIER_KEY", "dev-carrier-signing-key-change-me"),
			"carrier shipment-authorization HMAC key"); err != nil {
			log.Fatalf("vault-service: provision secret: %v", err)
		}
		log.Printf("vault-service: provisioned secret %q (encrypted at rest, never exposed)", carrierHandle)
	}

	console := env("VSVC_CONSOLE", "http://127.0.0.1:18455")
	idFile := env("VSVC_IDENTITY", "vsvc.id")
	waitForDeps(ctx, "vault-service", console, envSeeds("VSVC_SEEDS"))
	log.Printf("vault-service: enrolling with console %s …", console)
	grant, root, err := agentkit.Enroll(ctx, console, "vault-service", idFile, 1, func(oob string) {
		log.Printf("vault-service: APPROVE enrollment — out-of-band code %s", oob)
	})
	if err != nil {
		log.Fatalf("vault-service: enroll: %v", err)
	}
	m, err := agentkit.Open(ctx, agentkit.Options{
		Advertise:     env("VSVC_ADVERTISE", "http://127.0.0.1:18491"),
		Listen:        env("VSVC_LISTEN", "127.0.0.1:18491"),
		Caps:          []string{"secrets"},
		Seeds:         envSeeds("VSVC_SEEDS"),
		InsecureTLS:   true,
		IdentityFile:  idFile,
		AuthorityRoot: root,
		Grant:         grant,
	})
	if err != nil {
		log.Fatalf("vault-service: open: %v", err)
	}
	defer m.Close()
	go agentkit.KeepFresh(ctx, m, console, root, 30*time.Second)

	str := map[string]any{"type": "string"}
	m.Node().RegisterTool("secret.sign",
		"Sign `data` with the secret at `handle` (HMAC-SHA256). Returns only the signature — the secret never leaves the vault.",
		map[string]any{"type": "object", "properties": map[string]any{"handle": str, "data": str}, "required": []string{"data"}},
		false, secretSign)
	log.Printf("vault-service: live — secret.sign serving (the carrier key stays sealed) node %s…", m.ID()[:8])
	<-ctx.Done()
}

func secretSign(args map[string]any) (string, any, error) {
	handle, _ := args["handle"].(string)
	if handle == "" {
		handle = carrierHandle
	}
	data, _ := args["data"].(string)
	secret, err := vlt.Get(handle) // in-process plaintext — NEVER returned over the mesh
	if err != nil {
		return "", nil, err
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(data))
	return "signed", map[string]any{"handle": handle, "signature": hex.EncodeToString(mac.Sum(nil))}, nil
}
