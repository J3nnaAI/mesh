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

// Command console is the mesh's control plane — the ROOT of trust, never a hub. It originates identity
// and authorization (enroll, approve, grant, revoke) and hands clients capability credentials they
// wield autonomously; it is not on the hot path of any peer-to-peer call. This first cut establishes
// the identity foundation: an encrypted token→identity store and a Users management API (mint / list /
// revoke). Enrollment, root-signing of grants, and the Agents surface build on top of this.
//
// See docs/ARCHITECTURE.md and docs/SECURITY.md for the full model.
package main

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/J3nnaAI/mesh/jip"
	"github.com/J3nnaAI/mesh/vault"
)

// Version is the console's semantic version. Releases follow semver; the wire protocol enforces
// major-compatibility between peers (see the ADR).
const Version = "0.1.0"

func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func main() {
	addr := envOr("CONSOLE_ADDR", "127.0.0.1:8455")
	vaultPath := envOr("CONSOLE_VAULT", "console-vault.enc")

	vlt, err := vault.Open(vaultPath, "CONSOLE_VAULT")
	if err != nil {
		log.Fatalf("console: vault: %v", err)
	}
	mgmtVault = vlt
	if vlt.Locked() {
		log.Printf("console: vault LOCKED (set CONSOLE_VAULT_KEYFILE/KEY/PASSPHRASE) — user management disabled until unlocked")
	}
	seedConsoleUsers(vlt, os.Getenv("CONSOLE_USERS"))

	// The authority: root of trust. Issues/verifies signed grants; publishes a signed CRL. Peers verify
	// grants OFFLINE against the root pubkey served at /authority — the console is never on the hot path.
	rootKeyPath := envOr("CONSOLE_ROOT_KEY", "console-root.key")
	// Fail-closed guard for orchestrated/clustered deploys: when CONSOLE_ROOT_KEY_REQUIRED is set, REFUSE
	// to start if the root key is absent rather than generating a fresh one. A generated key would be a
	// rogue authority no peer can verify, and (on a reschedule without persistence, or a mismounted
	// Secret) would silently invalidate every existing grant in the mesh. Provision the key (e.g. a
	// Kubernetes Secret / shared across console replicas) and set this in production.
	if envBool("CONSOLE_ROOT_KEY_REQUIRED", false) {
		if _, statErr := os.Stat(rootKeyPath); statErr != nil {
			log.Fatalf("console: CONSOLE_ROOT_KEY_REQUIRED is set but the root key at %q is missing/unreadable (%v) — refusing to generate a new authority. Provision the key (e.g. a Secret) or unset CONSOLE_ROOT_KEY_REQUIRED for first-run generation.", rootKeyPath, statErr)
		}
	}
	auth, err := openAuthority(rootKeyPath, envOr("CONSOLE_CRL", "console-crl.json"))
	if err != nil {
		log.Fatalf("console: authority: %v", err)
	}

	// Optional telemetry: the console is NOT a jip Node, so it emits directly through an Observer. When
	// JIP_TELEMETRY_URL is set, POST each control-plane event (grant issued/renewed) to the collector;
	// otherwise obs stays nil and every Observe call below is a no-op.
	var obs jip.Observer
	if url := strings.TrimSpace(os.Getenv("JIP_TELEMETRY_URL")); url != "" {
		obs = jip.NewHTTPObserver(url)
	}

	mux := http.NewServeMux()

	// Enrollment (the single untrusted ingress) + the authority surface.
	newEnrollStore().install(mux, auth, obs)
	mux.HandleFunc("/authority", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"root_public_key": base64.StdEncoding.EncodeToString(auth.RootPub()),
			"protocol_major":  jip.ProtocolMajor,
			"version":         Version,
		})
	})
	mux.HandleFunc("/crl", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, auth.CRL()) })

	// Grant renewal — a cryptographically self-authenticating ingress (no operator action). An already-
	// approved peer POSTs its current grant + a node-key signature; the authority re-issues before expiry
	// so long-running peers stay in discovery without the console ever being on the hot path. Revocation
	// dominates: a revoked or expired grant cannot be renewed (RenewGrant enforces). See docs/SECURITY.md.
	mux.HandleFunc("/renew", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req jip.RenewalRequest
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		if err := jip.VerifyRenewal(req, time.Now()); err != nil { // proves possession of the pinned node key
			log.Printf("AUDIT renew: rejected request for grant %s: %s", maskToken(req.Grant.ID), safeErr(err))
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		g, err := auth.RenewGrant(req.Grant) // re-checks our signature + expiry + CRL
		if err != nil {
			log.Printf("AUDIT renew: declined grant %s for %s: %s", maskToken(req.Grant.ID), maskToken(req.Grant.Subject), safeErr(err))
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		log.Printf("AUDIT renew: re-issued grant %s for %s (tier %d) until %s",
			maskToken(g.ID), maskToken(g.Subject), g.Tier, time.Unix(g.NotAfter, 0).UTC().Format(time.RFC3339))
		if obs != nil {
			obs.Observe(jip.Event{Kind: jip.EvGrant, Peer: g.Subject, Outcome: "ok", Detail: "renewed", Span: jip.NewSpanID()})
		}
		writeJSON(w, g)
	})
	mux.HandleFunc("/grants/", func(w http.ResponseWriter, r *http.Request) {
		if !mayManage(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodDelete {
			http.Error(w, "DELETE only", http.StatusMethodNotAllowed)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/grants/")
		if err := auth.Revoke(id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("console: revoked grant %s", maskToken(id))
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	mux.HandleFunc("/version", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"console": Version})
	})

	// Who the caller is, as PROVEN by their token (or loopback) — the identity the mesh carries for
	// provenance.
	mux.HandleFunc("/whoami", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"identity": userIdentity(r), "can_manage": mayManage(r)})
	})

	// Users: the console's human-identity management. Approving a person mints a bearer token bound to
	// their identity; multiple tokens may map to one identity (several devices / delegates). Tokens are
	// shown ONCE at creation and only their mapping is stored.
	mux.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		if !mayManage(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodGet:
			// List identities + masked token fingerprints — never the full tokens.
			out := []map[string]string{}
			for tok, id := range consoleUsersMap() {
				out = append(out, map[string]string{"identity": id, "token": maskToken(tok)})
			}
			writeJSON(w, map[string]any{"users": out})
		case http.MethodPost:
			var b struct{ Identity, Token string }
			if json.NewDecoder(r.Body).Decode(&b) != nil || strings.TrimSpace(b.Identity) == "" {
				http.Error(w, "identity required", http.StatusBadRequest)
				return
			}
			tok := strings.TrimSpace(b.Token)
			if tok == "" {
				if tok, err = newToken(); err != nil {
					http.Error(w, "token mint failed", http.StatusInternalServerError)
					return
				}
			}
			m := consoleUsersMap()
			if m == nil {
				m = map[string]string{}
			}
			m[tok] = strings.TrimSpace(b.Identity)
			if err := putConsoleUsers(m); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			log.Printf("console: issued token for identity %q (now %d tokens)", b.Identity, len(m))
			writeJSON(w, map[string]any{"identity": b.Identity, "token": tok, "note": "store this token now — it is shown only once"})
		default:
			http.Error(w, "GET or POST", http.StatusMethodNotAllowed)
		}
	})

	// Revoke a specific token: DELETE /users/<token>. Effective immediately for new requests.
	mux.HandleFunc("/users/", func(w http.ResponseWriter, r *http.Request) {
		if !mayManage(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodDelete {
			http.Error(w, "DELETE only", http.StatusMethodNotAllowed)
			return
		}
		tok := strings.TrimPrefix(r.URL.Path, "/users/")
		m := consoleUsersMap()
		if _, ok := m[tok]; !ok {
			http.Error(w, "no such token", http.StatusNotFound)
			return
		}
		id := m[tok]
		delete(m, tok)
		if err := putConsoleUsers(m); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("console: revoked a token for identity %q (now %d tokens)", id, len(m))
		w.WriteHeader(http.StatusNoContent)
	})

	// Vault handle metadata (never values); both read and write are manage-gated — even handle NAMES are
	// operational metadata that shouldn't leak to an unauthenticated caller on a non-loopback bind.
	mux.HandleFunc("/vault", func(w http.ResponseWriter, r *http.Request) {
		if !mayManage(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, map[string]any{"locked": vlt.Locked(), "handles": vlt.List()})
		case http.MethodPost:
			var b struct{ Handle, Value, Desc string }
			if json.NewDecoder(r.Body).Decode(&b) != nil {
				http.Error(w, "bad body", http.StatusBadRequest)
				return
			}
			if err := vlt.Put(b.Handle, b.Value, b.Desc); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, map[string]any{"stored": b.Handle}) // handle only, never the value
		default:
			http.Error(w, "GET or POST", http.StatusMethodNotAllowed)
		}
	})

	// The management UI (embedded static SPA) — mounted last so the API routes above take precedence.
	if err := mountUI(mux); err != nil {
		log.Printf("console: UI not mounted: %v", err)
	}

	log.Printf("console %s listening on %s (vault=%s, locked=%v)", Version, addr, vaultPath, vlt.Locked())
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("console: serve: %v", err)
	}
}

// maskToken shows only a short fingerprint of a token for listings — never the full value.
func maskToken(tok string) string {
	if len(tok) <= 8 {
		return "…"
	}
	return logSafe(tok[:4] + "…" + tok[len(tok)-4:])
}

// envBool reads a boolean env var (1/true/yes = true).
func envBool(k string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
}

// logSafe strips CR/LF and other C0 control characters from caller-controlled strings so a malicious peer
// cannot forge or break audit/log lines (log injection). Tabs are preserved.
func logSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' {
			return r
		}
		if r == '\n' || r == '\r' || r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

// safeErr is logSafe over an error message (nil-safe), for audit logs.
func safeErr(err error) string {
	if err == nil {
		return "<nil>"
	}
	return logSafe(err.Error())
}
