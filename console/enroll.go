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

package main

// Enrollment — the single ingress for the untrusted. A client (human device or agent) submits a
// request and gets back a request id + an out-of-band code; the operator sees the request in the
// console, matches the code, and approves or denies. On approval a USER gets a bearer token bound to
// their identity; an AGENT gets an authority-signed grant bound to its node id + public key. Email is
// a human-readable LABEL — the approval (with OOB match) is the actual authentication, so a typed
// address can never become access on its own.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/J3nnaAI/mesh/jip"
)

type enrollReq struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"` // "user" | "agent"
	ClientName string `json:"client_name"`
	Email      string `json:"email,omitempty"`      // user label
	Subject    string `json:"subject,omitempty"`    // agent node id
	PublicKey  []byte `json:"public_key,omitempty"` // agent ed25519 pubkey
	Tier       int    `json:"tier,omitempty"`
	OOB        string `json:"oob"`
	CreatedAt  int64  `json:"created_at"`
	Status     string `json:"status"` // "pending" | "approved" | "denied"
	// credential delivered to the requester on approval (token for users; grant for agents)
	Token string     `json:"token,omitempty"`
	Grant *jip.Grant `json:"grant,omitempty"`
}

type enrollStore struct {
	mu   sync.Mutex
	reqs map[string]*enrollReq
}

func newEnrollStore() *enrollStore { return &enrollStore{reqs: map[string]*enrollReq{}} }

func oobCode() string {
	n := func() int { v, _ := rand.Int(rand.Reader, big.NewInt(1000)); return int(v.Int64()) }
	return fmt.Sprintf("%03d-%03d", n(), n())
}

// installEnroll wires the enrollment routes. POST /enroll is OPEN (untrusted ingress); the
// pending/approve/deny operations are manage-gated; GET /enroll/<id> lets the requester poll for its
// credential (it holds the id).
func (es *enrollStore) install(mux *http.ServeMux, auth *authority, obs jip.Observer) {
	mux.HandleFunc("/enroll", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var b struct {
			Kind       string `json:"kind"`
			ClientName string `json:"client_name"`
			Email      string `json:"email"`
			Subject    string `json:"subject"`
			PublicKey  string `json:"public_key"`
			Tier       int    `json:"tier"`
		}
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		kind := strings.ToLower(strings.TrimSpace(b.Kind))
		if kind != "user" && kind != "agent" {
			http.Error(w, "kind must be user or agent", http.StatusBadRequest)
			return
		}
		req := &enrollReq{
			ID: mustToken(), Kind: kind, ClientName: strings.TrimSpace(b.ClientName),
			Email: strings.TrimSpace(b.Email), Subject: strings.TrimSpace(b.Subject),
			Tier: b.Tier, OOB: oobCode(), CreatedAt: time.Now().Unix(), Status: "pending",
		}
		if kind == "agent" {
			pk, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b.PublicKey))
			if err != nil || len(pk) != 32 {
				http.Error(w, "agent enroll requires base64 public_key (32 bytes)", http.StatusBadRequest)
				return
			}
			req.PublicKey = pk
		}
		es.mu.Lock()
		es.reqs[req.ID] = req
		// DEV-ONLY: with CONSOLE_DEV_AUTOAPPROVE set, agent enrollments are approved on submission — no
		// operator out-of-band confirmation. For self-running examples / CI only; NEVER set in production.
		if kind == "agent" && os.Getenv("CONSOLE_DEV_AUTOAPPROVE") != "" {
			if g, err := auth.IssueGrant(req.Subject, req.PublicKey, req.Tier, nil); err == nil {
				req.Grant = &g
				req.Status = "approved"
				log.Printf("AUDIT enroll: DEV-AUTOAPPROVE issued grant to agent %q (subject %s)",
					logSafe(req.ClientName), maskToken(req.Subject))
				if obs != nil {
					obs.Observe(jip.Event{Kind: jip.EvGrant, Peer: g.Subject, Outcome: "ok", Detail: "issued", Span: jip.NewSpanID()})
				}
			}
		}
		es.mu.Unlock()
		// The requester displays this OOB next to the one the operator sees in the console.
		writeJSON(w, map[string]any{"request_id": req.ID, "oob": req.OOB, "status": "pending"})
	})

	mux.HandleFunc("/enroll/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/enroll/")
		if rest == "pending" {
			if !mayManage(r) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			es.mu.Lock()
			out := []enrollReq{}
			for _, q := range es.reqs {
				if q.Status == "pending" {
					v := *q
					v.PublicKey = nil // don't echo key bytes in the list
					v.Token, v.Grant = "", nil
					out = append(out, v)
				}
			}
			es.mu.Unlock()
			writeJSON(w, map[string]any{"pending": out})
			return
		}
		id, action, _ := strings.Cut(rest, "/")
		es.mu.Lock()
		req := es.reqs[id]
		es.mu.Unlock()
		if req == nil {
			http.Error(w, "no such request", http.StatusNotFound)
			return
		}
		switch action {
		case "": // GET — the requester polls for status + credential
			writeJSON(w, req)
		case "approve":
			if !mayManage(r) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			var b struct{ Oob string }
			_ = json.NewDecoder(r.Body).Decode(&b)
			if strings.TrimSpace(b.Oob) != req.OOB {
				http.Error(w, "oob mismatch — confirm the code shown by the requester", http.StatusBadRequest)
				return
			}
			es.mu.Lock()
			defer es.mu.Unlock()
			if req.Kind == "user" {
				tok, err := newToken()
				if err != nil {
					http.Error(w, "token mint failed", http.StatusInternalServerError)
					return
				}
				id := req.Email
				if id == "" {
					id = req.ClientName
				}
				m := consoleUsersMap()
				if m == nil {
					m = map[string]string{}
				}
				m[tok] = id
				if err := putConsoleUsers(m); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				req.Token = tok
			} else {
				g, err := auth.IssueGrant(req.Subject, req.PublicKey, req.Tier, nil)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				req.Grant = &g
				log.Printf("AUDIT enroll: issued grant %s to agent %q (subject %s, tier %d)",
					maskToken(g.ID), req.ClientName, maskToken(req.Subject), req.Tier)
				// Telemetry: a grant was issued to the enrolling node (nil-safe — console isn't a jip Node).
				if obs != nil {
					obs.Observe(jip.Event{Kind: jip.EvGrant, Peer: g.Subject, Outcome: "ok", Detail: "issued", Span: jip.NewSpanID()})
				}
			}
			req.Status = "approved"
			log.Printf("AUDIT enroll: approved %s request %q (%s)", req.Kind, req.ClientName, maskToken(req.ID))
			writeJSON(w, map[string]any{"status": "approved"})
		case "deny":
			if !mayManage(r) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			es.mu.Lock()
			req.Status = "denied"
			es.mu.Unlock()
			log.Printf("AUDIT enroll: denied %s request %q (%s)", req.Kind, req.ClientName, maskToken(req.ID))
			writeJSON(w, map[string]any{"status": "denied"})
		default:
			http.Error(w, "unknown action", http.StatusNotFound)
		}
	})
}

func mustToken() string {
	t, _ := newToken()
	return t
}
