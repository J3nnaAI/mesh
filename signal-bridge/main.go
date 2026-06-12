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

// Command signal-bridge is the mesh's events + webhooks component. It is an authorized mesh peer that:
//
//   - is an EVENT HUB: authorized peers publish structured signals (signal.publish) and poll them
//     (signal.poll) — pub/sub by topic, in-band on the mesh;
//   - fires OUTBOUND webhooks: on each published signal it POSTs matching subscriptions to external URLs,
//     HMAC-SHA256-signed so receivers can verify authenticity;
//   - accepts INBOUND webhooks: an external system POSTs /hook/<id> (HMAC-verified) to raise a mesh signal.
//
// Subscriptions + their HMAC secrets live in an encrypted vault and are managed over an authz-gated HTTP
// API (the console UI drives it). The bridge runs autonomously from cached state — the console is never on
// the hot path (root-not-hub). Part of J3nna Mesh; see docs/.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/J3nnaAI/mesh/vault"
	"github.com/J3nnaAI/mesh/agentkit"
)

const subsHandle = "webhook-subs"

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

// Signal is one event on the bus.
type Signal struct {
	Seq       int             `json:"seq"`
	Topic     string          `json:"topic"`
	Data      json.RawMessage `json:"data"`
	Source    string          `json:"source"`
	UnixMilli int64           `json:"unix_milli"`
}

// subscription is an outbound webhook: topic (or "*") → URL, HMAC-signed with a secret held in the vault
// under handle "whsec:<id>".
type subscription struct {
	ID    string `json:"id"`
	Topic string `json:"topic"`
	URL   string `json:"url"`
}

type bridge struct {
	mu  sync.Mutex
	log []Signal
	seq int
	vlt *vault.Vault
	hc  *http.Client
}

func (b *bridge) subs() []subscription {
	raw, err := b.vlt.Get(subsHandle)
	if err != nil || strings.TrimSpace(raw) == "" {
		return nil
	}
	var s []subscription
	_ = json.Unmarshal([]byte(raw), &s)
	return s
}

func (b *bridge) saveSubs(s []subscription) error {
	data, _ := json.Marshal(s)
	return b.vlt.Put(subsHandle, string(data), "outbound webhook subscriptions")
}

// publish appends a signal and fires matching outbound webhooks (async).
func (b *bridge) publish(topic, source string, data json.RawMessage) Signal {
	b.mu.Lock()
	b.seq++
	s := Signal{Seq: b.seq, Topic: topic, Data: data, Source: source, UnixMilli: time.Now().UnixMilli()}
	b.log = append(b.log, s)
	if len(b.log) > 1000 {
		b.log = b.log[len(b.log)-1000:]
	}
	b.mu.Unlock()
	go b.fireWebhooks(s)
	return s
}

func (b *bridge) fireWebhooks(s Signal) {
	body, _ := json.Marshal(s)
	for _, sub := range b.subs() {
		if sub.Topic != "*" && sub.Topic != s.Topic {
			continue
		}
		secret, err := b.vlt.Get("whsec:" + sub.ID)
		if err != nil {
			log.Printf("signal-bridge: missing secret for sub %s", sub.ID)
			continue
		}
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		req, _ := http.NewRequest(http.MethodPost, sub.URL, strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Signal-Topic", s.Topic)
		req.Header.Set("X-Signal-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
		resp, err := b.hc.Do(req)
		if err != nil {
			log.Printf("signal-bridge: webhook %s POST failed: %v", sub.ID, err)
			continue
		}
		resp.Body.Close()
	}
}

func (b *bridge) poll(topic string, since int) []Signal {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []Signal
	for _, s := range b.log {
		if s.Seq > since && (topic == "" || topic == s.Topic) {
			out = append(out, s)
		}
	}
	return out
}

func mustToken() string {
	x := make([]byte, 16)
	_, _ = rand.Read(x)
	return hex.EncodeToString(x)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func loopback(r *http.Request) bool {
	h := r.RemoteAddr
	if i := strings.LastIndex(h, ":"); i >= 0 {
		h = h[:i]
	}
	return h == "127.0.0.1" || h == "::1" || h == "[::1]"
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	vlt, err := vault.Open(envOr("SIGNAL_VAULT", "signal-vault.enc"), "SIGNAL_VAULT")
	if err != nil {
		log.Fatalf("signal-bridge: vault: %v", err)
	}
	if vlt.Locked() {
		log.Printf("signal-bridge: vault LOCKED (set SIGNAL_VAULT_KEYFILE/KEY/PASSPHRASE) — webhook management disabled")
	}
	b := &bridge{vlt: vlt, hc: &http.Client{Timeout: 15 * time.Second}}

	opts := agentkit.Options{
		Advertise: envOr("SIGNAL_ADVERTISE", "http://127.0.0.1:8483"),
		Listen:    envOr("SIGNAL_LISTEN", "0.0.0.0:8483"),
		Caps: []string{"signals"}, Discover: envBool("SIGNAL_DISCOVER", true), InsecureTLS: true,
		IdentityFile: envOr("SIGNAL_IDENTITY", "signal-bridge.id"),
		Seeds:     envSeeds("SIGNAL_SEEDS"),
	}
	console := strings.TrimSpace(os.Getenv("SIGNAL_CONSOLE"))
	if console != "" {
		grant, root, err := agentkit.Enroll(ctx, console, "signal-bridge", opts.IdentityFile, 3, func(oob string) {
			log.Printf("signal-bridge: APPROVE this enrollment in the console — out-of-band code %s", oob)
		})
		if err != nil {
			log.Fatalf("signal-bridge: enroll: %v", err)
		}
		opts.AuthorityRoot, opts.Grant = root, grant
		log.Printf("signal-bridge: enrolled — grant %s…", grant.ID[:8])
	}

	m, err := agentkit.Open(ctx, opts)
	if err != nil {
		log.Fatalf("signal-bridge: open mesh: %v", err)
	}
	defer m.Close()
	if console != "" && opts.AuthorityRoot != nil {
		go agentkit.KeepFresh(ctx, m, console, opts.AuthorityRoot, 30*time.Second)
	}

	// Event-hub tools any authorized peer can call.
	node := m.Node()
	node.RegisterTool("signal.publish",
		"Publish a structured signal/event on the mesh. args: topic (string), data (object).",
		map[string]any{"type": "object", "properties": map[string]any{
			"topic": map[string]any{"type": "string"}, "data": map[string]any{"type": "object"},
		}, "required": []string{"topic"}}, false,
		func(args map[string]any) (string, any, error) {
			topic, _ := args["topic"].(string)
			data, _ := json.Marshal(args["data"])
			s := b.publish(strings.TrimSpace(topic), "mesh", data)
			return "published", map[string]any{"seq": s.Seq}, nil
		})
	node.RegisterTool("signal.poll",
		"Poll signals since a sequence cursor. args: topic (optional), since (int).",
		map[string]any{"type": "object", "properties": map[string]any{
			"topic": map[string]any{"type": "string"}, "since": map[string]any{"type": "integer"},
		}}, false,
		func(args map[string]any) (string, any, error) {
			topic, _ := args["topic"].(string)
			since := 0
			if f, ok := args["since"].(float64); ok {
				since = int(f)
			}
			out := b.poll(topic, since)
			return strconv.Itoa(len(out)) + " signals", map[string]any{"signals": out}, nil
		})

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })

	// Webhook management (loopback/console-gated): register/list/revoke OUTBOUND subscriptions. The HMAC
	// secret is generated here and shown ONCE so the receiver can verify; only the bridge + receiver hold it.
	mux.HandleFunc("/webhooks", func(w http.ResponseWriter, r *http.Request) {
		if !loopback(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, map[string]any{"subscriptions": b.subs()})
		case http.MethodPost:
			var in struct{ Topic, URL string }
			if json.NewDecoder(r.Body).Decode(&in) != nil || strings.TrimSpace(in.URL) == "" {
				http.Error(w, "topic + url required", http.StatusBadRequest)
				return
			}
			sub := subscription{ID: mustToken(), Topic: strings.TrimSpace(in.Topic), URL: strings.TrimSpace(in.URL)}
			if sub.Topic == "" {
				sub.Topic = "*"
			}
			secret := mustToken() + mustToken()
			if err := b.vlt.Put("whsec:"+sub.ID, secret, "webhook hmac secret"); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if err := b.saveSubs(append(b.subs(), sub)); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, map[string]any{"id": sub.ID, "topic": sub.Topic, "url": sub.URL,
				"secret": secret, "note": "configure your receiver with this HMAC secret — shown once"})
		default:
			http.Error(w, "GET or POST", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/webhooks/", func(w http.ResponseWriter, r *http.Request) {
		if !loopback(r) || r.Method != http.MethodDelete {
			http.Error(w, "unauthorized DELETE only", http.StatusUnauthorized)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/webhooks/")
		var keep []subscription
		for _, s := range b.subs() {
			if s.ID != id {
				keep = append(keep, s)
			}
		}
		_ = b.vlt.Delete("whsec:" + id)
		_ = b.saveSubs(keep)
		w.WriteHeader(http.StatusNoContent)
	})

	// Inbound webhook: external POST /hook/<sub-id> with X-Signal-Signature (HMAC of body using the sub's
	// secret) raises a mesh signal on the sub's topic. HMAC-verified — fail closed.
	mux.HandleFunc("/hook/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/hook/")
		secret, err := b.vlt.Get("whsec:" + id)
		if err != nil {
			http.Error(w, "unknown hook", http.StatusNotFound)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if !hmac.Equal([]byte(want), []byte(r.Header.Get("X-Signal-Signature"))) {
			log.Printf("AUDIT hook: rejected inbound webhook on %q (bad HMAC signature) from %s", id, r.RemoteAddr)
			http.Error(w, "bad signature", http.StatusUnauthorized)
			return
		}
		topic := "*"
		for _, s := range b.subs() {
			if s.ID == id {
				topic = s.Topic
			}
		}
		s := b.publish(topic, "webhook:"+id, body)
		writeJSON(w, map[string]any{"published": s.Seq, "topic": topic})
	})

	httpAddr := envOr("SIGNAL_HTTP", "127.0.0.1:8484")
	go func() {
		log.Printf("signal-bridge: HTTP (webhooks + inbound hooks) on %s", httpAddr)
		if err := http.ListenAndServe(httpAddr, mux); err != nil {
			log.Printf("signal-bridge: http: %v", err)
		}
	}()
	log.Printf("signal-bridge up: id=%s caps=[signals] mesh=%s authz=%v", m.ID(), m.SelfMCP(), opts.AuthorityRoot != nil)
	<-ctx.Done()
}

// envSeeds parses a comma-separated list of bootstrap peer base URLs. On networks without UDP multicast
// (Docker bridges, Kubernetes pods) peers discover one another via these gossip seeds instead.
func envSeeds(k string) []string {
	var out []string
	for _, u := range strings.Split(os.Getenv(k), ",") {
		if u = strings.TrimSpace(u); u != "" {
			out = append(out, u)
		}
	}
	return out
}

// envBool reads a boolean env var (1/true/yes = true). Used to toggle multicast discovery off in cloud /
// Kubernetes environments where peers find each other via gossip seeds instead.
func envBool(k string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
}
