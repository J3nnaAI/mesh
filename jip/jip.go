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

// mcpmesh — a tiny decentralized peer mesh for MCP services.
//
// Each process is a Node with:
//   - an ed25519 keypair and a v4 UUID (its identity)
//   - a list of capabilities and an HTTP endpoint
//   - a Registry of presence records it has learned about
//   - a gossip loop that periodically push-pulls its registry with one
//     random known peer
//   - an MCP JSON-RPC endpoint at /mcp exposing its capabilities as tools
//
// Trust model: each node is the sole authority on its own PresenceRecord
// because only it holds the private key needed to sign one. Conflict
// resolution between two records claiming the same UUID is by signature:
// the record that Verify()s against the pubkey we first saw for that UUID
// wins; anything that fails verification is dropped. Later heartbeats
// from the legitimate owner replace earlier ones.
//
// Stdlib only. Run multiple instances on different ports and point each
// at the previous one with -seed to watch the mesh converge.
//
//	go run . -listen :9001 -caps echo,clock
//	go run . -listen :9002 -seed http://127.0.0.1:9001 -caps echo
//	go run . -listen :9003 -seed http://127.0.0.1:9002 -caps clock
//
// Inspect a node:  curl localhost:9001/peers | jq
//
//	Call its MCP:    curl -X POST localhost:9001/mcp -H 'Content-Type: application/json' \
//	                   -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
package jip

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Identity & presence records
// ---------------------------------------------------------------------------

// UUID is an RFC 4122 v4 identifier rendered as the canonical 36-char string.
// Typed string so it can be used directly as a map key.
type UUID string

// newUUID returns a fresh v4 UUID using crypto/rand.
func newUUID() (UUID, error) {
	var b [16]byte
	if _, err := cryptorand.Read(b[:]); err != nil {
		return "", fmt.Errorf("uuid: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return UUID(fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])), nil
}

// ProtocolVersion is the JIP wire version this node speaks. It is part
// of the signed presence payload, surfaced in MCP serverInfo and on the
// gossip envelope, so a peer (or a later JIP version) can negotiate.
// JIP/0.1 == this MCP-over-gossip mesh: ed25519 identity, push-pull
// gossip, MCP/JSON-RPC tool surface — the PoC line. The whole point is
// that it's generic enough for any device to implement with minimal
// boilerplate, which is why nothing here depends on a Go-specific
// encoding.
const ProtocolVersion = "JIP/0.1"

// Capability is a discovery label advertising something a node can do
// ("echo", "clock", "gpu.cuda"). It is a routing hint only — "ask this
// node about X". The *contract* for calling it (argument schema, result
// shape, whether it is access-restricted) lives at the MCP layer and is
// served by tools/list; see mcpTool. Keeping the label in the signed
// payload cheap means presence records stay small and any language can
// reproduce them.
type Capability string

// PresencePayload is the canonical, signable view of a node's announcement.
// Every field is part of the signature; anything outside this struct is
// untrusted metadata and MUST NOT influence merge decisions.
type PresencePayload struct {
	Protocol      string       `json:"protocol"` // e.g. "JIP/1.0"
	ID            UUID         `json:"id"`
	PublicKey     []byte       `json:"public_key"` // ed25519, 32 bytes
	Endpoint      string       `json:"endpoint"`   // e.g. "http://10.0.0.5:9000"
	MCPPath       string       `json:"mcp_path"`   // e.g. "/mcp"
	Capabilities  []Capability `json:"capabilities"`
	HeartbeatUnix int64        `json:"heartbeat_unix"`
	// Authorized-discovery fields. ProtocolMajor enables semver enforcement (peers reject incompatible
	// majors); Grant is the authority-signed authorization peers verify offline before admitting this
	// node. Both are covered by the owner's presence signature (see canonicalBytes).
	ProtocolMajor int    `json:"protocol_major,omitempty"`
	Grant         *Grant `json:"grant,omitempty"`
	// Alg is the presence signature's algorithm (crypto agility); empty == ed25519. Covered by the
	// signature so it can't be downgraded. Lets a post-quantum scheme be added without a breaking change.
	Alg string `json:"alg,omitempty"`
}

// PresenceRecord is a payload plus the owning node's signature over its
// canonical JSON. Records flow freely; receivers Verify() before trusting.
type PresenceRecord struct {
	Payload   PresencePayload `json:"payload"`
	Signature []byte          `json:"signature"`
}

// canonicalBytes returns a language-neutral, deterministic byte sequence
// for signing and verification.
//
// It deliberately does NOT use json.Marshal. Go's encoder emits struct
// fields in declaration order, which is a Go-specific accident: a JIP
// node written in Swift, Rust, or JS would have no way to reproduce that
// ordering reliably, so its signatures would never verify here and the
// "any device, minimal boilerplate" promise would be a lie. Instead we
// define an explicit framing every language can implement in a few
// lines:
//
//	bytes := proto‖id‖pubkey‖endpoint‖mcp_path‖caps‖heartbeat
//
// where ‖ concatenates fields and every variable-length field is
// prefixed with its length as a big-endian uint32. Capabilities are
// sorted before framing so set order never changes the signature; the
// capability count is a uint32, each entry length-prefixed. Heartbeat is
// a big-endian uint64. No JSON, no map iteration order, no float
// formatting — nothing locale- or language-dependent.
func (p PresencePayload) canonicalBytes() ([]byte, error) {
	var b bytes.Buffer
	field := func(x []byte) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(x)))
		b.Write(n[:])
		b.Write(x)
	}
	field([]byte(p.Protocol))
	field([]byte(sigAlg(p.Alg))) // signature algorithm — covered so it can't be downgraded
	field([]byte(p.ID))
	field(p.PublicKey)
	field([]byte(p.Endpoint))
	field([]byte(p.MCPPath))
	caps := append([]Capability(nil), p.Capabilities...)
	sort.Slice(caps, func(i, j int) bool { return caps[i] < caps[j] })
	var nc [4]byte
	binary.BigEndian.PutUint32(nc[:], uint32(len(caps)))
	b.Write(nc[:])
	for _, c := range caps {
		field([]byte(c))
	}
	var pm [4]byte
	binary.BigEndian.PutUint32(pm[:], uint32(p.ProtocolMajor))
	b.Write(pm[:])
	gid := ""
	if p.Grant != nil {
		gid = p.Grant.ID
	}
	field([]byte(gid))
	var hb [8]byte
	binary.BigEndian.PutUint64(hb[:], uint64(p.HeartbeatUnix))
	b.Write(hb[:])
	return b.Bytes(), nil
}

func sign(priv ed25519.PrivateKey, payload PresencePayload) (PresenceRecord, error) {
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return PresenceRecord{}, errors.New("sign: bad private key")
	}
	if len(payload.PublicKey) != ed25519.PublicKeySize ||
		!bytes.Equal(payload.PublicKey, pub) {
		return PresenceRecord{}, errors.New("sign: payload.PublicKey doesn't match signer")
	}
	buf, err := payload.canonicalBytes()
	if err != nil {
		return PresenceRecord{}, err
	}
	return PresenceRecord{Payload: payload, Signature: ed25519.Sign(priv, buf)}, nil
}

// Verify is the only trust check in the mesh. A valid signature over the
// payload, using the public key embedded *in* that payload, proves the
// holder of the corresponding private key authored this record. The
// pinned-key check in Registry then binds (UUID, pubkey) on first sight.
func (r PresenceRecord) Verify() error {
	if sigAlg(r.Payload.Alg) != SigAlgEd25519 {
		return errors.New("verify: unsupported signature algorithm")
	}
	if len(r.Payload.PublicKey) != ed25519.PublicKeySize {
		return errors.New("verify: pubkey size")
	}
	if len(r.Signature) != ed25519.SignatureSize {
		return errors.New("verify: signature size")
	}
	buf, err := r.Payload.canonicalBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(r.Payload.PublicKey), buf, r.Signature) {
		return errors.New("verify: bad signature")
	}
	return nil
}

// Self is the local node's identity plus its private signing material.
// Never serialised; only PresenceRecords derived from it leave the process.
type Self struct {
	ID       UUID
	Priv     ed25519.PrivateKey
	Pub      ed25519.PublicKey
	Endpoint string
	MCPPath  string
	Caps     []Capability
	grantMu  sync.RWMutex
	Grant    *Grant // this node's authority-signed authorization (nil until enrolled); guarded by grantMu
}

// setGrant atomically swaps this node's live grant. The gossip goroutine reads it each tick via
// signedPresence, so a renewal installed here rides out on the next presence broadcast.
func (s *Self) setGrant(g *Grant) {
	s.grantMu.Lock()
	s.Grant = g
	s.grantMu.Unlock()
}

// currentGrant returns the live grant under the read lock (a copy of the pointer).
func (s *Self) currentGrant() *Grant {
	s.grantMu.RLock()
	defer s.grantMu.RUnlock()
	return s.Grant
}

// identityBlob is the persisted node identity (stable id + ed25519 private key, base64). The private
// key never leaves the process except into this 0600 file the operator controls.
type identityBlob struct {
	ID   string `json:"id"`
	Priv string `json:"priv_b64"`
}

func newSelf(endpoint, mcpPath, identityPath string, caps []Capability) (*Self, error) {
	if mcpPath == "" {
		mcpPath = "/mcp"
	}
	mk := func(id UUID, priv ed25519.PrivateKey, pub ed25519.PublicKey) *Self {
		return &Self{ID: id, Priv: priv, Pub: pub, Endpoint: endpoint, MCPPath: mcpPath,
			Caps: append([]Capability(nil), caps...)}
	}
	// Load a persisted identity if present → STABLE id + key across restarts (required so a peer can
	// be cryptographically allow-listed by id). Corrupt/missing file falls through to generate.
	if identityPath != "" {
		if data, err := os.ReadFile(identityPath); err == nil {
			var b identityBlob
			if json.Unmarshal(data, &b) == nil && b.ID != "" {
				if raw, err := base64.StdEncoding.DecodeString(b.Priv); err == nil && len(raw) == ed25519.PrivateKeySize {
					priv := ed25519.PrivateKey(raw)
					pub, _ := priv.Public().(ed25519.PublicKey)
					return mk(UUID(b.ID), priv, pub), nil
				}
			}
		}
	}
	id, err := newUUID()
	if err != nil {
		return nil, err
	}
	pub, priv, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		return nil, err
	}
	if identityPath != "" {
		blob, _ := json.Marshal(identityBlob{ID: string(id), Priv: base64.StdEncoding.EncodeToString(priv)})
		if mkErr := os.MkdirAll(filepath.Dir(identityPath), 0o700); mkErr == nil {
			_ = os.WriteFile(identityPath, blob, 0o600)
		}
	}
	return mk(id, priv, pub), nil
}

// EnsureIdentity loads (or creates + persists, 0600) the ed25519 identity at path and returns its node
// id and public key — so a client can enroll with the console (the grant binds to this key) BEFORE
// opening the mesh, then Open with the SAME IdentityFile so its node uses the enrolled identity.
func EnsureIdentity(path string) (UUID, ed25519.PublicKey, error) {
	self, err := newSelf("", "", path, nil)
	if err != nil {
		return "", nil, err
	}
	return self.ID, self.Pub, nil
}

// signedPresence returns a freshly signed record stamped with now. Called
// each gossip tick so remote peers don't expire us.
func (s *Self) signedPresence(now time.Time) (PresenceRecord, error) {
	return sign(s.Priv, PresencePayload{
		Protocol:      ProtocolVersion,
		ID:            s.ID,
		PublicKey:     []byte(s.Pub),
		Endpoint:      s.Endpoint,
		MCPPath:       s.MCPPath,
		Capabilities:  append([]Capability(nil), s.Caps...),
		HeartbeatUnix: now.Unix(),
		ProtocolMajor: ProtocolMajor,
		Grant:         s.currentGrant(),
		Alg:           SigAlgEd25519,
	})
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

// Registry is the in-memory presence table. Safe for concurrent use.
type Registry struct {
	mu      sync.RWMutex
	records map[UUID]PresenceRecord
	// admit, when set, gates which incoming records may enter the registry (authorized discovery). A
	// non-nil error rejects the record — the peer stays invisible. nil = open discovery.
	admit func(PresenceRecord) error
	// pinnedKey records the first verified pubkey we ever saw for a UUID.
	// It's the only key permitted to author future records for that UUID.
	// Without this, anyone who picked a colliding UUID and signed with
	// their own key could displace the legitimate owner.
	pinnedKey map[UUID][]byte
	// audit logging for admit rejections (authorized discovery). logger nil = silent (open discovery).
	// rejLogged dedupes by (id→last reason) so a peer beaconing every interval logs once per reason,
	// not once per beacon.
	logger    *log.Logger
	rejLogged map[UUID]string
	// observer, when set, receives EvAdmit/EvReject telemetry on registry transitions. nil = no telemetry.
	observer Observer
}

func newRegistry(observer Observer) *Registry {
	return &Registry{
		records:   make(map[UUID]PresenceRecord),
		pinnedKey: make(map[UUID][]byte),
		rejLogged: make(map[UUID]string),
		observer:  observer,
	}
}

func (r *Registry) snapshot() []PresenceRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]PresenceRecord, 0, len(r.records))
	for _, rec := range r.records {
		out = append(out, cloneRecord(rec))
	}
	return out
}

// get returns a copy of the record pinned for id, if present. Used by the
// ACL to resolve a caller's pubkey when verifying a tools/call proof.
func (r *Registry) get(id UUID) (PresenceRecord, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rec, ok := r.records[id]
	if !ok {
		return PresenceRecord{}, false
	}
	return cloneRecord(rec), true
}

// digest returns the {id: heartbeat} summary the anti-entropy exchange
// sends instead of full records.
func (r *Registry) digest() map[UUID]int64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	d := make(map[UUID]int64, len(r.records))
	for id, rec := range r.records {
		d[id] = rec.Payload.HeartbeatUnix
	}
	return d
}

// delta returns the records this registry holds that the caller's digest
// is missing or has a staler heartbeat for — i.e. exactly what the caller
// needs to catch up, and nothing it already has.
func (r *Registry) delta(have map[UUID]int64) []PresenceRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]PresenceRecord, 0)
	for id, rec := range r.records {
		if hb, ok := have[id]; !ok || rec.Payload.HeartbeatUnix > hb {
			out = append(out, cloneRecord(rec))
		}
	}
	return out
}

// upsert stores a verified record. Entry point for the local node writing
// its own freshly signed record; gossip from peers goes through merge.
func (r *Registry) upsert(rec PresenceRecord) error {
	if err := rec.Verify(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_, err := r.applyLocked(rec)
	return err
}

// mergeResult summarises a batch merge for logging.
type mergeResult struct{ Accepted, Ignored, Rejected int }

// merge ingests a batch from a peer. Each record is verified independently;
// failures are counted but don't abort the batch. For two valid records
// claiming the same UUID, the one with the later heartbeat wins; ties keep
// the incumbent (avoids needless churn).
// evictRevoked removes every currently-registered peer whose presented grant id is now revoked.
func (r *Registry) evictRevoked(revoked func(string) bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, rec := range r.records {
		if rec.Payload.Grant != nil && revoked(rec.Payload.Grant.ID) {
			delete(r.records, id)
		}
	}
}

func (r *Registry) merge(incoming []PresenceRecord) mergeResult {
	var res mergeResult
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, rec := range incoming {
		if err := rec.Verify(); err != nil {
			res.Rejected++
			continue
		}
		if r.admit != nil { // authorized discovery: reject peers without a valid, current grant
			if err := r.admit(rec); err != nil {
				if r.logger != nil { // AUDIT: log the first rejection (and any reason change) per peer id
					id := rec.Payload.ID
					if r.rejLogged[id] != err.Error() {
						r.rejLogged[id] = err.Error()
						r.logger.Printf("AUDIT discovery: rejected peer %s: %s", logSafe(string(id)), safeErr(err))
						emit(r.observer, Event{Kind: EvReject, Peer: string(id), Outcome: "denied", Detail: err.Error(), Span: NewSpanID()})
					}
				}
				res.Rejected++
				continue
			}
			delete(r.rejLogged, rec.Payload.ID) // admitted now → re-log if it's ever rejected again
		}
		_, existed := r.records[rec.Payload.ID]
		changed, err := r.applyLocked(rec)
		switch {
		case err != nil:
			res.Rejected++
		case changed:
			res.Accepted++
			if !existed { // genuinely new peer admitted (not a heartbeat refresh of an existing one)
				emit(r.observer, Event{Kind: EvAdmit, Peer: string(rec.Payload.ID), Outcome: "ok", Span: NewSpanID()})
			}
		default:
			res.Ignored++
		}
	}
	return res
}

// applyLocked is the shared write path. Caller holds r.mu for writing.
// Enforces pinned-key and later-heartbeat-wins.
func (r *Registry) applyLocked(rec PresenceRecord) (bool, error) {
	id := rec.Payload.ID
	if pinned, ok := r.pinnedKey[id]; ok {
		if !bytes.Equal(pinned, rec.Payload.PublicKey) {
			return false, errors.New("pinned key mismatch")
		}
	} else {
		r.pinnedKey[id] = append([]byte(nil), rec.Payload.PublicKey...)
	}
	cur, exists := r.records[id]
	if exists && rec.Payload.HeartbeatUnix <= cur.Payload.HeartbeatUnix {
		return false, nil
	}
	r.records[id] = cloneRecord(rec)
	return true, nil
}

// expire drops records whose heartbeat is older than now-ttl. The local
// node's own record is exempt; the gossip loop refreshes it every tick
// anyway, but exempting it defends against clock skew at startup.
// The pinned key is intentionally retained: if the peer comes back later
// we still require the same identity.
func (r *Registry) expire(now time.Time, ttl time.Duration, selfID UUID) int {
	cutoff := now.Add(-ttl).Unix()
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, rec := range r.records {
		if id == selfID {
			continue
		}
		if rec.Payload.HeartbeatUnix < cutoff {
			delete(r.records, id)
			n++
		}
	}
	return n
}

// randomPeer returns the record of a random peer other than self. pick is
// injected so tests can be deterministic; production passes rand.IntN.
func (r *Registry) randomPeer(selfID UUID, pick func(n int) int) (PresenceRecord, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	cands := make([]PresenceRecord, 0, len(r.records))
	for id, rec := range r.records {
		if id == selfID {
			continue
		}
		cands = append(cands, rec)
	}
	if len(cands) == 0 {
		return PresenceRecord{}, false
	}
	return cloneRecord(cands[pick(len(cands))]), true
}

// cloneRecord deep-copies slice fields so callers can mutate the returned
// record without corrupting registry state.
func cloneRecord(rec PresenceRecord) PresenceRecord {
	out := rec
	out.Payload.PublicKey = append([]byte(nil), rec.Payload.PublicKey...)
	out.Signature = append([]byte(nil), rec.Signature...)
	if len(rec.Payload.Capabilities) > 0 {
		out.Payload.Capabilities = append([]Capability(nil), rec.Payload.Capabilities...)
	}
	return out
}

// ---------------------------------------------------------------------------
// Gossip
// ---------------------------------------------------------------------------

// envelope is the wire format for /gossip in both directions.
//
// Anti-entropy: instead of blindly shipping the whole registry every tick
// (O(N) records per exchange, O(N²) across the mesh per round), the
// requester sends a Digest — a cheap {id: heartbeat} map of everything it
// already knows — plus only its own freshly-signed record. The responder
// replies with just the records the requester is missing or has a stale
// heartbeat for. In steady state, when both sides are converged, the
// digests match and the delta is empty: a few hundred bytes per exchange
// regardless of mesh size. New or restarted nodes still converge in one
// round because their digest is empty, so the responder sends everything.
// (The digest itself is still O(N); a bucketed/Merkle digest is the next
// bound, noted for JIP/0.2.)
type envelope struct {
	Protocol string           `json:"protocol,omitempty"` // sender's JIP version
	Digest   map[UUID]int64   `json:"digest,omitempty"`   // id -> heartbeat the sender already holds
	Records  []PresenceRecord `json:"records,omitempty"`  // pushed records (requester: just self; responder: the delta)
}

// gossipConfig — zero values get defaults in newGossip.
type gossipConfig struct {
	Interval    time.Duration // default 3s
	TTL         time.Duration // default 30s; should be several * Interval
	DialTimeout time.Duration // default 2s
	Seeds       []string      // bootstrap peer URLs
	InsecureTLS bool          // skip TLS verification on gossip POSTs
	Logger      *log.Logger
}

func (c *gossipConfig) defaults() {
	if c.Interval == 0 {
		c.Interval = 3 * time.Second
	}
	if c.TTL == 0 {
		c.TTL = 30 * time.Second
	}
	if c.DialTimeout == 0 {
		c.DialTimeout = 2 * time.Second
	}
	if c.Logger == nil {
		c.Logger = log.Default()
	}
}

type gossipEngine struct {
	self *Self
	reg  *Registry
	cfg  gossipConfig
	http *http.Client
}

func newGossip(self *Self, reg *Registry, cfg gossipConfig) *gossipEngine {
	cfg.defaults()
	return &gossipEngine{
		self: self, reg: reg, cfg: cfg,
		http: jipHTTPClient(cfg.DialTimeout, cfg.InsecureTLS),
	}
}

func (e *gossipEngine) registerHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/gossip", e.handleGossip)
	mux.HandleFunc("/peers", e.handlePeers)
}

// handleGossip is the server side of anti-entropy push-pull. The caller
// POSTs its digest plus its own record; we merge what it pushed and reply
// with only the records its digest shows it is missing or stale on.
func (e *gossipEngine) handleGossip(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	// Cap the body. ~300 bytes per record * 1000 peers fits well under 1 MiB;
	// the hard limit blocks accidental abuse.
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var in envelope
	if err := json.Unmarshal(body, &in); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	res := e.reg.merge(in.Records)
	if res.Accepted > 0 || res.Rejected > 0 {
		e.cfg.Logger.Printf("gossip<- accepted=%d ignored=%d rejected=%d from=%s",
			res.Accepted, res.Ignored, res.Rejected, r.RemoteAddr)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(envelope{
		Protocol: ProtocolVersion,
		Digest:   e.reg.digest(),
		Records:  e.reg.delta(in.Digest), // only what the caller lacks
	})
}

// handlePeers is a read-only debug/discovery view. Stays a full snapshot —
// it's for humans (curl | jq), not the hot gossip path.
func (e *gossipEngine) handlePeers(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(envelope{Protocol: ProtocolVersion, Records: e.reg.snapshot()})
}

// run drives the ticker until ctx is cancelled. Contacts seeds immediately
// so the node doesn't wait a full interval to bootstrap.
func (e *gossipEngine) run(ctx context.Context) error {
	for _, seed := range e.cfg.Seeds {
		if err := e.exchangeWith(ctx, seed); err != nil {
			e.cfg.Logger.Printf("gossip seed %s: %v", seed, err)
		}
	}
	t := time.NewTicker(e.cfg.Interval)
	defer t.Stop()
	for {
		if err := e.tick(ctx); err != nil {
			e.cfg.Logger.Printf("gossip tick: %v", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

func (e *gossipEngine) tick(ctx context.Context) error {
	// 1. Refresh our own record so peers don't expire us.
	rec, err := e.self.signedPresence(time.Now())
	if err != nil {
		return fmt.Errorf("sign self: %w", err)
	}
	if err := e.reg.upsert(rec); err != nil {
		return fmt.Errorf("upsert self: %w", err)
	}
	// 2. Drop stale entries.
	if n := e.reg.expire(time.Now(), e.cfg.TTL, e.self.ID); n > 0 {
		e.cfg.Logger.Printf("gossip expired %d stale peers", n)
	}
	// 3. Pick a random peer and exchange.
	peer, ok := e.reg.randomPeer(e.self.ID, rand.IntN)
	if !ok {
		// Lonely — re-probe seeds in case the mesh restarted around us.
		for _, seed := range e.cfg.Seeds {
			if err := e.exchangeWith(ctx, seed); err == nil {
				break
			}
		}
		return nil
	}
	return e.exchangeWith(ctx, peer.Payload.Endpoint)
}

func (e *gossipEngine) exchangeWith(ctx context.Context, base string) error {
	// Send our digest (what we already know) plus only our own freshly
	// signed record. The peer replies with the records we're missing; it
	// learns/refreshes us from the pushed self-record. Everything else
	// propagates over subsequent rounds — classic anti-entropy.
	self, err := e.self.signedPresence(time.Now())
	if err != nil {
		return err
	}
	payload, err := json.Marshal(envelope{
		Protocol: ProtocolVersion,
		Digest:   e.reg.digest(),
		Records:  []PresenceRecord{self},
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/gossip", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	var in envelope
	if err := json.Unmarshal(body, &in); err != nil {
		return err
	}
	res := e.reg.merge(in.Records)
	if res.Accepted > 0 {
		e.cfg.Logger.Printf("gossip-> %s accepted=%d ignored=%d rejected=%d",
			base, res.Accepted, res.Ignored, res.Rejected)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Discovery via UDP multicast
// ---------------------------------------------------------------------------
//
// Seeding is a cheat: it assumes you already know somebody. For true zero-
// config discovery we use IP multicast — the stdlib primitive that's been
// sitting there the whole time. Every node:
//
//   1. Joins a well-known multicast group (default 239.42.42.42:9999, an
//      IPv4 administratively-scoped address — link/site local, never
//      routed across the internet).
//   2. Sends an ANNOUNCE every beaconInterval containing its own signed
//      PresenceRecord. Newcomers learn about it just by listening.
//   3. On startup, sends a QUERY once. Anyone who hears it unicasts an
//      ANNOUNCE back to the querier's address so the newcomer converges
//      in milliseconds instead of waiting a full beacon interval.
//
// The signature on every PresenceRecord means a beacon and a gossip body
// are interchangeable: same Verify, same merge, same registry. The only
// new attack surface is "flood the multicast group with garbage" — and
// since unverifiable frames are dropped before they touch the registry,
// the worst an attacker on the LAN can do is waste a bit of CPU on
// Ed25519 verification.
//
// Constraints we accept on purpose: multicast usually doesn't cross
// subnets, and some cloud networks block it outright. Where it does
// work (LAN, home lab, k8s with multicast enabled, IPv6 link-local) it
// gives us discovery for free. -seed remains available as a fallback
// for environments where multicast isn't an option.

const (
	beaconKindAnnounce = "announce"
	beaconKindQuery    = "query"
	// 8 KiB is generous for a single record (~300 B) and well under the
	// IPv4 minimum reassembly buffer. We never fragment on purpose.
	beaconMaxFrame = 8 * 1024
)

// beaconFrame is one UDP datagram on the multicast group. Record is
// always the sender's own signed presence; on a query, it lets the
// receiver immediately learn the querier and unicast a reply back.
type beaconFrame struct {
	Kind   string         `json:"kind"`
	Record PresenceRecord `json:"record"`
}

type discoveryConfig struct {
	Group    string        // multicast UDP address, e.g. "239.42.42.42:9999"
	Interval time.Duration // ANNOUNCE cadence; default 5s
	Logger   *log.Logger
}

func (c *discoveryConfig) defaults() {
	if c.Group == "" {
		c.Group = "239.42.42.42:9999"
	}
	if c.Interval == 0 {
		c.Interval = 5 * time.Second
	}
	if c.Logger == nil {
		c.Logger = log.Default()
	}
}

type discovery struct {
	self  *Self
	reg   *Registry
	cfg   discoveryConfig
	group *net.UDPAddr
	// send is a connected UDP socket for outbound multicast. recv is the
	// joined multicast listener. They are separate sockets because the
	// OS-level semantics differ: the sender just needs a route to the
	// group, the receiver needs to actually join it.
	send *net.UDPConn
	recv *net.UDPConn
}

func newDiscovery(self *Self, reg *Registry, cfg discoveryConfig) (*discovery, error) {
	cfg.defaults()
	group, err := net.ResolveUDPAddr("udp4", cfg.Group)
	if err != nil {
		return nil, fmt.Errorf("discovery: resolve group: %w", err)
	}
	if !group.IP.IsMulticast() {
		return nil, fmt.Errorf("discovery: %s is not a multicast address", cfg.Group)
	}
	// Sender: an unconnected UDP socket bound to an ephemeral port. We use
	// WriteToUDP(group) to publish; the kernel picks an outbound interface
	// per its routing table. For multi-homed hosts a SetMulticastInterface
	// call would be the right knob; we don't need it for the demo.
	send, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("discovery: open sender: %w", err)
	}
	// Receiver: join the multicast group. ListenMulticastUDP handles the
	// IP_ADD_MEMBERSHIP dance for us and enables SO_REUSEADDR so multiple
	// nodes on the same host can co-exist.
	recv, err := net.ListenMulticastUDP("udp4", nil, group)
	if err != nil {
		_ = send.Close()
		return nil, fmt.Errorf("discovery: join group: %w", err)
	}
	_ = recv.SetReadBuffer(1 << 20)
	return &discovery{self: self, reg: reg, cfg: cfg, group: group, send: send, recv: recv}, nil
}

// run drives both directions until ctx is cancelled. The listener loop
// runs in its own goroutine; the main loop ticks ANNOUNCE.
func (d *discovery) run(ctx context.Context) error {
	go d.listenLoop(ctx)

	// Kick things off: one immediate ANNOUNCE so peers learn us, plus a
	// QUERY so they reply with themselves without waiting a full interval.
	if err := d.sendBeacon(beaconKindAnnounce, nil); err != nil {
		d.cfg.Logger.Printf("discovery initial announce: %v", err)
	}
	if err := d.sendBeacon(beaconKindQuery, nil); err != nil {
		d.cfg.Logger.Printf("discovery initial query: %v", err)
	}

	t := time.NewTicker(d.cfg.Interval)
	defer t.Stop()
	defer d.send.Close()
	defer d.recv.Close()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			if err := d.sendBeacon(beaconKindAnnounce, nil); err != nil {
				d.cfg.Logger.Printf("discovery announce: %v", err)
			}
		}
	}
}

// sendBeacon writes one frame. If dst is nil it goes to the multicast
// group; otherwise it's unicast (used to reply directly to a querier).
func (d *discovery) sendBeacon(kind string, dst *net.UDPAddr) error {
	rec, err := d.self.signedPresence(time.Now())
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	buf, err := json.Marshal(beaconFrame{Kind: kind, Record: rec})
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if len(buf) > beaconMaxFrame {
		return fmt.Errorf("frame too large: %d bytes", len(buf))
	}
	target := d.group
	if dst != nil {
		target = dst
	}
	_, err = d.send.WriteToUDP(buf, target)
	return err
}

// listenLoop reads multicast frames, verifies, merges, and replies to
// queries. We deliberately do not trust the UDP source address for
// anything — identity comes from the signature inside the frame.
func (d *discovery) listenLoop(ctx context.Context) {
	buf := make([]byte, beaconMaxFrame)
	for {
		if ctx.Err() != nil {
			return
		}
		// Wake the read up periodically so ctx cancellation is responsive.
		_ = d.recv.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, src, err := d.recv.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			d.cfg.Logger.Printf("discovery read: %v", err)
			continue
		}
		var f beaconFrame
		if err := json.Unmarshal(buf[:n], &f); err != nil {
			continue // junk packet on the group; ignore
		}
		// Ignore our own announces. Multicast loopback echoes them back.
		if f.Record.Payload.ID == d.self.ID {
			continue
		}
		res := d.reg.merge([]PresenceRecord{f.Record})
		if res.Accepted > 0 {
			d.cfg.Logger.Printf("discovery<- %s id=%s ep=%s caps=%v",
				f.Kind, f.Record.Payload.ID[:8],
				f.Record.Payload.Endpoint, f.Record.Payload.Capabilities)
		}
		if res.Rejected > 0 {
			d.cfg.Logger.Printf("discovery rejected frame from %s", src)
			continue
		}
		if f.Kind == beaconKindQuery {
			// Reply unicast so the newcomer learns us immediately. The
			// querier's authoritative endpoint is the one in their
			// signed record; the UDP src port is ephemeral and useless
			// for return contact, so we just reply to the group. (A more
			// ambitious build would parse Endpoint to get host:port; the
			// group reply is simpler and works.)
			if err := d.sendBeacon(beaconKindAnnounce, nil); err != nil {
				d.cfg.Logger.Printf("discovery reply: %v", err)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// MCP endpoint (JSON-RPC 2.0 over a single POST /mcp)
// ---------------------------------------------------------------------------
//
// This is the minimum surface a peer needs to advertise: initialize,
// tools/list, tools/call. It speaks the simple JSON response form of the
// Streamable HTTP transport (Content-Type: application/json), which is
// permitted by the spec and avoids the SSE machinery for a sketch like
// this. Each advertised capability is surfaced as a tool of the same name.

const mcpProtocolVersion = "2025-06-18"

type jsonrpcReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonrpcResp struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *jsonrpcErr     `json:"error,omitempty"`
}

type jsonrpcErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// toolHandler implements one MCP tool. Returns the structured result that
// goes into the "structuredContent" field, plus a short text summary.
type toolHandler func(args map[string]any) (text string, structured any, err error)

// argTraceKey carries the inbound traceparent into a room handler's args (dispatch injects it for room.*
// tools, after proof verification) so the handler's fan-out deliveries stitch into the originating trace.
// Internal — never part of a tool's public input schema.
const argTraceKey = "__trace"

// mcpTool is one callable tool plus the contract callers need to use it.
// The InputSchema is real JSON Schema (served verbatim in tools/list) so a
// caller can validate arguments before dispatch instead of guessing —
// "capabilities" on the presence record are just discovery labels; THIS is
// the request/response contract. Restricted marks a tool that requires an
// authenticated, allow-listed caller (see ACL + tools/call).
type mcpTool struct {
	Name        string
	Description string
	InputSchema map[string]any
	Restricted  bool
	// IdentityBound marks a room.* call that acts on behalf of a claimed identity (the `from`/`node_id`
	// argument). The caller MUST present a CallProof signed by a known mesh member whose NodeID equals that
	// claimed identity — closing the spoofable-`from` hole the room trust model (approve/agree/grant/invoke)
	// depends on. Unlike Restricted it does not consult the global allowedCallers ACL; room membership and
	// ownership are per-room and enforced by the handler on the now-VERIFIED identity.
	IdentityBound bool
	Handler       toolHandler
}

type mcpServer struct {
	self  *Self
	tools map[string]mcpTool
	acl   *ACL
	reg   *Registry   // resolves a caller's pinned key to verify call proofs
	hub   *sessionHub // live WS/SSE participant sessions for real-time delivery
	// observer, when set, receives an EvCall telemetry event per inbound tools/call. nil = no telemetry.
	observer Observer
}

func newMCPServer(self *Self, reg *Registry, acl *ACL, hub *sessionHub, observer Observer) *mcpServer {
	s := &mcpServer{self: self, tools: map[string]mcpTool{}, acl: acl, reg: reg, hub: hub, observer: observer}
	// A tool gets registered for every capability the node advertises.
	// The demo wires "echo" and "clock" with real schemas; unknown caps
	// get a stub tool (declared, not implemented) so the advertisement
	// isn't a lie. A capability is restricted when the ACL names it.
	for _, c := range self.Caps {
		name := string(c)
		t := mcpTool{Name: name, Restricted: acl != nil && acl.restricted(name)}
		switch name {
		case "echo":
			t.Description = "Echo a message back to the caller."
			t.InputSchema = map[string]any{
				"type": "object",
				"properties": map[string]any{
					"message": map[string]any{"type": "string", "description": "Text to echo back"},
				},
				"required":             []any{"message"},
				"additionalProperties": false,
			}
			t.Handler = toolEcho
		case "clock":
			t.Description = "Return the node's current UTC time (RFC 3339)."
			t.InputSchema = map[string]any{
				"type":                 "object",
				"properties":           map[string]any{},
				"additionalProperties": false,
			}
			t.Handler = toolClock
		default:
			t.Description = fmt.Sprintf("Capability %q advertised by node %s (not implemented on this node).", name, self.ID)
			t.InputSchema = map[string]any{
				"type": "object", "properties": map[string]any{}, "additionalProperties": true,
			}
			t.Handler = toolStub(name)
		}
		s.tools[name] = t
	}
	return s
}

func (s *mcpServer) registerHandlers(mux *http.ServeMux) {
	mux.HandleFunc(s.self.MCPPath, s.handle)
}

// handle is the MCP entry point. POST carries one JSON-RPC request and gets
// one JSON-RPC response (classic request/response). GET opens a live
// server->client stream — a WebSocket if the client asks to upgrade, else
// Server-Sent Events. Both real-time transports carry the SAME JSON-RPC
// frames and route through the same dispatch(), so a tool call is identical
// whether it arrived over POST, SSE-paired POSTs, or a WebSocket. By design
// 2026-05-29: "support both streaming HTTP and WebSockets, same RPC styles,
// so it can actually support real-time."
func (s *mcpServer) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.handleStream(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST or GET", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeRPCError(w, nil, -32700, "parse error")
		return
	}
	var req jsonrpcReq
	if err := json.Unmarshal(body, &req); err != nil {
		writeRPCError(w, nil, -32700, "parse error")
		return
	}
	resp := s.dispatch(req)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// dispatch executes one JSON-RPC request and returns the response. It is the
// single source of truth for the RPC surface, shared by every transport
// (POST, SSE, WebSocket). Pure modulo tool side effects — no http.ResponseWriter.
func (s *mcpServer) dispatch(req jsonrpcReq) jsonrpcResp {
	mkResult := func(result any) jsonrpcResp {
		return jsonrpcResp{JSONRPC: "2.0", ID: req.ID, Result: result}
	}
	mkError := func(code int, msg string) jsonrpcResp {
		return jsonrpcResp{JSONRPC: "2.0", ID: req.ID, Error: &jsonrpcErr{Code: code, Message: msg}}
	}
	if req.JSONRPC != "2.0" {
		return mkError(-32600, "invalid request")
	}
	switch req.Method {
	case "initialize":
		return mkResult(map[string]any{
			"protocolVersion": mcpProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo": map[string]any{
				"name":        "mcpmesh-peer",
				"version":     "0.1.0",
				"nodeId":      s.self.ID,
				"jipProtocol": ProtocolVersion,
				"transports":  []string{"http", "sse", "websocket"},
			},
		})
	case "notifications/initialized", "ping":
		return mkResult(map[string]any{})
	case "tools/list":
		return mkResult(map[string]any{"tools": s.toolDescriptors()})
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments map[string]any  `json:"arguments"`
			Caller    *CallProof      `json:"caller,omitempty"`
			Presenter *PresenceRecord `json:"presenter,omitempty"`
			// Trace is UNSIGNED observability metadata (W3C traceparent) propagated across hops.
			// It is NOT part of CallProof's signed bytes and MUST NOT affect proof verification.
			Trace string `json:"trace,omitempty"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return mkError(-32602, "invalid params")
		}
		// First-contact bootstrap: a caller the host has never met presents its signed presence record so
		// the host can admit it (subject to the discovery admit policy — open, or grant-checked under
		// AuthorityRoot) and then verify the caller's signed identity below. merge verifies the record's
		// self-signature; the admit policy gates WHO may bootstrap. Idempotent on repeat presentation.
		if p.Presenter != nil {
			s.reg.merge([]PresenceRecord{*p.Presenter})
		}
		t, ok := s.tools[p.Name]
		if !ok {
			return mkError(-32601, "unknown tool: "+p.Name)
		}
		// EvCall telemetry: one event per dispatched tools/call, emitted exactly once on every return path
		// below via the deferred closure. Outcome is left "" (→ "ok") unless a path sets denied/error.
		var caller string
		if p.Caller != nil {
			caller = string(p.Caller.NodeID)
		}
		start := time.Now()
		// Propagate an inbound (unsigned) traceparent so a multi-hop op stitches into one trace;
		// mint a fresh one if the caller supplied none.
		trace := p.Trace
		if trace == "" {
			trace = NewTraceparent()
		}
		ev := Event{Kind: EvCall, Node: string(s.self.ID), Tool: p.Name, Peer: caller, Trace: trace, Span: NewSpanID()}
		defer func() {
			if ev.Outcome == "" {
				ev.Outcome = "ok"
			}
			ev.DurMs = time.Since(start).Milliseconds()
			emit(s.observer, ev)
		}()
		if t.Restricted {
			if err := s.authorizeCall(p.Name, p.Arguments, p.Caller); err != nil {
				var who string
				if p.Caller != nil {
					who = string(p.Caller.NodeID)
				}
				log.Printf("AUDIT mcp: denied restricted call %q from %q: %s", logSafe(p.Name), logSafe(who), safeErr(err))
				ev.Outcome = "denied"
				ev.Detail = err.Error()
				return mkResult(map[string]any{
					"isError": true,
					"content": []map[string]any{{"type": "text", "text": "access denied: " + err.Error()}},
				})
			}
		}
		if t.IdentityBound {
			if err := s.authorizeIdentity(p.Name, p.Arguments, p.Caller); err != nil {
				var who string
				if p.Caller != nil {
					who = string(p.Caller.NodeID)
				}
				log.Printf("AUDIT mcp: denied identity-bound call %q claiming %s signed by %q: %s", logSafe(p.Name), logSafe(fmt.Sprintf("%v", p.Arguments["from"])), logSafe(who), safeErr(err))
				ev.Outcome = "denied"
				ev.Detail = err.Error()
				return mkResult(map[string]any{
					"isError": true,
					"content": []map[string]any{{"type": "text", "text": "access denied: " + err.Error()}},
				})
			}
		}
		// Hand room handlers the inbound trace (unsigned) so their fan-out deliveries stitch into this
		// operation's trace. Injected only for room.* tools and only AFTER the proof/identity checks above,
		// so it never affects CallProof verification.
		if strings.HasPrefix(p.Name, "room.") {
			if p.Arguments == nil {
				p.Arguments = map[string]any{}
			}
			p.Arguments[argTraceKey] = trace
		}
		text, structured, err := t.Handler(p.Arguments)
		if err != nil {
			ev.Outcome = "error"
			ev.Detail = err.Error()
			return mkResult(map[string]any{
				"isError": true,
				"content": []map[string]any{{"type": "text", "text": err.Error()}},
			})
		}
		return mkResult(map[string]any{
			"content":           []map[string]any{{"type": "text", "text": text}},
			"structuredContent": structured,
		})
	default:
		return mkError(-32601, "method not found: "+req.Method)
	}
}

// toolDescriptors returns the tool list in MCP's expected shape, sorted by
// name for a stable response. Each tool carries its real inputSchema (the
// callable contract) and an annotation marking whether a call needs an
// authenticated, allow-listed caller.
func (s *mcpServer) toolDescriptors() []map[string]any {
	names := make([]string, 0, len(s.tools))
	for name := range s.tools {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]map[string]any, 0, len(names))
	for _, name := range names {
		t := s.tools[name]
		out = append(out, map[string]any{
			"name":        t.Name,
			"description": t.Description,
			"inputSchema": t.InputSchema,
			// Non-standard hint; harmless to MCP clients that ignore it,
			// useful to mesh-aware callers deciding whether to attach a proof.
			"annotations": map[string]any{"restricted": t.Restricted},
		})
	}
	return out
}

func writeRPCResult(w http.ResponseWriter, id json.RawMessage, result any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(jsonrpcResp{JSONRPC: "2.0", ID: id, Result: result})
}

func writeRPCError(w http.ResponseWriter, id json.RawMessage, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(jsonrpcResp{
		JSONRPC: "2.0", ID: id,
		Error: &jsonrpcErr{Code: code, Message: msg},
	})
}

// ---------------------------------------------------------------------------
// Real-time transport — live sessions over WebSocket or SSE (GET /mcp)
// ---------------------------------------------------------------------------
//
// Same JSON-RPC, two pipes (by design):
//   - Streaming HTTP: POST /mcp for request/response, GET /mcp (Accept:
//     text/event-stream) opens a one-way server->client SSE stream. The
//     client sends RPCs over POST and receives notifications over the SSE.
//   - WebSocket: GET /mcp with Upgrade: websocket — one bidirectional
//     socket carrying the SAME JSON-RPC frames in both directions, plus
//     server-pushed notifications. True real-time.
//
// Both register a session keyed by the participant's node id (via a
// session.hello frame on WS, or ?as=<id> on SSE), so the RoomHost can
// stream room events down the held channel — the answer to delivering to a
// NAT'd phone or an agent session that can't accept inbound dials.
//
// The WebSocket is hand-rolled on the stdlib (crypto/sha1 + base64 for the
// handshake, manual RFC 6455 text framing over a hijacked net.Conn) so the
// "stdlib only, any device" invariant holds — no third-party dep, even for
// WS.

type session struct {
	out    chan []byte
	closed chan struct{}
}

type sessionHub struct {
	mu   sync.Mutex
	subs map[UUID]map[*session]bool
}

func newSessionHub() *sessionHub { return &sessionHub{subs: map[UUID]map[*session]bool{}} }

func (h *sessionHub) add(node UUID, s *session) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.subs[node] == nil {
		h.subs[node] = map[*session]bool{}
	}
	h.subs[node][s] = true
}

func (h *sessionHub) remove(node UUID, s *session) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if m := h.subs[node]; m != nil {
		delete(m, s)
		if len(m) == 0 {
			delete(h.subs, node)
		}
	}
}

func (h *sessionHub) live(node UUID) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs[node]) > 0
}

// push delivers a frame to every live session for node, non-blocking (a
// slow/full session drops the frame and catches up via room.history).
func (h *sessionHub) push(node UUID, frame []byte) {
	h.mu.Lock()
	targets := make([]*session, 0, len(h.subs[node]))
	for s := range h.subs[node] {
		targets = append(targets, s)
	}
	h.mu.Unlock()
	for _, s := range targets {
		select {
		case s.out <- frame:
		default:
		}
	}
}

func (s *mcpServer) handleStream(w http.ResponseWriter, r *http.Request) {
	if s.hub == nil {
		http.Error(w, "streaming not enabled", http.StatusNotImplemented)
		return
	}
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		s.serveWS(w, r)
		return
	}
	s.serveSSE(w, r)
}

// serveSSE streams server->client notifications. The participant id comes
// from ?as=<node_id>; that node's room events flow down this stream. Inbound
// RPC for an SSE client rides POST /mcp (the streaming-HTTP pairing).
func (s *mcpServer) serveSSE(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "no flush", http.StatusInternalServerError)
		return
	}
	node := UUID(r.URL.Query().Get("as"))
	sess := &session{out: make(chan []byte, 64), closed: make(chan struct{})}
	if node != "" {
		s.hub.add(node, sess)
		defer s.hub.remove(node, sess)
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(": jip stream open\n\n"))
	fl.Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case frame := <-sess.out:
			_, _ = w.Write([]byte("data: "))
			_, _ = w.Write(frame)
			_, _ = w.Write([]byte("\n\n"))
			fl.Flush()
		}
	}
}

// serveWS upgrades to a WebSocket and runs the bidirectional loop: inbound
// frames are JSON-RPC requests routed through dispatch() (identical to
// POST); a session.hello frame binds this socket to a node id so room
// events stream down it. Notifications (no id) get no reply.
func (s *mcpServer) serveWS(w http.ResponseWriter, r *http.Request) {
	ws, err := wsUpgrade(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer ws.close()
	sess := &session{out: make(chan []byte, 64), closed: make(chan struct{})}
	var bound UUID
	go func() {
		for {
			select {
			case <-sess.closed:
				return
			case frame := <-sess.out:
				if ws.writeText(frame) != nil {
					return
				}
			}
		}
	}()
	defer func() {
		close(sess.closed)
		if bound != "" {
			s.hub.remove(bound, sess)
		}
	}()
	for {
		msg, err := ws.readText()
		if err != nil {
			return
		}
		var req jsonrpcReq
		if json.Unmarshal(msg, &req) != nil {
			continue
		}
		if req.Method == "session.hello" {
			var p struct {
				NodeID UUID `json:"node_id"`
			}
			_ = json.Unmarshal(req.Params, &p)
			if p.NodeID != "" {
				if bound != "" {
					s.hub.remove(bound, sess)
				}
				bound = p.NodeID
				s.hub.add(bound, sess)
			}
			if len(req.ID) > 0 {
				_ = ws.writeText(mustRaw(jsonrpcResp{JSONRPC: "2.0", ID: req.ID,
					Result: map[string]any{"bound": bound, "node": s.self.ID}}))
			}
			continue
		}
		resp := s.dispatch(req)
		if len(req.ID) > 0 { // requests get a reply; notifications don't
			_ = ws.writeText(mustRaw(resp))
		}
	}
}

// --- minimal RFC 6455 server (text frames, stdlib only) ---

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

type wsConn struct {
	conn net.Conn
	br   *bufio.Reader
	wmu  sync.Mutex
}

func wsUpgrade(w http.ResponseWriter, r *http.Request) (*wsConn, error) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return nil, errors.New("not a websocket upgrade")
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return nil, errors.New("missing Sec-WebSocket-Key")
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("hijack unsupported")
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	sum := sha1.Sum([]byte(key + wsGUID))
	accept := base64.StdEncoding.EncodeToString(sum[:])
	_, err = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n")
	if err == nil {
		err = brw.Flush()
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &wsConn{conn: conn, br: brw.Reader}, nil
}

// readText returns the next text/binary message payload, transparently
// answering pings and surfacing close as io.EOF. Client frames are masked
// per spec; we unmask. (PoC: a non-final fragment is treated as complete —
// JSON-RPC frames are small and unfragmented in practice.)
func (c *wsConn) readText() ([]byte, error) {
	for {
		h := make([]byte, 2)
		if _, err := io.ReadFull(c.br, h); err != nil {
			return nil, err
		}
		op := h[0] & 0x0f
		masked := h[1]&0x80 != 0
		ln := int(h[1] & 0x7f)
		switch ln {
		case 126:
			e := make([]byte, 2)
			if _, err := io.ReadFull(c.br, e); err != nil {
				return nil, err
			}
			ln = int(binary.BigEndian.Uint16(e))
		case 127:
			e := make([]byte, 8)
			if _, err := io.ReadFull(c.br, e); err != nil {
				return nil, err
			}
			ln = int(binary.BigEndian.Uint64(e))
		}
		var mask [4]byte
		if masked {
			if _, err := io.ReadFull(c.br, mask[:]); err != nil {
				return nil, err
			}
		}
		payload := make([]byte, ln)
		if _, err := io.ReadFull(c.br, payload); err != nil {
			return nil, err
		}
		if masked {
			for i := range payload {
				payload[i] ^= mask[i&3]
			}
		}
		switch op {
		case 0x1, 0x2: // text / binary
			return payload, nil
		case 0x8: // close
			return nil, io.EOF
		case 0x9: // ping -> pong
			_ = c.writeFrame(0xA, payload)
		case 0xA: // pong, ignore
		}
	}
}

func (c *wsConn) writeFrame(op byte, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	var hdr []byte
	b0 := byte(0x80) | op // FIN + opcode
	n := len(payload)
	switch {
	case n < 126:
		hdr = []byte{b0, byte(n)}
	case n < 65536:
		hdr = []byte{b0, 126, byte(n >> 8), byte(n)}
	default:
		hdr = make([]byte, 10)
		hdr[0], hdr[1] = b0, 127
		binary.BigEndian.PutUint64(hdr[2:], uint64(n))
	}
	if _, err := c.conn.Write(hdr); err != nil {
		return err
	}
	_, err := c.conn.Write(payload)
	return err
}

func (c *wsConn) writeText(b []byte) error { return c.writeFrame(0x1, b) }
func (c *wsConn) close() error             { _ = c.writeFrame(0x8, nil); return c.conn.Close() }

// --- demo tool handlers ----------------------------------------------------

func toolEcho(args map[string]any) (string, any, error) {
	msg, _ := args["message"].(string)
	if msg == "" {
		msg = "(no message)"
	}
	return msg, map[string]any{"echo": msg}, nil
}

func toolClock(_ map[string]any) (string, any, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	return now, map[string]any{"now": now}, nil
}

func toolStub(name string) toolHandler {
	return func(_ map[string]any) (string, any, error) {
		return "", nil, fmt.Errorf("capability %q advertised but not implemented on this node", name)
	}
}

// ---------------------------------------------------------------------------
// Access control — who may call restricted tools
// ---------------------------------------------------------------------------
//
// The mesh is open by default: any reachable client can call a node's
// tools, which is fine for echo/clock. But once a node exposes something
// sensitive — and especially once an agent on one instance can reach an
// agent on another (one user's agent -> another user's agent) — "reachable" is not
// "authorized". The ACL gates restricted tools behind a caller proof:
// the caller signs its identity + the tool name + a fresh timestamp with
// its node key, and the server verifies that signature against the pubkey
// it has PINNED for that node id in its registry. So a restricted call
// requires (a) a known mesh member (b) on the allow-list (c) holding the
// private key for the id it claims (d) within the freshness window. Fails
// closed: no proof, no call.
type ACL struct {
	restrictedCaps map[string]bool // capability name -> requires authorization
	allowedCallers map[UUID]bool   // node id -> permitted to call restricted tools
}

func newACL(restricted, allowed []string) *ACL {
	a := &ACL{restrictedCaps: map[string]bool{}, allowedCallers: map[UUID]bool{}}
	for _, r := range restricted {
		if r = strings.TrimSpace(r); r != "" {
			a.restrictedCaps[r] = true
		}
	}
	for _, c := range allowed {
		if c = strings.TrimSpace(c); c != "" {
			a.allowedCallers[UUID(c)] = true
		}
	}
	return a
}

func (a *ACL) restricted(capName string) bool {
	return a != nil && a.restrictedCaps[capName]
}

// CallProof authenticates one tools/call. The caller signs signedBytes()
// with its node private key; the server verifies against the caller's
// pinned pubkey. A domain-separator prefix guarantees these bytes can
// never be confused with a presence-record signature.
type CallProof struct {
	NodeID    UUID   `json:"node_id"`
	Tool      string `json:"tool"`
	ArgsHash  []byte `json:"args_hash"` // sha256 of the canonical arguments — binds the proof to THIS payload
	UnixMilli int64  `json:"unix_milli"`
	Alg       string `json:"alg,omitempty"` // signature algorithm (crypto agility); empty == ed25519
	Signature []byte `json:"signature"`
}

// hashArgs is the canonical argument digest both sides compute. Go's json.Marshal sorts map keys, so
// the same arguments map hashes identically on caller and server — binding the signature to the exact
// payload (a captured proof can't be replayed with swapped arguments).
func hashArgs(args map[string]any) []byte {
	b, _ := json.Marshal(args)
	h := sha256.Sum256(b)
	return h[:]
}

func (p CallProof) signedBytes() []byte {
	var b bytes.Buffer
	field := func(x []byte) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(x)))
		b.Write(n[:])
		b.Write(x)
	}
	field([]byte("JIP-call/0.2")) // domain separator (bumped: now covers ArgsHash)
	field([]byte(sigAlg(p.Alg)))  // signature algorithm — covered so it can't be downgraded
	field([]byte(p.NodeID))
	field([]byte(p.Tool))
	field(p.ArgsHash)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(p.UnixMilli))
	b.Write(ts[:])
	return b.Bytes()
}

const callProofMaxSkew = 30 * time.Second

// VerifyCallProof verifies a caller proof's AUTHENTICITY, INTEGRITY, and FRESHNESS against a known public key:
// the algorithm is ed25519 (no downgrade), the proof names `tool`, its ArgsHash matches `args`, its timestamp
// is within the freshness window of `now`, and its signature verifies against `pub`. It is the single source
// of truth for proof verification — both the mesh's authorizeCall and any other server (e.g. the Fabric
// console resolving an agent principal) call this, then resolve `pub` from their own trust root (a pinned
// presence record, or a verified authority grant's PublicKey) and authorize the caller's SCOPES separately.
func VerifyCallProof(p CallProof, pub ed25519.PublicKey, tool string, args map[string]any, now time.Time) error {
	if sigAlg(p.Alg) != SigAlgEd25519 {
		return errors.New("unsupported caller signature algorithm")
	}
	if p.Tool != tool {
		return errors.New("proof is for a different tool")
	}
	if !bytes.Equal(p.ArgsHash, hashArgs(args)) {
		return errors.New("proof does not match the call arguments")
	}
	skew := now.Sub(time.UnixMilli(p.UnixMilli))
	if skew < -callProofMaxSkew || skew > callProofMaxSkew {
		return errors.New("proof timestamp outside freshness window")
	}
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, p.signedBytes(), p.Signature) {
		return errors.New("bad caller signature")
	}
	return nil
}

// CallProofArgsHash exposes the canonical argument digest so a non-mesh server (the Fabric console) can build
// or check a proof's ArgsHash with the SAME canonicalization both sides use.
func CallProofArgsHash(args map[string]any) []byte { return hashArgs(args) }

// authorizeCall returns nil iff the proof is present, names this tool, MATCHES the actual arguments,
// is fresh, is signed by the claimed node's pinned key, and that node id is allow-listed. Anything
// else is a denial.
func (s *mcpServer) authorizeCall(tool string, args map[string]any, proof *CallProof) error {
	if proof == nil {
		return errors.New("restricted tool requires a signed caller proof")
	}
	if !s.acl.allowedCallers[proof.NodeID] {
		return fmt.Errorf("caller %s is not allow-listed", proof.NodeID)
	}
	rec, ok := s.reg.get(proof.NodeID)
	if !ok {
		return fmt.Errorf("caller %s is not a known mesh member", proof.NodeID)
	}
	return VerifyCallProof(*proof, ed25519.PublicKey(rec.Payload.PublicKey), tool, args, time.Now())
}

// authorizeIdentity gates an identity-bound room.* call. The caller must present a CallProof that is (1)
// signed by a KNOWN mesh member, (2) bound to these exact arguments and fresh, and (3) whose NodeID equals
// the identity the call claims to act as (the `from`/`node_id` argument). It deliberately does NOT consult
// the global allowedCallers ACL — room membership/ownership is per-room and enforced by the handler — it
// only proves WHO is calling, so a member can no longer forge `from=<owner>` to self-approve, grant, kick,
// or invoke. This is the enforcement the room trust model documents but previously lacked.
func (s *mcpServer) authorizeIdentity(tool string, args map[string]any, proof *CallProof) error {
	if proof == nil {
		return errors.New("this room operation requires a signed caller proof")
	}
	var pub ed25519.PublicKey
	if s.self != nil && proof.NodeID == s.self.ID {
		// A node authenticating as ITSELF (hosting/managing its own room). A node is not a discovered peer
		// in its own registry, so verify against its own key directly.
		pub = s.self.Pub
	} else {
		rec, ok := s.reg.get(proof.NodeID)
		if !ok {
			return fmt.Errorf("caller %s is not a known mesh member", proof.NodeID)
		}
		pub = ed25519.PublicKey(rec.Payload.PublicKey)
	}
	if err := VerifyCallProof(*proof, pub, tool, args, time.Now()); err != nil {
		return err
	}
	// Bind EVERY actor field to the verified signer. Checking only `from` let an attacker set the OTHER
	// actor field to a victim: room.leave/join/create act on `node_id` while the gate had verified `from`,
	// so {from:self, node_id:victim} passed the gate and the handler acted on the victim (field-confusion).
	// `target`/`grantee` are the OBJECT of the action, not the caller — the handler's canManage authorizes
	// those; they are deliberately not bound here.
	for _, field := range []string{"from", "node_id"} {
		if v, _ := args[field].(string); v != "" && v != string(proof.NodeID) {
			return fmt.Errorf("room call %q claims identity %q but is cryptographically signed by %q", field, v, proof.NodeID)
		}
	}
	return nil
}

// signCall is the caller-side helper: produce a proof for invoking tool with argsHash on a remote
// node, signed with this node's key. Exposed so a JIP client (or a test) can build authorized
// requests with a couple of lines.
func (s *Self) signCall(tool string, argsHash []byte, now time.Time) CallProof {
	return SignCallProof(s.ID, s.Priv, tool, argsHash, now)
}

// SignCallProof builds a signed caller proof for invoking `tool` with `argsHash`, signed by the node's key.
// Standalone counterpart to VerifyCallProof — a non-mesh client (e.g. a Fabric agent calling the console's
// persona tools) builds an authorized request with this; the server verifies it with VerifyCallProof against
// the caller's granted public key.
func SignCallProof(nodeID UUID, priv ed25519.PrivateKey, tool string, argsHash []byte, now time.Time) CallProof {
	p := CallProof{NodeID: nodeID, Tool: tool, ArgsHash: argsHash, UnixMilli: now.UnixMilli(), Alg: SigAlgEd25519}
	p.Signature = ed25519.Sign(priv, p.signedBytes())
	return p
}

// ---------------------------------------------------------------------------
// Rooms — the unit of collaboration (JIP/0.1 chat layer)
// ---------------------------------------------------------------------------
//
// By design: "the room itself becomes the unit of
// collaboration. Identity, capabilities, discovery — all scoped to who's
// in the room at that moment." A Room is a named, live-membership space.
// It can hold two participants (you and one agent) or many.
//
// Rooms ride entirely on MCP tools — no second protocol. The room tools
// are registered on EVERY node (independent of -caps):
//
//	room.join    — greet: announce yourself + the tools you bring; receive
//	               the roster and the room-scoped union of available tools
//	room.leave   — exit; roster + available tools recompute
//	room.post    — say something to the room (chat)
//	room.tools   — the current union of members' available tools
//	room.history — catch up on messages since a sequence cursor
//	room.invoke  — call another member's advertised tool IN-BAND, so the
//	               call and its result land in the room log where every
//	               member (including a routing agent) can see them
//	room.deliver — inbound: the host pushes a new room event to a member
//
// A room lives on its HOST node — whichever node the participants connect
// to. The host owns the roster, the monotonic message log, and fan-out.
// Because every member is itself a reachable JIP node, the host pushes
// each event by calling room.deliver on the member's own MCP endpoint;
// the log lets a member catch up via room.history if a push is missed.
// "Available tools" is recomputed from live membership on every join and
// leave — that is the "scoped to who's in the room at that moment" rule.

type roomMsg struct {
	Seq       int            `json:"seq"`
	Kind      string         `json:"kind"` // say|join|leave|roster|tool_call|tool_result
	From      UUID           `json:"from"`
	Text      string         `json:"text,omitempty"`
	Tool      string         `json:"tool,omitempty"`
	Target    UUID           `json:"target,omitempty"`
	Args      map[string]any `json:"args,omitempty"`
	Result    any            `json:"result,omitempty"`
	UnixMilli int64          `json:"unix_milli"`
}

type roomMember struct {
	NodeID   UUID          `json:"node_id"`
	Alias    string        `json:"alias"` // display name; disambiguated on collision
	Endpoint string        `json:"endpoint"`
	MCPPath  string        `json:"mcp_path"`
	Approved bool          `json:"approved"` // owner admitted them (private rooms)
	agreed   map[UUID]bool // node ids this member has confirmed identity/keys with
}

// toolGrant is one dynamically-exposed hook: Granter has agreed to let
// Grantee call Tool, inside this (private) room, right now. Grants are
// added on request and can be revoked; the set a participant sees changes
// live through the conversation. By design: "the tools available
// can change dynamically throughout the chat... you request read DOM, that
// tool is exposed to you; you request write, the write tool is presented."
type toolGrant struct {
	Granter UUID           `json:"granter"`
	Grantee UUID           `json:"grantee"`
	Tool    map[string]any `json:"tool"` // descriptor: name, description, inputSchema
}

// Room is one collaboration space on the host node.
//
// Two channel modes (by design). A PUBLIC room is the open
// lobby: anyone may join and chat, identities/keys get exchanged and
// agreed — but NO tool may be invoked. A PRIVATE room is where tools live:
// entry is owner-approved, and a tool call requires BOTH ends to have
// mutually agreed (keys confirmed) AND an explicit grant for that tool.
type Room struct {
	mu          sync.Mutex
	id          string
	owner       UUID
	private     bool
	seq         int
	members     map[UUID]*roomMember
	supervisors map[UUID]bool // may boot members (in addition to owner + host supervisors)
	grants      []toolGrant
	msgs        []roomMsg
}

// removeMember drops a member and revokes every grant they hold or extend —
// a booted/departed agent must not retain tool access, and tools it exposed
// stop being callable. Caller holds rm.mu.
func (rm *Room) removeMember(id UUID) {
	delete(rm.members, id)
	kept := rm.grants[:0]
	for _, g := range rm.grants {
		if g.Granter == id || g.Grantee == id {
			continue
		}
		kept = append(kept, g)
	}
	rm.grants = kept
}

// mutuallyAgreed reports whether a and b have each confirmed the other's
// identity/keys — the "both sides agree in the public channel" gate.
func (rm *Room) mutuallyAgreed(a, b UUID) bool {
	ma, oka := rm.members[a]
	mb, okb := rm.members[b]
	return oka && okb && ma.agreed[b] && mb.agreed[a]
}

// grantsTo returns the tools currently exposed to grantee — the dynamic,
// per-participant available-tool set.
func (rm *Room) grantsTo(grantee UUID) []map[string]any {
	out := make([]map[string]any, 0)
	for _, g := range rm.grants {
		if g.Grantee == grantee {
			d := map[string]any{}
			for k, v := range g.Tool {
				d[k] = v
			}
			d["granted_by"] = string(g.Granter)
			out = append(out, d)
		}
	}
	return out
}

// hasGrant reports whether granter has exposed toolName to grantee.
func (rm *Room) hasGrant(granter, grantee UUID, toolName string) bool {
	for _, g := range rm.grants {
		if g.Granter == granter && g.Grantee == grantee {
			if n, _ := g.Tool["name"].(string); n == toolName {
				return true
			}
		}
	}
	return false
}

// aliasTaken reports whether name is already used by a DIFFERENT node — the
// trigger for asking a same-named agent to pick an alias.
func (rm *Room) aliasTaken(name string, except UUID) bool {
	for id, m := range rm.members {
		if id != except && strings.EqualFold(m.Alias, name) {
			return true
		}
	}
	return false
}

func (rm *Room) append(m roomMsg) roomMsg {
	rm.seq++
	m.Seq = rm.seq
	rm.msgs = append(rm.msgs, m)
	// Bound the log; history is best-effort catch-up, not durable storage.
	if len(rm.msgs) > 500 {
		rm.msgs = rm.msgs[len(rm.msgs)-500:]
	}
	return m
}

func (rm *Room) roster() []roomMember {
	out := make([]roomMember, 0, len(rm.members))
	for _, m := range rm.members {
		out = append(out, *m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out
}

// RoomHost owns the rooms hosted on this node and fans events out to
// members. ts is injected (defaults to time.Now) so tests are deterministic.
// RoomHookEvent is handed to every registered RoomHook before and after a
// room.* method runs. It is the switchboard's tap on the message path: one
// place that sees every operation in every room. Phase is "before" or
// "after". In the "before" phase a hook may:
//   - observe (read Args, return nil),
//   - transform (mutate Args in place — the handler runs on the modified
//     args; e.g. redact or rewrite a post's text), or
//   - gate (return a non-nil error — the method is aborted with that error,
//     and later hooks + the handler do not run).
//
// In the "after" phase Args is the (possibly transformed) input and
// Text/Structured/Err carry the handler's result; after-phase hooks are
// observe-only (their return is ignored). Args is the live map passed to the
// handler, so before-phase mutations are what the handler sees.
type RoomHookEvent struct {
	Phase      string         // "before" | "after"
	Method     string         // "room.post", "room.join", "room.kick", ...
	Args       map[string]any // input args (mutable in the before phase)
	Text       string         // handler result text (after phase)
	Structured any            // handler structured result (after phase)
	Err        error          // handler error (after phase)
}

// RoomHook observes / transforms / gates a room method. A non-nil error
// returned in the "before" phase vetoes the call. See RoomHookEvent.
type RoomHook func(ev *RoomHookEvent) error

type RoomHost struct {
	mu          sync.Mutex
	rooms       map[string]*Room
	self        *Self
	http        *http.Client
	log         *log.Logger
	ts          func() time.Time
	hub         *sessionHub   // live sessions to push room events to (NAT'd participants)
	supervisors map[UUID]bool // host-wide supervisors (operator-designated node ids) — may boot in ANY room
	hooksMu     sync.RWMutex  // guards hooks (separate from mu — hooks fire AROUND handlers that take mu/rm.mu)
	hooks       []RoomHook    // switchboard taps: fire before+after every room.* method
	// observer, when set, receives EvRoom telemetry on room join/post. nil = no telemetry.
	observer Observer
}

func newRoomHost(self *Self, logger *log.Logger, hub *sessionHub, supervisors []UUID, insecureTLS bool, observer Observer) *RoomHost {
	if logger == nil {
		logger = log.Default()
	}
	sup := map[UUID]bool{}
	for _, s := range supervisors {
		if s != "" {
			sup[s] = true
		}
	}
	return &RoomHost{
		rooms:       map[string]*Room{},
		self:        self,
		http:        jipHTTPClient(3*time.Second, insecureTLS),
		log:         logger,
		ts:          time.Now,
		hub:         hub,
		supervisors: sup,
		observer:    observer,
	}
}

// AddRoomHook registers a switchboard tap. Hooks fire in registration order
// before and after every room.* method. Safe to call at any time (including
// concurrently with live traffic). See RoomHookEvent for the observe /
// transform / gate contract.
func (h *RoomHost) AddRoomHook(hook RoomHook) {
	if hook == nil {
		return
	}
	h.hooksMu.Lock()
	h.hooks = append(h.hooks, hook)
	h.hooksMu.Unlock()
}

// fireRoomHooks runs every registered hook for ev. It returns the first
// non-nil error (used to veto in the "before" phase); callers in the "after"
// phase ignore the return. A snapshot of the slice is ranged so registration
// during a fire is safe.
func (h *RoomHost) fireRoomHooks(ev *RoomHookEvent) error {
	h.hooksMu.RLock()
	hooks := h.hooks
	h.hooksMu.RUnlock()
	for _, hook := range hooks {
		if err := hook(ev); err != nil {
			return err
		}
	}
	return nil
}

// RoomMember is a read-only view of one room participant.
type RoomMember struct {
	NodeID   string `json:"node_id"`
	Alias    string `json:"alias"`
	Approved bool   `json:"approved"`
}

// RoomView is a read-only snapshot of one hosted room — for a monitor/observer
// (member roster + message count; no message bodies).
type RoomView struct {
	ID       string       `json:"id"`
	Owner    string       `json:"owner"`
	Private  bool         `json:"private"`
	Messages int          `json:"messages"`
	Members  []RoomMember `json:"members"`
}

// RoomsSnapshot returns a read-only view of every room this host owns/serves, so
// a monitor can show the live mesh (rooms + who's in them), not just sessions.
func (h *RoomHost) RoomsSnapshot() []RoomView {
	h.mu.Lock()
	rooms := make([]*Room, 0, len(h.rooms))
	for _, rm := range h.rooms {
		rooms = append(rooms, rm)
	}
	h.mu.Unlock()
	out := make([]RoomView, 0, len(rooms))
	for _, rm := range rooms {
		rm.mu.Lock()
		v := RoomView{ID: rm.id, Owner: string(rm.owner), Private: rm.private, Messages: len(rm.msgs)}
		for _, m := range rm.members {
			v.Members = append(v.Members, RoomMember{NodeID: string(m.NodeID), Alias: m.Alias, Approved: m.Approved})
		}
		rm.mu.Unlock()
		sort.Slice(v.Members, func(i, j int) bool { return v.Members[i].Alias < v.Members[j].Alias })
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (h *RoomHost) room(id string, create bool) *Room {
	h.mu.Lock()
	defer h.mu.Unlock()
	rm, ok := h.rooms[id]
	if !ok && create {
		rm = &Room{id: id, members: map[UUID]*roomMember{}, supervisors: map[UUID]bool{}}
		h.rooms[id] = rm
	}
	return rm
}

// canManage reports whether `who` may boot members from rm: the room owner,
// a room-level supervisor, or a host-wide supervisor (operator-designated nodes).
func (h *RoomHost) canManage(rm *Room, who UUID) bool {
	// The host node always manages rooms on its OWN /mcp — otherwise a peer could room.create a predictable
	// name first and permanently lock the legitimate host out of its own room (F2).
	return who == rm.owner || rm.supervisors[who] || h.supervisors[who] || (h.self != nil && who == h.self.ID)
}

// broadcast appends an event to the room log and pushes it to every member
// except the originator by calling room.deliver on their MCP endpoint.
// Fan-out is best-effort and concurrent; a member that's unreachable simply
// catches up later via room.history. Caller must hold rm.mu.
func (h *RoomHost) broadcastLocked(rm *Room, m roomMsg) roomMsg {
	return h.broadcastLockedTraced(rm, m, "")
}

// broadcastLockedTraced is broadcastLocked carrying an inbound traceparent: each dialed room.deliver
// inherits it, so the host's fan-out deliveries appear as part of the operation that triggered them (e.g.
// a room.post's N deliveries share the post's trace in the monitor). Caller must hold rm.mu.
func (h *RoomHost) broadcastLockedTraced(rm *Room, m roomMsg, trace string) roomMsg {
	stored := rm.append(m)
	roomID := rm.id
	// Split members into those with a live WS/SSE session (push down the
	// held channel, real-time — works for NAT'd participants like a phone
	// or an agent session) and those reachable only by dialing their MCP
	// endpoint (LAN mesh nodes → call room.deliver). Same event either way.
	type ep struct {
		node     UUID
		endpoint string
	}
	var dialed []ep
	for _, mem := range rm.members {
		if mem.NodeID == stored.From {
			continue
		}
		if mem.NodeID == h.self.ID {
			continue // never dial ourselves — we host this room and already have the message
		}
		if strings.TrimSpace(mem.Endpoint) == "" {
			continue // endpoint-less member (e.g. a human on the monitor) catches up via room.history
		}
		if h.hub != nil && h.hub.live(mem.NodeID) {
			frame := mustRaw(map[string]any{
				"jsonrpc": "2.0", "method": "room.event",
				"params": map[string]any{"room_id": roomID, "event": mustMap(stored)},
			})
			h.hub.push(mem.NodeID, frame)
			continue
		}
		dialed = append(dialed, ep{mem.NodeID, mem.Endpoint + mem.MCPPath})
	}
	// Deliver to each dialed member CONCURRENTLY (own goroutine, bounded by the http
	// client's short timeout) so one slow/unreachable endpoint can't stall the rest —
	// the jam fix. A missed member simply catches up via room.history.
	for _, d := range dialed {
		go func(d ep) {
			args := map[string]any{"room_id": roomID, "event": mustMap(stored)}
			if _, _, err := callRemoteTool(h.http, d.endpoint, "room.deliver", args, nil, trace); err != nil {
				h.log.Printf("room %s deliver-> %s seq=%d: %v", roomID, d.node, stored.Seq, err)
			}
		}(d)
	}
	return stored
}

// --- room tool handlers (registered on every node) ---

// toolCreate starts a room. The caller becomes owner and first member,
// auto-approved. private=true makes it a tools-capable channel gated by
// approval + key agreement + grants; private=false (default) is an open
// chat lobby where no tool can be invoked.
func (h *RoomHost) toolCreate(args map[string]any) (string, any, error) {
	roomID, _ := args["room_id"].(string)
	owner, _ := args["node_id"].(string)
	if roomID == "" || owner == "" {
		return "", nil, errors.New("room.create: room_id and node_id required")
	}
	private, _ := args["private"].(bool)
	alias, _ := args["alias"].(string)
	endpoint, _ := args["endpoint"].(string)
	mcpPath, _ := args["mcp_path"].(string)
	if mcpPath == "" {
		mcpPath = "/mcp"
	}
	rm := h.room(roomID, true)
	rm.mu.Lock()
	defer rm.mu.Unlock()
	// SECURITY: room.create is get-or-create. Reject re-owning an EXISTING room unless the caller already
	// manages it (owner/supervisor) — otherwise any member seizes any room by id, overwrites the owner, and
	// locks out the legitimate owner. (Survives AuthorityRoot being set: member-vs-member takeover.)
	if rm.owner != "" && !h.canManage(rm, UUID(owner)) {
		return "", nil, fmt.Errorf("room.create: room %q already exists and you are not its owner/supervisor", roomID)
	}
	rm.owner = UUID(owner)
	rm.private = private
	// SECURITY (F1): a (re)create starts the room CLEAN. room.join auto-creates a PUBLIC room and marks the
	// joiner Approved; without this reset a PRE-joiner's Approved record + grants would survive when the owner
	// later creates/flips the room to private, letting them pass the members-only history/tools gate and read
	// content they were never owner-approved into. Only the new owner remains.
	rm.members = map[UUID]*roomMember{}
	rm.grants = nil
	rm.supervisors = map[UUID]bool{}
	// Optional supervisors: extra agents (besides the owner + host-wide
	// supervisors) permitted to boot members. Typically operator-designated nodes.
	for _, s := range toStrSlice(args["supervisors"]) {
		rm.supervisors[UUID(s)] = true
	}
	rm.members[UUID(owner)] = &roomMember{
		NodeID: UUID(owner), Alias: alias, Endpoint: endpoint, MCPPath: mcpPath,
		Approved: true, agreed: map[UUID]bool{},
	}
	return fmt.Sprintf("created %s (private=%v)", roomID, private),
		map[string]any{"room_id": roomID, "private": private, "owner": owner}, nil
}

func (h *RoomHost) toolJoin(args map[string]any) (string, any, error) {
	roomID, _ := args["room_id"].(string)
	nodeID, _ := args["node_id"].(string)
	endpoint, _ := args["endpoint"].(string)
	if roomID == "" || nodeID == "" {
		return "", nil, errors.New("room.join: room_id and node_id required")
	}
	mcpPath, _ := args["mcp_path"].(string)
	if mcpPath == "" {
		mcpPath = "/mcp"
	}
	alias, _ := args["alias"].(string)
	if alias == "" {
		alias = nodeID[:8]
	}
	// A bare join auto-creates a PUBLIC room (open lobby). Private rooms
	// must be created with room.create; you can only request into them.
	rm := h.room(roomID, true)
	rm.mu.Lock()
	defer rm.mu.Unlock()
	// Alias collision → ask the (same-named) agent to pick a distinct one.
	if rm.aliasTaken(alias, UUID(nodeID)) {
		return "", nil, fmt.Errorf("alias %q is taken in %s — choose an alias", alias, roomID)
	}
	approved := !rm.private // public: in immediately; private: pending owner approval
	rm.members[UUID(nodeID)] = &roomMember{
		NodeID: UUID(nodeID), Alias: alias, Endpoint: endpoint, MCPPath: mcpPath,
		Approved: approved, agreed: map[UUID]bool{},
	}
	h.broadcastLocked(rm, roomMsg{Kind: "join", From: UUID(nodeID), Text: alias, UnixMilli: h.ts().UnixMilli()})
	h.broadcastLocked(rm, roomMsg{Kind: "roster", From: h.self.ID, UnixMilli: h.ts().UnixMilli()})
	status := "active"
	if !approved {
		status = "pending owner approval"
	}
	emit(h.observer, Event{Kind: EvRoom, Room: roomID, Peer: nodeID, Detail: "join", Outcome: "ok", Span: NewSpanID()})
	return fmt.Sprintf("joined %s as %q (%s)", roomID, alias, status),
		map[string]any{"room_id": roomID, "alias": alias, "approved": approved,
			"private": rm.private, "roster": rm.roster()}, nil
}

// toolApprove admits a pending member to a private room. Owner-only — the
// "they have to approve once they verified the identity" step.
func (h *RoomHost) toolApprove(args map[string]any) (string, any, error) {
	roomID, _ := args["room_id"].(string)
	by, _ := args["from"].(string)
	target, _ := args["target"].(string)
	rm := h.room(roomID, false)
	if rm == nil {
		return "", nil, fmt.Errorf("room.approve: no such room %q", roomID)
	}
	rm.mu.Lock()
	defer rm.mu.Unlock()
	if UUID(by) != rm.owner {
		return "", nil, errors.New("room.approve: only the owner may approve")
	}
	mem, ok := rm.members[UUID(target)]
	if !ok {
		return "", nil, fmt.Errorf("room.approve: %s is not in the room", target)
	}
	mem.Approved = true
	h.broadcastLocked(rm, roomMsg{Kind: "approved", From: UUID(target), UnixMilli: h.ts().UnixMilli()})
	return fmt.Sprintf("approved %s", target), map[string]any{"approved": target}, nil
}

// toolAgree records that `from` has verified and agreed to `target`'s
// identity/keys. When both directions are recorded the pair is mutually
// agreed and may, in a private room, grant and invoke tools.
func (h *RoomHost) toolAgree(args map[string]any) (string, any, error) {
	roomID, _ := args["room_id"].(string)
	from, _ := args["from"].(string)
	target, _ := args["target"].(string)
	rm := h.room(roomID, false)
	if rm == nil {
		return "", nil, fmt.Errorf("room.agree: no such room %q", roomID)
	}
	rm.mu.Lock()
	defer rm.mu.Unlock()
	mem, ok := rm.members[UUID(from)]
	if !ok {
		return "", nil, errors.New("room.agree: caller not a member")
	}
	if _, ok := rm.members[UUID(target)]; !ok {
		return "", nil, errors.New("room.agree: target not a member")
	}
	mem.agreed[UUID(target)] = true
	mutual := rm.mutuallyAgreed(UUID(from), UUID(target))
	h.broadcastLocked(rm, roomMsg{Kind: "agreed", From: UUID(from), Target: UUID(target), UnixMilli: h.ts().UnixMilli()})
	return fmt.Sprintf("agreed to %s (mutual=%v)", target, mutual),
		map[string]any{"target": target, "mutual": mutual}, nil
}

// toolRequestTool is a participant asking another to expose a capability
// ("let me read the DOM"). It is just a signalling message — the grant is
// the other side's decision (toolGrant).
func (h *RoomHost) toolRequestTool(args map[string]any) (string, any, error) {
	roomID, _ := args["room_id"].(string)
	from, _ := args["from"].(string)
	cap, _ := args["capability"].(string)
	rm := h.room(roomID, false)
	if rm == nil {
		return "", nil, fmt.Errorf("room.request_tool: no such room %q", roomID)
	}
	rm.mu.Lock()
	defer rm.mu.Unlock()
	h.broadcastLocked(rm, roomMsg{Kind: "tool_request", From: UUID(from), Tool: cap, UnixMilli: h.ts().UnixMilli()})
	return "requested " + cap, map[string]any{"capability": cap}, nil
}

// toolGrantTool exposes a hook: granter lets grantee call tool, in this
// private room, now. Requires the room be private and the pair mutually
// agreed. The granted tool is immediately invokable and shows up in the
// grantee's room.tools — the dynamic exposure described above.
func (h *RoomHost) toolGrantTool(args map[string]any) (string, any, error) {
	roomID, _ := args["room_id"].(string)
	granter, _ := args["from"].(string)
	grantee, _ := args["grantee"].(string)
	tool, _ := args["tool"].(map[string]any)
	rm := h.room(roomID, false)
	if rm == nil {
		return "", nil, fmt.Errorf("room.grant_tool: no such room %q", roomID)
	}
	if tool == nil || tool["name"] == nil {
		return "", nil, errors.New("room.grant_tool: tool descriptor with a name required")
	}
	rm.mu.Lock()
	defer rm.mu.Unlock()
	if !rm.private {
		return "", nil, errors.New("room.grant_tool: tools can only be exposed in a private room")
	}
	if !rm.mutuallyAgreed(UUID(granter), UUID(grantee)) {
		return "", nil, errors.New("room.grant_tool: grant requires a mutually-agreed (keys exchanged) pair")
	}
	rm.grants = append(rm.grants, toolGrant{Granter: UUID(granter), Grantee: UUID(grantee), Tool: tool})
	name, _ := tool["name"].(string)
	h.broadcastLocked(rm, roomMsg{Kind: "tool_granted", From: UUID(granter), Target: UUID(grantee), Tool: name, UnixMilli: h.ts().UnixMilli()})
	return fmt.Sprintf("granted %q to %s", name, grantee),
		map[string]any{"granted": name, "grantee": grantee}, nil
}

// toolRevokeTool withdraws a previously granted hook — the set of available
// tools shrinks live.
func (h *RoomHost) toolRevokeTool(args map[string]any) (string, any, error) {
	roomID, _ := args["room_id"].(string)
	granter, _ := args["from"].(string)
	grantee, _ := args["grantee"].(string)
	name, _ := args["tool"].(string)
	rm := h.room(roomID, false)
	if rm == nil {
		return "", nil, fmt.Errorf("room.revoke_tool: no such room %q", roomID)
	}
	rm.mu.Lock()
	defer rm.mu.Unlock()
	kept := rm.grants[:0]
	removed := 0
	for _, g := range rm.grants {
		gn, _ := g.Tool["name"].(string)
		if g.Granter == UUID(granter) && g.Grantee == UUID(grantee) && gn == name {
			removed++
			continue
		}
		kept = append(kept, g)
	}
	rm.grants = kept
	h.broadcastLocked(rm, roomMsg{Kind: "tool_revoked", From: UUID(granter), Target: UUID(grantee), Tool: name, UnixMilli: h.ts().UnixMilli()})
	return fmt.Sprintf("revoked %q from %s", name, grantee), map[string]any{"revoked": removed}, nil
}

// toolLeave is a member removing THEMSELVES. Their grants are revoked on the
// way out (see removeMember). To remove someone else, see room.kick.
func (h *RoomHost) toolLeave(args map[string]any) (string, any, error) {
	roomID, _ := args["room_id"].(string)
	nodeID, _ := args["node_id"].(string)
	rm := h.room(roomID, false)
	if rm == nil {
		return "", nil, fmt.Errorf("room.leave: no such room %q", roomID)
	}
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.removeMember(UUID(nodeID))
	h.broadcastLocked(rm, roomMsg{Kind: "leave", From: UUID(nodeID), UnixMilli: h.ts().UnixMilli()})
	h.broadcastLocked(rm, roomMsg{Kind: "roster", From: h.self.ID, UnixMilli: h.ts().UnixMilli()})
	return fmt.Sprintf("left %s", roomID), map[string]any{"room_id": roomID, "participants": len(rm.members)}, nil
}

// toolKick boots another member. Only the room owner, a room supervisor, or
// a host-wide supervisor (operator-designated nodes) may do it. The booted agent's
// grants are revoked, so it loses all tool access immediately.
func (h *RoomHost) toolKick(args map[string]any) (string, any, error) {
	roomID, _ := args["room_id"].(string)
	by, _ := args["from"].(string)
	target, _ := args["target"].(string)
	rm := h.room(roomID, false)
	if rm == nil {
		return "", nil, fmt.Errorf("room.kick: no such room %q", roomID)
	}
	rm.mu.Lock()
	defer rm.mu.Unlock()
	if !h.canManage(rm, UUID(by)) {
		return "", nil, errors.New("room.kick: only the owner or a supervisor may boot a member")
	}
	if _, ok := rm.members[UUID(target)]; !ok {
		return "", nil, fmt.Errorf("room.kick: %s is not in the room", target)
	}
	rm.removeMember(UUID(target))
	h.broadcastLocked(rm, roomMsg{Kind: "kicked", From: UUID(by), Target: UUID(target), UnixMilli: h.ts().UnixMilli()})
	h.broadcastLocked(rm, roomMsg{Kind: "roster", From: h.self.ID, UnixMilli: h.ts().UnixMilli()})
	return fmt.Sprintf("booted %s from %s", target, roomID),
		map[string]any{"booted": target, "by": by, "participants": len(rm.members)}, nil
}

func (h *RoomHost) toolPost(args map[string]any) (string, any, error) {
	roomID, _ := args["room_id"].(string)
	from, _ := args["from"].(string)
	text, _ := args["text"].(string)
	rm := h.room(roomID, false)
	if rm == nil {
		return "", nil, fmt.Errorf("room.post: no such room %q", roomID)
	}
	rm.mu.Lock()
	defer rm.mu.Unlock()
	if _, ok := rm.members[UUID(from)]; !ok {
		return "", nil, errors.New("room.post: sender is not a member")
	}
	trace, _ := args[argTraceKey].(string)
	m := h.broadcastLockedTraced(rm, roomMsg{Kind: "say", From: UUID(from), Text: text, UnixMilli: h.ts().UnixMilli()}, trace)
	emit(h.observer, Event{Kind: EvRoom, Room: roomID, Peer: from, Detail: "post", Outcome: "ok", Span: NewSpanID()})
	return "posted", map[string]any{"seq": m.Seq}, nil
}

// toolTools returns the tools currently exposed TO `as` — the dynamic,
// per-participant available set (it grows/shrinks as grants change). With
// no `as`, returns every grant in the room for an operator overview.
func (h *RoomHost) toolTools(args map[string]any) (string, any, error) {
	roomID, _ := args["room_id"].(string)
	from, _ := args["from"].(string)
	as, _ := args["as"].(string)
	rm := h.room(roomID, false)
	if rm == nil {
		return "", nil, fmt.Errorf("room.tools: no such room %q", roomID)
	}
	rm.mu.Lock()
	defer rm.mu.Unlock()
	// SECURITY: members-only. A member may enumerate only their OWN granted tools (as==from); listing another
	// member's grants or the whole grant graph (as=="") requires manage rights — else the full trust/grant
	// graph leaks to any caller. `from` is identity-verified (IdentityBound).
	manager := h.canManage(rm, UUID(from))
	if m, ok := rm.members[UUID(from)]; (!ok || !m.Approved) && !manager {
		return "", nil, errors.New("room.tools: you are not a member of this room")
	}
	if as == "" && !manager {
		as = from // a non-manager only ever sees their own grants
	}
	if as != "" && as != from && !manager {
		return "", nil, errors.New("room.tools: only a manager may list another member's grants")
	}
	var avail []map[string]any
	if as != "" {
		avail = rm.grantsTo(UUID(as))
	} else {
		avail = make([]map[string]any, 0)
		for _, g := range rm.grants {
			d := map[string]any{"name": g.Tool["name"], "granted_by": string(g.Granter), "grantee": string(g.Grantee)}
			avail = append(avail, d)
		}
	}
	return fmt.Sprintf("%d tools available to %q in %s", len(avail), as, roomID),
		map[string]any{"room_id": roomID, "available_tools": avail, "private": rm.private}, nil
}

func (h *RoomHost) toolHistory(args map[string]any) (string, any, error) {
	roomID, _ := args["room_id"].(string)
	from, _ := args["from"].(string)
	since := toInt(args["since"])
	rm := h.room(roomID, false)
	if rm == nil {
		return "", nil, fmt.Errorf("room.history: no such room %q", roomID)
	}
	rm.mu.Lock()
	defer rm.mu.Unlock()
	// SECURITY: a room's message log is members-only. `from` is identity-verified (IdentityBound); require
	// it to name an approved member (or a manager) — otherwise any HTTP caller reads any room's full history.
	if m, ok := rm.members[UUID(from)]; (!ok || !m.Approved) && !h.canManage(rm, UUID(from)) {
		return "", nil, errors.New("room.history: you are not a member of this room")
	}
	out := make([]roomMsg, 0)
	for _, m := range rm.msgs {
		if m.Seq > since {
			out = append(out, m)
		}
	}
	return fmt.Sprintf("%d messages", len(out)), map[string]any{"room_id": roomID, "messages": out, "cursor": rm.seq}, nil
}

// toolInvoke calls a tool that `target` has granted to `from`, recording
// the call + result into the room so the exchange is in-band and
// observable. The gate enforces the whole trust model: tools live only in
// a PRIVATE room, both ends must be approved + mutually agreed (keys
// exchanged), and the specific tool must have been granted to the caller.
func (h *RoomHost) toolInvoke(args map[string]any) (string, any, error) {
	roomID, _ := args["room_id"].(string)
	from, _ := args["from"].(string)
	target, _ := args["target"].(string)
	tool, _ := args["tool"].(string)
	callArgs, _ := args["arguments"].(map[string]any)
	rm := h.room(roomID, false)
	if rm == nil {
		return "", nil, fmt.Errorf("room.invoke: no such room %q", roomID)
	}
	rm.mu.Lock()
	if !rm.private {
		rm.mu.Unlock()
		return "", nil, errors.New("room.invoke: tools can only be invoked in a private room")
	}
	caller, okc := rm.members[UUID(from)]
	mem, ok := rm.members[UUID(target)]
	if !okc || !ok {
		rm.mu.Unlock()
		return "", nil, errors.New("room.invoke: caller and target must both be members")
	}
	if !caller.Approved || !mem.Approved {
		rm.mu.Unlock()
		return "", nil, errors.New("room.invoke: both parties must be approved into the room")
	}
	if !rm.mutuallyAgreed(UUID(from), UUID(target)) {
		rm.mu.Unlock()
		return "", nil, errors.New("room.invoke: keys not mutually agreed between caller and target")
	}
	if !rm.hasGrant(UUID(target), UUID(from), tool) {
		rm.mu.Unlock()
		return "", nil, fmt.Errorf("room.invoke: %q is not granted to you by %s (request it first)", tool, target)
	}
	endpoint := mem.Endpoint + mem.MCPPath
	h.broadcastLocked(rm, roomMsg{Kind: "tool_call", From: UUID(from), Target: UUID(target), Tool: tool, Args: callArgs, UnixMilli: h.ts().UnixMilli()})
	rm.mu.Unlock()
	// Invoke the target's real MCP tool. The host signs the call as itself
	// so target ACLs can allow-list the host as a router.
	proof := h.self.signCall(tool, hashArgs(callArgs), h.ts())
	text, structured, err := callRemoteTool(h.http, endpoint, tool, callArgs, &proof, "")
	res := map[string]any{"text": text, "structured": structured}
	if err != nil {
		res = map[string]any{"error": err.Error()}
	}
	rm.mu.Lock()
	h.broadcastLocked(rm, roomMsg{Kind: "tool_result", From: UUID(target), Tool: tool, Result: res, UnixMilli: h.ts().UnixMilli()})
	rm.mu.Unlock()
	return "invoked", map[string]any{"tool": tool, "target": target, "result": res}, nil
}

// toolDeliver is the inbound side: another node's host pushes a room event
// to us. The PoC just logs it (a real participant UI would render it). We
// accept deliveries for any room — the message log on the host is the
// source of truth; this is the live tap.
func (h *RoomHost) toolDeliver(args map[string]any) (string, any, error) {
	roomID, _ := args["room_id"].(string)
	ev, _ := args["event"].(map[string]any)
	h.log.Printf("room %s event: kind=%v from=%v text=%q", roomID, ev["kind"], ev["from"], ev["text"])
	return "ok", map[string]any{"received": true}, nil
}

// registerRoomTools installs the room.* tools on an mcpServer. They are
// always present — every JIP node can host and join rooms — and carry real
// schemas so tools/list documents the chat surface too.
func (h *RoomHost) registerRoomTools(s *mcpServer) {
	obj := func(props map[string]any, required ...string) map[string]any {
		r := map[string]any{"type": "object", "properties": props}
		if len(required) > 0 {
			ra := make([]any, len(required))
			for i, x := range required {
				ra[i] = x
			}
			r["required"] = ra
		}
		return r
	}
	str := map[string]any{"type": "string"}
	boolean := map[string]any{"type": "boolean"}
	reg := func(name, desc string, schema map[string]any, fn toolHandler) {
		// Wrap every room.* handler with the switchboard hook seam: a
		// "before" pass (observe / transform Args / gate via error) and an
		// "after" pass (observe the result). One chokepoint, all methods.
		wrapped := func(args map[string]any) (string, any, error) {
			if err := h.fireRoomHooks(&RoomHookEvent{Phase: "before", Method: name, Args: args}); err != nil {
				return "", nil, err // a before-hook vetoed the call
			}
			text, structured, err := fn(args)
			h.fireRoomHooks(&RoomHookEvent{Phase: "after", Method: name, Args: args, Text: text, Structured: structured, Err: err})
			return text, structured, err
		}
		s.tools[name] = mcpTool{Name: name, Description: desc, InputSchema: schema, Handler: wrapped}
	}
	arr := map[string]any{"type": "array"}
	reg("room.create", "Start a room; caller becomes owner. private=true makes it a tools-capable channel (approval + key agreement + grants gate invocation); default is an open chat lobby. supervisors[] may boot members.",
		obj(map[string]any{"room_id": str, "node_id": str, "alias": str, "endpoint": str, "mcp_path": str, "private": boolean, "supervisors": arr}, "room_id", "node_id"), h.toolCreate)
	reg("room.join", "Join a room with a display alias (asked to pick another if it collides). Public rooms admit immediately; private rooms leave you pending owner approval.",
		obj(map[string]any{"room_id": str, "node_id": str, "alias": str, "endpoint": str, "mcp_path": str}, "room_id", "node_id"), h.toolJoin)
	reg("room.approve", "Owner-only: admit a pending member to a private room after verifying their identity.",
		obj(map[string]any{"room_id": str, "from": str, "target": str}, "room_id", "from", "target"), h.toolApprove)
	reg("room.agree", "Record that you've verified and agreed to another member's identity/keys. Mutual agreement unlocks tool grants in a private room.",
		obj(map[string]any{"room_id": str, "from": str, "target": str}, "room_id", "from", "target"), h.toolAgree)
	reg("room.leave", "Leave a room yourself; your grants are revoked on the way out.",
		obj(map[string]any{"room_id": str, "node_id": str}, "room_id", "node_id"), h.toolLeave)
	reg("room.kick", "Boot another member (owner / room supervisor / host supervisor only). The booted agent's grants are revoked immediately.",
		obj(map[string]any{"room_id": str, "from": str, "target": str}, "room_id", "from", "target"), h.toolKick)
	reg("room.post", "Say a message to the room (allowed in public and private).",
		obj(map[string]any{"room_id": str, "from": str, "text": str}, "room_id", "from", "text"), h.toolPost)
	reg("room.request_tool", "Ask another member to expose a capability to you (e.g. read_dom). Signalling only; the grant is their decision.",
		obj(map[string]any{"room_id": str, "from": str, "capability": str}, "room_id", "from", "capability"), h.toolRequestTool)
	reg("room.grant_tool", "Expose a hook to a grantee in this private room (requires a mutually-agreed pair). The tool becomes immediately invokable by them.",
		obj(map[string]any{"room_id": str, "from": str, "grantee": str, "tool": map[string]any{"type": "object"}}, "room_id", "from", "grantee", "tool"), h.toolGrantTool)
	reg("room.revoke_tool", "Withdraw a previously granted hook; the grantee's available-tool set shrinks live.",
		obj(map[string]any{"room_id": str, "from": str, "grantee": str, "tool": str}, "room_id", "from", "grantee", "tool"), h.toolRevokeTool)
	reg("room.tools", "List the tools currently exposed to `as` (the dynamic, per-participant available set). Members see their own; a manager may omit `as` for an overview of all grants.",
		obj(map[string]any{"room_id": str, "from": str, "as": str}, "room_id", "from"), h.toolTools)
	reg("room.history", "Return room messages with sequence greater than `since` (members only).",
		obj(map[string]any{"room_id": str, "from": str, "since": map[string]any{"type": "integer"}}, "room_id", "from"), h.toolHistory)
	reg("room.invoke", "Call a tool a member has granted to you, in-band; gated by private-room + approval + mutual agreement + an explicit grant. Call and result post to the room.",
		obj(map[string]any{"room_id": str, "from": str, "target": str, "tool": str, "arguments": map[string]any{"type": "object"}}, "room_id", "from", "target", "tool"), h.toolInvoke)
	reg("room.deliver", "Inbound: receive a pushed room event from the host. (Members call history to catch up.)",
		obj(map[string]any{"room_id": str, "event": map[string]any{"type": "object"}}, "room_id", "event"), h.toolDeliver)

	// SECURITY: these room operations act on behalf of the caller's CLAIMED identity (`from`/`node_id`).
	// Marking them IdentityBound makes dispatch require a CallProof whose NodeID == that identity, so a member
	// can no longer forge `from=<owner>` to self-approve, grant a tool, kick the owner, post as someone else,
	// or invoke. This is where the room trust model the docs describe is actually ENFORCED.
	for _, name := range []string{
		"room.create", "room.join", "room.approve", "room.agree", "room.leave",
		"room.kick", "room.post", "room.request_tool", "room.grant_tool",
		"room.revoke_tool", "room.invoke", "room.history", "room.tools",
	} {
		if t, ok := s.tools[name]; ok {
			t.IdentityBound = true
			s.tools[name] = t
		}
	}
}

// --- small helpers shared by the room layer ---

// callRemoteTool issues a tools/call to a remote node's MCP endpoint and
// returns the text + structuredContent of the result. proof, if non-nil,
// authenticates the call for restricted tools.
func callRemoteTool(client *http.Client, endpoint, name string, args map[string]any, proof *CallProof, trace string) (string, any, error) {
	params := map[string]any{"name": name, "arguments": args}
	if proof != nil {
		params["caller"] = proof
	}
	if trace != "" {
		params["trace"] = trace // unsigned W3C traceparent: deliveries stitch into the originating op's trace
	}
	reqBody, _ := json.Marshal(jsonrpcReq{
		JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/call",
		Params: mustRaw(params),
	})
	resp, err := client.Post(endpoint, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var rr jsonrpcResp
	if err := json.Unmarshal(body, &rr); err != nil {
		return "", nil, err
	}
	if rr.Error != nil {
		return "", nil, fmt.Errorf("rpc error %d: %s", rr.Error.Code, rr.Error.Message)
	}
	resMap, _ := rr.Result.(map[string]any)
	if isErr, _ := resMap["isError"].(bool); isErr {
		txt := ""
		if cs, ok := resMap["content"].([]any); ok && len(cs) > 0 {
			if c0, ok := cs[0].(map[string]any); ok {
				txt, _ = c0["text"].(string)
			}
		}
		return "", nil, errors.New(txt)
	}
	text := ""
	if cs, ok := resMap["content"].([]any); ok && len(cs) > 0 {
		if c0, ok := cs[0].(map[string]any); ok {
			text, _ = c0["text"].(string)
		}
	}
	return text, resMap["structuredContent"], nil
}

func mustRaw(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
func mustMap(v any) map[string]any {
	b, _ := json.Marshal(v)
	m := map[string]any{}
	_ = json.Unmarshal(b, &m)
	return m
}
func toMapSlice(v any) []map[string]any {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(arr))
	for _, e := range arr {
		if m, ok := e.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}
func toStrSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}
func toInt(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	}
	return 0
}

// ---------------------------------------------------------------------------
// Agent mode — models a browser agent participating via intents
// ---------------------------------------------------------------------------
//
// This is the executable template for how a browser agent communicates over
// JIP. Like the bench, the agent is UNREACHABLE (can't be dialed), so it:
//   - holds a WebSocket UP to the room host for INBOUND room events (the
//     held-channel on-ramp), and
//   - dispatches its INTENTS as OUTBOUND HTTP room-ops (room.join, room.post,
//     room.invoke) — exactly what a browser agent authors and
//     her heartbeat fires.
//
// A synchronous agent, by contrast, participates synchronously (emits the same room ops
// directly). Same room RPC, two runtimes. Inbound events are folded into a
// "room_recent" log — the analog of an agent writing them into its store.
type AgentConfig struct {
	Host      string
	Room      string
	NodeID    UUID
	Alias     string
	Say       string
	ListenFor time.Duration
}

// agentIntent mirrors the bench's intent shape for room participation.
type agentIntent struct {
	Kind string         // room_post | room_invoke
	Text string         // room_post
	Tool string         // room_invoke
	Args map[string]any // room_invoke
}

func RunAgent(cfg AgentConfig) error {
	if cfg.Host == "" {
		return errors.New("agent mode needs -host <room-host-url>")
	}
	httpc := &http.Client{Timeout: 5 * time.Second}
	post := func(method string, args map[string]any) (map[string]any, error) {
		params := map[string]any{"name": method, "arguments": args}
		b, _ := json.Marshal(jsonrpcReq{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/call", Params: mustRaw(params)})
		resp, err := httpc.Post(strings.TrimRight(cfg.Host, "/")+"/mcp", "application/json", bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		var rr jsonrpcResp
		if err := json.Unmarshal(body, &rr); err != nil {
			return nil, err
		}
		if rr.Error != nil {
			return nil, fmt.Errorf("%s", rr.Error.Message)
		}
		m, _ := rr.Result.(map[string]any)
		return m, nil
	}

	// 1. Hold a WS to the host for inbound room events (a browser agent's tab).
	wsURL := strings.TrimRight(cfg.Host, "/") + "/mcp"
	go agentListenWS(wsURL, cfg.NodeID, func(ev map[string]any) {
		log.Printf("[%s inbound] kind=%v from=%v text=%q tool=%v",
			cfg.Alias, ev["kind"], ev["from"], ev["text"], ev["tool"])
	})
	time.Sleep(300 * time.Millisecond) // let the WS bind before ops

	// 2. Join the room (outbound HTTP op — a dispatched intent).
	if _, err := post("room.join", map[string]any{
		"room_id": cfg.Room, "node_id": string(cfg.NodeID),
		"alias": cfg.Alias, "endpoint": "http://unreachable",
	}); err != nil {
		return fmt.Errorf("join: %w", err)
	}
	log.Printf("[%s] joined room %q via intent dispatch", cfg.Alias, cfg.Room)

	// 3. Drain seeded intents (what the heartbeat does to the evolve's queue).
	var intents []agentIntent
	if cfg.Say != "" {
		intents = append(intents, agentIntent{Kind: "room_post", Text: cfg.Say})
	}
	for _, it := range intents {
		switch it.Kind {
		case "room_post":
			_, err := post("room.post", map[string]any{"room_id": cfg.Room, "from": string(cfg.NodeID), "text": it.Text})
			log.Printf("[%s] dispatched room_post %q (err=%v)", cfg.Alias, it.Text, err)
		case "room_invoke":
			_, err := post("room.invoke", map[string]any{"room_id": cfg.Room, "from": string(cfg.NodeID), "tool": it.Tool, "arguments": it.Args})
			log.Printf("[%s] dispatched room_invoke %q (err=%v)", cfg.Alias, it.Tool, err)
		}
	}

	// 4. Keep listening for inbound events (the agent's replies land here).
	time.Sleep(cfg.ListenFor)
	return nil
}

// agentListenWS opens a WebSocket to the host, binds this node id, and calls
// onEvent for each inbound room.event. Minimal client using the same stdlib
// framing as the server side.
func agentListenWS(url string, node UUID, onEvent func(map[string]any)) {
	u := strings.TrimPrefix(strings.TrimPrefix(url, "http://"), "https://")
	host := u
	if i := strings.Index(u, "/"); i >= 0 {
		host = u[:i]
	}
	conn, err := net.Dial("tcp", host)
	if err != nil {
		log.Printf("agent ws dial: %v", err)
		return
	}
	defer conn.Close()
	key := base64.StdEncoding.EncodeToString([]byte("jip-agent-0001ke"))
	fmt.Fprintf(conn, "GET /mcp HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n", host, key)
	br := bufio.NewReader(conn)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		if line == "\r\n" {
			break
		}
	}
	cli := &wsConn{conn: conn, br: br}
	hello, _ := json.Marshal(jsonrpcReq{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "session.hello", Params: mustRaw(map[string]any{"node_id": string(node)})})
	_ = cli.writeClientText(hello)
	for {
		msg, err := cli.readText()
		if err != nil {
			return
		}
		var n struct {
			Method string `json:"method"`
			Params struct {
				Event map[string]any `json:"event"`
			} `json:"params"`
		}
		if json.Unmarshal(msg, &n) == nil && n.Method == "room.event" {
			onEvent(n.Params.Event)
		}
	}
}

// writeClientText sends a masked text frame (client->server frames MUST be
// masked per RFC 6455).
func (c *wsConn) writeClientText(b []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	var mask [4]byte
	binary.BigEndian.PutUint32(mask[:], 0x9a7b3c1d)
	n := len(b)
	var hdr []byte
	switch {
	case n < 126:
		hdr = []byte{0x81, byte(0x80 | n)}
	case n < 65536:
		hdr = []byte{0x81, 0x80 | 126, byte(n >> 8), byte(n)}
	default:
		hdr = make([]byte, 10)
		hdr[0], hdr[1] = 0x81, 0x80|127
		binary.BigEndian.PutUint64(hdr[2:], uint64(n))
	}
	masked := make([]byte, n)
	for i := range b {
		masked[i] = b[i] ^ mask[i&3]
	}
	if _, err := c.conn.Write(hdr); err != nil {
		return err
	}
	if _, err := c.conn.Write(mask[:]); err != nil {
		return err
	}
	_, err := c.conn.Write(masked)
	return err
}

// ---------------------------------------------------------------------------
// Embed API — run a JIP node inside a host process (e.g. archetyped)
// ---------------------------------------------------------------------------

// Options configures a Node. The embedding host typically sets Advertise to
// its externally-reachable URL and mounts the handlers on its own mux so JIP
// shares the host's port/TLS.
type Options struct {
	Advertise      string        // externally reachable base URL, e.g. "https://home.local:8451"
	MCPPath        string        // default "/mcp"
	Caps           []string      // capability labels to advertise
	Seeds          []string      // bootstrap peer URLs
	Interval       time.Duration // gossip interval (default 3s)
	TTL            time.Duration // presence TTL (default 30s)
	Discover       bool          // enable multicast discovery
	MulticastGroup string        // default "239.42.42.42:9999"
	BeaconEvery    time.Duration // multicast announce cadence (default 5s)
	Restrict       []string      // capability names requiring an authorized caller
	Allow          []string      // caller node ids allowed to call restricted tools
	Supervisors    []string      // node ids permitted to boot members from any hosted room
	InsecureTLS    bool          // skip TLS verification on outbound gossip/room calls (self-signed dev/loopback certs)
	IdentityFile   string        // path to persist this node's ed25519 identity (id+key) → STABLE id across restarts (required to allow-list a specific peer)
	// AUTHORIZED DISCOVERY (opt-in): when AuthorityRoot is set, this node REFUSES to admit any peer that
	// does not present a valid authority-signed grant (verified offline) bound to its id+pubkey, not in
	// the CRL, on a compatible protocol major. Grant is this node's own authorization, attached to its
	// presence. With AuthorityRoot unset, discovery is open (legacy/dev behavior).
	AuthorityRoot ed25519.PublicKey
	Grant         *Grant
	Logger        *log.Logger
	// Observer, when set, receives a telemetry Event at every operation boundary (presence admission, tool
	// calls, room activity). Opt-in and zero-cost when nil — the core does nothing extra without one.
	Observer Observer
}

// jipHTTPClient builds an http.Client, optionally skipping TLS verification — used for the local
// platform where peers serve HTTPS with a shared self-signed (tailnet/loopback) cert. Off by default.
func jipHTTPClient(timeout time.Duration, insecure bool) *http.Client {
	if !insecure {
		return &http.Client{Timeout: timeout}
	}
	// InsecureTLS skips verification ONLY for loopback peers (self-signed dev/loopback certs); any
	// off-host peer is verified normally — so this can never silently become a cross-host MITM hole.
	tr := &http.Transport{DialTLSContext: loopbackAwareTLSDial}
	return &http.Client{Timeout: timeout, Transport: tr}
}

// loopbackAwareTLSDial dials TLS skipping verification for loopback addresses and verifying
// (ServerName-pinned) for everything else. Shared by jip + (mirrored in) agentkit/persona clients.
func loopbackAwareTLSDial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, _ := net.SplitHostPort(addr)
	cfg := &tls.Config{}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		cfg.InsecureSkipVerify = true
	} else {
		cfg.ServerName = host
	}
	return (&tls.Dialer{Config: cfg}).DialContext(ctx, network, addr)
}

// Node is an embeddable JIP peer: identity + registry + gossip + MCP/rooms +
// discovery. Construct with New, mount with RegisterHandlers on the host's
// mux, drive the background loops with Run. New starts no listener or loop.
type Node struct {
	self    *Self
	reg     *Registry
	gossip  *gossipEngine
	mcp     *mcpServer
	rooms   *RoomHost
	discCfg discoveryConfig
	discOn  bool
	revoked *revocationSet // CRL applied during authorized discovery (nil when authz is off)
	log     *log.Logger
}

// revocationSet is the node's view of revoked grant ids (the CRL), updated from the console's signed
// CRL (gossiped/fetched). Used by the authorized-discovery admit gate.
type revocationSet struct {
	mu  sync.RWMutex
	ids map[string]bool
}

func newRevocationSet() *revocationSet { return &revocationSet{ids: map[string]bool{}} }

func (s *revocationSet) has(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ids[id]
}

func (s *revocationSet) set(ids []string) {
	m := make(map[string]bool, len(ids))
	for _, id := range ids {
		m[id] = true
	}
	s.mu.Lock()
	s.ids = m
	s.mu.Unlock()
}

// SetRevoked replaces this node's revocation list (from the console's signed CRL) and immediately EVICTS
// any already-admitted peer whose grant is now revoked — so revocation takes effect within the CRL
// refresh interval (seconds), not at the next TTL expiry. Future presences from a revoked peer are also
// rejected by the admit gate.
func (n *Node) SetRevoked(ids []string) {
	if n.revoked != nil {
		n.revoked.set(ids)
		n.reg.evictRevoked(n.revoked.has)
	}
}

// CurrentGrant returns this node's live authority-signed grant (nil until enrolled). A renewal loop reads
// it to decide when to refresh (e.g. once past half its lifetime).
func (n *Node) CurrentGrant() *Grant { return n.self.currentGrant() }

// SetGrant installs a freshly-issued grant as this node's live authorization. It rides out on the next
// presence broadcast (gossip tick), so a renewed grant keeps the peer in authorized discovery without a
// restart. Callers should verify the grant against the authority root before installing it.
func (n *Node) SetGrant(g Grant) { n.self.setGrant(&g) }

// SignRenewal builds a renewal request for this node's current grant, signed with the node identity key
// (proving possession of the key the grant is pinned to). The console verifies it (VerifyRenewal) then
// re-issues. Returns an error if this node holds no grant. issuedAt is unix seconds (freshness).
func (n *Node) SignRenewal(issuedAt int64) (RenewalRequest, error) {
	g := n.self.currentGrant()
	if g == nil {
		return RenewalRequest{}, errors.New("renew: node holds no grant")
	}
	r := RenewalRequest{Grant: *g, IssuedAt: issuedAt, Alg: SigAlgEd25519}
	r.Signature = ed25519.Sign(n.self.Priv, RenewSigningBytes(r.Alg, g.ID, g.Subject, g.PublicKey, issuedAt))
	return r, nil
}

// AddRoomHook registers a switchboard tap on this node's hosted rooms. The
// hook fires before and after every room.* method and may observe, transform
// (mutate Args), or gate (return an error in the "before" phase) the call.
// This is the seam a supervisor console builds on to watch every room and
// intervene. See RoomHookEvent.
func (n *Node) AddRoomHook(hook RoomHook) { n.rooms.AddRoomHook(hook) }

// RoomsSnapshot returns a read-only view of the rooms this node hosts (roster +
// message counts) so an operator console can witness the live mesh.
func (n *Node) RoomsSnapshot() []RoomView { return n.rooms.RoomsSnapshot() }

// RegisterTool exposes a custom MCP tool on this node's /mcp endpoint — callable
// via tools/call and advertised by tools/list — so capabilities beyond the
// built-in room.* set (e.g. a process control plane) become drivable over the
// mesh. The handler returns (text, structuredContent, error).
//
// Set restricted=true to require an authenticated, allow-listed caller (a signed
// CallProof): use it for ANY tool that acts or spends. Leave it false only for
// read/observation tools. Register before serving begins (the tool map is not
// guarded for concurrent registration during live traffic).
func (n *Node) RegisterTool(name, desc string, schema map[string]any, restricted bool, handler func(args map[string]any) (text string, structured any, err error)) {
	n.mcp.tools[name] = mcpTool{Name: name, Description: desc, InputSchema: schema, Restricted: restricted, Handler: toolHandler(handler)}
}

// New builds a Node without starting any network activity.
func New(opts Options) (*Node, error) {
	logger := opts.Logger
	if logger == nil {
		logger = log.Default()
	}
	mcpPath := opts.MCPPath
	if mcpPath == "" {
		mcpPath = "/mcp"
	}
	caps := make([]Capability, 0, len(opts.Caps))
	for _, c := range opts.Caps {
		if c = strings.TrimSpace(c); c != "" {
			caps = append(caps, Capability(c))
		}
	}
	self, err := newSelf(opts.Advertise, mcpPath, opts.IdentityFile, caps)
	if err != nil {
		return nil, err
	}
	reg := newRegistry(opts.Observer)
	if rec, err := self.signedPresence(time.Now()); err == nil {
		_ = reg.upsert(rec)
	}
	eng := newGossip(self, reg, gossipConfig{Interval: opts.Interval, TTL: opts.TTL, Seeds: opts.Seeds, InsecureTLS: opts.InsecureTLS, Logger: logger})
	acl := newACL(opts.Restrict, opts.Allow)
	hub := newSessionHub()
	mcp := newMCPServer(self, reg, acl, hub, opts.Observer)
	sup := make([]UUID, 0, len(opts.Supervisors))
	for _, s := range opts.Supervisors {
		if s = strings.TrimSpace(s); s != "" {
			sup = append(sup, UUID(s))
		}
	}
	rooms := newRoomHost(self, logger, hub, sup, opts.InsecureTLS, opts.Observer)
	rooms.registerRoomTools(mcp)
	group := opts.MulticastGroup
	if group == "" {
		group = "239.42.42.42:9999"
	}
	self.Grant = opts.Grant

	// Authorized discovery (opt-in): with an authority root configured, install the admit gate so only
	// peers presenting a valid, current, compatible, non-revoked grant bound to their id+pubkey enter
	// the registry. Verified OFFLINE against the root — no console round-trip.
	var revoked *revocationSet
	if len(opts.AuthorityRoot) == ed25519.PublicKeySize {
		revoked = newRevocationSet()
		root := opts.AuthorityRoot
		reg.logger = logger // AUDIT: log admit rejections (reason, deduped per peer)
		reg.admit = func(rec PresenceRecord) error {
			p := rec.Payload
			if !CompatibleMajor(p.ProtocolMajor) {
				return fmt.Errorf("incompatible protocol major %d", p.ProtocolMajor)
			}
			if p.Grant == nil {
				return errors.New("peer presents no grant")
			}
			g := *p.Grant
			if g.Subject != string(p.ID) {
				return errors.New("grant subject != node id")
			}
			if !bytes.Equal(g.PublicKey, p.PublicKey) {
				return errors.New("grant pubkey != node pubkey")
			}
			if revoked.has(g.ID) {
				return errors.New("grant revoked")
			}
			return VerifyGrant(g, root, time.Now())
		}
	}

	return &Node{
		self: self, reg: reg, gossip: eng, mcp: mcp, rooms: rooms,
		discCfg: discoveryConfig{Group: group, Interval: opts.BeaconEvery},
		discOn:  opts.Discover, revoked: revoked, log: logger,
	}, nil
}

// RegisterHandlers mounts /mcp, /gossip, /peers, /whoami on mux. The host
// owns the http.Server.
func (n *Node) RegisterHandlers(mux *http.ServeMux) {
	n.gossip.registerHandlers(mux)
	n.mcp.registerHandlers(mux)
	mux.HandleFunc("/whoami", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"protocol":     ProtocolVersion,
			"id":           n.self.ID,
			"endpoint":     n.self.Endpoint,
			"mcp_path":     n.self.MCPPath,
			"capabilities": n.self.Caps,
		})
	})
}

// Run drives the gossip loop (and discovery if enabled) until ctx is
// cancelled. Call in a goroutine.
func (n *Node) Run(ctx context.Context) error {
	if n.discOn {
		if disc, err := newDiscovery(n.self, n.reg, n.discCfg); err != nil {
			n.log.Printf("jip discovery disabled: %v", err)
		} else {
			n.log.Printf("jip discovery joined %s", n.discCfg.Group)
			go func() {
				if err := disc.run(ctx); err != nil && !errors.Is(err, context.Canceled) {
					n.log.Printf("jip discovery: %v", err)
				}
			}()
		}
	}
	return n.gossip.run(ctx)
}

// ID returns this node's identity. Endpoint returns its advertised URL.
// SignCall produces a CallProof for invoking tool on a remote node, signed with THIS node's private
// key — attach it as params.caller on a tools/call so a restricted (allow-listed) tool will authorize
// it. The proof is single-tool and time-boxed (±30s); a fresh one is needed per call.
func (n *Node) SignCall(tool string, args map[string]any) CallProof {
	return n.self.signCall(tool, hashArgs(args), time.Now())
}

// Peers returns a snapshot of all presence records currently known to this node (self + discovered),
// each carrying endpoint + mcp_path + capabilities — the discovery surface a caller uses to reach peers.
func (n *Node) Peers() []PresenceRecord { return n.reg.snapshot() }

// SignedPresence returns this node's current signed presence record. A node presents it to a host it has
// never met (first contact) so the host can admit it — subject to the discovery admit policy (open, or
// grant-checked under AuthorityRoot) — and thereafter verify this node's signed calls.
func (n *Node) SignedPresence() (PresenceRecord, error) { return n.self.signedPresence(time.Now()) }

func (n *Node) ID() UUID         { return n.self.ID }
func (n *Node) Endpoint() string { return n.self.Endpoint }

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
