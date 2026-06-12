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

// Package agentkit gives a persona (or any agent) first-class capabilities on the J3nna mesh,
// reusable across personas. Its first capability is Mesh: the agent hosts a JIP peer (identity,
// presence/gossip, discovery, its own /mcp endpoint) and drives room operations — create, join,
// leave, post, read history, snapshot rosters. This is how an agent becomes a real participant in the
// brigadier room rather than a bolted-on chatbot: she peers onto the mesh like the builder.
package agentkit

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/J3nnaAI/mesh/jip"
)

const defaultMCPPath = "/mcp"

// Mesh is an agent's presence on the JIP mesh. It hosts a jip.Node and performs room operations as
// JSON-RPC tools/call requests. Rooms this peer hosts are reached at its own /mcp; rooms hosted by
// a peer are reached by passing that peer's /mcp URL.
type Mesh struct {
	node    *jip.Node
	srv     *http.Server
	selfMCP string
	hc      *http.Client
	log     *log.Logger
}

// Options configures a mesh peer.
type Options struct {
	Advertise    string   // externally-reachable base URL, e.g. "http://127.0.0.1:8471"
	Listen       string   // listen address for the peer's HTTP server, e.g. ":8471"
	MCPPath      string   // default "/mcp"
	Caps         []string // advertised capability labels
	Seeds        []string // bootstrap peer URLs (gossip discovery)
	Discover     bool     // enable multicast discovery
	Supervisors  []string // node ids permitted to boot members from this peer's hosted rooms
	InsecureTLS  bool     // skip TLS verification reaching peers (self-signed dev/loopback certs)
	IdentityFile string   // persist this peer's ed25519 identity → STABLE node id (so it can be allow-listed)
	// Restricted tools: Restrict names the tools (registered via Node().RegisterTool(..., restricted=true))
	// that require an authorized caller; Allow lists the node ids permitted to call them. A restricted
	// tools/call is accepted only if the caller presents a valid CallProof AND its node id is in Allow.
	Restrict []string
	Allow    []string
	// Authorized discovery (opt-in): with AuthorityRoot set, this peer admits only peers presenting a
	// valid authority-signed grant; Grant is this peer's own authorization (from console enrollment).
	AuthorityRoot []byte
	Grant         *jip.Grant
	Logger        *log.Logger
	// Observer receives a telemetry event for every operation this peer performs (calls, room activity, peer
	// admit/reject). Optional. When nil and JIP_TELEMETRY_URL is set, Open wires a non-blocking HTTP emitter
	// to that collector (e.g. the mesh monitor). nil + no env var = zero-cost, no telemetry.
	Observer jip.Observer
}

// Open constructs the peer, mounts its JIP handlers, and starts the gossip loop + HTTP listener.
// The peer is live on the mesh when Open returns. Cancel ctx to stop gossip; call Close to stop the
// listener.
func Open(ctx context.Context, opts Options) (*Mesh, error) {
	mcpPath := opts.MCPPath
	if mcpPath == "" {
		mcpPath = defaultMCPPath
	}
	logger := opts.Logger
	if logger == nil {
		logger = log.Default()
	}
	// Bind the listener FIRST. With Listen ":0" / "127.0.0.1:0" the OS hands out a free port, which we
	// then advertise — so ANY number of peers share a host with ZERO port assignment. Identity is the
	// JIP node id (stable, allow-listable); the transport port is ephemeral and gossiped via discovery.
	// (A hardcoded per-peer port was the non-scalable shortcut; this removes it.)
	ln, err := net.Listen("tcp", opts.Listen)
	if err != nil {
		return nil, fmt.Errorf("agentkit: listen %s: %w", opts.Listen, err)
	}
	advertise := opts.Advertise
	if advertise == "" {
		advertise = "http://" + ln.Addr().String() // auto: the ACTUAL bound address (ephemeral-friendly)
	}
	observer := opts.Observer
	if observer == nil {
		if url := strings.TrimSpace(os.Getenv("JIP_TELEMETRY_URL")); url != "" {
			observer = jip.NewHTTPObserver(url) // auto-wire telemetry to the configured collector
		}
	}
	node, err := jip.New(jip.Options{
		Advertise: advertise, MCPPath: mcpPath, Caps: opts.Caps, Seeds: opts.Seeds,
		Discover: opts.Discover, Supervisors: opts.Supervisors, InsecureTLS: opts.InsecureTLS,
		IdentityFile: opts.IdentityFile, AuthorityRoot: opts.AuthorityRoot, Grant: opts.Grant,
		Restrict: opts.Restrict, Allow: opts.Allow,
		Logger: logger, Observer: observer,
	})
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	mux := http.NewServeMux()
	node.RegisterHandlers(mux)
	srv := &http.Server{Handler: mux}
	go func() {
		if e := srv.Serve(ln); e != nil && e != http.ErrServerClosed {
			logger.Printf("agentkit: mesh listener: %v", e)
		}
	}()
	go func() { _ = node.Run(ctx) }()
	hc := &http.Client{Timeout: 15 * time.Second}
	if opts.InsecureTLS {
		hc.Transport = InsecureLoopbackTransport()
	}
	return &Mesh{
		node: node, srv: srv, selfMCP: advertise + mcpPath,
		hc: hc, log: logger,
	}, nil
}

func (m *Mesh) ID() string            { return string(m.node.ID()) }
func (m *Mesh) Endpoint() string      { return m.node.Endpoint() }
func (m *Mesh) SelfMCP() string       { return m.selfMCP }
func (m *Mesh) Rooms() []jip.RoomView { return m.node.RoomsSnapshot() }
func (m *Mesh) Node() *jip.Node       { return m.node }

// Peer is a discovered mesh peer: node id, its reachable MCP URL (endpoint+mcp_path), and the
// capability labels it advertises. This is the DISCOVERY surface — what a persona enumerates before
// reaching out to use another agent's tools.
type Peer struct {
	ID   string
	MCP  string
	Caps []string
}

// Peers returns the peers this node currently knows (discovered via multicast/gossip), excluding self.
func (m *Mesh) Peers() []Peer {
	self := m.ID()
	var out []Peer
	for _, r := range m.node.Peers() {
		p := r.Payload
		if string(p.ID) == self {
			continue
		}
		caps := make([]string, 0, len(p.Capabilities))
		for _, c := range p.Capabilities {
			caps = append(caps, string(c))
		}
		out = append(out, Peer{ID: string(p.ID), MCP: strings.TrimRight(p.Endpoint, "/") + p.MCPPath, Caps: caps})
	}
	return out
}

// ToolInfo is one entry from the desktop's tools/list — its name, description and argument schema, so
// a persona can DISCOVER what the body can do before invoking it.
type ToolInfo struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

// PeerTools fetches a peer's advertised tools (JSON-RPC tools/list at its MCP URL).
func (m *Mesh) PeerTools(ctx context.Context, mcpURL string) ([]ToolInfo, error) {
	raw, err := mcpRaw(ctx, m.hc, mcpURL, "", "tools/list", map[string]any{})
	if err != nil {
		return nil, err
	}
	var out struct {
		Tools []ToolInfo `json:"tools"`
	}
	_ = json.Unmarshal(raw, &out)
	return out.Tools, nil
}

// CallPeer invokes a tool on a peer's MCP endpoint and returns its structuredContent. The call is
// SIGNED with this node's key (params.caller) so restricted, allow-listed peer tools authorize it.
func (m *Mesh) CallPeer(ctx context.Context, mcpURL, tool string, args map[string]any) (map[string]any, error) {
	raw, err := mcpRaw(ctx, m.hc, mcpURL, "", "tools/call", m.callParams(tool, args))
	if err != nil {
		return nil, err
	}
	var wrap struct {
		Structured map[string]any `json:"structuredContent"`
	}
	_ = json.Unmarshal(raw, &wrap)
	return wrap.Structured, nil
}

// CallPeerRaw invokes a peer tool (SIGNED) and returns the FULL raw result JSON (content + structured
// + error).
func (m *Mesh) CallPeerRaw(ctx context.Context, mcpURL, tool string, args map[string]any) (json.RawMessage, error) {
	return mcpRaw(ctx, m.hc, mcpURL, "", "tools/call", m.callParams(tool, args))
}

// callParams builds tools/call params with a freshly signed CallProof (ed25519, single-tool, ±30s)
// attached as `caller`, so a restricted peer tool can verify + authorize this node.
func (m *Mesh) callParams(tool string, args map[string]any) map[string]any {
	return map[string]any{"name": tool, "arguments": args, "caller": m.node.SignCall(tool, args)}
}

// InsecureLoopbackTransport skips TLS verification for LOOPBACK peers only (self-signed dev/loopback
// certs) and verifies everything else normally — reusable by any agent client so "insecure TLS" can
// never silently extend to an off-host (MITM-able) peer.
func InsecureLoopbackTransport() *http.Transport {
	return &http.Transport{DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(addr)
		cfg := &tls.Config{}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			cfg.InsecureSkipVerify = true
		} else {
			cfg.ServerName = host
		}
		return (&tls.Dialer{Config: cfg}).DialContext(ctx, network, addr)
	}}
}

// RoomMemberInfo is one current member of a room, from the host's live roster.
type RoomMemberInfo struct {
	NodeID string
	Alias  string
}

// RoomRoster returns the live membership of a room this node hosts (read from the local snapshot — no
// RPC). Lets a responder name participants and resolve a speaker's alias from real data instead of any
// hardcoded identity.
func (m *Mesh) RoomRoster(room string) []RoomMemberInfo {
	var out []RoomMemberInfo
	for _, rv := range m.node.RoomsSnapshot() {
		if rv.ID != room {
			continue
		}
		for _, mem := range rv.Members {
			out = append(out, RoomMemberInfo{NodeID: mem.NodeID, Alias: mem.Alias})
		}
	}
	return out
}

// AddRoomResponder turns a hosted room from a passive bus into a LIVE participant: for every message
// another member posts, fn is invoked (in its own goroutine) and any non-empty reply is posted back to
// that room. Self-posts are ignored so the persona never answers itself into a loop. This is how an agent
// actually collaborates in #brigadier rather than merely hosting it.
func (m *Mesh) AddRoomResponder(fn func(ctx context.Context, room, from, text string) string) {
	self := m.ID()
	m.node.AddRoomHook(func(ev *jip.RoomHookEvent) error {
		if ev.Phase != "after" || ev.Method != "room.post" || ev.Err != nil {
			return nil
		}
		from, _ := ev.Args["from"].(string)
		room, _ := ev.Args["room_id"].(string)
		text, _ := ev.Args["text"].(string)
		if from == self || strings.TrimSpace(text) == "" || strings.TrimSpace(room) == "" {
			return nil // ignore our own posts + empties (no self-reply loop)
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
			defer cancel()
			if reply := fn(ctx, room, from, text); strings.TrimSpace(reply) != "" {
				if e := m.Post(ctx, "", room, reply); e != nil {
					m.log.Printf("agentkit: room responder post: %v", e)
				}
			}
		}()
		return nil
	})
}

// Close stops the HTTP listener. Gossip stops when the ctx passed to Open is cancelled.
func (m *Mesh) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return m.srv.Shutdown(ctx)
}

func (m *Mesh) host(h string) string {
	if h == "" {
		return m.selfMCP
	}
	return h
}

// CreateRoom opens a room with this peer as owner. private=true enables the tool-grant workflow.
func (m *Mesh) CreateRoom(ctx context.Context, roomID, alias string, private bool) error {
	_, err := m.call(ctx, m.selfMCP, "room.create", map[string]any{
		"room_id": roomID, "node_id": m.ID(), "alias": alias,
		"endpoint": m.node.Endpoint(), "mcp_path": defaultMCPPath, "private": private,
	})
	return err
}

// JoinRoom joins a room hosted at hostMCP ("" = a room this peer hosts). Returns the live roster.
func (m *Mesh) JoinRoom(ctx context.Context, hostMCP, roomID, alias string) (Roster, error) {
	res, err := m.call(ctx, m.host(hostMCP), "room.join", map[string]any{
		"room_id": roomID, "node_id": m.ID(), "alias": alias,
		"endpoint": m.node.Endpoint(), "mcp_path": defaultMCPPath,
	})
	if err != nil {
		return nil, err
	}
	return rosterFrom(res), nil
}

// Post sends a message to a room (this peer must be a member).
func (m *Mesh) Post(ctx context.Context, hostMCP, roomID, text string) error {
	_, err := m.call(ctx, m.host(hostMCP), "room.post", map[string]any{
		"room_id": roomID, "from": m.ID(), "text": text,
	})
	return err
}

// Leave leaves a room.
func (m *Mesh) Leave(ctx context.Context, hostMCP, roomID string) error {
	_, err := m.call(ctx, m.host(hostMCP), "room.leave", map[string]any{
		"room_id": roomID, "node_id": m.ID(),
	})
	return err
}

// Message is one room event (from history).
type Message struct {
	Seq  int    `json:"seq"`
	Kind string `json:"kind"`
	From string `json:"from"`
	Text string `json:"text"`
}

// History fetches room messages with seq > since.
func (m *Mesh) History(ctx context.Context, hostMCP, roomID string, since int) ([]Message, error) {
	res, err := m.call(ctx, m.host(hostMCP), "room.history", map[string]any{
		"room_id": roomID, "from": m.ID(), "since": since,
	})
	if err != nil {
		return nil, err
	}
	var out struct {
		Messages []Message `json:"messages"`
	}
	remarshal(res, &out)
	return out.Messages, nil
}

// Roster is a room's membership.
type Roster []jip.RoomMember

func rosterFrom(res map[string]any) Roster {
	var out struct {
		Roster []jip.RoomMember `json:"roster"`
	}
	remarshal(res, &out)
	return out.Roster
}

// ---- JSON-RPC plumbing ----

type rpcReq struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      int            `json:"id"`
	Method  string         `json:"method"`
	Params  map[string]any `json:"params"`
}

type rpcResp struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// call performs a SIGNED tools/call against this peer's chosen host and returns its structuredContent.
// Every mesh op (incl. room.*) now carries this node's CallProof so the host can verify the caller's
// identity — required since room.* + restricted tools are IdentityBound. Without this the host denies them.
func (m *Mesh) call(ctx context.Context, mcpURL, tool string, args map[string]any) (map[string]any, error) {
	var presenter any
	if pres, err := m.node.SignedPresence(); err == nil {
		presenter = pres
	}
	return mcpToolsCallAuth(ctx, m.hc, mcpURL, "", tool, args, m.node.SignCall(tool, args), presenter)
}

// mcpToolsCall is the shared JSON-RPC tools/call client used by both the mesh and the desktop
// bridge — POST {jsonrpc,method:"tools/call",params:{name,arguments}} → result.structuredContent.
func mcpToolsCall(ctx context.Context, hc *http.Client, mcpURL, tool string, args map[string]any) (map[string]any, error) {
	return mcpToolsCallAuth(ctx, hc, mcpURL, "", tool, args, nil, nil)
}

// mcpToolsCallAuth is mcpToolsCall with an optional bearer token — the desktop MCP gates every call
// on a per-client grant (Authorization: Bearer), so the desktop bridge passes the agent's enrolled token.
// An empty bearer sends no auth header (mesh peers are open on loopback).
func mcpToolsCallAuth(ctx context.Context, hc *http.Client, mcpURL, bearer, tool string, args map[string]any, caller, presenter any) (map[string]any, error) {
	params := map[string]any{"name": tool, "arguments": args}
	if caller != nil {
		params["caller"] = caller // signed CallProof so the host can verify identity for IdentityBound/restricted tools
	}
	if presenter != nil {
		params["presenter"] = presenter // signed presence record so a host we've never met can admit us first
	}
	body, _ := json.Marshal(rpcReq{
		JSONRPC: "2.0", ID: 1, Method: "tools/call",
		Params: params,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, mcpURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("agentkit: %s: %w", tool, err)
	}
	defer resp.Body.Close()
	var rr rpcResp
	if err := json.NewDecoder(resp.Body).Decode(&rr); err != nil {
		return nil, fmt.Errorf("agentkit: %s decode: %w", tool, err)
	}
	if rr.Error != nil {
		return nil, fmt.Errorf("agentkit: %s: %s", tool, rr.Error.Message)
	}
	var wrap struct {
		Structured map[string]any `json:"structuredContent"`
	}
	_ = json.Unmarshal(rr.Result, &wrap)
	return wrap.Structured, nil
}

// mcpRaw performs an arbitrary JSON-RPC method (e.g. tools/list) and returns the raw `result` JSON —
// for calls whose payload isn't the tools/call structuredContent envelope.
func mcpRaw(ctx context.Context, hc *http.Client, mcpURL, bearer, method string, params map[string]any) (json.RawMessage, error) {
	body, _ := json.Marshal(rpcReq{JSONRPC: "2.0", ID: 1, Method: method, Params: params})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, mcpURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("agentkit: %s: %w", method, err)
	}
	defer resp.Body.Close()
	var rr rpcResp
	if err := json.NewDecoder(resp.Body).Decode(&rr); err != nil {
		return nil, fmt.Errorf("agentkit: %s decode: %w", method, err)
	}
	if rr.Error != nil {
		return nil, fmt.Errorf("agentkit: %s: %s", method, rr.Error.Message)
	}
	return rr.Result, nil
}

func remarshal(in any, out any) {
	b, _ := json.Marshal(in)
	_ = json.Unmarshal(b, out)
}
