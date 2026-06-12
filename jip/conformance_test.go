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

package jip

// Cross-language conformance vectors. This test is the executable contract every non-Go SDK (Python, TS,
// Rust, Java, C#, …) must satisfy: for a fixed set of inputs and keys it pins the EXACT canonical signing
// bytes and the resulting ed25519 signatures. A port reproduces the bytes from the inputs, checks them
// against `signing_bytes_hex`, then checks its signature against `signature_b64` (ed25519 is deterministic,
// so the signature is reproducible). If those match, the port is wire-compatible with the Go reference.
//
// It is also a drift guard for the Go reference: change a framing detail and this test fails until the
// vectors are deliberately regenerated (JIP_UPDATE_VECTORS=1), which forces a conscious wire decision.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type confVector struct {
	Name               string         `json:"name"`
	Description        string         `json:"description"`
	SignerPublicKeyHex string         `json:"signer_public_key_hex"`
	Input              map[string]any `json:"input"`
	SigningBytesHex    string         `json:"signing_bytes_hex"`
	SignatureB64       string         `json:"signature_b64"`
}

type confFile struct {
	Protocol      string       `json:"protocol"`
	ProtocolMajor int          `json:"protocol_major"`
	Framing       string       `json:"framing"`
	Note          string       `json:"note"`
	Vectors       []confVector `json:"vectors"`
}

func seq(start byte) []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = start + byte(i)
	}
	return s
}

// TestConformanceVectors builds the fixtures and either writes them (JIP_UPDATE_VECTORS=1) or asserts the
// committed conformance/vectors.json still matches (so a wire change can't land silently).
func TestConformanceVectors(t *testing.T) {
	nodePriv := ed25519.NewKeyFromSeed(seq(0x01)) // deterministic peer key
	nodePub := nodePriv.Public().(ed25519.PublicKey)
	rootPriv := ed25519.NewKeyFromSeed(seq(0x40)) // deterministic authority root key
	rootPub := rootPriv.Public().(ed25519.PublicKey)

	const nodeID = "11111111-1111-1111-1111-111111111111"
	const t0 = int64(1735689600)     // fixed unix seconds
	const tms = int64(1735689600000) // fixed unix millis

	var vecs []confVector

	// ── 1. presence record (signed by the peer's node key) ──
	pp := PresencePayload{
		Protocol:      ProtocolVersion,
		ID:            UUID(nodeID),
		PublicKey:     nodePub,
		Endpoint:      "http://10.0.0.5:8471",
		MCPPath:       "/mcp",
		Capabilities:  []Capability{"tools", "chat"}, // intentionally unsorted; canonical sorts them
		ProtocolMajor: ProtocolMajor,
		HeartbeatUnix: t0,
	}
	ppBytes, err := pp.canonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	vecs = append(vecs, confVector{
		Name:               "presence-record",
		Description:        "PresencePayload.canonicalBytes — protocol, alg, id, pubkey, endpoint, mcp_path, sorted caps (count-prefixed), protocol_major (uint32), grant_id, heartbeat (uint64).",
		SignerPublicKeyHex: hex.EncodeToString(nodePub),
		Input: map[string]any{
			"protocol":       pp.Protocol,
			"alg":            SigAlgEd25519,
			"id":             string(pp.ID),
			"public_key_hex": hex.EncodeToString(pp.PublicKey),
			"endpoint":       pp.Endpoint,
			"mcp_path":       pp.MCPPath,
			"capabilities":   []string{"tools", "chat"},
			"protocol_major": pp.ProtocolMajor,
			"grant_id":       "",
			"heartbeat_unix": pp.HeartbeatUnix,
		},
		SigningBytesHex: hex.EncodeToString(ppBytes),
		SignatureB64:    base64.StdEncoding.EncodeToString(ed25519.Sign(nodePriv, ppBytes)),
	})

	// ── 2. grant (signed by the authority root key) ──
	g := Grant{
		ID:        "grant-0001",
		Subject:   nodeID,
		PublicKey: nodePub,
		Tier:      3,
		Scopes:    []string{"tools:call", "room:join"}, // canonical sorts them
		IssuedAt:  t0,
		NotAfter:  t0 + 3600,
	}
	gBytes := GrantSigningBytes(g)
	vecs = append(vecs, confVector{
		Name:               "grant",
		Description:        "GrantSigningBytes — domain 'J3nna-mesh-grant/1', alg, id, subject, pubkey, tier (uint64), sorted scopes (NUL-joined), issued_at, not_after (uint64). Signed by the AUTHORITY ROOT key.",
		SignerPublicKeyHex: hex.EncodeToString(rootPub),
		Input: map[string]any{
			"alg":            SigAlgEd25519,
			"id":             g.ID,
			"subject":        g.Subject,
			"public_key_hex": hex.EncodeToString(g.PublicKey),
			"tier":           g.Tier,
			"scopes":         []string{"tools:call", "room:join"},
			"issued_at":      g.IssuedAt,
			"not_after":      g.NotAfter,
			"principal":      "",
		},
		SigningBytesHex: hex.EncodeToString(gBytes),
		SignatureB64:    base64.StdEncoding.EncodeToString(ed25519.Sign(rootPriv, gBytes)),
	})

	// ── 3. CallProof (signed by the peer's node key) ──
	// ArgsHash = sha256( Go json.Marshal(args) ). Go sorts map keys and HTML-escapes; an SDK MUST reproduce
	// that exact byte string. args_canonical_json below shows the precise bytes that get hashed.
	// Args deliberately exercise the two cross-language JSON divergence points: a '/' (which Go does NOT
	// escape, but some encoders emit as '\/') and '<>&' (which Go's json.Marshal HTML-escapes). An SDK must
	// reproduce Go's exact bytes or its args_hash diverges — the bug live-testing caught in a slash-bearing
	// endpoint URL.
	args := map[string]any{"message": "hello/world", "count": 3, "path": "/v1/tools", "html": "<b>a&b</b>"}
	argsJSON, _ := json.Marshal(args)
	argsHash := hashArgs(args)
	cp := CallProof{
		NodeID:    UUID(nodeID),
		Tool:      "echo",
		ArgsHash:  argsHash,
		UnixMilli: tms,
	}
	cpBytes := cp.signedBytes()
	vecs = append(vecs, confVector{
		Name:               "callproof",
		Description:        "CallProof.signedBytes — domain 'JIP-call/0.2', alg, node_id, tool, args_hash, unix_milli (uint64). args_hash = sha256(canonical_json), where canonical_json = Go json.Marshal(args): keys sorted, '<>&' HTML-escaped, '/' NOT escaped. args_canonical_json is the exact bytes an SDK must reproduce. Signed by the caller's NODE key.",
		SignerPublicKeyHex: hex.EncodeToString(nodePub),
		Input: map[string]any{
			"alg":                 SigAlgEd25519,
			"node_id":             string(cp.NodeID),
			"tool":                cp.Tool,
			"args":                args,
			"args_canonical_json": string(argsJSON),
			"args_hash_hex":       hex.EncodeToString(argsHash),
			"unix_milli":          cp.UnixMilli,
		},
		SigningBytesHex: hex.EncodeToString(cpBytes),
		SignatureB64:    base64.StdEncoding.EncodeToString(ed25519.Sign(nodePriv, cpBytes)),
	})

	// ── 4. renewal request (signed by the peer's NODE key — proves possession of the grant's pinned key) ──
	rnBytes := RenewSigningBytes(SigAlgEd25519, g.ID, g.Subject, nodePub, t0)
	vecs = append(vecs, confVector{
		Name:               "renewal",
		Description:        "RenewSigningBytes — domain 'J3nna-mesh-renew/1', alg, grant_id, subject, pubkey, issued_at (uint64), all length-prefixed except the trailing uint64. Signed by the peer's NODE key to prove possession of the grant's pinned key.",
		SignerPublicKeyHex: hex.EncodeToString(nodePub),
		Input: map[string]any{
			"alg":            SigAlgEd25519,
			"grant_id":       g.ID,
			"subject":        g.Subject,
			"public_key_hex": hex.EncodeToString(nodePub),
			"issued_at":      t0,
		},
		SigningBytesHex: hex.EncodeToString(rnBytes),
		SignatureB64:    base64.StdEncoding.EncodeToString(ed25519.Sign(nodePriv, rnBytes)),
	})

	// ── 5. CRL (signed by the AUTHORITY ROOT key) ──
	crl := SignedCRL{
		Revoked:  map[string]int64{"grant-0007": t0 + 10, "grant-0003": t0 + 5}, // unsorted on purpose; canonical sorts ids
		IssuedAt: t0,
	}
	crlBytes := CRLSigningBytes(crl)
	vecs = append(vecs, confVector{
		Name:               "crl",
		Description:        "CRLSigningBytes — ASCII 'J3nna-mesh-crl/1|<alg>|<issued_at>|' then each revoked grant id in SORTED order, each followed by a comma. Revoked-at timestamps are NOT in the signed bytes. Signed by the AUTHORITY ROOT key.",
		SignerPublicKeyHex: hex.EncodeToString(rootPub),
		Input: map[string]any{
			"alg":       SigAlgEd25519,
			"issued_at": crl.IssuedAt,
			"revoked":   map[string]int64{"grant-0007": t0 + 10, "grant-0003": t0 + 5}, // SDK sorts the ids
		},
		SigningBytesHex: hex.EncodeToString(crlBytes),
		SignatureB64:    base64.StdEncoding.EncodeToString(ed25519.Sign(rootPriv, crlBytes)),
	})

	out := confFile{
		Protocol:      ProtocolVersion,
		ProtocolMajor: ProtocolMajor,
		Framing:       "Every variable-length field is prefixed with a 4-byte big-endian length, then its raw bytes. Integers are 8-byte big-endian. Sets (capabilities, scopes) are sorted before framing. Signatures are ed25519 over the signing bytes (deterministic).",
		Note:          "Cross-language conformance fixtures. Regenerate with JIP_UPDATE_VECTORS=1 go test ./... -run TestConformanceVectors. SDKs in any language assert against this file.",
		Vectors:       vecs,
	}
	got, _ := json.MarshalIndent(out, "", "  ")
	got = append(got, '\n')

	path := filepath.Join("conformance", "vectors.json")
	if os.Getenv("JIP_UPDATE_VECTORS") == "1" {
		if err := os.MkdirAll("conformance", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", path)
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s missing — generate it once with: JIP_UPDATE_VECTORS=1 go test -run TestConformanceVectors", path)
	}
	if !bytes.Equal(bytes.TrimSpace(got), bytes.TrimSpace(want)) {
		t.Fatalf("conformance vectors drifted — the canonical wire bytes changed.\nIf intentional, regenerate with JIP_UPDATE_VECTORS=1 (and treat it as a protocol change per VERSIONING.md).")
	}
}
