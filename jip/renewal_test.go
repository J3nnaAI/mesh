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

import (
	"crypto/ed25519"
	"path/filepath"
	"testing"
	"time"
)

// controlledPeer is like authorizedPeer but returns the peer's private key so the test can re-sign its
// presence after a grant renewal. mkGrant builds a grant for this peer with the given lifetime, signed
// by signer; presence builds a fresh signed presence record carrying a given grant.
type controlledPeer struct {
	id   UUID
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func newControlledPeer() controlledPeer {
	pub, priv, _ := ed25519.GenerateKey(nil)
	id, _ := newUUID()
	return controlledPeer{id: id, priv: priv, pub: pub}
}

func (p controlledPeer) grant(signer ed25519.PrivateKey, ttl time.Duration) Grant {
	now := time.Now()
	g := Grant{
		ID: string(p.id) + "-g", Subject: string(p.id), PublicKey: p.pub, Tier: 1,
		IssuedAt: now.Unix(), NotAfter: now.Add(ttl).Unix(),
	}
	g.Signature = ed25519.Sign(signer, GrantSigningBytes(g))
	return g
}

func (p controlledPeer) presence(g Grant) PresenceRecord {
	rec, _ := sign(p.priv, PresencePayload{
		Protocol: ProtocolVersion, ID: p.id, PublicKey: p.pub, Endpoint: "http://peer", MCPPath: "/mcp",
		HeartbeatUnix: time.Now().UnixNano(), ProtocolMajor: ProtocolMajor, Grant: &g,
	})
	return rec
}

// consoleRenew models the authority's RenewGrant: re-sign the SAME grant id with an advanced expiry.
func consoleRenew(rootPriv ed25519.PrivateKey, cur Grant, ttl time.Duration) Grant {
	now := time.Now()
	g := cur // same id/subject/pubkey/tier/scopes
	g.IssuedAt = now.Unix()
	g.NotAfter = now.Add(ttl).Unix()
	g.Signature = ed25519.Sign(rootPriv, GrantSigningBytes(g))
	return g
}

// TestRenewalAdmitsAcrossTTLBoundary is the core property: a peer whose grant has expired is rejected,
// but the SAME peer presenting a renewed grant (re-issued before expiry in real life) is admitted again —
// so a long-running peer stays in authorized discovery past one TTL boundary instead of partitioning.
func TestRenewalAdmitsAcrossTTLBoundary(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(nil)
	n := authzNode(t, rootPub)
	peer := newControlledPeer()

	// The grant has expired (we are PAST the TTL boundary): admission must fail.
	expired := peer.grant(rootPriv, -time.Second)
	if res := n.reg.merge([]PresenceRecord{peer.presence(expired)}); res.Rejected != 1 {
		t.Fatalf("expired grant must be rejected at the TTL boundary: %+v", res)
	}

	// Renewal re-issues the same grant id with a fresh window; the peer re-presents and is admitted.
	renewed := consoleRenew(rootPriv, expired, time.Hour)
	if res := n.reg.merge([]PresenceRecord{peer.presence(renewed)}); res.Accepted != 1 {
		t.Fatalf("renewed grant must be admitted (peer stays on the mesh): %+v", res)
	}
}

// TestRevocationDominatesRenewal proves the stable-id design: because renewal keeps the SAME grant id,
// revoking that id kills the whole renewal chain — a renewed grant carrying a revoked id is rejected.
func TestRevocationDominatesRenewal(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(nil)
	n := authzNode(t, rootPub)
	peer := newControlledPeer()

	g := peer.grant(rootPriv, time.Hour)
	if res := n.reg.merge([]PresenceRecord{peer.presence(g)}); res.Accepted != 1 {
		t.Fatalf("fresh grant should admit: %+v", res)
	}
	n.SetRevoked([]string{g.ID}) // operator revokes the (stable) grant id

	// Even a freshly RENEWED grant — same id, valid signature, far-future expiry — must be rejected.
	renewed := consoleRenew(rootPriv, g, time.Hour)
	if res := n.reg.merge([]PresenceRecord{peer.presence(renewed)}); res.Rejected != 1 {
		t.Fatalf("revocation must dominate renewal (same id stays revoked): %+v", res)
	}
}

// TestRenewalRequestAuth covers the /renew request authentication: a request signed by the node key
// verifies; tampering, staleness, or a wrong key are rejected. Node.SignRenewal is exercised end-to-end.
func TestRenewalRequestAuth(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(nil)

	// Build a node that holds a grant, using a persisted identity so SignRenewal signs with the same key
	// the grant is pinned to.
	idFile := filepath.Join(t.TempDir(), "id.json")
	id, pub, err := EnsureIdentity(idFile)
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	now := time.Now()
	g := Grant{ID: string(id) + "-g", Subject: string(id), PublicKey: pub, Tier: 1,
		IssuedAt: now.Unix(), NotAfter: now.Add(time.Hour).Unix()}
	g.Signature = ed25519.Sign(rootPriv, GrantSigningBytes(g))

	n, err := New(Options{Advertise: "http://self", AuthorityRoot: rootPub, Grant: &g, IdentityFile: idFile})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req, err := n.SignRenewal(time.Now().Unix())
	if err != nil {
		t.Fatalf("SignRenewal: %v", err)
	}
	if err := VerifyRenewal(req, time.Now()); err != nil {
		t.Fatalf("valid renewal request should verify: %v", err)
	}

	// Tampered signature → rejected.
	bad := req
	bad.Signature = append([]byte(nil), req.Signature...)
	bad.Signature[0] ^= 0xFF
	if VerifyRenewal(bad, time.Now()) == nil {
		t.Fatalf("tampered signature must be rejected")
	}

	// Stale timestamp (beyond RenewMaxSkew) → rejected.
	if VerifyRenewal(req, time.Now().Add(2*RenewMaxSkew)) == nil {
		t.Fatalf("stale renewal request must be rejected")
	}

	// A request whose signature is from a DIFFERENT key than the grant pins → rejected.
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	forged := RenewalRequest{Grant: g, IssuedAt: time.Now().Unix(), Alg: SigAlgEd25519}
	forged.Signature = ed25519.Sign(otherPriv, RenewSigningBytes(forged.Alg, g.ID, g.Subject, g.PublicKey, forged.IssuedAt))
	if VerifyRenewal(forged, time.Now()) == nil {
		t.Fatalf("renewal signed by a non-pinned key must be rejected")
	}

	// A node that holds no grant cannot build a renewal request.
	bare, _ := New(Options{Advertise: "http://bare"})
	if _, err := bare.SignRenewal(time.Now().Unix()); err == nil {
		t.Fatalf("SignRenewal must fail when the node holds no grant")
	}
}
