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
	"testing"
	"time"
)

// TestSigAlgFailClosed proves the crypto-agility tag is enforced fail-closed across every signed
// structure: an unknown (e.g. future post-quantum) algorithm value is rejected by today's verifiers, so
// a v1 peer can never be tricked onto a signature path it cannot verify. Empty == ed25519 (the default).
func TestSigAlgFailClosed(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(nil)
	peer := newControlledPeer()

	// Presence: empty alg is accepted (== ed25519); an unknown alg is rejected.
	n := authzNode(t, rootPub)
	g := peer.grant(rootPriv, time.Hour)
	if res := n.reg.merge([]PresenceRecord{peer.presence(g)}); res.Accepted != 1 {
		t.Fatalf("presence with default (empty) alg should be admitted: %+v", res)
	}
	future := newControlledPeer()
	fg := future.grant(rootPriv, time.Hour)
	rec, _ := sign(future.priv, PresencePayload{
		Protocol: ProtocolVersion, ID: future.id, PublicKey: future.pub, Endpoint: "http://p", MCPPath: "/mcp",
		HeartbeatUnix: time.Now().UnixNano(), ProtocolMajor: ProtocolMajor, Grant: &fg, Alg: "pq-future",
	})
	if err := rec.Verify(); err == nil {
		t.Fatal("presence with an unknown signature algorithm must be rejected")
	}

	// Grant: unknown authority-signature algorithm is rejected.
	bad := peer.grant(rootPriv, time.Hour)
	bad.Alg = "pq-future"
	bad.Signature = ed25519.Sign(rootPriv, GrantSigningBytes(bad)) // even a VALID signature over the new alg…
	if VerifyGrant(bad, rootPub, time.Now()) == nil {
		t.Fatal("grant with an unknown algorithm must be rejected even if the signature itself verifies")
	}

	// The tag is signature-COVERED: tampering a valid ed25519 grant's alg breaks verification.
	tampered := peer.grant(rootPriv, time.Hour) // signed with default alg
	tampered.Alg = "pq-future"                  // flip the tag WITHOUT re-signing
	if VerifyGrant(tampered, rootPub, time.Now()) == nil {
		t.Fatal("flipping a signed grant's alg tag must break verification (tag is covered)")
	}

	// SignedCRL: unknown algorithm rejected.
	crl := SignedCRL{Revoked: map[string]int64{"x": 1}, IssuedAt: time.Now().Unix(), Alg: "pq-future"}
	crl.Signature = ed25519.Sign(rootPriv, CRLSigningBytes(crl))
	if VerifyCRL(crl, rootPub) == nil {
		t.Fatal("CRL with an unknown algorithm must be rejected")
	}

	// RenewalRequest: unknown algorithm rejected.
	rr := RenewalRequest{Grant: g, IssuedAt: time.Now().Unix(), Alg: "pq-future"}
	rr.Signature = ed25519.Sign(peer.priv, RenewSigningBytes(rr.Alg, g.ID, g.Subject, g.PublicKey, rr.IssuedAt))
	if VerifyRenewal(rr, time.Now()) == nil {
		t.Fatal("renewal request with an unknown algorithm must be rejected")
	}
}
