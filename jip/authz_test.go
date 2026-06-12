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

// authorizedPeer builds a signed presence record for a fresh peer, with a grant issued by rootPriv
// (unless a different signer is given) on the requested protocol major + TTL. Returns the record and
// its grant id.
func authorizedPeer(signer ed25519.PrivateKey, major int, ttl time.Duration) (PresenceRecord, string) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	id, _ := newUUID()
	g := Grant{
		ID: string(id) + "-g", Subject: string(id), PublicKey: pub, Tier: 1,
		IssuedAt: time.Now().Unix(), NotAfter: time.Now().Add(ttl).Unix(),
	}
	g.Signature = ed25519.Sign(signer, GrantSigningBytes(g))
	rec, _ := sign(priv, PresencePayload{
		Protocol: ProtocolVersion, ID: id, PublicKey: pub, Endpoint: "http://peer", MCPPath: "/mcp",
		HeartbeatUnix: time.Now().Unix(), ProtocolMajor: major, Grant: &g,
	})
	return rec, g.ID
}

// noGrantPeer builds a signed presence record with NO grant.
func noGrantPeer(major int) PresenceRecord {
	pub, priv, _ := ed25519.GenerateKey(nil)
	id, _ := newUUID()
	rec, _ := sign(priv, PresencePayload{
		Protocol: ProtocolVersion, ID: id, PublicKey: pub, Endpoint: "http://peer", MCPPath: "/mcp",
		HeartbeatUnix: time.Now().Unix(), ProtocolMajor: major,
	})
	return rec
}

func authzNode(t *testing.T, root ed25519.PublicKey) *Node {
	n, err := New(Options{Advertise: "http://self:1", AuthorityRoot: root})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return n
}

func TestAuthorizedDiscovery(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(nil)
	_, otherSigner, _ := ed25519.GenerateKey(nil) // a different authority (its grants must be rejected)

	cases := []struct {
		name      string
		rec       func() PresenceRecord
		wantAdmit bool
	}{
		{"valid grant", func() PresenceRecord { r, _ := authorizedPeer(rootPriv, ProtocolMajor, time.Hour); return r }, true},
		{"no grant", func() PresenceRecord { return noGrantPeer(ProtocolMajor) }, false},
		{"incompatible major", func() PresenceRecord { r, _ := authorizedPeer(rootPriv, ProtocolMajor+1, time.Hour); return r }, false},
		{"expired grant", func() PresenceRecord { r, _ := authorizedPeer(rootPriv, ProtocolMajor, -time.Minute); return r }, false},
		{"grant from wrong authority", func() PresenceRecord { r, _ := authorizedPeer(otherSigner, ProtocolMajor, time.Hour); return r }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n := authzNode(t, rootPub)
			res := n.reg.merge([]PresenceRecord{c.rec()})
			admitted := res.Accepted == 1
			if admitted != c.wantAdmit {
				t.Fatalf("%s: admitted=%v want=%v (res %+v)", c.name, admitted, c.wantAdmit, res)
			}
		})
	}
}

func TestRevocationDropsPeer(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(nil)
	n := authzNode(t, rootPub)
	rec, gid := authorizedPeer(rootPriv, ProtocolMajor, time.Hour)

	if res := n.reg.merge([]PresenceRecord{rec}); res.Accepted != 1 {
		t.Fatalf("valid peer should be admitted first: %+v", res)
	}
	n.SetRevoked([]string{gid}) // console revoked this grant; CRL propagated
	// Re-present the SAME (now-revoked) peer: must be rejected.
	if res := n.reg.merge([]PresenceRecord{rec}); res.Rejected != 1 {
		t.Fatalf("revoked peer must be rejected: %+v", res)
	}
}

func TestOpenDiscoveryWhenNoAuthority(t *testing.T) {
	// With no AuthorityRoot, discovery is open — a peer without a grant is admitted (legacy/dev).
	n, err := New(Options{Advertise: "http://self:2"})
	if err != nil {
		t.Fatal(err)
	}
	if res := n.reg.merge([]PresenceRecord{noGrantPeer(ProtocolMajor)}); res.Accepted != 1 {
		t.Fatalf("open discovery should admit ungranted peer: %+v", res)
	}
}
