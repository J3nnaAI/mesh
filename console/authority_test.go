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

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/J3nnaAI/mesh/jip"
)

// TestGrantIssueVerify exercises the offline grant-verification path peers rely on: a valid grant
// verifies against the authority root; a tampered grant, an expired grant, and verification against a
// different root all FAIL closed.
func TestGrantIssueVerify(t *testing.T) {
	dir := t.TempDir()
	a, err := openAuthority(dir+"/root.key", dir+"/crl.json")
	if err != nil {
		t.Fatalf("openAuthority: %v", err)
	}
	pub, _, _ := ed25519.GenerateKey(nil)

	g, err := a.IssueGrant("node-1", pub, 2, []string{"room.join"})
	if err != nil {
		t.Fatalf("IssueGrant: %v", err)
	}
	if err := jip.VerifyGrant(g, a.RootPub(), time.Now()); err != nil {
		t.Fatalf("valid grant should verify: %v", err)
	}

	bad := g
	bad.Tier = 9 // signature covers Tier → must fail
	if jip.VerifyGrant(bad, a.RootPub(), time.Now()) == nil {
		t.Fatal("tampered grant must fail")
	}

	if jip.VerifyGrant(g, a.RootPub(), time.Unix(g.NotAfter+1, 0)) == nil {
		t.Fatal("expired grant must fail")
	}

	otherPub, _, _ := ed25519.GenerateKey(nil)
	if jip.VerifyGrant(g, otherPub, time.Now()) == nil {
		t.Fatal("verification against the wrong root must fail")
	}
}

// TestGrantSurvivesRootReload confirms the persisted root key verifies grants across a restart.
func TestGrantSurvivesRootReload(t *testing.T) {
	dir := t.TempDir()
	a1, _ := openAuthority(dir+"/root.key", dir+"/crl.json")
	pub, _, _ := ed25519.GenerateKey(nil)
	g, _ := a1.IssueGrant("node-2", pub, 1, nil)

	a2, err := openAuthority(dir+"/root.key", dir+"/crl.json") // reload same key
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if err := jip.VerifyGrant(g, a2.RootPub(), time.Now()); err != nil {
		t.Fatalf("grant should verify against the reloaded root: %v", err)
	}
}

// signRenewal builds a renewal request for grant g signed by the node key nodePriv (the key the grant is
// pinned to), mirroring what agentkit does on the wire.
func signRenewal(nodePriv ed25519.PrivateKey, g jip.Grant) jip.RenewalRequest {
	now := time.Now().Unix()
	r := jip.RenewalRequest{Grant: g, IssuedAt: now, Alg: jip.SigAlgEd25519}
	r.Signature = ed25519.Sign(nodePriv, jip.RenewSigningBytes(r.Alg, g.ID, g.Subject, g.PublicKey, now))
	return r
}

// TestRenewGrant exercises the console's renewal path: a valid grant renews to the SAME id with an
// advanced expiry (verifiable against the root); a REVOKED grant cannot be renewed (revocation dominates);
// and a grant from a different authority cannot be renewed.
func TestRenewGrant(t *testing.T) {
	dir := t.TempDir()
	a, err := openAuthority(dir+"/root.key", dir+"/crl.json")
	if err != nil {
		t.Fatalf("openAuthority: %v", err)
	}
	pub, priv, _ := ed25519.GenerateKey(nil)
	g, _ := a.IssueGrant("node-renew", pub, 1, []string{"room.join"})

	// Happy path: the node proves possession of its key, the console re-issues.
	req := signRenewal(priv, g)
	if err := jip.VerifyRenewal(req, time.Now()); err != nil {
		t.Fatalf("valid renewal request should verify: %v", err)
	}
	fresh, err := a.RenewGrant(req.Grant)
	if err != nil {
		t.Fatalf("RenewGrant: %v", err)
	}
	if fresh.ID != g.ID {
		t.Fatalf("renewal must keep the SAME grant id (the stable revocation handle): %s != %s", fresh.ID, g.ID)
	}
	if fresh.NotAfter < g.NotAfter {
		t.Fatalf("renewal must advance the expiry: %d !> %d", fresh.NotAfter, g.NotAfter)
	}
	if err := jip.VerifyGrant(fresh, a.RootPub(), time.Now()); err != nil {
		t.Fatalf("renewed grant must verify against the root: %v", err)
	}

	// Revocation dominates: once the id is revoked, it can never be renewed again.
	if err := a.Revoke(g.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := a.RenewGrant(fresh); err == nil {
		t.Fatal("a revoked grant must not be renewable")
	}

	// A grant from a different authority cannot be renewed here (bad signature).
	other, _ := openAuthority(dir+"/other.key", dir+"/other-crl.json")
	foreign, _ := other.IssueGrant("node-x", pub, 1, nil)
	if _, err := a.RenewGrant(foreign); err == nil {
		t.Fatal("a grant from a different authority must not be renewable")
	}
}
