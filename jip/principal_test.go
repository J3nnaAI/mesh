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

func TestPrincipalBinding(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	now := time.Now()
	base := Grant{ID: "g1", Subject: "node1", PublicKey: pub, Tier: 1, IssuedAt: now.Unix(), NotAfter: now.Add(time.Hour).Unix()}

	// Legacy grant (no principal): signs + verifies exactly as before; fails the service (bound) check.
	g := base
	g.Signature = ed25519.Sign(priv, GrantSigningBytes(g))
	if err := VerifyGrant(g, pub, now); err != nil {
		t.Fatalf("legacy principal-less grant failed plain verify: %v", err)
	}
	if err := VerifyServiceGrant(g, pub, now); err == nil {
		t.Fatal("a principal-less grant passed the service (bound) check — the floor must refuse it")
	}

	// Principal-bound grant: verifies as a serving identity.
	pg := base
	pg.Principal = "Jason"
	pg.Signature = ed25519.Sign(priv, GrantSigningBytes(pg))
	if err := VerifyServiceGrant(pg, pub, now); err != nil {
		t.Fatalf("principal-bound grant failed the service check: %v", err)
	}

	// Rebinding whom-she-serves without the authority key MUST break the signature.
	tampered := pg
	tampered.Principal = "Mallory"
	if err := VerifyGrant(tampered, pub, now); err == nil {
		t.Fatal("rebinding the principal was NOT detected — whom-she-serves is not cryptographically bound")
	}
	// And stripping the principal off a bound grant also breaks it.
	stripped := pg
	stripped.Principal = ""
	if err := VerifyGrant(stripped, pub, now); err == nil {
		t.Fatal("stripping the principal off a bound grant was not detected")
	}
}
