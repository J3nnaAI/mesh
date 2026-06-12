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

// The authority — the mesh's ROOT of trust. It holds an ed25519 root keypair and ISSUES the signed
// grants peers verify offline (the Grant format + verification live in the jip protocol layer, so
// issuer and verifier agree byte-for-byte; the authority is the one party holding the private key).
// It also publishes a signed CRL. The console is never on the hot path — it issues and revokes; peers
// run on cached grants and verify against the root pubkey served at /authority.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/J3nnaAI/mesh/jip"
)

type authority struct {
	priv    ed25519.PrivateKey
	pub     ed25519.PublicKey
	mu      sync.Mutex
	revoked map[string]int64 // grant id -> revoked-at unix (the CRL)
	keyPath string
	crlPath string
}

type rootKeyBlob struct {
	Priv string `json:"priv_b64"`
}

// openAuthority loads or generates the root keypair (0600) and loads the CRL.
func openAuthority(keyPath, crlPath string) (*authority, error) {
	a := &authority{revoked: map[string]int64{}, keyPath: keyPath, crlPath: crlPath}
	if data, err := os.ReadFile(keyPath); err == nil {
		var blob rootKeyBlob
		if json.Unmarshal(data, &blob) == nil {
			if raw, err := base64.StdEncoding.DecodeString(blob.Priv); err == nil && len(raw) == ed25519.PrivateKeySize {
				a.priv = ed25519.PrivateKey(raw)
				a.pub = a.priv.Public().(ed25519.PublicKey)
			}
		}
	}
	if a.priv == nil {
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			return nil, err
		}
		a.priv, a.pub = priv, pub
		blob, _ := json.Marshal(rootKeyBlob{Priv: base64.StdEncoding.EncodeToString(priv)})
		if e := os.MkdirAll(filepath.Dir(keyPath), 0o700); e == nil {
			_ = os.WriteFile(keyPath, blob, 0o600)
		}
	}
	if data, err := os.ReadFile(crlPath); err == nil {
		_ = json.Unmarshal(data, &a.revoked)
	}
	return a, nil
}

// IssueGrant signs a fresh jip.Grant binding subject↔pubkey for jip.GrantTTL.
func (a *authority) IssueGrant(subject string, pub []byte, tier int, scopes []string) (jip.Grant, error) {
	if subject == "" || len(pub) != ed25519.PublicKeySize {
		return jip.Grant{}, fmt.Errorf("grant: subject and 32-byte pubkey required")
	}
	id, err := newToken()
	if err != nil {
		return jip.Grant{}, err
	}
	now := time.Now()
	g := jip.Grant{
		ID: id, Subject: subject, PublicKey: pub, Tier: tier, Scopes: scopes,
		IssuedAt: now.Unix(), NotAfter: now.Add(jip.GrantTTL).Unix(), Alg: jip.SigAlgEd25519,
	}
	g.Signature = ed25519.Sign(a.priv, jip.GrantSigningBytes(g))
	return g, nil
}

// RenewGrant re-issues a peer's grant before it expires, WITHOUT re-running operator approval. The
// presented grant is the proof of prior approval: it must be one THIS authority signed, still unexpired,
// and NOT revoked. The renewed grant keeps the SAME id (the stable revocation handle) with an advanced
// expiry — so revoking that id permanently kills the renewal chain (revocation dominates renewal). The
// handler must first verify the requester proved possession of the pinned node key (jip.VerifyRenewal).
func (a *authority) RenewGrant(cur jip.Grant) (jip.Grant, error) {
	if err := jip.VerifyGrant(cur, a.pub, time.Now()); err != nil {
		return jip.Grant{}, fmt.Errorf("renew: %w", err) // not ours, or already expired → must re-enroll
	}
	if a.IsRevoked(cur.ID) {
		return jip.Grant{}, fmt.Errorf("renew: grant revoked")
	}
	now := time.Now()
	g := cur // same id/subject/pubkey/tier/scopes — only the validity window advances
	g.IssuedAt = now.Unix()
	g.NotAfter = now.Add(jip.GrantTTL).Unix()
	g.Signature = ed25519.Sign(a.priv, jip.GrantSigningBytes(g))
	return g, nil
}

func (a *authority) RootPub() ed25519.PublicKey { return a.pub }

// Revoke adds a grant id to the CRL and persists it.
func (a *authority) Revoke(grantID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.revoked[grantID] = time.Now().Unix()
	b, _ := json.Marshal(a.revoked)
	return os.WriteFile(a.crlPath, b, 0o600)
}

func (a *authority) IsRevoked(grantID string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.revoked[grantID]
	return ok
}

// CRL returns the signed revocation list (jip format) so peers verify it offline against the root and
// gossip it.
func (a *authority) CRL() jip.SignedCRL {
	a.mu.Lock()
	defer a.mu.Unlock()
	cp := make(map[string]int64, len(a.revoked))
	for k, v := range a.revoked {
		cp[k] = v
	}
	c := jip.SignedCRL{Revoked: cp, IssuedAt: time.Now().Unix(), Alg: jip.SigAlgEd25519}
	c.Signature = ed25519.Sign(a.priv, jip.CRLSigningBytes(c))
	return c
}
