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

// Grants are the unit of mesh authorization. The console (the authority) holds the root keypair and
// SIGNS grants binding a subject (a node id) to its pinned public key, a tier, scopes, and an expiry.
// Peers VERIFY a grant OFFLINE against the authority's root public key — the console is never on the
// hot path. The format and verification live here in the protocol layer so issuer and verifier agree
// byte-for-byte; the authority (which holds the private key) does the signing.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"time"
)

// ProtocolMajor is the wire-protocol major version. Peers refuse to engage across incompatible majors
// (semver enforcement). Bumped only on a breaking protocol change.
const ProtocolMajor = 1

// Crypto agility — the mesh is signature-based, and ed25519 is CLASSICAL (not post-quantum). Every signed
// structure (presence, Grant, SignedCRL, CallProof, RenewalRequest) carries a SigAlg tag that is COVERED
// by its signing bytes, so a post-quantum scheme (e.g. ML-DSA / FIPS 204) can be added later as a
// NON-BREAKING change: peers negotiate by tag and REJECT unknown algorithms fail-closed. Because the tag
// is part of what is signed, it cannot be stripped or downgraded (changing it changes the bytes and
// breaks the signature). Today ed25519 is the only algorithm. The mesh is NOT yet quantum-resistant; this
// is the migration primitive that makes it so without a flag-day. See docs/POST-QUANTUM.md.
const SigAlgEd25519 = "ed25519"

// sigAlg normalizes a (possibly empty) algorithm tag to the default. Empty == ed25519 — the only scheme
// to date — so the field is forward-compatible; any non-empty unknown value fails verification.
func sigAlg(a string) string {
	if a == "" {
		return SigAlgEd25519
	}
	return a
}

// GrantTTL is the pinned default grant lifetime (5 minutes — see the identity ADR). Tunable DOWN per
// deployment; the worst-case revocation window with the gossiped CRL fast path.
const GrantTTL = 5 * time.Minute

// Grant is an authority-signed authorization. It travels in a peer's signed presence; a verifier
// checks Signature against the authority root, confirms NotAfter, confirms Subject/PublicKey match the
// presenting peer, and confirms ID is not in the CRL.
type Grant struct {
	ID        string   `json:"id"`            // unique — the revocation handle
	Subject   string   `json:"subject"`       // the peer's node id
	PublicKey []byte   `json:"public_key"`    // the peer's ed25519 pubkey, pinned (binds id↔key)
	Tier      int      `json:"tier"`
	Scopes    []string `json:"scopes,omitempty"`
	// Principal is WHOM this identity serves — the cryptographic operator binding. It is covered by the
	// signature (so a derivative cannot rebind it without the authority key) but only when non-empty, so
	// legacy grants without a principal sign and verify byte-for-byte exactly as before — a
	// backward-compatible extension, not a domain-separator break.
	Principal string   `json:"principal,omitempty"`
	IssuedAt  int64    `json:"issued_at"`     // unix seconds
	NotAfter  int64    `json:"not_after"`     // unix seconds
	Alg       string   `json:"alg,omitempty"` // signature algorithm (crypto agility); empty == ed25519
	Signature []byte   `json:"signature"`     // authority signature over GrantSigningBytes
}

// GrantSigningBytes is the canonical, domain-separated, length-prefixed encoding both signer and
// verifier compute. Deterministic (scopes sorted) so a grant signs and verifies identically anywhere.
func GrantSigningBytes(g Grant) []byte {
	var b bytes.Buffer
	field := func(x []byte) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(x)))
		b.Write(n[:])
		b.Write(x)
	}
	u64 := func(v int64) {
		var x [8]byte
		binary.BigEndian.PutUint64(x[:], uint64(v))
		b.Write(x[:])
	}
	field([]byte("J3nna-mesh-grant/1")) // domain separator
	field([]byte(sigAlg(g.Alg)))        // signature algorithm — covered so it can't be downgraded
	field([]byte(g.ID))
	field([]byte(g.Subject))
	field(g.PublicKey)
	u64(int64(g.Tier))
	sc := append([]string(nil), g.Scopes...)
	sort.Strings(sc)
	field(bytes.Join(byteSlices(sc), []byte{0}))
	u64(g.IssuedAt)
	u64(g.NotAfter)
	// Principal binding — appended (domain-tagged) ONLY when present, so a legacy grant with no
	// principal produces the identical pre-extension byte string and its existing signature still
	// verifies. A principal-bearing grant binds it under the signature: it cannot be rebound or
	// stripped without the authority key.
	if g.Principal != "" {
		field([]byte("J3nna-mesh-principal/1"))
		field([]byte(g.Principal))
	}
	return b.Bytes()
}

// VerifyServiceGrant is the constitutional check: a valid grant that is also PRINCIPAL-BOUND. A
// derivative bound to serve must carry a non-empty, signature-covered principal — otherwise it is not
// a being that serves anyone, and the floor refuses it. (Plain VerifyGrant stays permissive so the
// existing principal-less mesh grants keep working.)
func VerifyServiceGrant(g Grant, root ed25519.PublicKey, now time.Time) error {
	if err := VerifyGrant(g, root, now); err != nil {
		return err
	}
	if g.Principal == "" {
		return errors.New("grant: not principal-bound — a serving identity must name whom it serves")
	}
	return nil
}

func byteSlices(ss []string) [][]byte {
	out := make([][]byte, len(ss))
	for i, s := range ss {
		out[i] = []byte(s)
	}
	return out
}

// VerifyGrant checks a grant's signature against the authority root and its expiry. Revocation (CRL)
// and subject/pubkey binding are checked by the caller so a verifier can apply its freshest CRL and
// match the grant to the presenting peer. This is the OFFLINE check peers run — no console round-trip.
func VerifyGrant(g Grant, root ed25519.PublicKey, now time.Time) error {
	if sigAlg(g.Alg) != SigAlgEd25519 {
		return errors.New("grant: unsupported signature algorithm")
	}
	if len(root) != ed25519.PublicKeySize {
		return errors.New("grant: bad authority root key")
	}
	if g.NotAfter > 0 && now.Unix() > g.NotAfter {
		return errors.New("grant: expired")
	}
	if !ed25519.Verify(root, GrantSigningBytes(g), g.Signature) {
		return errors.New("grant: bad authority signature")
	}
	return nil
}

// CompatibleMajor reports whether a peer advertising protocol major `peer` may interoperate with this
// node. Same major only (semver: a major bump is breaking). Zero = unknown/legacy → rejected when
// authz is enforced.
func CompatibleMajor(peer int) bool { return peer == ProtocolMajor }

// Renewal — keeping a short-TTL grant alive without re-running operator approval.
//
// Grants live for GrantTTL (5 min by design — the worst-case revocation backstop). The console
// re-issues before expiry so a long-running peer stays in discovery, WITHOUT the console ever being on
// the hot path: renewal rides the same periodic background tick as the CRL refresh. A renewal re-signs
// the SAME grant id with an advanced expiry — the id is the stable revocation handle, so revoking it
// (CRL) permanently kills the whole renewal chain. The current valid grant is itself the proof of prior
// approval: only a grant the authority signed, still unexpired, and not revoked may be renewed, and the
// requester must prove possession of the pinned node key. Revocation therefore always dominates renewal.

// RenewMaxSkew bounds how far a renewal request's timestamp may drift from the console clock (replay
// hygiene). A replayed request is harmless anyway — it only re-issues a grant for a key the attacker
// cannot sign presence with — but freshness is cheap.
const RenewMaxSkew = 2 * time.Minute

// RenewalRequest is what a peer POSTs to the console's /renew to refresh its grant. It carries the
// current grant (proof of prior approval) and a node-key signature proving the requester holds the
// identity the grant is pinned to.
type RenewalRequest struct {
	Grant     Grant  `json:"grant"`
	IssuedAt  int64  `json:"issued_at"`     // unix seconds, for freshness
	Alg       string `json:"alg,omitempty"` // node-signature algorithm (crypto agility); empty == ed25519
	Signature []byte `json:"signature"`     // node-key sig over RenewSigningBytes
}

// RenewSigningBytes is the canonical, domain-separated encoding the requester signs with its NODE key
// and the console recomputes — both sides agree byte-for-byte. Bound to the specific grant being renewed
// plus a timestamp; the signature algorithm is covered so it can't be downgraded.
func RenewSigningBytes(alg, grantID, subject string, pub []byte, issuedAt int64) []byte {
	var b bytes.Buffer
	field := func(x []byte) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(x)))
		b.Write(n[:])
		b.Write(x)
	}
	field([]byte("J3nna-mesh-renew/1")) // domain separator
	field([]byte(sigAlg(alg)))
	field([]byte(grantID))
	field([]byte(subject))
	field(pub)
	var x [8]byte
	binary.BigEndian.PutUint64(x[:], uint64(issuedAt))
	b.Write(x[:])
	return b.Bytes()
}

// VerifyRenewal confirms the requester proved possession of the grant's pinned node key and the request
// is fresh. It does NOT check the grant's authority signature, expiry, or revocation — the console does
// those against its own root + CRL (so revocation dominates). now is the console clock.
func VerifyRenewal(r RenewalRequest, now time.Time) error {
	if sigAlg(r.Alg) != SigAlgEd25519 {
		return errors.New("renew: unsupported signature algorithm")
	}
	if len(r.Grant.PublicKey) != ed25519.PublicKeySize {
		return errors.New("renew: bad node pubkey")
	}
	if d := now.Unix() - r.IssuedAt; d > int64(RenewMaxSkew/time.Second) || d < -int64(RenewMaxSkew/time.Second) {
		return errors.New("renew: stale request")
	}
	if !ed25519.Verify(r.Grant.PublicKey, RenewSigningBytes(r.Alg, r.Grant.ID, r.Grant.Subject, r.Grant.PublicKey, r.IssuedAt), r.Signature) {
		return errors.New("renew: bad node signature")
	}
	return nil
}

// SignedCRL is the authority's revocation list (revoked grant ids → revoked-at) plus its signature, so
// any peer can verify it offline and gossip it. Combined with the short grant TTL, revocation
// propagates in seconds (gossip/fetch) with the TTL as the worst-case backstop.
type SignedCRL struct {
	Revoked   map[string]int64 `json:"revoked"`
	IssuedAt  int64            `json:"issued_at"`
	Alg       string           `json:"alg,omitempty"` // signature algorithm (crypto agility); empty == ed25519
	Signature []byte           `json:"signature"`
}

// CRLSigningBytes is the canonical bytes the authority signs and verifiers recompute (ids sorted).
func CRLSigningBytes(c SignedCRL) []byte {
	ids := make([]string, 0, len(c.Revoked))
	for id := range c.Revoked {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var b bytes.Buffer
	fmt.Fprintf(&b, "J3nna-mesh-crl/1|%s|%d|", sigAlg(c.Alg), c.IssuedAt) // alg covered so it can't be downgraded
	for _, id := range ids {
		fmt.Fprintf(&b, "%s,", id)
	}
	return b.Bytes()
}

// VerifyCRL checks the CRL signature against the authority root.
func VerifyCRL(c SignedCRL, root ed25519.PublicKey) error {
	if sigAlg(c.Alg) != SigAlgEd25519 {
		return errors.New("crl: unsupported signature algorithm")
	}
	if len(root) != ed25519.PublicKeySize {
		return errors.New("crl: bad authority root key")
	}
	if !ed25519.Verify(root, CRLSigningBytes(c), c.Signature) {
		return errors.New("crl: bad authority signature")
	}
	return nil
}

// RevokedIDs returns the revoked grant ids from a CRL (for Node.SetRevoked).
func (c SignedCRL) RevokedIDs() []string {
	out := make([]string, 0, len(c.Revoked))
	for id := range c.Revoked {
		out = append(out, id)
	}
	return out
}
