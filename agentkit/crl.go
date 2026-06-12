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

package agentkit

// CRL distribution: an authorized peer periodically fetches the console's SIGNED revocation list,
// verifies it against the authority root, and applies it — so a revoked grant drops out of discovery in
// seconds (the refresh interval), with the grant TTL as the worst-case backstop. The console is hit only
// on this background refresh, never on the hot path of a peer-to-peer call (root-not-hub).

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/J3nnaAI/mesh/jip"
)

// RefreshCRL fetches + applies the console CRL once now, then every interval until ctx ends. Run in a
// goroutine. A fetch/verify failure is skipped silently (the last good CRL + TTL still protect).
func RefreshCRL(ctx context.Context, m *Mesh, consoleURL string, root []byte, interval time.Duration) {
	hc := &http.Client{Timeout: 10 * time.Second, Transport: InsecureLoopbackTransport()}
	url := strings.TrimRight(consoleURL, "/") + "/crl"
	apply := func() {
		var crl jip.SignedCRL
		if err := doJSON(ctx, hc, http.MethodGet, url, nil, &crl); err != nil {
			return
		}
		if jip.VerifyCRL(crl, root) != nil {
			return // never apply an unsigned/forged CRL
		}
		m.Node().SetRevoked(crl.RevokedIDs())
	}
	apply()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			apply()
		}
	}
}

// KeepFresh is the credential housekeeping loop for a long-running authorized peer. On each tick it
// (1) refreshes the CRL — so revocations land within the interval — and (2) RENEWS this peer's grant
// once it is past half its lifetime. Grants are short-lived by design (jip.GrantTTL); without renewal a
// peer would silently drop out of authorized discovery at expiry. Both happen on the SAME background
// tick — the console is touched periodically, NEVER on the hot path of a peer-to-peer call (root-not-hub).
// Run in a goroutine. consoleURL is the enrollment console; root is the authority root pubkey.
//
// KeepFresh supersedes RefreshCRL for enrolled peers (it does the CRL work too) and is the supported mode
// for any long-running peer — the console issues short (jip.GrantTTL) grants, so a peer that does NOT
// renew will drop out of authorized discovery at expiry. Use RefreshCRL alone only for a short-lived or
// ephemeral peer that is fine to expire (e.g. a static-grant peer configured without a console URL).
func KeepFresh(ctx context.Context, m *Mesh, consoleURL string, root []byte, interval time.Duration) {
	hc := &http.Client{Timeout: 10 * time.Second, Transport: InsecureLoopbackTransport()}
	base := strings.TrimRight(consoleURL, "/")

	refreshCRL := func() {
		var crl jip.SignedCRL
		if err := doJSON(ctx, hc, http.MethodGet, base+"/crl", nil, &crl); err != nil {
			return
		}
		if jip.VerifyCRL(crl, root) != nil {
			return // never apply an unsigned/forged CRL
		}
		m.Node().SetRevoked(crl.RevokedIDs())
	}

	renew := func() {
		g := m.Node().CurrentGrant()
		if g == nil || g.NotAfter == 0 {
			return
		}
		// Renew once past half the grant's lifetime — leaves a full half-life of margin to absorb a
		// momentary console blip before the grant would actually expire.
		half := g.IssuedAt + (g.NotAfter-g.IssuedAt)/2
		if time.Now().Unix() < half {
			return
		}
		req, err := m.Node().SignRenewal(time.Now().Unix())
		if err != nil {
			return
		}
		body, _ := json.Marshal(req)
		var fresh jip.Grant
		if err := doJSON(ctx, hc, http.MethodPost, base+"/renew", body, &fresh); err != nil {
			return // console unreachable — keep the current grant; retry next tick (still has margin)
		}
		if jip.VerifyGrant(fresh, ed25519.PublicKey(root), time.Now()) != nil {
			return // never install a grant that doesn't verify against the authority root
		}
		m.Node().SetGrant(fresh)
	}

	refreshCRL()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			refreshCRL()
			renew()
		}
	}
}
