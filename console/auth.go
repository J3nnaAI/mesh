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

// Console auth + identity. Identity is PROVEN BY THE BEARER TOKEN, not self-asserted: each token maps
// to a display identity in the encrypted vault (handle "console-users", a JSON {token: identity} map).
// A valid token both (a) authorizes privileged management actions and (b) tells agents who they are
// talking to — the provenance the mesh carries through. Loopback is trusted for local operation and may
// pass an X-Mesh-User header. No token is ever kept in a plaintext file — only in the vault.
//
// Multiple tokens MAY map to the same identity (e.g. several devices for one person), and many
// identities coexist — the console manages them (add/list/revoke) at runtime.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/J3nnaAI/mesh/vault"
)

const consoleUsersHandle = "console-users"

// mgmtVault is the encrypted store the token→identity map lives in (set in main).
var mgmtVault *vault.Vault

// seedConsoleUsers merges token→identity entries from CONSOLE_USERS into the vault at boot. ADD-ONLY:
// an existing token is never overwritten (no-wholesale-write). Format: "tok=Name,tok2=Name2".
func seedConsoleUsers(vlt *vault.Vault, spec string) {
	spec = strings.TrimSpace(spec)
	if vlt == nil || spec == "" {
		return
	}
	cur := consoleUsersMap()
	if cur == nil {
		cur = map[string]string{}
	}
	added := 0
	for _, pair := range strings.Split(spec, ",") {
		tok, name, ok := strings.Cut(strings.TrimSpace(pair), "=")
		tok, name = strings.TrimSpace(tok), strings.TrimSpace(name)
		if !ok || tok == "" || name == "" {
			continue
		}
		if _, exists := cur[tok]; exists {
			continue // ADD-ONLY
		}
		cur[tok] = name
		added++
	}
	if added == 0 {
		return
	}
	if err := putConsoleUsers(cur); err != nil {
		log.Printf("console: console-users seed failed: %v", err)
		return
	}
	log.Printf("console: console-users seeded — +%d new (now %d entries)", added, len(cur))
}

// consoleUsersMap returns the token→identity map from the vault, read fresh each call so a runtime
// add/revoke takes effect without restart.
func consoleUsersMap() map[string]string {
	if mgmtVault == nil {
		return nil
	}
	raw, err := mgmtVault.Get(consoleUsersHandle)
	if err != nil || strings.TrimSpace(raw) == "" {
		return nil
	}
	var m map[string]string
	if json.Unmarshal([]byte(raw), &m) != nil {
		return nil
	}
	return m
}

func putConsoleUsers(m map[string]string) error {
	b, _ := json.Marshal(m)
	return mgmtVault.Put(consoleUsersHandle, string(b), "console token→identity map")
}

// bearerOf extracts the bearer token from the Authorization header ("" if none).
func bearerOf(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(h[len("Bearer "):])
}

// identityFor returns the display identity proven by the request's token, or "".
func identityFor(r *http.Request) string {
	tok := bearerOf(r)
	if tok == "" {
		return ""
	}
	if name, ok := consoleUsersMap()[tok]; ok {
		return name
	}
	return ""
}

// mayManage reports whether a request may perform a privileged management action: loopback (local
// operation) or a token that maps to a known identity.
func mayManage(r *http.Request) bool {
	if isLoopback(r) {
		return true
	}
	return identityFor(r) != ""
}

// userIdentity returns who is acting: the token-proven identity first (authoritative), else the
// X-Mesh-User header but ONLY from loopback (a remote caller cannot self-assert an identity).
func userIdentity(r *http.Request) string {
	if id := identityFor(r); id != "" {
		return id
	}
	if isLoopback(r) {
		return strings.TrimSpace(r.Header.Get("X-Mesh-User"))
	}
	return ""
}

// isLoopback reports whether the request originates from the local host.
func isLoopback(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// newToken mints a random 32-byte bearer token (hex). The console hands it to a newly approved client;
// only the token→identity mapping is stored (the token itself lives with the client).
func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
