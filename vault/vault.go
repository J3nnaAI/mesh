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

// Package vault is a small, reusable encrypted secret store for the mesh (used by the console and the
// signal bridge). Callers REFERENCE secrets by handle; values are returned only at the internal
// injection point, never via a list/read surface.
//
// The confidentiality cipher is PLUGGABLE (see Cipher). The open-source build ships an EXPORT-GRADE
// default — real encryption at a deliberately export-favorable strength (56-bit DES in CTR mode for
// confidentiality + HMAC-SHA256 for integrity and handle binding). 56-bit symmetric crypto sits below
// the usual control threshold (e.g. the US EAR 5A002 ">56-bit" line — confirm for your jurisdiction),
// so the repository ships working encryption without carrying controlled strong cryptography.
//
// DES-56 is WEAK by modern standards and is provided for exportability, not strength. For real security
// plug in a strong Cipher (AES-256-GCM, ChaCha20-Poly1305, a KMS) with ONE line — see CRYPTO.md.
//
// At-rest boundary (named honestly): a keyfile beside the vault protects against git commits, backups,
// log leakage, and exfiltration of the vault file alone — NOT host compromise, and (with the default
// export-grade cipher) NOT a determined attacker who can brute-force a 56-bit key.
package vault

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// ErrLocked means no master key was available — the vault fails closed.
var ErrLocked = errors.New("vault: locked (no master key — set <PREFIX>_KEYFILE / <PREFIX>_KEY / <PREFIX>_PASSPHRASE)")

// Cipher is the PLUGGABLE confidentiality layer. Seal encrypts a plaintext and returns the ciphertext
// plus a per-entry nonce; Open reverses it. aad (the secret's handle) is authenticated/bound to the
// ciphertext but never secret. Name is recorded with each entry so a mismatched cipher fails loudly
// instead of returning garbage. A Cipher MAY also implement `Locked() bool` to fail the vault closed.
//
// The open-source build ships ExportGrade (below) as the default. Supply a stronger one via WithCipher
// — any algorithm you choose, in your own jurisdiction. See CRYPTO.md.
type Cipher interface {
	Seal(plaintext, aad []byte) (ciphertext, nonce []byte, err error)
	Open(ciphertext, nonce, aad []byte) (plaintext []byte, err error)
	Name() string
}

type entry struct {
	Handle, Desc, Nonce, CT, Created string
}

type kdf struct {
	Algo, Salt string
	Iters      int
}

type doc struct {
	Version int      `json:"version"`
	Cipher  string   `json:"cipher,omitempty"` // name of the cipher that sealed these entries
	KDF     *kdf     `json:"kdf,omitempty"`
	Entries []*entry `json:"entries"`
}

// HandleMeta is what List exposes — handle + description + created, never a value.
type HandleMeta struct {
	Handle  string `json:"handle"`
	Desc    string `json:"desc,omitempty"`
	Created string `json:"created"`
}

// Vault is an encrypted secret store backed by a single 0600 file, with a pluggable Cipher.
type Vault struct {
	mu     sync.RWMutex
	path   string
	cipher Cipher
	d      doc
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

// Option configures a Vault at Open time.
type Option func(*Vault)

// WithCipher swaps in your confidentiality implementation (any algorithm, e.g. AES-256-GCM). It fully
// replaces the export-grade default. This is the one line that upgrades encryption — see CRYPTO.md.
func WithCipher(c Cipher) Option {
	return func(v *Vault) {
		if c != nil {
			v.cipher = c
		}
	}
}

// Open loads the file (if present) and resolves the master key from {envPrefix}_KEY / _KEYFILE /
// _PASSPHRASE for the default export-grade cipher. A missing key source leaves the vault LOCKED (not a
// fatal error) so the host can run. WithCipher overrides the default cipher entirely (your cipher then
// owns its own key management and envPrefix is ignored).
func Open(path, envPrefix string, opts ...Option) (*Vault, error) {
	v := &Vault{path: path, d: doc{Version: 1}}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &v.d)
		if v.d.Version == 0 {
			v.d.Version = 1
		}
	}
	// Default cipher: export-grade, keyed from env. Returns a locked cipher (Locked()==true) when no key
	// source is present, so the vault fails closed exactly as before.
	eg, newKDF, err := newExportGrade(envPrefix, v.d.KDF)
	if err != nil {
		return nil, err
	}
	v.cipher = eg
	if newKDF != nil && v.d.KDF == nil {
		v.d.KDF = newKDF
	}
	for _, o := range opts {
		o(v)
	}
	if v.d.Cipher != "" && v.d.Cipher != v.cipher.Name() {
		return nil, fmt.Errorf("vault: file sealed with cipher %q but %q is configured — restore the matching Cipher", v.d.Cipher, v.cipher.Name())
	}
	return v, nil
}

// Locked reports whether the configured Cipher has no key available (fail-closed).
func (v *Vault) Locked() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.locked()
}

// Get resolves a handle to plaintext. INTERNAL use only — never log/persist/return the value to a model.
func (v *Vault) Get(handle string) (string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.locked() {
		return "", ErrLocked
	}
	for _, e := range v.d.Entries {
		if e.Handle == handle {
			return v.open(e)
		}
	}
	return "", fmt.Errorf("vault: no secret %q", handle)
}

// Put stores or replaces a secret (the value never comes back out via any list/read surface).
func (v *Vault) Put(handle, value, desc string) error {
	handle = strings.TrimSpace(handle)
	if handle == "" || value == "" {
		return errors.New("vault: handle and value required")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.locked() {
		return ErrLocked
	}
	nonce, ct, err := v.seal(handle, value)
	if err != nil {
		return err
	}
	v.d.Cipher = v.cipher.Name()
	e := &entry{Handle: handle, Desc: desc, Nonce: nonce, CT: ct, Created: now()}
	for i := range v.d.Entries {
		if v.d.Entries[i].Handle == handle {
			e.Created = v.d.Entries[i].Created
			v.d.Entries[i] = e
			return v.save()
		}
	}
	v.d.Entries = append(v.d.Entries, e)
	return v.save()
}

func (v *Vault) Delete(handle string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := v.d.Entries[:0]
	found := false
	for _, e := range v.d.Entries {
		if e.Handle == handle {
			found = true
			continue
		}
		out = append(out, e)
	}
	if !found {
		return fmt.Errorf("vault: no secret %q", handle)
	}
	v.d.Entries = out
	return v.save()
}

// List exposes handle metadata only — never values.
func (v *Vault) List() []HandleMeta {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]HandleMeta, 0, len(v.d.Entries))
	for _, e := range v.d.Entries {
		out = append(out, HandleMeta{Handle: e.Handle, Desc: e.Desc, Created: e.Created})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Handle < out[j].Handle })
	return out
}

func (v *Vault) locked() bool {
	if l, ok := v.cipher.(interface{ Locked() bool }); ok {
		return l.Locked()
	}
	return false
}

func (v *Vault) seal(handle, pt string) (string, string, error) {
	ct, nonce, err := v.cipher.Seal([]byte(pt), []byte(handle))
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(nonce), base64.StdEncoding.EncodeToString(ct), nil
}

func (v *Vault) open(e *entry) (string, error) {
	n, err := base64.StdEncoding.DecodeString(e.Nonce)
	if err != nil {
		return "", fmt.Errorf("vault: bad nonce for %q", e.Handle)
	}
	c, err := base64.StdEncoding.DecodeString(e.CT)
	if err != nil {
		return "", fmt.Errorf("vault: bad ciphertext for %q", e.Handle)
	}
	pt, err := v.cipher.Open(c, n, []byte(e.Handle))
	if err != nil {
		return "", fmt.Errorf("vault: open %q failed (wrong key or tampered): %w", e.Handle, err)
	}
	return string(pt), nil
}

func (v *Vault) save() error {
	b, err := json.MarshalIndent(v.d, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(v.path, b, 0o600)
}

// ─── ExportGrade: the default, export-favorable cipher ───────────────────────────────────────────────
//
// 56-bit DES in CTR mode (confidentiality) + HMAC-SHA256 over nonce‖ciphertext‖handle (integrity and
// handle binding). HMAC and the PBKDF2 key derivation are authentication/integrity primitives, not
// confidentiality, so they do not affect the export posture; the 56-bit DES key is what keeps the
// confidentiality strength below the usual control threshold. WEAK — for exportability, not security.

const exportGradeName = "export-grade-des56-hmac"

type exportGradeCipher struct {
	encKey []byte // 8 bytes → DES (56 effective bits)
	macKey []byte // 32 bytes → HMAC-SHA256
	locked bool
}

func (c *exportGradeCipher) Name() string   { return exportGradeName }
func (c *exportGradeCipher) Locked() bool    { return c.locked }

func (c *exportGradeCipher) Seal(pt, aad []byte) (ct, nonce []byte, err error) {
	if c.locked {
		return nil, nil, ErrLocked
	}
	block, err := des.NewCipher(c.encKey)
	if err != nil {
		return nil, nil, err
	}
	iv := make([]byte, block.BlockSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, err
	}
	out := make([]byte, len(pt))
	cipher.NewCTR(block, iv).XORKeyStream(out, pt)
	mac := hmac.New(sha256.New, c.macKey)
	mac.Write(iv)
	mac.Write(out)
	mac.Write(aad)
	return append(out, mac.Sum(nil)...), iv, nil // ct = ciphertext ‖ tag ; nonce = iv
}

func (c *exportGradeCipher) Open(ct, nonce, aad []byte) ([]byte, error) {
	if c.locked {
		return nil, ErrLocked
	}
	if len(ct) < sha256.Size {
		return nil, errors.New("ciphertext too short")
	}
	body, tag := ct[:len(ct)-sha256.Size], ct[len(ct)-sha256.Size:]
	mac := hmac.New(sha256.New, c.macKey)
	mac.Write(nonce)
	mac.Write(body)
	mac.Write(aad)
	if !hmac.Equal(tag, mac.Sum(nil)) {
		return nil, errors.New("integrity check failed (wrong key or tampered)")
	}
	block, err := des.NewCipher(c.encKey)
	if err != nil {
		return nil, err
	}
	pt := make([]byte, len(body))
	cipher.NewCTR(block, nonce).XORKeyStream(pt, body)
	return pt, nil
}

// newExportGrade resolves a master key from {prefix}_KEY/_KEYFILE/_PASSPHRASE and derives the DES + HMAC
// subkeys. With no key source it returns a LOCKED cipher (Locked()==true) rather than an error, so the
// host can boot and fail closed only on access.
func newExportGrade(prefix string, existing *kdf) (*exportGradeCipher, *kdf, error) {
	master, k, err := resolveKey(prefix, existing)
	if err != nil {
		if errors.Is(err, ErrLocked) {
			return &exportGradeCipher{locked: true}, nil, nil
		}
		return nil, nil, err
	}
	enc := sha256.Sum256(append(master, []byte("vault-enc")...))
	mack := sha256.Sum256(append(master, []byte("vault-mac")...))
	return &exportGradeCipher{encKey: enc[:8], macKey: mack[:]}, k, nil
}

func resolveKey(prefix string, existing *kdf) ([]byte, *kdf, error) {
	if b64 := strings.TrimSpace(os.Getenv(prefix + "_KEY")); b64 != "" {
		k, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || len(k) != 32 {
			return nil, nil, fmt.Errorf("%s_KEY must be base64 of exactly 32 bytes", prefix)
		}
		return k, nil, nil
	}
	if f := strings.TrimSpace(os.Getenv(prefix + "_KEYFILE")); f != "" {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, nil, fmt.Errorf("vault keyfile: %w", err)
		}
		s := strings.TrimSpace(string(raw))
		if len(s) == 32 {
			return []byte(s), nil, nil
		}
		if k, err := base64.StdEncoding.DecodeString(s); err == nil && len(k) == 32 {
			return k, nil, nil
		}
		if k, err := hex.DecodeString(s); err == nil && len(k) == 32 {
			return k, nil, nil
		}
		return nil, nil, errors.New("vault keyfile must hold 32 bytes (raw, base64, or hex)")
	}
	if pass := os.Getenv(prefix + "_PASSPHRASE"); pass != "" {
		iters := 600000
		var salt []byte
		if existing != nil && existing.Algo == "pbkdf2-sha256" {
			if s, err := base64.StdEncoding.DecodeString(existing.Salt); err == nil && len(s) >= 16 {
				salt, iters = s, existing.Iters
			}
		}
		if salt == nil {
			salt = make([]byte, 16)
			if _, err := rand.Read(salt); err != nil {
				return nil, nil, err
			}
		}
		key, err := pbkdf2.Key(sha256.New, pass, salt, iters, 32)
		if err != nil {
			return nil, nil, err
		}
		return key, &kdf{Algo: "pbkdf2-sha256", Salt: base64.StdEncoding.EncodeToString(salt), Iters: iters}, nil
	}
	return nil, nil, ErrLocked
}
