# Vault encryption is pluggable — bring your own cipher

The mesh `vault` stores secrets behind a **pluggable confidentiality layer**. The open-source build
ships a working **export-grade** default and lets you swap in a stronger algorithm with one line — your
choice of cipher and key management, in your own jurisdiction.

Why it's built this way: shipping *strong* confidentiality cryptography in published source code carries
export-control obligations in some jurisdictions (e.g. the US EAR, whose 5A002 control turns on
symmetric key length **> 56 bits** — *verify for your situation*). By shipping a default that stays at
the export-favorable 56-bit strength and letting each adopter plug in strong crypto themselves, the
repository ships working encryption without carrying controlled strong cryptography. (This is an
engineering choice, not legal advice — consult your own counsel.)

## The default: `ExportGrade` (real, but deliberately weak)

With no cipher configured, the vault uses an **export-grade** cipher: **56-bit DES in CTR mode** for
confidentiality, plus **HMAC-SHA256** over nonce‖ciphertext‖handle for integrity and handle binding,
with the key derived from `<PREFIX>_KEY` / `<PREFIX>_KEYFILE` / `<PREFIX>_PASSPHRASE` (PBKDF2). With no
key source the vault is **locked** and fails closed.

This is **real encryption** — secrets are not stored in plaintext — but DES-56 is **weak by modern
standards and is provided for exportability, not security**. For production, plug in a strong `Cipher`
(below). HMAC and PBKDF2 are authentication/integrity primitives and do not affect the export posture;
only the 56-bit confidentiality key keeps the default below the control threshold.

## The interface

```go
type Cipher interface {
    Seal(plaintext, aad []byte) (ciphertext, nonce []byte, err error)
    Open(ciphertext, nonce, aad []byte) (plaintext []byte, err error)
    Name() string
}
```

- `aad` is the secret's **handle** — authenticated/bound to the ciphertext, but never secret.
- `nonce` is whatever your algorithm needs per entry (return `nil` if it doesn't use one).
- `Name()` is recorded with each entry, so loading a vault with a *different* cipher fails loudly
  instead of returning garbage.
- Optionally implement `Locked() bool` to fail the vault closed when no key is available.

## Plug it in (one line)

```go
v, err := vault.Open("secrets.enc", vault.WithCipher(myCipher))
```

## Example: AES-256-GCM (paste into YOUR project, not the mesh repo)

This is a complete, production-shaped `Cipher` using Go's standard library. Because it lives in **your**
tree, the published mesh repository still contains no confidentiality cryptography. Adapt the key
source (env var, KMS, HSM, keyfile) to your environment.

```go
package mycrypto

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "errors"
)

// AESGCM is a 256-bit AES-GCM Cipher for github.com/J3nnaAI/mesh/vault.
type AESGCM struct{ aead cipher.AEAD }

// NewAESGCM takes a 32-byte key (AES-256). Source it from your KMS/keyfile/env.
func NewAESGCM(key []byte) (*AESGCM, error) {
    if len(key) != 32 {
        return nil, errors.New("AES-256-GCM needs a 32-byte key")
    }
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    aead, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    return &AESGCM{aead: aead}, nil
}

func (c *AESGCM) Name() string { return "aes-256-gcm" }

func (c *AESGCM) Seal(plaintext, aad []byte) (ciphertext, nonce []byte, err error) {
    nonce = make([]byte, c.aead.NonceSize())
    if _, err = rand.Read(nonce); err != nil {
        return nil, nil, err
    }
    return c.aead.Seal(nil, nonce, plaintext, aad), nonce, nil
}

func (c *AESGCM) Open(ciphertext, nonce, aad []byte) ([]byte, error) {
    return c.aead.Open(nil, nonce, ciphertext, aad)
}
```

Wire it up:

```go
key := loadYour32ByteKey()           // KMS, keyfile, env — your call
ciph, err := mycrypto.NewAESGCM(key)
if err != nil { /* handle */ }
v, err := vault.Open("secrets.enc", vault.WithCipher(ciph))
```

## Other choices

Any algorithm works as long as it satisfies `Cipher`:
- **ChaCha20-Poly1305** (`golang.org/x/crypto/chacha20poly1305`) — same shape as the AES example.
- **Envelope encryption** — `Seal`/`Open` call out to AWS KMS / GCP KMS / Vault Transit; store the
  wrapped data key as the `nonce`/ciphertext envelope.
- **HSM / PKCS#11** — back the AEAD with a hardware key.

## Migrating an existing encrypted vault

The vault records the sealing cipher's `Name()`. If you change algorithms, decrypt with the old cipher
and re-`Put` each secret with the new one (a short migration loop), or keep both and branch on the
recorded name. The vault refuses to silently mix ciphers.
