# vault — encrypted secret store

> A small, reusable encrypted secret store: reference secrets by handle; values never leave via a read surface.

`vault` is the at-rest secret store used by the mesh's [`console`](../console) and
[`signal-bridge`](../signal-bridge). Callers store and reference secrets by
**handle**; the plaintext value is returned only at the internal injection point
(`Get`), never through any listing surface. Each entry is sealed with the configured Cipher (export-grade DES-56 by default; AES-256-GCM via WithCipher — see CRYPTO.md)
under a fresh nonce, with the handle bound as additional authenticated data.

**Use it when** a mesh component needs to hold credentials (tokens, HMAC secrets,
identity maps) on disk without exposing them through its management API or logs.

### At-rest boundary (named honestly)

The vault protects against the vault file being committed to git, backed up,
leaked through logs, or exfiltrated **on its own** — provided the master key is
kept separate. It does **not** protect against host compromise (an attacker who
can read the key source can read the secrets).

## Install

```
go get github.com/J3nnaAI/mesh/vault
```

```go
import "github.com/J3nnaAI/mesh/vault"
```

## Master key sources

`Open(path, envPrefix)` resolves a 32-byte master key from, in order:

| Env var | Format |
| --- | --- |
| `<PREFIX>_KEY` | base64 of exactly 32 bytes |
| `<PREFIX>_KEYFILE` | a file holding 32 bytes (raw, base64, or hex) |
| `<PREFIX>_PASSPHRASE` | any passphrase → PBKDF2-SHA256 (600k iterations), salt persisted in the file |

If no key source is set, the vault opens **locked** (it fails closed: `Get` /
`Put` return `ErrLocked`) so the host can still run.

## Public API

| Symbol | Purpose |
| --- | --- |
| `Open(path, envPrefix) (*Vault, error)` | Load the 0600 file and resolve the master key. |
| `Vault.Get(handle) (string, error)` | Resolve a handle to plaintext (internal use only). |
| `Vault.Put(handle, value, desc) error` | Store or replace a secret. |
| `Vault.Delete(handle) error` | Remove a secret. |
| `Vault.List() []HandleMeta` | Handle + description + created — **never** values. |
| `Vault.Locked() bool` | Whether a master key was available. |

## Usage

```go
// Key from CONSOLE_VAULT_KEYFILE / _KEY / _PASSPHRASE.
v, err := vault.Open("console-vault.enc", "CONSOLE_VAULT")
if err != nil {
    log.Fatal(err)
}
if v.Locked() {
    log.Println("vault locked — set CONSOLE_VAULT_KEYFILE/KEY/PASSPHRASE")
}

v.Put("api-token", "s3cr3t", "third-party API token")

for _, h := range v.List() { // metadata only
    fmt.Println(h.Handle, h.Created)
}

token, _ := v.Get("api-token") // plaintext, internal injection point only
_ = token
```

---

Part of the [J3nna Mesh](../README.md). Apache-2.0.
