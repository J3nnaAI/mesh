# JIP wire conformance

This directory is the **cross-language contract** for J3nna Mesh. The mesh is decentralized: a peer written
in any language must produce signatures that verify against a peer written in any other. That only works if
every implementation builds the *signed bytes* identically, down to the byte. `vectors.json` pins those
bytes for a fixed set of inputs and keys; an SDK in any language is "wire-compatible" once it reproduces
them.

The Go package [`jip`](..) is the **reference implementation**. `vectors.json` is generated from it by
`TestConformanceVectors` and is also a drift guard: changing the framing fails that test until the vectors
are deliberately regenerated (which is, by definition, a protocol change — see
[`../../docs/VERSIONING.md`](../../docs/VERSIONING.md)).

```sh
# regenerate (only when the wire format intentionally changes):
JIP_UPDATE_VECTORS=1 go test -run TestConformanceVectors ./...
```

## The framing primitive

Everything that gets signed is built with two rules — no JSON, no map-iteration order, no locale- or
language-dependent number formatting:

- **`field(x)`** — a 4-byte **big-endian** `uint32` length, then the raw bytes of `x`.
- **`u64(v)`** — an 8-byte **big-endian** representation of the integer.
- **Sets are sorted** before framing (capabilities, scopes), so set order never changes a signature.
- **Signatures are ed25519** over the resulting bytes. Ed25519 is deterministic (RFC 8032), so a correct
  implementation reproduces the *exact* signature in `vectors.json`, not merely a valid one.
- The empty signature algorithm is treated as `ed25519`; the algorithm string is itself a signed field, so
  it cannot be downgraded.

## The three signed structures a peer needs

### 1. Presence record — signed by the peer's **node** key
Domain is the protocol string itself (first field). Order:
`field(protocol)` · `field(alg)` · `field(id)` · `field(public_key)` · `field(endpoint)` · `field(mcp_path)`
· `uint32(len(caps))` then `field(cap)` for each **sorted** capability · `uint32(protocol_major)` ·
`field(grant_id)` (empty string when no grant) · `u64(heartbeat_unix)`.

### 2. Grant — signed by the **authority root** key
`field("J3nna-mesh-grant/1")` · `field(alg)` · `field(id)` · `field(subject)` · `field(public_key)` ·
`u64(tier)` · `field(scopes)` where scopes are **sorted and joined by a single NUL byte (0x00)** ·
`u64(issued_at)` · `u64(not_after)` · then **only if a principal is present**:
`field("J3nna-mesh-principal/1")` · `field(principal)`. (A grant with no principal produces the identical
pre-extension bytes, so old signatures still verify.)

### 3. CallProof — signed by the caller's **node** key
`field("JIP-call/0.2")` · `field(alg)` · `field(node_id)` · `field(tool)` · `field(args_hash)` ·
`u64(unix_milli)`.

> **The one cross-language gotcha — `args_hash`.** It is `sha256(canonical_json)` where `canonical_json`
> is **Go's `encoding/json.Marshal` of the arguments map**: keys sorted lexicographically, `<`, `>`, `&`
> HTML-escaped (`<`, `>`, `&`), no insignificant whitespace, integers without a decimal
> point. An SDK MUST reproduce that byte string exactly. `vectors.json` includes `args_canonical_json` and
> `args_hash_hex` for the callproof case so you can check your JSON canonicalization in isolation before
> touching signatures. (If a future port can't match Go's JSON encoder, the migration path is RFC 8785 JCS,
> which would be a protocol-major bump.)

## How an SDK proves conformance

For each vector:
1. Rebuild the signing bytes from `input` using the framing above; assert they equal `signing_bytes_hex`.
2. Derive/observe the signer key; assert its public key equals `signer_public_key_hex`.
3. ed25519-verify `signature_b64` over your bytes against that public key — and, since ed25519 is
   deterministic, also assert your own signature over those bytes equals `signature_b64`.

If all three hold for every vector, the SDK is wire-compatible with the reference and can join a Go mesh.

## Platforms — all verified against these vectors

Run every implementation in one shot: **`./run-all.sh`** (`9 passed, 0 failed`).

| Platform | Directory | ed25519 | JSON | Run |
| --- | --- | --- | --- | --- |
| **Go** (reference) | `../conformance_test.go` | stdlib | stdlib | `go test -run TestConformanceVectors` |
| **Python** | `python/` | `cryptography` | stdlib | `python3 conformance_test.py` |
| **Node.js / TypeScript** | `node/` | `node:crypto` (no deps) | stdlib | `node conformance_test.mjs` |
| **Rust** | `rust/` | `ed25519-dalek` | `serde_json` | `cargo run` |
| **WebAssembly** | `wasm/` | *(the Rust SDK → `wasm32-wasip1`)* | — | `node --experimental-wasi-unstable-preview1 run.mjs` |
| **Dart** (Flutter) | `dart/` | `cryptography` | stdlib | `dart run bin/conformance.dart` |
| **C# / .NET** (→ F#, VB) | `csharp/` | BouncyCastle | `System.Text.Json` | `dotnet run` |
| **Java / JVM** (→ Kotlin, Scala, Clojure) | `java/` | JDK `Ed25519` | gson | `javac` + `java` |
| **Swift** (CryptoKit / swift-crypto) | `swift/` | swift-crypto | Foundation | `swift run` |

A C ABI for the long tail (Ruby, PHP, Lua, R, …) is generated from the Rust target — same code, same vectors.

## What the suite covers

The suite validates the canonical signed-bytes framing — presence, grant, CallProof, grant renewal, and the
CRL — against the shared fixtures across all nine platforms. The CallProof fixture's arguments deliberately
include a `/` and `<>&`, pinning the one cross-language JSON-canonicalization rule down byte-for-byte
(Go-exact: HTML-escape `<>&`, never escape `/`). The full SDK surface (enroll → discover → call → join a
room) is built on this verified wire layer and proven **live** against a Go mesh (see
[docs/SDKS.md](../../docs/SDKS.md)).
