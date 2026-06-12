# J3nna Mesh SDK — Swift

A J3nna Mesh peer in Swift (iOS/macOS via CryptoKit, Linux/server via swift-crypto — same `Crypto` API),
mirroring the [Python reference SDK](../python). Build a peer that speaks the J3nna Integration Protocol
(JIP): cryptographic identity, console enrollment, peer discovery, offline grant verification, MCP tool
calls, and rooms — **wire-compatible with the Go reference** (validated against
[`jip/conformance/vectors.json`](../../jip/conformance/vectors.json)).

## Package

A SwiftPM package with:

- **library `J3nnaMesh`** — modules: `Wire` (canonical signing bytes + ed25519 sign/verify +
  Go-compatible args canonicalization + traceparent), `Identity` (load-or-create, Go-interchangeable
  on-disk format), `Enroll`, `Discovery`, `MCP`, `Rooms`. JSON is carried as `[String: Any]` and
  canonicalized with `JSONSerialization(.sortedKeys)` so the byte-for-byte wire contract holds.
- **executable `joiner`** — the full enroll → discover → join → post → history loop (see
  [`samples/swift`](../../samples/swift)).

Dependency: [apple/swift-crypto](https://github.com/apple/swift-crypto) (`Crypto`). HTTP is synchronous
over Foundation `URLSession`.

## Build & test

```sh
export PATH=$PATH:/opt/swift/usr/bin
swift build
swift test          # reproduces jip/conformance/vectors.json through the SDK's Wire API
swift run joiner    # the sample peer
```
