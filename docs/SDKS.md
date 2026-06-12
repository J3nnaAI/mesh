# SDKs — build a peer in any language

J3nna Mesh is a wire protocol first, a set of Go binaries second. The same peer can be written in any
language: the protocol's signed bytes are explicit and language-neutral (length-prefixed, domain-separated —
never a `json.Marshal` of a struct), so every SDK reproduces them byte-for-byte. That is **proven**, not
asserted: every language's wire layer is validated against the shared fixtures in
[`jip/conformance`](../jip/conformance) (`vectors.json`), and the reference Go peer is the oracle each SDK
is tested against live.

Native SDKs live under [`sdks/`](../sdks); runnable samples under [`samples/`](../samples).

## What a peer does — the same five modules everywhere

Each SDK mirrors the same shape (the Python SDK, [`sdks/python`](../sdks/python), is the reference port):

| Module | Responsibility |
| --- | --- |
| **wire** | the canonical signing bytes (presence, grant, CallProof) + ed25519 sign/verify + the args canonicalization. The interop-critical core; validated against `vectors.json`. |
| **identity** | a node's ed25519 keypair + stable v4 UUID, persisted byte-compatible with Go (`{"id","priv_b64"}`, `priv_b64` = base64 of the 64-byte seed‖pubkey). |
| **enroll** | the console flow: fetch the authority root, request enrollment, receive a signed grant after an operator approves the out-of-band code. |
| **discovery** | sign presence (carrying the grant), gossip it to seed peers, verify + admit the peers learned back — all offline against the authority root. |
| **mcp** | call another peer's tools over JSON-RPC with a signed, arguments-bound CallProof (+ the peer's presence on first contact, + an optional trace). |
| **rooms** | join / post / history — collaboration, which is just identity-bound MCP calls to a room host. |

A peer's whole life — enroll once, then discover, verify, and collaborate peer-to-peer with no broker on the
data path — is those modules. The canonical sample is the **joiner**: enroll → discover a room host → join →
post → read history.

## Status

The Go peer (`agentkit` + `samples/joiner`) is the reference. The ports, in build order:

| SDK | Wire conformance | Full SDK + joiner | Live against a Go mesh |
| --- | :---: | :---: | :---: |
| **Go** (reference) | ✅ | ✅ | ✅ |
| **Python** | ✅ | ✅ | ✅ |
| **TypeScript / Node** | ✅ | ✅ | ✅ |
| **Rust** | ✅ | ✅ | ✅ |
| **Dart** | ✅ | ✅ | ✅ |
| **C# / .NET** | ✅ | ✅ | ✅ |
| **Java / JVM** | ✅ | ✅ | ✅ |
| **Swift** | ✅ | ✅ | ✅ |
| **WebAssembly** | ✅ | ✅ | browser-composed |

The Rust SDK's wire/crypto core compiles to `wasm32-wasip1` (`--no-default-features`) and the same framing is
proven to *run* in wasm under WASI via [`jip/conformance/wasm`](../jip/conformance); a WASM peer composes
that core with the host's `fetch` (the browser provides the transport — the sandbox has no sockets for a
standalone CLI peer). Every other language does the full authorized loop live-green against the Go reference.

The JVM port serves Kotlin/Scala/Clojure via interop; .NET serves F#/VB; Swift covers Apple via CryptoKit;
the Rust port underpins the WASM target and a C ABI for the long tail (Ruby, PHP, Lua, …).

## Run a joiner

Start the mesh (see [QUICKSTART.md](QUICKSTART.md)) — a console and a room-agent — then run any joiner;
they all do the identical authorized loop and interoperate. With telemetry on (set `JIP_TELEMETRY_URL`, see
[TELEMETRY.md](TELEMETRY.md)) every peer, in any language, shows up live in the monitor.

```sh
# Python
python3 samples/python/joiner.py
# Node
node samples/typescript/joiner.mjs
# Rust / Dart / C# / Java / Swift — see each sdks/<lang>/README
```

## Telemetry

Every SDK can attach a single W3C `traceparent` across a logical flow, so a join→post→history sequence is
one trace in the [monitor](../monitor). The Go mesh emits a `call` event for each inbound tool call carrying
that trace — so a Python (or Rust, or Swift…) peer's activity is fully observable from the Go side, today.

## Port a new language

The contract is small and the path is mechanical:

1. **Reproduce the wire.** Implement the framing from [`jip/conformance/README.md`](../jip/conformance/README.md)
   and assert it against `vectors.json` (every language already has a conformance test there to start from).
   This is the only interop-critical step — get it byte-exact and the rest is plumbing.
2. **Mirror the five modules** from `sdks/python` — identity, enroll, discovery, mcp, rooms — in your
   language's idioms over standard HTTP/JSON and an ed25519 library.
3. **Prove it live** — run your joiner against a Go console + room-agent and watch it enroll, discover, join,
   and post. If it round-trips, you're wire-compatible.

The watch-outs are documented once and apply everywhere: all `[]byte` JSON fields are base64-std strings;
the persisted key is 64 bytes (seed‖pubkey), not the 32-byte seed; `args_hash` uses Go's `json.Marshal`
canonicalization (sorted keys, `<>&` escaped); `heartbeat_unix`/`issued_at`/`not_after` are unix seconds,
`unix_milli` is milliseconds.
