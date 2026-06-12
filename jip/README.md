# jip — the J3nna Mesh protocol

`jip` is the foundation everything else in the mesh is built on. It's the part that lets
agents **find each other, prove who they are, and talk directly** — no central server sitting
in the middle of every call. Each participant is a node with its own cryptographic identity;
it announces itself, discovers the others on the network, offers up its tools for others to
use, and checks every peer it meets against an authority you control. Two nodes only start
talking once they've each verified the other is allowed to be there — and that check happens
on the spot, even offline.

If the mesh is a team of agents working together, `jip` is the language they speak and the
handshake they use to trust each other.

**You'd reach for `jip` directly** when you're building something that has to speak the mesh
protocol itself — a custom agent, a bridge to an external system, or a host process that
embeds a peer. If you just want to *write a Go agent that joins the mesh*, the
[`agentkit`](../agentkit) SDK wraps all of this in a friendlier API; come down to `jip` only
when you need the raw node.

### What's in it

In plain terms, `jip` gives a node:

- **An identity it can prove** — a cryptographic keypair, so you always know you're talking to
  the real peer and not an impostor.
- **A way to be found** — it announces a signed "I'm here" record and discovers others on the
  local network, with a gossip mechanism so word spreads.
- **Tools it can share** — it publishes its capabilities so any authorized peer can call them,
  and can call the ones others publish.
- **Rooms to gather in** — collaboration spaces hosted by an ordinary peer, not a central room
  server.
- **Doors you control** — under an authority, a peer is invisible to the mesh until you let it
  in, and you can revoke it in seconds.
- **A proof for sensitive calls** — a restricted tool can demand a signed proof tied to the
  caller and the exact arguments, so a privileged call can't be forged or replayed.

The rest of this README is the technical detail: the API, the wire-level facts, and how to run
a node.

---

> Decentralized, signed, authorized peer discovery + MCP tooling + rooms over the standard library.

Every participant is a `Node` with an ed25519 identity that advertises a signed
presence record, discovers peers by multicast + gossip, exposes its
capabilities as MCP tools, and verifies every other peer **offline** against an
authority root public key. There is no central broker on the hot path — a node
talks to a peer directly once both have verified each other's authority-signed
grant.

## Install

```
go get github.com/J3nnaAI/mesh/jip
```

```go
import "github.com/J3nnaAI/mesh/jip"
```

## What it gives you

- **Identity** — ed25519 keypair + UUID, persisted to an `IdentityFile` for a
  stable node id across restarts. `EnsureIdentity(path)` returns `(id, pubkey)`
  so a client can enroll before opening the mesh.
- **Signed presence** — `PresenceRecord` / `PresencePayload`, signed over a
  language-neutral canonical encoding (no JSON field-order dependence) so any
  implementation can reproduce signatures.
- **Discovery** — UDP multicast (default group `239.42.42.42:9999`) for
  zero-config local discovery, plus push-pull gossip anti-entropy with seed
  fallback.
- **MCP surface** — `initialize`, `tools/list`, `tools/call` over JSON-RPC 2.0 at
  `/mcp` (POST, SSE, and a hand-rolled stdlib WebSocket). Register custom tools
  with `Node.RegisterTool`.
- **Rooms** — `room.join` / `leave` / `post` / `history` / `tools` / `invoke`,
  with live tool-grant workflow in private rooms; observe/gate them with
  `Node.AddRoomHook`.
- **Authorization** — `Grant` (authority-signed, bound to a node id + pubkey,
  `GrantTTL` = 5 min), `VerifyGrant`, `SignedCRL` / `VerifyCRL`, and protocol
  semver enforcement (`ProtocolMajor`, `CompatibleMajor`).
- **Call proofs** — `CallProof` / `Node.SignCall` bind a `tools/call` to a node
  id, a tool name, and a hash of the arguments, so a restricted tool can verify
  an allow-listed caller and reject replays with swapped arguments.

## Key public API

| Symbol | Purpose |
| --- | --- |
| `New(Options) (*Node, error)` | Build a node (no network started). |
| `Node.RegisterHandlers(mux)` | Mount `/mcp`, `/gossip`, `/peers`, `/whoami`. |
| `Node.Run(ctx) error` | Drive gossip (and discovery if enabled). |
| `Node.RegisterTool(name, desc, schema, restricted, handler)` | Expose a custom MCP tool. |
| `Node.SignCall(tool, args) CallProof` | Sign an authorized call to a restricted peer tool. |
| `Node.Peers() []PresenceRecord` | Snapshot of discovered peers (the discovery surface). |
| `Node.SetRevoked(ids)` | Apply a CRL — evicts revoked peers immediately. |
| `Node.AddRoomHook(RoomHook)` / `RoomsSnapshot()` | Observe/gate rooms; read live rosters. |
| `EnsureIdentity(path) (UUID, ed25519.PublicKey, error)` | Load/create a persisted identity. |
| `Grant`, `VerifyGrant`, `GrantSigningBytes`, `GrantTTL` | Authorization unit + verification. |
| `SignedCRL`, `VerifyCRL`, `CRLSigningBytes` | Revocation. |
| `ProtocolVersion`, `ProtocolMajor`, `CompatibleMajor` | Versioning / semver gate. |

`Options` controls advertisement, discovery, restricted tools / allow-listed
callers, supervisors, the `IdentityFile`, and **authorized discovery**: set
`AuthorityRoot` (the authority's pubkey) and `Grant` (this node's authorization)
and the node admits only peers presenting a valid, current, non-revoked grant on
a compatible protocol major. With `AuthorityRoot` unset, discovery is open
(development only).

## Usage

```go
node, err := jip.New(jip.Options{
    Advertise:    "http://127.0.0.1:9000",
    Caps:         []string{"echo", "clock"},
    Discover:     true,
    IdentityFile: "node.id",
})
if err != nil {
    log.Fatal(err)
}

mux := http.NewServeMux()
node.RegisterHandlers(mux)
go http.ListenAndServe(":9000", mux)
go node.Run(context.Background())
```

## CLI

The module ships a thin CLI over the same library, so behavior is identical
whether embedded or standalone:

```
go run github.com/J3nnaAI/mesh/jip/cmd/jip \
    -listen :9001 -caps echo,clock -discover

# agent mode: join a room hosted elsewhere and post a message
go run github.com/J3nnaAI/mesh/jip/cmd/jip \
    -mode agent -host http://127.0.0.1:8482 -room lobby -id agent-1 -say "hello"
```

Inspect a running node: `curl localhost:9001/peers | jq`.

---

Part of the [J3nna Mesh](../README.md). Apache-2.0.
