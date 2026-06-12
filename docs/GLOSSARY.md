# Glossary

Terms used across J3nna Mesh, alphabetically. Definitions are grounded in the
actual system; cross-references point to related entries and, where useful, to
[ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY.md](SECURITY.md), and
[VERSIONING.md](VERSIONING.md).

---

### Advertise address

The host:port a peer publishes in its signed [presence](#presence) as the
endpoint other peers should dial (e.g. `http://10.0.0.5:8482`). Distinct from the
[listen address](#listen-address): a peer may listen on `0.0.0.0` but advertise a
routable address. Set via the `Advertise` option / a component's `*_ADVERTISE`
env var. See [listen address](#listen-address).

### Agent

A program that participates in the mesh as a [peer](#peer) and offers
[capabilities](#capability) / [tools](#mcp--tools). J3nna Mesh ships ready
agents — the [room-agent](#room-agent), the [signal-bridge](#signal-bridge), and
the [room-view](#room-view) human front door — and a [sample](#sample) joiner. An agent is a *role* a peer plays, not a separate
process type. (Proprietary personas built *on* the mesh are out of scope for this
project.)

### Anti-entropy

See [gossip / anti-entropy](#gossip--anti-entropy).

### Authority root

The [console](#console)'s ed25519 **root public key**: the single anchor of trust
every peer pre-seeds. Peers verify [grants](#grant) and the [CRL](#crl) against
this key **offline**, with no call back to the console. The console holds the
matching private key and is the only thing that can sign a grant or a CRL.
Configured on a peer via the `AuthorityRoot` option (or fetched at
[enrollment](#enrollment)). See [root-not-hub](#root-not-hub), [grant](#grant),
[console](#console).

### CallProof

A fresh ed25519 signature a caller attaches to a [tools/call](#mcp--tools) for a
**restricted** tool. It binds the caller's [node identity](#identity) + the tool
name + a SHA-256 **hash of the exact arguments** + a timestamp. The server
verifies it against the caller's pinned key, checks the caller is allow-listed,
and checks freshness (±30s) — so a captured proof can't be replayed with swapped
arguments or after it goes stale. See [capability](#capability), [tier](#tier),
[scope](#scope).

### Capability

A short discovery **label** a node advertises ("echo", "clock", "rooms") in its
signed presence. It's a routing hint — *"ask this node about X"* — not a contract.
The actual callable contract (argument schema, result shape, whether it's
restricted) lives at the [MCP](#mcp--tools) layer and is served by `tools/list`.
See [MCP / tools](#mcp--tools).

### Console

The mesh's **authority / control plane** and the [root of trust](#root-not-hub).
It holds the [authority root](#authority-root) keypair, processes
[enrollment](#enrollment), issues signed [grants](#grant), publishes the signed
[CRL](#crl), and exposes a small HTTP management API (default `127.0.0.1:8455`:
`/healthz`, `/version`, `/authority`, `/users`, `/enroll`, `/vault`, `/crl`,
`/grants/<id>`). It **originates** trust but is **never on the hot path** of a
normal interaction. See [enrollment](#enrollment), [grant](#grant), [CRL](#crl),
[vault](#vault).

### CRL

(Credential / Certificate Revocation List.) The [console](#console)'s signed list
of revoked [grant](#grant) IDs (`SignedCRL`). Peers fetch and **verify it
offline** against the [authority root](#authority-root) on an interval
(`agentkit.RefreshCRL`) and immediately **evict** any peer presenting a revoked
grant (`Node.SetRevoked`). With the short grant TTL as a worst-case backstop,
revocation typically propagates in seconds. See [grant](#grant),
[authority root](#authority-root).

### Discovery

How peers find each other. Two mechanisms: zero-config [multicast](#multicast) (a
node beacons its signed presence to the group and queries on startup) and
[gossip](#gossip--anti-entropy) seeds. With an [authority root](#authority-root)
set, discovery is **authorized**: only peers carrying a valid [grant](#grant)
(and a compatible [protocol major](#protocol-major)) are admitted; everyone else
is invisible. With no authority root set, discovery is **open** (development
only). See [presence](#presence), [grant](#grant).

### Enrollment

The single ingress for an untrusted user or agent to join. The joiner `POST`s
`/enroll` to the [console](#console) (kind `user` or `agent`) and receives a
`request_id` and an [OOB code](#oob-out-of-band-code). An [operator](#operator)
approves it in the console, matching the OOB (`POST /enroll/<id>/approve {oob}`).
A **user** is approved to a bearer [token](#token) bound to an
[identity](#identity); an **agent** is issued a signed [grant](#grant). See
[OOB code](#oob-out-of-band-code), [grant](#grant), [token](#token).

### Gossip / anti-entropy

The peer-to-peer presence-sync protocol. Each tick a node push-pulls with one
random known peer: it sends a cheap **digest** (`{id: heartbeat}`) of what it
already knows plus its own freshly signed record; the responder replies with only
the records the requester is **missing or stale on**. Converged meshes exchange
almost nothing; new nodes converge in one round. This is *anti-entropy* — sync
the difference, not the whole table. See [presence](#presence),
[discovery](#discovery).

### Grant

The unit of authorization. An [authority](#authority-root)-signed token binding a
[subject](#identity) (a [node identity](#identity)) to its **pinned ed25519 public
key**, a [tier](#tier), [scopes](#scope), and an expiry. It travels inside the
peer's signed [presence](#presence). A verifier checks, **offline**: the signature
against the authority root, the subject and public key match the presenting peer,
the grant isn't expired, it isn't in the [CRL](#crl), and the
[protocol major](#protocol-major) is compatible — only then is the peer admitted.
Grants are short-lived (`GrantTTL`, default 5 minutes). See
[authority root](#authority-root), [CRL](#crl), [tier](#tier), [scope](#scope).

### Identity

(Node identity.) A peer's stable cryptographic identity: an ed25519 keypair plus a
UUID, persisted to a `0600` identity file so the same `(id, key)` survives
restarts (required to be allow-listed or granted). The public key is **pinned** on
first sight; only that key may author future [presence](#presence) for that id.
See [grant](#grant), [presence](#presence), [vault](#vault).

### JIP

The **J3nna Integration Protocol**, the mesh's wire protocol, implemented in the
[`jip`](../jip/) module: ed25519 [identity](#identity), signed [presence](#presence),
[multicast](#multicast) discovery + [gossip](#gossip--anti-entropy) anti-entropy,
[MCP](#mcp--tools)-style tools and [rooms](#room), authorized discovery with
[grants](#grant)/[CRL](#crl), and [CallProof](#callproof). The human-readable wire
string (e.g. `JIP/0.1`) appears in presence and MCP `serverInfo`; the **enforced**
compatibility check keys on the integer [protocol major](#protocol-major). See
[protocol major](#protocol-major), [MCP / tools](#mcp--tools).

### Kernel

The optional embeddable **memory / knowledge-graph engine** ([`kernel`](../kernel/)
module): a bi-temporal activation graph with spreading-activation recall, typed
nodes/edges, scopes, and embeddings. It is a **substrate an agent may use for
memory** — the core mesh does **not** depend on it (clean layering). Distinct from
the mesh's authorization sense of [scope](#scope). See [agent](#agent).

### Listen address

The local host:port a component actually binds and accepts connections on (e.g.
`0.0.0.0:8482`). May differ from the [advertise address](#advertise-address) that
other peers dial. Set via the `Listen` option / a component's `*_LISTEN` env var.
See [advertise address](#advertise-address).

### MCP / tools

Each peer exposes an **MCP** (Model Context Protocol) JSON-RPC endpoint at `/mcp`
(`initialize`, `tools/list`, `tools/call`), speaking the simple JSON-response form
and also offering live server→client streams over SSE or a hand-rolled WebSocket —
all routing through one shared dispatch. Each advertised [capability](#capability)
surfaces as a **tool** with a real JSON-Schema input contract; **restricted**
tools require a [CallProof](#callproof). See [capability](#capability),
[CallProof](#callproof).

### Mesh

The whole decentralized network of [peers](#peer) and the infrastructure that
makes it work: the [JIP](#jip) protocol, the [console](#console) authority, the
[agentkit](../agentkit/) SDK, optional [kernel](#kernel) memory, and the ready
[agents](#agent). Peers run on cached credentials and verify each other offline —
there is no broker on the hot path. See [root-not-hub](#root-not-hub).

### Multicast

The zero-config [discovery](#discovery) transport. Nodes join a well-known
administratively-scoped IPv4 UDP group (default `239.42.42.42:9999`,
link/site-local, never internet-routed), beacon their signed [presence](#presence),
and query on startup so newcomers converge in milliseconds. Unverifiable frames
are dropped before they touch the registry; identity comes from the signature
inside the frame, never the UDP source address. Multicast often doesn't cross
subnets — [gossip](#gossip--anti-entropy) seeds are the fallback. See
[discovery](#discovery), [signal](#signal).

### OOB (out-of-band) code

A short code returned to a joiner at [enrollment](#enrollment) and shown to the
approving [operator](#operator), who must enter the **matching** code to approve.
It out-of-band-binds the approval to the actual request, so approving in the
console is a deliberate, matched act. See [enrollment](#enrollment).

### Operator

The human (or controlling role) who runs the [console](#console) and approves
[enrollments](#enrollment), revokes [grants](#grant), and manages the deployment.
The operator is the human side of the [authority](#authority-root). See
[console](#console), [enrollment](#enrollment).

### Peer

Any node participating in the [mesh](#mesh): it has an [identity](#identity),
publishes signed [presence](#presence), discovers and gossips with others, and
exposes an [MCP](#mcp--tools) endpoint. An [agent](#agent) is a peer playing a
role. See [identity](#identity), [presence](#presence).

### Presence

A peer's signed announcement of itself: protocol, node [id](#identity), public
key, [advertise](#advertise-address) endpoint, MCP path,
[capabilities](#capability), heartbeat, [protocol major](#protocol-major), and its
[grant](#grant). The whole payload is ed25519-signed by the owner (the only one
holding the key); receivers `Verify()` before trusting and **pin** the key on
first sight. Presence flows over [multicast](#multicast) beacons and
[gossip](#gossip--anti-entropy) — same record, same verification, same registry.
See [gossip / anti-entropy](#gossip--anti-entropy), [grant](#grant),
[identity](#identity).

### Protocol major

The integer wire-protocol major version (`jip.ProtocolMajor`, currently **1**). It
rides in signed [presence](#presence), and peers refuse to engage across
incompatible majors (`CompatibleMajor` — same major only; zero / unknown is
rejected when authorization is enforced). This is **semver enforcement at the
admit gate**, fail-closed. See [VERSIONING.md](VERSIONING.md),
[discovery](#discovery), [JIP](#jip).

### Room

The unit of multi-party collaboration ([JIP](#jip) chat layer). A named space
peers create/join, post to, and read history from, with a roster and membership
controls. Rooms are addressed by the hosting node's [identity](#identity), not a
global name, so there's no name-collision authority. See [room-agent](#room-agent).

### Room-agent

A ready [agent](#agent) ([`room-agent`](../room-agent/) module) that plays the
**room-host role**: it hosts [rooms](#room) on its node and fans events out to
participants. It is **not a central server** — it's just a peer that hosts rooms,
addressed by its node identity. It self-enrolls via `ROOM_AGENT_CONSOLE` (or runs
static with a pre-issued [authority root](#authority-root) + [grant](#grant)).
Default mesh listen `0.0.0.0:8482`. See [room](#room), [agent](#agent).

### Room-view

A ready [agent](#agent) ([`room-view`](../room-view/) module) that is the **human
chat front door** to a [room](#room): a small authorized [peer](#peer) that joins
the mesh, discovers a room host (a peer advertising the `rooms`
[capability](#capability)), [joins](#room) a room on a person's behalf, and serves
a web chat UI so a human reads and posts *alongside* agents over the same protocol.
It **hosts nothing — it joins**. Self-enrolls via `ROOMVIEW_CONSOLE`; chat UI +
local API default `127.0.0.1:8487`, mesh listen `0.0.0.0:8485`. See
[room](#room), [room-agent](#room-agent), [agent](#agent).

### Root-not-hub

The core architectural principle: the [console](#console) is the **root** that
*originates* trust (enroll / grant / revoke) but is **never a hub** on the hot
path. Peers operate on cached credentials and verify each other **offline**
against the [authority root](#authority-root). Testable invariant: a normal
peer-to-peer interaction makes **no** console call. See
[authority root](#authority-root), [console](#console).

### Sample

A reference [agent](#agent) under [`samples/`](../samples/) (the `joiner`) showing
the full authorized loop: [enroll](#enrollment) → open authorized →
[discover](#discovery) a 'rooms' peer → join its [room](#room) → post → read.
Configured via `SAMPLE_*` env vars. The canonical worked example for building your
own agent. See [QUICKSTART.md](QUICKSTART.md).

### Scope

A permission string carried in a [grant](#grant) (alongside a [tier](#tier)) that
narrows what the granted [peer](#peer) is authorized to do. Part of the grant's
canonical signed bytes. (Not to be confused with a [kernel](#kernel) memory
scope.) See [grant](#grant), [tier](#tier).

### Signal

An event in the [signal-bridge](#signal-bridge)'s event hub, raised or consumed
via mesh tools (`signal.publish` / `signal.poll`) and bridged to outside systems
via [webhooks](#webhook). (Unrelated to the UDP discovery beacon, which is part of
[multicast](#multicast).) See [signal-bridge](#signal-bridge), [webhook](#webhook).

### Signal-bridge

A ready [agent](#agent) ([`signal-bridge`](../signal-bridge/) module) that
connects the mesh to the outside world via events and [webhooks](#webhook). It
runs an event hub (`signal.publish` / `signal.poll`), posts each
[signal](#signal) to matching **outbound** webhook subscriptions (HMAC-SHA256
signed), and accepts **inbound** `POST /hook/<sub-id>` (HMAC-verified) to raise a
mesh signal. Management HTTP default `127.0.0.1:8484`; subscriptions and secrets
live in its [vault](#vault). See [signal](#signal), [webhook](#webhook).

### Tier

An integer trust/privilege level carried in a [grant](#grant) (alongside
[scopes](#scope)) and part of the grant's canonical signed bytes. It classifies
how much a granted peer is trusted. See [grant](#grant), [scope](#scope).

### Token

A bearer credential issued to a **user** at [enrollment](#enrollment), bound to an
[identity](#identity), used to authenticate to the [console](#console)'s
management API (where `mayManage` = loopback **or** a valid token mapping to an
identity). Multiple tokens per user are supported; email is a label, not the
authenticator — approval is. (Distinct from a [grant](#grant), which authorizes an
*agent* peer on the mesh.) See [enrollment](#enrollment), [identity](#identity).

### Vault

A reusable **encrypted secret store** ([`vault`](../vault/) module): pluggable Cipher (export-grade DES-56 default; AES-256-GCM via WithCipher)
per entry (the entry handle as additional authenticated data) with a PBKDF2-SHA256
key derived from a `<PREFIX>_KEY` / `<PREFIX>_KEYFILE` / `<PREFIX>_PASSPHRASE`
environment input; a `0600` file. `Get`/`Put`/`Delete`/`List` — **`List` never
returns values**. An honest at-rest boundary (protects against file exfiltration /
backups / logs, **not** host compromise). Used by the [console](#console) and
[signal-bridge](#signal-bridge). See [token](#token), [SECURITY.md](SECURITY.md).

### Webhook

The [signal-bridge](#signal-bridge)'s outside-world connector. **Outbound**: each
[signal](#signal) is `POST`ed to matching subscriptions, signed HMAC-SHA256
(`X-Signal-Signature: sha256=<hex>`, `X-Signal-Topic`). **Inbound**: a
`POST /hook/<sub-id>` carrying the matching HMAC raises a mesh signal. The
subscription secret is returned **once** at registration. See
[signal-bridge](#signal-bridge), [signal](#signal).

---

See also: [ARCHITECTURE.md](ARCHITECTURE.md) · [SECURITY.md](SECURITY.md) ·
[VERSIONING.md](VERSIONING.md) · [README.md](README.md)
