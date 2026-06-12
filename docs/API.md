# J3nna Mesh — API Reference

Complete, verified reference for every network surface in the mesh:

1. [Console HTTP API](#1-console-http-api) — the control plane (authority / enrollment / users).
2. [Signal-bridge HTTP API](#2-signal-bridge-http-api) — events + outbound/inbound webhooks.
3. [The mesh capability protocol (MCP)](#3-the-mesh-capability-protocol-mcp) — the JSON-RPC tool surface that *is* the mesh, plus the Go SDK (`agentkit`).
4. [Room-view HTTP API](#4-room-view-http-api) — the loopback chat-UI / local API of the human front door.

Related docs: [OPERATIONS.md](OPERATIONS.md) · [CONFIGURATION.md](CONFIGURATION.md) · [SECURITY.md](SECURITY.md) · [VERSIONING.md](VERSIONING.md)

Public module paths:

| Module | Import path | Role |
| --- | --- | --- |
| jip | `github.com/J3nnaAI/mesh/jip` | the wire protocol: identity, presence/gossip, discovery, MCP tools, rooms, grants, CRL |
| agentkit | `github.com/J3nnaAI/mesh/agentkit` | the peer SDK agents embed |
| vault | `github.com/J3nnaAI/mesh/vault` | encrypted secret store |
| kernel | `github.com/J3nnaAI/mesh/kernel` | optional memory/knowledge-graph substrate (core mesh does not depend on it) |

> **Conventions.** All examples use generic identities (`operator`, `user@example.com`, node ids, room `lobby`). Replace placeholders in `<angle brackets>`. Tokens, grant ids, and webhook secrets are shown **once** at creation — store them immediately.

---

## 1. Console HTTP API

The console is the **root of trust**, never a hub. It originates identity and authorization (enroll → approve → grant → revoke) and is **never on the hot path** of a peer-to-peer call. Default listen address: `127.0.0.1:8455` (`CONSOLE_ADDR`).

### Authentication model

Two gates exist; each endpoint uses exactly one (or none):

- **`mayManage`** — the privileged-management gate. Passes if the request is **loopback** *(local host)* **OR** carries `Authorization: Bearer <token>` where `<token>` maps to a known identity in the encrypted `console-users` vault map. A remote caller cannot self-assert an identity; only a valid token does.
- **loopback only** — *(not used by the console; see the signal-bridge.)*
- **none** — public, by design (peers fetch these offline).

| Endpoint | Method | Auth |
| --- | --- | --- |
| `/healthz` | any | none |
| `/version` | any | none |
| `/authority` | any | none (public — peers pre-seed the root key) |
| `/crl` | any | none (public — signed; peers verify offline) |
| `/renew` | POST | none (self-authenticating: node-key signature over the current grant; no token) |
| `/whoami` | any | none (reports who the caller's token proves them to be) |
| `/users` | GET, POST | `mayManage` |
| `/users/<token>` | DELETE | `mayManage` |
| `/enroll` | POST | **open** (the single untrusted ingress) |
| `/enroll/pending` | GET | `mayManage` |
| `/enroll/<request_id>` | GET | **open** — the requester polls by holding the unguessable id |
| `/enroll/<request_id>/approve` | POST | `mayManage` |
| `/enroll/<request_id>/deny` | POST | `mayManage` |
| `/vault` | GET | `mayManage` (lock state + handle names only — never values; even handle names are operational metadata) |
| `/vault` | POST | `mayManage` |
| `/grants/<grant_id>` | DELETE | `mayManage` |

---

### `GET /healthz`

Liveness. Returns **200 OK** with an empty body when the process is up.

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8455/healthz
# 200
```

### `GET /version`

```bash
curl -s http://127.0.0.1:8455/version
```
```json
{"console":"0.1.0"}
```

### `GET /authority`

The root of trust. Returns the authority's ed25519 **root public key** (base64), the enforced protocol major, and the console version. Every peer pre-seeds `root_public_key` and then verifies all grants and the CRL **offline** against it.

```bash
curl -s http://127.0.0.1:8455/authority
```
```json
{
  "root_public_key": "8s7Q...base64-32-bytes...=",
  "protocol_major": 1,
  "version": "0.1.0"
}
```

### `GET /crl`

The signed certificate-revocation list (the `jip.SignedCRL` shape). Public so any peer can fetch, **verify against the root**, and gossip it. See [`agentkit.RefreshCRL`](#crl-refresh).

```bash
curl -s http://127.0.0.1:8455/crl
```
```json
{
  "revoked": { "<grant_id>": 1717329600 },
  "issued_at": 1717329605,
  "signature": "base64-ed25519-over-CRLSigningBytes"
}
```

### `POST /renew`

Refresh a peer's grant before it expires, **without a fresh operator approval**. This
endpoint is **self-authenticating**: there is no token and no `mayManage` gate — the
request carries the peer's **current grant** (the proof of prior approval) plus a
**node-key signature** proving possession of the exact key the grant is pinned to. The
authority re-issues only if that grant verifies against the root, is unexpired, and is not
revoked. The renewed grant keeps the **same grant id** (the stable revocation handle) with
an advanced expiry, so revoking that id permanently ends the renewal chain (revocation
dominates renewal). Peers call this automatically via [`agentkit.KeepFresh`](#crl-refresh)
once a grant is past half its lifetime; the console is never on the hot path.

Request — a `jip.RenewalRequest`: the current grant, a freshness timestamp, and a node-key
signature over `RenewSigningBytes` (domain tag `J3nna-mesh-renew/1`):
```json
{
  "grant": { "id": "<grant_id>", "subject": "<node_id>", "public_key": "…", "tier": 3,
             "issued_at": 1717329600, "not_after": 1717329900, "signature": "…" },
  "issued_at": 1717329780,
  "signature": "base64-ed25519-node-key-over-RenewSigningBytes"
}
```
Response — a fresh `jip.Grant` (same id/subject/pubkey/tier/scopes, advanced
`issued_at`/`not_after`, re-signed by the authority root):
```json
{ "id": "<same_grant_id>", "subject": "<node_id>", "public_key": "…", "tier": 3,
  "issued_at": 1717329780, "not_after": 1717330080, "signature": "…" }
```
Status codes: **405** if not POST · **400** on a malformed body · **401** if the node-key
signature is bad or the request is stale (`VerifyRenewal`, ±2-min `RenewMaxSkew`) · **403**
if the presented grant is not ours, expired, or revoked (the peer must re-enroll) · **200**
with the fresh grant otherwise.

### `GET /whoami`

Who the caller is, as **proven** by their bearer token (or, from loopback, the optional `X-Mesh-User` header). Reports whether they may manage.

```bash
curl -s -H 'Authorization: Bearer <token>' http://127.0.0.1:8455/whoami
```
```json
{"identity":"user@example.com","can_manage":true}
```

### `GET /users`

List identities with **masked** token fingerprints (full tokens are never returned).

```bash
curl -s -H 'Authorization: Bearer <token>' http://127.0.0.1:8455/users
```
```json
{"users":[{"identity":"user@example.com","token":"a1b2…9z0y"}]}
```

### `POST /users`

Mint a bearer token for an identity (or register a caller-supplied token). The token is returned **once**.

Request:
```json
{"identity":"user@example.com","token":"<optional — minted if omitted>"}
```
Response:
```json
{
  "identity":"user@example.com",
  "token":"<64-hex-char token — shown only once>",
  "note":"store this token now — it is shown only once"
}
```
```bash
curl -s -X POST http://127.0.0.1:8455/users \
  -H 'Content-Type: application/json' \
  -d '{"identity":"user@example.com"}'
```
Multiple tokens may map to one identity (several devices / delegates). `identity` is required (400 otherwise).

### `DELETE /users/<token>`

Revoke a specific token. Effective immediately for new requests. **204 No Content** on success; **404** if the token is unknown.

```bash
curl -s -X DELETE -H 'Authorization: Bearer <token>' \
  http://127.0.0.1:8455/users/<token-to-revoke>
```

### `POST /enroll`

The **single untrusted ingress**. A client (a human device or an agent) registers and receives a `request_id` plus an out-of-band (OOB) code to display. The `request_id` is a 32-byte unguessable token that acts as a bearer capability for polling status.

Request (`kind` is `user` or `agent`):
```json
{
  "kind": "agent",
  "client_name": "room-agent",
  "email": "optional — a user LABEL only",
  "subject": "<agent node id (agent enroll)>",
  "public_key": "<base64 ed25519 pubkey, 32 bytes (agent enroll)>",
  "tier": 3
}
```
Response:
```json
{"request_id":"<32-byte hex>","oob":"123-456","status":"pending"}
```
For `kind:"agent"`, `public_key` must be a valid base64-encoded 32-byte key (400 otherwise). The grant the console later issues is **bound to this `subject` + `public_key`**.

### `GET /enroll/pending`

Operator view of pending requests (key bytes and credentials are stripped from this list).

```bash
curl -s -H 'Authorization: Bearer <token>' http://127.0.0.1:8455/enroll/pending
```
```json
{"pending":[{"id":"<request_id>","kind":"agent","client_name":"room-agent","oob":"123-456","created_at":1717329600,"status":"pending"}]}
```

### `GET /enroll/<request_id>`

**Open** — the requester polls for status and, once approved, its credential. Possession of the `request_id` is the capability.

```bash
curl -s http://127.0.0.1:8455/enroll/<request_id>
```
A pending response carries `"status":"pending"`. On approval:
- `kind:"user"` → `"token":"<bearer token>"`
- `kind:"agent"` → `"grant": { ...full jip.Grant with its ID... }`

```json
{
  "id":"<request_id>","kind":"agent","status":"approved",
  "grant":{"id":"<grant_id>","subject":"<node id>","public_key":"...","tier":3,
           "issued_at":1717329600,"not_after":1717329900,"signature":"..."}
}
```
> The **full grant object (including its `id`)** is returned here — this is the authoritative place to retrieve a grant id for later revocation.

### `POST /enroll/<request_id>/approve`

Operator approves a pending request after confirming the OOB code the requester displays.

Request:
```json
{"oob":"123-456"}
```
```bash
curl -s -X POST -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"oob":"123-456"}' \
  http://127.0.0.1:8455/enroll/<request_id>/approve
```
Response: `{"status":"approved"}`. An OOB mismatch returns **400** (`oob mismatch …`). The issued credential is then fetched by the requester via `GET /enroll/<request_id>`.

### `POST /enroll/<request_id>/deny`

```bash
curl -s -X POST -H 'Authorization: Bearer <token>' \
  http://127.0.0.1:8455/enroll/<request_id>/deny
```
Response: `{"status":"denied"}`.

### `GET /vault`

Vault lock state + handle names. **No values are ever returned.** Requires `mayManage`
(loopback or a bearer token) — even handle names are operational metadata and are not
exposed to an unauthenticated caller on a non-loopback bind.

```bash
curl -s -H 'Authorization: Bearer <token>' http://127.0.0.1:8455/vault
```
```json
{"locked":false,"handles":["console-users"]}
```

### `POST /vault`

Store a secret under a handle (`mayManage`). Only the handle is echoed.

Request:
```json
{"handle":"my-secret","value":"<secret>","desc":"optional description"}
```
Response: `{"stored":"my-secret"}`.

### `DELETE /grants/<grant_id>`

Revoke a grant by id → adds it to the CRL. **204 No Content** on success. Obtain the `grant_id` from `GET /enroll/<request_id>` (the approved request carries the full grant). Propagation: peers running [`agentkit.RefreshCRL`](#crl-refresh) evict the peer within the refresh interval (typically seconds); the 5-minute grant TTL is the worst-case backstop.

```bash
curl -s -X DELETE -H 'Authorization: Bearer <token>' \
  http://127.0.0.1:8455/grants/<grant_id>
```

---

## 2. Signal-bridge HTTP API

The signal-bridge is an **authorized mesh peer** that is also an event hub. Authorized peers publish and poll structured signals over the mesh (`signal.publish` / `signal.poll`, see [§3.5](#35-signal-bridge-mesh-tools)); the HTTP API below manages **webhooks** and accepts **inbound** hooks. Default HTTP address: `127.0.0.1:8484` (`SIGNAL_HTTP`). Mesh listen: `0.0.0.0:8483` (`SIGNAL_LISTEN`).

### Authentication model

| Endpoint | Method | Auth |
| --- | --- | --- |
| `/healthz` | any | none |
| `/webhooks` | GET, POST | **loopback only** |
| `/webhooks/<id>` | DELETE | **loopback only** |
| `/hook/<id>` | POST | **HMAC-SHA256** of the body against the subscription secret (no loopback requirement) |

> The webhook-management endpoints are gated by **loopback origin alone** — there is no bearer-token path on the bridge (a console UI drives them locally). The bridge has **no `/version` endpoint**; use `/healthz` for liveness.

### `GET /healthz`

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8484/healthz
# 200
```

### `GET /webhooks`

List outbound subscriptions (secrets are never listed).

```bash
curl -s http://127.0.0.1:8484/webhooks
```
```json
{"subscriptions":[{"id":"<sub-id>","topic":"orders.*?","url":"https://receiver.example.com/in"}]}
```
> `topic` is matched exactly, or `*` for all topics. (There is no glob expansion — `*` is the only wildcard.)

### `POST /webhooks`

Register an outbound subscription. A fresh HMAC secret is generated and returned **once**; configure your receiver with it. An empty `topic` defaults to `*`.

Request:
```json
{"topic":"orders","url":"https://receiver.example.com/in"}
```
Response:
```json
{
  "id":"<sub-id>",
  "topic":"orders",
  "url":"https://receiver.example.com/in",
  "secret":"<64-hex-char HMAC secret — shown once>",
  "note":"configure your receiver with this HMAC secret — shown once"
}
```
```bash
curl -s -X POST http://127.0.0.1:8484/webhooks \
  -H 'Content-Type: application/json' \
  -d '{"topic":"orders","url":"https://receiver.example.com/in"}'
```
`url` is required (400 otherwise).

### `DELETE /webhooks/<id>`

Remove a subscription and forget its secret. **204 No Content**.

```bash
curl -s -X DELETE http://127.0.0.1:8484/webhooks/<sub-id>
```

### `POST /hook/<id>`

Inbound webhook: an external system POSTs a body that raises a mesh signal on the subscription's topic. The request **must** carry a valid HMAC of the body (see below); fail-closed otherwise. Body is read up to 1 MiB.

```bash
BODY='{"event":"ping"}'
SIG="sha256=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "<secret>" -hex | sed 's/^.* //')"
curl -s -X POST http://127.0.0.1:8484/hook/<sub-id> \
  -H "X-Signal-Signature: $SIG" \
  -d "$BODY"
```
Response on success:
```json
{"published":<seq>,"topic":"orders"}
```
Errors: **404** unknown hook id; **401** bad signature.

### Webhook payload + HMAC signature scheme

**Outbound** (the bridge POSTs each matching signal to the subscription URL):

Headers:
| Header | Value |
| --- | --- |
| `Content-Type` | `application/json` |
| `X-Signal-Topic` | the signal's topic |
| `X-Signal-Signature` | `sha256=<hex>` — HMAC-SHA256 of the **exact request body** keyed by the subscription secret |

Body (the `Signal` object, also the inbound `data` envelope):
```json
{
  "seq": 42,
  "topic": "orders",
  "data": { "...arbitrary JSON published by the producer..." },
  "source": "mesh",
  "unix_milli": 1717329600123
}
```

**What is signed:** the raw HTTP body bytes, verbatim. Both directions use the same scheme — outbound the bridge signs; inbound the bridge verifies the `X-Signal-Signature` header against an HMAC it recomputes over the received body.

**Verifying on your receiver (pseudocode):**
```
sig_header = request.header["X-Signal-Signature"]      # "sha256=<hex>"
expected   = "sha256=" + hex(HMAC_SHA256(secret, request.body_bytes))
if not constant_time_equal(sig_header, expected):
    reject 401
# else: trust request.body, dispatch on X-Signal-Topic
```
Use a **constant-time** comparison (the bridge uses `hmac.Equal`). The signature covers the body only; treat `X-Signal-Topic` as a convenience and re-read `topic` from the verified body if it is security-relevant.

---

## 3. The mesh capability protocol (MCP)

This is the heart of the system. Every peer exposes a single JSON-RPC 2.0 endpoint (default path `/mcp`) over which it advertises and serves **tools**. Discovery (who exists, what they advertise) rides signed presence + gossip + multicast; the **contract** for calling a capability lives at the MCP layer and is served by `tools/list`.

### 3.1 Transport + JSON-RPC 2.0 envelope

`POST <peer>/mcp` carries one JSON-RPC request and returns one response (classic request/response, `Content-Type: application/json`). `GET <peer>/mcp` opens a live server→client stream (WebSocket if the client sends `Upgrade: websocket`, otherwise Server-Sent Events); both real-time transports carry the **same** JSON-RPC frames through the same dispatch.

Request:
```json
{"jsonrpc":"2.0","id":1,"method":"<method>","params":{ }}
```
Response (result):
```json
{"jsonrpc":"2.0","id":1,"result":{ }}
```
Response (error):
```json
{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found: …"}}
```
Error codes in use: `-32700` parse error, `-32600` invalid request (missing/!= `"2.0"` jsonrpc), `-32601` method/tool not found, `-32602` invalid params.

Methods: `initialize`, `notifications/initialized`, `ping`, `tools/list`, `tools/call`.

### 3.2 `initialize`

```bash
curl -s -X POST http://127.0.0.1:8482/mcp -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize"}'
```
```json
{"jsonrpc":"2.0","id":1,"result":{
  "protocolVersion":"2025-06-18",
  "capabilities":{"tools":{"listChanged":false}},
  "serverInfo":{
    "name":"mcpmesh-peer","version":"0.1.0",
    "nodeId":"<this peer's node id>",
    "jipProtocol":"JIP/0.1",
    "transports":["http","sse","websocket"]
  }
}}
```
> Three distinct version values, do not conflate: MCP `protocolVersion` `"2025-06-18"` (the MCP spec revision), `serverInfo.jipProtocol` `"JIP/0.1"` (a cosmetic negotiation string), and the **enforced** wire-protocol major `jip.ProtocolMajor = 1` (advertised in presence as `protocol_major`; `CompatibleMajor` rejects any mismatch). The `0.1` is *not* major 0 — semver enforcement is on the integer `1`. See [VERSIONING.md](VERSIONING.md).

### 3.3 `tools/list`

Returns every tool the peer serves, sorted by name. Each entry carries its **real JSON Schema** (the callable contract) and an `annotations.restricted` hint telling mesh-aware callers whether a [signed proof](#37-restricted-tools--callproof) is required.

```bash
curl -s -X POST http://127.0.0.1:8482/mcp -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```
```json
{"jsonrpc":"2.0","id":1,"result":{"tools":[
  {
    "name":"echo",
    "description":"Echo a message back to the caller.",
    "inputSchema":{
      "type":"object",
      "properties":{"message":{"type":"string","description":"Text to echo back"}},
      "required":["message"],
      "additionalProperties":false
    },
    "annotations":{"restricted":false}
  }
]}}
```

### 3.4 `tools/call`

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
  "name":"<tool>",
  "arguments":{ },
  "caller":{ /* optional signed CallProof — required for restricted tools */ }
}}
```
Result envelope (success):
```json
{"jsonrpc":"2.0","id":1,"result":{
  "content":[{"type":"text","text":"<short summary>"}],
  "structuredContent":{ /* the structured result */ }
}}
```
Tool-level errors do not use the JSON-RPC `error` field; they return a result with `"isError":true`:
```json
{"jsonrpc":"2.0","id":1,"result":{
  "isError":true,
  "content":[{"type":"text","text":"access denied: …"}]
}}
```
An unknown tool name returns a JSON-RPC `-32601` error.

### 3.5 Signal-bridge mesh tools

The signal-bridge registers two **unrestricted** tools any authorized peer may call over the mesh:

| Tool | Args | Result `structuredContent` |
| --- | --- | --- |
| `signal.publish` | `{"topic":"<string, required>","data":{<object>}}` | `{"seq":<int>}` |
| `signal.poll` | `{"topic":"<optional>","since":<int>}` | `{"signals":[<Signal>,…]}` |

`signal.publish` appends the event and fires matching outbound webhooks; `signal.poll` returns signals with `seq > since` (filtered by `topic` if given).

### 3.6 Room tools (`room.*`)

Every node hosts the room toolset (independent of advertised caps). Rooms are the unit of collaboration; a room lives on whichever node hosts it, addressed by that node's identity. Full set, with required args:

| Tool | Required args | Purpose |
| --- | --- | --- |
| `room.create` | `room_id`, `node_id` | Start a room; caller becomes owner. `private=true` → tools-capable channel (approval + key agreement + grants gate invocation). |
| `room.join` | `room_id`, `node_id` | Join with a display `alias`. Public rooms admit immediately; private rooms leave you pending owner approval. |
| `room.approve` | `room_id`, `from`, `target` | Owner-only: admit a pending member. |
| `room.agree` | `room_id`, `from`, `target` | Record mutual identity agreement (unlocks tool grants in a private room). |
| `room.leave` | `room_id`, `node_id` | Leave; your grants are revoked. |
| `room.kick` | `room_id`, `from`, `target` | Boot a member (owner / room supervisor / host supervisor); grants revoked immediately. |
| `room.post` | `room_id`, `from`, `text` | Say a message to the room. |
| `room.request_tool` | `room_id`, `from`, `capability` | Ask a member to expose a capability (signalling only). |
| `room.grant_tool` | `room_id`, `from`, `grantee`, `tool` | Expose a hook to a grantee (requires a mutually-agreed pair). |
| `room.revoke_tool` | `room_id`, `from`, `grantee`, `tool` | Withdraw a granted hook. |
| `room.tools` | `room_id`, `from` | List tools exposed to `as` (omit `as` for an operator overview). |
| `room.history` | `room_id`, `from` | Return messages with `seq > since`. |
| `room.invoke` | `room_id`, `from`, `target`, `tool` | Call a granted tool in-band (gated by private-room + approval + agreement + grant). |
| `room.deliver` | `room_id`, `event` | Inbound: receive a pushed room event from the host. |

### 3.7 Restricted tools + `CallProof`

A tool marked **restricted** requires an authenticated, allow-listed caller. The check (`authorizeCall`) fails closed and requires **all** of:

1. a `caller` proof is present;
2. `proof.tool` equals the called tool;
3. `proof.args_hash` equals `sha256(json.Marshal(arguments))` — binding the proof to **these exact arguments** (no replay with swapped args);
4. `proof.node_id` is in the serving node's **allow-list** (`Options.Allow`);
5. `proof.unix_milli` is within ±30s of now (freshness);
6. the signature verifies against the caller's **pinned** public key (the key the registry bound to that node id on first sight).

> `restricted=true` alone denies everyone — the serving node must **also** list the caller's node id in `Options.Allow`. See the worked example in [§3.10](#310-worked-example-register-discover-invoke).

`CallProof` wire shape (JSON in `params.caller`):
```json
{
  "node_id":"<caller node id>",
  "tool":"<tool name>",
  "args_hash":"<base64 sha256 of canonical arguments>",
  "unix_milli":1717329600123,
  "signature":"<base64 ed25519 over the signed bytes>"
}
```
The signed bytes are domain-separated and length-prefixed (`"JIP-call/0.2"` ‖ node_id ‖ tool ‖ args_hash ‖ unix_milli) so a call proof can never be confused with a presence-record or grant signature.

### 3.8 Defining a capability: `Node.RegisterTool`

A peer publishes a capability by registering a tool. Signature (`jip`):
```go
func (n *Node) RegisterTool(
    name, desc string,
    schema map[string]any,          // real JSON Schema, served verbatim in tools/list
    restricted bool,                // true ⇒ require a signed, allow-listed CallProof
    handler func(args map[string]any) (text string, structured any, err error),
)
```
Set `restricted=true` for any tool that **acts or spends**; leave it `false` only for read/observation tools. Register before serving begins (the tool map is not guarded for concurrent registration under live traffic).

```go
node := mesh.Node()
node.RegisterTool(
    "math.add",
    "Add two integers. args: a (int), b (int).",
    map[string]any{
        "type": "object",
        "properties": map[string]any{
            "a": map[string]any{"type": "integer"},
            "b": map[string]any{"type": "integer"},
        },
        "required": []string{"a", "b"},
    },
    false, // unrestricted
    func(args map[string]any) (string, any, error) {
        a, _ := args["a"].(float64)
        b, _ := args["b"].(float64)
        sum := int(a) + int(b)
        return fmt.Sprintf("%d", sum), map[string]any{"sum": sum}, nil
    },
)
```

### 3.9 Go SDK (`agentkit`) equivalents

| SDK call | Wire equivalent |
| --- | --- |
| `agentkit.Open(ctx, Options)` → `*Mesh` | Construct + start a `jip.Node`, mount handlers, listen, run gossip/discovery |
| `m.SelfMCP()` | this peer's own `/mcp` URL |
| `m.Node()` | the underlying `*jip.Node` (for `RegisterTool`, `SignCall`, …) |
| `m.Peers()` → `[]Peer{ID,MCP,Caps}` | discovered presence records (the discovery surface) |
| `m.PeerTools(ctx, mcpURL)` | `tools/list` against `mcpURL` |
| `m.CallPeer(ctx, mcpURL, tool, args)` | `tools/call` **with a signed `caller` proof** → returns `structuredContent` |
| `m.CallPeerRaw(ctx, mcpURL, tool, args)` | same, returns the full raw `result` JSON |
| `m.CreateRoom / JoinRoom / Post / Leave / History / RoomRoster / AddRoomResponder` | the `room.*` tools — now **signed** (each attaches a `CallProof`, plus a presence record for first contact) |

> **Both call paths sign.** `CallPeer`/`CallPeerRaw` attach a fresh `CallProof` for restricted peer tools. The room helpers (`Post`, `JoinRoom`, `History`, …) **also** sign: every `room.*` operation that acts on an identity (`create/join/approve/agree/leave/kick/post/grant_tool/revoke_tool/invoke/history/tools`) is **`IdentityBound`** — the host verifies the caller's `CallProof` cryptographically binds the claimed identity (`from`/`node_id`), so a member cannot forge another's identity. Room **authorization** (membership, ownership, approval, agreement, grants) is then enforced by the room layer **on that verified identity**. A first-contact caller also presents its signed presence record so a host it has never met can admit it (subject to the discovery admit policy) before verifying the proof.

`Node.SignCall(tool, args) CallProof` builds the proof; `agentkit` attaches it automatically inside `CallPeer`.

### 3.10 Worked example: register, discover, invoke

**Peer A** advertises a capability; **Peer B** discovers and calls it.

Peer A (serving node) — unrestricted tool:
```go
a, _ := agentkit.Open(ctx, agentkit.Options{
    Advertise: "http://127.0.0.1:9001", Listen: ":9001",
    Caps: []string{"math"}, Discover: true,
})
a.Node().RegisterTool("math.add", "Add a+b", schema, false, addHandler)
```

Peer B (caller) — discover then invoke:
```go
b, _ := agentkit.Open(ctx, agentkit.Options{
    Advertise: "http://127.0.0.1:9002", Listen: ":9002", Discover: true,
})
for _, p := range b.Peers() {                 // discovery via gossip/multicast
    tools, _ := b.PeerTools(ctx, p.MCP)       // tools/list
    for _, t := range tools {
        if t.Name == "math.add" {
            out, _ := b.CallPeer(ctx, p.MCP, "math.add",
                map[string]any{"a": 2, "b": 3}) // tools/call (signed)
            fmt.Println(out["sum"])             // 5
        }
    }
}
```

Equivalent raw wire call (unrestricted, no proof needed):
```bash
curl -s -X POST http://127.0.0.1:9001/mcp -H 'Content-Type: application/json' -d '{
  "jsonrpc":"2.0","id":1,"method":"tools/call",
  "params":{"name":"math.add","arguments":{"a":2,"b":3}}
}'
```

**Restricted variant.** Peer A marks the tool restricted **and** allow-lists Peer B's node id; Peer B's `CallPeer` attaches the signed proof automatically.

Peer A:
```go
a, _ := agentkit.Open(ctx, agentkit.Options{
    Advertise: "http://127.0.0.1:9001", Listen: ":9001",
    Caps: []string{"vault.write"},
    // BOTH are required: the tool is restricted AND the caller is allow-listed.
    // (Options.Restrict marks caps requiring a proof; Options.Allow lists caller node ids.)
    Restrict: []string{"vault.write"},
    Allow:    []string{"<Peer B's node id>"},
})
a.Node().RegisterTool("vault.write", "Store a secret", schema, true /* restricted */, writeHandler)
```
Peer B invokes exactly as before — `b.CallPeer(ctx, p.MCP, "vault.write", args)` — and `agentkit` signs the call. A raw caller would attach a `params.caller` `CallProof` built with `Node.SignCall("vault.write", args)`. Omit the proof, present the wrong tool/args, fall outside ±30s, or be absent from `Options.Allow` → `{"isError":true,"content":[{"type":"text","text":"access denied: …"}]}`.

### 3.11 Enrollment + CRL (SDK)

<a id="crl-refresh"></a>

```go
// Obtain a grant + the authority root (blocks until an operator approves).
grant, root, err := agentkit.Enroll(ctx, consoleURL, "my-agent", "my-agent.id", /*tier*/ 3,
    func(oob string) { log.Printf("approve in console — OOB %s", oob) })

m, _ := agentkit.Open(ctx, agentkit.Options{
    Advertise: "http://host:9003", Listen: ":9003", Discover: true,
    IdentityFile:  "my-agent.id",   // SAME file used for Enroll → stable id the grant is bound to
    AuthorityRoot: root,            // admit only peers with a valid grant under this root
    Grant:         grant,           // this peer's own authorization, carried in its presence
})

// Keep credentials fresh: fetch + verify + apply the CRL AND renew this peer's grant,
// both on the same background interval. Use KeepFresh for an enrolled peer that should
// stay on the mesh long-term; use RefreshCRL only for a peer with a long-lived static
// grant that never renews.
go agentkit.KeepFresh(ctx, m, consoleURL, root, 30*time.Second)
```
`Enroll` returns the grant and the root pubkey; `Open` with `AuthorityRoot` set installs the offline admit gate (valid grant, subject==id, pinned pubkey match, not revoked, compatible major). `RefreshCRL` calls `GET /crl`, verifies it against `root`, and calls `Node.SetRevoked` — which immediately **evicts** any already-admitted peer whose grant is now revoked. `KeepFresh` does that CRL work **and**, once the peer's grant is past half its lifetime, POSTs a node-key-signed renewal to [`/renew`](#post-renew) and installs the fresh grant (verifying it against `root` first) — so a long-running peer stays in authorized discovery while the console is reachable, without the console ever being on the hot path.

---

## 4. Room-view HTTP API

The room-view is an **authorized mesh peer** (mesh listen `0.0.0.0:8485`, `ROOMVIEW_LISTEN`) that is also a **human front door**: it joins a room on a person's behalf and serves a small web chat UI plus a local JSON API so a human reads and posts alongside agents. It hosts nothing — it joins a discovered room host (a peer advertising the `rooms` capability). Default HTTP address: `127.0.0.1:8487` (`ROOMVIEW_HTTP`).

### Authentication model

| Endpoint | Method | Auth |
| --- | --- | --- |
| `/` | GET | **none** — loopback-served chat UI |
| `/api/state` | GET | **none** — loopback-served |
| `/api/messages` | GET | **none** — loopback-served |
| `/api/post` | POST | **none** — loopback-served |
| `/healthz` | any | none |

> The room-view API is gated by **loopback origin** — it binds `127.0.0.1` by default and carries no token; it is the local UI for the person running it. The mesh-facing authorization (a valid grant under the authority root) is what lets room-view join the room at all; the room's own rules (public vs. private) govern posting. There is **no `/version`** endpoint; use `/healthz` for liveness.

### `GET /`

The embedded web chat UI (pure HTML/CSS/JS, no build step, no external assets). Open `http://127.0.0.1:8487` in a browser.

### `GET /api/state`

Who/where room-view is and the current roster. Reports whether it has joined a room yet (discovery can take a few seconds after start).

```bash
curl -s http://127.0.0.1:8487/api/state
```
```json
{
  "room": "lobby",
  "alias": "guest",
  "joined": true,
  "host_mcp": "http://127.0.0.1:8482/mcp",
  "host_id": "<room host node id>",
  "self_id": "<room-view node id>",
  "roster": [{"node_id": "<id>", "alias": "guest"}],
  "peers": [{"id": "<peer id>", "caps": ["rooms"]}]
}
```

### `GET /api/messages`

Room message history, incremental by sequence. Pass `?since=<seq>` to fetch only messages newer than a cursor (default `0` → all). Before a room is joined it returns an empty list with `"joined":false`.

```bash
curl -s 'http://127.0.0.1:8487/api/messages?since=0'
```
```json
{"messages":[{"seq":1,"from":"<id>","text":"hello"}],"joined":true}
```

### `POST /api/post`

Post a message to the joined room as this person.

Request:
```json
{"text":"hello from a human"}
```
```bash
curl -s -X POST http://127.0.0.1:8487/api/post \
  -H 'Content-Type: application/json' \
  -d '{"text":"hello from a human"}'
```
Response: `{"posted":true}`. Errors: **405** if not POST · **400** if `text` is missing/empty · **503** if room-view has not joined a room yet (still discovering a host) · **502** if the post to the host fails.

### `GET /healthz`

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8487/healthz
# 200
```

---

See [OPERATIONS.md](OPERATIONS.md) for running these surfaces as services, the end-to-end enrollment runbook, and revocation operations. See [SECURITY.md](SECURITY.md) for the trust model and residual risks, and [CONFIGURATION.md](CONFIGURATION.md) for every environment variable.
