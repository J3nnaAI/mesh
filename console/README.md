# console — the mesh authority / control plane

> The root of trust: enroll, approve, grant, revoke. Originates authorization — never on the hot path.

`console` is the mesh's control plane. It holds the authority's ed25519 root
keypair, issues authority-signed [grants](../jip), publishes a signed
revocation list (CRL), and manages user tokens. It is the **root of trust, not a
hub**: peers run on cached credentials and verify each other **offline** against
the root public key, so the console is never on the hot path of a peer-to-peer
call. It is the single ingress for the untrusted — everything enters the mesh
through enrollment here.

**Use it when** you are operating a mesh and need a place to approve who may join
and to revoke them. This is a long-running binary.

## Install / run

```
go install github.com/J3nnaAI/mesh/console@latest

# minimal: unlock the vault and set a root key location
CONSOLE_VAULT_PASSPHRASE='change-me' console
```

Defaults to `127.0.0.1:8455`.

## Environment

| Var | Purpose | Default |
| --- | --- | --- |
| `CONSOLE_ADDR` | listen address | `127.0.0.1:8455` |
| `CONSOLE_VAULT` | vault file path | `console-vault.enc` |
| `CONSOLE_VAULT_KEY` / `_KEYFILE` / `_PASSPHRASE` | vault master key source (see [vault](../vault)) | — |
| `CONSOLE_ROOT_KEY` | authority root keypair file (created if absent) | `console-root.key` |
| `CONSOLE_CRL` | signed CRL file | `console-crl.json` |
| `CONSOLE_USERS` | seed user tokens, `"tok=Name,tok2=Name2"` | — |

## Endpoints

Management actions require `mayManage`: the request is on loopback **or** carries
a bearer token that maps to a known identity.

| Method + path | Auth | Purpose |
| --- | --- | --- |
| `GET /healthz`, `GET /version` | open | liveness / version |
| `GET /authority` | open | root public key + protocol major + version |
| `GET /whoami` | open | the identity proven by the caller's token (or loopback) |
| `POST /enroll` | open (untrusted ingress) | request to join (`kind` = `user` \| `agent`) → `request_id` + OOB code |
| `GET /enroll/pending` | manage | list pending requests |
| `GET /enroll/<id>` | holder polls | poll status / fetch issued credential |
| `POST /enroll/<id>/approve` | manage | approve (body `{oob}` must match) → mints a user token or issues an agent grant |
| `POST /enroll/<id>/deny` | manage | deny a request |
| `GET /users` / `POST /users` / `DELETE /users/<token>` | manage | list (masked) / mint / revoke user tokens |
| `GET /vault` / `POST /vault` | GET open, POST manage | vault handle metadata (never values) / store a secret |
| `GET /crl` | open | the signed revocation list |
| `DELETE /grants/<id>` | manage | revoke a grant (adds to the CRL) |

**Enrollment flow:** a client `POST /enroll` returns a `request_id` and an
out-of-band code; the operator approves with the matching code. A `user` is
issued a bearer token bound to its identity (email is a label; the approval is the
authorization). An `agent` is issued a signed grant bound to its node id + pubkey.
**Revocation** is published via the CRL; peers fetch and apply it on an interval
(see [`agentkit.RefreshCRL`](../agentkit)) and evict revoked peers within
seconds, with the short grant TTL as the worst-case backstop.

## Documentation

- Operations and deployment: [docs/OPERATIONS.md](../docs/OPERATIONS.md)
- Full HTTP API reference: [docs/API.md](../docs/API.md)
- Mesh overview: [../README.md](../README.md)

Apache-2.0.
