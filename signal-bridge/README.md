# signal-bridge — events + webhooks

> An authorized mesh peer that is an event hub and a bidirectional HMAC-signed webhook bridge.

`signal-bridge` connects the mesh to the outside world through events. It is an
authorized mesh peer that:

- **is an event hub** — authorized peers publish structured signals
  (`signal.publish`) and poll them (`signal.poll`): pub/sub by topic, in-band on
  the mesh;
- **fires outbound webhooks** — each published signal is POSTed to matching
  subscriptions at external URLs, signed with HMAC-SHA256 so receivers can verify
  authenticity;
- **accepts inbound webhooks** — an external system POSTs `/hook/<id>` with a
  valid HMAC to raise a mesh signal.

It runs autonomously from cached state; the console is never on the hot path.
Subscriptions and their HMAC secrets live in an encrypted [vault](../vault).

**Use it when** you need the mesh to react to external events, or external
systems to react to mesh activity. This is a long-running binary built on
[`agentkit`](../agentkit).

## Install / run

```
go install github.com/J3nnaAI/mesh/signal-bridge@latest

SIGNAL_VAULT_PASSPHRASE='change-me' \
SIGNAL_CONSOLE=http://127.0.0.1:8455 \
signal-bridge
```

## Mesh tools

Available to any authorized peer over `tools/call`:

- `signal.publish` — args `{topic, data}`; appends a signal and fires matching outbound webhooks.
- `signal.poll` — args `{topic?, since}`; returns signals after a sequence cursor.

## Outbound + inbound webhooks

- **Outbound:** each signal is POSTed to subscriptions whose topic matches (or
  `*`), with headers `X-Signal-Topic` and `X-Signal-Signature: sha256=<hex>` (HMAC
  of the body using the subscription's secret).
- **Inbound:** `POST /hook/<sub-id>` with a matching `X-Signal-Signature` raises a
  mesh signal on the subscription's topic. The signature is verified fail-closed.

## Environment

| Var | Purpose | Default |
| --- | --- | --- |
| `SIGNAL_LISTEN` | mesh HTTP listen address | `0.0.0.0:8483` |
| `SIGNAL_ADVERTISE` | externally reachable base URL | `http://127.0.0.1:8483` |
| `SIGNAL_HTTP` | management + inbound-hook HTTP address | `127.0.0.1:8484` |
| `SIGNAL_VAULT` | vault file path | `signal-vault.enc` |
| `SIGNAL_VAULT_KEY` / `_KEYFILE` / `_PASSPHRASE` | vault master key source (see [vault](../vault)) | — |
| `SIGNAL_IDENTITY` | persisted ed25519 identity file | `signal-bridge.id` |
| `SIGNAL_CONSOLE` | console URL for self-enrollment | — |

## Management endpoints (loopback-gated)

| Method + path | Purpose |
| --- | --- |
| `GET /healthz` | liveness |
| `GET /webhooks` | list outbound subscriptions |
| `POST /webhooks` | register a subscription `{topic, url}` → returns the HMAC `secret` **once** |
| `DELETE /webhooks/<id>` | remove a subscription |
| `POST /hook/<id>` | inbound webhook (HMAC-verified) → raises a mesh signal |

---

Part of the [J3nna Mesh](../README.md). Apache-2.0.
