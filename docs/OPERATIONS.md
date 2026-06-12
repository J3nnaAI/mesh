# J3nna Mesh — Operations Runbook

Day-2 operations for running an authorized agent mesh: services, users, agents, rooms, webhooks, revocation, secrets, upgrades, backup, monitoring, and troubleshooting.

Related docs: [API.md](API.md) (every endpoint + the MCP protocol) · [CONFIGURATION.md](CONFIGURATION.md) (every env var) · [SECURITY.md](SECURITY.md) (trust model + residuals) · [VERSIONING.md](VERSIONING.md) (semver + protocol compatibility)

Components and their default ports:

| Component | Public module | Default mgmt HTTP | Default mesh listen | State files (0600) |
| --- | --- | --- | --- | --- |
| console | `github.com/J3nnaAI/mesh/console` | `127.0.0.1:8455` | — (not a peer) | `console-vault.enc`, `console-root.key`, `console-crl.json` |
| room-agent | `github.com/J3nnaAI/mesh/room-agent` | — (none) | `0.0.0.0:8482` | `room-agent.id` |
| signal-bridge | `github.com/J3nnaAI/mesh/signal-bridge` | `127.0.0.1:8484` | `0.0.0.0:8483` | `signal-vault.enc`, `signal-bridge.id` |
| room-view | `github.com/J3nnaAI/mesh/room-view` | `127.0.0.1:8487` | `0.0.0.0:8485` | `room-view.id` |

> The **console** is the root of trust and is never on the hot path; bind its HTTP to loopback (or a trusted admin interface) and reach it locally or over a secured tunnel. **room-agent** has no HTTP management surface — it is a pure mesh peer (its "API" is the `room.*` MCP tools on its mesh listener). **signal-bridge** is both a mesh peer (port 8483) and a local webhook-management HTTP server (port 8484). **room-view** is both a mesh peer (port 8485) and a loopback **chat UI + local API** server (port 8487) — a human front door that joins a room alongside agents; it holds no secrets and has no vault.

---

## 1. Running each component as a long-lived service

Each component is a single static binary. Build with Go 1.26.3+ (latest stable):

```bash
cd console       && go build -o /usr/local/bin/mesh-console .
cd room-agent    && go build -o /usr/local/bin/mesh-room-agent .
cd signal-bridge && go build -o /usr/local/bin/mesh-signal-bridge .
cd room-view     && go build -o /usr/local/bin/mesh-room-view .
```

Put environment in `/etc/mesh/*.env` (see [CONFIGURATION.md](CONFIGURATION.md) for the full variable reference). Run each as a dedicated, unprivileged user; the state files are `0600` and must be owned by that user.

### systemd: console

`/etc/mesh/console.env`:
```ini
CONSOLE_ADDR=127.0.0.1:8455
CONSOLE_VAULT=/var/lib/mesh/console-vault.enc
CONSOLE_VAULT_PASSPHRASE=<a strong passphrase>      # or CONSOLE_VAULT_KEYFILE / CONSOLE_VAULT_KEY
CONSOLE_ROOT_KEY=/var/lib/mesh/console-root.key
CONSOLE_CRL=/var/lib/mesh/console-crl.json
# CONSOLE_USERS=tok=operator@example.com            # optional add-only seed
```
`/etc/systemd/system/mesh-console.service`:
```ini
[Unit]
Description=J3nna Mesh Console (authority / control plane)
After=network-online.target
Wants=network-online.target

[Service]
User=mesh
Group=mesh
EnvironmentFile=/etc/mesh/console.env
ExecStart=/usr/local/bin/mesh-console
WorkingDirectory=/var/lib/mesh
Restart=on-failure
RestartSec=2
# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/mesh
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

### systemd: room-agent

`/etc/mesh/room-agent.env`:
```ini
ROOM_AGENT_LISTEN=0.0.0.0:8482
ROOM_AGENT_ADVERTISE=http://<this-host>:8482
ROOM_AGENT_ROOM=lobby
ROOM_AGENT_IDENTITY=/var/lib/mesh/room-agent.id
ROOM_AGENT_CONSOLE=http://127.0.0.1:8455      # self-enroll for authorized discovery
ROOM_AGENT_CRL_SEC=30                          # CRL refresh interval (seconds)
```
`/etc/systemd/system/mesh-room-agent.service` — same skeleton as above with:
```ini
Description=J3nna Mesh Room Agent
EnvironmentFile=/etc/mesh/room-agent.env
ExecStart=/usr/local/bin/mesh-room-agent
```
> On first start with `ROOM_AGENT_CONSOLE` set, the room-agent self-enrolls and logs an OOB code; it **blocks until an operator approves it** (see §3). For unattended boot in a static deployment, pre-provision instead: `ROOM_AGENT_AUTHORITY_ROOT=<base64 root pubkey>` + `ROOM_AGENT_GRANT=<path to grant JSON>`.

### systemd: signal-bridge

`/etc/mesh/signal-bridge.env`:
```ini
SIGNAL_LISTEN=0.0.0.0:8483
SIGNAL_ADVERTISE=http://<this-host>:8483
SIGNAL_HTTP=127.0.0.1:8484
SIGNAL_VAULT=/var/lib/mesh/signal-vault.enc
SIGNAL_VAULT_PASSPHRASE=<a strong passphrase>      # or SIGNAL_VAULT_KEYFILE / SIGNAL_VAULT_KEY
SIGNAL_IDENTITY=/var/lib/mesh/signal-bridge.id
SIGNAL_CONSOLE=http://127.0.0.1:8455               # self-enroll for authorized discovery
```
`/etc/systemd/system/mesh-signal-bridge.service`:
```ini
Description=J3nna Mesh Signal Bridge (events + webhooks)
EnvironmentFile=/etc/mesh/signal-bridge.env
ExecStart=/usr/local/bin/mesh-signal-bridge
```

### systemd: room-view

`/etc/mesh/room-view.env`:
```ini
ROOMVIEW_HTTP=127.0.0.1:8487                   # loopback chat UI + local API
ROOMVIEW_NAME=guest                            # display alias in the room
ROOMVIEW_ROOM=lobby
ROOMVIEW_LISTEN=0.0.0.0:8485
ROOMVIEW_ADVERTISE=http://<this-host>:8485
ROOMVIEW_IDENTITY=/var/lib/mesh/room-view.id
ROOMVIEW_CONSOLE=http://127.0.0.1:8455         # self-enroll for authorized discovery
```
`/etc/systemd/system/mesh-room-view.service` — same skeleton with:
```ini
Description=J3nna Mesh Room View (human chat front door)
EnvironmentFile=/etc/mesh/room-view.env
ExecStart=/usr/local/bin/mesh-room-view
```
> On first start with `ROOMVIEW_CONSOLE` set, room-view self-enrolls and logs an OOB code; it **blocks until an operator approves it** (see §3 — the pending request's `client_name` is `room-view`). For unattended boot in a static deployment, pre-provision instead: `ROOMVIEW_AUTHORITY_ROOT=<base64 root pubkey>` + `ROOMVIEW_GRANT=<path to grant JSON>`. Once joined, the **chat UI is served on `http://127.0.0.1:8487`** — bind it to loopback; it is unauthenticated.

Enable + start:
```bash
systemctl daemon-reload
systemctl enable --now mesh-console mesh-room-agent mesh-signal-bridge mesh-room-view
journalctl -u mesh-console -f          # watch for the OOB enrollment codes from agents
```

> **Vault must be unlocked.** If none of `*_VAULT_PASSPHRASE` / `*_VAULT_KEYFILE` / `*_VAULT_KEY` is set, the vault is **locked** and user/webhook management is disabled (the process still runs and logs `vault LOCKED`). See [CONFIGURATION.md](CONFIGURATION.md) and §7.

---

## 2. Managing users

A "user" is a human identity. Approving one mints a bearer token bound to that identity in the console's encrypted `console-users` map. Tokens are shown **once**. Manage from loopback, or remotely with `Authorization: Bearer <token>` of an existing manager identity.

**Mint a token:**
```bash
curl -s -X POST http://127.0.0.1:8455/users \
  -H 'Content-Type: application/json' \
  -d '{"identity":"user@example.com"}'
# → {"identity":"user@example.com","token":"<64-hex — store now>","note":"…shown only once"}
```

**List users** (masked token fingerprints):
```bash
curl -s http://127.0.0.1:8455/users
# → {"users":[{"identity":"user@example.com","token":"a1b2…9z0y"}]}
```

**Revoke a token** (immediate for new requests):
```bash
curl -s -X DELETE http://127.0.0.1:8455/users/<full-token>
```
> Revocation needs the **full** token, not the masked fingerprint. If you only have the fingerprint, you cannot reconstruct the token — mint a replacement for the user and revoke the whole set if compromise is suspected. Multiple tokens may map to one identity (per-device); revoke individually.

Full request/response shapes: [API.md §1](API.md#1-console-http-api).

---

## 3. Managing agents (enrollment workflow, end to end)

An "agent" is a mesh peer. Approving one issues an authority-signed **grant** bound to the agent's node id + ed25519 public key. The grant travels in the agent's signed presence; other peers verify it offline. The flow is **pending → match OOB → approve → grant**.

1. **Agent requests enrollment.** When started with its console URL (e.g. `ROOM_AGENT_CONSOLE` / `SIGNAL_CONSOLE`, or `agentkit.Enroll`), the agent POSTs `/enroll` and logs its OOB code:
   ```
   room-agent: APPROVE this enrollment in the console — out-of-band code 123-456
   ```
2. **Operator lists pending requests:**
   ```bash
   curl -s http://127.0.0.1:8455/enroll/pending
   # → {"pending":[{"id":"<request_id>","kind":"agent","client_name":"room-agent","oob":"123-456",…}]}
   ```
3. **Match the OOB out of band** — confirm the code in the agent's log/console matches the one in the pending entry. This match *is* the authentication; do not approve a code you have not independently confirmed.
4. **Approve** with the matching OOB:
   ```bash
   curl -s -X POST http://127.0.0.1:8455/enroll/<request_id>/approve \
     -H 'Content-Type: application/json' -d '{"oob":"123-456"}'
   # → {"status":"approved"}
   ```
   The agent (polling `GET /enroll/<request_id>`) then receives its grant and joins under authorized discovery.

**Deny** instead:
```bash
curl -s -X POST http://127.0.0.1:8455/enroll/<request_id>/deny
# → {"status":"denied"}
```

### Revoke an agent's grant → CRL → propagation

To revoke, you need the **grant id**. Approval returns only `{"status":"approved"}` and `/enroll/pending` strips the grant, so retrieve the full grant from the approved request:

```bash
# 1. Get the approved request — it carries the full grant object incl. its id.
curl -s http://127.0.0.1:8455/enroll/<request_id> | jq -r '.grant.id'
# → <grant_id>

# 2. Revoke it. This adds the id to the signed CRL.
curl -s -X DELETE http://127.0.0.1:8455/grants/<grant_id>
# → 204 No Content
```

**Propagation.** Each peer runs `agentkit.KeepFresh` (the bundled agents) — or `agentkit.RefreshCRL` for a static-grant peer — which fetches `GET /crl`, verifies the signature against the authority root, and applies it via `Node.SetRevoked` — **immediately evicting** any already-admitted peer whose grant is now revoked. Effective revocation is therefore roughly the refresh interval (default 30s; tune via `ROOM_AGENT_CRL_SEC` and the interval passed to `KeepFresh`/`RefreshCRL`). The 5-minute grant TTL (`jip.GrantTTL`) is the worst-case backstop if CRL distribution is unavailable. See [SECURITY.md](SECURITY.md) for the revocation-window analysis.

> **Revocation dominates renewal.** Because grant renewal (below) keeps the **same grant id**, revoking that id via `DELETE /grants/<grant_id>` also ends the agent's renewal chain — a revoked grant cannot be renewed (`/renew` rejects it). One revoke is permanent; you do not have to "out-wait" renewals.

> Keep a record of `request_id → grant_id → agent` at approval time; it makes revocation a one-liner and is the audit trail.

---

## 4. Rooms

Rooms come and go through the **room-agent role**, not a central server. A room lives on whichever peer hosts it and is addressed by that peer's node identity, so the same room name on two hosts is two distinct rooms (no collision).

- **Create a room:** run a `room-agent` with `ROOM_AGENT_ROOM=<name>` (default `lobby`); it hosts that room on start. To host several rooms, run several room-agents (or call `room.create` from any peer via the SDK / `tools/call`).
- **Join / post / read:** members call `room.join`, `room.post`, `room.history` against the host's `/mcp` (the SDK wraps these as `JoinRoom`/`Post`/`History`). Public rooms admit immediately; private rooms (`private=true`) gate membership on owner approval and gate tool invocation on mutual agreement + explicit grants.
- **Remove a member:** `room.kick` (owner / room supervisor / host supervisor) — the booted member's grants are revoked immediately.
- **Retire a room:** stop the hosting room-agent. Membership is live; when the host goes away the room is gone (members catch up / discover elsewhere). There is no persistent room store to clean up.

Full `room.*` tool list and schemas: [API.md §3.6](API.md#36-room-tools-room).

---

## 5. Webhooks

The signal-bridge bridges the mesh event bus to HTTP. Management endpoints are **loopback-only** (run the curl on the bridge host, or tunnel to `127.0.0.1:8484`).

### Outbound subscription (mesh signal → your HTTP endpoint)

Register — the HMAC secret is returned **once**:
```bash
curl -s -X POST http://127.0.0.1:8484/webhooks \
  -H 'Content-Type: application/json' \
  -d '{"topic":"orders","url":"https://receiver.example.com/in"}'
# → {"id":"<sub-id>","topic":"orders","url":"…","secret":"<store now>","note":"…shown once"}
```
`topic` matches exactly, or use `*` (the only wildcard; empty defaults to `*`). List / delete:
```bash
curl -s http://127.0.0.1:8484/webhooks
curl -s -X DELETE http://127.0.0.1:8484/webhooks/<sub-id>
```

When any peer publishes a matching signal (`signal.publish`), the bridge POSTs the `Signal` JSON to your URL with headers `X-Signal-Topic` and `X-Signal-Signature: sha256=<hmac-hex>`.

**Verify the HMAC on your receiver** (the body is what is signed):
```python
import hmac, hashlib
expected = "sha256=" + hmac.new(secret.encode(), request.body, hashlib.sha256).hexdigest()
if not hmac.compare_digest(expected, request.headers["X-Signal-Signature"]):
    return 401
# trust request.body, dispatch on request.headers["X-Signal-Topic"]
```

### Inbound hook (external HTTP → mesh signal)

The same subscription id + secret accept inbound posts. The external sender must HMAC the body with the secret:
```bash
BODY='{"event":"ping"}'
SIG="sha256=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "<secret>" -hex | sed 's/^.* //')"
curl -s -X POST http://127.0.0.1:8484/hook/<sub-id> \
  -H "X-Signal-Signature: $SIG" -d "$BODY"
# → {"published":<seq>,"topic":"orders"}
```
A bad/absent signature is rejected **401** (fail-closed); an unknown id is **404**. The inbound post raises a mesh signal on the subscription's topic, which authorized peers can `signal.poll`. Payload + signature scheme in detail: [API.md §2](API.md#2-signal-bridge-http-api).

---

## 6. CRL / revocation & renewal operations

- **How fast revocation propagates:** seconds. Each peer's `KeepFresh` (or `RefreshCRL`) loop fetches the signed CRL, verifies it against the root, and evicts revoked peers on apply. Worst case (CRL unreachable) is bounded by the 5-minute grant TTL.
- **Renewal is automatic.** The bundled agents run `agentkit.KeepFresh`, which on the **same background tick** also **renews** the agent's grant once it is past half its lifetime — POSTing a node-key-signed request to `/renew`. So a long-running agent stays in authorized discovery indefinitely **while the console is reachable**, without any operator action and without the console ever being on the hot path. No re-approval is needed: the current grant is itself the proof of prior approval.
  - **Console reachability matters.** An unplanned console outage longer than ~half the TTL near a renewal will let a grant expire and the agent will fall out of discovery until the console returns and it renews. Keep the console up across the renew/CRL interval. (A planned *maintenance-mode auto-extend* is designed but not yet implemented — see [SECURITY.md](SECURITY.md).)
  - **Revoking ends renewal.** Renewal keeps the same grant id, so `DELETE /grants/<grant_id>` stops the renewal chain permanently.
- **Tuning the refresh interval:** trade off propagation speed vs. console load. room-agent: `ROOM_AGENT_CRL_SEC` (seconds). Other agents: the `interval` arg to `agentkit.KeepFresh`/`RefreshCRL`. The console is hit only on this background tick, never on the hot path.
- **Verify the CRL is being served:**
  ```bash
  curl -s http://127.0.0.1:8455/crl | jq '.revoked | keys'
  ```
- **Forged-CRL safety:** peers never apply a CRL whose signature does not verify against the authority root, so a tampered CRL is silently ignored (the last-good CRL + TTL still protect).

---

## 7. Key & secret management

| Secret | Where | Rotation | Backup |
| --- | --- | --- | --- |
| **Root keypair** | `console-root.key` (`CONSOLE_ROOT_KEY`, JSON, 0600) | Rotating the root **invalidates every issued grant** — all peers must re-enroll under the new root and re-fetch `/authority`. Treat as a planned re-key event, not routine. | Back up offline; loss means a full re-enrollment of the mesh. |
| **Vault encryption key** | `CONSOLE_VAULT_{PASSPHRASE,KEYFILE,KEY}` / `SIGNAL_VAULT_{…}` | To rotate: open the vault with the old key, re-write entries under the new key (or migrate the file), update the env, restart. | Back up the key/passphrase **separately** from the `.enc` file — the encrypted file is useless without it, and vice versa. |
| **Bearer tokens** | `console-vault.enc` (`console-users` map) | Revoke (`DELETE /users/<token>`) + re-mint per identity. | Covered by the vault backup. |
| **Webhook HMAC secrets** | `signal-vault.enc` (`whsec:<id>`) | Delete + re-register the subscription (new secret); reconfigure the receiver. | Covered by the vault backup. |

Vault details (pluggable cipher — export-grade DES-56 + HMAC default, AES-256-GCM via WithCipher — per entry with the handle bound, PBKDF2-SHA256 key derivation, values never returned by list/read): see [SECURITY.md](SECURITY.md) and [CONFIGURATION.md](CONFIGURATION.md). The vault is an honest **at-rest** boundary (protects against file exfiltration / backups / logs), **not** against same-uid host compromise.

---

## 8. Upgrades

- **Semver discipline.** Module releases use path-prefixed semver tags (e.g. `jip/v1.2.0`). The wire protocol enforces **major** compatibility: a peer advertising a different `protocol_major` is refused (`CompatibleMajor`). See [VERSIONING.md](VERSIONING.md).
- **Rolling peers (same protocol major):** upgrade peers one at a time; minor/patch releases interoperate, so a mixed-version mesh is fine during the roll. Restart each service; identity files keep node ids stable across restarts (grants stay valid).
- **Protocol-major bumps are breaking:** a new major cannot talk to the old one. Plan a coordinated cutover (or run two meshes briefly). The console's `/authority` advertises `protocol_major` so you can confirm what a fleet expects before rolling.
- Before upgrading, run a supply-chain/vulnerability check on the new artifacts and prefer the latest stable Go toolchain.

---

## 9. Backup / restore

State is a handful of `0600` files per component. Back them up while the service is stopped (or use a consistent filesystem snapshot), and store the **vault encryption keys/passphrases separately** from the encrypted vault files.

| Component | Files to back up |
| --- | --- |
| console | `console-vault.enc`, `console-root.key`, `console-crl.json` |
| room-agent | `room-agent.id` |
| signal-bridge | `signal-vault.enc`, `signal-bridge.id` |
| room-view | `room-view.id` |

```bash
systemctl stop mesh-console
install -m600 -o mesh -g mesh /var/lib/mesh/console-vault.enc  /backup/mesh/
install -m600 -o mesh -g mesh /var/lib/mesh/console-root.key   /backup/mesh/
install -m600 -o mesh -g mesh /var/lib/mesh/console-crl.json   /backup/mesh/
systemctl start mesh-console
```
**Restore:** place the files back with `0600` ownership for the service user, restore the matching vault key/passphrase into the env, and start the service. Restoring `*.id` files preserves node identities (so existing grants and allow-list entries remain valid); restoring `console-root.key` preserves the authority so issued grants keep verifying.

> Losing `console-root.key` means the mesh's entire trust anchor is gone — every agent must re-enroll under a new root. This file is the single most important backup.

---

## 10. Health monitoring

- **console:** `GET /healthz` (200) and `GET /version` (`{"console":"0.1.0"}`).
- **signal-bridge:** `GET /healthz` (200). **The bridge has no `/version`** — do not probe it.
- **room-agent:** no HTTP surface. Verify liveness via the systemd unit (`systemctl is-active`), its logs (`room-agent up: …`), or by listing peers/rooms from another peer over the mesh (`tools/list`, `room.history`).
- **room-view:** `GET /healthz` (200) on its chat-UI/API port (`127.0.0.1:8487`). It has no `/version`; `GET /api/state` also reports whether it has joined a room.

```bash
curl -s -o /dev/null -w 'console  %{http_code}\n' http://127.0.0.1:8455/healthz
curl -s -o /dev/null -w 'bridge   %{http_code}\n' http://127.0.0.1:8484/healthz
curl -s -o /dev/null -w 'roomview %{http_code}\n' http://127.0.0.1:8487/healthz
systemctl is-active mesh-room-agent
```
A liveness probe for systemd/k8s can curl `/healthz`; for the room-agent use a process/port check on its mesh listener.

**Security-event monitoring.** Each component emits security-relevant events to stderr prefixed **`AUDIT`** — filter with `journalctl -u mesh-console | grep AUDIT` (or your log stack). The lines worth alerting on:
- `AUDIT enroll: issued grant …` / `approved …` / `denied …` — every grant issuance and approval/denial (console).
- `AUDIT renew: re-issued grant …` — a grant's life was extended (self-authenticating, so this is the only record); `rejected`/`declined` variants flag a bad-signature, stale, expired, or revoked renewal attempt.
- `AUDIT discovery: rejected peer <id>: <reason>` — a peer failed the admit gate (deduped per id); a spike alongside a climbing `rejected=` count signals probing or a version mismatch.
- `AUDIT mcp: denied restricted call …` — a peer attempted a privileged tool it is not allow-listed for.
- `AUDIT hook: rejected inbound webhook … (bad HMAC signature) …` — someone is probing `/hook/<id>` with a wrong secret (signal-bridge).

These are plain stderr lines with no built-in rotation; capture them with the host logger (journald / a file under logrotate) and ship off-host. Full coverage, gaps, and alert guidance: [AUDIT-LOGGING.md](AUDIT-LOGGING.md).

---

## 11. Troubleshooting

**A peer is invisible / "nothing tries to talk to it."** Under authorized discovery a peer must present a valid grant or it is ignored. Check, in order:
- **No grant / not approved:** the agent is still pending — approve its enrollment (§3).
- **Expired grant:** grants are short-lived (5-min TTL) but `agentkit.KeepFresh` renews them automatically while the console is reachable. A peer drops out only if renewal could not reach the console for longer than ~half the TTL (an extended console outage) — confirm the console was reachable on the renew interval; if the grant already lapsed, the peer re-enrolls. A static-grant peer (no `KeepFresh`/`/renew`) does expire at the TTL and must be re-granted.
- **Revoked grant:** check `GET /crl` — if the peer's grant id is listed, it was revoked; re-enroll to get a new one.
- **Wrong authority root:** the peer's `AuthorityRoot` must equal the console's current `/authority` `root_public_key`. After a root rotation, peers on the old root are invisible — re-fetch and re-enroll.
- **Protocol-major mismatch:** a peer on a different `protocol_major` is refused. Confirm versions; roll to a compatible major (§8).
- **Grant binding mismatch:** the grant's subject must equal the node id and its pubkey must match the presence pubkey — this breaks if the identity file changed after enrollment. Always `Open` with the **same** `IdentityFile` used at `Enroll`.

**Discovery fails entirely (no peers seen).** Multicast discovery uses UDP group `239.42.42.42:9999`.
- Multicast is often blocked across subnets and on many cloud networks. Verify peers are on the same L2 segment, or supply `Seeds` (bootstrap peer URLs) as a fallback.
- Check host firewalls allow UDP `9999` and the mesh TCP listen ports (8482/8483) between peers.
- Confirm each peer's `Advertise` URL is reachable by other peers (not `127.0.0.1` when peers are on different hosts).

**`vault LOCKED` in the logs / management 401 or disabled.** No vault key was provided — set `*_VAULT_PASSPHRASE` / `*_VAULT_KEYFILE` / `*_VAULT_KEY` and restart (§1, [CONFIGURATION.md](CONFIGURATION.md)).

**`unauthorized` (401) on console management.** You are not on loopback and have no valid bearer token, or the token was revoked. Run locally, or pass `Authorization: Bearer <token>` of a known identity (`GET /whoami` to confirm `can_manage`).

**`unauthorized` on `/webhooks`.** These are **loopback-only** — there is no bearer path. Run the request on the bridge host or via a loopback tunnel.

**Webhook receiver rejects deliveries / inbound `401 bad signature`.** Recompute the HMAC over the **exact raw body** with the subscription secret and compare to `X-Signal-Signature: sha256=<hex>` using a constant-time compare. A secret mismatch (re-registered subscription) is the usual cause — re-register and update the receiver (§5).

**`oob mismatch` on approve.** The code you sent does not match the pending request's OOB. Re-read the agent's logged code and the `/enroll/pending` entry; they must match exactly (`NNN-NNN`).

---

See [API.md](API.md) for exact request/response shapes, [CONFIGURATION.md](CONFIGURATION.md) for every environment variable, [SECURITY.md](SECURITY.md) for the threat model, and [VERSIONING.md](VERSIONING.md) for compatibility policy.
