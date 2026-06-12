# Audit logging — J3nna Mesh

This document describes what each mesh component logs today, which security-relevant
events are **not** currently emitted, where logs go, and how an operator should retain,
review, and alert on them. It is deliberately precise about gaps: several
authorization-critical events are not logged by the current code, and pretending
otherwise would defeat the purpose of an audit document.

Companion documents:

- [`./SECURITY.md`](./SECURITY.md) — the trust and threat model these events relate to.
- [`./OPERATIONS.md`](./OPERATIONS.md) — deployment runbook. *(Forward reference.)*

---

## 1. How logging works today

Every component logs with the Go standard-library `log` package, writing **plain-text
lines to standard error**. Security-relevant events are prefixed **`AUDIT`** so they can
be filtered out of operational chatter with a plain `grep AUDIT` or a journald match —
but that prefix is the *only* structure. There is still:

- **no structured (JSON/`slog`) audit log**,
- **no dedicated audit channel** separate from operational chatter (the `AUDIT` prefix is
  a filter handle on the same stderr stream, not a separate sink),
- **no built-in retention, rotation, or shipping**.

This means **the host is responsible for capture and retention.** Run each component
under a service manager that captures stderr — for example `systemd` (→ `journald`) or a
container runtime — or redirect stderr to a file under logrotate. All guidance below
assumes you have done this; the components themselves do not persist their own logs.

Because logging is operational-grade rather than audit-grade, the honest posture is:
**treat the `AUDIT`-prefixed lines below as the available signal, and wrap the components
with the host logger to capture and retain them.** The authorization-critical events
(grant issuance/approval/denial, grant renewal, admit rejections with reasons,
restricted-call denials, inbound-hook signature failures) are now emitted directly; a few
gaps remain (noted per row below) where a reverse proxy / sidecar is still the way to
capture them.

---

## 2. Event coverage by component

Legend: **Logged** = a log line is emitted today · **Not emitted** = security-relevant but
no log line exists in current code (recommended additions / operator-side capture noted).

### Console (control plane / authority)

| Event | Status | Detail |
|---|---|---|
| Startup, listen address, vault locked/unlocked | Logged | `console <ver> listening on <addr> (vault=…, locked=…)` |
| Vault locked at boot | Logged | warns that user management is disabled |
| `console-users` seed applied | Logged | count of new entries (no tokens) |
| Token mint via `POST /users` | Logged | `issued token for identity "<id>"` (identity only; token never logged) |
| Token revoke via `DELETE /users/<token>` | Logged | `revoked a token for identity "<id>"` |
| Grant **revoke** via `DELETE /grants/<id>` | Logged | `console: revoked grant <masked-id>` (no `AUDIT` prefix) |
| Enrollment **request** (`POST /enroll`) | **Not emitted** | no log line; the untrusted ingress is silent |
| Enrollment **approve / deny** (`POST /enroll/<id>/approve|deny`) | Logged | `AUDIT enroll: approved <kind> "<client>" (<masked-req-id>)` · `AUDIT enroll: denied …` |
| Grant **issuance** (on enroll-approve) | Logged | `AUDIT enroll: issued grant <masked-id> to agent "<client>" (subject <masked>, tier <n>)` |
| Grant **renewal** (`POST /renew`) | Logged | `AUDIT renew: re-issued grant <masked-id> for <masked-subject> (tier <n>) until <RFC3339>`; declines log `AUDIT renew: rejected request …` (bad node sig / stale) or `AUDIT renew: declined grant …` (expired / revoked / not ours) |
| `mayManage` authorization failures (401 on management routes) | **Not emitted** | rejected management attempts return 401 but are not logged |

> **What is and isn't covered now:** administrative token mint/revoke, grant *revoke*, the
> **enrollment approval path** (which mints user tokens and **issues agent grants**), and
> **grant renewal** are all logged — the act of granting and re-granting authorization,
> the most audit-worthy events in the system, leave an `AUDIT` line. The remaining
> console gaps are the silent untrusted-ingress (`POST /enroll`) and unlogged `mayManage`
> 401s; capture those operator-side (§4). Note grant renewal is **self-authenticating**
> (no operator action) — its `AUDIT renew:` line is the only record that a grant's life
> was extended.

### jip (protocol library, embedded in every peer)

| Event | Status | Detail |
|---|---|---|
| Peer admitted (accepted into registry) | Logged (aggregate) | gossip: `accepted=N ignored=N rejected=N`; discovery: per-accepted line with id prefix + endpoint |
| Peer **rejected** by admit gate / bad signature | Logged (aggregate count **+** per-peer reason) | still counted as `rejected=N`, and `discovery rejected frame from <addr>` for raw frames; **now also** `AUDIT discovery: rejected peer <id>: <reason>` naming the specific reason (bad signature, grant subject≠id, revoked, incompatible major, expired). **Deduped per peer id** — a beaconing peer logs once per reason, not once per beacon |
| Stale peers expired | Logged | `gossip expired N stale peers` |
| Revocation applied / peers evicted | **Not emitted** | `SetRevoked`/`evictRevoked` change state silently |
| Restricted `tools/call` **denied** (`authorizeCall` failure) | Logged | `AUDIT mcp: denied restricted call "<tool>" from "<caller-id>": <reason>` (the caller still also receives `access denied: <reason>` in the RPC response) |

> Admit rejections now carry a **per-peer reason** (`AUDIT discovery: rejected peer …`)
> alongside the aggregate `rejected=` count, deduped per id so a persistent beaconer does
> not flood the log. A spike in `rejected=` is still worth alerting on (§5), and the
> `AUDIT` line now lets you root-cause it.

### agentkit (peer SDK)

| Event | Status | Detail |
|---|---|---|
| Mesh listener error | Logged | `agentkit: mesh listener: <err>` |
| Room-responder post failure | Logged | `agentkit: room responder post: <err>` |
| CRL fetch / verify **failure** | **Not emitted** | `RefreshCRL` / `KeepFresh` skip a failed/forged CRL **silently** (by design — last-good CRL + TTL still protect — but it means a console that has been unreachable for hours is invisible in logs) |
| CRL applied successfully | **Not emitted** | no line on a successful refresh |
| Grant **renewal** by a peer (`KeepFresh` → `POST /renew`) | **Not emitted (peer side)** | `KeepFresh` renews silently on the background tick; a failed renew (console unreachable) is skipped silently and retried next tick. The console **does** log it (`AUDIT renew:` above), so the authoritative renewal record is console-side |

### room-agent

| Event | Status | Detail |
|---|---|---|
| Enrollment OOB prompt | Logged | `APPROVE this enrollment in the console — out-of-band code <oob>` |
| Enrolled (grant obtained) | Logged | `enrolled — grant <id-prefix>…` |
| Startup (id, room, authz on/off) | Logged | `room-agent up: id=… hosting #… authz=…` |
| Fatal errors (enroll, open, bad root/grant) | Logged | `log.Fatalf` lines |

### signal-bridge (events + webhooks)

| Event | Status | Detail |
|---|---|---|
| Startup, HTTP address, authz on/off | Logged | `signal-bridge up: …`; `HTTP (webhooks + inbound hooks) on <addr>` |
| Vault locked at boot | Logged | warns webhook management disabled |
| Enrollment OOB prompt / enrolled | Logged | as room-agent |
| Outbound webhook POST failure | Logged | `webhook <id> POST failed: <err>` |
| Missing webhook secret for a subscription | Logged | `missing secret for sub <id>` |
| Webhook **registered** (`POST /webhooks`) | **Not emitted** | secret returned once; no audit line |
| Webhook **deleted** (`DELETE /webhooks/<id>`) | **Not emitted** | no log line |
| Inbound hook **signature verification failure** (`POST /hook/<id>`) | Logged | `AUDIT hook: rejected inbound webhook on "<id>" (bad HMAC signature) from <remote-addr>` (still returns `401`, fail-closed) |
| Inbound hook accepted → signal raised | **Not emitted** | the published seq is returned to the caller but not logged |

> The **inbound-hook signature failure** — exactly the event you would want to alert on
> (someone probing `/hook/<id>` with a wrong/guessed secret) — is **now logged** with the
> hook id and remote address. You can alert on the `AUDIT hook:` line directly rather than
> only counting `401`s at a proxy.

---

## 3. Where logs go

| Component | Default sinks | Notes |
|---|---|---|
| All | `stderr` (stdlib `log`) | The component never writes its own log file |

Recommended capture:

- **systemd / journald:** run each as a unit; `journalctl -u <unit>` is your audit trail.
  Set `SyslogIdentifier=` per component so events are filterable.
- **Containers:** the runtime captures stdout/stderr; ship to your log stack.
- **Plain file:** redirect stderr to a file managed by `logrotate` (`0600`, owned by the
  service uid). Logs may contain identities (email-like labels) and **masked** token
  fingerprints; they do **not** contain raw tokens, grant private material, or vault
  values — but treat them as sensitive operational data regardless.

---

## 4. Capturing what the code does not emit

The highest-value events — grant/token issuance on approval, **grant renewal**,
admit-reject reasons, inbound-hook signature failures, restricted-call denials — are
**now emitted directly** as `AUDIT` lines, so capturing and retaining the component
stderr (§3) is the primary trail. A few gaps remain (the untrusted `POST /enroll`
ingress, `mayManage` 401s, webhook register/delete, successful inbound-hook signal
raises); for those, the operator-side compensations are:

1. **Front the management HTTP surfaces with a reverse proxy** that access-logs every
   request. On the **console**, this captures `POST /enroll` (the silent ingress), the
   `POST /enroll/<id>/approve|deny` and `DELETE /grants/<id>` calls (corroborating the
   `AUDIT enroll:` / revoke lines), `POST /users`, and `DELETE /users/<token>` with
   timestamp, source, and status — plus any `mayManage` `401`s the component does not log.
   On the **signal-bridge**, it captures `POST/DELETE /webhooks…` (still unlogged) — the
   `401`s on `/hook/<id>` are now also in the component's own `AUDIT hook:` lines.
2. **Periodically snapshot authority state** as a point-in-time audit: `GET /users` (masked
   token list) and `GET /crl` (signed revocation list). Diffing successive snapshots reveals
   token and grant-revocation changes even though issuance itself is unlogged.
3. **Wrap the components with the host logger** and filter on the `AUDIT` prefix to
   separate the security trail from operational chatter. Where you control a build,
   structured (`slog`/JSON) audit lines and the few remaining *Not emitted* points are the
   clean long-term fix; the proxy and snapshots are the no-code-change interim for those.

---

## 5. What to alert on

| Alert | Source signal | Why |
|---|---|---|
| **Repeated rejected admits** | `rejected=N` climbing in gossip/discovery logs; `AUDIT discovery: rejected peer <id>: <reason>` for the specific cause | Possible unauthorized peers probing, an expired/revoked peer still announcing, or a protocol-version mismatch after a partial upgrade |
| **Inbound-hook signature failures** | `AUDIT hook: rejected inbound webhook … (bad HMAC signature) …` (now in the bridge's own logs; a proxy `401` count corroborates) | Someone is POSTing to an inbound hook with a wrong/guessed HMAC secret |
| **Unexpected grant revocation** | `console: revoked grant <id>` not matching a planned action | Indicates console access you did not authorize, or an operator error |
| **Unexpected token mint** | `console: issued token for identity …` not matching a planned action | Same — token issuance you did not initiate |
| **Unexpected grant issuance / renewal** | `AUDIT enroll: issued grant …` or `AUDIT renew: re-issued grant …` not matching an intended enrollment | A grant issued or its life extended without a corresponding intended approval (renewal is self-authenticating, so the `AUDIT renew:` line is the only signal it happened) |
| **Restricted-call denials** | `AUDIT mcp: denied restricted call "<tool>" from "<caller>": <reason>` (now server-side; caller still sees `access denied`) | A peer attempting privileged tools it is not allow-listed for |
| **CRL not refreshing** | Silence where you expect periodic refresh; `GET /crl` unreachable from a peer host | A revoked grant may be relying on TTL expiry instead of fast eviction; console may be down |
| **Vault opened locked** | `vault LOCKED …` at startup | Management is disabled and secrets are unavailable — almost always a misconfiguration |
| **Enrollment approvals out of band** | `AUDIT enroll: approved …` (now logged by the component; a proxy access log corroborates the source) | Every authorization grant should correspond to an intended operator approval |

---

## 6. Recommended retention & review cadence

These are baseline recommendations; align with your own policy.

- **Retention:** keep captured logs **≥ 90 days** for the console (it holds the
  authorization audit trail); **≥ 30 days** for peers and the signal-bridge. Store on a
  host the audited components cannot themselves rewrite.
- **Integrity:** ship logs off-host (journald remote, syslog, or your log stack) so a
  compromised peer cannot erase its own trail.
- **Review cadence:**
  - *Continuous:* the alerts in §5 (admit-reject spikes, hook `401`s, unexpected
    revoke/mint) should page or notify.
  - *Weekly:* review console enrollment-approval and token/grant activity against intended
    changes; diff the `GET /users` and `GET /crl` snapshots from §4.
  - *On change:* after any deployment, version bump, or key rotation, confirm peers
    re-admit cleanly (no sustained `rejected=`) and the CRL is still reachable.

---

## 7. Honest summary of current limitations

- Logging is **operational, not audit-grade in form**: plain-text stderr with an `AUDIT`
  prefix, no structured (JSON/`slog`) channel, no built-in retention or rotation. The
  prefix is a filter handle on the same stream, not a separate sink.
- The **enrollment-approval path, grant issuance, and grant renewal are now logged**
  (`AUDIT enroll:` / `AUDIT renew:`) — the most important authorization events leave a
  component-side record. Renewal is self-authenticating, so its `AUDIT renew:` line is the
  authoritative record that a grant's life was extended.
- **Admit rejections now carry a per-peer reason** (`AUDIT discovery: rejected peer …`,
  deduped per id) alongside the aggregate `rejected=` count.
- **Inbound-hook signature failures and restricted-call denials are now logged**
  (`AUDIT hook:` / `AUDIT mcp:`).
- Remaining gaps: the untrusted `POST /enroll` ingress, `mayManage` 401s, webhook
  register/delete, and successful inbound-hook signal raises are **still not emitted**;
  and **CRL fetch/verify failures (and silent renew skips) are intentionally silent**
  (fail-safe to last-good CRL + TTL, but invisible to monitoring).

Capture and retain the `AUDIT` lines via the host logger (§3); for the residual gaps, the
reverse-proxy access logging and periodic authority-state snapshots in §4 fill them in.
The mesh's security controls (§ in [`./SECURITY.md`](./SECURITY.md)) are cryptographic and
fail-closed regardless of logging; logging gaps reduce *observability*, not *enforcement*.

---

*Apache-2.0.*
