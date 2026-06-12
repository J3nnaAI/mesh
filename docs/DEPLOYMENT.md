# J3nna Mesh — Deployment

How to run a J3nna Mesh beyond a single workstation: a verified Docker/Compose path
and Kubernetes manifests that mirror it, with an honest operational runbook (enrollment,
discovery, fail-closed root key, probes).

> **Honesty note (read first).** Both paths are **verified end-to-end**. The **Docker /
> Compose path** runs the full enroll → approve → seed-discovery → join → post loop across
> containers. The **Kubernetes manifests in [`../deploy/k8s/`](../deploy/k8s/) are verified on
> MicroK8s v1.35.3** — the same loop formed end-to-end across pods (console + room-agent +
> room-view + signal-bridge + a sample joiner, all pods `Running 1/1`, **0 restarts** on a fresh
> concurrent deploy). **CI does not run a cluster**, so schema-validate and smoke-test against
> *your* cluster and Kubernetes version before relying on these. What is verified is
> **single-instance-per-role** — not multi-replica; multi-instance horizontal scaling is not
> supported in this release (see §4).

Cross-references:
[INSTALL.md](INSTALL.md) (build the binaries) ·
[CONFIGURATION.md](CONFIGURATION.md) (every environment variable) ·
[SECURITY.md](SECURITY.md) (trust model, grants, residual risks) ·
[OPERATIONS.md](OPERATIONS.md) (enroll/approve/revoke day-two) ·
[QUICKSTART.md](QUICKSTART.md) (the 10-minute loop).

---

## 1. The load-bearing reframe: a peer is an identity, not a worker

Before any deployment decision, internalize what a mesh peer *is*.

**A mesh peer is a cryptographically-pinned IDENTITY** — a persisted ed25519 keypair that
yields a stable node id. The console issues a **grant** bound to that id **and** its public
key; other peers pin the first verified key for an id and verify grants offline against the
authority root. A peer is therefore not a stateless web worker behind a load balancer. It is a
named, credentialed participant with its own state (the rooms it hosts, its event log, its
roster).

**Why this drives the topology: identity stability.** Because a peer's grant is bound to its
persisted identity, that identity must survive restarts and reschedules. Lose the `.id` file
and the peer comes back as a *different* participant whose old grant is worthless. So each peer
maps to a **`StatefulSet` with a per-pod PVC** (a `volumeClaimTemplate` holding the `.id` file)
and a **headless `Service`** for stable per-pod DNS — never `Deployment` + `ClusterIP`. A
reschedule reattaches the same PVC → same identity → same node id → the grant stays valid and
the peer is the same participant it was before. Every manifest in `deploy/k8s/` follows this
rule and ships `replicas: 1` on purpose.

---

## 2. Docker / Compose quickstart (the verified path)

The compose file at [`../deploy/docker/compose.yaml`](../deploy/docker/compose.yaml) runs **one
of each role** — console, room-agent, signal-bridge, room-view — plus an optional demo
`joiner`. Discovery is gossip-seeded (`*_DISCOVER=false`, multicast off), and every
`*_ADVERTISE` is the service DNS name, not `127.0.0.1`.

### Bring it up

```sh
# From the repo root. --build the images on first run.
docker compose -f deploy/docker/compose.yaml up --build -d

# (optional) include the demo joiner:
docker compose -f deploy/docker/compose.yaml --profile demo up --build -d
```

### Approve the enrollments

Every agent (room-agent, signal-bridge, room-view, joiner) **self-enrolls and BLOCKS until an
operator approves it** in the console. Approval is authenticated with the operator bearer token
seeded via `CONSOLE_USERS` (in the compose file, `change-me-operator-token`). The approval also
matches an out-of-band (OOB) code each agent prints to its log.

```sh
TOKEN='change-me-operator-token'
CONSOLE='http://localhost:8455'

# List pending enrollments (id + the OOB code each agent printed):
curl -s -H "Authorization: Bearer $TOKEN" "$CONSOLE/enroll/pending"

# Approve each one. Find the agent's OOB code in its container log:
#   docker compose -f deploy/docker/compose.yaml logs room-agent | grep out-of-band
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  "$CONSOLE/enroll/<id>/approve" -d '{"oob":"<the-oob-code>"}'
```

Or loop over every pending request. It can't be fully no-touch — the OOB code is, by design,
out-of-band (each agent prints it to *its own* log), so the loop prompts you per id:

```sh
for id in $(curl -s -H "Authorization: Bearer $TOKEN" "$CONSOLE/enroll/pending" \
            | grep -o '"id":"[^"]*"' | cut -d'"' -f4); do
  read -rp "OOB code for $id (from its container log): " oob
  curl -s -X POST -H "Authorization: Bearer $TOKEN" \
    "$CONSOLE/enroll/$id/approve" -d "{\"oob\":\"$oob\"}"
done
```

Approve every pending request the same way. Once approved, the agent unblocks, discovers the
room host via its seed, and joins.

### See it work

- Console UI + API: <http://localhost:8455/>
- Human chat UI (room-view): <http://localhost:8487/>

Post from the chat UI and you will see your message land in the same `lobby` room the agents
joined — a human and agents sharing one room over one protocol.

### Persistence — where state survives a restart

Every component that holds state writes it under `/data`, backed by a per-service **named volume** in
Compose and a per-pod **PVC** (`volumeClaimTemplates`) in Kubernetes. A restart or reschedule reattaches
the same volume, so identity and secrets survive. (Verified: after a full container recreate the authority
root pubkey is unchanged and stored vault handles are still present.)

| Component | Persisted state | Compose volume | Kubernetes |
|---|---|---|---|
| **console** | authority root key, encrypted vault (users/tokens), CRL | `console-state` → `/data` | PVC `/data` (root key also mountable from a Secret — see §3.3) |
| **signal-bridge** | encrypted webhook-subscription vault + HMAC secrets, identity | `signal-state` → `/data` | PVC `/data` |
| **room-agent** | ed25519 identity (`room-agent.id` → stable node id) | `room-agent-state` → `/data` | PVC `/data` |
| **room-view** | ed25519 identity | `room-view-state` → `/data` | PVC `/data` |

Why it matters: losing the console root key mints a new authority that invalidates **every** grant; losing
a peer's `.id` file changes its node id, forcing re-enrollment. The images run as the distroless `nonroot`
uid (65532) with `/data` writable by that uid, so the volumes need no extra permission setup. See
[SECURITY.md](SECURITY.md) for why a stable root matters.

---

## 3. Kubernetes (verified on MicroK8s v1.35.3)

The manifests in [`../deploy/k8s/`](../deploy/k8s/) mirror the Compose topology one-to-one,
translated into the `StatefulSet` + headless-`Service` model the reframe (§1) requires. Images
were built from [`../deploy/docker/Dockerfile`](../deploy/docker/Dockerfile) and pushed to an
in-cluster registry; the manifests (StatefulSets + headless Services + a root-key Secret + PVCs
+ startupProbes) applied cleanly, the mesh formed end-to-end across pods, and every pod came up
`Running 1/1` with **0 restarts** on a fresh concurrent deploy.

> Reminder: **CI does not run a cluster.** Validate these against your own cluster and
> Kubernetes version (`kubectl --dry-run=server`, `kubeconform`, or your admission pipeline)
> before relying on them. What is verified is **single instance per role**, not multi-replica.

### 3.1 Why StatefulSet + headless Service (not Deployment + ClusterIP)

Recap of §1, made concrete:

- **StatefulSet** gives each pod a **stable ordinal identity** and a **per-pod PVC** (via
  `volumeClaimTemplates`). The peer's ed25519 identity file lives on that PVC, so a reschedule
  reuses the *same* identity — the grant stays valid and the peer is the same participant.
- **Headless Service** (`clusterIP: None`) gives the pod a **stable, routable DNS name**. That
  name is what each peer publishes as its `*_ADVERTISE` and what other peers use as a seed. A
  normal `ClusterIP` would load-balance across pods — meaningless (and harmful) for a single
  identity.
- The **console** additionally gets a normal `Service` (`console`) because it is dialed by name
  (`http://console:8455`) by every agent for enroll/renew/crl — but it is **not a mesh peer**:
  do not seed it, do not put it on discovery.
- **room-view** and **signal-bridge** each get **two** Services: a headless one for the mesh
  port (so their `ADVERTISE` resolves) and a normal one for their HTTP surface (the chat UI on
  8487, the bridge mgmt/webhooks on 8484).

### 3.2 Discovery, advertise, and seeds (the rules that make it work)

These three rules are **verified** in both the Docker run and the MicroK8s deploy:

1. **`*_DISCOVER=false`.** UDP multicast does not cross pods or nodes, so multicast discovery is
   off in containers and Kubernetes. Peers find each other purely via gossip **seeds**. (Proven
   on the cluster: with multicast off, a seeded joiner discovered the room host and
   joined/posted across pods.)
2. **`*_SEEDS=http://room-agent:8482`** on every peer *except* the room-agent itself. The
   room-agent is the **seed target** — it bootstraps no one (it has no `*_SEEDS`, matching the
   verified compose file). Everyone else bootstraps off it.
3. **`*_ADVERTISE` MUST be the routable Service/pod DNS name** (e.g. `http://room-agent:8482`),
   **never `127.0.0.1`.** If a peer advertises loopback, other peers learn an address they can
   never dial — a silent failure (discovery "succeeds," every call times out).

### 3.3 The console root key — fail-closed, and its honest provenance

The console is the **root of trust**. Two settings protect it:

- **`CONSOLE_ROOT_KEY`** points at the root key file. Mount it from a `Secret`.
- **`CONSOLE_ROOT_KEY_REQUIRED=1`** makes the console **refuse to start** if that key is
  missing or unreadable, rather than silently generating a fresh one. A freshly generated key
  would be a **rogue authority no peer can verify**, and (on a reschedule without persistence,
  or a mismounted Secret) would **invalidate every existing grant in the mesh**. Fail closed.

**Honest provenance of the key (there is no keygen CLI).** The console *generates* the root key
on first run, when `CONSOLE_ROOT_KEY_REQUIRED` is **unset**. So the real bootstrap is:

1. **First run, REQUIRED off, no Secret mount.** Let the console generate
   `console-root.key` (a JSON blob `{"priv_b64":"..."}`) onto its `/data` PVC. (For a one-off
   bootstrap, temporarily set `CONSOLE_ROOT_KEY` to a `/data` path and `CONSOLE_ROOT_KEY_REQUIRED`
   to `"0"`.)
2. **Capture the generated key** and load it into a `Secret`:
   ```sh
   # Copy the generated key out of the running console pod:
   kubectl -n j3nna-mesh cp console-0:/data/console-root.key ./console-root.key

   # Create the Secret the production manifest mounts:
   kubectl -n j3nna-mesh create secret generic console-secrets \
     --from-file=console-root.key=./console-root.key \
     --from-literal=vault-passphrase='<a-strong-passphrase>' \
     --from-literal=operator-token='<a-strong-operator-token>'
   ```
3. **Redeploy with `CONSOLE_ROOT_KEY_REQUIRED=1`** and the key mounted from the Secret (the
   committed `console.yaml` assumes this state). Now a missing/mismounted key fails closed.

Treat the key like the crown jewels: it can sign any grant. Store the Secret with whatever
encryption-at-rest / external-secret mechanism your cluster uses.

### 3.4 startupProbe, not liveness, on the not-yet-enrolled path

Agents (room-agent, signal-bridge, room-view, joiner) **self-enroll and BLOCK until an operator
approves them.** That approval is a manual, out-of-band step that can take minutes. A
**liveness** probe on that path would fail before approval and **crash-loop the pod**, making
approval impossible.

The correct idiom — used in every agent manifest — is a **generous `startupProbe` that gates a
normal `livenessProbe`.** Kubernetes does not run the liveness probe until the startup probe
succeeds, so the pod survives the entire approval wait. Size the startup window with
`periodSeconds × failureThreshold`:

> `30s × 30 = ~15 minutes` of grace for enroll + manual approval. Tune both numbers to your
> operations (a faster operator → smaller window; an unattended overnight bring-up → larger).

There is also a complementary robustness fix in the agent runtime: **`agentkit.Enroll` retries
the initial console contact with backoff** instead of fatally exiting. So an agent that starts
*before* the console is reachable simply WAITS for it rather than CrashLoopBackOff-ing — startup
order is not fragile. (This is what produced the **0-restart** clean start on the concurrent
MicroK8s deploy.)

The console itself does **not** block on enrollment — it is an always-up HTTP server — so it
uses an ordinary startup/readiness/liveness trio on `/healthz`.

**Probe targets per component (verified against the code — note the off-by-one-port traps):**

| Component | Health surface | Probe |
|---|---|---|
| console | `/healthz` on **8455** (`CONSOLE_ADDR`) | `httpGet /healthz :8455` (startup + readiness + liveness; never blocks) |
| room-agent | **none** — only the mesh listener exists | `tcpSocket :8482` (startup + liveness) |
| signal-bridge | `/healthz` on the **mgmt port 8484** (`SIGNAL_HTTP`), **not** mesh 8483 | `httpGet /healthz :8484` (startup gates liveness) |
| room-view | `/healthz` on the **chat-UI port 8487** (`ROOMVIEW_HTTP`), **not** mesh 8485 | `httpGet /healthz :8487` (startup gates liveness) |
| joiner (demo) | **none** — only the mesh listener exists | `tcpSocket :8486` (startup + liveness) |

### 3.5 Apply order

Order matters: the console must exist before agents can enroll, and the room-agent (the seed
target) should be up before the peers that seed off it. (Thanks to the `agentkit.Enroll` retry,
a momentary out-of-order start self-heals — but this is still the clean order.)

```sh
# 1. Namespace.
kubectl apply -f deploy/k8s/namespace.yaml

# 2. Console. First create the root-key Secret per §3.3 (or do the first-run bootstrap), then:
kubectl apply -f deploy/k8s/console.yaml
kubectl -n j3nna-mesh rollout status statefulset/console

# 3. Room-agent (the seed target) — bring it up before the peers that seed off it.
kubectl apply -f deploy/k8s/room-agent.yaml

# 4. The peers that bootstrap off the room-agent.
kubectl apply -f deploy/k8s/signal-bridge.yaml
kubectl apply -f deploy/k8s/room-view.yaml
# (optional demo)
kubectl apply -f deploy/k8s/samples-joiner.yaml
```

Then **approve each enrollment** exactly as in §2, reaching the console by Service DNS instead
of localhost:

```sh
TOKEN='<your-operator-token>'   # the one you put in the console-secrets Secret
kubectl -n j3nna-mesh port-forward svc/console 8455:8455 &
CONSOLE='http://localhost:8455'
# match each id to the OOB code in the agent's log, e.g.:
#   kubectl -n j3nna-mesh logs statefulset/room-agent | grep out-of-band
# Then loop (prompts per id, since the OOB is out-of-band in each agent's log):
for id in $(curl -s -H "Authorization: Bearer $TOKEN" "$CONSOLE/enroll/pending" \
            | grep -o '"id":"[^"]*"' | cut -d'"' -f4); do
  read -rp "OOB code for $id (from its pod log): " oob
  curl -s -X POST -H "Authorization: Bearer $TOKEN" \
    "$CONSOLE/enroll/$id/approve" -d "{\"oob\":\"$oob\"}"
done
```

### 3.6 Exposing the human UI and managing webhooks (honest limits)

- **room-view chat UI (8487) is unauthenticated.** Reach it in-cluster via the `room-view-ui`
  Service. Before exposing it beyond the cluster, front it with an **Ingress that adds
  authentication and TLS**.
- **signal-bridge webhook management (`/webhooks` CRUD) is loopback-gated in code** — it
  returns `401` over a Service. Over the `signal-bridge-mgmt` Service (8484) you get `/healthz`
  and the HMAC-gated inbound `/hook/<id>` endpoint. To register/list/revoke subscriptions, run
  the call from **inside the pod** (loopback), e.g. `kubectl exec`/port-forward to localhost.
- **Console management** (users, grants, vault, enrollment approval) **does** work remotely via
  bearer token — that is the intended remote-admin surface.

---

## 4. Scaling & multi-instance (out of scope for this release)

This release targets **one instance per role** — and that is what is verified (single console,
single room-agent, single signal-bridge, single room-view; all `replicas: 1`).

**Multi-instance horizontal scaling is not supported in this release.** This is deliberate, not an
oversight: a mesh peer is a **pinned cryptographic identity**, so scaling is not a trivial
`replicas: 3` — cloning one identity behind a `ClusterIP` would round-robin into divergent backends
and return inconsistent results. The supported way to add capacity is to run **distinct peers**, each
with its own persisted identity and its own grant (for example, sharding rooms across multiple
room-agents). A single console is the active writer for the authority state (root key, CRL, users,
enrollment).

---

## 5. Honesty summary

- **Both the Docker / Compose path and the Kubernetes manifests are verified end-to-end** — the
  Compose path across containers, and the k8s manifests **on MicroK8s v1.35.3** (full
  enroll → approve → seed-discover → join → post across pods, 0-restart clean start). **CI runs
  no cluster**, so schema-validate and smoke-test on your own cluster/version. Only
  **single-instance-per-role** is verified, not multi-replica.
- Every env var, port, and health surface in this guide and in the manifests was **verified
  against the component source** (`console/`, `room-agent/`, `signal-bridge/`, `room-view/`,
  `samples/joiner/`) and against the verified `deploy/docker/compose.yaml`.
- **Multi-instance horizontal scaling is out of scope for this release** (see §4). The docs
  intentionally stop at single-instance-per-role, which is what is verified.
- The placeholder image refs (`ghcr.io/j3nnaai/mesh-*`) are **not published images** — build
  and push your own from `deploy/docker/Dockerfile`; the manifests document the build command.

See also: [SECURITY.md](SECURITY.md) · [OPERATIONS.md](OPERATIONS.md) ·
[CONFIGURATION.md](CONFIGURATION.md) · [INSTALL.md](INSTALL.md).
