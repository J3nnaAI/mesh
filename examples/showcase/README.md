# showcase — the all-in-one J3nna Mesh demo

> A human and a handful of cooperating services in one room — exercising **every** core capability of the
> mesh, deterministically, with **no AI at all**. This is the canonical "what is the mesh, and how is it
> meant to be used" example.

You sit in a chat room (served by **room-view**) and type **1** or **2**. Behind the glass, a set of
independent services **discover each other**, **call each other's tools directly**, share an **inventory**
through a common memory, **sign** a shipment with a private key, and hand it off to an **external** system
over a signed webhook — and every step is narrated back into your room so you watch it happen.

```
            ┌──────────┐  enroll/approve/grant/revoke (off the hot path)
            │ console  │  ── root of trust ──
            └────┬─────┘
        ┌────────┴───────── the mesh (peers discover + call each other) ──────────┐
        │                                                                          │
   ┌────▼────┐   inventory.check    ┌──────────┐   inventory.reserve (RESTRICTED) ┌▼──────────┐
   │ quote   │ ───────────────────▶ │inventory │ ◀─────────────────────────────── │ dispatch  │
   │  -svc   │                      │  -svc    │  (shared KERNEL = the inventory)  │   -svc    │
   └────▲────┘                      └──────────┘                                   └────┬──────┘
        │  quote.price                                                signs manifest    │  signal.publish
        │                                                            from its own VAULT │
   ┌────┴─────┐  hosts the room, routes 1/2          ┌──────────────┐   HMAC webhook   ┌▼──────────────┐
   │   desk   │ ◀───────── you type 1/2 ──────────── │  room-view   │   ───────────▶   │ signal-bridge │ ─▶ carrier (external)
   └──────────┘                                       │   (human)    │                  └───────────────┘
```

## What it demonstrates

| Mesh capability | Where you see it |
|---|---|
| Enrollment + a single authority | `console` issues every grant; nothing joins unapproved |
| **Discovery (multicast + gossip)** | every service finds the others by *capability*, never a hardcoded address |
| Authorized, offline verification | unauthorized peers are invisible; grants are checked without calling home |
| **Peer tool discovery + invocation** | `quote-svc`→`inventory.check`, `dispatch-svc`→`inventory.reserve`, `desk`→both services |
| **Restricted tools + CallProof** | `inventory.reserve` is allow-listed; only `dispatch-svc`, with a signed proof, may draw down stock |
| **Shared kernel** (cooperative memory) | `inventory-svc` hosts one inventory graph that several agents read and atomically mutate |
| **vault**, used three canonical ways | `console` (grants), `signal-bridge` (webhook HMAC), and `dispatch-svc` signing its **own** manifest |
| **signal-bridge** events + webhooks | a shipment becomes an HMAC-signed outbound webhook to an external `carrier` |
| Rooms + a **human in the loop** | `room-view` puts you in the same room as the agents, over the identical protocol |

Everything is a deterministic Go service — there is **no model, no inference, no AI**. The "agents" are
services; the cooperation is the point.

## The cast

| Service | Capability | Teaches |
|---|---|---|
| `inventory-svc` | `inventory` | embedding the **kernel** as shared state; an **atomic, restricted** tool |
| `quote-svc` | `quote` | **discovering** a peer and **invoking** its tool to do its job |
| `dispatch-svc` | `dispatch` | a **restricted** peer call + signing with its **own vault** + raising a **signal** |
| `desk` | `rooms` | **hosting a room** and reacting to humans with `AddRoomResponder` |
| `carrier` | — (external) | the mesh's **edge**: an HMAC-signed webhook to a system that knows nothing about JIP |
| `registrar`, `operator` | — | dev glue for the container path (register the webhook; auto-approve enrollments) |

## Run it

### Locally (one command)

```sh
./run-local.sh
```

Builds everything, starts the console + signal-bridge + every service + room-view on loopback, then drives
the two choices and asserts the whole flow. Add `INTERACTIVE=1 ./run-local.sh` to leave it running and play
yourself at <http://127.0.0.1:8487>.

### As containers

```sh
docker compose -f docker-compose.yml up --build
# then open the chat UI and type 1 or 2:
open http://localhost:8487
```

One of each role, gossip-seed discovery (no multicast), persisted identities, an auto-approver, and the
webhook registrar — a self-contained stack.

### On Kubernetes (microk8s)

```sh
kubectl apply -k k8s/        # namespace, console, signal-bridge, services, room-view
kubectl -n j3nna-showcase port-forward svc/room-view 8487:8487
open http://localhost:8487
```

See [k8s/README.md](k8s/README.md) for the manifests and the deployment model (one StatefulSet per role —
a peer is a pinned identity, not a stateless replica).

## The two choices

```
1) quote → dispatch :  price first (quote.price, which checks inventory), then ship that price
2) dispatch → quote :  reserve + ship first (dispatch.ship), then price the shipment
```

Either way the *other* service consumes the leader's data, and both end in a reserved, priced, **signed**,
carrier-notified delivery. Customise the order inline, e.g. `1 GADGET 2`.

## Make it your own

Add a fourth service in a few lines — see **[../../docs/BUILD-AN-AGENT.md](../../docs/BUILD-AN-AGENT.md)** for
a step-by-step guide to writing your own service (or AI agent) that joins this mesh, exposes a tool, and is
discovered and called by the others.

---

Part of the [J3nna Mesh](../../README.md). Apache-2.0.
