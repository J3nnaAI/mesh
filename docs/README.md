# J3nna Mesh — Documentation

**J3nna Mesh** is a decentralized agent-mesh **infrastructure**: a wire protocol,
a control-plane console (the authority / root of trust), a peer SDK, an optional
memory engine, and ready-to-run agents (a room host and a signal/webhook bridge),
plus samples. It is the toolkit for *"build your own authorized agent mesh."*
Peers discover and verify each other **offline**; the authority originates trust
but is never on the hot path. Everything is Go, standard-library-leaning, and
Apache-2.0 licensed.

This folder is the documentation set. Start with the reader guide below, then use
the table of contents.

> **Status note.** This index is the map of the full documentation set. Entries
> marked *(planned)* are companion docs that are being written; their links are
> the intended paths. The docs without that marker are present now.

---

## Where do I start?

- **New user — "I just want to see it work."**
  Read the project overview ([../README.md](../README.md)), then walk the
  authorized loop in [QUICKSTART.md](QUICKSTART.md): run the console, run a
  room-agent, approve it, run the sample joiner, watch it discover/join/post.
  Skim the [GLOSSARY.md](GLOSSARY.md) when a term is unfamiliar.

- **Operator — "I'm going to run a mesh."**
  [INSTALL.md](INSTALL.md) → [CONFIGURATION.md](CONFIGURATION.md) for every
  component's env vars → [OPERATIONS.md](OPERATIONS.md) for running, enrolling,
  approving, and revoking → [DEPLOYMENT.md](DEPLOYMENT.md) for Docker/Kubernetes and the
  scaling model → [SECURITY.md](SECURITY.md) for the trust model and the
  honest residual risks → [AUDIT-LOGGING.md](AUDIT-LOGGING.md).

- **Contributor — "I want to change the code."**
  [CONTRIBUTING.md](../CONTRIBUTING.md) (dev setup, code style, the hygiene gate, PR
  expectations) → [ARCHITECTURE.md](ARCHITECTURE.md) for how the pieces fit →
  [VERSIONING.md](VERSIONING.md) before touching any wire bytes or public API.

- **Integrator — "I'm building an agent / calling the mesh."**
  [ARCHITECTURE.md](ARCHITECTURE.md) and [GLOSSARY.md](GLOSSARY.md) for the model
  → the [`agentkit`](../agentkit/) SDK and the [`samples/joiner`](../samples/)
  reference agent → [API.md](API.md) for the console and agent HTTP surfaces →
  [SECURITY.md](SECURITY.md) for enrollment, grants, and CallProof.

---

## Documentation index

### Getting started

| Doc | What it covers |
| --- | --- |
| [Project overview](../README.md) | What the mesh is, the components, and the quickstart story at a glance. |
| [QUICKSTART.md](QUICKSTART.md) | The full authorized loop end-to-end: console → room-agent → approve → sample joiner → join + post. |
| [INSTALL.md](INSTALL.md) | Prerequisites (Go 1.26.3+ (latest stable)), building the components, producing the binaries. |
| [CONFIGURATION.md](CONFIGURATION.md) | Every component's environment variables (addresses, identity files, vault keys, console/authority wiring). |

### Concepts

| Doc | What it covers |
| --- | --- |
| [ARCHITECTURE.md](ARCHITECTURE.md) | The layering: protocol, SDK, authority, agents, optional memory; root-not-hub; offline verification. |
| [GLOSSARY.md](GLOSSARY.md) | Every term, defined and cross-referenced — agent, grant, presence, gossip, CallProof, protocol major, and the rest. |

### Operating

| Doc | What it covers |
| --- | --- |
| [OPERATIONS.md](OPERATIONS.md) | Running a mesh day-to-day: enrollment approval, grant lifecycle, revocation, maintenance. |
| [DEPLOYMENT.md](DEPLOYMENT.md) | Deploying beyond one workstation: the verified Docker/Compose path, the Kubernetes manifests, and the honest scaling model (peers are identities, not workers). |
| [SECURITY.md](SECURITY.md) | The trust model in depth: authorized discovery, grants/CRL, CallProof, the vault boundary, and the honest residual risks. |
| [AUDIT-LOGGING.md](AUDIT-LOGGING.md) | What is logged, where, and how to audit enrollment/grant/revocation activity. |
| [API.md](API.md) | The HTTP surfaces: console management API, room-agent, and signal-bridge endpoints. |

### Project

| Doc | What it covers |
| --- | --- |
| [VERSIONING.md](VERSIONING.md) | Semver, enforced two ways: wire-protocol major at the admit gate, and path-prefixed Go-module tags. Compatibility promise, deprecation, how a release is cut. |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | Dev setup, code style, permissive-deps rule, the no-personal-identifiers hygiene gate, the publish tooling, PR expectations, license/sign-off. |

---

## Modules

Each module is an independent Go module under `github.com/J3nnaAI/mesh/<module>`.
A per-module README documents each one in depth.

| Module | README | Role |
| --- | --- | --- |
| **jip** | [`../jip/README.md`](../jip/README.md) | The mesh wire protocol: identity, signed presence, multicast discovery + gossip, MCP tools, rooms, grants/CRL, CallProof. |
| **agentkit** | [`../agentkit/README.md`](../agentkit/README.md) | The peer SDK: `Open(Options) → Mesh`, enrollment, peer/room calls, CRL refresh. |
| **kernel** | [`../kernel/README.md`](../kernel/README.md) | Optional embeddable memory / knowledge-graph engine. The core mesh does not depend on it. |
| **vault** | [`../vault/README.md`](../vault/README.md) | Reusable encrypted secret store (pluggable cipher; export-grade DES-56 default, AES-256-GCM via WithCipher), `0600` at rest. |
| **console** | [`../console/README.md`](../console/README.md) | The authority / control plane: enrollment, grant issuance, signed CRL. Root of trust, off the hot path. |
| **room-agent** | [`../room-agent/README.md`](../room-agent/README.md) | Decentralized room-host agent (a peer that hosts rooms, not a central server). |
| **signal-bridge** | [`../signal-bridge/README.md`](../signal-bridge/README.md) | Events + outbound/inbound webhooks (HMAC-signed) bridging the mesh to outside systems. |
| **room-view** | [`../room-view/README.md`](../room-view/README.md) | Human chat front door: an authorized peer that joins a room and serves a web chat UI so a person reads/posts alongside agents (hosts nothing). |
| **samples** | [`../samples/README.md`](../samples/README.md) | Reference agent: enroll → discover → join a room → post → read. |

---

J3nna Mesh is licensed under **Apache-2.0**.
