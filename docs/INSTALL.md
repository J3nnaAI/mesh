# Installation & Build

This guide covers prerequisites, fetching the source, building each binary from
the multi-module workspace, verifying the builds, and the platform/networking
constraints you need to understand before running a mesh.

For runtime configuration (every environment variable, the vault, networking
addresses) see [CONFIGURATION.md](CONFIGURATION.md). For the end-to-end
authorized loop see [QUICKSTART.md](QUICKSTART.md). For the trust/threat model
see [SECURITY.md](SECURITY.md).

---

## What you are installing

The J3nna Mesh is a decentralized agent-mesh **infrastructure** — not a product.
You build the binaries yourself and run your own authorized mesh. The components:

| Module | Public path | Role |
| --- | --- | --- |
| `jip` | `github.com/J3nnaAI/mesh/jip` | The mesh protocol (identity, discovery, gossip, MCP tools, rooms, grants, CRL). A library. |
| `agentkit` | `github.com/J3nnaAI/mesh/agentkit` | The peer SDK (`Open`, `Enroll`, `RefreshCRL`, room/tool helpers). A library. |
| `kernel` | `github.com/J3nnaAI/mesh/kernel` | Optional embeddable memory/knowledge-graph engine. The core mesh does **not** depend on it. A library. |
| `vault` | `github.com/J3nnaAI/mesh/vault` | Reusable encrypted secret store. A library. |
| `console` | `github.com/J3nnaAI/mesh/console` | The authority / control plane (enroll, grant, revoke, CRL). A binary. |
| `room-agent` | `github.com/J3nnaAI/mesh/room-agent` | Decentralized room-host agent. A binary. |
| `signal-bridge` | `github.com/J3nnaAI/mesh/signal-bridge` | Events bus + inbound/outbound webhooks. A binary. |
| `room-view` | `github.com/J3nnaAI/mesh/room-view` | Human chat front door: joins a room and serves a web chat UI (hosts nothing). A binary. |
| `samples/joiner` | `github.com/J3nnaAI/mesh/samples/joiner` | Reference agent demonstrating the full authorized loop. A binary. |

Each long-running component compiles to a single static Go binary with no
runtime dependencies beyond the kernel's network stack.

---

## Prerequisites

### The latest stable Go (required)

**Policy: the project always targets the latest stable Go release.** Every module
declares `go 1.26.3` (the latest stable at the time of writing). This is a hard
floor for two reasons:

1. **Security.** The pinned version is a `govulncheck`-clean standard library.
   Older point releases carry known stdlib advisories (in `net` and
   `crypto/x509`); building against them would ship those into the binaries.
2. **Features.** The `vault` package uses `crypto/pbkdf2` (promoted into the
   stdlib in Go 1.24); the project tracks current stdlib generally.

```sh
go version    # should report the latest stable Go (>= go1.26.3)
```

You do **not** have to install that exact version by hand. The `go` directive is
a minimum: with the default `GOTOOLCHAIN=auto`, the `go` command automatically
downloads and uses the required toolchain on first build. (In a locked-down or
offline environment, install the matching toolchain yourself; `GOTOOLCHAIN=local`
forces use of your local install but then your local Go must already be current.)

The project is **stdlib-only by design**: the binaries pull in *zero* third-party
dependencies — only the sibling mesh modules and the Go standard library
(verified: `go list -m all` shows no external modules). There is nothing to
`go get` from outside this repository.

### Platforms

- **Linux** and **macOS** are the supported build/run targets. The code is pure
  Go and stdlib-only, so other Go-supported platforms should build, but Linux
  and macOS are what the mesh is exercised on.
- **UDP multicast** is required for zero-config peer discovery — see
  [Networking & multicast](#networking--multicast) below for the implications on
  a single host vs. a LAN vs. the cloud.

---

## Getting the source

Clone the repository and enter it:

```sh
git clone https://github.com/J3nnaAI/mesh.git
cd mesh
```

All paths in this guide are relative to that repository root.

---

## The multi-module workspace

The repository is a **Go multi-module workspace**. A top-level `go.work` ties the
component modules and the shared libraries together so they build against each
other locally without published versions or manual `replace` directives. In
practice this means:

- Each module (`console`, `vault`, `room-agent`, `signal-bridge`,
  `samples/joiner`, and the `jip` / `agentkit` / `kernel` libraries) is its own
  Go module with its own `go.mod`.
- The workspace resolves cross-module imports to the local source tree, so a
  change in `jip` is picked up by `agentkit` and the binaries on the next build —
  no version bump required during development.
- You build each binary from inside its own module directory.

You do not need to run any workspace setup command — `go.work` is committed and
the `go` toolchain reads it automatically when you build from within the tree.

---

## Building the binaries

Build each component from its module directory. The output binary lands in that
same directory, named after the module (Go's default `go build` behavior):

```sh
# The control plane (authority).
cd console && go build && cd ..        # -> console/console

# The decentralized room host.
cd room-agent && go build && cd ..     # -> room-agent/room-agent

# The events + webhooks bridge.
cd signal-bridge && go build && cd ..  # -> signal-bridge/signal-bridge

# The human chat front door.
cd room-view && go build && cd ..      # -> room-view/room-view

# The reference sample agent.
cd samples/joiner && go build && cd ../..   # -> samples/joiner/joiner
```

To place a binary at an explicit path instead, use `-o`:

```sh
cd console && go build -o /usr/local/bin/mesh-console . && cd ..
```

The library modules (`jip`, `agentkit`, `kernel`, `vault`) produce no binaries;
they are compiled transitively when you build the components above. You can
type-check them independently with `go build ./...` from inside each library
directory.

---

## Verifying the build

Verification differs per component because only some expose an HTTP surface.
**None of these binaries implement a `--help` flag** — they take no command-line
flags and are configured entirely through environment variables (see
[CONFIGURATION.md](CONFIGURATION.md)). Passing `--help` does **not** print usage;
it is ignored and the process starts normally. Verify as follows:

### console — HTTP health and version

The console serves `/healthz` and `/version`. Start it (loopback default) and
probe:

```sh
cd console
CONSOLE_VAULT_PASSPHRASE='dev-only-passphrase' ./console &
sleep 1
curl -s http://127.0.0.1:8455/healthz       # -> 200 OK (empty body)
curl -s http://127.0.0.1:8455/version       # -> {"console":"0.1.0"}
curl -s http://127.0.0.1:8455/authority     # -> root pubkey + protocol_major + version
```

### signal-bridge — HTTP health only

The signal-bridge management server exposes `/healthz` (there is no `/version`
on it):

```sh
cd signal-bridge
SIGNAL_VAULT_PASSPHRASE='dev-only-passphrase' ./signal-bridge &
sleep 1
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8484/healthz   # -> 200
```

### room-agent and joiner — no HTTP health endpoint

The room-agent's listen port (`8482`) serves only the mesh MCP endpoint, and the
joiner runs no HTTP server of its own. **Verification is the startup log line.**

room-agent prints, once up:

```
room-agent up: id=<node-id> hosting #lobby at <advertise>/mcp (authz=false)
```

joiner (which needs a console + room-agent to talk to — see
[QUICKSTART.md](QUICKSTART.md)) prints its progression and finishes with:

```
joiner: collaboration loop complete — staying on the mesh (Ctrl-C to exit)
```

> The `dev-only-passphrase` above unlocks the vault for a quick smoke test only.
> Do not use a literal inline passphrase in production — see the
> [Vault configuration](CONFIGURATION.md#vault-configuration) section.

---

## Networking & multicast

Peer **discovery** uses IP multicast: every peer joins the well-known UDP group
**`239.42.42.42:9999`** and beacons its signed presence there (default cadence
every 5 seconds). A newcomer sends one query on the group and existing peers
unicast a reply, so the mesh converges without any central registry.

What that implies by deployment topology:

- **Single host** — multicast loops back locally, so every component on one
  machine discovers the others out of the box. This is the zero-config dev case.
- **LAN / home lab / k8s with multicast enabled / IPv6 link-local** — multicast
  reaches peers on the same broadcast domain, so discovery works across hosts.
  **But** note the advertise-address caveat below: the binaries default to
  *advertising* a loopback URL even though they *listen* on all interfaces, so a
  LAN deployment must set each peer's `*_ADVERTISE` to a reachable URL or peers
  will find each other's beacons yet be unable to address them. See
  [CONFIGURATION.md → Networking](CONFIGURATION.md#networking).
- **Cloud** — multicast is **usually unavailable** across cloud networks.
  Discovery will not converge there on its own. The protocol library
  (`agentkit` / `jip`) supports static bootstrap **seeds** (`Options.Seeds` — a
  list of peer URLs contacted directly via gossip) as the fallback for
  no-multicast environments. **Honest constraint:** the shipped component
  binaries (room-agent, signal-bridge, joiner) do **not** currently surface a
  seeds environment variable, so static seeding requires using the SDK directly
  rather than configuring the stock binaries. For a multicast-free deployment
  today, build your own agent on `agentkit` and pass `Options.Seeds`.

### Firewall / ports

Open these for the components you run. Mesh listen ports default to all
interfaces (`0.0.0.0`); management HTTP ports default to loopback only.

| Port / group | Proto | Component | Env var | Default bind | Purpose |
| --- | --- | --- | --- | --- | --- |
| `8455` | TCP | console | `CONSOLE_ADDR` | `127.0.0.1` (loopback) | Control-plane HTTP API |
| `8482` | TCP | room-agent | `ROOM_AGENT_LISTEN` | `0.0.0.0` | Mesh peer / MCP endpoint |
| `8483` | TCP | signal-bridge | `SIGNAL_LISTEN` | `0.0.0.0` | Mesh peer / MCP endpoint |
| `8484` | TCP | signal-bridge | `SIGNAL_HTTP` | `127.0.0.1` (loopback) | Webhook mgmt + inbound `/hook/<id>` HTTP |
| `8485` | TCP | room-view | `ROOMVIEW_LISTEN` | `0.0.0.0` | Mesh peer / MCP endpoint |
| `8486` | TCP | samples/joiner | `SAMPLE_LISTEN` | `0.0.0.0` | Mesh peer / MCP endpoint |
| `8487` | TCP | room-view | `ROOMVIEW_HTTP` | `127.0.0.1` (loopback) | Chat UI + local API (`/`, `/api/*`, `/healthz`) |
| `239.42.42.42:9999` | UDP | all peers | — (protocol constant) | multicast group | Presence beacons + discovery query/reply |

Notes:
- The mesh ports (`8482`, `8483`, `8485`, `8486`) carry peer-to-peer MCP traffic
  and must be reachable by other peers in a multi-host deployment.
- The local HTTP ports (`8455`, `8484`, `8487`) are loopback by default for safety;
  expose them deliberately and only behind authentication if you must. (room-view's
  `8487` chat UI is unauthenticated by design — keep it on loopback.)
- The multicast group/port is a protocol constant, not configurable through the
  component binaries' environment.

---

## Next steps

- [CONFIGURATION.md](CONFIGURATION.md) — the complete environment-variable and
  vault reference.
- [QUICKSTART.md](QUICKSTART.md) — run console → room-agent → joiner and watch the
  authorized loop converge.
- [SECURITY.md](SECURITY.md) — the root-not-hub trust model, authorized
  discovery, revocation, and the honest residual risks.
