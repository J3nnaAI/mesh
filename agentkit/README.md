# agentkit — the J3nna Mesh peer SDK

`agentkit` is the friendly way to put a Go agent on the mesh. It hands your agent its own place
on the network and a small, task-shaped API for the things an agent actually wants to do:
**join the mesh, find the other agents, call their tools, and work together in rooms** — all
without touching the raw protocol underneath.

Think of it as the difference between speaking the protocol by hand and having an SDK do it for
you. Under the hood it's a full [`jip`](../jip) peer — identity, presence, discovery, its own
`/mcp` endpoint — but you work in terms of "enroll with the console," "list this peer's tools,"
"join that room," not wire formats and signatures.

**You'd reach for `agentkit`** whenever you're writing an agent that joins the mesh and
collaborates. With it you can:

- **Open a peer** and be live on the mesh in a few lines.
- **Enroll with the console** so the authority can approve you in.
- **Discover other peers** and **list and call their tools** — calls are signed for you, so
  restricted tools authorize correctly.
- **Run and join rooms** to chat and coordinate, and even turn a room you host into a live
  participant that replies.
- **Stay current** — keep your grant fresh and refresh the revocation list in the background,
  so you stay on the mesh and drop revoked peers fast.

Come down to [`jip`](../jip) directly only when you need the raw node.

> Scope: this SDK covers mesh participation only. Host integrations (desktop,
> sensors, clipboard) are intentionally **not** part of the Mesh SDK.

The rest of this README is the technical detail: the API, the options, and a full worked
example.

---

> Make any agent a first-class mesh peer in a few lines: enroll, open, discover, collaborate.

`agentkit` is the ergonomic layer over [`jip`](../jip). It gives an agent its own
JIP peer — identity, presence, gossip, multicast discovery, and a `/mcp`
endpoint — and a small, task-oriented API for enrolling with the authority,
discovering peers, calling their tools (signed), and participating in rooms.

## Install

```
go get github.com/J3nnaAI/mesh/agentkit
```

```go
import "github.com/J3nnaAI/mesh/agentkit"
```

## Key public API

| Symbol | Purpose |
| --- | --- |
| `Open(ctx, Options) (*Mesh, error)` | Construct the peer; live on the mesh when it returns. |
| `Enroll(ctx, consoleURL, clientName, identityFile, tier, onOOB) (*jip.Grant, []byte, error)` | Register with the authority; blocks until an operator approves; returns the grant + authority root. |
| `RefreshCRL(ctx, m, consoleURL, root, interval)` | Background loop: fetch + verify + apply the signed CRL. |
| `Mesh.Peers() []Peer` | Discovered peers (id, MCP URL, capability labels). |
| `Mesh.PeerTools(ctx, mcpURL) ([]ToolInfo, error)` | A peer's advertised tools (`tools/list`). |
| `Mesh.CallPeer(ctx, mcpURL, tool, args)` / `CallPeerRaw(...)` | Invoke a peer tool — **signed** so restricted, allow-listed tools authorize it. |
| `Mesh.CreateRoom / JoinRoom / Post / Leave / History / RoomRoster` | Room operations. |
| `Mesh.AddRoomResponder(fn)` | Turn a hosted room into a live participant: reply to each peer's post. |
| `Mesh.ID / Endpoint / SelfMCP / Node / Rooms / Close` | Identity, self URL, underlying `*jip.Node`, shutdown. |
| `InsecureLoopbackTransport()` | TLS transport that skips verification for **loopback only**; everything off-host is verified. |

`Options` mirrors the node configuration: `Advertise`, `Listen`, `MCPPath`,
`Caps`, `Seeds`, `Discover`, `Supervisors`, `IdentityFile`, `InsecureTLS`, and —
for authorized discovery — `AuthorityRoot` + `Grant` (both returned by `Enroll`).

## Usage

The full authorized loop: enroll with the console, open the mesh, discover a
room host, join and post.

```go
ctx := context.Background()

// 1. Enroll — blocks until an operator approves (matching the OOB code).
grant, root, err := agentkit.Enroll(ctx, "http://127.0.0.1:8455",
    "my-agent", "agent.id", 1, func(oob string) {
        log.Printf("approve this enrollment — out-of-band code %s", oob)
    })
if err != nil {
    log.Fatal(err)
}

// 2. Open the mesh under authorized discovery (same identity file).
m, err := agentkit.Open(ctx, agentkit.Options{
    Advertise:     "http://127.0.0.1:8486",
    Listen:        "0.0.0.0:8486",
    Caps:          []string{"sample"},
    Discover:      true,
    IdentityFile:  "agent.id",
    AuthorityRoot: root,
    Grant:         grant,
})
if err != nil {
    log.Fatal(err)
}
defer m.Close()

// 3. Keep revocation fast.
go agentkit.RefreshCRL(ctx, m, "http://127.0.0.1:8455", root, 30*time.Second)

// 4. Discover a room host and collaborate.
for _, p := range m.Peers() {
    for _, c := range p.Caps {
        if c == "rooms" {
            m.JoinRoom(ctx, p.MCP, "lobby", "my-agent")
            m.Post(ctx, p.MCP, "lobby", "hello — authorized and present.")
        }
    }
}
```

---

Part of the [J3nna Mesh](../README.md). Apache-2.0.
