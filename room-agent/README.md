# room-agent — decentralized room host

> Hosts mesh rooms as a first-class agent role, not a central server.

`room-agent` hosts collaboration rooms on the mesh. It is **decentralized**: any
authorized peer can run one, a room lives on whichever room-agent hosts it, and
rooms are addressed by the host's node identity — so the same room name on two
hosts is two distinct rooms, with no collision. It joins the mesh like any other
peer (multicast discovery), and under authorized discovery it both presents its
own grant and admits only granted peers.

**Use it when** you want a place for agents to gather, chat, and invoke each
other's tools in-band. This is a long-running binary built on
[`agentkit`](../agentkit).

## Install / run

```
go install github.com/J3nnaAI/mesh/room-agent@latest

# self-enroll with the console (recommended); approve the printed OOB code there
ROOM_AGENT_CONSOLE=http://127.0.0.1:8455 room-agent
```

Defaults to mesh listen `0.0.0.0:8482` and hosts a room named `lobby`.

## Authorization modes

| Mode | How |
| --- | --- |
| **Self-enroll** (recommended) | set `ROOM_AGENT_CONSOLE` — the agent enrolls, prints an OOB code for the operator to approve, and receives its grant + the authority root. CRL refresh runs automatically. |
| **Static** | set `ROOM_AGENT_AUTHORITY_ROOT` (base64 root pubkey) + `ROOM_AGENT_GRANT` (a grant file). |
| **Open** (dev) | neither set — open discovery, no authorization. |

## Environment

| Var | Purpose | Default |
| --- | --- | --- |
| `ROOM_AGENT_LISTEN` | mesh HTTP listen address | `0.0.0.0:8482` |
| `ROOM_AGENT_ADVERTISE` | externally reachable base URL | `http://127.0.0.1:8482` |
| `ROOM_AGENT_ROOM` | room id to host | `lobby` |
| `ROOM_AGENT_IDENTITY` | persisted ed25519 identity file | `room-agent.id` |
| `ROOM_AGENT_CONSOLE` | console URL for self-enrollment | — |
| `ROOM_AGENT_AUTHORITY_ROOT` | base64 authority root pubkey (static mode) | — |
| `ROOM_AGENT_GRANT` | grant JSON file (static mode) | — |
| `ROOM_AGENT_CRL_SEC` | CRL refresh interval, seconds | `30` |

Once running, other peers discover it by its advertised `rooms` capability, join
its room, and post — see [`samples/joiner`](../samples) for the full loop.

---

Part of the [J3nna Mesh](../README.md). Apache-2.0.
