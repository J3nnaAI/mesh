# samples — reference agents

> Minimal, runnable examples of the authorized-collaboration loop on the mesh.

These samples show how to build a real mesh participant with
[`agentkit`](../agentkit). They are deliberately small and readable — start
here when learning the mesh.

## joiner

The `joiner` is a minimal agent that walks the full authorized loop:

```
enroll with the console   ->  receive a signed grant + the authority root
open the mesh authorized   ->  multicast discovery, presenting our grant
find a 'rooms' peer        ->  the room agent, discovered (not hardcoded)
join its room + post       ->  collaborate, all authorized
```

It teaches the core pattern: enrollment is the single ingress, discovery is by
advertised capability (never a hardcoded address), and every peer verifies the
others offline against the authority root.

### Run it

Start a [`console`](../console) and a [`room-agent`](../room-agent) first, then:

```
go run github.com/J3nnaAI/mesh/samples/joiner
```

When the joiner prints its out-of-band code, approve the enrollment in the
console (matching that code). It then discovers the room agent, joins its room,
posts a message, and prints the room history. Unauthorized peers are invisible to
each other — nothing tries to talk to a peer without a valid grant.

### Environment

| Var | Purpose | Default |
| --- | --- | --- |
| `SAMPLE_CONSOLE` | console URL | `http://127.0.0.1:8455` |
| `SAMPLE_NAME` | display / client name | `sample-joiner` |
| `SAMPLE_IDENTITY` | persisted ed25519 identity file | `sample.id` |
| `SAMPLE_LISTEN` | mesh HTTP listen address | `0.0.0.0:8486` |
| `SAMPLE_ADVERTISE` | externally reachable base URL | `http://127.0.0.1:8486` |
| `SAMPLE_ROOM` | room id to join | `lobby` |

## showcase

Where `joiner` shows the minimal loop, **`showcase`** shows a peer *using* the mesh: it discovers the
services of the [examples/showcase](../examples/showcase/) demo by capability and **invokes their tools
directly** (cross-language), including watching a restricted tool get denied. Run the showcase first
(`examples/showcase/run-local.sh` with `INTERACTIVE=1`, or its `docker compose`), then:

```
python3 samples/python/showcase.py        # a Python peer calling the Go services
node     samples/typescript/showcase.mjs  # a Node peer calling the Go services
```

Both print the same thing from another language: discover `inventory` + `quote`, call `inventory.check`
and `quote.price`, and see `inventory.reserve` correctly refused (it's restricted to the dispatch service).
The full, multi-service, human-in-the-loop system those services form is the
[showcase example](../examples/showcase/); to build your own peer, see
[docs/BUILD-AN-AGENT.md](../docs/BUILD-AN-AGENT.md).

## Layout

Samples live here, one folder per language (`samples/<lang>/`); the SDK **libraries** they import live in
[`sdks/<lang>/`](../sdks/). Keep the two separate.

---

Part of the [J3nna Mesh](../README.md). Apache-2.0.
