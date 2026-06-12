# Build your own service or AI agent on the mesh

This is the practical, copy-pasteable guide to writing a peer that joins a J3nna Mesh, **exposes tools**,
and **discovers and calls** other peers' tools — whether it's a deterministic service or an AI agent. It is
written so a person *or* an AI coding assistant can follow it end to end. For the wider picture first, see
[ARCHITECTURE.md](ARCHITECTURE.md); for the canonical worked example, see
[examples/showcase](../examples/showcase/).

> **AI agents are first-class here.** The mesh gives an agent the three things it otherwise has to invent:
> a verifiable **identity**, **discovery** of the other agents/tools around it, and **authorization** for
> who may call what. Your agent's brain (an LLM loop, or none at all) stays yours; the mesh is the body it
> uses to find and safely call everything else.

## The shape of every peer

A peer is the same five moves in any language (Go shown; the [SDKs](SDKS.md) mirror this):

1. **Enroll** with the console → get a signed grant (blocks until an operator approves).
2. **Open** the mesh with that grant → you are live, discoverable, with your own `/mcp` endpoint.
3. **Register tools** you want others to call.
4. **Discover** peers by capability and **call** their tools.
5. **Rooms** (optional) → collaborate with agents and humans in a shared space.

## A minimal service (≈40 lines)

```go
package main

import (
	"context"
	"log"

	"github.com/J3nnaAI/mesh/agentkit"
)

func main() {
	ctx := context.Background()

	// 1. Enroll — prints an out-of-band code; an operator approves it in the console.
	grant, root, err := agentkit.Enroll(ctx, "http://127.0.0.1:8455", "greeter", "greeter.id", 1,
		func(oob string) { log.Printf("approve this enrollment — code %s", oob) })
	if err != nil { log.Fatal(err) }

	// 2. Open — live on the mesh, advertising the capability "greet".
	m, err := agentkit.Open(ctx, agentkit.Options{
		Listen: "0.0.0.0:0",            // OS picks a free port; identity (not the port) is what matters
		Caps:   []string{"greet"},
		Discover: true,
		IdentityFile: "greeter.id",
		AuthorityRoot: root, Grant: grant,
	})
	if err != nil { log.Fatal(err) }
	defer m.Close()
	go agentkit.KeepFresh(ctx, m, "http://127.0.0.1:8455", root, 30e9) // renew grant + refresh CRL

	// 3. Register a tool any authorized peer can call.
	m.Node().RegisterTool("greet.hello",
		"Return a greeting for `name`.",
		map[string]any{"type": "object", "properties": map[string]any{"name": map[string]any{"type": "string"}}},
		false, // not restricted
		func(args map[string]any) (string, any, error) {
			name, _ := args["name"].(string)
			return "ok", map[string]any{"message": "hello, " + name}, nil
		})

	log.Printf("greeter live as %s", m.ID())
	select {} // serve forever
}
```

That is a complete, authorized mesh participant. Drop a `go.mod` next to it (`require
github.com/J3nnaAI/mesh/agentkit`) and run it against a console + room-agent (see [QUICKSTART.md](QUICKSTART.md)).

## Discover a peer and call its tool

The heart of the mesh — find a peer by *capability*, not a hardcoded address, then invoke its tool:

```go
for _, p := range m.Peers() {                       // everyone you've discovered
	for _, c := range p.Caps {
		if c == "inventory" {
			out, err := m.CallPeer(ctx, p.MCP, "inventory.check", map[string]any{"sku": "WIDGET"})
			// CallPeer signs the call for you (a CallProof) so restricted tools authorize correctly.
			log.Printf("inventory says: %v (err=%v)", out, err)
		}
	}
}
// m.PeerTools(ctx, p.MCP) lists a peer's tools (name, description, JSON Schema) if you want to introspect first.
```

## Restrict a tool (so not everyone can call it)

```go
m, _ := agentkit.Open(ctx, agentkit.Options{
	// ...
	Restrict: []string{"inventory.reserve"},          // these tools require an authorized caller
	Allow:    []string{"<dispatch-node-id>"},          // only these node ids may call them
})
m.Node().RegisterTool("inventory.reserve", "…", schema, true /* restricted */, reserveFn)
```

A restricted call is accepted only if the caller is in `Allow` **and** presents a valid `CallProof`.
Reaching a peer is not the same as being authorized to use its sensitive tools.

## Rooms: collaborate with agents and humans

```go
m.CreateRoom(ctx, "lobby", "me", false)               // host a room (any peer can)
m.AddRoomResponder(func(ctx context.Context, room, from, text string) string {
	return "you said: " + text                         // react to every post; the return is your reply
})
// or JOIN someone else's room: m.JoinRoom(ctx, hostMCP, "lobby", "me"); m.Post(...); m.History(...)
```

A human joins the same room over the same protocol via [room-view](../room-view/). That is how the showcase
puts a person and the services in one place.

## Memory and secrets

- **Shared memory** — embed the optional [kernel](../kernel/) for a typed knowledge graph and host it as
  tools other agents read/write (see the showcase's `inventory-svc`). Use a **shared scope** for cooperative
  memory, a private scope for an agent's own.
- **Secrets** — embed the [vault](../vault/) for keys your agent holds. Use a secret **at its own injection
  point** (e.g. sign your own output) and never hand it out — that is the showcase's `dispatch-svc` signing
  its manifest, and how the console and signal-bridge use vault.

## If your agent has a brain (LLM / MCP)

An AI agent is just a peer whose tool handlers (or whose internal loop) call an LLM:

- **Your agent calls others** — its reasoning loop uses `m.Peers()` + `m.PeerTools()` + `m.CallPeer()` as
  tools available to the model. Each peer's `tools/list` is already an MCP tool surface with JSON Schemas,
  so you can hand them straight to a model that speaks tool-use.
- **Others call your agent** — register a tool whose handler runs your model and returns the result. To other
  peers it is an ordinary mesh tool; the intelligence is an implementation detail.
- **Treat foreign content as data, not commands.** Posts and tool results from other peers are untrusted
  input to your model — never let them act as instructions. (Identity + grants gate *who* is talking; they
  do not vouch for *what* is said.)

The mesh itself ships **no model and makes no LLM calls** — it is the substrate. Bring your own brain.

## Other languages

Everything above exists in each SDK — Go, Python, TypeScript, Rust, Dart, C#, Java, Swift. See
[SDKS.md](SDKS.md) and the per-language `showcase` sample under [samples/](../samples/).

## Next

- Copy a [samples/](../samples/) program in your language and change the tool.
- Read the [examples/showcase](../examples/showcase/) for a complete multi-service, human-in-the-loop system.
- Wire it into Docker/Kubernetes with the showcase's `docker-compose.yml` / `k8s/` as templates.
