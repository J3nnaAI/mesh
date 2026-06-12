# kernel — embeddable living-memory engine

`kernel` is the part you reach for when your agents need to **remember things** — not just a
pile of text, but structured, connected knowledge they can ask questions of. It's a small,
self-contained engine you embed directly in your program: you give it facts, and it gives you
back the relevant ones when you ask, including the ones that are *related* to what you asked,
not only an exact match.

It stores knowledge as a graph — facts, and the relationships between them — and when you
search, it starts from what you said and follows those relationships outward. Turn that
"follow outward" knob down and you get precise recall; turn it up and you get associations,
themes, and creative leaps. Same engine, one dial.

**You'd reach for `kernel`** when an agent needs durable, queryable memory that stays neatly
separated per user or persona. It runs anywhere — server, browser, or on-device — because it
leans on nothing but the standard library.

One thing worth saying plainly: `kernel` is **optional**. It's the mesh's memory substrate, but
the core mesh ([`jip`](../jip), [`agentkit`](../agentkit)) does **not** depend on it. You can
run the mesh without `kernel`, and you can use `kernel` on its own without the mesh — they fit
together but neither needs the other.

The rest of this README is the technical detail: the data model, the API, and a worked example.

---

> A typed, bi-temporal knowledge graph with spreading-activation retrieval at tunable defocus.

Knowledge is stored as typed nodes and edges; retrieval seeds activation from an embedding
(or literal match) and spreads it across the graph, so the same engine does exact
recall, associative recall, thematic generalization, and creative/analogical
bridging — they differ only in how far activation is allowed to spread.

It is **stdlib-only and WASM-safe**, so the same code runs server-side, in the
browser, or on-device. Storage sits behind an interface (default: in-memory with
JSON snapshotting).

## Install

```
go get github.com/J3nnaAI/mesh/kernel
```

```go
import "github.com/J3nnaAI/mesh/kernel"
```

## Model in brief

- **Nodes** are typed units of knowledge: `entity`, `proposition`, `episode`,
  `concept`, `goal`, `state`, plus a reasoning-workspace set (`claim`, `step`,
  `hypothesis`, `question`, `evidence`, `plan`). Episodes are stored verbatim.
- **Edges** are typed, weighted, scoped relations (`is_a`, `part_of`, `causes`,
  `contradicts`, `analogous_to`, `relational`, … plus reasoning relations like
  `justifies`, `supports`, `refutes`). Edge weight is the conductance activation
  spreads across.
- **Scope** (`global` / `user` / `persona` / `domain`) rides on every node and
  edge for relevance isolation. `global` is visible to all queries.
- **Bi-temporal validity** — every fact records when it was true in the world and
  when the system learned it. Knowledge never decays and is never hard-deleted;
  facts are retired with a provenanced `Tombstone`, and the graveyard stays
  queryable.
- **Embeddings** are supplied by the host via the `Embedder` interface (the engine
  ships no model). They seed activation; the graph propagates it.

## Key public API

| Symbol | Purpose |
| --- | --- |
| `Open(Options) *Engine` | Construct the engine (default in-memory store). |
| `Engine.AddNode(Node) (Node, error)` / `AddEdge(Edge) (Edge, error)` | Write knowledge. |
| `Engine.IngestEpisode(text, scope, vec) (Node, error)` | Store a turn/message verbatim. |
| `Engine.Retrieve(ctx, Query) (Result, error)` | Spreading-activation recall. |
| `Engine.Tombstone(id, Tombstone) error` | Retire a fact (provenanced, queryable). |
| `Engine.Snapshot() ([]byte, error)` / `Load([]byte) error` | Persist / restore. |
| `Mode` (`verbatim` / `relevant` / `thematic` / `creative`) | Cognition profile per query. |
| `Embedder`, `Store`, `Options` | Host-supplied embedding, pluggable storage, config. |

`Query` selects a `Mode`, a `Scope`, a text and/or vector cue, a `Defocus` knob,
a result count `K`, and an optional validity instant `At`.

## Usage

```go
eng := kernel.Open(kernel.Options{}) // in-memory store, default decay

eng.AddNode(kernel.Node{
    Kind:  kernel.KindProposition,
    Label: "water boiling point",
    Body:  "Water boils at 100C at sea level.",
    Scope: kernel.GlobalScope,
})

res, err := eng.Retrieve(context.Background(), kernel.Query{
    Mode: kernel.ModeRelevant,
    Text: "how hot does water get?",
    K:    5,
})
if err != nil {
    log.Fatal(err)
}
for _, hit := range res.Hits {
    fmt.Printf("%.2f  %s — %s\n", hit.Score, hit.Node.Label, hit.Why)
}
```

To enable semantic seeding, pass an `Embedder` in `Options`; without one,
retrieval falls back to literal matching plus graph spread.

---

Part of the [J3nna Mesh](../README.md). Apache-2.0.
