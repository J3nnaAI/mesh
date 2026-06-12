# CLAUDE.md

Guidance for Claude Code working in this repository.

**Read [AGENTS.md](AGENTS.md) first** — it is the canonical orientation for AI assistants (what J3nna Mesh is,
the repo map, how to build/run/test, how to help a user get started and build their own service or AI agent,
and the conventions to respect). Everything below is supplementary.

## Fast facts

- **What it is:** an open-source decentralized, governed peer-to-peer mesh for AI agents and services —
  identity, discovery, peer tool-calling, rooms, and trust you issue and revoke. The mesh ships **no model**;
  agents bring their own brain.
- **See it run:** `./examples/showcase/run-local.sh` (loopback, asserts the flow) or
  `docker compose -f examples/showcase/docker-compose.yml up --build` → `http://localhost:8487`.
- **Build an agent:** follow [docs/BUILD-AN-AGENT.md](docs/BUILD-AN-AGENT.md); start from a `samples/<lang>/`
  program; use the `agentkit` SDK, not raw `jip`.

## Working here

- Go multi-module **workspace** (`go.work`). Build monorepo modules with the workspace; build
  `samples/`/`examples/` modules with `GOWORK=off` (they use `replace` directives). Go 1.26+ via
  `GOTOOLCHAIN=auto`.
- **Hard invariants:** `jip/` is pure stdlib (no third-party imports); every Go file carries the Apache-2.0
  header; **no AI/LLM calls in the mesh core or the examples**; samples live in `samples/<lang>/`, SDK
  libraries in `sdks/<lang>/`. Keep `go vet` clean; never commit binaries, `*.id`, or `*.enc`.
- When changing the protocol (`jip/`), keep it language-reproducible (canonical byte encodings; no
  dependency on JSON field order) and update `docs/PROTOCOL.md` + the conformance vectors.

## Verify, don't assert

When you claim something works, run it — `./examples/showcase/run-local.sh` for end-to-end, `go test` per
module, `go vet`. Prefer showing the real output to asserting success.
