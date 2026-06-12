# Contributing to J3nna Mesh

Thanks for your interest in the mesh. It's a small, deliberately simple codebase:
a decentralized agent-mesh **infrastructure** — a wire protocol, a control-plane
console, a peer SDK, an optional memory engine, and a couple of ready-to-run
agents. Contributions that keep it small, clear, and dependency-light are very
welcome.

This guide covers dev setup, code style, the hygiene gate every change must pass,
the release/export tooling, and what we expect on a PR.

---

## Development setup

You need **Go 1.26.4 (latest stable) or newer**. That's it — no other toolchain.

The repo is a **multi-module monorepo** tied together by a `go.work` workspace, so
the modules resolve against each other locally without published tags:

```
go.work        # the workspace — wires the modules together for local dev
jip/           # the mesh protocol
agentkit/      # the peer SDK
kernel/        # optional memory/knowledge-graph engine
vault/         # encrypted secret store
console/       # the authority / control plane
room-agent/    # decentralized room-host agent
signal-bridge/ # events + outbound/inbound webhooks
samples/joiner # reference "enroll → join a room → post" agent
scripts/       # release + hygiene tooling
docs/          # this documentation set
```

Clone and confirm the workspace builds:

```sh
git clone https://github.com/J3nnaAI/mesh.git
cd mesh
go build ./...        # builds every module in the workspace
```

### Building and testing a single module

Each module is independent and built/tested on its own:

```sh
cd jip
go build ./...
go test ./...
```

Run `go test ./...` in **every module you touched** before opening a PR (and in
`jip` if you changed anything the others depend on). The protocol library has the
broadest blast radius — a change there can affect every consumer.

Run the components with their environment variables; see
[CONFIGURATION.md](docs/CONFIGURATION.md) and each module's README for the full set.
The fastest end-to-end check is the authorized loop in
[QUICKSTART.md](docs/QUICKSTART.md): run the console, run a `room-agent` against it,
approve its enrollment, then run `samples/joiner` and watch it discover the room,
join, and post.

---

## Code style

The project's whole appeal is that it's auditable and portable. Keep it that way.

- **Stdlib-leaning.** The protocol, the WebSocket handshake, the crypto, the
  multicast discovery, the HTTP surfaces — all on the Go standard library. New
  code should reach for the stdlib first. Adding a dependency is a notable
  decision, not a default.
- **Wire code must be language-neutral.** Anything that gets signed or sent on the
  wire uses the project's explicit length-prefixed, domain-separated framing — not
  `json.Marshal` of a Go struct for the *signed bytes*. A node written in another
  language must be able to reproduce the bytes. If you touch a canonical-bytes
  function, you are touching the protocol; read [VERSIONING.md](docs/VERSIONING.md)
  first (it's very likely a MAJOR bump).
- **`gofmt` / `go vet` clean.** Run both. Formatting is not up for debate.
- **Small, single-purpose functions; comments explain *why*.** Match the
  surrounding style — the existing code documents intent and trade-offs inline;
  follow that.
- **Fail closed.** Security decisions (admit, authorize a restricted tool, verify
  a grant/CRL/proof) default to *deny* on any error or ambiguity. Never add a
  path that admits or authorizes on a soft failure.

### Dependency licensing — permissive only

Every dependency, across the whole import graph, **must be permissively
licensed**: MIT, BSD (2- or 3-clause), Apache-2.0, or ISC. **Copyleft licenses —
GPL, LGPL, AGPL, and the like — are not acceptable** and a PR that introduces one
(directly or transitively) will be rejected. When proposing a new dependency,
state its license in the PR. The strong default remains: don't add one.

---

## The hygiene gate (required for every change)

The mesh is public infrastructure. **No personal, organizational, or
deployment-specific identifiers may appear in shippable source** — not in code,
not in comments, not in docs. Identities and names belong in *configuration and
data at runtime* (a console mints them, an operator enters them), never baked into
the infrastructure. Use the generic roles instead: **operator, user, agent,
peer.**

This is enforced by a script that every change must pass:

```sh
./scripts/check-no-personal-identifiers.sh           # scans the repo
./scripts/check-no-personal-identifiers.sh jip vault # or specific paths
```

It greps `*.go`, `*.md`, and `*.sh` (excluding `_test.go`) for a deny-list of
personal/identity names and **exits non-zero** if it finds any, printing each hit
with its file and line so you can fix it. A non-zero exit blocks the release.

Run it locally before you push — it's the same gate the release tooling runs, so
catching a hit early saves a round-trip. If you're adding an example that needs a
name, use a generic role or an obviously-fictional placeholder.

---

## Release / export tooling

You generally won't cut releases as a contributor, but it helps to understand how
the public tree is produced so your changes land correctly.

[`scripts/publish.sh`](scripts/publish.sh) produces the clean, public Mesh
export from the working tree. At a high level it:

1. **Curates** the Mesh modules into an output directory (the source tree is never
   modified — everything happens in the export dir).
2. **Excludes private material** that must never ship (internal design/strategy
   docs, non-public SDK surface), while keeping tests.
3. **Rewrites internal import paths** to the public
   `github.com/J3nnaAI/mesh/<module>` names.
4. **Lays down a `go.work`** so the export builds out of the box.
5. **Runs the hygiene gates** over the whole export — the no-personal-identifiers
   scan (`check-no-personal-identifiers.sh`) **and** an Apache license-header check
   (every shipped `*.go` must carry the header); a single failure aborts the publish.
6. **Build- and test-verifies** every module in the renamed export, then runs
   **`govulncheck`** — a vulnerability or a build/test failure aborts the publish.
7. **Stamps the legal files** — copies `LICENSE` (Apache-2.0) and `NOTICE`
   (attribution + trademark notice) into the export root.

Practical implication for contributors: write against the **public** module paths
and the generic roles, keep tests passing, and keep the source identifier-clean —
then the export builds and ships without manual cleanup.

Versioning, tags, and how a release is actually cut are documented in
[VERSIONING.md](docs/VERSIONING.md).

---

## Commit and PR expectations

- **One logical change per PR.** Easier to review, easier to revert.
- **Clear commit messages.** A concise subject line in the imperative mood
  ("jip: reject zero protocol major at admit gate"), then a body explaining the
  *why* if it isn't obvious. Reference an issue if there is one.
- **Tests with behavior changes.** Add or update tests for what you changed.
  Bug fixes should come with a test that fails without the fix.
- **Before you open the PR, confirm:**
  - `go build ./...` and `go test ./...` pass in every module you touched.
  - `gofmt` and `go vet` are clean.
  - `./scripts/check-no-personal-identifiers.sh` passes.
  - Every new source file carries the Apache-2.0 license header (the copyright +
    boilerplate block); the publish gate rejects any `*.go` that doesn't.
  - You didn't add a non-permissive dependency.
  - If you touched canonical wire bytes or an admit/authorize path, you read
    [VERSIONING.md](docs/VERSIONING.md) and noted the likely version impact in the PR.
- **Describe the change** in the PR: what, why, and any compatibility impact
  (wire and/or API).

---

## License and sign-off

J3nna Mesh is licensed under **Apache-2.0**. By contributing, you agree that your
contributions are submitted under the **same Apache-2.0 license** and that you
have the right to submit them.

We keep this lightweight: add a `Signed-off-by` line to your commits (a
[Developer Certificate of Origin](https://developercertificate.org/) sign-off) to
certify you wrote the change or otherwise have the right to contribute it under
Apache-2.0. Git does it for you:

```sh
git commit -s -m "module: short summary of the change"
```

No separate CLA is required.

---

Welcome aboard. If you're unsure whether a change is a good fit, open an issue and
ask before investing a lot of time — we'd rather talk early than turn away good
work late.

See also: [docs/README.md](docs/README.md) (docs index) · [VERSIONING.md](docs/VERSIONING.md) ·
[GLOSSARY.md](docs/GLOSSARY.md) · [SECURITY.md](docs/SECURITY.md)
