# Versioning

J3nna Mesh versions two distinct things, and enforces both:

1. **The wire protocol** — the bytes peers exchange (presence, grants, the CRL,
   call proofs). Compatibility here is enforced *at runtime, fail-closed*: a peer
   refuses to engage another peer across an incompatible protocol **major**, the
   same way it refuses an unauthorized peer.
2. **The Go modules** — the multi-module monorepo that ships the protocol library,
   the SDK, and the agents. Compatibility here is the standard Go-module
   contract, enforced by the compiler and the module system through
   **path-prefixed semver tags**.

Both follow [Semantic Versioning 2.0.0](https://semver.org): `MAJOR.MINOR.PATCH`.

- **MAJOR** — a breaking change. Existing consumers / peers may stop working.
- **MINOR** — a backward-compatible addition. Existing consumers keep working.
- **PATCH** — a backward-compatible fix. No surface change.

---

## 1. Wire-protocol versioning (enforced at the admit gate)

The mesh has no central broker on the hot path: peers verify each other
**offline**. That makes wire compatibility a hard, peer-to-peer contract — there
is no server to paper over a mismatch. The protocol layer (`jip`) therefore
carries a single integer the whole mesh agrees on:

```go
// jip
const ProtocolMajor = 1   // the wire-protocol major version

func CompatibleMajor(peer int) bool { return peer == ProtocolMajor }
```

Every node stamps `ProtocolMajor` into its **signed presence record**, so the
value is covered by the owner's signature and cannot be forged or downgraded in
transit. When authorized discovery is on, the admit gate verifies a peer's grant
*and* requires `CompatibleMajor(peer)` to be true. A peer advertising a
different (or zero/unknown) major is **not admitted** — it stays invisible,
exactly as an unauthorized peer does. This is deliberate: protocol-version
mismatch is treated as an authorization-class failure, fail-closed, not a
best-effort downgrade.

> Note the layering. `ProtocolMajor` is the integer used for the *compatibility
> decision*. There is also a human-readable `ProtocolVersion` string (e.g.
> `"JIP/0.1"`) carried in presence and surfaced in MCP `serverInfo` for
> diagnostics and negotiation hints — but the **enforced gate keys on the integer
> major**, not the string.

### What is a breaking wire change → MAJOR bump

Bump `ProtocolMajor` (and the module majors that ship it) when an old peer can no
longer correctly interoperate with a new one. Concretely:

- Changing the **canonical signing bytes** of any signed object (presence
  payload, `Grant`, `SignedCRL`, `CallProof`) — field order, framing,
  length-prefixing, or the domain-separator string. These encodings are
  byte-for-byte agreements between signer and verifier; any change makes old
  signatures fail to verify against new code.
- Removing or repurposing a field that the verifier depends on.
- Changing the meaning of an existing field, a tier, or a scope.
- Changing the discovery/admit contract (e.g. requiring a new field in presence
  to be admitted).
- Changing the JSON-RPC method names or the tool-call authorization contract.

### What is an additive wire change → MINOR bump

Keep `ProtocolMajor` the same when an old peer keeps working unchanged:

- Adding a **new optional field** to a wire struct that is *not* part of the
  canonical signing bytes, or that is appended in a way both majors compute
  identically. (The presence payload already does this — see how
  `protocol_major` and the optional `grant` were folded into the canonical bytes
  without breaking the older framing.)
- Adding a new MCP tool, a new capability label, or a new optional RPC method
  that older peers simply don't call.
- Adding a new endpoint to the console or an agent's management API.

When in doubt, ask: *would a peer running the previous release still verify and
interoperate?* Yes → minor. No → major.

### Revocation and TTL are availability, not compatibility

Grants are short-lived (`GrantTTL = 5 * time.Minute`) and revocation rides a
signed CRL that peers fetch and verify offline, evicting revoked peers on the
next refresh. These are **operational** controls (see
[SECURITY.md](SECURITY.md)), independent of the protocol major. Tuning the TTL
*down* in a deployment is not a protocol change.

---

## 2. Go-module versioning (multi-module monorepo)

The repository is a **multi-module monorepo** stitched together for local
development by a `go.work` workspace:

```
go.work        # workspace: developer convenience, NOT published
jip/           # module github.com/J3nnaAI/mesh/jip        — the protocol
agentkit/      # module github.com/J3nnaAI/mesh/agentkit   — the peer SDK
kernel/        # module github.com/J3nnaAI/mesh/kernel     — optional memory engine
vault/         # module github.com/J3nnaAI/mesh/vault      — encrypted secret store
console/       # module github.com/J3nnaAI/mesh/console    — the authority/control plane
room-agent/    # module github.com/J3nnaAI/mesh/room-agent — room-host agent
signal-bridge/ # module github.com/J3nnaAI/mesh/signal-bridge — events + webhooks
samples/joiner # module github.com/J3nnaAI/mesh/samples/joiner — reference agent
```

Each directory is an **independent Go module** with its own `go.mod` and its own
version line. There is no single repo-wide version; `jip` can be at `v1.4.0`
while `agentkit` is at `v0.9.2` and `vault` at `v1.0.0`.

### Path-prefixed semver tags

Because several modules live in one repository, Go requires each module's release
tag to be **prefixed with the module's directory path** (the
[major-subdirectory / submodule tagging](https://go.dev/ref/mod#vcs-version)
convention). The tag format is:

```
<module-dir>/v<MAJOR>.<MINOR>.<PATCH>
```

Examples:

```
jip/v1.2.0
agentkit/v0.3.1
vault/v1.0.0
console/v0.5.0
room-agent/v0.4.2
signal-bridge/v0.4.0
kernel/v0.7.0
samples/joiner/v0.2.0
```

A bare `v1.2.0` tag (no path prefix) does **not** publish any module in this
repo. Always tag with the directory prefix.

### The v2+ module-path rule

Go's import-compatibility rule: a module at **major version 2 or higher must
encode the major in its module path**. So when `jip` makes a breaking change and
goes to v2, its `go.mod` module line becomes:

```go
module github.com/J3nnaAI/mesh/jip/v2
```

and consumers import `github.com/J3nnaAI/mesh/jip/v2`. The release tag is then
`jip/v2.0.0`. v0 and v1 share the unsuffixed path; v2+ each get their own. This
lets a major bump ship without breaking anyone still on the previous major —
both can coexist in the same build.

> **v0 caveat.** Modules below v1 (e.g. `agentkit v0.x`) carry **no stability
> guarantee** under semver — a v0 minor bump may break. We still try not to
> break v0 consumers gratuitously, and we call out breaking v0 changes in the
> release notes, but v0 is explicitly pre-stable. Pin a v0 dependency to an exact
> version.

---

## Compatibility promise to consumers

- **Within a stable major (v1+):** code that imports a module and builds will
  keep building and behaving across all later **minor** and **patch** releases of
  that major. We do not remove or change exported API within a major.
- **Wire:** two peers on the **same `ProtocolMajor`** interoperate, regardless of
  their minor/patch releases. A new minor may add optional fields/tools that an
  older peer ignores.
- **Across a major:** no promise. A major release may break the API and/or the
  wire; that is what the major bump *means*. For the wire, peers on different
  majors will simply refuse each other rather than misbehave.
- **The `go.work` file is not part of the published artifact.** It is a developer
  convenience and is stripped from the public export. Consumers depend on tagged
  module versions, not on the workspace.

---

## Deprecation policy

We prefer additive evolution over removal. When something must go away:

1. **Mark it deprecated, don't delete it.** Exported Go identifiers get a
   `// Deprecated:` doc comment naming the replacement; `go vet` and editors then
   warn consumers. The symbol keeps working for the remainder of its current
   major.
2. **Announce it** in the release notes / CHANGELOG, with the replacement and a
   migration note.
3. **Remove only at the next major bump** of that module. A deprecated-then-
   removed symbol never disappears within a major.
4. **Wire fields** follow the same rule: a field can be *deprecated* (ignored,
   documented) within a major and only *removed from the canonical signing bytes*
   at a protocol-major bump, because removing it from the signed bytes is itself a
   breaking wire change.

---

## How a release is cut

Releases are per-module. The public Mesh tree is produced by
[`scripts/publish.sh`](../scripts/publish.sh) (see [CONTRIBUTING.md](../CONTRIBUTING.md)),
which curates the modules, rewrites internal import paths to the public
`github.com/J3nnaAI/mesh/<module>` names, lays down a workspace, runs the hygiene
gate, and build-verifies the result. To cut a release of a module:

1. **Decide the bump.** Review the changes since the last tag for that module
   against the rules above (API surface for the Go side; canonical signing bytes /
   admit contract for the wire side). Pick MAJOR / MINOR / PATCH.
2. **If it's a Go major to v2+,** update the module's `go.mod` path to add the
   `/vN` suffix and update intra-repo imports accordingly.
3. **If it's a wire major,** bump `ProtocolMajor` in `jip` and ship the dependent
   module majors together — the wire and the library that carries it move as one.
4. **Update the CHANGELOG / release notes** for the module, including any
   deprecations and migration notes.
5. **Verify:** `go build ./...` and `go test ./...` green in the module; the
   hygiene gate clean (`scripts/check-no-personal-identifiers.sh`); a `publish.sh`
   dry run builds the export.
6. **Tag** with the path-prefixed semver tag, e.g.:

   ```sh
   git tag jip/v1.3.0
   git push origin jip/v1.3.0
   ```

7. **Publish** the export and announce the release.

Tag only what verified clean. A path-prefixed tag is the public, immutable
contract for that module version — treat it as final once pushed.

---

See also: [CONTRIBUTING.md](../CONTRIBUTING.md) ·
[SECURITY.md](SECURITY.md) · [GLOSSARY.md](GLOSSARY.md)
