#!/usr/bin/env bash
# publish.sh — produce a clean, public Mesh export of the mesh from the private monorepo.
#
# It curates the Mesh modules, EXCLUDES private material (kernel design docs; agentkit desktop/sensor
# surface; tests are kept), rewrites module paths web-stt-tts/* -> J3nnaAI/mesh/*, lays down a workspace,
# runs the no-personal-identifiers guard, and build-verifies the result. The private monorepo is never
# modified — everything happens in the export dir.
#
#   ./publish.sh [OUT_DIR]            export + verify only (default OUT_DIR: /tmp/mesh-oss)
#   PUBLISH=1 ./publish.sh            ALSO commit (+optional tag) the verified export to the public
#                                     repo and push it — see the PUBLISH_* block at the end of this file.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"   # web-stt-tts/
MESH="$ROOT/j3nna-mesh"
OUT="${1:-/tmp/mesh-oss}"

echo "publish: exporting Mesh -> $OUT"
rm -rf "$OUT"; mkdir -p "$OUT"

# --- copy supporting libs from the monorepo root (renamed under mesh/) ---
copy() {
  # exclude per-language BUILD artifacts but never source dirs (Dart's source lives in bin/, so that one is
  # anchored to the C# project specifically).
  rsync -a --exclude '*_test.go.orig' \
    --exclude 'target/' --exclude '.build/' --exclude '.dart_tool/' --exclude 'node_modules/' \
    --exclude '*.class' --exclude 'gson.jar' \
    --exclude '/conformance/csharp/bin/' --exclude '/conformance/csharp/obj/' \
    --exclude 'Cargo.lock' --exclude 'pubspec.lock' --exclude 'Package.resolved' \
    "$1/" "$2/"
}
copy "$MESH/jip"      "$OUT/jip"
copy "$MESH/agentkit" "$OUT/agentkit"
copy "$MESH/kernel"   "$OUT/kernel"

# --- copy the Mesh modules (already github.com/J3nnaAI/mesh/*) ---
for m in vault console room-agent room-view signal-bridge samples monitor sdks scripts docs deploy examples; do
  # exclude per-language SDK build artifacts (Dart keeps source in bare bin/, so only the .NET bin/Debug|Release)
  # + the example's python caches and in-place Go service binaries.
  [ -e "$MESH/$m" ] && rsync -a \
    --exclude 'target/' --exclude '.build/' --exclude '.dart_tool/' --exclude 'node_modules/' \
    --exclude 'bin/Debug/' --exclude 'bin/Release/' --exclude 'obj/' --exclude '*.class' --exclude 'gson.jar' \
    --exclude 'Cargo.lock' --exclude 'pubspec.lock' --exclude 'Package.resolved' --exclude '*.id' \
    --exclude '__pycache__/' --exclude '*.pyc' \
    --exclude 'kernel-service/kernel-service' --exclude 'vault-service/vault-service' \
    "$MESH/$m/" "$OUT/$m/"
done

# --- The order-fulfillment example's Docker chain assumes the MONOREPO layout (the example is 3 levels deep
# and the modules live under j3nna-mesh/). The export is FLAT (example 2 deep, modules at the root), so
# recalibrate it: compose context ../../.. -> ../.. and drop the j3nna-mesh/ prefix everywhere, then write
# flat allowlist .dockerignores. This makes `docker compose up` work in the published repo. ---
EX="$OUT/examples/order-fulfillment"
if [ -d "$EX" ]; then
  sed -i 's#context: \.\./\.\./\.\.#context: ../..#g; s#dockerfile: j3nna-mesh/#dockerfile: #g' "$EX/docker-compose.yml"
  sed -i 's#j3nna-mesh/##g' "$EX/Dockerfile.go" "$EX/Dockerfile.py"
  cat > "$EX/Dockerfile.go.dockerignore" <<'IGN'
# Allowlist for the flat published layout (context = repo root): ignore all, re-include only what the Go build needs.
*
!jip
jip/conformance
!agentkit
!kernel
!vault
!console
!room-agent
!monitor
!examples
examples/*
!examples/order-fulfillment
examples/order-fulfillment/*
!examples/order-fulfillment/kernel-service
!examples/order-fulfillment/vault-service
!examples/order-fulfillment/inventory.jsonl
**/.git
**/*.id
examples/order-fulfillment/kernel-service/kernel-service
examples/order-fulfillment/vault-service/vault-service
IGN
  cat > "$EX/Dockerfile.py.dockerignore" <<'IGN'
# Allowlist for the flat published layout (context = repo root): the python SDK + the agents.
*
!sdks
sdks/*
!sdks/python
!examples
examples/*
!examples/order-fulfillment
examples/order-fulfillment/*
!examples/order-fulfillment/agents
!examples/order-fulfillment/inventory.jsonl
**/.git
**/__pycache__
**/*.pyc
IGN
fi

# --- root docs land at the export root (README + CONTRIBUTING + WHY — their relative links resolve from
# there; CONTRIBUTING/SECURITY at root are also where GitHub looks for the community-health files).
# AGENTS.md / CLAUDE.md / llms.txt are the AI-assistant front doors and travel too. ---
for f in README.md CONTRIBUTING.md WHY.md VISION.md AGENTS.md CLAUDE.md llms.txt; do
  [ -f "$MESH/$f" ] && cp "$MESH/$f" "$OUT/$f"
done
# Cursor rules (the AI-assistant guidance Cursor reads) ship as a directory.
[ -d "$MESH/.cursor" ] && rsync -a "$MESH/.cursor/" "$OUT/.cursor/"

# --- .github (CodeQL + Dependabot) + community-health files are PUBLIC-MANAGED: on an EXISTING public
#     repo Dependabot/CodeQL own them and we must not clobber their PRs. But a FRESH repo (after a delete
#     + recreate) has none, so we stage them here and SEED-IF-ABSENT in the push step (rsync
#     --ignore-existing) — preserving the public versions when present, seeding them when not. Keep the
#     monorepo copies current (pull the latest from the public repo) before a re-publish. ---
[ -d "$MESH/.github" ] && rsync -a "$MESH/.github/" "$OUT/.github/"
for f in CODE_OF_CONDUCT.md LICENSE; do [ -f "$MESH/$f" ] && cp "$MESH/$f" "$OUT/$f"; done

# --- EXCLUSIONS: private material that must never ship ---
# kernel private design/strategy docs (lore, authority chain, licensing figures)
rm -f "$OUT"/kernel/{CHARTER,DESIGN,PROGRESS,COMPETITIVE-LANGCHAIN,INTEGRATION,LOCK}.md
# agentkit private surface (desktop/sensor/clipboard bridges are not part of the Mesh SDK)
rm -f "$OUT"/agentkit/{desktop,sensor,clipboard}.go "$OUT"/agentkit/{desktop,sensor,clipboard}_test.go
# any stray local go.work / build artifacts / runtime state
find "$OUT" -name 'go.work' -delete -o -name 'go.work.sum' -delete 2>/dev/null || true
find "$OUT" -type f \( -name '*.enc' -o -name '*-root.key' -o -name '*crl.json' -o -name '*.id' -o -name 'console' -o -name 'room-agent' -o -name 'signal-bridge' -o -name 'joiner' \) -delete 2>/dev/null || true
# the diagram build tooling + any scratch are INTERNAL-ONLY — never ship them to the public repo
rm -rf "$OUT/docs/assets/_src" "$OUT/docs/assets/_review"

# --- rewrite module paths: web-stt-tts/{jip,agentkit,kernel} -> J3nnaAI/mesh/{...} ---
# The source modules are now ALREADY github.com/J3nnaAI/mesh/* in-tree, so this loop is a no-op safety net
# for any stale web-stt-tts refs. The grep must NOT abort the pipeline (set -euo pipefail) when nothing
# matches, or the LICENSE/identifier-gate/build-verify/govulncheck steps below never run. Hence `|| true`.
for mod in jip agentkit kernel; do
  grep -rIl "github.com/web-stt-tts/$mod" "$OUT" 2>/dev/null \
    | xargs -r sed -i "s#github.com/web-stt-tts/$mod#github.com/J3nnaAI/mesh/$mod#g" || true
done

# --- workspace so the export builds out of the box ---
{
  # The go directive targets the latest stable Go (a govulncheck-clean stdlib); it alone forces the build
  # toolchain to >= this version (GOTOOLCHAIN=auto downloads it), so no separate toolchain line is needed.
  echo "go 1.26.4"
  echo
  for d in jip agentkit kernel vault console room-agent room-view signal-bridge samples/joiner monitor; do
    [ -f "$OUT/$d/go.mod" ] && echo "use ./$d"
  done
} > "$OUT/go.work"

# --- LICENSE + NOTICE: Apache-2.0 license text and the attribution/trademark notice (sourced verbatim) ---
if [ -f "$ROOT/LICENSE-APACHE-2.0.txt" ]; then
  cp "$ROOT/LICENSE-APACHE-2.0.txt" "$OUT/LICENSE"
else
  echo "publish: WARNING — Apache-2.0 LICENSE text not found at $ROOT/LICENSE-APACHE-2.0.txt; add it before release" >&2
fi
if [ -f "$ROOT/NOTICE" ]; then
  cp "$ROOT/NOTICE" "$OUT/NOTICE"
else
  echo "publish: WARNING — NOTICE (attribution + trademark notice) not found at $ROOT/NOTICE; add it before release" >&2
fi

# --- gate: no personal identifiers anywhere in the export ---
echo "publish: running no-personal-identifiers guard over the export …"
"$OUT/scripts/check-no-personal-identifiers.sh" "$OUT/jip" "$OUT/agentkit" "$OUT/kernel" "$OUT/vault" \
  "$OUT/console" "$OUT/room-agent" "$OUT/room-view" "$OUT/signal-bridge" "$OUT/samples" "$OUT/monitor" "$OUT/sdks" \
  "$OUT/examples" "$OUT/README.md" "$OUT/CONTRIBUTING.md" "$OUT/WHY.md" "$OUT/VISION.md" "$OUT/docs" \
  "$OUT/AGENTS.md" "$OUT/CLAUDE.md" "$OUT/llms.txt" "$OUT/.cursor"   # shipped front-door + AI-assistant docs too

# --- gate: every exported Go source carries the Apache license header (no un-headered file ships) ---
echo "publish: checking Apache license headers …"
missing="$(grep -rL 'Licensed under the Apache License' --include='*.go' \
  "$OUT/jip" "$OUT/agentkit" "$OUT/kernel" "$OUT/vault" "$OUT/console" \
  "$OUT/room-agent" "$OUT/room-view" "$OUT/signal-bridge" "$OUT/samples" "$OUT/monitor" 2>/dev/null)"
if [ -n "$missing" ]; then
  echo "✗ Go source files missing the Apache license header (run scripts/add-license-headers):" >&2
  echo "$missing" >&2
  exit 1
fi
echo "✓ every Go source carries the Apache license header"

# --- build- AND test-verify the renamed export (so the path rewrite is proven, not assumed) ---
echo "publish: build + test-verifying the export …"
( cd "$OUT" && for d in jip agentkit kernel vault console room-agent room-view signal-bridge samples/joiner monitor; do
    [ -f "$d/go.mod" ] && ( cd "$d" && go build ./... && go test ./... >/dev/null ) && echo "  ok: $d"
  done )

# --- vulnerability scan (standing policy: govulncheck every shipped artifact). Best-effort: if the tool
#     isn't installed we say so rather than silently skipping. The toolchain is pinned (go.work) to a
#     patched stdlib, so a clean local toolchain build is clean here. ---
GVC="$(command -v govulncheck 2>/dev/null || echo "$(go env GOPATH)/bin/govulncheck")"
if [ -x "$GVC" ]; then
  echo "publish: govulncheck over the export …"
  ( cd "$OUT" && for d in jip agentkit kernel vault console room-agent room-view signal-bridge samples/joiner monitor; do
      [ -f "$d/go.mod" ] && ( cd "$d" && "$GVC" ./... >/dev/null ) && echo "  clean: $d"
    done )
else
  echo "publish: NOTE — govulncheck not installed; run 'go install golang.org/x/vuln/cmd/govulncheck@latest' and re-scan before release" >&2
fi

# `go build ./...` during the build-verify drops each command's binary into its module dir; strip them so
# the export ships source only (not 9 MB binaries per command).
( cd "$OUT" && for d in console room-agent room-view signal-bridge monitor samples/joiner; do
    rm -f "$d/$(basename "$d")"
  done )

echo "publish: export complete + verified -> $OUT"

# ─────────────────────────────────────────────────────────────────────────────
# Optional: commit (+ tag) the verified export to the public repo and push it.
# Off by default (export-only). Enable with PUBLISH=1.
#   PUBLISH_REMOTE  repo URL          (default https://github.com/J3nnaAI/mesh.git)
#   PUBLISH_CLONE   working clone dir  (default /tmp/mesh-oss-git)
#   PUBLISH_BRANCH  branch             (default main)
#   PUBLISH_MSG     commit message     (default: "publish: sync from monorepo @ <sha>")
#   PUBLISH_TAG     annotated tag to also create + push (e.g. jip/v0.1.1) — optional
#   PUBLISH_PUSH=0  commit (+tag) locally but DO NOT push — review the diff first
# ─────────────────────────────────────────────────────────────────────────────
if [ "${PUBLISH:-0}" = "1" ]; then
  REMOTE="${PUBLISH_REMOTE:-https://github.com/J3nnaAI/mesh.git}"
  CLONE="${PUBLISH_CLONE:-/tmp/mesh-oss-git}"
  BRANCH="${PUBLISH_BRANCH:-main}"
  echo "publish: syncing verified export -> $REMOTE ($BRANCH) via $CLONE"
  if [ -d "$CLONE/.git" ]; then
    git -C "$CLONE" fetch --quiet origin "$BRANCH"
    git -C "$CLONE" checkout --quiet -B "$BRANCH" "origin/$BRANCH"
    git -C "$CLONE" reset --hard --quiet "origin/$BRANCH"
  else
    rm -rf "$CLONE"; git clone --quiet --branch "$BRANCH" "$REMOTE" "$CLONE"
  fi
  # Sync the verified export onto the clone — NON-destructive (no --delete) and skipping the files the
  # public repo owns independently, so a publish never clobbers Dependabot / CodeQL / community-health /
  # external-consumer changes that live only on the public side:
  #   .github/             CI + Dependabot (public-managed)
  #   CODE_OF_CONDUCT.md   community-health file maintained on the public repo
  #   **/go.mod **/go.sum  cross-module require-pinning for external `go get` (added at publish time; the
  #                        monorepo builds via go.work and carries no such pins) — TODO: add a proper
  #                        pin-rewrite step here rather than skipping, so real go.mod changes propagate.
  rsync -a --exclude '.git/' --exclude '.github/' --exclude 'CODE_OF_CONDUCT.md' --exclude 'LICENSE' \
    --exclude '**/go.mod' --exclude '**/go.sum' "$OUT/" "$CLONE/"
  # SEED-IF-ABSENT: a fresh repo (post delete+recreate) has no .github/community files; seed them from the
  # export WITHOUT overwriting an existing public version (--ignore-existing). On a persisting repo this is
  # a no-op, so Dependabot/CodeQL PRs are never clobbered. (go.mod pins are still TODO above — a fresh
  # repo needs them regenerated/seeded before external `go get` works.)
  rsync -a --ignore-existing \
    $( [ -d "$OUT/.github" ] && echo "$OUT/.github" ) \
    $( [ -f "$OUT/CODE_OF_CONDUCT.md" ] && echo "$OUT/CODE_OF_CONDUCT.md" ) \
    $( [ -f "$OUT/LICENSE" ] && echo "$OUT/LICENSE" ) \
    "$CLONE/" 2>/dev/null || true
  git -C "$CLONE" add -A
  if git -C "$CLONE" diff --cached --quiet; then
    echo "publish: clone already matches origin/$BRANCH — nothing to commit"
  else
    SRC_REF="$(git -C "$MESH" rev-parse --short HEAD 2>/dev/null || echo unknown)"
    MSG="${PUBLISH_MSG:-publish: sync from monorepo @ $SRC_REF}"
    git -C "$CLONE" commit --quiet -m "$MSG"
    if [ -n "${PUBLISH_TAG:-}" ]; then git -C "$CLONE" tag -a "$PUBLISH_TAG" -m "$PUBLISH_TAG"; fi
    echo "publish: committed: $MSG${PUBLISH_TAG:+  (+ tag $PUBLISH_TAG)}"
    git -C "$CLONE" --no-pager show --stat --oneline HEAD | sed 's/^/  /'
    if [ "${PUBLISH_PUSH:-1}" = "1" ]; then
      git -C "$CLONE" push origin "$BRANCH"
      if [ -n "${PUBLISH_TAG:-}" ]; then git -C "$CLONE" push origin "$PUBLISH_TAG"; fi
      echo "publish: pushed -> $REMOTE ($BRANCH)${PUBLISH_TAG:+ + $PUBLISH_TAG}"
    else
      echo "publish: PUBLISH_PUSH=0 — committed locally in $CLONE; review, then push"
    fi
  fi
fi
