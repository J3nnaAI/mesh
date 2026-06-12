#!/usr/bin/env bash
# Copyright 2026 J3nna Technologies, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Run every language's J3nna Mesh wire-conformance test against vectors.json. Each must reproduce the
# canonical signing bytes byte-for-byte and verify the reference ed25519 signatures. A green run means all
# implementations are wire-compatible with the Go reference (and therefore with each other).
#
#   ./run-all.sh
#
# Toolchains expected on PATH (or the well-known locations below): go, python3, node, cargo, dotnet, javac,
# /opt/dart-sdk/bin/dart, /opt/swift/usr/bin/swift.

set -u
cd "$(dirname "$0")"
export PATH="$PATH:/opt/dart-sdk/bin:/opt/swift/usr/bin:/usr/lib/dotnet"
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
pass=0; fail=0; skip=0
declare -a results

have() { command -v "$1" >/dev/null 2>&1; }

run() { # name  toolcheck  "command"
  local name="$1"; local tool="$2"; local cmd="$3"; local log="/tmp/conf-$name.log"
  if ! have "$tool"; then results+=("  SKIP  $name (no $tool)"); skip=$((skip+1)); return; fi
  if bash -c "$cmd" >"$log" 2>&1; then
    results+=("  PASS  $name — $(grep -E '^PASS' "$log" | tail -1)"); pass=$((pass+1))
  else
    results+=("  FAIL  $name (see $log)"); fail=$((fail+1))
  fi
}

run go     go      "cd .. && go test -run TestConformanceVectors ./... -count=1"
run python python3 "cd python && python3 conformance_test.py"
run node   node    "cd node && node conformance_test.mjs"
run rust   cargo   "cd rust && cargo run -q"
run dart   dart    "cd dart && dart pub get >/dev/null 2>&1 && dart run bin/conformance.dart"
run csharp dotnet  "cd csharp && dotnet run -c Release"
run java   javac   "cd java && { [ -f gson.jar ] || curl -fsSL https://repo1.maven.org/maven2/com/google/code/gson/gson/2.11.0/gson-2.11.0.jar -o gson.jar; } && javac -cp gson.jar Conformance.java && java -cp .:gson.jar Conformance"
run wasm   cargo   "cd rust && cargo build -q --target wasm32-wasip1 --release && cd ../wasm && node --experimental-wasi-unstable-preview1 run.mjs"
run swift  swift   "cd swift && swift run 2>/dev/null"

echo
echo "===== J3nna Mesh wire conformance ====="
printf '%s\n' "${results[@]}"
echo "  ---------------------------------------"
echo "  $pass passed, $fail failed, $skip skipped"
[ "$fail" -eq 0 ] || exit 1
