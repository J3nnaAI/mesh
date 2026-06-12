// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// J3nna Mesh wire-conformance test for WebAssembly. Runs the Rust wire-layer compiled to wasm32-wasip1
// under Node's built-in WASI — proving the exact same canonical-bytes + ed25519 logic works in a WASM
// runtime (browsers, edge, WASI hosts). No native crypto: it's the Rust SDK, in WASM.
//
//   node --experimental-wasi-unstable-preview1 run.mjs

import { WASI } from "node:wasi";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const confDir = join(here, "..");
const wasmPath = join(here, "..", "rust", "target", "wasm32-wasip1", "release", "jip-conformance.wasm");

const wasi = new WASI({
  version: "preview1",
  args: ["jip-conformance", "/conf/vectors.json"],
  preopens: { "/conf": confDir },
});

const wasm = await WebAssembly.compile(readFileSync(wasmPath));
const instance = await WebAssembly.instantiate(wasm, wasi.getImportObject());
const code = wasi.start(instance);
process.exit(typeof code === "number" ? code : 0);
