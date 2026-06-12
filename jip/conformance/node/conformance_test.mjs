// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// J3nna Mesh wire-conformance test for Node.js / TypeScript. Proves a Node implementation reproduces the
// canonical signing bytes byte-for-byte and verifies the reference signatures from ../vectors.json, using
// only Node's built-in `crypto` (ed25519 — no dependencies). The framing helpers here are the seed of the
// TS/Node SDK's wire layer.
//
//   node conformance_test.mjs          # exits 0 on pass, non-zero on any mismatch

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import crypto from "node:crypto";

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(join(here, "..", "vectors.json"), "utf8"));

// ── framing primitive ──
function field(parts, x) {
  const buf = Buffer.isBuffer(x) ? x : Buffer.from(x, "utf8");
  const len = Buffer.alloc(4);
  len.writeUInt32BE(buf.length, 0);
  parts.push(len, buf);
}
function u64(parts, v) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(v), 0);
  parts.push(b);
}
function u32(parts, v) {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(v >>> 0, 0);
  parts.push(b);
}
const hexBuf = (h) => Buffer.from(h, "hex");

function presenceSigningBytes(inp) {
  const p = [];
  field(p, inp.protocol);
  field(p, inp.alg);
  field(p, inp.id);
  field(p, hexBuf(inp.public_key_hex));
  field(p, inp.endpoint);
  field(p, inp.mcp_path);
  const caps = [...inp.capabilities].sort();
  u32(p, caps.length);
  for (const c of caps) field(p, c);
  u32(p, inp.protocol_major);
  field(p, inp.grant_id);
  u64(p, inp.heartbeat_unix);
  return Buffer.concat(p);
}

function grantSigningBytes(inp) {
  const p = [];
  field(p, "J3nna-mesh-grant/1");
  field(p, inp.alg);
  field(p, inp.id);
  field(p, inp.subject);
  field(p, hexBuf(inp.public_key_hex));
  u64(p, inp.tier);
  field(p, [...inp.scopes].sort().join("\0"));
  u64(p, inp.issued_at);
  u64(p, inp.not_after);
  if (inp.principal) {
    field(p, "J3nna-mesh-principal/1");
    field(p, inp.principal);
  }
  return Buffer.concat(p);
}

// Reproduce Go's json.Marshal of a map: keys sorted, compact, and <, >, & escaped as < > &.
function canonicalArgsJSON(args) {
  const sortKeys = (v) =>
    v && typeof v === "object" && !Array.isArray(v)
      ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortKeys(v[k])]))
      : Array.isArray(v)
      ? v.map(sortKeys)
      : v;
  return JSON.stringify(sortKeys(args))
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026");
}

function callproofSigningBytes(inp) {
  const p = [];
  field(p, "JIP-call/0.2");
  field(p, inp.alg);
  field(p, inp.node_id);
  field(p, inp.tool);
  field(p, hexBuf(inp.args_hash_hex));
  u64(p, inp.unix_milli);
  return Buffer.concat(p);
}

const builders = {
  "presence-record": presenceSigningBytes,
  grant: grantSigningBytes,
  callproof: callproofSigningBytes,
};

function ed25519PublicKey(hex) {
  // import a raw 32-byte ed25519 public key via JWK (base64url, no padding)
  const x = Buffer.from(hex, "hex").toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return crypto.createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x }, format: "jwk" });
}

function main() {
  if (vectors.protocol !== "JIP/0.1") throw new Error(`unexpected protocol ${vectors.protocol}`);
  for (const v of vectors.vectors) {
    const build = builders[v.name];
    if (!build) throw new Error(`no Node builder for vector ${v.name}`);

    const got = build(v.input);
    if (got.toString("hex") !== v.signing_bytes_hex) throw new Error(`${v.name}: signing bytes differ`);

    const pub = ed25519PublicKey(v.signer_public_key_hex);
    const ok = crypto.verify(null, got, pub, Buffer.from(v.signature_b64, "base64"));
    if (!ok) throw new Error(`${v.name}: signature did not verify`);

    if (v.name === "callproof") {
      const cj = canonicalArgsJSON(v.input.args);
      if (cj !== v.input.args_canonical_json) throw new Error("args canonical JSON differs from Go");
      const h = crypto.createHash("sha256").update(cj).digest("hex");
      if (h !== v.input.args_hash_hex) throw new Error("args hash differs");
    }
    console.log(`  ok  ${v.name}`);
  }
  console.log(`PASS: ${vectors.vectors.length} vectors verified (Node.js wire-compatible with the Go reference)`);
}

main();
