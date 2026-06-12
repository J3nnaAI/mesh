// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Wire-conformance test for the Node.js / TypeScript SDK. Proves the SDK's `wire.mjs` reproduces the
// canonical signing bytes byte-for-byte and verifies the reference signatures from the shared
// jip/conformance/vectors.json — using only the SDK (which uses node:crypto, no deps). It also runs a
// SIGN round-trip self-test, because the vectors carry no private seeds and so cannot exercise the sign path.
//
//   node test_conformance.mjs          # exits 0 on pass, non-zero on any mismatch

import { readFileSync, unlinkSync } from "node:fs";
import crypto from "node:crypto";

import * as wire from "./wire.mjs";
import { ensureIdentity } from "./identity.mjs";

// The canonical vectors live in the jip repo, beside the other languages' conformance tests.
const VECTORS_PATH = "/home/j3nna/web-stt-tts/jip/conformance/vectors.json";
const hexBuf = (h) => Buffer.from(h, "hex");

// Bridge the vectors' hex inputs into the SDK's raw-Buffer wire functions.
const builders = {
  "presence-record": (i) =>
    wire.presenceSigningBytes({
      protocol: i.protocol, alg: i.alg, id: i.id, publicKey: hexBuf(i.public_key_hex),
      endpoint: i.endpoint, mcpPath: i.mcp_path, capabilities: i.capabilities,
      protocolMajor: i.protocol_major, grantId: i.grant_id, heartbeatUnix: i.heartbeat_unix,
    }),
  grant: (i) =>
    wire.grantSigningBytes({
      alg: i.alg, id: i.id, subject: i.subject, publicKey: hexBuf(i.public_key_hex),
      tier: i.tier, scopes: i.scopes, issuedAt: i.issued_at, notAfter: i.not_after,
      principal: i.principal || "",
    }),
  callproof: (i) =>
    wire.callproofSigningBytes({
      alg: i.alg, nodeId: i.node_id, tool: i.tool, argsHash: hexBuf(i.args_hash_hex),
      unixMilli: i.unix_milli,
    }),
  renewal: (i) =>
    wire.renewSigningBytes({
      alg: i.alg, grantId: i.grant_id, subject: i.subject,
      publicKey: hexBuf(i.public_key_hex), issuedAt: i.issued_at,
    }),
  crl: (i) =>
    wire.crlSigningBytes({ alg: i.alg, issuedAt: i.issued_at, revokedIds: Object.keys(i.revoked) }),
};

function verifyVectors() {
  const vectors = JSON.parse(readFileSync(VECTORS_PATH, "utf8"));
  if (vectors.protocol !== "JIP/0.1") throw new Error(`unexpected protocol ${vectors.protocol}`);
  for (const v of vectors.vectors) {
    const build = builders[v.name];
    if (!build) throw new Error(`no builder for vector ${v.name}`);

    const got = build(v.input);
    if (got.toString("hex") !== v.signing_bytes_hex) {
      throw new Error(`${v.name}: signing bytes differ\n  got: ${got.toString("hex")}\n  want: ${v.signing_bytes_hex}`);
    }

    // ed25519-verify the reference signature over our bytes against the signer's public key.
    const pub = hexBuf(v.signer_public_key_hex);
    if (!wire.verify(pub, Buffer.from(v.signature_b64, "base64"), got)) {
      throw new Error(`${v.name}: signature did not verify`);
    }

    if (v.name === "callproof") {
      const cj = wire.canonicalArgsJson(v.input.args).toString("utf8");
      if (cj !== v.input.args_canonical_json) throw new Error("args canonical JSON differs from Go");
      const h = crypto.createHash("sha256").update(cj).digest("hex");
      if (h !== v.input.args_hash_hex) throw new Error("args hash differs");
    }
    console.log(`  ok  ${v.name}  (signing-bytes + ed25519 verify)`);
  }
  console.log(`PASS: ${vectors.vectors.length} vectors verified (Node.js wire-compatible with the Go reference)`);
}

// The sign path is not covered by vectors (no seed fixtures) — exercise it with a round-trip: a fresh
// identity signs each structure's bytes, and the SDK verifies under the derived public key.
function signRoundTrip(tmp) {
  const ident = ensureIdentity(tmp);

  const cases = {
    presence: wire.presenceSigningBytes({
      protocol: wire.PROTOCOL, alg: wire.SIG_ALG, id: ident.id, publicKey: ident.publicKey,
      endpoint: "http://127.0.0.1:1/", mcpPath: "/mcp", capabilities: ["rooms", "tools"],
      protocolMajor: wire.PROTOCOL_MAJOR, grantId: "g-1", heartbeatUnix: Math.floor(Date.now() / 1000),
    }),
    callproof: wire.callproofSigningBytes({
      alg: wire.SIG_ALG, nodeId: ident.id, tool: "echo",
      argsHash: wire.argsHash({ count: 3, message: "hello" }), unixMilli: Date.now(),
    }),
  };
  for (const [name, bytes] of Object.entries(cases)) {
    const sig = ident.sign(bytes);
    if (!wire.verify(ident.publicKey, sig, bytes)) throw new Error(`sign round-trip failed: ${name}`);
    if (wire.verify(ident.publicKey, sig, Buffer.concat([bytes, Buffer.from("x")]))) {
      throw new Error(`sign round-trip: tampered message verified (${name})`);
    }
    console.log(`  ok  sign-roundtrip ${name}`);
  }
  console.log("PASS: ed25519 sign round-trip (no seed fixtures exist; this proves the sign path)");
}

function main() {
  verifyVectors();
  const tmp = `/tmp/j3nna-mesh-rt-${process.pid}.id`;
  try {
    signRoundTrip(tmp);
  } finally {
    try { unlinkSync(tmp); } catch { /* ignore */ }
  }
}

main();
