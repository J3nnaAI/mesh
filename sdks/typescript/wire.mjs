// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// The J3nna Mesh wire layer for Node.js / TypeScript: the canonical signing bytes every peer must reproduce,
// plus ed25519 sign/verify. This is the byte-for-byte contract — it is validated against the shared
// jip/conformance/vectors.json by test_conformance.mjs, so a Node peer is wire-compatible with the Go
// reference (and therefore every other SDK).
//
// Framing primitive: variable-length fields are 4-byte big-endian length-prefixed; integers are 8-byte
// big-endian; sets (capabilities, scopes) are sorted before framing. Uses only Node's built-in `crypto`
// (ed25519 — no dependencies). The framing helpers mirror the proven jip/conformance/node/conformance_test.mjs.

import crypto from "node:crypto";

export const PROTOCOL = "JIP/0.1";
export const PROTOCOL_MAJOR = 1;
export const SIG_ALG = "ed25519";

// ── framing primitives ──
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
function alg(a) {
  return a || SIG_ALG;
}

// 1. Presence record — signed by the peer's NODE key. `publicKey` is raw Buffer bytes.
export function presenceSigningBytes({
  protocol, alg: a, id, publicKey, endpoint, mcpPath, capabilities,
  protocolMajor, grantId, heartbeatUnix,
}) {
  const p = [];
  field(p, protocol);
  field(p, alg(a));
  field(p, id);
  field(p, publicKey);
  field(p, endpoint);
  field(p, mcpPath);
  const caps = [...capabilities].sort();
  u32(p, caps.length);
  for (const c of caps) field(p, c);
  u32(p, protocolMajor);
  field(p, grantId || "");
  u64(p, heartbeatUnix);
  return Buffer.concat(p);
}

// 2. Grant — signed by the AUTHORITY ROOT key. `publicKey` is raw Buffer bytes.
export function grantSigningBytes({
  alg: a, id, subject, publicKey, tier, scopes, issuedAt, notAfter, principal = "",
}) {
  const p = [];
  field(p, "J3nna-mesh-grant/1");
  field(p, alg(a));
  field(p, id);
  field(p, subject);
  field(p, publicKey);
  u64(p, tier);
  field(p, [...(scopes || [])].sort().join("\0"));
  u64(p, issuedAt);
  u64(p, notAfter);
  if (principal) {
    // signature-covered only when present, so legacy grants verify byte-identically
    field(p, "J3nna-mesh-principal/1");
    field(p, principal);
  }
  return Buffer.concat(p);
}

// 3. CallProof — signed by the caller's NODE key. `argsHash` is raw Buffer bytes.
export function callproofSigningBytes({ alg: a, nodeId, tool, argsHash, unixMilli }) {
  const p = [];
  field(p, "JIP-call/0.2");
  field(p, alg(a));
  field(p, nodeId);
  field(p, tool);
  field(p, argsHash);
  u64(p, unixMilli);
  return Buffer.concat(p);
}

// renew — field-framed, signed by the NODE key to prove possession of the pinned identity.
export function renewSigningBytes({ alg: a, grantId, subject, publicKey, issuedAt }) {
  const p = [];
  field(p, "J3nna-mesh-renew/1");
  field(p, alg(a));
  field(p, grantId);
  field(p, subject);
  field(p, publicKey);
  u64(p, issuedAt);
  return Buffer.concat(p);
}

// CRL — NOT field-framed: pipe/comma ASCII with a trailing comma after EVERY id; ids sorted ascending.
//   J3nna-mesh-crl/1|<alg>|<issued_at>|<id1>,<id2>,...,
export function crlSigningBytes({ alg: a, issuedAt, revokedIds }) {
  const head = `J3nna-mesh-crl/1|${a || SIG_ALG}|${issuedAt}|`;
  const body = [...revokedIds].sort().map((rid) => `${rid},`).join("");
  return Buffer.from(head + body, "utf8");
}

// Reproduce Go's json.Marshal of the arguments map: keys sorted (recursively), compact, and <, >, &
// escaped as < > &. This is the one place JSON canonicalization must match byte-for-byte.
export function canonicalArgsJson(args) {
  const sortKeys = (v) =>
    v && typeof v === "object" && !Array.isArray(v)
      ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortKeys(v[k])]))
      : Array.isArray(v)
      ? v.map(sortKeys)
      : v;
  const s = JSON.stringify(sortKeys(args))
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026");
  return Buffer.from(s, "utf8");
}

export function argsHash(args) {
  return crypto.createHash("sha256").update(canonicalArgsJson(args)).digest();
}

// ── ed25519 sign/verify (node:crypto, raw 32-byte seed/pubkey via JWK) ──
const b64url = (b) => Buffer.from(b).toString("base64url");

// Import a raw 32-byte ed25519 public key.
export function publicKeyFromRaw(pub32) {
  return crypto.createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: b64url(pub32) },
    format: "jwk",
  });
}

// Import a raw 32-byte ed25519 seed (with its public key) into a signing key.
export function privateKeyFromSeed(seed32, pub32) {
  return crypto.createPrivateKey({
    key: { kty: "OKP", crv: "Ed25519", d: b64url(seed32), x: b64url(pub32) },
    format: "jwk",
  });
}

export function sign(seed32, pub32, msg) {
  return crypto.sign(null, msg, privateKeyFromSeed(seed32, pub32));
}

export function verify(pub32, sig, msg) {
  try {
    return crypto.verify(null, msg, publicKeyFromRaw(pub32), sig);
  } catch {
    return false;
  }
}

// A fresh 64-bit span id (16 hex chars).
export function newSpanId() {
  return crypto.randomBytes(8).toString("hex");
}

// A fresh W3C `traceparent` (version 00, sampled). Attach one across a logical operation's calls so a
// telemetry backend stitches them into a single trace.
export function newTraceparent() {
  return "00-" + crypto.randomBytes(16).toString("hex") + "-" + crypto.randomBytes(8).toString("hex") + "-01";
}
