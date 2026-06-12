// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//! The J3nna Mesh wire layer for Rust: the canonical signing bytes every peer must reproduce, plus
//! ed25519 sign/verify. This is the byte-for-byte contract — it is validated against the shared
//! `jip/conformance/vectors.json` by the conformance tests, so a Rust peer is wire-compatible with the Go
//! reference (and therefore every other SDK).
//!
//! Framing primitive: variable-length fields are 4-byte big-endian length-prefixed; integers are 8-byte
//! big-endian; sets (capabilities, scopes) are sorted before framing.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::RngCore;
use sha2::{Digest, Sha256};

pub const PROTOCOL: &str = "JIP/0.1";
pub const PROTOCOL_MAJOR: u32 = 1;
pub const SIG_ALG: &str = "ed25519";

fn field(buf: &mut Vec<u8>, x: &[u8]) {
    buf.extend_from_slice(&(x.len() as u32).to_be_bytes());
    buf.extend_from_slice(x);
}
fn u64f(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_be_bytes());
}
fn u32f(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}
fn alg_bytes(a: &str) -> &str {
    if a.is_empty() {
        SIG_ALG
    } else {
        a
    }
}

/// Presence record signing bytes — signed by the peer's NODE key.
/// `public_key` is the raw 32-byte ed25519 public key. `capabilities` are sorted before framing.
#[allow(clippy::too_many_arguments)]
pub fn presence_signing_bytes(
    protocol: &str,
    alg: &str,
    id: &str,
    public_key: &[u8],
    endpoint: &str,
    mcp_path: &str,
    capabilities: &[String],
    protocol_major: u32,
    grant_id: &str,
    heartbeat_unix: u64,
) -> Vec<u8> {
    let mut b = Vec::new();
    field(&mut b, protocol.as_bytes());
    field(&mut b, alg_bytes(alg).as_bytes());
    field(&mut b, id.as_bytes());
    field(&mut b, public_key);
    field(&mut b, endpoint.as_bytes());
    field(&mut b, mcp_path.as_bytes());
    let mut caps: Vec<String> = capabilities.to_vec();
    caps.sort();
    u32f(&mut b, caps.len() as u32);
    for c in &caps {
        field(&mut b, c.as_bytes());
    }
    u32f(&mut b, protocol_major);
    field(&mut b, grant_id.as_bytes());
    u64f(&mut b, heartbeat_unix);
    b
}

/// Grant signing bytes — signed by the AUTHORITY ROOT key. Scopes are sorted and NUL-joined.
/// The principal extension is signature-covered only when present, so legacy grants verify identically.
#[allow(clippy::too_many_arguments)]
pub fn grant_signing_bytes(
    alg: &str,
    id: &str,
    subject: &str,
    public_key: &[u8],
    tier: u64,
    scopes: &[String],
    issued_at: u64,
    not_after: u64,
    principal: &str,
) -> Vec<u8> {
    let mut b = Vec::new();
    field(&mut b, b"J3nna-mesh-grant/1");
    field(&mut b, alg_bytes(alg).as_bytes());
    field(&mut b, id.as_bytes());
    field(&mut b, subject.as_bytes());
    field(&mut b, public_key);
    u64f(&mut b, tier);
    let mut s: Vec<String> = scopes.to_vec();
    s.sort();
    field(&mut b, s.join("\0").as_bytes());
    u64f(&mut b, issued_at);
    u64f(&mut b, not_after);
    if !principal.is_empty() {
        field(&mut b, b"J3nna-mesh-principal/1");
        field(&mut b, principal.as_bytes());
    }
    b
}

/// CallProof signing bytes — signed by the caller's NODE key.
pub fn callproof_signing_bytes(
    alg: &str,
    node_id: &str,
    tool: &str,
    args_hash: &[u8],
    unix_milli: u64,
) -> Vec<u8> {
    let mut b = Vec::new();
    field(&mut b, b"JIP-call/0.2");
    field(&mut b, alg_bytes(alg).as_bytes());
    field(&mut b, node_id.as_bytes());
    field(&mut b, tool.as_bytes());
    field(&mut b, args_hash);
    u64f(&mut b, unix_milli);
    b
}

/// Renewal-request signing bytes — signed by the peer's NODE key to prove possession of the grant's pinned
/// key. Field-framed (like grant/presence): domain 'J3nna-mesh-renew/1', alg, grant_id, subject, public_key;
/// then issued_at as an 8-byte big-endian uint64.
pub fn renew_signing_bytes(
    alg: &str,
    grant_id: &str,
    subject: &str,
    public_key: &[u8],
    issued_at: u64,
) -> Vec<u8> {
    let mut b = Vec::new();
    field(&mut b, b"J3nna-mesh-renew/1");
    field(&mut b, alg_bytes(alg).as_bytes());
    field(&mut b, grant_id.as_bytes());
    field(&mut b, subject.as_bytes());
    field(&mut b, public_key);
    u64f(&mut b, issued_at);
    b
}

/// CRL signing bytes — signed by the AUTHORITY ROOT key. NOT field-framed: the ASCII string
/// `J3nna-mesh-crl/1|<alg>|<issued_at>|` followed by each revoked id in SORTED ascending order, each id
/// followed by a comma (trailing comma after EVERY id). Revoked-at timestamps are NOT signed.
pub fn crl_signing_bytes(alg: &str, issued_at: u64, revoked_ids: &[String]) -> Vec<u8> {
    let mut ids: Vec<String> = revoked_ids.to_vec();
    ids.sort();
    let mut s = format!("J3nna-mesh-crl/1|{}|{}|", alg_bytes(alg), issued_at);
    for id in &ids {
        s.push_str(id);
        s.push(',');
    }
    s.into_bytes()
}

/// Reproduce Go's `json.Marshal` of the arguments map: keys sorted, compact, and `<`, `>`, `&` escaped as
/// `< > &`. `serde_json`'s default `Map` is a `BTreeMap`, so re-serialization sorts keys and
/// is compact — matching Go's `json.Marshal` — except Go also HTML-escapes `< > &`, applied here.
/// This is the one place JSON canonicalization must match byte-for-byte.
pub fn canonical_args_json(args: &serde_json::Value) -> Vec<u8> {
    serde_json::to_string(args)
        .unwrap()
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        .into_bytes()
}

/// sha256(canonical_args_json(args)).
pub fn args_hash(args: &serde_json::Value) -> Vec<u8> {
    Sha256::digest(canonical_args_json(args)).to_vec()
}

/// ed25519 sign `msg` with the 32-byte `seed`.
pub fn sign(seed32: &[u8; 32], msg: &[u8]) -> Vec<u8> {
    let sk = SigningKey::from_bytes(seed32);
    sk.sign(msg).to_bytes().to_vec()
}

/// ed25519 verify — strict (RFC 8032 + dalek's malleability/cofactor checks). Returns false on any error.
pub fn verify(public_key32: &[u8], sig: &[u8], msg: &[u8]) -> bool {
    let pk: [u8; 32] = match public_key32.try_into() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let vk = match VerifyingKey::from_bytes(&pk) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let sig_arr: [u8; 64] = match sig.try_into() {
        Ok(s) => s,
        Err(_) => return false,
    };
    let signature = Signature::from_bytes(&sig_arr);
    vk.verify_strict(msg, &signature).is_ok()
}

fn rand_hex(n_bytes: usize) -> String {
    let mut buf = vec![0u8; n_bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

/// A fresh 64-bit span id (16 hex chars).
pub fn new_span_id() -> String {
    rand_hex(8)
}

/// A fresh W3C `traceparent` (version 00, sampled). Attach one across a logical operation's calls so a
/// telemetry backend stitches them into a single trace.
pub fn new_traceparent() -> String {
    format!("00-{}-{}-01", rand_hex(16), rand_hex(8))
}
