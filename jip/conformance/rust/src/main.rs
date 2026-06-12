// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// J3nna Mesh wire-conformance test for Rust. Reproduces the canonical signing bytes byte-for-byte and
// verifies the reference signatures from ../vectors.json. Rust is the multiplier port: the same wire layer
// compiles to WASM and exports a C ABI, so this also underpins the WASM and C/FFI targets.
//
//   cargo run        # exits 0 on pass, non-zero on any mismatch

use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

const VECTORS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors.json");

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
fn s(v: &serde_json::Value, k: &str) -> String {
    v[k].as_str().unwrap_or_default().to_string()
}
fn n(v: &serde_json::Value, k: &str) -> u64 {
    v[k].as_u64().unwrap_or_else(|| v[k].as_i64().unwrap_or(0) as u64)
}
fn hexb(v: &serde_json::Value, k: &str) -> Vec<u8> {
    hex::decode(v[k].as_str().unwrap()).unwrap()
}

fn presence_bytes(i: &serde_json::Value) -> Vec<u8> {
    let mut b = Vec::new();
    field(&mut b, s(i, "protocol").as_bytes());
    field(&mut b, s(i, "alg").as_bytes());
    field(&mut b, s(i, "id").as_bytes());
    field(&mut b, &hexb(i, "public_key_hex"));
    field(&mut b, s(i, "endpoint").as_bytes());
    field(&mut b, s(i, "mcp_path").as_bytes());
    let mut caps: Vec<String> = i["capabilities"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().to_string()).collect();
    caps.sort();
    u32f(&mut b, caps.len() as u32);
    for c in &caps {
        field(&mut b, c.as_bytes());
    }
    u32f(&mut b, n(i, "protocol_major") as u32);
    field(&mut b, s(i, "grant_id").as_bytes());
    u64f(&mut b, n(i, "heartbeat_unix"));
    b
}

fn grant_bytes(i: &serde_json::Value) -> Vec<u8> {
    let mut b = Vec::new();
    field(&mut b, b"J3nna-mesh-grant/1");
    field(&mut b, s(i, "alg").as_bytes());
    field(&mut b, s(i, "id").as_bytes());
    field(&mut b, s(i, "subject").as_bytes());
    field(&mut b, &hexb(i, "public_key_hex"));
    u64f(&mut b, n(i, "tier"));
    let mut scopes: Vec<String> = i["scopes"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().to_string()).collect();
    scopes.sort();
    field(&mut b, scopes.join("\0").as_bytes());
    u64f(&mut b, n(i, "issued_at"));
    u64f(&mut b, n(i, "not_after"));
    let principal = s(i, "principal");
    if !principal.is_empty() {
        field(&mut b, b"J3nna-mesh-principal/1");
        field(&mut b, principal.as_bytes());
    }
    b
}

fn callproof_bytes(i: &serde_json::Value) -> Vec<u8> {
    let mut b = Vec::new();
    field(&mut b, b"JIP-call/0.2");
    field(&mut b, s(i, "alg").as_bytes());
    field(&mut b, s(i, "node_id").as_bytes());
    field(&mut b, s(i, "tool").as_bytes());
    field(&mut b, &hexb(i, "args_hash_hex"));
    u64f(&mut b, n(i, "unix_milli"));
    b
}

// serde_json's default Map is a BTreeMap, so re-serialization sorts keys and is compact — matching Go's
// json.Marshal — except Go also HTML-escapes < > &, which we apply here.
fn canonical_args_json(args: &serde_json::Value) -> String {
    serde_json::to_string(args)
        .unwrap()
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
}

fn main() {
    // Native run uses the baked path; the WASM/WASI run is handed a preopened path as argv[1].
    let path = std::env::args().nth(1).unwrap_or_else(|| VECTORS.to_string());
    let raw = std::fs::read_to_string(&path).expect("read vectors.json");
    let doc: serde_json::Value = serde_json::from_str(&raw).expect("parse vectors.json");
    assert_eq!(doc["protocol"].as_str(), Some("JIP/0.1"));

    let mut count = 0;
    for v in doc["vectors"].as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        let i = &v["input"];
        let got = match name {
            "presence-record" => presence_bytes(i),
            "grant" => grant_bytes(i),
            "callproof" => callproof_bytes(i),
            other => panic!("no Rust builder for vector {other}"),
        };
        assert_eq!(hex::encode(&got), v["signing_bytes_hex"].as_str().unwrap(), "{name}: signing bytes differ");

        let pk: [u8; 32] = hex::decode(v["signer_public_key_hex"].as_str().unwrap()).unwrap().try_into().unwrap();
        let vk = VerifyingKey::from_bytes(&pk).unwrap();
        let sig_bytes = base64::engine::general_purpose::STANDARD.decode(v["signature_b64"].as_str().unwrap()).unwrap();
        let sig = Signature::from_bytes(&sig_bytes.try_into().unwrap());
        vk.verify_strict(&got, &sig).unwrap_or_else(|_| panic!("{name}: signature did not verify"));

        if name == "callproof" {
            let cj = canonical_args_json(&i["args"]);
            assert_eq!(cj, i["args_canonical_json"].as_str().unwrap(), "args canonical JSON differs from Go");
            let h = hex::encode(Sha256::digest(cj.as_bytes()));
            assert_eq!(h, i["args_hash_hex"].as_str().unwrap(), "args hash differs");
        }
        println!("  ok  {name}");
        count += 1;
    }
    println!("PASS: {count} vectors verified (Rust wire-compatible with the Go reference)");
}
