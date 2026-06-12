// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//! Discovery — how a Rust peer finds others on the mesh. It builds and signs its own presence record
//! (carrying its grant), gossips it to seed peers' /gossip endpoints, and receives their presence in return.
//! Every received record is verified offline (self-signature, and — under an authority root — its grant), so
//! a peer admits only authorized peers.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde_json::{json, Value};

use crate::identity::Identity;
use crate::{http, wire};

const B64: base64::engine::general_purpose::GeneralPurpose = base64::engine::general_purpose::STANDARD;

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn caps_from(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|c| c.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

/// Build this peer's signed PresenceRecord (payload + ed25519 signature over the canonical bytes).
/// `grant` is the grant JSON object returned by enrollment; `heartbeat` defaults to now (seconds) when None.
pub fn build_presence(
    ident: &Identity,
    grant: &Value,
    endpoint: &str,
    caps: &[String],
    heartbeat: Option<u64>,
    mcp_path: &str,
) -> Value {
    let heartbeat = heartbeat.unwrap_or_else(now_unix);
    let grant_id = grant.get("id").and_then(|x| x.as_str()).unwrap_or_default();

    let payload = json!({
        "protocol": wire::PROTOCOL,
        "id": ident.id,
        "public_key": B64.encode(ident.public_key),
        "endpoint": endpoint,
        "mcp_path": mcp_path,
        "capabilities": caps,
        "heartbeat_unix": heartbeat,
        "protocol_major": wire::PROTOCOL_MAJOR,
        "grant": grant,
        "alg": wire::SIG_ALG,
    });

    let sb = wire::presence_signing_bytes(
        wire::PROTOCOL,
        wire::SIG_ALG,
        &ident.id,
        &ident.public_key,
        endpoint,
        mcp_path,
        caps,
        wire::PROTOCOL_MAJOR,
        grant_id,
        heartbeat,
    );
    json!({
        "payload": payload,
        "signature": B64.encode(ident.sign(&sb)),
    })
}

/// Verify a presence record's self-signature; with `root` set, also verify its grant binds id↔key and is
/// authority-signed (the admission check).
pub fn verify_record(rec: &Value, root: Option<&[u8]>) -> bool {
    let p = match rec.get("payload") {
        Some(p) => p,
        None => return false,
    };
    let pub_b64 = match p.get("public_key").and_then(|x| x.as_str()) {
        Some(s) => s,
        None => return false,
    };
    let pubkey = match B64.decode(pub_b64.as_bytes()) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let grant_id = p
        .get("grant")
        .and_then(|g| g.get("id"))
        .and_then(|x| x.as_str())
        .unwrap_or_default();

    let sb = wire::presence_signing_bytes(
        p.get("protocol").and_then(|x| x.as_str()).unwrap_or_default(),
        p.get("alg").and_then(|x| x.as_str()).unwrap_or_default(),
        p.get("id").and_then(|x| x.as_str()).unwrap_or_default(),
        &pubkey,
        p.get("endpoint").and_then(|x| x.as_str()).unwrap_or_default(),
        p.get("mcp_path").and_then(|x| x.as_str()).unwrap_or_default(),
        &caps_from(p.get("capabilities").unwrap_or(&Value::Null)),
        p.get("protocol_major").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
        grant_id,
        p.get("heartbeat_unix").and_then(|x| x.as_u64()).unwrap_or(0),
    );

    let sig = match rec
        .get("signature")
        .and_then(|x| x.as_str())
        .and_then(|s| B64.decode(s.as_bytes()).ok())
    {
        Some(s) => s,
        None => return false,
    };
    if !wire::verify(&pubkey, &sig, &sb) {
        return false;
    }

    let root = match root {
        None => return true,
        Some(r) => r,
    };

    let g = match p.get("grant") {
        Some(g) if g.is_object() => g,
        _ => return false,
    };
    let subject = g.get("subject").and_then(|x| x.as_str()).unwrap_or_default();
    let id = p.get("id").and_then(|x| x.as_str()).unwrap_or_default();
    let g_pub = g
        .get("public_key")
        .and_then(|x| x.as_str())
        .and_then(|s| B64.decode(s.as_bytes()).ok())
        .unwrap_or_default();
    if subject != id || g_pub != pubkey {
        return false;
    }

    let scopes: Vec<String> = g
        .get("scopes")
        .map(caps_from)
        .unwrap_or_default();
    let gb = wire::grant_signing_bytes(
        g.get("alg").and_then(|x| x.as_str()).unwrap_or_default(),
        g.get("id").and_then(|x| x.as_str()).unwrap_or_default(),
        subject,
        &pubkey,
        g.get("tier").and_then(|x| x.as_u64()).unwrap_or(0),
        &scopes,
        g.get("issued_at").and_then(|x| x.as_u64()).unwrap_or(0),
        g.get("not_after").and_then(|x| x.as_u64()).unwrap_or(0),
        g.get("principal").and_then(|x| x.as_str()).unwrap_or_default(),
    );
    let g_sig = match g
        .get("signature")
        .and_then(|x| x.as_str())
        .and_then(|s| B64.decode(s.as_bytes()).ok())
    {
        Some(s) => s,
        None => return false,
    };
    wire::verify(root, &g_sig, &gb)
}

fn gossip_once(seed_base: &str, my_record: &Value) -> crate::error::Result<Vec<Value>> {
    let my = &my_record["payload"];
    let id = my.get("id").and_then(|x| x.as_str()).unwrap_or_default();
    let heartbeat = my.get("heartbeat_unix").cloned().unwrap_or(json!(0));
    let env = json!({
        "protocol": wire::PROTOCOL,
        "digest": { id: heartbeat },
        "records": [my_record],
    });
    let url = format!("{}/gossip", seed_base.trim_end_matches('/'));
    let resp = http::post_json(&url, &env, 10.0)?;
    Ok(resp
        .get("records")
        .and_then(|r| r.as_array())
        .cloned()
        .unwrap_or_default())
}

/// A discovered peer on the mesh.
#[derive(Clone, Debug)]
pub struct Peer {
    pub id: String,
    /// The peer's reachable MCP URL (endpoint + mcp_path).
    pub mcp: String,
    pub caps: Vec<String>,
}

/// Gossip our presence to each seed and return the verified peers learned (excluding self), optionally
/// filtered to those advertising `want_cap`.
pub fn discover(
    seeds: &[String],
    my_record: &Value,
    root: Option<&[u8]>,
    want_cap: Option<&str>,
) -> Vec<Peer> {
    let my_id = my_record["payload"]
        .get("id")
        .and_then(|x| x.as_str())
        .unwrap_or_default()
        .to_string();
    let mut peers: std::collections::BTreeMap<String, Peer> = std::collections::BTreeMap::new();

    for seed in seeds {
        let records = match gossip_once(seed, my_record) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for rec in &records {
            let p = match rec.get("payload") {
                Some(p) => p,
                None => continue,
            };
            let pid = p.get("id").and_then(|x| x.as_str()).unwrap_or_default();
            if pid == my_id || !verify_record(rec, root) {
                continue;
            }
            let caps = caps_from(p.get("capabilities").unwrap_or(&Value::Null));
            if let Some(wc) = want_cap {
                if !caps.iter().any(|c| c == wc) {
                    continue;
                }
            }
            let endpoint = p.get("endpoint").and_then(|x| x.as_str()).unwrap_or_default();
            let mcp_path = p.get("mcp_path").and_then(|x| x.as_str()).unwrap_or_default();
            let mcp = format!("{}{}", endpoint.trim_end_matches('/'), mcp_path);
            peers.insert(
                pid.to_string(),
                Peer {
                    id: pid.to_string(),
                    mcp,
                    caps,
                },
            );
        }
    }
    peers.into_values().collect()
}
