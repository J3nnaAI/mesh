// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//! MCP tool calls — how a Rust peer invokes another peer's tools (and rooms, which are just tools). Builds
//! the JSON-RPC tools/call envelope, attaches a signed, arguments-bound CallProof so restricted/identity-bound
//! tools authorize the caller, includes the peer's presence as `presenter` on first contact, and optionally a
//! W3C `trace` for distributed tracing.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde_json::{json, Value};

use crate::error::{Error, Result};
use crate::identity::Identity;
use crate::{http, wire};

const B64: base64::engine::general_purpose::GeneralPurpose = base64::engine::general_purpose::STANDARD;

fn now_milli() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A CallProof: the caller signs (domain, alg, node_id, tool, sha256(canonical args), unix_milli) with its
/// node key, binding the proof to THIS tool + arguments at THIS time. `unix_milli` defaults to now (millis)
/// when None.
pub fn make_callproof(ident: &Identity, tool: &str, args: &Value, unix_milli: Option<u64>) -> Value {
    let unix_milli = unix_milli.unwrap_or_else(now_milli);
    let ah = wire::args_hash(args);
    let sb = wire::callproof_signing_bytes(wire::SIG_ALG, &ident.id, tool, &ah, unix_milli);
    json!({
        "node_id": ident.id,
        "tool": tool,
        "args_hash": B64.encode(&ah),
        "unix_milli": unix_milli,
        "alg": wire::SIG_ALG,
        "signature": B64.encode(ident.sign(&sb)),
    })
}

/// Invoke `tool` at a peer's MCP URL with a signed CallProof; returns its `structuredContent`. `presenter`
/// (our signed presence) must be included on first contact so the host can resolve our pinned key; `trace`
/// propagates a traceparent for telemetry.
pub fn call_tool(
    mcp_url: &str,
    ident: &Identity,
    tool: &str,
    args: &Value,
    presenter: Option<&Value>,
    trace: Option<&str>,
    timeout_secs: f64,
) -> Result<Value> {
    let mut params = json!({
        "name": tool,
        "arguments": args,
        "caller": make_callproof(ident, tool, args, None),
    });
    if let Some(pr) = presenter {
        params["presenter"] = pr.clone();
    }
    if let Some(t) = trace {
        params["trace"] = json!(t);
    }
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": params,
    });

    let resp = http::post_json(mcp_url, &body, timeout_secs)?;
    if let Some(err) = resp.get("error") {
        if !err.is_null() {
            return Err(Error::Rejected(format!("mcp protocol error: {err}")));
        }
    }
    let result = resp.get("result").cloned().unwrap_or_else(|| json!({}));
    if result
        .get("isError")
        .and_then(|x| x.as_bool())
        .unwrap_or(false)
    {
        let msg = result
            .get("content")
            .and_then(|c| c.as_array())
            .and_then(|a| a.first())
            .and_then(|m| m.get("text"))
            .and_then(|t| t.as_str())
            .unwrap_or("tool error")
            .to_string();
        return Err(Error::Rejected(msg));
    }
    Ok(result
        .get("structuredContent")
        .cloned()
        .unwrap_or_else(|| json!({})))
}

/// List a peer's tools.
pub fn list_tools(mcp_url: &str, timeout_secs: f64) -> Result<Vec<Value>> {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}});
    let resp = http::post_json(mcp_url, &body, timeout_secs)?;
    Ok(resp
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(|t| t.as_array())
        .cloned()
        .unwrap_or_default())
}
