// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//! Rooms — collaboration on the mesh. Room operations are ordinary identity-bound MCP tools/call requests to
//! the room host peer; each carries a CallProof (whose node_id must equal the actor) and, on first contact,
//! the caller's presence as `presenter`. Thin wrappers over mcp::call_tool.

use serde_json::{json, Value};

use crate::error::Result;
use crate::identity::Identity;
use crate::mcp;

/// Join (auto-creating a public room if needed). Returns the roster.
#[allow(clippy::too_many_arguments)]
pub fn join(
    host_mcp: &str,
    ident: &Identity,
    room_id: &str,
    alias: &str,
    endpoint: &str,
    presenter: Option<&Value>,
    trace: Option<&str>,
    mcp_path: &str,
) -> Result<Value> {
    let args = json!({
        "room_id": room_id,
        "node_id": ident.id,
        "alias": alias,
        "endpoint": endpoint,
        "mcp_path": mcp_path,
    });
    mcp::call_tool(host_mcp, ident, "room.join", &args, presenter, trace, 15.0)
}

/// Post a message (must already be a member). Returns {seq}.
pub fn post(
    host_mcp: &str,
    ident: &Identity,
    room_id: &str,
    text: &str,
    presenter: Option<&Value>,
    trace: Option<&str>,
) -> Result<Value> {
    let args = json!({
        "room_id": room_id,
        "from": ident.id,
        "text": text,
    });
    mcp::call_tool(host_mcp, ident, "room.post", &args, presenter, trace, 15.0)
}

/// Read room history from `since` (members only). Returns {messages, cursor}.
pub fn history(
    host_mcp: &str,
    ident: &Identity,
    room_id: &str,
    since: u64,
    presenter: Option<&Value>,
    trace: Option<&str>,
) -> Result<Value> {
    let args = json!({
        "room_id": room_id,
        "from": ident.id,
        "since": since,
    });
    mcp::call_tool(host_mcp, ident, "room.history", &args, presenter, trace, 15.0)
}
