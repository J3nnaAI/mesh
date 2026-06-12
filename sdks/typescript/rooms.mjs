// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Rooms — collaboration on the mesh. Room operations are ordinary identity-bound MCP tools/call requests to
// the room host peer; each carries a CallProof (whose node_id must equal the actor) and, on first contact,
// the caller's presence as `presenter`. Thin wrappers over mcp.callTool.

import * as mcp from "./mcp.mjs";

// Join (auto-creating a public room if needed). Returns the roster.
export async function join(hostMcp, ident, roomId, alias, endpoint, {
  presenter = null, trace = null, mcpPath = "/mcp",
} = {}) {
  return mcp.callTool(hostMcp, ident, "room.join", {
    room_id: roomId, node_id: ident.id, alias,
    endpoint, mcp_path: mcpPath,
  }, { presenter, trace });
}

// Post a message (must already be a member). Returns {seq}.
export async function post(hostMcp, ident, roomId, text, { presenter = null, trace = null } = {}) {
  return mcp.callTool(hostMcp, ident, "room.post", {
    room_id: roomId, from: ident.id, text,
  }, { presenter, trace });
}

// Read room history from `since` (members only). Returns {messages, cursor}.
export async function history(hostMcp, ident, roomId, {
  since = 0, presenter = null, trace = null,
} = {}) {
  return mcp.callTool(hostMcp, ident, "room.history", {
    room_id: roomId, from: ident.id, since,
  }, { presenter, trace });
}
