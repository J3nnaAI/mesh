// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Rooms — collaboration on the mesh. Room operations are ordinary identity-bound MCP tools/call requests to
// the room host peer; each carries a CallProof (whose node_id must equal the actor) and, on first contact,
// the caller's presence as `presenter`. Thin wrappers over Mcp.CallTool.

using System.Text.Json;

namespace J3nnaMesh;

public static class Rooms
{
    // Join (auto-creating a public room if needed). Returns the roster.
    public static JsonElement Join(string hostMcp, Identity ident, string roomId, string alias,
        string endpoint, PresenceRecord presenter, string? trace = null, string mcpPath = "/mcp")
    {
        return Mcp.CallTool(hostMcp, ident, "room.join", new Dictionary<string, object?>
        {
            ["room_id"] = roomId,
            ["node_id"] = ident.Id,
            ["alias"] = alias,
            ["endpoint"] = endpoint,
            ["mcp_path"] = mcpPath,
        }, presenter: presenter, trace: trace);
    }

    // Post a message (must already be a member). Returns {seq}.
    public static JsonElement Post(string hostMcp, Identity ident, string roomId, string text,
        PresenceRecord? presenter = null, string? trace = null)
    {
        return Mcp.CallTool(hostMcp, ident, "room.post", new Dictionary<string, object?>
        {
            ["room_id"] = roomId,
            ["from"] = ident.Id,
            ["text"] = text,
        }, presenter: presenter, trace: trace);
    }

    // Read room history from `since` (members only). Returns {messages, cursor}.
    public static JsonElement History(string hostMcp, Identity ident, string roomId, long since = 0,
        PresenceRecord? presenter = null, string? trace = null)
    {
        return Mcp.CallTool(hostMcp, ident, "room.history", new Dictionary<string, object?>
        {
            ["room_id"] = roomId,
            ["from"] = ident.Id,
            ["since"] = since,
        }, presenter: presenter, trace: trace);
    }
}
