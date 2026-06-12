// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Rooms — collaboration on the mesh. Room operations are ordinary identity-bound MCP tools/call requests
// to the room host peer; each carries a CallProof (whose node_id must equal the actor) and, on first
// contact, the caller's presence as `presenter`. Thin wrappers over MCP.callTool.

import Foundation

public enum Rooms {

    /// Join (auto-creating a public room if needed). Returns the roster.
    @discardableResult
    public static func join(hostMCP: String, ident: Identity, roomID: String, alias: String,
                            endpoint: String, presenter: [String: Any], trace: String? = nil,
                            mcpPath: String = "/mcp") throws -> [String: Any] {
        try MCP.callTool(mcpURL: hostMCP, ident: ident, tool: "room.join", args: [
            "room_id": roomID,
            "node_id": ident.id,
            "alias": alias,
            "endpoint": endpoint,
            "mcp_path": mcpPath,
        ], presenter: presenter, trace: trace)
    }

    /// Post a message (must already be a member). Returns {seq}.
    @discardableResult
    public static func post(hostMCP: String, ident: Identity, roomID: String, text: String,
                            presenter: [String: Any]? = nil, trace: String? = nil) throws -> [String: Any] {
        try MCP.callTool(mcpURL: hostMCP, ident: ident, tool: "room.post", args: [
            "room_id": roomID,
            "from": ident.id,
            "text": text,
        ], presenter: presenter, trace: trace)
    }

    /// Read room history from `since` (members only). Returns {messages, cursor}.
    @discardableResult
    public static func history(hostMCP: String, ident: Identity, roomID: String, since: Int = 0,
                               presenter: [String: Any]? = nil, trace: String? = nil) throws -> [String: Any] {
        try MCP.callTool(mcpURL: hostMCP, ident: ident, tool: "room.history", args: [
            "room_id": roomID,
            "from": ident.id,
            "since": since,
        ], presenter: presenter, trace: trace)
    }
}
