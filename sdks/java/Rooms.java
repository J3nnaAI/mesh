// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Rooms — collaboration on the mesh. Room operations are ordinary identity-bound MCP tools/call requests to
// the room host peer; each carries a CallProof (whose node_id must equal the actor) and, on first contact,
// the caller's presence as `presenter`. Thin wrappers over Mcp.callTool.

import com.google.gson.JsonObject;
import java.util.LinkedHashMap;
import java.util.Map;

public final class Rooms {
    private Rooms() {}

    /** Join (auto-creating a public room if needed). Returns the roster. */
    public static JsonObject join(String hostMcp, Identity ident, String roomId, String alias, String endpoint,
                                  JsonObject presenter, String trace, String mcpPath) throws Exception {
        Map<String, Object> args = new LinkedHashMap<>();
        args.put("room_id", roomId);
        args.put("node_id", ident.id);
        args.put("alias", alias);
        args.put("endpoint", endpoint);
        args.put("mcp_path", mcpPath);
        return Mcp.callTool(hostMcp, ident, "room.join", args, presenter, trace);
    }

    public static JsonObject join(String hostMcp, Identity ident, String roomId, String alias, String endpoint,
                                  JsonObject presenter, String trace) throws Exception {
        return join(hostMcp, ident, roomId, alias, endpoint, presenter, trace, "/mcp");
    }

    /** Post a message (must already be a member). Returns {seq}. */
    public static JsonObject post(String hostMcp, Identity ident, String roomId, String text,
                                  JsonObject presenter, String trace) throws Exception {
        Map<String, Object> args = new LinkedHashMap<>();
        args.put("room_id", roomId);
        args.put("from", ident.id);
        args.put("text", text);
        return Mcp.callTool(hostMcp, ident, "room.post", args, presenter, trace);
    }

    /** Read room history from `since` (members only). Returns {messages, cursor}. */
    public static JsonObject history(String hostMcp, Identity ident, String roomId, long since,
                                     JsonObject presenter, String trace) throws Exception {
        Map<String, Object> args = new LinkedHashMap<>();
        args.put("room_id", roomId);
        args.put("from", ident.id);
        args.put("since", (int) since); // whole number → canonical JSON integer
        return Mcp.callTool(hostMcp, ident, "room.history", args, presenter, trace);
    }
}
