# Copyright 2026 J3nna Technologies, LLC
# SPDX-License-Identifier: Apache-2.0
"""Rooms — collaboration on the mesh. Room operations are ordinary identity-bound MCP tools/call requests to
the room host peer; each carries a CallProof (whose node_id must equal the actor) and, on first contact, the
caller's presence as `presenter`. Thin wrappers over mcp.call_tool."""

from . import mcp


def join(host_mcp: str, ident, room_id: str, alias: str, endpoint: str, presenter: dict,
         trace: str = None, mcp_path: str = "/mcp") -> dict:
    """Join (auto-creating a public room if needed). Returns the roster."""
    return mcp.call_tool(host_mcp, ident, "room.join", {
        "room_id": room_id, "node_id": ident.id, "alias": alias,
        "endpoint": endpoint, "mcp_path": mcp_path,
    }, presenter=presenter, trace=trace)


def post(host_mcp: str, ident, room_id: str, text: str, presenter: dict = None, trace: str = None) -> dict:
    """Post a message (must already be a member). Returns {seq}."""
    return mcp.call_tool(host_mcp, ident, "room.post", {
        "room_id": room_id, "from": ident.id, "text": text,
    }, presenter=presenter, trace=trace)


def history(host_mcp: str, ident, room_id: str, since: int = 0, presenter: dict = None,
            trace: str = None) -> dict:
    """Read room history from `since` (members only). Returns {messages, cursor}."""
    return mcp.call_tool(host_mcp, ident, "room.history", {
        "room_id": room_id, "from": ident.id, "since": since,
    }, presenter=presenter, trace=trace)
