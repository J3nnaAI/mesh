// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Rooms — collaboration on the mesh. Room operations are ordinary identity-bound MCP tools/call requests to
// the room host peer; each carries a CallProof (whose node_id must equal the actor) and, on first contact,
// the caller's presence as `presenter`. Thin wrappers over mcp.callTool.

import 'identity.dart';
import 'mcp.dart' as mcp;

/// Join (auto-creating a public room if needed). Returns the roster.
Future<Map> join(String hostMcp, Identity ident, String roomId, String alias, String endpoint,
    {required Map presenter, String? trace, String mcpPath = '/mcp'}) {
  return mcp.callTool(
    hostMcp,
    ident,
    'room.join',
    {
      'room_id': roomId,
      'node_id': ident.id,
      'alias': alias,
      'endpoint': endpoint,
      'mcp_path': mcpPath,
    },
    presenter: presenter,
    trace: trace,
  );
}

/// Post a message (must already be a member). Returns {seq}.
Future<Map> post(String hostMcp, Identity ident, String roomId, String text,
    {Map? presenter, String? trace}) {
  return mcp.callTool(
    hostMcp,
    ident,
    'room.post',
    {'room_id': roomId, 'from': ident.id, 'text': text},
    presenter: presenter,
    trace: trace,
  );
}

/// Read room history from `since` (members only). Returns {messages, cursor}.
Future<Map> history(String hostMcp, Identity ident, String roomId,
    {int since = 0, Map? presenter, String? trace}) {
  return mcp.callTool(
    hostMcp,
    ident,
    'room.history',
    {'room_id': roomId, 'from': ident.id, 'since': since},
    presenter: presenter,
    trace: trace,
  );
}
