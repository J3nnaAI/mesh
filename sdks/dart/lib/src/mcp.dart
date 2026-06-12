// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// MCP tool calls — how a Dart peer invokes another peer's tools (and rooms, which are just tools). Builds the
// JSON-RPC tools/call envelope, attaches a signed, arguments-bound CallProof so restricted/identity-bound
// tools authorize the caller, includes the peer's presence as `presenter` on first contact, and optionally a
// W3C `trace` for distributed tracing.

import 'dart:convert';

import 'http.dart';
import 'identity.dart';
import 'wire.dart' as wire;

/// A CallProof: the caller signs (domain, alg, node_id, tool, sha256(canonical args), unix_milli) with its
/// node key, binding the proof to THIS tool + arguments at THIS time.
Future<Map> makeCallproof(Identity ident, String tool, Map args, {int? unixMilli}) async {
  unixMilli ??= DateTime.now().millisecondsSinceEpoch;
  final ah = await wire.argsHash(args);
  final sb = wire.callproofSigningBytes(
      alg: wire.sigAlg, nodeId: ident.id, tool: tool, argsHash: ah, unixMilli: unixMilli);
  final sig = await ident.sign(sb);
  return {
    'node_id': ident.id,
    'tool': tool,
    'args_hash': base64.encode(ah),
    'unix_milli': unixMilli,
    'alg': wire.sigAlg,
    'signature': base64.encode(sig),
  };
}

/// Invoke `tool` at a peer's MCP URL with a signed CallProof; returns its structuredContent. `presenter`
/// (our signed presence) must be included on first contact so the host can resolve our pinned key; `trace`
/// propagates a traceparent for telemetry.
Future<Map> callTool(
  String mcpUrl,
  Identity ident,
  String tool,
  Map args, {
  Map? presenter,
  String? trace,
  Duration timeout = const Duration(seconds: 15),
}) async {
  final params = <String, dynamic>{
    'name': tool,
    'arguments': args,
    'caller': await makeCallproof(ident, tool, args),
  };
  if (presenter != null) params['presenter'] = presenter;
  if (trace != null) params['trace'] = trace;
  final body = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': params};
  final resp = await httpPostJson(mcpUrl, body, timeout: timeout) as Map;
  if (resp.containsKey('error')) {
    throw StateError('mcp protocol error: ${resp['error']}');
  }
  final result = (resp['result'] as Map?) ?? {};
  if (result['isError'] == true) {
    final content = (result['content'] as List?) ?? [];
    final msg = content.isNotEmpty ? ((content[0] as Map)['text'] ?? 'tool error') : 'tool error';
    throw StateError('call rejected: $msg');
  }
  return (result['structuredContent'] as Map?) ?? {};
}

Future<List> listTools(String mcpUrl, {Duration timeout = const Duration(seconds: 15)}) async {
  final body = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list', 'params': {}};
  final resp = await httpPostJson(mcpUrl, body, timeout: timeout) as Map;
  return ((resp['result'] as Map?)?['tools'] as List?) ?? [];
}
