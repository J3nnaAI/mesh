// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Discovery — how a Dart peer finds others on the mesh. It builds and signs its own presence record (carrying
// its grant), gossips it to seed peers' /gossip endpoints, and receives their presence in return. Every
// received record is verified offline (self-signature, and — under an authority root — its grant), so a peer
// admits only authorized peers.

import 'dart:convert';
import 'dart:typed_data';

import 'http.dart';
import 'identity.dart';
import 'wire.dart' as wire;

/// A discovered peer.
class Peer {
  final String id;
  final String mcp; // the peer's reachable MCP URL (endpoint + mcp_path)
  final List<String> caps;
  Peer(this.id, this.mcp, this.caps);

  @override
  String toString() {
    final short = id.length >= 8 ? id.substring(0, 8) : id;
    return 'Peer(id=$short…, caps=$caps, mcp=$mcp)';
  }
}

String _rstripSlash(String s) => s.replaceAll(RegExp(r'/+$'), '');

/// Build this peer's signed PresenceRecord (payload + ed25519 signature over the canonical bytes).
Future<Map> buildPresence(Identity ident, Map grant, String endpoint, List<String> caps,
    {int? heartbeat, String mcpPath = '/mcp'}) async {
  heartbeat ??= DateTime.now().millisecondsSinceEpoch ~/ 1000; // unix SECONDS
  final payload = {
    'protocol': wire.protocol,
    'id': ident.id,
    'public_key': base64.encode(ident.publicKey),
    'endpoint': endpoint,
    'mcp_path': mcpPath,
    'capabilities': caps,
    'heartbeat_unix': heartbeat,
    'protocol_major': wire.protocolMajor,
    'grant': grant,
    'alg': wire.sigAlg,
  };
  final sb = wire.presenceSigningBytes(
    protocol: wire.protocol,
    alg: wire.sigAlg,
    id: ident.id,
    publicKey: ident.publicKey,
    endpoint: endpoint,
    mcpPath: mcpPath,
    capabilities: caps,
    protocolMajor: wire.protocolMajor,
    grantId: grant['id'] as String,
    heartbeatUnix: heartbeat,
  );
  final sig = await ident.sign(sb);
  return {'payload': payload, 'signature': base64.encode(sig)};
}

/// Verify a presence record's self-signature; with `root` set, also verify its grant binds id↔key and is
/// authority-signed (the admission check).
Future<bool> verifyRecord(Map rec, {Uint8List? root}) async {
  final p = rec['payload'] as Map;
  final pub = base64.decode(p['public_key'] as String);
  final grant = p['grant'] as Map?;
  final sb = wire.presenceSigningBytes(
    protocol: p['protocol'] as String,
    alg: (p['alg'] as String?) ?? '',
    id: p['id'] as String,
    publicKey: pub,
    endpoint: p['endpoint'] as String,
    mcpPath: p['mcp_path'] as String,
    capabilities: ((p['capabilities'] as List?) ?? []).map((e) => '$e').toList(),
    protocolMajor: (p['protocol_major'] as int?) ?? 0,
    grantId: (grant?['id'] as String?) ?? '',
    heartbeatUnix: p['heartbeat_unix'] as int,
  );
  if (!await wire.verify(pub, base64.decode(rec['signature'] as String), sb)) {
    return false;
  }
  if (root == null) return true;
  if (grant == null ||
      grant['subject'] != p['id'] ||
      !_bytesEqual(base64.decode(grant['public_key'] as String), pub)) {
    return false;
  }
  final gb = wire.grantSigningBytes(
    alg: (grant['alg'] as String?) ?? '',
    id: grant['id'] as String,
    subject: grant['subject'] as String,
    publicKey: pub,
    tier: grant['tier'] as int,
    scopes: ((grant['scopes'] as List?) ?? []).map((e) => '$e').toList(),
    issuedAt: grant['issued_at'] as int,
    notAfter: grant['not_after'] as int,
    principal: (grant['principal'] as String?) ?? '',
  );
  return wire.verify(root, base64.decode(grant['signature'] as String), gb);
}

bool _bytesEqual(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

Future<List> _gossipOnce(String seedBase, Map myRecord,
    {Duration timeout = const Duration(seconds: 10)}) async {
  final my = myRecord['payload'] as Map;
  final env = {
    'protocol': wire.protocol,
    'digest': {my['id']: my['heartbeat_unix']},
    'records': [myRecord],
  };
  final resp =
      await httpPostJson('${_rstripSlash(seedBase)}/gossip', env, timeout: timeout) as Map;
  return (resp['records'] as List?) ?? [];
}

/// Gossip our presence to each seed and return the verified peers learned (excluding self), optionally
/// filtered to those advertising `wantCap`.
Future<List<Peer>> discover(List<String> seeds, Map myRecord,
    {Uint8List? root, String? wantCap}) async {
  final myId = (myRecord['payload'] as Map)['id'];
  final peers = <String, Peer>{};
  for (final seed in seeds) {
    List records;
    try {
      records = await _gossipOnce(seed, myRecord);
    } catch (_) {
      continue;
    }
    for (final rec in records) {
      final p = (rec as Map)['payload'] as Map;
      if (p['id'] == myId || !await verifyRecord(rec, root: root)) continue;
      final caps = ((p['capabilities'] as List?) ?? []).map((e) => '$e').toList();
      if (wantCap != null && !caps.contains(wantCap)) continue;
      peers[p['id'] as String] =
          Peer(p['id'] as String, _rstripSlash(p['endpoint'] as String) + (p['mcp_path'] as String), caps);
    }
  }
  return peers.values.toList();
}
