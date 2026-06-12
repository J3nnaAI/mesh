// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// The J3nna Mesh wire layer for Dart: the canonical signing bytes every peer must reproduce, plus ed25519
// sign/verify. This is the byte-for-byte contract — validated against the shared jip/conformance/vectors.json
// (see test/conformance_test.dart), so a Dart peer is wire-compatible with the Go reference (and therefore
// every other SDK).
//
// Framing primitive: variable-length fields are 4-byte big-endian length-prefixed; integers are 8-byte
// big-endian; sets (capabilities, scopes) are sorted before framing. The presence/grant/callproof framing is
// reused verbatim from jip/conformance/dart/bin/conformance.dart — the proven, byte-exact reference.

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

const protocol = 'JIP/0.1';
const protocolMajor = 1;
const sigAlg = 'ed25519';

void _field(BytesBuilder b, List<int> x) {
  final n = ByteData(4)..setUint32(0, x.length, Endian.big);
  b.add(n.buffer.asUint8List());
  b.add(x);
}

void _u64(BytesBuilder b, int v) {
  final x = ByteData(8)..setUint64(0, v, Endian.big);
  b.add(x.buffer.asUint8List());
}

void _u32(BytesBuilder b, int v) {
  final x = ByteData(4)..setUint32(0, v, Endian.big);
  b.add(x.buffer.asUint8List());
}

List<int> _utf8b(String s) => utf8.encode(s);

String _alg(String? a) => (a == null || a.isEmpty) ? sigAlg : a;

/// PresenceRecord.canonicalBytes — protocol, alg, id, pubkey, endpoint, mcp_path, sorted caps
/// (count-prefixed), protocol_major (uint32), grant_id, heartbeat (uint64). Signed by the node key.
Uint8List presenceSigningBytes({
  required String protocol,
  required String alg,
  required String id,
  required List<int> publicKey,
  required String endpoint,
  required String mcpPath,
  required List<String> capabilities,
  required int protocolMajor,
  required String grantId,
  required int heartbeatUnix,
}) {
  final b = BytesBuilder();
  _field(b, _utf8b(protocol));
  _field(b, _utf8b(_alg(alg)));
  _field(b, _utf8b(id));
  _field(b, publicKey);
  _field(b, _utf8b(endpoint));
  _field(b, _utf8b(mcpPath));
  final caps = List<String>.from(capabilities)..sort();
  _u32(b, caps.length);
  for (final c in caps) {
    _field(b, _utf8b(c));
  }
  _u32(b, protocolMajor);
  _field(b, _utf8b(grantId));
  _u64(b, heartbeatUnix);
  return b.toBytes();
}

/// GrantSigningBytes — domain 'J3nna-mesh-grant/1', alg, id, subject, pubkey, tier (uint64), sorted scopes
/// (NUL-joined), issued_at, not_after (uint64), then only-if-present principal. Signed by the authority root.
Uint8List grantSigningBytes({
  required String alg,
  required String id,
  required String subject,
  required List<int> publicKey,
  required int tier,
  required List<String> scopes,
  required int issuedAt,
  required int notAfter,
  String principal = '',
}) {
  final b = BytesBuilder();
  _field(b, _utf8b('J3nna-mesh-grant/1'));
  _field(b, _utf8b(_alg(alg)));
  _field(b, _utf8b(id));
  _field(b, _utf8b(subject));
  _field(b, publicKey);
  _u64(b, tier);
  final s = List<String>.from(scopes)..sort();
  // sorted scopes joined by a single NUL byte (0x00).
  final joined = BytesBuilder();
  for (var i = 0; i < s.length; i++) {
    if (i > 0) joined.addByte(0x00);
    joined.add(_utf8b(s[i]));
  }
  _field(b, joined.toBytes());
  _u64(b, issuedAt);
  _u64(b, notAfter);
  if (principal.isNotEmpty) {
    // signature-covered only when present, so legacy grants verify byte-identically.
    _field(b, _utf8b('J3nna-mesh-principal/1'));
    _field(b, _utf8b(principal));
  }
  return b.toBytes();
}

/// RenewSigningBytes — domain 'J3nna-mesh-renew/1', alg, grant_id, subject, pubkey (all length-prefixed),
/// then issued_at (uint64). Signed by the peer's NODE key to prove possession of the grant's pinned key.
Uint8List renewSigningBytes({
  required String alg,
  required String grantId,
  required String subject,
  required List<int> publicKey,
  required int issuedAt,
}) {
  final b = BytesBuilder();
  _field(b, _utf8b('J3nna-mesh-renew/1'));
  _field(b, _utf8b(_alg(alg)));
  _field(b, _utf8b(grantId));
  _field(b, _utf8b(subject));
  _field(b, publicKey);
  _u64(b, issuedAt);
  return b.toBytes();
}

/// CRLSigningBytes — NOT field-framed: ASCII 'J3nna-mesh-crl/1|<alg>|<issued_at>|' then each revoked
/// grant id in SORTED ascending order, each followed by a comma (trailing comma after EVERY id).
/// Revoked-at timestamps are NOT signed. Signed by the AUTHORITY ROOT key.
Uint8List crlSigningBytes({
  required String alg,
  required int issuedAt,
  required List<String> revokedIds,
}) {
  final ids = List<String>.from(revokedIds)..sort();
  final sb = StringBuffer('J3nna-mesh-crl/1|${_alg(alg)}|$issuedAt|');
  for (final id in ids) {
    sb.write('$id,');
  }
  return Uint8List.fromList(_utf8b(sb.toString()));
}

/// CallProof.signedBytes — domain 'JIP-call/0.2', alg, node_id, tool, args_hash, unix_milli (uint64).
/// Signed by the caller's node key.
Uint8List callproofSigningBytes({
  required String alg,
  required String nodeId,
  required String tool,
  required List<int> argsHash,
  required int unixMilli,
}) {
  final b = BytesBuilder();
  _field(b, _utf8b('JIP-call/0.2'));
  _field(b, _utf8b(_alg(alg)));
  _field(b, _utf8b(nodeId));
  _field(b, _utf8b(tool));
  _field(b, argsHash);
  _u64(b, unixMilli);
  return b.toBytes();
}

/// Reproduce Go's json.Marshal of the arguments map: keys sorted at every level, compact, and <, >, &
/// escaped as < > &. Mirrors Python's json.dumps(sort_keys=True, separators=(",",":")) plus
/// the HTML escapes. This is the one place JSON canonicalization must match byte-for-byte.
String canonicalArgsJson(Map args) {
  final s = _canon(args);
  return s
      .replaceAll('<', '\\u003c')
      .replaceAll('>', '\\u003e')
      .replaceAll('&', '\\u0026');
}

String _canon(dynamic v) {
  if (v is Map) {
    final keys = v.keys.map((k) => k.toString()).toList()..sort();
    final parts = keys.map((k) => '${jsonEncode(k)}:${_canon(v[k])}');
    return '{${parts.join(',')}}';
  }
  if (v is List) {
    return '[${v.map(_canon).join(',')}]';
  }
  // Whole-number doubles must serialize as integers (Go marshals 0.0 as "0" only for ints; the SDK uses
  // ints for counts). jsonEncode already renders ints without a decimal point.
  return jsonEncode(v);
}

/// args_hash = sha256(canonical_json). Async because package:cryptography's Sha256 returns a Future.
Future<Uint8List> argsHash(Map args) async {
  final h = await Sha256().hash(_utf8b(canonicalArgsJson(args)));
  return Uint8List.fromList(h.bytes);
}

/// Sign `msg` with the 32-byte ed25519 seed. Returns the 64-byte signature.
Future<Uint8List> sign(List<int> seed32, List<int> msg) async {
  final ed = Ed25519();
  final kp = await ed.newKeyPairFromSeed(seed32);
  final sig = await ed.sign(msg, keyPair: kp);
  return Uint8List.fromList(sig.bytes);
}

/// Verify `sig` over `msg` against the 32-byte public key.
Future<bool> verify(List<int> publicKey32, List<int> sig, List<int> msg) async {
  try {
    final pub = SimplePublicKey(publicKey32, type: KeyPairType.ed25519);
    return await Ed25519().verify(msg, signature: Signature(sig, publicKey: pub));
  } catch (_) {
    return false;
  }
}

String _hex(int n, int nibbles) => n.toRadixString(16).padLeft(nibbles, '0');

/// A fresh 64-bit span id (16 hex chars).
String newSpanId() {
  final r = Random.secure();
  return _hex(r.nextInt(0x100000000), 8) + _hex(r.nextInt(0x100000000), 8);
}

/// A fresh W3C `traceparent` (version 00, sampled): "00-" + 32 hex (trace) + "-" + 16 hex (span) + "-01".
String newTraceparent() {
  final r = Random.secure();
  final trace = _hex(r.nextInt(0x100000000), 8) +
      _hex(r.nextInt(0x100000000), 8) +
      _hex(r.nextInt(0x100000000), 8) +
      _hex(r.nextInt(0x100000000), 8);
  return '00-$trace-${newSpanId()}-01';
}
