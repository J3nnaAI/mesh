// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Wire-conformance test for the Dart SDK. Reproduces the canonical signing bytes byte-for-byte and verifies
// the reference signatures from jip/conformance/vectors.json — exercising the SDK's own lib/src/wire.dart
// (not a copy). Run:
//
//   dart run test/conformance_test.dart        # exits 0 on pass, non-zero on failure
//
// Pure script (no test runner dep) so `dart run` exercises it directly per the build instructions.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:j3nna_mesh/src/wire.dart' as wire;

List<int> _unhex(String s) =>
    [for (var i = 0; i < s.length; i += 2) int.parse(s.substring(i, i + 2), radix: 16)];
String _enhex(List<int> b) => b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

// Locate vectors.json relative to this repo regardless of cwd.
String _vectorsPath() {
  for (final p in [
    '../../../jip/conformance/vectors.json', // from sdks/dart
    '/home/j3nna/web-stt-tts/jip/conformance/vectors.json',
  ]) {
    if (File(p).existsSync()) return p;
  }
  // Fallback: walk up from script dir to find jip/conformance/vectors.json.
  var dir = Directory(Platform.script.toFilePath()).parent;
  for (var i = 0; i < 8; i++) {
    final cand = File('${dir.path}/jip/conformance/vectors.json');
    if (cand.existsSync()) return cand.path;
    dir = dir.parent;
  }
  throw StateError('could not locate jip/conformance/vectors.json');
}

Future<void> main() async {
  final doc = jsonDecode(File(_vectorsPath()).readAsStringSync()) as Map;
  if (doc['protocol'] != 'JIP/0.1') {
    throw 'unexpected protocol ${doc['protocol']}';
  }
  var count = 0;
  for (final vAny in doc['vectors']) {
    final v = vAny as Map;
    final name = v['name'] as String;
    final i = v['input'] as Map;
    Uint8List got;
    switch (name) {
      case 'presence-record':
        got = wire.presenceSigningBytes(
          protocol: i['protocol'] as String,
          alg: i['alg'] as String,
          id: i['id'] as String,
          publicKey: _unhex(i['public_key_hex'] as String),
          endpoint: i['endpoint'] as String,
          mcpPath: i['mcp_path'] as String,
          capabilities: (i['capabilities'] as List).map((e) => '$e').toList(),
          protocolMajor: i['protocol_major'] as int,
          grantId: i['grant_id'] as String,
          heartbeatUnix: i['heartbeat_unix'] as int,
        );
        break;
      case 'grant':
        got = wire.grantSigningBytes(
          alg: i['alg'] as String,
          id: i['id'] as String,
          subject: i['subject'] as String,
          publicKey: _unhex(i['public_key_hex'] as String),
          tier: i['tier'] as int,
          scopes: (i['scopes'] as List).map((e) => '$e').toList(),
          issuedAt: i['issued_at'] as int,
          notAfter: i['not_after'] as int,
          principal: (i['principal'] as String?) ?? '',
        );
        break;
      case 'callproof':
        got = wire.callproofSigningBytes(
          alg: i['alg'] as String,
          nodeId: i['node_id'] as String,
          tool: i['tool'] as String,
          argsHash: _unhex(i['args_hash_hex'] as String),
          unixMilli: i['unix_milli'] as int,
        );
        break;
      case 'renewal':
        got = wire.renewSigningBytes(
          alg: i['alg'] as String,
          grantId: i['grant_id'] as String,
          subject: i['subject'] as String,
          publicKey: _unhex(i['public_key_hex'] as String),
          issuedAt: i['issued_at'] as int,
        );
        break;
      case 'crl':
        got = wire.crlSigningBytes(
          alg: i['alg'] as String,
          issuedAt: i['issued_at'] as int,
          revokedIds: (i['revoked'] as Map).keys.map((e) => '$e').toList(),
        );
        break;
      default:
        throw 'no Dart builder for $name';
    }

    if (_enhex(got) != v['signing_bytes_hex']) {
      throw '$name: signing bytes differ\n  got ${_enhex(got)}\n  exp ${v['signing_bytes_hex']}';
    }

    // ed25519-verify the reference signature over our bytes, via the SDK's verify().
    final pub = _unhex(v['signer_public_key_hex'] as String);
    final sig = base64.decode(v['signature_b64'] as String);
    if (!await wire.verify(pub, sig, got)) {
      throw '$name: signature did not verify';
    }

    if (name == 'callproof') {
      final cj = wire.canonicalArgsJson(i['args'] as Map);
      if (cj != i['args_canonical_json']) {
        throw 'args canonical JSON differs from Go\n  got $cj\n  exp ${i['args_canonical_json']}';
      }
      final h = await wire.argsHash(i['args'] as Map);
      if (_enhex(h) != i['args_hash_hex']) {
        throw 'args hash differs';
      }
    }
    stdout.writeln('  ok  $name');
    count++;
  }
  stdout.writeln('PASS: $count vectors verified (Dart SDK wire-compatible with the Go reference)');
}
