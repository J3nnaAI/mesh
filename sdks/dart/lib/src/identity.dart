// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Node identity: a random v4 UUID plus an ed25519 keypair, persisted in the SAME on-disk format as the Go
// reference so the file is byte-interchangeable — {"id", "priv_b64"} where priv_b64 is base64-std of the
// 64-byte Go private key (32-byte seed || 32-byte public key). The UUID is independent of the key and is what
// a grant binds to, so it must be persisted and reused (regenerating it after enrollment breaks admission).

import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

import 'wire.dart' as wire;

class Identity {
  final String id;
  final List<int> seed; // 32-byte ed25519 seed (private)
  final List<int> publicKey; // 32-byte ed25519 public key

  Identity(this.id, this.seed, this.publicKey);

  Future<Uint8List> sign(List<int> msg) => wire.sign(seed, msg);

  String get publicKeyB64 => base64.encode(publicKey);
}

/// A random v4 UUID from a secure RNG (no external dependency).
String _uuid4() {
  final r = Random.secure();
  final b = Uint8List(16);
  for (var i = 0; i < 16; i++) {
    b[i] = r.nextInt(256);
  }
  b[6] = (b[6] & 0x0f) | 0x40; // version 4
  b[8] = (b[8] & 0x3f) | 0x80; // variant 10xx
  String h(int i) => b[i].toRadixString(16).padLeft(2, '0');
  final s = StringBuffer();
  for (var i = 0; i < 16; i++) {
    if (i == 4 || i == 6 || i == 8 || i == 10) s.write('-');
    s.write(h(i));
  }
  return s.toString();
}

/// Load the identity at `path`, or create + persist (0600) a fresh one. Byte-compatible with Go's
/// EnsureIdentity.
Future<Identity> ensureIdentity(String path) async {
  final f = File(path);
  if (await f.exists()) {
    final blob = jsonDecode(await f.readAsString()) as Map;
    final raw = base64.decode(blob['priv_b64'] as String);
    if (raw.length != 64) {
      throw StateError('identity priv_b64 must decode to 64 bytes (seed||pubkey)');
    }
    return Identity(blob['id'] as String, raw.sublist(0, 32), raw.sublist(32));
  }

  final ed = Ed25519();
  final kp = await ed.newKeyPair();
  final seed = await kp.extractPrivateKeyBytes();
  final pub = (await kp.extractPublicKey()).bytes;
  final ident = Identity(_uuid4(), seed, pub);

  final priv = Uint8List(64)
    ..setRange(0, 32, seed)
    ..setRange(32, 64, pub);
  final blob = {'id': ident.id, 'priv_b64': base64.encode(priv)};

  final dir = File(path).parent;
  if (!await dir.exists()) await dir.create(recursive: true);
  await f.writeAsString(jsonEncode(blob));
  // dart:io has no create-mode; tighten to 0600 (POSIX) to mirror the Python reference.
  try {
    await Process.run('chmod', ['600', path]);
  } catch (_) {/* best-effort on non-POSIX */}
  return ident;
}
