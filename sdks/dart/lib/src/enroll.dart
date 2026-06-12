// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Enrollment with the console — the four-call HTTP flow that turns a fresh identity into a signed grant:
// fetch the authority root, POST /enroll, display the out-of-band code for an operator to confirm, then poll
// GET /enroll/<id> until the signed grant comes back. The console is the root of trust; after this the peer
// runs on cached credentials and never needs it on the hot path.

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'http.dart';
import 'identity.dart';

/// The result of a successful enrollment.
class Enrollment {
  final Identity identity;
  final Map grant;
  final Uint8List root; // authority root public key (32 bytes)
  Enrollment(this.identity, this.grant, this.root);
}

/// The authority root public key — the offline-verification key for every grant and CRL.
Future<Uint8List> fetchRoot(String consoleUrl, {int retries = 10}) async {
  Object? last;
  for (var i = 0; i < retries; i++) {
    try {
      final j = await httpGetJson('$consoleUrl/authority');
      return base64.decode((j as Map)['root_public_key'] as String);
    } catch (e) {
      // console may not be up yet
      last = e;
      await Future.delayed(const Duration(seconds: 2));
    }
  }
  throw last ?? StateError('fetchRoot failed');
}

/// Enroll an agent. Returns (Identity, grant, root_pubkey). Blocks until an operator approves the request
/// out-of-band (the console then returns the signed grant), or throws on denial/timeout. `onOob` is called
/// with the out-of-band code so the caller can display it.
Future<Enrollment> enroll(
  String consoleUrl,
  String clientName,
  String identityPath, {
  int tier = 1,
  void Function(String oob)? onOob,
  Duration timeout = const Duration(seconds: 120),
}) async {
  consoleUrl = consoleUrl.replaceAll(RegExp(r'/+$'), '');
  final ident = await ensureIdentity(identityPath);
  final root = await fetchRoot(consoleUrl);
  final resp = await httpPostJson('$consoleUrl/enroll', {
    'kind': 'agent',
    'client_name': clientName,
    'subject': ident.id,
    'public_key': ident.publicKeyB64,
    'tier': tier,
  }) as Map;
  final requestId = resp['request_id'] as String;
  final oob = resp['oob'];
  if (onOob != null) onOob('$oob');

  final deadline = DateTime.now().add(timeout);
  while (DateTime.now().isBefore(deadline)) {
    final q = await httpGetJson('$consoleUrl/enroll/$requestId') as Map;
    final status = q['status'];
    if (status == 'approved') {
      return Enrollment(ident, q['grant'] as Map, root);
    }
    if (status == 'denied') {
      throw StateError('enrollment denied');
    }
    await Future.delayed(const Duration(seconds: 1));
  }
  throw TimeoutException('enrollment not approved within ${timeout.inSeconds}s');
}
