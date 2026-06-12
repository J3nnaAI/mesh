// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// A J3nna Mesh peer in Dart — the full authorized-collaboration loop, mirroring samples/joiner (Go) and the
// other SDKs' joiners:
//
//     enroll with the console   ->  receive a signed grant + the authority root
//     discover a 'rooms' peer    ->  the room agent, found over gossip (not hardcoded)
//     join its room + post       ->  collaborate, all authorized, with one trace for telemetry
//
// Run a console and a room-agent first, then this; approve the enrollment in the console (match the
// out-of-band code it prints). Built on the j3nna_mesh SDK.
//
//     dart run bin/joiner.dart

import 'dart:io';

import 'package:j3nna_mesh/j3nna_mesh.dart';

String _env(String k, String d) => Platform.environment[k] ?? d;
String _short(String s) => s.length >= 8 ? s.substring(0, 8) : s;

Future<void> main() async {
  final console = _env('SAMPLE_CONSOLE', 'http://127.0.0.1:18455');
  final seeds = _env('SAMPLE_SEEDS', 'http://127.0.0.1:18482')
      .split(',')
      .map((s) => s.trim())
      .where((s) => s.isNotEmpty)
      .toList();
  final room = _env('SAMPLE_ROOM', 'lobby');
  final name = _env('SAMPLE_NAME', 'dart-joiner');
  final idPath = _env('SAMPLE_IDENTITY', 'dart-joiner.id');
  // A client-only peer: it polls history, so its advertised endpoint need not be reachable.
  final endpoint = _env('SAMPLE_ADVERTISE', 'http://127.0.0.1:1/');

  stdout.writeln('joiner: enrolling with console $console …');
  final Enrollment en;
  try {
    en = await enroll(
      console,
      name,
      idPath,
      tier: 1,
      onOob: (oob) => stdout.writeln(
          'joiner: APPROVE this enrollment in the console — out-of-band code $oob'),
    );
  } catch (e) {
    stderr.writeln('joiner: enrollment failed: $e');
    exit(1);
  }
  stdout.writeln('joiner: enrolled — grant ${_short('${en.grant['id'] ?? ''}')}…');

  final record = await buildPresence(en.identity, en.grant, endpoint, ['sample']);

  Peer? host;
  for (var i = 0; i < 30; i++) {
    final peers = await discover(seeds, record, root: en.root, wantCap: 'rooms');
    if (peers.isNotEmpty) {
      host = peers.first;
      break;
    }
    await Future.delayed(const Duration(seconds: 1));
  }
  if (host == null) {
    stderr.writeln('joiner: no authorized room agent discovered on the mesh');
    exit(1);
  }
  stdout.writeln('joiner: discovered room agent at ${host.mcp} — joining #$room');

  // One trace for the whole session — so a telemetry backend stitches these calls into one operation.
  final trace = newTraceparent();
  await join(host.mcp, en.identity, room, name, endpoint, presenter: record, trace: trace);
  await post(
    host.mcp,
    en.identity,
    room,
    'hello from $name — Dart peer, authorized and present.',
    presenter: record,
    trace: trace,
  );
  final hist = await history(host.mcp, en.identity, room, since: 0, presenter: record, trace: trace);

  final msgs = (hist['messages'] as List?) ?? [];
  stdout.writeln('joiner: #$room has ${msgs.length} message(s):');
  for (final m in msgs) {
    final text = '${(m as Map)['text'] ?? ''}';
    if (text.trim().isEmpty) continue;
    stdout.writeln('joiner:   ${_short('${m['from'] ?? ''}')}: $text');
  }
  stdout.writeln('joiner: collaboration loop complete — trace ${trace.substring(3, 11)}');
}
