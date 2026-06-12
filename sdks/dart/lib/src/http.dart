// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Minimal JSON-over-HTTP helpers on dart:io HttpClient, shared by enroll/discovery/mcp.

import 'dart:async';
import 'dart:convert';
import 'dart:io';

final HttpClient _client = HttpClient();

Future<dynamic> httpGetJson(String url, {Duration timeout = const Duration(seconds: 10)}) async {
  final req = await _client.getUrl(Uri.parse(url));
  final resp = await req.close().timeout(timeout);
  final body = await resp.transform(utf8.decoder).join();
  return jsonDecode(body);
}

Future<dynamic> httpPostJson(String url, Object obj,
    {Duration timeout = const Duration(seconds: 10)}) async {
  final req = await _client.postUrl(Uri.parse(url));
  req.headers.set(HttpHeaders.contentTypeHeader, 'application/json');
  req.add(utf8.encode(jsonEncode(obj)));
  final resp = await req.close().timeout(timeout);
  final body = await resp.transform(utf8.decoder).join();
  return jsonDecode(body);
}
