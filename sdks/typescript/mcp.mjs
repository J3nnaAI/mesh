// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// MCP tool calls — how a Node peer invokes another peer's tools (and rooms, which are just tools). Builds the
// JSON-RPC tools/call envelope, attaches a signed, arguments-bound CallProof so restricted/identity-bound
// tools authorize the caller, includes the peer's presence as `presenter` on first contact, and optionally a
// W3C `trace` for distributed tracing. Uses the built-in `fetch` (no deps).

import * as wire from "./wire.mjs";

const b64 = (b) => Buffer.from(b).toString("base64");

// A CallProof: the caller signs (domain, alg, node_id, tool, sha256(canonical args), unix_milli) with its
// node key, binding the proof to THIS tool + arguments at THIS time.
export function makeCallproof(ident, tool, args, unixMilli = null) {
  if (unixMilli === null) unixMilli = Date.now();
  const ah = wire.argsHash(args);
  const sb = wire.callproofSigningBytes({
    alg: wire.SIG_ALG, nodeId: ident.id, tool, argsHash: ah, unixMilli,
  });
  return {
    node_id: ident.id,
    tool,
    args_hash: b64(ah),
    unix_milli: unixMilli,
    alg: wire.SIG_ALG,
    signature: b64(ident.sign(sb)),
  };
}

// Invoke `tool` at a peer's MCP URL with a signed CallProof; returns its structuredContent. `presenter`
// (our signed presence) must be included on first contact so the host can resolve our pinned key; `trace`
// propagates a traceparent for telemetry.
export async function callTool(mcpUrl, ident, tool, args, {
  presenter = null, trace = null, timeout = 15000,
} = {}) {
  const params = { name: tool, arguments: args, caller: makeCallproof(ident, tool, args) };
  if (presenter !== null) params.presenter = presenter;
  if (trace) params.trace = trace;
  const body = { jsonrpc: "2.0", id: 1, method: "tools/call", params };

  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeout);
  let resp;
  try {
    const r = await fetch(mcpUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      signal: ctrl.signal,
    });
    resp = await r.json();
  } finally {
    clearTimeout(t);
  }
  if (resp.error) throw new Error(`mcp protocol error: ${JSON.stringify(resp.error)}`);
  const result = resp.result || {};
  if (result.isError) {
    const msg = ((result.content || [{}])[0] || {}).text || "tool error";
    throw new Error(`call rejected: ${msg}`);
  }
  return result.structuredContent || {};
}

export async function listTools(mcpUrl, timeout = 15000) {
  const body = { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} };
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeout);
  try {
    const r = await fetch(mcpUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      signal: ctrl.signal,
    });
    const j = await r.json();
    return (j.result || {}).tools || [];
  } finally {
    clearTimeout(t);
  }
}
