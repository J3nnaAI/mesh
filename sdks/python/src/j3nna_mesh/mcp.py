# Copyright 2026 J3nna Technologies, LLC
# SPDX-License-Identifier: Apache-2.0
"""MCP tool calls — how a Python peer invokes another peer's tools (and rooms, which are just tools). Builds
the JSON-RPC tools/call envelope, attaches a signed, arguments-bound CallProof so restricted/identity-bound
tools authorize the caller, includes the peer's presence as `presenter` on first contact, and optionally a
W3C `trace` for distributed tracing. Stdlib-only (urllib)."""

import base64
import json
import time
import urllib.request

from . import wire


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def make_callproof(ident, tool: str, args: dict, unix_milli: int = None) -> dict:
    """A CallProof: the caller signs (domain, alg, node_id, tool, sha256(canonical args), unix_milli) with
    its node key, binding the proof to THIS tool + arguments at THIS time."""
    if unix_milli is None:
        unix_milli = int(time.time() * 1000)
    ah = wire.args_hash(args)
    sb = wire.callproof_signing_bytes(alg=wire.SIG_ALG, node_id=ident.id, tool=tool,
                                      args_hash=ah, unix_milli=unix_milli)
    return {
        "node_id": ident.id, "tool": tool, "args_hash": _b64(ah),
        "unix_milli": unix_milli, "alg": wire.SIG_ALG, "signature": _b64(ident.sign(sb)),
    }


def call_tool(mcp_url: str, ident, tool: str, args: dict, presenter: dict = None,
              trace: str = None, timeout: float = 15) -> dict:
    """Invoke `tool` at a peer's MCP URL with a signed CallProof; returns its structuredContent. `presenter`
    (our signed presence) must be included on first contact so the host can resolve our pinned key; `trace`
    propagates a traceparent for telemetry."""
    params = {"name": tool, "arguments": args, "caller": make_callproof(ident, tool, args)}
    if presenter is not None:
        params["presenter"] = presenter
    if trace:
        params["trace"] = trace
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params}
    req = urllib.request.Request(mcp_url, data=json.dumps(body).encode(),
                                 headers={"content-type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        resp = json.load(r)
    if "error" in resp:
        raise RuntimeError(f"mcp protocol error: {resp['error']}")
    result = resp.get("result", {})
    if result.get("isError"):
        msg = (result.get("content") or [{}])[0].get("text", "tool error")
        raise RuntimeError(f"call rejected: {msg}")
    return result.get("structuredContent", {})


def list_tools(mcp_url: str, timeout: float = 15) -> list:
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    req = urllib.request.Request(mcp_url, data=json.dumps(body).encode(),
                                 headers={"content-type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r).get("result", {}).get("tools", [])
