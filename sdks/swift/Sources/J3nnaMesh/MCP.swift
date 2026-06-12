// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// MCP tool calls — how a Swift peer invokes another peer's tools (and rooms, which are just tools). Builds
// the JSON-RPC tools/call envelope, attaches a signed, arguments-bound CallProof so restricted/identity-
// bound tools authorize the caller, includes the peer's presence as `presenter` on first contact, and
// optionally a W3C `trace` for distributed tracing.

import Foundation

public enum MCPError: Error {
    case protocolError(String)
    case rejected(String)
}

public enum MCP {

    /// A CallProof: the caller signs (domain, alg, node_id, tool, sha256(canonical args), unix_milli) with
    /// its node key, binding the proof to THIS tool + arguments at THIS time.
    public static func makeCallproof(ident: Identity, tool: String, args: [String: Any],
                                     unixMilli: UInt64? = nil) throws -> [String: Any] {
        let ms = unixMilli ?? UInt64(Date().timeIntervalSince1970 * 1000)
        let ah = Wire.argsHash(args)
        let sb = Wire.callproofSigningBytes(alg: Wire.SIG_ALG, nodeID: ident.id, tool: tool,
                                            argsHash: ah, unixMilli: ms)
        let sig = try ident.sign(sb)
        return [
            "node_id": ident.id,
            "tool": tool,
            "args_hash": ah.b64Std,
            "unix_milli": ms,
            "alg": Wire.SIG_ALG,
            "signature": sig.b64Std,
        ]
    }

    /// Invoke `tool` at a peer's MCP URL with a signed CallProof; returns its structuredContent.
    /// `presenter` (our signed presence) must be included on first contact so the host can resolve our
    /// pinned key; `trace` propagates a traceparent for telemetry.
    @discardableResult
    public static func callTool(mcpURL: String, ident: Identity, tool: String, args: [String: Any],
                                presenter: [String: Any]? = nil, trace: String? = nil,
                                timeout: TimeInterval = 15) throws -> [String: Any] {
        var params: [String: Any] = [
            "name": tool,
            "arguments": args,
            "caller": try makeCallproof(ident: ident, tool: tool, args: args),
        ]
        if let presenter = presenter { params["presenter"] = presenter }
        if let trace = trace { params["trace"] = trace }
        let body: [String: Any] = ["jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params]
        let resp = try HTTP.postJSON(mcpURL, body, timeout: timeout)
        if let err = resp["error"] {
            throw MCPError.protocolError("\(err)")
        }
        let result = resp["result"] as? [String: Any] ?? [:]
        if let isError = result["isError"] as? Bool, isError {
            var msg = "tool error"
            if let content = result["content"] as? [[String: Any]],
               let first = content.first, let text = first["text"] as? String {
                msg = text
            }
            throw MCPError.rejected(msg)
        }
        return result["structuredContent"] as? [String: Any] ?? [:]
    }

    public static func listTools(mcpURL: String, timeout: TimeInterval = 15) throws -> [[String: Any]] {
        let body: [String: Any] = ["jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": [:]]
        let resp = try HTTP.postJSON(mcpURL, body, timeout: timeout)
        let result = resp["result"] as? [String: Any] ?? [:]
        return result["tools"] as? [[String: Any]] ?? []
    }
}
