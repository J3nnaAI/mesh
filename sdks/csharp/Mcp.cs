// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// MCP tool calls — how a C# peer invokes another peer's tools (and rooms, which are just tools). Builds the
// JSON-RPC tools/call envelope, attaches a signed, arguments-bound CallProof so restricted/identity-bound
// tools authorize the caller, includes the peer's presence as `presenter` on first contact, and optionally a
// W3C `trace` for distributed tracing.

using System.Text.Json;
using System.Text.Json.Nodes;

namespace J3nnaMesh;

public sealed class McpError : Exception
{
    public McpError(string message) : base(message) { }
}

public static class Mcp
{
    private static readonly TimeSpan CallTimeout = TimeSpan.FromSeconds(15);

    // A CallProof: the caller signs (domain, alg, node_id, tool, sha256(canonical args), unix_milli) with its
    // node key, binding the proof to THIS tool + arguments at THIS time.
    public static JsonObject MakeCallProof(Identity ident, string tool,
        IReadOnlyDictionary<string, object?> args, long? unixMilli = null)
    {
        var ms = unixMilli ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var ah = Wire.ArgsHash(args);
        var sb = Wire.CallProofSigningBytes(Wire.SigAlg, ident.Id, tool, ah, (ulong)ms);
        return new JsonObject
        {
            ["node_id"] = ident.Id,
            ["tool"] = tool,
            ["args_hash"] = Convert.ToBase64String(ah),
            ["unix_milli"] = ms,
            ["alg"] = Wire.SigAlg,
            ["signature"] = Convert.ToBase64String(ident.Sign(sb)),
        };
    }

    // Invoke `tool` at a peer's MCP URL with a signed CallProof; returns its structuredContent. `presenter`
    // (our signed presence) must be included on first contact so the host can resolve our pinned key; `trace`
    // propagates a traceparent for telemetry.
    public static JsonElement CallTool(string mcpUrl, Identity ident, string tool,
        IReadOnlyDictionary<string, object?> args, PresenceRecord? presenter = null, string? trace = null)
    {
        var argsNode = ToJsonNode(args);
        var prms = new JsonObject
        {
            ["name"] = tool,
            ["arguments"] = argsNode,
            ["caller"] = MakeCallProof(ident, tool, args),
        };
        if (presenter != null) prms["presenter"] = presenter.ToJson();
        if (!string.IsNullOrEmpty(trace)) prms["trace"] = trace;

        var body = new JsonObject
        {
            ["jsonrpc"] = "2.0",
            ["id"] = 1,
            ["method"] = "tools/call",
            ["params"] = prms,
        };

        var resp = Http.PostJson(mcpUrl, body.ToJsonString(), CallTimeout);
        if (resp.TryGetProperty("error", out var err))
            throw new McpError($"mcp protocol error: {err.GetRawText()}");
        if (!resp.TryGetProperty("result", out var result))
            return JsonDocument.Parse("{}").RootElement.Clone();
        if (result.TryGetProperty("isError", out var isErr) && isErr.ValueKind == JsonValueKind.True)
        {
            var msg = "tool error";
            if (result.TryGetProperty("content", out var content) &&
                content.ValueKind == JsonValueKind.Array && content.GetArrayLength() > 0 &&
                content[0].TryGetProperty("text", out var t))
                msg = t.GetString() ?? msg;
            throw new McpError($"call rejected: {msg}");
        }
        return result.TryGetProperty("structuredContent", out var sc)
            ? sc.Clone()
            : JsonDocument.Parse("{}").RootElement.Clone();
    }

    public static List<JsonElement> ListTools(string mcpUrl)
    {
        var body = new JsonObject
        {
            ["jsonrpc"] = "2.0",
            ["id"] = 1,
            ["method"] = "tools/list",
            ["params"] = new JsonObject(),
        };
        var resp = Http.PostJson(mcpUrl, body.ToJsonString(), CallTimeout);
        var tools = new List<JsonElement>();
        if (resp.TryGetProperty("result", out var result) &&
            result.TryGetProperty("tools", out var ts) && ts.ValueKind == JsonValueKind.Array)
            foreach (var t in ts.EnumerateArray()) tools.Add(t.Clone());
        return tools;
    }

    private static JsonNode? ToJsonNode(object? v)
    {
        switch (v)
        {
            case null: return null;
            case string s: return JsonValue.Create(s);
            case bool b: return JsonValue.Create(b);
            case int i: return JsonValue.Create(i);
            case long l: return JsonValue.Create(l);
            case double d: return JsonValue.Create(d);
            case float f: return JsonValue.Create(f);
            case decimal m: return JsonValue.Create(m);
            case IReadOnlyDictionary<string, object?> dict:
                var obj = new JsonObject();
                foreach (var kv in dict) obj[kv.Key] = ToJsonNode(kv.Value);
                return obj;
            case System.Collections.IEnumerable e:
                var arr = new JsonArray();
                foreach (var item in e) arr.Add(ToJsonNode(item));
                return arr;
            default:
                return JsonValue.Create(v.ToString());
        }
    }
}
