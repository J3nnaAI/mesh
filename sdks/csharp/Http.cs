// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Minimal JSON-over-HTTP helpers shared by Enroll, Discovery, and Mcp. Returns parsed JsonElement trees so
// the SDK can read the loosely-typed console/gossip/JSON-RPC responses without bespoke DTOs.

using System.Text;
using System.Text.Json;

namespace J3nnaMesh;

internal static class Http
{
    private static readonly HttpClient Client = new();

    public static JsonElement Get(string url, TimeSpan timeout)
    {
        using var cts = new CancellationTokenSource(timeout);
        using var resp = Client.GetAsync(url, cts.Token).GetAwaiter().GetResult();
        resp.EnsureSuccessStatusCode();
        var body = resp.Content.ReadAsStringAsync(cts.Token).GetAwaiter().GetResult();
        return JsonDocument.Parse(body).RootElement.Clone();
    }

    public static JsonElement PostJson(string url, string json, TimeSpan timeout)
    {
        using var cts = new CancellationTokenSource(timeout);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var resp = Client.PostAsync(url, content, cts.Token).GetAwaiter().GetResult();
        resp.EnsureSuccessStatusCode();
        var body = resp.Content.ReadAsStringAsync(cts.Token).GetAwaiter().GetResult();
        return JsonDocument.Parse(body).RootElement.Clone();
    }
}
