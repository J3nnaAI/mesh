// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Enrollment with the console — the four-call HTTP flow that turns a fresh identity into a signed grant:
// fetch the authority root, POST /enroll, surface the out-of-band code for an operator to confirm, then poll
// GET /enroll/<id> until the signed grant comes back. The console is the root of trust; after this the peer
// runs on cached credentials and never needs it on the hot path.

using System.Text.Json;

namespace J3nnaMesh;

public static class Enroll
{
    private static readonly TimeSpan HttpTimeout = TimeSpan.FromSeconds(10);

    public sealed record EnrollResult(Identity Identity, JsonElement Grant, byte[] Root);

    // The authority root public key — the offline-verification key for every grant and CRL.
    public static byte[] FetchRoot(string consoleUrl, int retries = 10)
    {
        Exception? last = null;
        for (var i = 0; i < retries; i++)
        {
            try
            {
                var doc = Http.Get(consoleUrl.TrimEnd('/') + "/authority", HttpTimeout);
                return Convert.FromBase64String(doc.GetProperty("root_public_key").GetString()!);
            }
            catch (Exception e) // console may not be up yet
            {
                last = e;
                Thread.Sleep(2000);
            }
        }
        throw last ?? new InvalidOperationException("unable to fetch authority root");
    }

    // Enroll an agent. Returns (Identity, grant, root). Blocks until an operator approves the request
    // out-of-band (the console then returns the signed grant), or throws on denial/timeout.
    public static EnrollResult Run(string consoleUrl, string clientName, string identityPath,
        int tier = 1, Action<string>? onOob = null, double timeoutSeconds = 120)
    {
        consoleUrl = consoleUrl.TrimEnd('/');
        var ident = Identity.Ensure(identityPath);
        var root = FetchRoot(consoleUrl);

        var reqBody = JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["kind"] = "agent",
            ["client_name"] = clientName,
            ["subject"] = ident.Id,
            ["public_key"] = ident.PublicKeyB64,
            ["tier"] = tier,
        });
        var resp = Http.PostJson(consoleUrl + "/enroll", reqBody, HttpTimeout);
        var requestId = resp.GetProperty("request_id").GetString()!;
        var oob = resp.GetProperty("oob").GetString()!;
        onOob?.Invoke(oob);

        var deadline = DateTime.UtcNow.AddSeconds(timeoutSeconds);
        while (DateTime.UtcNow < deadline)
        {
            var q = Http.Get($"{consoleUrl}/enroll/{requestId}", HttpTimeout);
            var status = q.TryGetProperty("status", out var s) ? s.GetString() : null;
            if (status == "approved")
                return new EnrollResult(ident, q.GetProperty("grant").Clone(), root);
            if (status == "denied")
                throw new InvalidOperationException("enrollment denied");
            Thread.Sleep(1000);
        }
        throw new TimeoutException($"enrollment not approved within {timeoutSeconds:0}s");
    }
}
