// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Discovery — how a C# peer finds others on the mesh. It builds and signs its own presence record (carrying
// its grant), gossips it to seed peers' /gossip endpoints, and receives their presence in return. Every
// received record is verified offline (self-signature, and — under an authority root — its grant), so a peer
// admits only authorized peers.

using System.Text.Json;
using System.Text.Json.Nodes;

namespace J3nnaMesh;

public sealed class Peer
{
    public string Id { get; }
    public string Mcp { get; }     // the peer's reachable MCP URL (endpoint + mcp_path)
    public List<string> Caps { get; }

    public Peer(string id, string mcp, List<string> caps)
    {
        Id = id;
        Mcp = mcp;
        Caps = caps;
    }

    public override string ToString() =>
        $"Peer(id={Id[..Math.Min(8, Id.Length)]}…, caps=[{string.Join(",", Caps)}], mcp={Mcp})";
}

// A signed presence record: the JSON `payload` object (carrying the embedded grant verbatim) plus its
// ed25519 `signature`. Held as a JsonObject so the grant round-trips byte-faithfully through gossip.
public sealed class PresenceRecord
{
    public JsonObject Payload { get; }
    public string SignatureB64 { get; }

    public PresenceRecord(JsonObject payload, string signatureB64)
    {
        Payload = payload;
        SignatureB64 = signatureB64;
    }

    public string Id => Payload["id"]!.GetValue<string>();
    public long HeartbeatUnix => Payload["heartbeat_unix"]!.GetValue<long>();

    public JsonObject ToJson() => new()
    {
        ["payload"] = Payload.DeepClone(),
        ["signature"] = SignatureB64,
    };

    public static PresenceRecord FromJson(JsonObject obj)
    {
        var payload = (JsonObject)obj["payload"]!.DeepClone();
        var sig = obj["signature"]!.GetValue<string>();
        return new PresenceRecord(payload, sig);
    }
}

public static class Discovery
{
    private static readonly TimeSpan GossipTimeout = TimeSpan.FromSeconds(10);

    // Build this peer's signed PresenceRecord (payload + ed25519 signature over the canonical bytes). `grant`
    // is the verbatim grant object the console returned.
    public static PresenceRecord BuildPresence(Identity ident, JsonElement grant, string endpoint,
        IEnumerable<string> caps, long? heartbeat = null, string mcpPath = "/mcp")
    {
        var hb = heartbeat ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var capList = caps.ToList();

        var capsArr = new JsonArray();
        foreach (var c in capList) capsArr.Add(c);

        var payload = new JsonObject
        {
            ["protocol"] = Wire.Protocol,
            ["id"] = ident.Id,
            ["public_key"] = Convert.ToBase64String(ident.PublicKey),
            ["endpoint"] = endpoint,
            ["mcp_path"] = mcpPath,
            ["capabilities"] = capsArr,
            ["heartbeat_unix"] = hb,
            ["protocol_major"] = Wire.ProtocolMajor,
            ["grant"] = JsonNode.Parse(grant.GetRawText()),
            ["alg"] = Wire.SigAlg,
        };

        var grantId = grant.TryGetProperty("id", out var gid) ? gid.GetString() ?? "" : "";
        var sb = Wire.PresenceSigningBytes(Wire.Protocol, Wire.SigAlg, ident.Id, ident.PublicKey,
            endpoint, mcpPath, capList, Wire.ProtocolMajor, grantId, (ulong)hb);
        return new PresenceRecord(payload, Convert.ToBase64String(ident.Sign(sb)));
    }

    // Verify a presence record's self-signature; with `root` set, also verify its grant binds id↔key and is
    // authority-signed (the admission check).
    public static bool VerifyRecord(PresenceRecord rec, byte[]? root = null)
    {
        var p = rec.Payload;
        var pub = Convert.FromBase64String(p["public_key"]!.GetValue<string>());
        var caps = p["capabilities"] is JsonArray ca
            ? ca.Select(n => n!.GetValue<string>()).ToList()
            : new List<string>();
        var grant = p["grant"] as JsonObject;
        var grantId = grant?["id"]?.GetValue<string>() ?? "";

        var sb = Wire.PresenceSigningBytes(
            p["protocol"]!.GetValue<string>(),
            p["alg"]?.GetValue<string>() ?? "",
            p["id"]!.GetValue<string>(),
            pub,
            p["endpoint"]!.GetValue<string>(),
            p["mcp_path"]!.GetValue<string>(),
            caps,
            p["protocol_major"]?.GetValue<int>() ?? 0,
            grantId,
            (ulong)p["heartbeat_unix"]!.GetValue<long>());

        if (!Wire.Verify(pub, Convert.FromBase64String(rec.SignatureB64), sb))
            return false;
        if (root == null)
            return true;

        if (grant == null)
            return false;
        if (grant["subject"]?.GetValue<string>() != p["id"]!.GetValue<string>())
            return false;
        var grantPub = Convert.FromBase64String(grant["public_key"]!.GetValue<string>());
        if (!grantPub.AsSpan().SequenceEqual(pub))
            return false;

        var scopes = grant["scopes"] is JsonArray sa
            ? sa.Select(n => n!.GetValue<string>()).ToList()
            : new List<string>();
        var principal = grant["principal"]?.GetValue<string>() ?? "";
        var gb = Wire.GrantSigningBytes(
            grant["alg"]?.GetValue<string>() ?? "",
            grant["id"]!.GetValue<string>(),
            grant["subject"]!.GetValue<string>(),
            grantPub,
            (ulong)grant["tier"]!.GetValue<long>(),
            scopes,
            (ulong)grant["issued_at"]!.GetValue<long>(),
            (ulong)grant["not_after"]!.GetValue<long>(),
            principal);
        return Wire.Verify(root, Convert.FromBase64String(grant["signature"]!.GetValue<string>()), gb);
    }

    private static List<PresenceRecord> GossipOnce(string seedBase, PresenceRecord myRecord)
    {
        var my = myRecord.Payload;
        var digest = new JsonObject { [my["id"]!.GetValue<string>()] = my["heartbeat_unix"]!.GetValue<long>() };
        var records = new JsonArray { myRecord.ToJson() };
        var env = new JsonObject
        {
            ["protocol"] = Wire.Protocol,
            ["digest"] = digest,
            ["records"] = records,
        };
        var resp = Http.PostJson(seedBase.TrimEnd('/') + "/gossip", env.ToJsonString(), GossipTimeout);
        var outRecs = new List<PresenceRecord>();
        if (resp.TryGetProperty("records", out var recs) && recs.ValueKind == JsonValueKind.Array)
        {
            foreach (var r in recs.EnumerateArray())
            {
                var obj = JsonNode.Parse(r.GetRawText()) as JsonObject;
                if (obj != null) outRecs.Add(PresenceRecord.FromJson(obj));
            }
        }
        return outRecs;
    }

    // Gossip our presence to each seed and return the verified peers learned (excluding self), optionally
    // filtered to those advertising `wantCap`.
    public static List<Peer> Discover(IEnumerable<string> seeds, PresenceRecord myRecord,
        byte[]? root = null, string? wantCap = null)
    {
        var myId = myRecord.Id;
        var peers = new Dictionary<string, Peer>();
        foreach (var seed in seeds)
        {
            List<PresenceRecord> records;
            try
            {
                records = GossipOnce(seed, myRecord);
            }
            catch
            {
                continue;
            }
            foreach (var rec in records)
            {
                var p = rec.Payload;
                var pid = p["id"]!.GetValue<string>();
                if (pid == myId || !VerifyRecord(rec, root))
                    continue;
                var caps = p["capabilities"] is JsonArray ca
                    ? ca.Select(n => n!.GetValue<string>()).ToList()
                    : new List<string>();
                if (wantCap != null && !caps.Contains(wantCap))
                    continue;
                var mcp = p["endpoint"]!.GetValue<string>().TrimEnd('/') + p["mcp_path"]!.GetValue<string>();
                peers[pid] = new Peer(pid, mcp, caps);
            }
        }
        return peers.Values.ToList();
    }
}
