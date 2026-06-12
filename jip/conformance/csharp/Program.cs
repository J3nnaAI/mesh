// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// J3nna Mesh wire-conformance test for C# / .NET. Reproduces the canonical signing bytes byte-for-byte and
// verifies the reference signatures from ../vectors.json.
//
//   dotnet run        # exits 0 on pass, non-zero on any mismatch

using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

static void Field(List<byte> b, byte[] x)
{
    Span<byte> n = stackalloc byte[4];
    BinaryPrimitives.WriteUInt32BigEndian(n, (uint)x.Length);
    b.AddRange(n.ToArray());
    b.AddRange(x);
}
static void U64(List<byte> b, ulong v)
{
    Span<byte> x = stackalloc byte[8];
    BinaryPrimitives.WriteUInt64BigEndian(x, v);
    b.AddRange(x.ToArray());
}
static void U32(List<byte> b, uint v)
{
    Span<byte> x = stackalloc byte[4];
    BinaryPrimitives.WriteUInt32BigEndian(x, v);
    b.AddRange(x.ToArray());
}
static byte[] U(string s) => Encoding.UTF8.GetBytes(s);
static byte[] Unhex(string s) => Convert.FromHexString(s);
static string Enhex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
static string Str(JsonElement e, string k) => e.GetProperty(k).GetString()!;
static ulong Num(JsonElement e, string k) => (ulong)e.GetProperty(k).GetInt64();

byte[] Presence(JsonElement i)
{
    var b = new List<byte>();
    Field(b, U(Str(i, "protocol")));
    Field(b, U(Str(i, "alg")));
    Field(b, U(Str(i, "id")));
    Field(b, Unhex(Str(i, "public_key_hex")));
    Field(b, U(Str(i, "endpoint")));
    Field(b, U(Str(i, "mcp_path")));
    var caps = i.GetProperty("capabilities").EnumerateArray().Select(c => c.GetString()!).OrderBy(c => c, StringComparer.Ordinal).ToList();
    U32(b, (uint)caps.Count);
    foreach (var c in caps) Field(b, U(c));
    U32(b, (uint)Num(i, "protocol_major"));
    Field(b, U(Str(i, "grant_id")));
    U64(b, Num(i, "heartbeat_unix"));
    return b.ToArray();
}

byte[] Grant(JsonElement i)
{
    var b = new List<byte>();
    Field(b, U("J3nna-mesh-grant/1"));
    Field(b, U(Str(i, "alg")));
    Field(b, U(Str(i, "id")));
    Field(b, U(Str(i, "subject")));
    Field(b, Unhex(Str(i, "public_key_hex")));
    U64(b, Num(i, "tier"));
    var scopes = i.GetProperty("scopes").EnumerateArray().Select(c => c.GetString()!).OrderBy(c => c, StringComparer.Ordinal);
    Field(b, U(string.Join('\0', scopes)));
    U64(b, Num(i, "issued_at"));
    U64(b, Num(i, "not_after"));
    var principal = i.TryGetProperty("principal", out var p) ? p.GetString() ?? "" : "";
    if (principal.Length > 0)
    {
        Field(b, U("J3nna-mesh-principal/1"));
        Field(b, U(principal));
    }
    return b.ToArray();
}

byte[] CallProof(JsonElement i)
{
    var b = new List<byte>();
    Field(b, U("JIP-call/0.2"));
    Field(b, U(Str(i, "alg")));
    Field(b, U(Str(i, "node_id")));
    Field(b, U(Str(i, "tool")));
    Field(b, Unhex(Str(i, "args_hash_hex")));
    U64(b, Num(i, "unix_milli"));
    return b.ToArray();
}

// Match Go's json.Marshal of a map: keys sorted, compact, < > & escaped.
string CanonicalArgsJson(JsonElement args)
{
    var parts = args.EnumerateObject()
        .OrderBy(p => p.Name, StringComparer.Ordinal)
        .Select(p => $"{JsonSerializer.Serialize(p.Name)}:{p.Value.GetRawText()}");
    return ("{" + string.Join(",", parts) + "}")
        .Replace("<", "\\u003c").Replace(">", "\\u003e").Replace("&", "\\u0026");
}

bool Verify(byte[] pub, byte[] msg, byte[] sig)
{
    var v = new Ed25519Signer();
    v.Init(false, new Ed25519PublicKeyParameters(pub, 0));
    v.BlockUpdate(msg, 0, msg.Length);
    return v.VerifySignature(sig);
}

var doc = JsonDocument.Parse(File.ReadAllText("../vectors.json")).RootElement;
if (doc.GetProperty("protocol").GetString() != "JIP/0.1") throw new Exception("unexpected protocol");
int count = 0;
foreach (var v in doc.GetProperty("vectors").EnumerateArray())
{
    var name = v.GetProperty("name").GetString()!;
    var i = v.GetProperty("input");
    var got = name switch
    {
        "presence-record" => Presence(i),
        "grant" => Grant(i),
        "callproof" => CallProof(i),
        _ => throw new Exception($"no C# builder for {name}"),
    };
    if (Enhex(got) != v.GetProperty("signing_bytes_hex").GetString()) throw new Exception($"{name}: signing bytes differ");

    var pub = Unhex(v.GetProperty("signer_public_key_hex").GetString()!);
    var sig = Convert.FromBase64String(v.GetProperty("signature_b64").GetString()!);
    if (!Verify(pub, got, sig)) throw new Exception($"{name}: signature did not verify");

    if (name == "callproof")
    {
        var cj = CanonicalArgsJson(i.GetProperty("args"));
        if (cj != Str(i, "args_canonical_json")) throw new Exception("args canonical JSON differs from Go");
        var h = Enhex(SHA256.HashData(U(cj)));
        if (h != Str(i, "args_hash_hex")) throw new Exception("args hash differs");
    }
    Console.WriteLine($"  ok  {name}");
    count++;
}
Console.WriteLine($"PASS: {count} vectors verified (C#/.NET wire-compatible with the Go reference)");
