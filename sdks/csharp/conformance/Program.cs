// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// J3nna Mesh wire-conformance test for the C#/.NET SDK. Reproduces the canonical signing bytes byte-for-byte
// THROUGH the SDK's J3nnaMesh.Wire (not a private copy), and verifies the reference signatures from
// jip/conformance/vectors.json — proving the shipped SDK is wire-compatible with the Go reference.
//
//   dotnet run        # exits 0 on pass, non-zero on any mismatch

using System.Text.Json;
using J3nnaMesh;

static byte[] Unhex(string s) => Convert.FromHexString(s);
static string Enhex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
static string Str(JsonElement e, string k) => e.GetProperty(k).GetString()!;
static ulong Num(JsonElement e, string k) => (ulong)e.GetProperty(k).GetInt64();

byte[] Presence(JsonElement i) => Wire.PresenceSigningBytes(
    Str(i, "protocol"), Str(i, "alg"), Str(i, "id"), Unhex(Str(i, "public_key_hex")),
    Str(i, "endpoint"), Str(i, "mcp_path"),
    i.GetProperty("capabilities").EnumerateArray().Select(c => c.GetString()!),
    (int)Num(i, "protocol_major"), Str(i, "grant_id"), Num(i, "heartbeat_unix"));

byte[] Grant(JsonElement i) => Wire.GrantSigningBytes(
    Str(i, "alg"), Str(i, "id"), Str(i, "subject"), Unhex(Str(i, "public_key_hex")),
    Num(i, "tier"),
    i.GetProperty("scopes").EnumerateArray().Select(c => c.GetString()!),
    Num(i, "issued_at"), Num(i, "not_after"),
    i.TryGetProperty("principal", out var p) ? p.GetString() ?? "" : "");

byte[] CallProof(JsonElement i) => Wire.CallProofSigningBytes(
    Str(i, "alg"), Str(i, "node_id"), Str(i, "tool"),
    Unhex(Str(i, "args_hash_hex")), Num(i, "unix_milli"));

byte[] Renewal(JsonElement i) => Wire.RenewSigningBytes(
    Str(i, "alg"), Str(i, "grant_id"), Str(i, "subject"),
    Unhex(Str(i, "public_key_hex")), Num(i, "issued_at"));

byte[] Crl(JsonElement i) => Wire.CrlSigningBytes(
    Str(i, "alg"), Num(i, "issued_at"),
    i.GetProperty("revoked").EnumerateObject().Select(p => p.Name));

// Parse the JSON `args` object into the loosely-typed dictionary the SDK's CanonicalArgsJson consumes, so we
// exercise the SAME code path a live caller would (not JsonElement.GetRawText).
static Dictionary<string, object?> ParseArgs(JsonElement args)
{
    var d = new Dictionary<string, object?>();
    foreach (var p in args.EnumerateObject()) d[p.Name] = ParseValue(p.Value);
    return d;
}

static object? ParseValue(JsonElement e) => e.ValueKind switch
{
    JsonValueKind.String => e.GetString(),
    JsonValueKind.True => true,
    JsonValueKind.False => false,
    JsonValueKind.Null => null,
    JsonValueKind.Number => e.TryGetInt64(out var l) ? l : e.GetDouble(),
    JsonValueKind.Object => e.EnumerateObject().ToDictionary(p => p.Name, p => ParseValue(p.Value)),
    JsonValueKind.Array => e.EnumerateArray().Select(ParseValue).ToList(),
    _ => throw new Exception($"unsupported arg value kind {e.ValueKind}"),
};

// vectors.json is the shared cross-language fixture; it lives at <repo>/jip/conformance/vectors.json. Allow
// an override, otherwise walk up from the binary to find the jip/ sibling tree.
static string FindVectors()
{
    var env = Environment.GetEnvironmentVariable("JIP_VECTORS");
    if (!string.IsNullOrEmpty(env) && File.Exists(env)) return env;

    var dir = new DirectoryInfo(AppContext.BaseDirectory);
    while (dir != null)
    {
        var candidate = Path.Combine(dir.FullName, "jip", "conformance", "vectors.json");
        if (File.Exists(candidate)) return candidate;
        dir = dir.Parent;
    }
    throw new FileNotFoundException("could not locate jip/conformance/vectors.json (set JIP_VECTORS)");
}

var vectorsPath = FindVectors();
var doc = JsonDocument.Parse(File.ReadAllText(vectorsPath)).RootElement;
if (doc.GetProperty("protocol").GetString() != "JIP/0.1") throw new Exception("unexpected protocol");

var count = 0;
foreach (var v in doc.GetProperty("vectors").EnumerateArray())
{
    var name = v.GetProperty("name").GetString()!;
    var i = v.GetProperty("input");
    var got = name switch
    {
        "presence-record" => Presence(i),
        "grant" => Grant(i),
        "callproof" => CallProof(i),
        "renewal" => Renewal(i),
        "crl" => Crl(i),
        _ => throw new Exception($"no C# builder for {name}"),
    };
    if (Enhex(got) != v.GetProperty("signing_bytes_hex").GetString())
        throw new Exception($"{name}: signing bytes differ");

    var pub = Unhex(v.GetProperty("signer_public_key_hex").GetString()!);
    var sig = Convert.FromBase64String(v.GetProperty("signature_b64").GetString()!);
    if (!Wire.Verify(pub, sig, got))
        throw new Exception($"{name}: signature did not verify");

    if (name == "callproof")
    {
        var parsed = ParseArgs(i.GetProperty("args"));
        var cj = Wire.CanonicalArgsJson(parsed);
        if (cj != Str(i, "args_canonical_json"))
            throw new Exception($"args canonical JSON differs from Go: got {cj}");
        var h = Enhex(Wire.ArgsHash(parsed));
        if (h != Str(i, "args_hash_hex"))
            throw new Exception("args hash differs");
    }
    Console.WriteLine($"  ok  {name}");
    count++;
}
// Round-trip self-test: the vectors verify the SDK's *verify* path against fixed keys, but carry no private
// seeds — so they never exercise Identity key generation, the on-disk format, or Wire.Sign. Prove those
// offline: create a fresh identity, sign through it, verify, and confirm the persisted file is the 64-byte
// (seed‖pub) Go-compatible blob with a stable id.
{
    var tmp = Path.Combine(Path.GetTempPath(), $"j3nna-selftest-{Guid.NewGuid():N}.id");
    try
    {
        var ident = Identity.Ensure(tmp);
        var msg = System.Text.Encoding.UTF8.GetBytes("round-trip");
        var sig = ident.Sign(msg);
        if (!Wire.Verify(ident.PublicKey, sig, msg))
            throw new Exception("self-test: fresh identity's signature did not verify");

        var reloaded = Identity.Ensure(tmp); // load path
        if (reloaded.Id != ident.Id) throw new Exception("self-test: id changed across reload");
        if (reloaded.Seed.Length != 32 || reloaded.PublicKey.Length != 32)
            throw new Exception("self-test: reloaded key is not 32-byte seed/pub");
        if (!reloaded.PublicKey.AsSpan().SequenceEqual(ident.PublicKey))
            throw new Exception("self-test: reloaded public key differs");
        if (!Wire.Verify(reloaded.PublicKey, reloaded.Sign(msg), msg))
            throw new Exception("self-test: reloaded identity's signature did not verify");

        var blob = JsonDocument.Parse(File.ReadAllText(tmp)).RootElement;
        if (Convert.FromBase64String(blob.GetProperty("priv_b64").GetString()!).Length != 64)
            throw new Exception("self-test: on-disk priv_b64 is not 64 bytes (seed||pub)");
        Console.WriteLine("  ok  identity-sign-roundtrip");
    }
    finally
    {
        if (File.Exists(tmp)) File.Delete(tmp);
    }
}

Console.WriteLine($"PASS: {count} vectors verified + identity/sign round-trip (C#/.NET SDK wire-compatible with the Go reference)");
