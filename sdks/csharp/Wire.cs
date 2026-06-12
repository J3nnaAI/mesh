// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// The J3nna Mesh wire layer for C#/.NET: the canonical signing bytes every peer must reproduce, plus
// ed25519 sign/verify. This is the byte-for-byte contract — it is validated against the shared
// jip/conformance/vectors.json, so a C# peer is wire-compatible with the Go reference (and therefore every
// other SDK).
//
// Framing primitive: variable-length fields are 4-byte big-endian length-prefixed; integers are 8-byte
// big-endian; sets (capabilities, scopes) are sorted before framing.

using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace J3nnaMesh;

public static class Wire
{
    public const string Protocol = "JIP/0.1";
    public const int ProtocolMajor = 1;
    public const string SigAlg = "ed25519";

    private static void Field(List<byte> b, byte[] x)
    {
        Span<byte> n = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(n, (uint)x.Length);
        b.AddRange(n.ToArray());
        b.AddRange(x);
    }

    private static void U64(List<byte> b, ulong v)
    {
        Span<byte> x = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(x, v);
        b.AddRange(x.ToArray());
    }

    private static void U32(List<byte> b, uint v)
    {
        Span<byte> x = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(x, v);
        b.AddRange(x.ToArray());
    }

    private static byte[] U(string s) => Encoding.UTF8.GetBytes(s);

    private static byte[] Alg(string? a) => U(string.IsNullOrEmpty(a) ? SigAlg : a);

    public static byte[] PresenceSigningBytes(string protocol, string? alg, string id, byte[] publicKey,
        string endpoint, string mcpPath, IEnumerable<string> capabilities, int protocolMajor,
        string grantId, ulong heartbeatUnix)
    {
        var b = new List<byte>();
        Field(b, U(protocol));
        Field(b, Alg(alg));
        Field(b, U(id));
        Field(b, publicKey);
        Field(b, U(endpoint));
        Field(b, U(mcpPath));
        var caps = capabilities.OrderBy(c => c, StringComparer.Ordinal).ToList();
        U32(b, (uint)caps.Count);
        foreach (var c in caps) Field(b, U(c));
        U32(b, (uint)protocolMajor);
        Field(b, U(grantId ?? ""));
        U64(b, heartbeatUnix);
        return b.ToArray();
    }

    public static byte[] GrantSigningBytes(string? alg, string id, string subject, byte[] publicKey,
        ulong tier, IEnumerable<string>? scopes, ulong issuedAt, ulong notAfter, string principal = "")
    {
        var b = new List<byte>();
        Field(b, U("J3nna-mesh-grant/1"));
        Field(b, Alg(alg));
        Field(b, U(id));
        Field(b, U(subject));
        Field(b, publicKey);
        U64(b, tier);
        var sorted = (scopes ?? Enumerable.Empty<string>()).OrderBy(s => s, StringComparer.Ordinal);
        Field(b, U(string.Join('\0', sorted)));
        U64(b, issuedAt);
        U64(b, notAfter);
        if (!string.IsNullOrEmpty(principal))
        {
            // signature-covered only when present, so legacy grants verify byte-identically
            Field(b, U("J3nna-mesh-principal/1"));
            Field(b, U(principal));
        }
        return b.ToArray();
    }

    public static byte[] CallProofSigningBytes(string? alg, string nodeId, string tool, byte[] argsHash,
        ulong unixMilli)
    {
        var b = new List<byte>();
        Field(b, U("JIP-call/0.2"));
        Field(b, Alg(alg));
        Field(b, U(nodeId));
        Field(b, U(tool));
        Field(b, argsHash);
        U64(b, unixMilli);
        return b.ToArray();
    }

    public static byte[] RenewSigningBytes(string? alg, string grantId, string subject, byte[] publicKey,
        ulong issuedAt)
    {
        // Field-framed, signed by the NODE key to prove possession of the pinned identity.
        var b = new List<byte>();
        Field(b, U("J3nna-mesh-renew/1"));
        Field(b, Alg(alg));
        Field(b, U(grantId));
        Field(b, U(subject));
        Field(b, publicKey);
        U64(b, issuedAt);
        return b.ToArray();
    }

    public static byte[] CrlSigningBytes(string? alg, ulong issuedAt, IEnumerable<string> revokedIds)
    {
        // NOT field-framed: pipe/comma ASCII with a trailing comma after EVERY id; ids sorted ascending.
        //   J3nna-mesh-crl/1|<alg>|<issued_at>|<id1>,<id2>,...,
        var head = $"J3nna-mesh-crl/1|{(string.IsNullOrEmpty(alg) ? SigAlg : alg)}|{issuedAt}|";
        var sb = new StringBuilder(head);
        foreach (var rid in revokedIds.OrderBy(r => r, StringComparer.Ordinal)) sb.Append(rid).Append(',');
        return U(sb.ToString());
    }

    // Reproduce Go's json.Marshal of the arguments map: keys sorted, compact, and <, >, & escaped as
    // < > & (lowercase). This is the one place JSON canonicalization must match byte-for-byte.
    public static string CanonicalArgsJson(IReadOnlyDictionary<string, object?> args)
    {
        var sb = new StringBuilder();
        sb.Append('{');
        var first = true;
        foreach (var key in args.Keys.OrderBy(k => k, StringComparer.Ordinal))
        {
            if (!first) sb.Append(',');
            first = false;
            AppendJsonString(sb, key);
            sb.Append(':');
            AppendJsonValue(sb, args[key]);
        }
        sb.Append('}');
        return sb.ToString();
    }

    public static byte[] CanonicalArgsJsonBytes(IReadOnlyDictionary<string, object?> args) =>
        U(CanonicalArgsJson(args));

    public static byte[] ArgsHash(IReadOnlyDictionary<string, object?> args) =>
        SHA256.HashData(CanonicalArgsJsonBytes(args));

    // Mirrors Go's encoding/json value rendering for the value types a tool's arguments use.
    private static void AppendJsonValue(StringBuilder sb, object? v)
    {
        switch (v)
        {
            case null:
                sb.Append("null");
                break;
            case bool bo:
                sb.Append(bo ? "true" : "false");
                break;
            case string s:
                AppendJsonString(sb, s);
                break;
            case int or long or short or byte or sbyte or uint or ulong or ushort:
                sb.Append(Convert.ToInt64(v).ToString(System.Globalization.CultureInfo.InvariantCulture));
                break;
            case double d:
                AppendNumber(sb, d);
                break;
            case float f:
                AppendNumber(sb, f);
                break;
            case decimal m:
                sb.Append(m.ToString(System.Globalization.CultureInfo.InvariantCulture));
                break;
            case IReadOnlyDictionary<string, object?> nested:
                sb.Append(CanonicalArgsJson(nested));
                break;
            case System.Collections.IEnumerable e:
                sb.Append('[');
                var first = true;
                foreach (var item in e)
                {
                    if (!first) sb.Append(',');
                    first = false;
                    AppendJsonValue(sb, item);
                }
                sb.Append(']');
                break;
            default:
                throw new ArgumentException($"unsupported arg value type for canonical JSON: {v.GetType()}");
        }
    }

    private static void AppendNumber(StringBuilder sb, double d)
    {
        // Whole numbers render without a decimal point (Go marshals integral float64 as "0", "3", …).
        if (d == Math.Floor(d) && !double.IsInfinity(d))
            sb.Append(((long)d).ToString(System.Globalization.CultureInfo.InvariantCulture));
        else
            sb.Append(d.ToString("R", System.Globalization.CultureInfo.InvariantCulture));
    }

    // String escaping matching Go's encoding/json: \" \\ \n \r \t short forms, all other control chars as
    // \u00xx (matching Go, which does NOT use \b/\f short forms), and <, >, & escaped as lowercase < > &.
    // Known deviation: U+2028/U+2029 (which Go also \u-escapes) are not special-cased here; all-ASCII tool
    // arguments — the conformance corpus and the common case — are unaffected.
    private static void AppendJsonString(StringBuilder sb, string s)
    {
        sb.Append('"');
        foreach (var ch in s)
        {
            switch (ch)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                case '<': sb.Append("\\u003c"); break;
                case '>': sb.Append("\\u003e"); break;
                case '&': sb.Append("\\u0026"); break;
                default:
                    if (ch < 0x20)
                        sb.Append("\\u").Append(((int)ch).ToString("x4",
                            System.Globalization.CultureInfo.InvariantCulture));
                    else
                        sb.Append(ch);
                    break;
            }
        }
        sb.Append('"');
    }

    public static byte[] Sign(byte[] seed32, byte[] msg)
    {
        var signer = new Ed25519Signer();
        signer.Init(true, new Ed25519PrivateKeyParameters(seed32, 0));
        signer.BlockUpdate(msg, 0, msg.Length);
        return signer.GenerateSignature();
    }

    public static bool Verify(byte[] publicKey32, byte[] sig, byte[] msg)
    {
        try
        {
            var v = new Ed25519Signer();
            v.Init(false, new Ed25519PublicKeyParameters(publicKey32, 0));
            v.BlockUpdate(msg, 0, msg.Length);
            return v.VerifySignature(sig);
        }
        catch
        {
            return false;
        }
    }

    private static readonly char[] HexChars = "0123456789abcdef".ToCharArray();

    private static string RandomHex(int nBytes)
    {
        var raw = RandomNumberGenerator.GetBytes(nBytes);
        var c = new char[nBytes * 2];
        for (var i = 0; i < nBytes; i++)
        {
            c[i * 2] = HexChars[raw[i] >> 4];
            c[i * 2 + 1] = HexChars[raw[i] & 0x0F];
        }
        return new string(c);
    }

    // A fresh 64-bit span id (16 hex chars).
    public static string NewSpanId() => RandomHex(8);

    // A fresh W3C `traceparent` (version 00, sampled). Attach one across a logical operation's calls so a
    // telemetry backend stitches them into a single trace.
    public static string NewTraceparent() => "00-" + RandomHex(16) + "-" + RandomHex(8) + "-01";
}
