// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Node identity: a random v4 UUID plus an ed25519 keypair, persisted in the SAME on-disk format as the Go
// reference so the file is byte-interchangeable — {"id", "priv_b64"} where priv_b64 is base64-std of the
// 64-byte Go private key (32-byte seed ‖ 32-byte public key). The UUID is independent of the key and is what
// a grant binds to, so it must be persisted and reused (regenerating it after enrollment breaks admission).

using System.Text.Json;
using System.Text.Json.Serialization;
using Org.BouncyCastle.Crypto.Parameters;

namespace J3nnaMesh;

public sealed class Identity
{
    public string Id { get; }
    public byte[] Seed { get; }       // 32-byte ed25519 seed (private)
    public byte[] PublicKey { get; }  // 32-byte ed25519 public key

    public Identity(string id, byte[] seed, byte[] publicKey)
    {
        Id = id;
        Seed = seed;
        PublicKey = publicKey;
    }

    public byte[] Sign(byte[] msg) => Wire.Sign(Seed, msg);

    public string PublicKeyB64 => Convert.ToBase64String(PublicKey);

    private sealed class Blob
    {
        [JsonPropertyName("id")] public string Id { get; set; } = "";
        [JsonPropertyName("priv_b64")] public string PrivB64 { get; set; } = "";
    }

    // Load the identity at `path`, or create + persist (0600) a fresh one. Byte-compatible with Go's
    // EnsureIdentity.
    public static Identity Ensure(string path)
    {
        if (File.Exists(path))
        {
            var blob = JsonSerializer.Deserialize<Blob>(File.ReadAllText(path))
                       ?? throw new InvalidDataException("identity file is empty");
            var raw = Convert.FromBase64String(blob.PrivB64);
            if (raw.Length != 64)
                throw new InvalidDataException("identity priv_b64 must decode to 64 bytes (seed||pubkey)");
            return new Identity(blob.Id, raw[..32], raw[32..]);
        }

        var priv = new Ed25519PrivateKeyParameters(new Org.BouncyCastle.Security.SecureRandom());
        var seed = priv.GetEncoded();                       // 32-byte seed
        var pub = priv.GeneratePublicKey().GetEncoded();    // 32-byte public key

        var id = Guid.NewGuid().ToString().ToLowerInvariant();
        var combined = new byte[64];
        Buffer.BlockCopy(seed, 0, combined, 0, 32);
        Buffer.BlockCopy(pub, 0, combined, 32, 32);
        var outBlob = new Blob { Id = id, PrivB64 = Convert.ToBase64String(combined) };

        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        File.WriteAllText(path, JsonSerializer.Serialize(outBlob));
        TrySetOwnerOnlyPermissions(path);

        return new Identity(id, seed, pub);
    }

    private static void TrySetOwnerOnlyPermissions(string path)
    {
        try
        {
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch
        {
            // best-effort; the identity is still written
        }
    }
}
