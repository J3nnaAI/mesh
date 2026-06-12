// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Wire-conformance test for the J3nna Mesh Java SDK. Reproduces the canonical signing bytes byte-for-byte
// THROUGH THE SDK's Wire and verifies the reference signatures from jip/conformance/vectors.json — so this
// SDK is wire-compatible with the Go reference (and every other SDK). Sign-side coverage (the vectors carry
// no private keys) is the Identity round-trip at the end.
//
//   javac -cp gson.jar *.java && java -cp .:gson.jar ConformanceTest

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class ConformanceTest {
    private static String S(JsonObject i, String k) { return i.get(k).getAsString(); }
    private static long N(JsonObject i, String k) { return i.get(k).getAsLong(); }

    private static Path findVectors() {
        String[] candidates = {
                "../../../jip/conformance/vectors.json",
                "../../../../jip/conformance/vectors.json",
                "jip/conformance/vectors.json",
                System.getProperty("user.home") + "/web-stt-tts/jip/conformance/vectors.json",
        };
        for (String c : candidates) {
            Path p = Path.of(c);
            if (Files.exists(p)) return p;
        }
        throw new RuntimeException("vectors.json not found in any candidate path");
    }

    // Build the SDK Wire signing bytes from a vector's input JsonObject.
    private static byte[] presence(JsonObject i) {
        var caps = new ArrayList<String>();
        i.getAsJsonArray("capabilities").forEach(c -> caps.add(c.getAsString()));
        return Wire.presenceSigningBytes(
                S(i, "protocol"), S(i, "alg"), S(i, "id"), Wire.unhex(S(i, "public_key_hex")),
                S(i, "endpoint"), S(i, "mcp_path"), caps, (int) N(i, "protocol_major"),
                S(i, "grant_id"), N(i, "heartbeat_unix"));
    }

    private static byte[] grant(JsonObject i) {
        var scopes = new ArrayList<String>();
        i.getAsJsonArray("scopes").forEach(c -> scopes.add(c.getAsString()));
        String principal = i.has("principal") ? i.get("principal").getAsString() : "";
        return Wire.grantSigningBytes(
                S(i, "alg"), S(i, "id"), S(i, "subject"), Wire.unhex(S(i, "public_key_hex")),
                N(i, "tier"), scopes, N(i, "issued_at"), N(i, "not_after"), principal);
    }

    private static byte[] callproof(JsonObject i) {
        return Wire.callproofSigningBytes(
                S(i, "alg"), S(i, "node_id"), S(i, "tool"), Wire.unhex(S(i, "args_hash_hex")),
                N(i, "unix_milli"));
    }

    private static byte[] renewal(JsonObject i) {
        return Wire.renewSigningBytes(
                S(i, "alg"), S(i, "grant_id"), S(i, "subject"), Wire.unhex(S(i, "public_key_hex")),
                N(i, "issued_at"));
    }

    private static byte[] crl(JsonObject i) {
        var ids = new ArrayList<String>(i.getAsJsonObject("revoked").keySet());
        return Wire.crlSigningBytes(S(i, "alg"), N(i, "issued_at"), ids);
    }

    public static void main(String[] args) throws Exception {
        var doc = JsonParser.parseString(Files.readString(findVectors())).getAsJsonObject();
        if (!doc.get("protocol").getAsString().equals("JIP/0.1")) {
            throw new RuntimeException("unexpected protocol");
        }
        int count = 0;
        for (var ve : doc.getAsJsonArray("vectors")) {
            var v = ve.getAsJsonObject();
            var name = v.get("name").getAsString();
            var i = v.getAsJsonObject("input");
            byte[] got = switch (name) {
                case "presence-record" -> presence(i);
                case "grant" -> grant(i);
                case "callproof" -> callproof(i);
                case "renewal" -> renewal(i);
                case "crl" -> crl(i);
                default -> throw new RuntimeException("no Java builder for " + name);
            };
            if (!Wire.enhex(got).equals(v.get("signing_bytes_hex").getAsString())) {
                throw new RuntimeException(name + ": signing bytes differ");
            }

            var pub = Wire.ed25519Pub(Wire.unhex(v.get("signer_public_key_hex").getAsString()));
            var sig = Base64.getDecoder().decode(v.get("signature_b64").getAsString());
            if (!Wire.verify(pub, sig, got)) {
                throw new RuntimeException(name + ": signature did not verify");
            }

            if (name.equals("callproof")) {
                var cj = Wire.canonicalArgsJson(i.getAsJsonObject("args"));
                if (!cj.equals(S(i, "args_canonical_json"))) {
                    throw new RuntimeException("args canonical JSON differs from Go");
                }
                var h = Wire.enhex(MessageDigest.getInstance("SHA-256").digest(Wire.U(cj)));
                if (!h.equals(S(i, "args_hash_hex"))) {
                    throw new RuntimeException("args hash differs");
                }
                // Cross-check the typed-Map canonicalizer used by the SDK call path.
                var map = new java.util.HashMap<String, Object>();
                map.put("count", 3);
                map.put("html", "<b>a&b</b>");
                map.put("message", "hello/world");
                map.put("path", "/v1/tools");
                if (!Wire.canonicalArgsJson(map).equals(S(i, "args_canonical_json"))) {
                    throw new RuntimeException("typed-map canonical JSON differs from Go");
                }
            }
            System.out.println("  ok  " + name);
            count++;
        }

        // Sign-side coverage: generate an identity, persist it, reload, sign with the persisted key, verify
        // with the persisted public key — catches a wrong-seed-slice bug that verify-only vectors can't.
        identityRoundTrip();

        System.out.println("PASS: " + count
                + " vectors verified + identity round-trip (Java wire-compatible with the Go reference)");
    }

    private static void identityRoundTrip() throws Exception {
        Path tmp = Files.createTempFile("mesh-id-", ".json");
        Files.delete(tmp); // ensureIdentity must create it fresh
        try {
            Identity created = Identity.ensureIdentity(tmp.toString());
            Identity loaded = Identity.ensureIdentity(tmp.toString());
            if (!created.id.equals(loaded.id)) {
                throw new RuntimeException("identity id changed on reload");
            }
            if (!java.util.Arrays.equals(created.seed, loaded.seed)
                    || !java.util.Arrays.equals(created.publicKey, loaded.publicKey)) {
                throw new RuntimeException("identity key bytes changed on reload");
            }
            byte[] msg = "the quick brown fox".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            byte[] sig = loaded.sign(msg);
            if (!Wire.verify(loaded.publicKeyObj(), sig, msg)) {
                throw new RuntimeException("identity sign/verify round-trip failed");
            }
            // Persisted priv_b64 must be exactly 64 bytes (seed||pub) per the Go format.
            var blob = JsonParser.parseString(Files.readString(tmp)).getAsJsonObject();
            byte[] raw = Base64.getDecoder().decode(blob.get("priv_b64").getAsString());
            if (raw.length != 64) {
                throw new RuntimeException("persisted priv_b64 is not 64 bytes");
            }
            System.out.println("  ok  identity-roundtrip (gen→persist→reload→sign→verify)");
        } finally {
            Files.deleteIfExists(tmp);
        }
    }
}
