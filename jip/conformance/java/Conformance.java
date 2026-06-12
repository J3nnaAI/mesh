// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// J3nna Mesh wire-conformance test for Java / the JVM (also serves Kotlin, Scala, Clojure via interop).
// Reproduces the canonical signing bytes byte-for-byte and verifies the reference signatures from
// ../vectors.json. ed25519 is built into the JDK (15+); JSON via gson.
//
//   javac -cp gson.jar Conformance.java && java -cp .:gson.jar Conformance

import com.google.gson.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class Conformance {
    static void field(ByteArrayOutputStream b, byte[] x) throws IOException {
        b.write(ByteBuffer.allocate(4).putInt(x.length).array());
        b.write(x);
    }
    static void u64(ByteArrayOutputStream b, long v) { b.write(ByteBuffer.allocate(8).putLong(v).array(), 0, 8); }
    static void u32(ByteArrayOutputStream b, int v) { b.write(ByteBuffer.allocate(4).putInt(v).array(), 0, 4); }
    static byte[] U(String s) { return s.getBytes(StandardCharsets.UTF_8); }
    static byte[] unhex(String s) {
        byte[] o = new byte[s.length() / 2];
        for (int k = 0; k < o.length; k++) o[k] = (byte) Integer.parseInt(s.substring(2 * k, 2 * k + 2), 16);
        return o;
    }
    static String enhex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
    static String S(JsonObject i, String k) { return i.get(k).getAsString(); }
    static long N(JsonObject i, String k) { return i.get(k).getAsLong(); }

    static byte[] presence(JsonObject i) throws IOException {
        var b = new ByteArrayOutputStream();
        field(b, U(S(i, "protocol")));
        field(b, U(S(i, "alg")));
        field(b, U(S(i, "id")));
        field(b, unhex(S(i, "public_key_hex")));
        field(b, U(S(i, "endpoint")));
        field(b, U(S(i, "mcp_path")));
        var caps = new ArrayList<String>();
        i.getAsJsonArray("capabilities").forEach(c -> caps.add(c.getAsString()));
        Collections.sort(caps);
        u32(b, caps.size());
        for (var c : caps) field(b, U(c));
        u32(b, (int) N(i, "protocol_major"));
        field(b, U(S(i, "grant_id")));
        u64(b, N(i, "heartbeat_unix"));
        return b.toByteArray();
    }

    static byte[] grant(JsonObject i) throws IOException {
        var b = new ByteArrayOutputStream();
        field(b, U("J3nna-mesh-grant/1"));
        field(b, U(S(i, "alg")));
        field(b, U(S(i, "id")));
        field(b, U(S(i, "subject")));
        field(b, unhex(S(i, "public_key_hex")));
        u64(b, N(i, "tier"));
        var scopes = new ArrayList<String>();
        i.getAsJsonArray("scopes").forEach(c -> scopes.add(c.getAsString()));
        Collections.sort(scopes);
        field(b, U(String.join("\0", scopes)));
        u64(b, N(i, "issued_at"));
        u64(b, N(i, "not_after"));
        var principal = i.has("principal") ? i.get("principal").getAsString() : "";
        if (!principal.isEmpty()) {
            field(b, U("J3nna-mesh-principal/1"));
            field(b, U(principal));
        }
        return b.toByteArray();
    }

    static byte[] callproof(JsonObject i) throws IOException {
        var b = new ByteArrayOutputStream();
        field(b, U("JIP-call/0.2"));
        field(b, U(S(i, "alg")));
        field(b, U(S(i, "node_id")));
        field(b, U(S(i, "tool")));
        field(b, unhex(S(i, "args_hash_hex")));
        u64(b, N(i, "unix_milli"));
        return b.toByteArray();
    }

    static String jsonString(String s) {
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }
    // Match Go's json.Marshal of a map: keys sorted, compact, < > & escaped.
    static String canonicalArgsJson(JsonObject args) {
        var keys = new ArrayList<>(args.keySet());
        Collections.sort(keys);
        var sb = new StringBuilder("{");
        for (int k = 0; k < keys.size(); k++) {
            if (k > 0) sb.append(",");
            var key = keys.get(k);
            var v = args.get(key);
            var vs = (v.isJsonPrimitive() && v.getAsJsonPrimitive().isString()) ? jsonString(v.getAsString()) : v.toString();
            sb.append(jsonString(key)).append(":").append(vs);
        }
        sb.append("}");
        return sb.toString().replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026");
    }

    static PublicKey ed25519Pub(byte[] raw) throws Exception {
        var prefix = unhex("302a300506032b6570032100"); // X.509 SubjectPublicKeyInfo prefix for Ed25519
        var der = new byte[prefix.length + raw.length];
        System.arraycopy(prefix, 0, der, 0, prefix.length);
        System.arraycopy(raw, 0, der, prefix.length, raw.length);
        return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(der));
    }
    static boolean verify(PublicKey pub, byte[] msg, byte[] sig) throws Exception {
        var s = Signature.getInstance("Ed25519");
        s.initVerify(pub);
        s.update(msg);
        return s.verify(sig);
    }

    public static void main(String[] args) throws Exception {
        var doc = JsonParser.parseString(Files.readString(Path.of("../vectors.json"))).getAsJsonObject();
        if (!doc.get("protocol").getAsString().equals("JIP/0.1")) throw new RuntimeException("unexpected protocol");
        int count = 0;
        for (var ve : doc.getAsJsonArray("vectors")) {
            var v = ve.getAsJsonObject();
            var name = v.get("name").getAsString();
            var i = v.getAsJsonObject("input");
            byte[] got = switch (name) {
                case "presence-record" -> presence(i);
                case "grant" -> grant(i);
                case "callproof" -> callproof(i);
                default -> throw new RuntimeException("no Java builder for " + name);
            };
            if (!enhex(got).equals(v.get("signing_bytes_hex").getAsString())) throw new RuntimeException(name + ": signing bytes differ");

            var pub = ed25519Pub(unhex(v.get("signer_public_key_hex").getAsString()));
            var sig = Base64.getDecoder().decode(v.get("signature_b64").getAsString());
            if (!verify(pub, got, sig)) throw new RuntimeException(name + ": signature did not verify");

            if (name.equals("callproof")) {
                var cj = canonicalArgsJson(i.getAsJsonObject("args"));
                if (!cj.equals(S(i, "args_canonical_json"))) throw new RuntimeException("args canonical JSON differs from Go");
                var h = enhex(MessageDigest.getInstance("SHA-256").digest(U(cj)));
                if (!h.equals(S(i, "args_hash_hex"))) throw new RuntimeException("args hash differs");
            }
            System.out.println("  ok  " + name);
            count++;
        }
        System.out.println("PASS: " + count + " vectors verified (Java wire-compatible with the Go reference)");
    }
}
