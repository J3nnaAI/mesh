// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// The J3nna Mesh wire layer for Java/the JVM: the canonical signing bytes every peer must reproduce, plus
// ed25519 sign/verify. This is the byte-for-byte contract — validated against the shared
// jip/conformance/vectors.json by ConformanceTest, so a Java peer is wire-compatible with the Go reference
// (and therefore every other SDK).
//
// Framing primitive: variable-length fields are 4-byte big-endian length-prefixed; integers are 8-byte
// big-endian; sets (capabilities, scopes) are sorted before framing.
//
// NB: this SDK is conceptually the `mesh` package, but the files are kept in the default package (no
// `package` declaration) so the conformance build `javac -cp gson.jar *.java && java -cp .:gson.jar
// ConformanceTest` works exactly as in jip/conformance/java — see README.

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public final class Wire {
    public static final String PROTOCOL = "JIP/0.1";
    public static final int PROTOCOL_MAJOR = 1;
    public static final String SIG_ALG = "ed25519";

    private static final SecureRandom RNG = new SecureRandom();

    private Wire() {}

    // --- framing primitives (identical to the conformance) ---

    static void field(ByteArrayOutputStream b, byte[] x) {
        try {
            b.write(ByteBuffer.allocate(4).putInt(x.length).array());
            b.write(x);
        } catch (IOException e) {
            throw new UncheckedIOException(e); // ByteArrayOutputStream never throws
        }
    }

    static void u64(ByteArrayOutputStream b, long v) {
        b.write(ByteBuffer.allocate(8).putLong(v).array(), 0, 8);
    }

    static void u32(ByteArrayOutputStream b, int v) {
        b.write(ByteBuffer.allocate(4).putInt(v).array(), 0, 4);
    }

    static byte[] U(String s) { return s.getBytes(StandardCharsets.UTF_8); }

    private static String alg(String a) { return (a == null || a.isEmpty()) ? SIG_ALG : a; }

    // --- signing-byte builders (mirror wire.py) ---

    public static byte[] presenceSigningBytes(String protocol, String alg, String id, byte[] publicKey,
                                              String endpoint, String mcpPath, List<String> capabilities,
                                              int protocolMajor, String grantId, long heartbeatUnix) {
        var b = new ByteArrayOutputStream();
        field(b, U(protocol));
        field(b, U(alg(alg)));
        field(b, U(id));
        field(b, publicKey);
        field(b, U(endpoint));
        field(b, U(mcpPath));
        var caps = new ArrayList<>(capabilities);
        Collections.sort(caps);
        u32(b, caps.size());
        for (var c : caps) field(b, U(c));
        u32(b, protocolMajor);
        field(b, U(grantId == null ? "" : grantId));
        u64(b, heartbeatUnix);
        return b.toByteArray();
    }

    public static byte[] grantSigningBytes(String alg, String id, String subject, byte[] publicKey, long tier,
                                           List<String> scopes, long issuedAt, long notAfter, String principal) {
        var b = new ByteArrayOutputStream();
        field(b, U("J3nna-mesh-grant/1"));
        field(b, U(alg(alg)));
        field(b, U(id));
        field(b, U(subject));
        field(b, publicKey);
        u64(b, tier);
        var sc = scopes == null ? new ArrayList<String>() : new ArrayList<>(scopes);
        Collections.sort(sc);
        field(b, U(String.join("\0", sc)));
        u64(b, issuedAt);
        u64(b, notAfter);
        if (principal != null && !principal.isEmpty()) { // signature-covered only when present
            field(b, U("J3nna-mesh-principal/1"));
            field(b, U(principal));
        }
        return b.toByteArray();
    }

    public static byte[] callproofSigningBytes(String alg, String nodeId, String tool, byte[] argsHash,
                                               long unixMilli) {
        var b = new ByteArrayOutputStream();
        field(b, U("JIP-call/0.2"));
        field(b, U(alg(alg)));
        field(b, U(nodeId));
        field(b, U(tool));
        field(b, argsHash);
        u64(b, unixMilli);
        return b.toByteArray();
    }

    /** Field-framed, signed by the NODE key to prove possession of the pinned identity. */
    public static byte[] renewSigningBytes(String alg, String grantId, String subject, byte[] publicKey,
                                           long issuedAt) {
        var b = new ByteArrayOutputStream();
        field(b, U("J3nna-mesh-renew/1"));
        field(b, U(alg(alg)));
        field(b, U(grantId));
        field(b, U(subject));
        field(b, publicKey);
        u64(b, issuedAt);
        return b.toByteArray();
    }

    /**
     * NOT field-framed: pipe/comma ASCII with a trailing comma after EVERY id; ids sorted ascending.
     *   J3nna-mesh-crl/1|&lt;alg&gt;|&lt;issued_at&gt;|&lt;id1&gt;,&lt;id2&gt;,...,
     */
    public static byte[] crlSigningBytes(String alg, long issuedAt, List<String> revokedIds) {
        StringBuilder head = new StringBuilder("J3nna-mesh-crl/1|")
                .append(alg(alg)).append("|").append(issuedAt).append("|");
        var ids = new ArrayList<>(revokedIds);
        Collections.sort(ids);
        for (String rid : ids) head.append(rid).append(",");
        return U(head.toString());
    }

    // --- canonical args JSON / hash (the one cross-language gotcha) ---

    private static String jsonString(String s) {
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    /**
     * Reproduce Go's json.Marshal of the arguments map: keys sorted, compact, and {@code < > &} escaped as
     * {@code < > &}. Values are rendered by gson's compact serialization (whole numbers as
     * integers, since gson keeps Number formatting). Mirror of wire.py's canonical_args_json.
     */
    public static String canonicalArgsJson(Map<String, Object> args) {
        var sorted = new TreeMap<>(args);
        var sb = new StringBuilder("{");
        boolean first = true;
        for (var e : sorted.entrySet()) {
            if (!first) sb.append(",");
            first = false;
            sb.append(jsonString(e.getKey())).append(":").append(renderValue(e.getValue()));
        }
        sb.append("}");
        return sb.toString().replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026");
    }

    /** Canonicalize a gson JsonObject directly (used by the conformance harness). */
    public static String canonicalArgsJson(com.google.gson.JsonObject args) {
        var keys = new ArrayList<>(args.keySet());
        Collections.sort(keys);
        var sb = new StringBuilder("{");
        for (int k = 0; k < keys.size(); k++) {
            if (k > 0) sb.append(",");
            var key = keys.get(k);
            var v = args.get(key);
            var vs = (v.isJsonPrimitive() && v.getAsJsonPrimitive().isString())
                    ? jsonString(v.getAsString()) : v.toString();
            sb.append(jsonString(key)).append(":").append(vs);
        }
        sb.append("}");
        return sb.toString().replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026");
    }

    private static String renderValue(Object v) {
        if (v == null) return "null";
        if (v instanceof String s) return jsonString(s);
        if (v instanceof Boolean b) return b.toString();
        if (v instanceof Integer || v instanceof Long || v instanceof Short || v instanceof Byte) {
            return v.toString();
        }
        if (v instanceof Number n) {
            // Render whole-valued floats/doubles without a decimal point, matching Go integers.
            double d = n.doubleValue();
            if (d == Math.rint(d) && !Double.isInfinite(d)) return Long.toString((long) d);
            return n.toString();
        }
        // Fall back to gson for any nested structure.
        return new com.google.gson.Gson().toJson(v);
    }

    public static byte[] argsHash(Map<String, Object> args) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(U(canonicalArgsJson(args)));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // --- ed25519 sign / verify ---

    public static byte[] sign(PrivateKey priv, byte[] msg) {
        try {
            var s = Signature.getInstance("Ed25519");
            s.initSign(priv);
            s.update(msg);
            return s.sign();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static boolean verify(PublicKey pub, byte[] sig, byte[] msg) {
        try {
            var s = Signature.getInstance("Ed25519");
            s.initVerify(pub);
            s.update(msg);
            return s.verify(sig);
        } catch (Exception e) {
            return false;
        }
    }

    /** Wrap a raw 32-byte ed25519 public key in X.509 SPKI and build a PublicKey (the conformance approach). */
    public static PublicKey ed25519Pub(byte[] raw) {
        try {
            byte[] prefix = unhex("302a300506032b6570032100");
            byte[] der = new byte[prefix.length + raw.length];
            System.arraycopy(prefix, 0, der, 0, prefix.length);
            System.arraycopy(raw, 0, der, prefix.length, raw.length);
            return java.security.KeyFactory.getInstance("Ed25519")
                    .generatePublic(new java.security.spec.X509EncodedKeySpec(der));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // --- trace ids ---

    public static String newSpanId() { return randomHex(8); }

    /** A fresh W3C traceparent (version 00, sampled). */
    public static String newTraceparent() {
        return "00-" + randomHex(16) + "-" + randomHex(8) + "-01";
    }

    private static String randomHex(int nBytes) {
        byte[] b = new byte[nBytes];
        RNG.nextBytes(b);
        return enhex(b);
    }

    // --- hex helpers (shared) ---

    public static byte[] unhex(String s) {
        byte[] o = new byte[s.length() / 2];
        for (int k = 0; k < o.length; k++) {
            o[k] = (byte) Integer.parseInt(s.substring(2 * k, 2 * k + 2), 16);
        }
        return o;
    }

    public static String enhex(byte[] b) {
        var sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
}
