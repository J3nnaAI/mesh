// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Discovery — how a Java peer finds others on the mesh. It builds and signs its own presence record
// (carrying its grant), gossips it to seed peers' /gossip endpoints, and receives their presence in return.
// Every received record is verified offline (self-signature, and — under an authority root — its grant), so
// a peer admits only authorized peers.

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class Discovery {
    private Discovery() {}

    private static String b64(byte[] b) { return Base64.getEncoder().encodeToString(b); }
    private static byte[] unb64(String s) { return Base64.getDecoder().decode(s); }

    /** A discovered peer: its id, reachable MCP URL (endpoint + mcp_path), and advertised capabilities. */
    public static final class Peer {
        public final String id;
        public final String mcp;
        public final List<String> caps;

        public Peer(String id, String mcp, List<String> caps) {
            this.id = id;
            this.mcp = mcp;
            this.caps = caps;
        }

        @Override
        public String toString() {
            return "Peer(id=" + id.substring(0, Math.min(8, id.length())) + "…, caps=" + caps
                    + ", mcp=" + mcp + ")";
        }
    }

    private static List<String> capList(JsonArray arr) {
        var out = new ArrayList<String>();
        if (arr != null) arr.forEach(c -> out.add(c.getAsString()));
        return out;
    }

    /** Build this peer's signed PresenceRecord (payload + ed25519 signature over the canonical bytes). */
    public static JsonObject buildPresence(Identity ident, JsonObject grant, String endpoint,
                                           Collection<String> caps, Long heartbeat, String mcpPath) {
        long hb = heartbeat != null ? heartbeat : (System.currentTimeMillis() / 1000); // unix SECONDS
        var capList = new ArrayList<>(caps);

        JsonObject payload = new JsonObject();
        payload.addProperty("protocol", Wire.PROTOCOL);
        payload.addProperty("id", ident.id);
        payload.addProperty("public_key", b64(ident.publicKey));
        payload.addProperty("endpoint", endpoint);
        payload.addProperty("mcp_path", mcpPath);
        JsonArray capsArr = new JsonArray();
        for (String c : capList) capsArr.add(c);
        payload.add("capabilities", capsArr);
        payload.addProperty("heartbeat_unix", hb);
        payload.addProperty("protocol_major", Wire.PROTOCOL_MAJOR);
        payload.add("grant", grant); // opaque, verbatim
        payload.addProperty("alg", Wire.SIG_ALG);

        byte[] sb = Wire.presenceSigningBytes(Wire.PROTOCOL, Wire.SIG_ALG, ident.id, ident.publicKey,
                endpoint, mcpPath, capList, Wire.PROTOCOL_MAJOR, grant.get("id").getAsString(), hb);

        JsonObject rec = new JsonObject();
        rec.add("payload", payload);
        rec.addProperty("signature", b64(ident.sign(sb)));
        return rec;
    }

    public static JsonObject buildPresence(Identity ident, JsonObject grant, String endpoint,
                                           Collection<String> caps) {
        return buildPresence(ident, grant, endpoint, caps, null, "/mcp");
    }

    private static String str(JsonObject o, String k, String dflt) {
        return o.has(k) && !o.get(k).isJsonNull() ? o.get(k).getAsString() : dflt;
    }

    private static long lng(JsonObject o, String k, long dflt) {
        return o.has(k) && !o.get(k).isJsonNull() ? o.get(k).getAsLong() : dflt;
    }

    /**
     * Verify a presence record's self-signature; with `root` set, also verify its grant binds id↔key and is
     * authority-signed (the admission check). Mirror of verify_record.
     */
    public static boolean verifyRecord(JsonObject rec, byte[] root) {
        JsonObject p = rec.getAsJsonObject("payload");
        byte[] pub = unb64(p.get("public_key").getAsString());
        JsonObject grant = (p.has("grant") && p.get("grant").isJsonObject()) ? p.getAsJsonObject("grant") : null;
        String grantId = grant != null ? str(grant, "id", "") : "";

        byte[] sb = Wire.presenceSigningBytes(
                p.get("protocol").getAsString(), str(p, "alg", ""), p.get("id").getAsString(), pub,
                p.get("endpoint").getAsString(), p.get("mcp_path").getAsString(),
                capList(p.has("capabilities") ? p.getAsJsonArray("capabilities") : null),
                (int) lng(p, "protocol_major", 0), grantId, p.get("heartbeat_unix").getAsLong());

        if (!Wire.verify(Wire.ed25519Pub(pub), unb64(rec.get("signature").getAsString()), sb)) {
            return false;
        }
        if (root == null) return true;

        if (grant == null) return false;
        if (!grant.get("subject").getAsString().equals(p.get("id").getAsString())) return false;
        if (!java.util.Arrays.equals(unb64(grant.get("public_key").getAsString()), pub)) return false;

        var scopes = new ArrayList<String>();
        if (grant.has("scopes") && grant.get("scopes").isJsonArray()) {
            grant.getAsJsonArray("scopes").forEach(s -> scopes.add(s.getAsString()));
        }
        byte[] gb = Wire.grantSigningBytes(
                str(grant, "alg", ""), grant.get("id").getAsString(), grant.get("subject").getAsString(),
                pub, grant.get("tier").getAsLong(), scopes,
                grant.get("issued_at").getAsLong(), grant.get("not_after").getAsLong(),
                str(grant, "principal", ""));
        return Wire.verify(Wire.ed25519Pub(root), unb64(grant.get("signature").getAsString()), gb);
    }

    private static List<JsonObject> gossipOnce(String seedBase, JsonObject myRecord) throws Exception {
        JsonObject my = myRecord.getAsJsonObject("payload");
        JsonObject digest = new JsonObject();
        digest.addProperty(my.get("id").getAsString(), my.get("heartbeat_unix").getAsLong());
        JsonArray records = new JsonArray();
        records.add(myRecord);
        JsonObject env = new JsonObject();
        env.addProperty("protocol", Wire.PROTOCOL);
        env.add("digest", digest);
        env.add("records", records);

        JsonObject resp = Http.post(seedBase.replaceAll("/+$", "") + "/gossip", env, 10);
        var out = new ArrayList<JsonObject>();
        if (resp.has("records") && resp.get("records").isJsonArray()) {
            for (JsonElement e : resp.getAsJsonArray("records")) out.add(e.getAsJsonObject());
        }
        return out;
    }

    /**
     * Gossip our presence to each seed and return the verified peers learned (excluding self), optionally
     * filtered to those advertising `wantCap`.
     */
    public static List<Peer> discover(List<String> seeds, JsonObject myRecord, byte[] root, String wantCap) {
        String myId = myRecord.getAsJsonObject("payload").get("id").getAsString();
        Map<String, Peer> peers = new LinkedHashMap<>();
        for (String seed : seeds) {
            List<JsonObject> records;
            try {
                records = gossipOnce(seed, myRecord);
            } catch (Exception e) {
                continue;
            }
            for (JsonObject rec : records) {
                JsonObject p = rec.getAsJsonObject("payload");
                String id = p.get("id").getAsString();
                if (id.equals(myId) || !verifyRecord(rec, root)) continue;
                List<String> caps = capList(p.has("capabilities") ? p.getAsJsonArray("capabilities") : null);
                if (wantCap != null && !caps.contains(wantCap)) continue;
                String mcp = p.get("endpoint").getAsString().replaceAll("/+$", "")
                        + p.get("mcp_path").getAsString();
                peers.put(id, new Peer(id, mcp, caps));
            }
        }
        return new ArrayList<>(peers.values());
    }
}
