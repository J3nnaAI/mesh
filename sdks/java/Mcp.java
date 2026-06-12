// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// MCP tool calls — how a Java peer invokes another peer's tools (and rooms, which are just tools). Builds the
// JSON-RPC tools/call envelope, attaches a signed, arguments-bound CallProof so restricted/identity-bound
// tools authorize the caller, includes the peer's presence as `presenter` on first contact, and optionally a
// W3C `trace` for distributed tracing.

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.util.Base64;
import java.util.List;
import java.util.Map;

public final class Mcp {
    private static final Gson GSON = new Gson();

    private Mcp() {}

    private static String b64(byte[] b) { return Base64.getEncoder().encodeToString(b); }

    /** Render an args map into a gson JsonObject (whole-number Integers stay integers in canonical JSON). */
    static JsonObject argsToJson(Map<String, Object> args) {
        return GSON.toJsonTree(args).getAsJsonObject();
    }

    /**
     * A CallProof: the caller signs (domain, alg, node_id, tool, sha256(canonical args), unix_milli) with its
     * node key, binding the proof to THIS tool + arguments at THIS time.
     */
    public static JsonObject makeCallproof(Identity ident, String tool, Map<String, Object> args,
                                           Long unixMilli) {
        long um = unixMilli != null ? unixMilli : System.currentTimeMillis(); // MILLIS
        byte[] ah = Wire.argsHash(args);
        byte[] sb = Wire.callproofSigningBytes(Wire.SIG_ALG, ident.id, tool, ah, um);
        JsonObject cp = new JsonObject();
        cp.addProperty("node_id", ident.id);
        cp.addProperty("tool", tool);
        cp.addProperty("args_hash", b64(ah));
        cp.addProperty("unix_milli", um);
        cp.addProperty("alg", Wire.SIG_ALG);
        cp.addProperty("signature", b64(ident.sign(sb)));
        return cp;
    }

    /**
     * Invoke `tool` at a peer's MCP URL with a signed CallProof; returns its structuredContent. `presenter`
     * (our signed presence) must be included on first contact so the host can resolve our pinned key; `trace`
     * propagates a traceparent for telemetry.
     */
    public static JsonObject callTool(String mcpUrl, Identity ident, String tool, Map<String, Object> args,
                                      JsonObject presenter, String trace, double timeoutSec) throws Exception {
        JsonObject params = new JsonObject();
        params.addProperty("name", tool);
        params.add("arguments", argsToJson(args));
        params.add("caller", makeCallproof(ident, tool, args, null));
        if (presenter != null) params.add("presenter", presenter);
        if (trace != null && !trace.isEmpty()) params.addProperty("trace", trace);

        JsonObject body = new JsonObject();
        body.addProperty("jsonrpc", "2.0");
        body.addProperty("id", 1);
        body.addProperty("method", "tools/call");
        body.add("params", params);

        JsonObject resp = Http.post(mcpUrl, body, timeoutSec);
        if (resp.has("error") && !resp.get("error").isJsonNull()) {
            throw new RuntimeException("mcp protocol error: " + resp.get("error"));
        }
        JsonObject result = resp.has("result") && resp.get("result").isJsonObject()
                ? resp.getAsJsonObject("result") : new JsonObject();
        if (result.has("isError") && result.get("isError").getAsBoolean()) {
            String msg = "tool error";
            if (result.has("content") && result.get("content").isJsonArray()) {
                JsonArray content = result.getAsJsonArray("content");
                if (content.size() > 0 && content.get(0).isJsonObject()) {
                    JsonObject first = content.get(0).getAsJsonObject();
                    if (first.has("text")) msg = first.get("text").getAsString();
                }
            }
            throw new RuntimeException("call rejected: " + msg);
        }
        return result.has("structuredContent") && result.get("structuredContent").isJsonObject()
                ? result.getAsJsonObject("structuredContent") : new JsonObject();
    }

    public static JsonObject callTool(String mcpUrl, Identity ident, String tool, Map<String, Object> args,
                                      JsonObject presenter, String trace) throws Exception {
        return callTool(mcpUrl, ident, tool, args, presenter, trace, 15);
    }

    public static List<JsonElement> listTools(String mcpUrl, double timeoutSec) throws Exception {
        JsonObject body = new JsonObject();
        body.addProperty("jsonrpc", "2.0");
        body.addProperty("id", 1);
        body.addProperty("method", "tools/list");
        body.add("params", new JsonObject());

        JsonObject resp = Http.post(mcpUrl, body, timeoutSec);
        JsonObject result = resp.has("result") && resp.get("result").isJsonObject()
                ? resp.getAsJsonObject("result") : new JsonObject();
        var out = new java.util.ArrayList<JsonElement>();
        if (result.has("tools") && result.get("tools").isJsonArray()) {
            for (JsonElement e : result.getAsJsonArray("tools")) out.add(e);
        }
        return out;
    }
}
