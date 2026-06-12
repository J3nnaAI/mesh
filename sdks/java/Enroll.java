// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Enrollment with the console — the four-call HTTP flow that turns a fresh identity into a signed grant:
// fetch the authority root, POST /enroll, display the out-of-band code for an operator to confirm, then poll
// GET /enroll/<id> until the signed grant comes back. The console is the root of trust; after this the peer
// runs on cached credentials and never needs it on the hot path.

import com.google.gson.JsonObject;
import java.util.Base64;
import java.util.function.Consumer;

public final class Enroll {
    private Enroll() {}

    /** The result of a successful enrollment: identity, the signed grant (opaque JSON), and the authority root. */
    public static final class Result {
        public final Identity identity;
        public final JsonObject grant;
        public final byte[] root;

        Result(Identity identity, JsonObject grant, byte[] root) {
            this.identity = identity;
            this.grant = grant;
            this.root = root;
        }
    }

    /** The authority root public key — the offline-verification key for every grant and CRL. */
    public static byte[] fetchRoot(String consoleUrl) throws Exception {
        Exception last = null;
        for (int i = 0; i < 10; i++) {
            try {
                JsonObject o = Http.get(consoleUrl + "/authority", 10);
                return Base64.getDecoder().decode(o.get("root_public_key").getAsString());
            } catch (Exception e) { // console may not be up yet
                last = e;
                Thread.sleep(2000);
            }
        }
        throw last;
    }

    /**
     * Enroll an agent. Returns (Identity, grant, root). Blocks until an operator approves the request
     * out-of-band (the console then returns the signed grant), or throws on denial/timeout.
     */
    public static Result enroll(String consoleUrl, String clientName, String identityPath, int tier,
                                Consumer<String> onOob, double timeoutSec) throws Exception {
        consoleUrl = consoleUrl.replaceAll("/+$", "");
        Identity ident = Identity.ensureIdentity(identityPath);
        byte[] root = fetchRoot(consoleUrl);

        JsonObject reqBody = new JsonObject();
        reqBody.addProperty("kind", "agent");
        reqBody.addProperty("client_name", clientName);
        reqBody.addProperty("subject", ident.id);
        reqBody.addProperty("public_key", ident.publicKeyB64());
        reqBody.addProperty("tier", tier);

        JsonObject resp = Http.post(consoleUrl + "/enroll", reqBody, 10);
        String requestId = resp.get("request_id").getAsString();
        String oob = resp.get("oob").getAsString();
        if (onOob != null) onOob.accept(oob);

        long deadline = System.currentTimeMillis() + (long) (timeoutSec * 1000);
        while (System.currentTimeMillis() < deadline) {
            JsonObject q = Http.get(consoleUrl + "/enroll/" + requestId, 10);
            String status = q.has("status") && !q.get("status").isJsonNull()
                    ? q.get("status").getAsString() : null;
            if ("approved".equals(status)) {
                return new Result(ident, q.getAsJsonObject("grant"), root);
            }
            if ("denied".equals(status)) {
                throw new RuntimeException("enrollment denied");
            }
            Thread.sleep(1000);
        }
        throw new RuntimeException(String.format("enrollment not approved within %.0fs", timeoutSec));
    }

    /** Convenience overload with the Python defaults (tier=1, timeout=120s). */
    public static Result enroll(String consoleUrl, String clientName, String identityPath,
                                Consumer<String> onOob) throws Exception {
        return enroll(consoleUrl, clientName, identityPath, 1, onOob, 120);
    }
}
