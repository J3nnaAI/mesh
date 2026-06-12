// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// A J3nna Mesh peer in Java — the full authorized-collaboration loop, mirroring samples/joiner (Go/Python):
//
//     enroll with the console   ->  receive a signed grant + the authority root
//     discover a 'rooms' peer    ->  the room agent, found over gossip (not hardcoded)
//     join its room + post       ->  collaborate, all authorized, with one trace for telemetry
//
// Run the console and a room-agent first, then this; approve the enrollment in the console (match the
// out-of-band code it prints). Built on the mesh SDK in this directory — pure JDK + gson.
//
//   javac -cp gson.jar *.java && java -cp .:gson.jar Joiner

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.util.ArrayList;
import java.util.List;

public final class Joiner {
    private static String env(String k, String d) {
        String v = System.getenv(k);
        return (v == null || v.isEmpty()) ? d : v;
    }

    public static void main(String[] args) throws Exception {
        String console = env("SAMPLE_CONSOLE", "http://127.0.0.1:18455");
        List<String> seeds = new ArrayList<>();
        for (String s : env("SAMPLE_SEEDS", "http://127.0.0.1:18482").split(",")) {
            if (!s.trim().isEmpty()) seeds.add(s.trim());
        }
        String room = env("SAMPLE_ROOM", "lobby");
        String name = env("SAMPLE_NAME", "java-joiner");
        String idPath = env("SAMPLE_IDENTITY", "java-joiner.id");
        // A client-only peer: it polls history, so its advertised endpoint need not be reachable.
        String endpoint = env("SAMPLE_ADVERTISE", "http://127.0.0.1:1/");

        System.out.println("joiner: enrolling with console " + console + " …");
        Enroll.Result en = Enroll.enroll(console, name, idPath,
                o -> System.out.println(
                        "joiner: APPROVE this enrollment in the console — out-of-band code " + o));
        Identity ident = en.identity;
        JsonObject grant = en.grant;
        byte[] root = en.root;
        System.out.println("joiner: enrolled — grant "
                + grant.get("id").getAsString().substring(0, 8) + "…");

        JsonObject record = Discovery.buildPresence(ident, grant, endpoint, List.of("sample"));
        String host = null;
        for (int i = 0; i < 30; i++) {
            List<Discovery.Peer> peers = Discovery.discover(seeds, record, root, "rooms");
            if (!peers.isEmpty()) {
                host = peers.get(0).mcp;
                break;
            }
            Thread.sleep(1000);
        }
        if (host == null) {
            System.out.println("joiner: no authorized room agent discovered on the mesh");
            System.exit(1);
        }
        System.out.println("joiner: discovered room agent at " + host + " — joining #" + room);

        // One trace for the whole session — so a telemetry backend stitches these calls into one operation.
        String trace = Wire.newTraceparent();
        Rooms.join(host, ident, room, name, endpoint, record, trace);
        Rooms.post(host, ident, room,
                "hello from " + name + " — JVM peer, authorized and present.", record, trace);
        JsonObject hist = Rooms.history(host, ident, room, 0, record, trace);

        JsonArray msgs = (hist.has("messages") && hist.get("messages").isJsonArray())
                ? hist.getAsJsonArray("messages") : new JsonArray();
        System.out.println("joiner: #" + room + " has " + msgs.size() + " message(s):");
        for (JsonElement me : msgs) {
            JsonObject m = me.getAsJsonObject();
            String text = m.has("text") && !m.get("text").isJsonNull() ? m.get("text").getAsString() : "";
            if (!text.trim().isEmpty()) {
                String from = m.get("from").getAsString();
                System.out.println("joiner:   " + from.substring(0, Math.min(8, from.length())) + ": " + text);
            }
        }
        System.out.println("joiner: collaboration loop complete — trace " + trace.substring(3, 11));
    }
}
