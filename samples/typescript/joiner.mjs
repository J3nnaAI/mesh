#!/usr/bin/env node
// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// A J3nna Mesh peer in Node.js — the full authorized-collaboration loop, mirroring samples/python/joiner.py
// and samples/joiner (Go):
//
//     enroll with the console   ->  receive a signed grant + the authority root
//     discover a 'rooms' peer    ->  the room agent, found over gossip (not hardcoded)
//     join its room + post       ->  collaborate, all authorized, with one trace for telemetry
//
// Run the console and a room-agent first, then this; approve the enrollment in the console (match the
// out-of-band code it prints). Built on the @j3nna/mesh SDK — pure Node, node:crypto, no external deps.

import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const sdk = join(here, "..", "..", "sdks", "typescript");

const { enroll } = await import(join(sdk, "enroll.mjs"));
const discovery = await import(join(sdk, "discovery.mjs"));
const rooms = await import(join(sdk, "rooms.mjs"));
const wire = await import(join(sdk, "wire.mjs"));

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const env = (k, d) => process.env[k] ?? d;

async function main() {
  const console_ = env("SAMPLE_CONSOLE", "http://127.0.0.1:18455");
  const seeds = env("SAMPLE_SEEDS", "http://127.0.0.1:18482").split(",").filter((s) => s.trim());
  const room = env("SAMPLE_ROOM", "lobby");
  const name = env("SAMPLE_NAME", "ts-joiner");
  const idPath = env("SAMPLE_IDENTITY", "ts-joiner.id");
  // A client-only peer: it polls history, so its advertised endpoint need not be reachable.
  const endpoint = env("SAMPLE_ADVERTISE", "http://127.0.0.1:1/");

  console.log(`joiner: enrolling with console ${console_} …`);
  const { ident, grant, root } = await enroll(console_, name, idPath, {
    onOob: (o) => console.log(`joiner: APPROVE this enrollment in the console — out-of-band code ${o}`),
  });
  console.log(`joiner: enrolled — grant ${grant.id.slice(0, 8)}…`);

  const record = discovery.buildPresence(ident, grant, endpoint, ["sample"]);
  let host = null;
  for (let i = 0; i < 30; i++) {
    const peers = await discovery.discover(seeds, record, { root, wantCap: "rooms" });
    if (peers.length) {
      host = peers[0].mcp;
      break;
    }
    await sleep(1000);
  }
  if (!host) {
    console.log("joiner: no authorized room agent discovered on the mesh");
    process.exit(1);
  }
  console.log(`joiner: discovered room agent at ${host} — joining #${room}`);

  // One trace for the whole session — so a telemetry backend stitches these calls into one operation.
  const trace = wire.newTraceparent();
  await rooms.join(host, ident, room, name, endpoint, { presenter: record, trace });
  await rooms.post(host, ident, room, `hello from ${name} — Node.js peer, authorized and present.`, {
    presenter: record, trace,
  });
  const hist = await rooms.history(host, ident, room, { since: 0, presenter: record, trace });

  const msgs = hist.messages || [];
  console.log(`joiner: #${room} has ${msgs.length} message(s):`);
  for (const m of msgs) {
    if ((m.text || "").trim()) console.log(`joiner:   ${m.from.slice(0, 8)}: ${m.text}`);
  }
  console.log(`joiner: collaboration loop complete — trace ${trace.slice(3, 11)}`);
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  main().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}
