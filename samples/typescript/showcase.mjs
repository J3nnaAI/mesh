#!/usr/bin/env node
// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// A Node.js peer that joins the running examples/showcase mesh and uses it — CROSS-LANGUAGE.
// It enrolls, then discovers the Go services by capability (never a hardcoded address) and invokes their
// tools directly over the mesh:
//
//     discover 'inventory'  ->  list its tools, then call inventory.check
//     discover 'quote'      ->  call quote.price (which itself calls the inventory peer — a Node→Go→Go chain)
//     try inventory.reserve ->  DENIED: restricted + allow-listed to the dispatch service, not us
//
// Bring up the showcase first (examples/showcase/run-local.sh with INTERACTIVE=1, or docker compose), then
// run this. Built on the @j3nna/mesh SDK — pure Node, node:crypto, no external deps.

import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const sdk = join(here, "..", "..", "sdks", "typescript");
const { enroll } = await import(join(sdk, "enroll.mjs"));
const discovery = await import(join(sdk, "discovery.mjs"));
const mcp = await import(join(sdk, "mcp.mjs"));

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const env = (k, d) => process.env[k] ?? d;

async function find(seeds, record, root, cap) {
  for (let i = 0; i < 30; i++) {
    const peers = await discovery.discover(seeds, record, { root, wantCap: cap });
    if (peers.length) return peers[0];
    await sleep(1000);
  }
  return null;
}

async function main() {
  const console_ = env("SHOWCASE_CONSOLE", "http://127.0.0.1:8455");
  const seeds = env("SHOWCASE_SEEDS", "http://127.0.0.1:8483").split(",").filter((s) => s.trim());
  const name = env("SHOWCASE_NAME", "ts-showcase");
  const idPath = env("SHOWCASE_IDENTITY", "ts-showcase.id");
  const endpoint = env("SHOWCASE_ADVERTISE", "http://127.0.0.1:1/"); // client-only

  console.log(`showcase(ts): enrolling with console ${console_} …`);
  const { ident, grant, root } = await enroll(console_, name, idPath, {
    onOob: (o) => console.log(`showcase(ts): APPROVE this enrollment — out-of-band code ${o}`),
  });
  console.log(`showcase(ts): enrolled — grant ${grant.id.slice(0, 8)}…`);
  const record = discovery.buildPresence(ident, grant, endpoint, ["showcase"]);

  const inv = await find(seeds, record, root, "inventory");
  const quote = await find(seeds, record, root, "quote");
  if (!inv || !quote) {
    console.log("showcase(ts): could not discover the inventory/quote peers — is the showcase running?");
    process.exit(1);
  }
  console.log(`showcase(ts): discovered inventory at ${inv.mcp} and quote at ${quote.mcp}`);

  // 1) introspect + call a peer's tool (cross-language tools/list + tools/call)
  const tools = (await mcp.listTools(inv.mcp)).map((t) => t.name);
  console.log(`showcase(ts): inventory exposes ${JSON.stringify(tools)}`);
  const check = await mcp.callTool(inv.mcp, ident, "inventory.check", { sku: "WIDGET" }, { presenter: record });
  console.log(`showcase(ts): inventory.check WIDGET → ${JSON.stringify(check)}`);

  // 2) call quote — which itself calls the inventory peer (Node → Go quote → Go inventory)
  const priced = await mcp.callTool(quote.mcp, ident, "quote.price", { sku: "WIDGET", qty: 2 }, { presenter: record });
  console.log(`showcase(ts): quote.price 2×WIDGET → $${priced.price} (quote ${priced.quote_id})`);

  // 3) try the RESTRICTED tool — we are not allow-listed (only dispatch is), so it must be denied
  try {
    await mcp.callTool(inv.mcp, ident, "inventory.reserve", { sku: "WIDGET", qty: 1 }, { presenter: record });
    console.log("showcase(ts): WARNING — inventory.reserve unexpectedly succeeded");
  } catch (e) {
    console.log(`showcase(ts): inventory.reserve correctly DENIED (restricted, not allow-listed): ${e.message}`);
  }

  console.log("showcase(ts): done — a Node peer discovered and used the Go agents' tools over the mesh.");
}

await main();
