// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Discovery — how a Node peer finds others on the mesh. It builds and signs its own presence record
// (carrying its grant), gossips it to seed peers' /gossip endpoints, and receives their presence in return.
// Every received record is verified offline (self-signature, and — under an authority root — its grant), so
// a peer admits only authorized peers. Uses the built-in `fetch` (no deps).

import * as wire from "./wire.mjs";

const b64 = (b) => Buffer.from(b).toString("base64");

// Build this peer's signed PresenceRecord (payload + ed25519 signature over the canonical bytes).
export function buildPresence(ident, grant, endpoint, caps, { heartbeat = null, mcpPath = "/mcp" } = {}) {
  if (heartbeat === null) heartbeat = Math.floor(Date.now() / 1000);
  caps = [...caps];
  const payload = {
    protocol: wire.PROTOCOL,
    id: ident.id,
    public_key: b64(ident.publicKey),
    endpoint,
    mcp_path: mcpPath,
    capabilities: caps,
    heartbeat_unix: heartbeat,
    protocol_major: wire.PROTOCOL_MAJOR,
    grant,
    alg: wire.SIG_ALG,
  };
  const sb = wire.presenceSigningBytes({
    protocol: wire.PROTOCOL, alg: wire.SIG_ALG, id: ident.id, publicKey: ident.publicKey,
    endpoint, mcpPath, capabilities: caps,
    protocolMajor: wire.PROTOCOL_MAJOR, grantId: grant.id, heartbeatUnix: heartbeat,
  });
  return { payload, signature: b64(ident.sign(sb)) };
}

// Verify a presence record's self-signature; with `root` set, also verify its grant binds id↔key and is
// authority-signed (the admission check).
export function verifyRecord(rec, root = null) {
  const p = rec.payload;
  const pub = Buffer.from(p.public_key, "base64");
  const sb = wire.presenceSigningBytes({
    protocol: p.protocol, alg: p.alg || "", id: p.id, publicKey: pub,
    endpoint: p.endpoint, mcpPath: p.mcp_path, capabilities: p.capabilities || [],
    protocolMajor: p.protocol_major || 0, grantId: (p.grant || {}).id || "",
    heartbeatUnix: p.heartbeat_unix,
  });
  if (!wire.verify(pub, Buffer.from(rec.signature, "base64"), sb)) return false;
  if (root === null) return true;
  const g = p.grant;
  if (!g || g.subject !== p.id || !Buffer.from(g.public_key, "base64").equals(pub)) return false;
  const gb = wire.grantSigningBytes({
    alg: g.alg || "", id: g.id, subject: g.subject, publicKey: pub, tier: g.tier,
    scopes: g.scopes || [], issuedAt: g.issued_at, notAfter: g.not_after,
    principal: g.principal || "",
  });
  return wire.verify(root, Buffer.from(g.signature, "base64"), gb);
}

async function gossipOnce(seedBase, myRecord, timeout = 10000) {
  const my = myRecord.payload;
  const env = {
    protocol: wire.PROTOCOL,
    digest: { [my.id]: my.heartbeat_unix },
    records: [myRecord],
  };
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeout);
  try {
    const r = await fetch(seedBase.replace(/\/+$/, "") + "/gossip", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(env),
      signal: ctrl.signal,
    });
    if (!r.ok) throw new Error(`gossip -> ${r.status}`);
    const j = await r.json();
    return j.records || [];
  } finally {
    clearTimeout(t);
  }
}

export class Peer {
  constructor(id, mcp, caps) {
    this.id = id;
    this.mcp = mcp; // the peer's reachable MCP URL (endpoint + mcp_path)
    this.caps = caps;
  }

  toString() {
    return `Peer(id=${this.id.slice(0, 8)}…, caps=${JSON.stringify(this.caps)}, mcp=${this.mcp})`;
  }
}

// Gossip our presence to each seed and return the verified peers learned (excluding self), optionally
// filtered to those advertising `wantCap`.
export async function discover(seeds, myRecord, { root = null, wantCap = null } = {}) {
  const myId = myRecord.payload.id;
  const peers = new Map();
  for (const seed of seeds) {
    let records;
    try {
      records = await gossipOnce(seed, myRecord);
    } catch {
      continue;
    }
    for (const rec of records) {
      const p = rec.payload;
      if (p.id === myId || !verifyRecord(rec, root)) continue;
      const caps = p.capabilities || [];
      if (wantCap && !caps.includes(wantCap)) continue;
      peers.set(p.id, new Peer(p.id, p.endpoint.replace(/\/+$/, "") + p.mcp_path, caps));
    }
  }
  return [...peers.values()];
}
