// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Enrollment with the console — the four-call HTTP flow that turns a fresh identity into a signed grant:
// fetch the authority root, POST /enroll, display the out-of-band code for an operator to confirm, then poll
// GET /enroll/<id> until the signed grant comes back. The console is the root of trust; after this the peer
// runs on cached credentials and never needs it on the hot path. Uses the built-in `fetch` (no deps).

import { ensureIdentity } from "./identity.mjs";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function getJson(url, timeout = 10000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeout);
  try {
    const r = await fetch(url, { signal: ctrl.signal });
    if (!r.ok) throw new Error(`GET ${url} -> ${r.status}`);
    return await r.json();
  } finally {
    clearTimeout(t);
  }
}

async function postJson(url, obj, timeout = 10000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeout);
  try {
    const r = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(obj),
      signal: ctrl.signal,
    });
    if (!r.ok) throw new Error(`POST ${url} -> ${r.status}`);
    return await r.json();
  } finally {
    clearTimeout(t);
  }
}

// The authority root public key — the offline-verification key for every grant and CRL.
export async function fetchRoot(consoleUrl, retries = 10) {
  let last = null;
  for (let i = 0; i < retries; i++) {
    try {
      const resp = await getJson(consoleUrl + "/authority");
      return Buffer.from(resp.root_public_key, "base64");
    } catch (e) {
      // console may not be up yet
      last = e;
      await sleep(2000);
    }
  }
  throw last;
}

// Enroll an agent. Returns { ident, grant, root } where root is the authority root pubkey bytes. Blocks
// until an operator approves the request out-of-band (the console then returns the signed grant), or throws
// on denial/timeout. `onOob` is called with the out-of-band code.
export async function enroll(consoleUrl, clientName, identityPath, {
  tier = 1, onOob = null, timeout = 120000,
} = {}) {
  consoleUrl = consoleUrl.replace(/\/+$/, "");
  const ident = ensureIdentity(identityPath);
  const root = await fetchRoot(consoleUrl);
  const resp = await postJson(consoleUrl + "/enroll", {
    kind: "agent",
    client_name: clientName,
    subject: ident.id,
    public_key: ident.publicKeyB64,
    tier,
  });
  const requestId = resp.request_id;
  const oob = resp.oob;
  if (onOob) onOob(oob);
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const q = await getJson(`${consoleUrl}/enroll/${requestId}`);
    const status = q.status;
    if (status === "approved") return { ident, grant: q.grant, root };
    if (status === "denied") throw new Error("enrollment denied");
    await sleep(1000);
  }
  throw new Error(`enrollment not approved within ${Math.round(timeout / 1000)}s`);
}
