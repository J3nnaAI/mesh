// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Node identity: a random v4 UUID plus an ed25519 keypair, persisted in the SAME on-disk format as the Go
// reference so the file is byte-interchangeable — {"id", "priv_b64"} where priv_b64 is base64-std of the
// 64-byte Go private key (32-byte seed ‖ 32-byte public key). The UUID is independent of the key and is what
// a grant binds to, so it must be persisted and reused (regenerating it after enrollment breaks admission).

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

import * as wire from "./wire.mjs";

export class Identity {
  constructor(id, seed, publicKey) {
    this.id = id;
    this.seed = seed; // 32-byte ed25519 seed (private)
    this.publicKey = publicKey; // 32-byte ed25519 public key
  }

  sign(msg) {
    return wire.sign(this.seed, this.publicKey, msg);
  }

  get publicKeyB64() {
    return Buffer.from(this.publicKey).toString("base64");
  }
}

// Export the raw 32-byte seed and public key out of a fresh ed25519 keypair (no direct raw export exists,
// so go through JWK).
function generateRawKeypair() {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const jwk = privateKey.export({ format: "jwk" });
  return {
    seed: Buffer.from(jwk.d, "base64url"),
    publicKey: Buffer.from(jwk.x, "base64url"),
  };
}

// Load the identity at `path`, or create + persist (0600) a fresh one. Byte-compatible with Go's
// EnsureIdentity.
export function ensureIdentity(idPath) {
  if (fs.existsSync(idPath)) {
    const blob = JSON.parse(fs.readFileSync(idPath, "utf8"));
    const raw = Buffer.from(blob.priv_b64, "base64");
    if (raw.length !== 64) {
      throw new Error("identity priv_b64 must decode to 64 bytes (seed||pubkey)");
    }
    return new Identity(blob.id, raw.subarray(0, 32), raw.subarray(32));
  }

  const { seed, publicKey } = generateRawKeypair();
  const ident = new Identity(crypto.randomUUID(), seed, publicKey);
  const blob = { id: ident.id, priv_b64: Buffer.concat([seed, publicKey]).toString("base64") };
  const dir = path.dirname(idPath);
  if (dir) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(idPath, JSON.stringify(blob), { mode: 0o600 });
  fs.chmodSync(idPath, 0o600); // ensure 0600 even if masked by umask on create
  return ident;
}
