// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// J3nna Mesh SDK for Node.js / TypeScript — a peer that speaks the J3nna Integration Protocol (JIP):
// cryptographic identity, console enrollment, peer discovery, offline grant/CRL verification, MCP tool
// calls, and rooms. Wire-compatible with the Go reference (validated against jip/conformance/vectors.json).

import * as wire from "./wire.mjs";
import * as discovery from "./discovery.mjs";
import * as mcp from "./mcp.mjs";
import * as rooms from "./rooms.mjs";
import * as enrollMod from "./enroll.mjs";

export { wire, discovery, mcp, rooms };
export { Identity, ensureIdentity } from "./identity.mjs";
export { enroll, fetchRoot } from "./enroll.mjs";
export { Peer, buildPresence, verifyRecord, discover } from "./discovery.mjs";

export const VERSION = "0.1.0";

// also expose the enroll namespace for parity with the Python `from . import enroll`
export { enrollMod as enroll_module };
