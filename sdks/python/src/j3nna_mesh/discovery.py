# Copyright 2026 J3nna Technologies, LLC
# SPDX-License-Identifier: Apache-2.0
"""Discovery — how a Python peer finds others on the mesh. It builds and signs its own presence record
(carrying its grant), gossips it to seed peers' /gossip endpoints, and receives their presence in return.
Every received record is verified offline (self-signature, and — under an authority root — its grant), so a
peer admits only authorized peers. Stdlib-only (urllib)."""

import base64
import json
import time
import urllib.request

from . import wire


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def build_presence(ident, grant: dict, endpoint: str, caps, heartbeat: int = None, mcp_path: str = "/mcp") -> dict:
    """Build this peer's signed PresenceRecord (payload + ed25519 signature over the canonical bytes)."""
    if heartbeat is None:
        heartbeat = int(time.time())
    caps = list(caps)
    payload = {
        "protocol": wire.PROTOCOL,
        "id": ident.id,
        "public_key": _b64(ident.public_key),
        "endpoint": endpoint,
        "mcp_path": mcp_path,
        "capabilities": caps,
        "heartbeat_unix": heartbeat,
        "protocol_major": wire.PROTOCOL_MAJOR,
        "grant": grant,
        "alg": wire.SIG_ALG,
    }
    sb = wire.presence_signing_bytes(
        protocol=wire.PROTOCOL, alg=wire.SIG_ALG, id=ident.id, public_key=ident.public_key,
        endpoint=endpoint, mcp_path=mcp_path, capabilities=caps,
        protocol_major=wire.PROTOCOL_MAJOR, grant_id=grant["id"], heartbeat_unix=heartbeat)
    return {"payload": payload, "signature": _b64(ident.sign(sb))}


def verify_record(rec: dict, root: bytes = None) -> bool:
    """Verify a presence record's self-signature; with `root` set, also verify its grant binds id↔key and is
    authority-signed (the admission check)."""
    p = rec["payload"]
    pub = base64.b64decode(p["public_key"])
    sb = wire.presence_signing_bytes(
        protocol=p["protocol"], alg=p.get("alg", ""), id=p["id"], public_key=pub,
        endpoint=p["endpoint"], mcp_path=p["mcp_path"], capabilities=p.get("capabilities", []),
        protocol_major=p.get("protocol_major", 0), grant_id=(p.get("grant") or {}).get("id", ""),
        heartbeat_unix=p["heartbeat_unix"])
    if not wire.verify(pub, base64.b64decode(rec["signature"]), sb):
        return False
    if root is None:
        return True
    g = p.get("grant")
    if not g or g["subject"] != p["id"] or base64.b64decode(g["public_key"]) != pub:
        return False
    gb = wire.grant_signing_bytes(
        alg=g.get("alg", ""), id=g["id"], subject=g["subject"], public_key=pub, tier=g["tier"],
        scopes=g.get("scopes") or [], issued_at=g["issued_at"], not_after=g["not_after"],
        principal=g.get("principal", ""))
    return wire.verify(root, base64.b64decode(g["signature"]), gb)


def _gossip_once(seed_base: str, my_record: dict, timeout: float = 10) -> list:
    my = my_record["payload"]
    env = {"protocol": wire.PROTOCOL, "digest": {my["id"]: my["heartbeat_unix"]}, "records": [my_record]}
    req = urllib.request.Request(seed_base.rstrip("/") + "/gossip", data=json.dumps(env).encode(),
                                 headers={"content-type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r).get("records", [])


class Peer:
    def __init__(self, id: str, mcp: str, caps: list):
        self.id = id
        self.mcp = mcp     # the peer's reachable MCP URL (endpoint + mcp_path)
        self.caps = caps

    def __repr__(self):
        return f"Peer(id={self.id[:8]}…, caps={self.caps}, mcp={self.mcp})"


def discover(seeds, my_record: dict, root: bytes = None, want_cap: str = None) -> list:
    """Gossip our presence to each seed and return the verified peers learned (excluding self), optionally
    filtered to those advertising `want_cap`."""
    my_id = my_record["payload"]["id"]
    peers = {}
    for seed in seeds:
        try:
            records = _gossip_once(seed, my_record)
        except Exception:
            continue
        for rec in records:
            p = rec["payload"]
            if p["id"] == my_id or not verify_record(rec, root):
                continue
            caps = p.get("capabilities", [])
            if want_cap and want_cap not in caps:
                continue
            peers[p["id"]] = Peer(p["id"], p["endpoint"].rstrip("/") + p["mcp_path"], caps)
    return list(peers.values())
