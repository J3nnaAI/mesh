#!/usr/bin/env python3
# Copyright 2026 J3nna Technologies, LLC
# SPDX-License-Identifier: Apache-2.0
#
# J3nna Mesh wire-conformance test for Python. Proves a Python implementation reproduces the canonical
# signing bytes byte-for-byte and verifies the reference signatures from ../vectors.json. The framing
# helpers here are the seed of the Python SDK's wire layer.
#
#   python3 conformance_test.py        # exits 0 on pass, non-zero on any mismatch
#   pytest conformance_test.py         # also runs as a pytest case
#
# Requires `cryptography` (ed25519). The whole point: if this passes, a Python peer is wire-compatible with
# a Go peer.

import base64
import binascii
import hashlib
import json
import struct
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

VECTORS = Path(__file__).resolve().parent.parent / "vectors.json"


def _field(buf: bytearray, x: bytes) -> None:
    """4-byte big-endian length prefix, then the raw bytes."""
    buf += struct.pack(">I", len(x))
    buf += x


def _u64(buf: bytearray, v: int) -> None:
    """8-byte big-endian integer."""
    buf += struct.pack(">Q", v & 0xFFFFFFFFFFFFFFFF)


def presence_signing_bytes(inp: dict) -> bytes:
    b = bytearray()
    _field(b, inp["protocol"].encode())
    _field(b, inp["alg"].encode())
    _field(b, inp["id"].encode())
    _field(b, bytes.fromhex(inp["public_key_hex"]))
    _field(b, inp["endpoint"].encode())
    _field(b, inp["mcp_path"].encode())
    caps = sorted(inp["capabilities"])
    b += struct.pack(">I", len(caps))
    for c in caps:
        _field(b, c.encode())
    b += struct.pack(">I", int(inp["protocol_major"]))
    _field(b, inp["grant_id"].encode())
    _u64(b, int(inp["heartbeat_unix"]))
    return bytes(b)


def grant_signing_bytes(inp: dict) -> bytes:
    b = bytearray()
    _field(b, b"J3nna-mesh-grant/1")
    _field(b, inp["alg"].encode())
    _field(b, inp["id"].encode())
    _field(b, inp["subject"].encode())
    _field(b, bytes.fromhex(inp["public_key_hex"]))
    _u64(b, int(inp["tier"]))
    _field(b, b"\x00".join(s.encode() for s in sorted(inp["scopes"])))
    _u64(b, int(inp["issued_at"]))
    _u64(b, int(inp["not_after"]))
    if inp.get("principal"):
        _field(b, b"J3nna-mesh-principal/1")
        _field(b, inp["principal"].encode())
    return bytes(b)


def canonical_args_json(args: dict) -> bytes:
    """Reproduce Go's json.Marshal of a map: keys sorted, no insignificant whitespace, and <, >, & escaped
    as \\u003c \\u003e \\u0026 (Go's default HTML escaping)."""
    s = json.dumps(args, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    s = s.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    return s.encode()


def callproof_signing_bytes(inp: dict) -> bytes:
    b = bytearray()
    _field(b, b"JIP-call/0.2")
    _field(b, inp["alg"].encode())
    _field(b, inp["node_id"].encode())
    _field(b, inp["tool"].encode())
    _field(b, bytes.fromhex(inp["args_hash_hex"]))
    _u64(b, int(inp["unix_milli"]))
    return bytes(b)


BUILDERS = {
    "presence-record": presence_signing_bytes,
    "grant": grant_signing_bytes,
    "callproof": callproof_signing_bytes,
}


def run() -> None:
    data = json.loads(VECTORS.read_text())
    assert data["protocol"] == "JIP/0.1", data["protocol"]
    for v in data["vectors"]:
        name = v["name"]
        builder = BUILDERS.get(name)
        assert builder is not None, f"no Python builder for vector {name!r}"

        # 1. byte-exact framing
        got = builder(v["input"])
        assert binascii.hexlify(got).decode() == v["signing_bytes_hex"], f"{name}: signing bytes differ"

        # 2. signature verifies against the reference public key
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(v["signer_public_key_hex"]))
        sig = base64.b64decode(v["signature_b64"])
        pub.verify(sig, got)  # raises InvalidSignature on mismatch

        # 3. the one cross-language subtlety: the CallProof args canonicalization
        if name == "callproof":
            cj = canonical_args_json(v["input"]["args"]).decode()
            assert cj == v["input"]["args_canonical_json"], "args canonical JSON differs from Go"
            h = hashlib.sha256(canonical_args_json(v["input"]["args"])).hexdigest()
            assert h == v["input"]["args_hash_hex"], "args hash differs"

        print(f"  ok  {name}")
    print(f"PASS: {len(data['vectors'])} vectors verified (Python wire-compatible with the Go reference)")


def test_conformance() -> None:  # pytest entry point
    run()


if __name__ == "__main__":
    run()
