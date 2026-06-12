# Copyright 2026 J3nna Technologies, LLC
# SPDX-License-Identifier: Apache-2.0
"""The J3nna Mesh wire layer for Python: the canonical signing bytes every peer must reproduce, plus
ed25519 sign/verify. This is the byte-for-byte contract — it is validated against the shared
jip/conformance/vectors.json by tests/test_conformance.py, so a Python peer is wire-compatible with the Go
reference (and therefore every other SDK).

Framing primitive: variable-length fields are 4-byte big-endian length-prefixed; integers are 8-byte
big-endian; sets (capabilities, scopes) are sorted before framing. Two structures (CRL, renew) use their
own framings, documented inline.
"""

import hashlib
import json
import secrets
import struct

from cryptography.hazmat.primitives.asymmetric import ed25519

PROTOCOL = "JIP/0.1"
PROTOCOL_MAJOR = 1
SIG_ALG = "ed25519"


def _field(buf: bytearray, x: bytes) -> None:
    buf += struct.pack(">I", len(x))
    buf += x


def _u64(buf: bytearray, v: int) -> None:
    buf += struct.pack(">Q", v & 0xFFFFFFFFFFFFFFFF)


def _u32(buf: bytearray, v: int) -> None:
    buf += struct.pack(">I", v & 0xFFFFFFFF)


def _alg(a: str) -> bytes:
    return (a or SIG_ALG).encode()


def presence_signing_bytes(*, protocol, alg, id, public_key, endpoint, mcp_path, capabilities,
                           protocol_major, grant_id, heartbeat_unix) -> bytes:
    b = bytearray()
    _field(b, protocol.encode())
    _field(b, _alg(alg))
    _field(b, id.encode())
    _field(b, public_key)
    _field(b, endpoint.encode())
    _field(b, mcp_path.encode())
    caps = sorted(capabilities)
    _u32(b, len(caps))
    for c in caps:
        _field(b, c.encode())
    _u32(b, protocol_major)
    _field(b, (grant_id or "").encode())
    _u64(b, heartbeat_unix)
    return bytes(b)


def grant_signing_bytes(*, alg, id, subject, public_key, tier, scopes, issued_at, not_after,
                        principal="") -> bytes:
    b = bytearray()
    _field(b, b"J3nna-mesh-grant/1")
    _field(b, _alg(alg))
    _field(b, id.encode())
    _field(b, subject.encode())
    _field(b, public_key)
    _u64(b, tier)
    _field(b, b"\x00".join(s.encode() for s in sorted(scopes or [])))
    _u64(b, issued_at)
    _u64(b, not_after)
    if principal:  # signature-covered only when present, so legacy grants verify byte-identically
        _field(b, b"J3nna-mesh-principal/1")
        _field(b, principal.encode())
    return bytes(b)


def callproof_signing_bytes(*, alg, node_id, tool, args_hash, unix_milli) -> bytes:
    b = bytearray()
    _field(b, b"JIP-call/0.2")
    _field(b, _alg(alg))
    _field(b, node_id.encode())
    _field(b, tool.encode())
    _field(b, args_hash)
    _u64(b, unix_milli)
    return bytes(b)


def renew_signing_bytes(*, alg, grant_id, subject, public_key, issued_at) -> bytes:
    # Field-framed, signed by the NODE key to prove possession of the pinned identity.
    b = bytearray()
    _field(b, b"J3nna-mesh-renew/1")
    _field(b, _alg(alg))
    _field(b, grant_id.encode())
    _field(b, subject.encode())
    _field(b, public_key)
    _u64(b, issued_at)
    return bytes(b)


def crl_signing_bytes(*, alg, issued_at, revoked_ids) -> bytes:
    # NOT field-framed: pipe/comma ASCII with a trailing comma after EVERY id; ids sorted ascending.
    #   J3nna-mesh-crl/1|<alg>|<issued_at>|<id1>,<id2>,...,
    head = f"J3nna-mesh-crl/1|{alg or SIG_ALG}|{issued_at}|"
    body = "".join(f"{rid}," for rid in sorted(revoked_ids))
    return (head + body).encode()


def canonical_args_json(args: dict) -> bytes:
    """Reproduce Go's json.Marshal of the arguments map: keys sorted, compact, and <, >, & escaped as
    \\u003c \\u003e \\u0026. This is the one place JSON canonicalization must match byte-for-byte."""
    s = json.dumps(args, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return s.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026").encode()


def args_hash(args: dict) -> bytes:
    return hashlib.sha256(canonical_args_json(args)).digest()


def sign(seed32: bytes, msg: bytes) -> bytes:
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed32).sign(msg)


def verify(public_key32: bytes, sig: bytes, msg: bytes) -> bool:
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(public_key32).verify(sig, msg)
        return True
    except Exception:
        return False


def new_span_id() -> str:
    """A fresh 64-bit span id (16 hex chars)."""
    return secrets.token_hex(8)


def new_traceparent() -> str:
    """A fresh W3C `traceparent` (version 00, sampled). Attach one across a logical operation's calls so a
    telemetry backend stitches them into a single trace."""
    return "00-" + secrets.token_hex(16) + "-" + secrets.token_hex(8) + "-01"
