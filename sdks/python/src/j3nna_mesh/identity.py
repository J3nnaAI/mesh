# Copyright 2026 J3nna Technologies, LLC
# SPDX-License-Identifier: Apache-2.0
"""Node identity: a random v4 UUID plus an ed25519 keypair, persisted in the SAME on-disk format as the Go
reference so the file is byte-interchangeable — {"id", "priv_b64"} where priv_b64 is base64-std of the
64-byte Go private key (32-byte seed ‖ 32-byte public key). The UUID is independent of the key and is what
a grant binds to, so it must be persisted and reused (regenerating it after enrollment breaks admission).
"""

import base64
import json
import os
import uuid

from cryptography.hazmat.primitives.asymmetric import ed25519


class Identity:
    def __init__(self, id: str, seed: bytes, public_key: bytes):
        self.id = id
        self.seed = seed              # 32-byte ed25519 seed (private)
        self.public_key = public_key  # 32-byte ed25519 public key

    def sign(self, msg: bytes) -> bytes:
        return ed25519.Ed25519PrivateKey.from_private_bytes(self.seed).sign(msg)

    @property
    def public_key_b64(self) -> str:
        return base64.b64encode(self.public_key).decode()


def ensure_identity(path: str) -> Identity:
    """Load the identity at `path`, or create + persist (0600) a fresh one. Byte-compatible with Go's
    EnsureIdentity."""
    if os.path.exists(path):
        with open(path) as f:
            blob = json.load(f)
        raw = base64.b64decode(blob["priv_b64"])
        if len(raw) != 64:
            raise ValueError("identity priv_b64 must decode to 64 bytes (seed||pubkey)")
        return Identity(blob["id"], raw[:32], raw[32:])

    priv = ed25519.Ed25519PrivateKey.generate()
    seed = priv.private_bytes_raw()
    pub = priv.public_key().public_bytes_raw()
    ident = Identity(str(uuid.uuid4()), seed, pub)
    blob = {"id": ident.id, "priv_b64": base64.b64encode(seed + pub).decode()}
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(blob, f)
    return ident
