# Copyright 2026 J3nna Technologies, LLC
# SPDX-License-Identifier: Apache-2.0
"""Enrollment with the console — the four-call HTTP flow that turns a fresh identity into a signed grant:
fetch the authority root, POST /enroll, display the out-of-band code for an operator to confirm, then poll
GET /enroll/<id> until the signed grant comes back. The console is the root of trust; after this the peer
runs on cached credentials and never needs it on the hot path. Stdlib-only (urllib)."""

import base64
import json
import time
import urllib.request

from .identity import ensure_identity


def _get(url: str, timeout: float = 10):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.load(r)


def _post(url: str, obj: dict, timeout: float = 10):
    req = urllib.request.Request(
        url, data=json.dumps(obj).encode(),
        headers={"content-type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def fetch_root(console_url: str, retries: int = 10) -> bytes:
    """The authority root public key — the offline-verification key for every grant and CRL."""
    last = None
    for _ in range(retries):
        try:
            return base64.b64decode(_get(console_url + "/authority")["root_public_key"])
        except Exception as e:  # console may not be up yet
            last = e
            time.sleep(2)
    raise last


def enroll(console_url: str, client_name: str, identity_path: str, tier: int = 1,
           on_oob=None, timeout: float = 120):
    """Enroll an agent. Returns (Identity, grant_dict, root_pubkey_bytes). Blocks until an operator approves
    the request out-of-band (the console then returns the signed grant), or raises on denial/timeout."""
    console_url = console_url.rstrip("/")
    ident = ensure_identity(identity_path)
    root = fetch_root(console_url)
    resp = _post(console_url + "/enroll", {
        "kind": "agent",
        "client_name": client_name,
        "subject": ident.id,
        "public_key": ident.public_key_b64,
        "tier": tier,
    })
    request_id, oob = resp["request_id"], resp["oob"]
    if on_oob:
        on_oob(oob)
    deadline = time.time() + timeout
    while time.time() < deadline:
        q = _get(f"{console_url}/enroll/{request_id}")
        status = q.get("status")
        if status == "approved":
            return ident, q["grant"], root
        if status == "denied":
            raise RuntimeError("enrollment denied")
        time.sleep(1)
    raise TimeoutError(f"enrollment not approved within {timeout:.0f}s")
