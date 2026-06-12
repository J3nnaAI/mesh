# Copyright 2026 J3nna Technologies, LLC
# SPDX-License-Identifier: Apache-2.0
"""Slice 1 — live: a Python peer enrolls against a running Go console and verifies its grant offline.
Requires the Go mesh oracle (ORACLE_CONSOLE, default http://127.0.0.1:18455). Run:  python3 tests/live_enroll.py
"""

import base64
import json
import os
import sys
import threading
import time
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from j3nna_mesh import enroll, wire  # noqa: E402

CONSOLE = os.environ.get("ORACLE_CONSOLE", "http://127.0.0.1:18455")
ID_PATH = "/tmp/py-sample.id"


def operator_approve():
    """Simulate the operator: poll pending, confirm the OOB (loopback-trusted)."""
    for _ in range(60):
        try:
            pend = json.load(urllib.request.urlopen(CONSOLE + "/enroll/pending")).get("pending", [])
        except Exception:
            pend = []
        if pend:
            r = pend[0]
            body = json.dumps({"oob": r["oob"]}).encode()
            req = urllib.request.Request(f"{CONSOLE}/enroll/{r['id']}/approve", data=body,
                                         headers={"content-type": "application/json"}, method="POST")
            urllib.request.urlopen(req)
            print(f"  [operator] approved {r['id'][:8]}… oob={r['oob']}")
            return
        time.sleep(0.5)
    print("  [operator] no pending request appeared")


if os.path.exists(ID_PATH):
    os.remove(ID_PATH)  # fresh identity each run

out = {}
t = threading.Thread(target=lambda: out.__setitem__(
    "r", enroll(CONSOLE, "py-joiner", ID_PATH, on_oob=lambda o: print("  [agent] OOB", o))))
t.start()
operator_approve()
t.join(timeout=30)

ident, grant, root = out["r"]
print(f"ENROLLED ✓  id={ident.id[:8]}…  grant={grant['id'][:8]}…  "
      f"subject==id: {grant['subject'] == ident.id}  pubkey_pinned: "
      f"{base64.b64decode(grant['public_key']) == ident.public_key}  root={len(root)}B")

# Verify the grant signature against the authority root, offline — the admit-gate primitive a peer uses to
# decide whether to trust another peer's presence.
gb = wire.grant_signing_bytes(
    alg=grant.get("alg", ""), id=grant["id"], subject=grant["subject"],
    public_key=base64.b64decode(grant["public_key"]), tier=grant["tier"],
    scopes=grant.get("scopes") or [], issued_at=grant["issued_at"],
    not_after=grant["not_after"], principal=grant.get("principal", ""))
ok = wire.verify(root, base64.b64decode(grant["signature"]), gb)
print(f"GRANT SIGNATURE VERIFIES against authority root: {ok}")
sys.exit(0 if ok else 1)
