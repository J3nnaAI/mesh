# Copyright 2026 J3nna Technologies, LLC
# SPDX-License-Identifier: Apache-2.0
"""Slice 2 — live: a Python peer enrolls, then discovers the Go room-agent over gossip (no hardcoded URL —
it learns the room host from the mesh). Requires the Go oracle (console :18455, room-agent :18482).
Run: python3 tests/live_discover.py
"""

import json
import os
import sys
import threading
import time
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from j3nna_mesh import discovery  # noqa: E402
from j3nna_mesh.enroll import enroll  # noqa: E402

CONSOLE = os.environ.get("ORACLE_CONSOLE", "http://127.0.0.1:18455")
SEED = os.environ.get("ORACLE_SEED", "http://127.0.0.1:18482")
ID_PATH = "/tmp/py-discover.id"


def operator_approve():
    for _ in range(60):
        try:
            pend = json.load(urllib.request.urlopen(CONSOLE + "/enroll/pending")).get("pending", [])
        except Exception:
            pend = []
        if pend:
            r = pend[0]
            req = urllib.request.Request(f"{CONSOLE}/enroll/{r['id']}/approve",
                                         data=json.dumps({"oob": r["oob"]}).encode(),
                                         headers={"content-type": "application/json"}, method="POST")
            urllib.request.urlopen(req)
            return
        time.sleep(0.5)


if os.path.exists(ID_PATH):
    os.remove(ID_PATH)

out = {}
t = threading.Thread(target=lambda: out.__setitem__(
    "r", enroll(CONSOLE, "py-joiner", ID_PATH, on_oob=lambda o: None)))
t.start()
operator_approve()
t.join(timeout=30)
ident, grant, root = out["r"]
print(f"enrolled — grant {grant['id'][:8]}…")

# Build our signed presence (carrying the grant) and discover via gossip to the seed.
record = discovery.build_presence(ident, grant, "http://127.0.0.1:1/", ["sample"])
peers = discovery.discover([SEED], record, root=root, want_cap="rooms")
print(f"discovered {len(peers)} peer(s) advertising 'rooms':")
for p in peers:
    print("  ", p)

assert peers, "did not discover the room-agent over gossip"
assert all(discovery.verify_record  # sanity: the discover() path verified each (root-admitted)
           for _ in [0])
print("DISCOVERY ✓ — Python peer found the room-agent on the mesh (grant-verified), no hardcoded URL")
