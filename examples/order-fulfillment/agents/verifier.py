#!/usr/bin/env python3
# Copyright 2026 J3nna Technologies, LLC
# SPDX-License-Identifier: Apache-2.0
"""Verifier — proves the choreography worked, by INVARIANT not by schedule (which order backorders depends
on timing). It polls the shared kernel until every order is `fulfilled` (quiescence) or it times out
(non-zero exit), then asserts:
  1. every order reached 'fulfilled';
  2. at least one backorder happened, and at least one restock happened (the feedback loop fired);
  3. every backordered order eventually reached 'fulfilled' (the loop closed);
  4. inventory is CONSERVED for every item: final == initial − allocated + restocked.
Exits 0 iff all hold — so `docker compose` / CI can gate on it.
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
from common import Agent  # noqa: E402
import scenario as S  # noqa: E402
from j3nna_mesh import rooms  # noqa: E402


class Verifier(Agent):
    def __init__(self):
        super().__init__("verifier", caps=("ofx", "verifier"), requires=["memory"])

    def all_events(self):
        hist = rooms.history(self.host, self.ident, self.room, since=0, presenter=self.presence, trace=self.trace)
        out = []
        for m in hist.get("messages", []):
            t = (m.get("text") or "").strip()
            if t.startswith("{"):
                try:
                    ev = json.loads(t)
                    if "event" in ev:
                        out.append(ev)
                except Exception:  # noqa: BLE001
                    pass
        return out

    def check(self, timeout=120):
        order_ids = [o[0] for o in S.ORDERS]
        deadline = time.time() + timeout
        statuses = {}
        while time.time() < deadline:
            statuses = {oid: (self.get(oid) or {}).get("status") for oid in order_ids}
            done = sum(1 for s in statuses.values() if s == "fulfilled")
            self.log(f"progress {done}/{len(order_ids)} fulfilled — {statuses}")
            if done == len(order_ids):
                break
            time.sleep(2)

        events = self.all_events()
        backorders = [e for e in events if e.get("event") == "backordered"]
        restocks = [e for e in events if e.get("event") == "restocked"]

        ok = [True]

        def check(name, cond):
            print(f"  [{'PASS' if cond else 'FAIL'}] {name}", flush=True)
            ok[0] = ok[0] and bool(cond)

        print("\n===== INVARIANTS =====", flush=True)
        check("every order reached 'fulfilled'", all(s == "fulfilled" for s in statuses.values()))
        check(f"a backorder occurred ({len(backorders)})", len(backorders) >= 1)
        check(f"a restock occurred ({len(restocks)})", len(restocks) >= 1)
        bo_orders = {e["order"] for e in backorders}
        check("every backordered order reached 'fulfilled'",
              all(statuses.get(o) == "fulfilled" for o in bo_orders))

        restock_by = {}
        for e in restocks:
            restock_by[e["item"]] = restock_by.get(e["item"], 0) + e.get("qty", 0)
        alloc_by = {}
        for _oid, _c, items in S.ORDERS:
            for sku, qty in items:
                alloc_by[sku] = alloc_by.get(sku, 0) + qty
        for item, init_avail in S.initial_inventory().items():
            final = (self.get(item) or {}).get("available")
            expected = init_avail - alloc_by.get(item, 0) + restock_by.get(item, 0)
            check(f"inventory conserved {item}: final={final} == initial−alloc+restock={expected}",
                  final is not None and float(final) == float(expected))

        # the vault authorized every shipment — a signature is recorded, and the key never left the vault
        for oid in order_ids:
            ship = self.get("shipment:" + oid.split(":")[1])
            check(f"shipment for {oid} carries a vault signature", bool(ship and ship.get("auth")))
        return ok[0]


if __name__ == "__main__":
    v = Verifier()
    print("===== VERIFYING ORDER-FULFILLMENT CHOREOGRAPHY =====", flush=True)
    passed = v.check()
    print("\nRESULT:", "ALL INVARIANTS HOLD ✅" if passed else "FAILED ❌", flush=True)
    sys.exit(0 if passed else 1)
