#!/usr/bin/env python3
# Copyright 2026 J3nna Technologies, LLC
# SPDX-License-Identifier: Apache-2.0
"""Intake agent — brings orders onto the mesh and plays supplier on the feedback loop:
  1. ingests the deterministic order set — writes each order node + its edges (placed_by, orders_item) into
     the shared kernel and emits a `received` event (the master data — inventory + customers — was preloaded
     by the kernel-service, so Intake only creates the transactional records);
  2. reacts to `backordered` events by RESTOCKING the scarce item and emitting `restocked` — the supply side
     of the backorder→restock→retry loop.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from common import Agent  # noqa: E402
import scenario as S  # noqa: E402


class Intake(Agent):
    def __init__(self):
        super().__init__("intake", caps=("ofx", "intake"), requires=["memory"])

    def ingest(self):
        for oid, cust, items in S.ORDERS:
            self.put(oid, "entity", oid, {
                "customer": cust,
                "items": [{"sku": s, "qty": q} for s, q in items],
                "status": "received",
            })
            self.link(oid, cust, "placed_by")
            for s, _q in items:
                self.link(oid, s, "orders_item")
            self.emit("received", order=oid)

    def on_event(self, ev):
        if ev["event"] == "backordered":
            item = ev["item"]
            r = self.restock(item, S.RESTOCK_QTY)
            self.log(f"supplier: backorder on {item} → restocked to {r.get('available')}")
            self.emit("restocked", item=item, qty=S.RESTOCK_QTY)


if __name__ == "__main__":
    a = Intake()
    a.ingest()
    a.run(a.on_event)
