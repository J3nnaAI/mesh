#!/usr/bin/env python3
# Copyright 2026 J3nna Technologies, LLC
# SPDX-License-Identifier: Apache-2.0
"""Pricing agent — reacts to `received` events, ENRICHES the order in the shared kernel: it finds the
customer by TRAVERSING the order's `placed_by` edge, reads the tier, sums the line items at each item's
price, applies the tier discount, writes the priced order back, and emits `priced`. Idempotent: it only
prices orders still in `received` state."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from common import Agent  # noqa: E402
import scenario as S  # noqa: E402


class Pricing(Agent):
    def __init__(self):
        super().__init__("pricing", caps=("ofx", "pricing"), requires=["memory"])

    def on_event(self, ev):
        if ev["event"] != "received":
            return
        oid = ev["order"]
        order = self.get(oid)
        if not order or order.get("status") != "received":
            return  # already priced/fulfilled — idempotent

        # customer tier via EDGE TRAVERSAL: order --placed_by--> customer
        tier = "bronze"
        custs = self.neighbors(oid, "placed_by", "out")
        if custs:
            c = self.get(custs[0]["id"]) or {}
            tier = c.get("tier", "bronze")
        disc = S.TIER_DISCOUNT.get(tier, 0.0)

        subtotal = 0.0
        for it in order["items"]:
            item = self.get(it["sku"]) or {}
            subtotal += float(item.get("price", 0.0)) * it["qty"]
        total = round(subtotal * (1 - disc), 2)

        order.update(status="priced", subtotal=round(subtotal, 2), discount=disc, tier=tier, total=total)
        self.put(oid, "entity", oid, order)
        self.log(f"priced {oid}: {tier} subtotal={subtotal:.2f} −{int(disc*100)}% = {total:.2f}")
        self.emit("priced", order=oid)


if __name__ == "__main__":
    a = Pricing()
    a.run(a.on_event)
