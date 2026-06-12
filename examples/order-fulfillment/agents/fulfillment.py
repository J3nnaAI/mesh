#!/usr/bin/env python3
# Copyright 2026 J3nna Technologies, LLC
# SPDX-License-Identifier: Apache-2.0
"""Fulfillment agent — reacts to `priced` events and EVOLVES the shared inventory:
  - tries to allocate every line item atomically (mem.allocate). If all succeed → mark fulfilled, record a
    shipment node + `shipped_as` edge, emit `fulfilled`.
  - if any item is short → roll back the partial allocations (so inventory stays conserved), mark
    backordered, emit `backordered` with the blocking item.
  - on `restocked`, finds the orders blocked on that item by TRAVERSING the item's reverse `orders_item`
    edges (item <--orders_item-- orders) and retries them — the demand side of the feedback loop.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from common import Agent  # noqa: E402


class Fulfillment(Agent):
    def __init__(self):
        super().__init__("fulfillment", caps=("ofx", "fulfillment"), requires=["memory", "secrets"])
        self.vault = self.peers["secrets"]   # vault-service (waited for + probed by the readiness gate above)
        self.log(f"vault for shipment signing: {self.vault}")

    def try_fulfill(self, oid):
        order = self.get(oid)
        if not order or order.get("status") not in ("priced", "backordered"):
            return
        allocated = []  # (sku, qty) already taken this attempt — rolled back on a shortfall
        blocked_on = None
        for it in order["items"]:
            r = self.allocate(it["sku"], it["qty"])
            if r.get("ok"):
                allocated.append((it["sku"], it["qty"]))
                self.link(oid, it["sku"], "allocated")
            else:
                blocked_on = it["sku"]
                break

        if blocked_on:
            for sku, qty in allocated:        # return partials → inventory conserved, retry stays clean
                self.restock(sku, qty)
            order.update(status="backordered", blocked_on=blocked_on)
            self.put(oid, "entity", oid, order)
            self.log(f"{oid} BACKORDERED on {blocked_on}")
            self.emit("backordered", order=oid, item=blocked_on)
        else:
            ship = "shipment:" + oid.split(":")[1]
            # Authorize the shipment: the vault signs (HMAC) with the carrier key BY HANDLE — the key never
            # leaves the vault; we only ever see the signature.
            auth = self.call_peer(self.vault, "secret.sign",
                                   {"handle": "carrier-hmac", "data": f"{oid}:{order.get('total')}"})
            sig = auth.get("signature", "")
            order.update(status="fulfilled")
            self.put(oid, "entity", oid, order)
            self.put(ship, "state", "Shipment", {"order": oid, "auth": sig})
            self.link(oid, ship, "shipped_as")
            self.log(f"{oid} FULFILLED — shipment authorized (auth {sig[:12]}…)")
            self.emit("fulfilled", order=oid)

    def on_event(self, ev):
        if ev["event"] == "priced":
            self.try_fulfill(ev["order"])
        elif ev["event"] == "restocked":
            # EDGE TRAVERSAL (reverse): which orders are blocked on this item? item <--orders_item-- orders
            for o in self.neighbors(ev["item"], "orders_item", "in"):
                order = self.get(o["id"])
                if order and order.get("status") == "backordered":
                    self.log(f"restock of {ev['item']} → retrying {o['id']}")
                    self.try_fulfill(o["id"])


if __name__ == "__main__":
    a = Fulfillment()
    a.run(a.on_event)
