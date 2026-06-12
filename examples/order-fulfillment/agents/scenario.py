# Copyright 2026 J3nna Technologies, LLC
# SPDX-License-Identifier: Apache-2.0
"""The deterministic scenario — no randomness, no LLM. The MASTER data (inventory items + customers) is
preloaded into the kernel by the kernel-service from inventory.jsonl; here lives only the TRANSACTIONAL
input (the orders) and the pricing/restock policy. Inventory is engineered so total demand for `item:gadget`
(3+4+2 = 9) EXCEEDS its initial stock (5) — a backorder is GUARANTEED, which triggers the restock→retry
feedback loop. The schedule (which order backorders) may vary by timing; the invariants do not."""

import json
import os

TIER_DISCOUNT = {"gold": 0.15, "silver": 0.07, "bronze": 0.0}

# (order_id, customer, [(item, qty), ...])
ORDERS = [
    ("order:1001", "customer:acme",    [("item:widget", 2), ("item:gadget", 3)]),
    ("order:1002", "customer:globex",  [("item:gadget", 4)]),
    ("order:1003", "customer:initech", [("item:gizmo", 1)]),
    ("order:1004", "customer:acme",    [("item:gadget", 2)]),
    ("order:1005", "customer:globex",  [("item:widget", 5), ("item:gizmo", 2)]),
]

RESTOCK_QTY = 20   # Intake replenishes a backordered item by this much (enough to clear demand)


def initial_inventory(path=None):
    """item -> initial `available`, read from the same inventory.jsonl the kernel-service preloads. The
    verifier uses this for the conservation invariant."""
    path = path or os.environ.get("OFX_SEED") or os.path.join(os.path.dirname(__file__), "..", "inventory.jsonl")
    inv = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            r = json.loads(line)
            if r.get("id", "").startswith("item:"):
                inv[r["id"]] = r.get("body", {}).get("available")
    return inv
