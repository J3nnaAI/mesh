#!/usr/bin/env python3
# Copyright 2026 J3nna Technologies, LLC
# SPDX-License-Identifier: Apache-2.0
"""A Python peer that joins the running `examples/showcase` mesh and uses it — CROSS-LANGUAGE.

It enrolls, then discovers the Go services by capability (never a hardcoded address) and invokes their
tools directly over the mesh:

    discover 'inventory'  ->  list its tools, then call inventory.check
    discover 'quote'      ->  call quote.price (which itself calls the inventory peer — a Python→Go→Go chain)
    try inventory.reserve ->  DENIED: it's restricted + allow-listed to the dispatch service, not us

This is the showcase, seen from another language: a Python agent is a first-class peer that finds and calls
the Go agents' tools. Bring up the showcase first (examples/showcase/run-local.sh with INTERACTIVE=1, or the
docker compose), then run this. Built on the j3nna_mesh SDK — stdlib + `cryptography`.
"""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "sdks", "python", "src"))
from j3nna_mesh import discovery, enroll, mcp  # noqa: E402


def env(k, d):
    return os.environ.get(k, d)


def find(seeds, record, root, cap):
    for _ in range(30):
        peers = discovery.discover(seeds, record, root=root, want_cap=cap)
        if peers:
            return peers[0]
        time.sleep(1)
    return None


def main():
    console = env("SHOWCASE_CONSOLE", "http://127.0.0.1:8455")
    seeds = [s for s in env("SHOWCASE_SEEDS", "http://127.0.0.1:8483").split(",") if s.strip()]
    name = env("SHOWCASE_NAME", "py-showcase")
    id_path = env("SHOWCASE_IDENTITY", "py-showcase.id")
    endpoint = env("SHOWCASE_ADVERTISE", "http://127.0.0.1:1/")  # client-only: we call out, nobody dials us

    print(f"showcase(py): enrolling with console {console} …")
    ident, grant, root = enroll(
        console, name, id_path,
        on_oob=lambda o: print(f"showcase(py): APPROVE this enrollment — out-of-band code {o}"))
    print(f"showcase(py): enrolled — grant {grant['id'][:8]}…")
    record = discovery.build_presence(ident, grant, endpoint, ["showcase"])

    inv = find(seeds, record, root, "inventory")
    quote = find(seeds, record, root, "quote")
    if not inv or not quote:
        print("showcase(py): could not discover the inventory/quote peers — is the showcase running?")
        sys.exit(1)
    print(f"showcase(py): discovered inventory at {inv.mcp} and quote at {quote.mcp}")

    # 1) introspect + call a peer's tool (cross-language tools/list + tools/call)
    tools = [t["name"] for t in mcp.list_tools(inv.mcp)]
    print(f"showcase(py): inventory exposes {tools}")
    check = mcp.call_tool(inv.mcp, ident, "inventory.check", {"sku": "WIDGET"}, presenter=record)
    print(f"showcase(py): inventory.check WIDGET → {check}")

    # 2) call the quote service — which itself calls the inventory peer (Python → Go quote → Go inventory)
    priced = mcp.call_tool(quote.mcp, ident, "quote.price", {"sku": "WIDGET", "qty": 2}, presenter=record)
    print(f"showcase(py): quote.price 2×WIDGET → ${priced.get('price')} (quote {priced.get('quote_id')})")

    # 3) try the RESTRICTED tool — we are not allow-listed (only dispatch is), so it must be denied
    try:
        mcp.call_tool(inv.mcp, ident, "inventory.reserve", {"sku": "WIDGET", "qty": 1}, presenter=record)
        print("showcase(py): WARNING — inventory.reserve unexpectedly succeeded")
    except RuntimeError as e:
        print(f"showcase(py): inventory.reserve correctly DENIED (restricted, not allow-listed): {e}")

    print("showcase(py): done — a Python peer discovered and used the Go agents' tools over the mesh.")


if __name__ == "__main__":
    main()
