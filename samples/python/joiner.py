#!/usr/bin/env python3
# Copyright 2026 J3nna Technologies, LLC
# SPDX-License-Identifier: Apache-2.0
"""A J3nna Mesh peer in Python — the full authorized-collaboration loop, mirroring samples/joiner (Go):

    enroll with the console   ->  receive a signed grant + the authority root
    discover a 'rooms' peer    ->  the room agent, found over gossip (not hardcoded)
    join its room + post       ->  collaborate, all authorized, with one trace for telemetry

Run the console and a room-agent first, then this; approve the enrollment in the console (match the
out-of-band code it prints). Built on the j3nna_mesh SDK — pure stdlib + `cryptography`.
"""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "sdks", "python", "src"))
from j3nna_mesh import discovery, enroll, rooms, wire  # noqa: E402


def env(k, d):
    return os.environ.get(k, d)


def main():
    console = env("SAMPLE_CONSOLE", "http://127.0.0.1:18455")
    seeds = [s for s in env("SAMPLE_SEEDS", "http://127.0.0.1:18482").split(",") if s.strip()]
    room = env("SAMPLE_ROOM", "lobby")
    name = env("SAMPLE_NAME", "py-joiner")
    id_path = env("SAMPLE_IDENTITY", "py-joiner.id")
    # A client-only peer: it polls history, so its advertised endpoint need not be reachable.
    endpoint = env("SAMPLE_ADVERTISE", "http://127.0.0.1:1/")

    print(f"joiner: enrolling with console {console} …")
    ident, grant, root = enroll(
        console, name, id_path,
        on_oob=lambda o: print(f"joiner: APPROVE this enrollment in the console — out-of-band code {o}"))
    print(f"joiner: enrolled — grant {grant['id'][:8]}…")

    record = discovery.build_presence(ident, grant, endpoint, ["sample"])
    host = None
    for _ in range(30):
        peers = discovery.discover(seeds, record, root=root, want_cap="rooms")
        if peers:
            host = peers[0].mcp
            break
        time.sleep(1)
    if not host:
        print("joiner: no authorized room agent discovered on the mesh")
        sys.exit(1)
    print(f"joiner: discovered room agent at {host} — joining #{room}")

    # One trace for the whole session — so a telemetry backend stitches these calls into one operation.
    trace = wire.new_traceparent()
    rooms.join(host, ident, room, name, endpoint, presenter=record, trace=trace)
    rooms.post(host, ident, room, f"hello from {name} — Python peer, authorized and present.",
               presenter=record, trace=trace)
    hist = rooms.history(host, ident, room, since=0, presenter=record, trace=trace)

    msgs = hist.get("messages", [])
    print(f"joiner: #{room} has {len(msgs)} message(s):")
    for m in msgs:
        if (m.get("text") or "").strip():
            print(f"joiner:   {m['from'][:8]}: {m['text']}")
    print(f"joiner: collaboration loop complete — trace {trace[3:11]}")


if __name__ == "__main__":
    main()
