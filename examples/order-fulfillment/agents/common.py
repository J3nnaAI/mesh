# Copyright 2026 J3nna Technologies, LLC
# SPDX-License-Identifier: Apache-2.0
"""Shared base for the order-fulfillment agents. Each agent is a J3nna Mesh peer (Python SDK) that:
  - enrolls with the console and discovers the kernel-service (cap "memory") + the room host (cap "rooms");
  - reads/writes the SHARED kernel graph via mem.* tool calls;
  - coordinates with the other agents over a room used as an EVENT BUS (events are JSON room messages).
No agent calls another agent directly — they interact through shared state + events (choreography), which is
how real distributed systems compose. Robust startup (retries with backoff) so it survives container races.
"""

import json
import os
import sys
import time

# Locate the SDK: installed, or via J3NNA_SDK / the in-repo path.
_sdk = os.environ.get("J3NNA_SDK")
if _sdk:
    sys.path.insert(0, _sdk)
else:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "sdks", "python", "src"))
from j3nna_mesh import discovery, enroll, mcp, rooms, wire  # noqa: E402


def _env(k, d):
    return os.environ.get(k, d)


class Agent:
    def __init__(self, name, caps=("ofx",), requires=()):
        self.name = name
        self.console = _env("OFX_CONSOLE", "http://127.0.0.1:18455")
        self.seeds = [s for s in _env("OFX_SEEDS", "http://127.0.0.1:18482").split(",") if s.strip()]
        self.room = _env("OFX_ROOM", "ops")
        self.id_path = _env("OFX_IDENTITY", f"/tmp/{name}.id")
        self.endpoint = "http://127.0.0.1:1/"   # client-only peer; advertised endpoint need not be reachable
        self.caps = list(caps)
        self.requires = list(requires)   # dependency capabilities that must be operational before we start
        self.peers = {}                  # cap -> mcp url, populated once each dependency is ready
        self.last_seq = 0
        self._connect()

    # ---- connection (robust) ----
    def _connect(self):
        for attempt in range(60):
            try:
                self.ident, self.grant, self.root = enroll(self.console, self.name, self.id_path,
                                                           on_oob=lambda o: None, timeout=120)
                self.presence = discovery.build_presence(self.ident, self.grant, self.endpoint, self.caps)
                self.trace = wire.new_traceparent()
                # Don't start talking until EVERY dependency is up and fully operational: the room (the event
                # bus) plus each declared capability. We wait for each to be discoverable AND to answer MCP.
                needed = ["rooms"] + [c for c in self.requires if c != "rooms"]
                for cap in needed:
                    self.log(f"waiting for dependency {cap!r}…")
                    self.peers[cap] = self._wait_ready(cap)
                self.host = self.peers["rooms"]
                self.mem = self.peers.get("memory")
                rooms.join(self.host, self.ident, self.room, self.name, self.endpoint,
                           presenter=self.presence, trace=self.trace)
                self.log(f"READY (node {self.ident.id[:8]}…) — dependencies operational: {', '.join(needed)}")
                return
            except Exception as e:  # noqa: BLE001
                self.log(f"connect retry ({attempt}): {e}")
                time.sleep(2)
        raise RuntimeError(f"{self.name}: could not connect")

    def _wait_ready(self, cap, timeout=120):
        """Block until a peer advertising `cap` is BOTH discoverable and operational (answers a tools/list
        liveness probe, which never mutates). This is the readiness gate that keeps an agent from talking to
        a dependency that has merely announced presence but isn't serving yet."""
        for _ in range(timeout):
            url = None
            for p in discovery.discover(self.seeds, self.presence, root=self.root, want_cap=cap):
                if cap in p.caps:
                    url = p.mcp
                    break
            if url:
                try:
                    mcp.list_tools(url)
                    return url
                except Exception:  # noqa: BLE001
                    pass  # discovered but not yet serving — keep waiting
            time.sleep(1)
        raise RuntimeError(f"{self.name}: dependency {cap!r} not operational within {timeout}s")

    # ---- generic peer tool call ----
    def call_peer(self, mcp_url, tool, args):
        return mcp.call_tool(mcp_url, self.ident, tool, args, presenter=self.presence, trace=self.trace)

    def discover_cap(self, cap):
        return self._wait_ready(cap)

    # ---- shared kernel memory (mem.* tools) ----
    def _mem(self, tool, args):
        return self.call_peer(self.mem, tool, args)

    def put(self, node_id, kind, label, body):
        return self._mem("mem.put", {"id": node_id, "kind": kind, "label": label, "body": json.dumps(body)})

    def get(self, node_id):
        try:
            n = self._mem("mem.get", {"id": node_id})
        except Exception:  # noqa: BLE001
            return None
        return json.loads(n["body"]) if n.get("body") else {}

    def link(self, frm, to, rel):
        return self._mem("mem.link", {"from": frm, "to": to, "rel": rel})

    def neighbors(self, node_id, rel, direction="out"):
        return self._mem("mem.neighbors", {"id": node_id, "rel": rel, "dir": direction}).get("nodes", [])

    def allocate(self, item, qty):
        return self._mem("mem.allocate", {"id": item, "qty": qty})

    def restock(self, item, qty):
        return self._mem("mem.restock", {"id": item, "qty": qty})

    def query(self, prefix=None, kind=None):
        a = {}
        if prefix:
            a["prefix"] = prefix
        if kind:
            a["kind"] = kind
        return self._mem("mem.query", a).get("nodes", [])

    # ---- event bus (the room) ----
    def emit(self, event, **fields):
        rooms.post(self.host, self.ident, self.room, json.dumps({"event": event, **fields}),
                   presenter=self.presence, trace=self.trace)
        self.log(f"→ {event} {fields}")

    def poll_events(self):
        """New events since last poll (dicts), de-duplicated by room sequence."""
        hist = rooms.history(self.host, self.ident, self.room, since=0, presenter=self.presence, trace=self.trace)
        out = []
        for m in hist.get("messages", []):
            seq = m.get("seq", 0)
            if seq <= self.last_seq:
                continue
            self.last_seq = seq
            txt = (m.get("text") or "").strip()
            if txt.startswith("{"):
                try:
                    ev = json.loads(txt)
                    if "event" in ev:
                        out.append(ev)
                except Exception:  # noqa: BLE001
                    pass
        return out

    def run(self, on_event, idle=None):
        """Poll the event bus, dispatching each new event to on_event(ev). The interval (OFX_POLL, default
        1.0s) trades a little responsiveness for much quieter telemetry — every poll is a room.history call,
        so a tight interval floods the monitor with poll noise that buries the real choreography events."""
        if idle is None:
            idle = float(_env("OFX_POLL", "1.0"))
        while True:
            for ev in self.poll_events():
                try:
                    on_event(ev)
                except Exception as e:  # noqa: BLE001
                    self.log(f"!! handling {ev.get('event')}: {e}")
            time.sleep(idle)

    def log(self, *a):
        print(f"[{self.name}]", *a, flush=True)
