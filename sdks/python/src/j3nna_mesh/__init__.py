# Copyright 2026 J3nna Technologies, LLC
# SPDX-License-Identifier: Apache-2.0
"""J3nna Mesh SDK for Python — a peer that speaks the J3nna Integration Protocol (JIP): cryptographic
identity, console enrollment, peer discovery, offline grant/CRL verification, MCP tool calls, and rooms.
Wire-compatible with the Go reference (validated against jip/conformance/vectors.json)."""

from . import discovery, mcp, rooms, wire
from .discovery import Peer, build_presence, discover
from .enroll import enroll, fetch_root
from .identity import Identity, ensure_identity

__all__ = [
    "wire", "discovery", "mcp", "rooms", "enroll", "fetch_root", "Identity", "ensure_identity",
    "Peer", "build_presence", "discover",
]
__version__ = "0.1.0"
