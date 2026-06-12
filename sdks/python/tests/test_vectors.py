# Copyright 2026 J3nna Technologies, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Offline wire-conformance validator for the Python SDK. Proves that wire.py reproduces the canonical
# signing bytes byte-for-byte and verifies the reference ed25519 signatures from the shared
# jip/conformance/vectors.json — the SAME fixtures the Go reference and the other SDKs assert against
# (mirrors sdks/typescript/test_conformance.mjs). This is the offline counterpart to the live tests:
# it needs no running mesh, only the SDK and the vectors.
#
#   cd sdks/python && PYTHONPATH=src python3 tests/test_vectors.py   # exits 0 on pass, nonzero on mismatch
#
# The vectors carry no private seeds, so the sign path is not exercised here (the live tests + the
# round-trip in the Node conformance test cover signing); this asserts signing-bytes + verify.

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from j3nna_mesh import wire  # noqa: E402

# The canonical vectors live in the jip repo, beside the other languages' conformance tests.
VECTORS_PATH = "/home/j3nna/web-stt-tts/jip/conformance/vectors.json"


def _hex(h: str) -> bytes:
    return bytes.fromhex(h)


# Bridge each vector's hex inputs into the SDK's raw-bytes wire functions.
BUILDERS = {
    "presence-record": lambda i: wire.presence_signing_bytes(
        protocol=i["protocol"], alg=i["alg"], id=i["id"],
        public_key=_hex(i["public_key_hex"]), endpoint=i["endpoint"], mcp_path=i["mcp_path"],
        capabilities=i["capabilities"], protocol_major=i["protocol_major"],
        grant_id=i["grant_id"], heartbeat_unix=i["heartbeat_unix"],
    ),
    "grant": lambda i: wire.grant_signing_bytes(
        alg=i["alg"], id=i["id"], subject=i["subject"], public_key=_hex(i["public_key_hex"]),
        tier=i["tier"], scopes=i["scopes"], issued_at=i["issued_at"], not_after=i["not_after"],
        principal=i.get("principal", ""),
    ),
    "callproof": lambda i: wire.callproof_signing_bytes(
        alg=i["alg"], node_id=i["node_id"], tool=i["tool"],
        args_hash=_hex(i["args_hash_hex"]), unix_milli=i["unix_milli"],
    ),
    "renewal": lambda i: wire.renew_signing_bytes(
        alg=i["alg"], grant_id=i["grant_id"], subject=i["subject"],
        public_key=_hex(i["public_key_hex"]), issued_at=i["issued_at"],
    ),
    "crl": lambda i: wire.crl_signing_bytes(
        alg=i["alg"], issued_at=i["issued_at"], revoked_ids=sorted(i["revoked"].keys()),
    ),
}


def verify_vectors() -> int:
    with open(VECTORS_PATH, "r", encoding="utf-8") as f:
        vectors = json.load(f)
    if vectors.get("protocol") != "JIP/0.1":
        raise SystemExit(f"unexpected protocol {vectors.get('protocol')}")

    for v in vectors["vectors"]:
        build = BUILDERS.get(v["name"])
        if build is None:
            raise SystemExit(f"no builder for vector {v['name']}")

        got = build(v["input"])
        want = v["signing_bytes_hex"]
        if got.hex() != want:
            raise SystemExit(
                f"{v['name']}: signing bytes differ\n  got:  {got.hex()}\n  want: {want}"
            )

        # ed25519-verify the reference signature over our bytes against the signer's public key.
        import base64
        pub = _hex(v["signer_public_key_hex"])
        sig = base64.b64decode(v["signature_b64"])
        if not wire.verify(pub, sig, got):
            raise SystemExit(f"{v['name']}: signature did not verify")

        # Extra check for callproof: reproduce Go's canonical args JSON + hash byte-for-byte.
        if v["name"] == "callproof":
            cj = wire.canonical_args_json(v["input"]["args"]).decode("utf-8")
            if cj != v["input"]["args_canonical_json"]:
                raise SystemExit("args canonical JSON differs from Go")
            if wire.args_hash(v["input"]["args"]).hex() != v["input"]["args_hash_hex"]:
                raise SystemExit("args hash differs")

        print(f"  ok  {v['name']}  (signing-bytes + ed25519 verify)")

    n = len(vectors["vectors"])
    print(f"PASS: {n} vectors verified")
    return n


if __name__ == "__main__":
    verify_vectors()
