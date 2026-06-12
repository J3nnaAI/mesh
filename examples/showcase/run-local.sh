#!/usr/bin/env bash
# run-local.sh — bring up the whole showcase on loopback and verify the human-driven flow end to end.
#
# Topology (all 127.0.0.1, multicast + gossip discovery):
#   console (authority)         :8455
#   signal-bridge               mesh :8483  mgmt/hook :8484   → HMAC webhook → carrier
#   carrier (external, no mesh) :8494
#   inventory-svc               :8490   (shared kernel; inventory.reserve allow-listed to dispatch)
#   quote-svc                   :8491   (discovers inventory, invokes inventory.check)
#   dispatch-svc                :8492   (restricted inventory.reserve + own-vault manifest sign + signal)
#   desk                        :8493   (hosts room "desk", routes the human's 1/2)
#   room-view (human)           mesh :8485  web :8487
#
# CI mode (default): drives room-view's API to choose 1 then 2, asserts both ship, exits non-zero on failure.
# INTERACTIVE=1: leaves everything running and prints the room-view URL so you can choose 1/2 yourself.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
log(){ echo "[showcase] $*"; }
GO(){ GOWORK=off GOTOOLCHAIN=auto go "$@"; }

C=http://127.0.0.1:8455
SB_MESH=http://127.0.0.1:8483
SEEDS=$SB_MESH                 # gossip seed; multicast is also on
PASS=dev-passphrase
PIDS=()
APPROVER=""
cleanup(){ [ ${#PIDS[@]} -gt 0 ] && kill "${PIDS[@]}" 2>/dev/null; [ -n "$APPROVER" ] && kill "$APPROVER" 2>/dev/null; true; }
trap cleanup EXIT

need(){ command -v "$1" >/dev/null || { log "missing required tool: $1"; exit 1; }; }
need curl; need go

build(){ # build <dir> <out> — GOWORK=off, for the showcase modules (own go.mod + replace directives)
  ( cd "$1" && GO build -o "$2" . ) || { log "build failed: $1"; exit 1; }
}
buildWS(){ # buildWS <module-rel-to-root> <out> — workspace build, for the monorepo modules (go.work)
  ( cd "$ROOT" && GOTOOLCHAIN=auto go build -o "$2" "./$1" ) || { log "build failed (ws): $1"; exit 1; }
}
waitlog(){ # waitlog <logfile> <pattern> <label>
  for _ in $(seq 1 40); do grep -q "$2" "$1" 2>/dev/null && return 0; sleep 0.5; done
  log "$3 did not come up; tail:"; tail -n 8 "$1"; exit 1
}
post(){ curl -fsS -X POST -H 'content-type: application/json' -d "$2" "$1"; }

rm -f /tmp/sc-*.log /tmp/sc-*.id "$HERE"/dispatch-svc/*.enc "$HERE"/sb-vault.enc

# ── console ────────────────────────────────────────────────────────────────
log "building + starting console…"
buildWS console /tmp/sc-console
CONSOLE_ADDR=127.0.0.1:8455 CONSOLE_VAULT_PASSPHRASE="$PASS" CONSOLE_ROOT_KEY=/tmp/sc-root.key \
  CONSOLE_VAULT=/tmp/sc-console-vault.enc CONSOLE_CRL=/tmp/sc-crl.json /tmp/sc-console >/tmp/sc-console.log 2>&1 & PIDS+=($!)
for _ in $(seq 1 40); do curl -fsS "$C/authority" >/dev/null 2>&1 && break; sleep 0.5; done
curl -fsS "$C/authority" >/dev/null 2>&1 || { log "console did not come up"; tail /tmp/sc-console.log; exit 1; }
log "console live"

# DEV loopback auto-approver (approves every enrollment; loopback is trusted)
( while true; do
    curl -fsS "$C/enroll/pending" 2>/dev/null | python3 -c '
import sys,json,urllib.request
try: d=json.load(sys.stdin)
except Exception: d={}
for r in d.get("pending",[]):
    b=json.dumps({"oob":r["oob"]}).encode()
    rq=urllib.request.Request("'"$C"'/enroll/%s/approve"%r["id"],data=b,headers={"content-type":"application/json"},method="POST")
    try: urllib.request.urlopen(rq)
    except Exception: pass
' 2>/dev/null; sleep 0.4; done ) & APPROVER=$!

# ── signal-bridge ──────────────────────────────────────────────────────────
log "building + starting signal-bridge…"
buildWS signal-bridge /tmp/sc-sb
SIGNAL_LISTEN=0.0.0.0:8483 SIGNAL_ADVERTISE=$SB_MESH SIGNAL_HTTP=127.0.0.1:8484 SIGNAL_CONSOLE=$C \
  SIGNAL_VAULT=/tmp/sc-sb-vault.enc SIGNAL_VAULT_PASSPHRASE="$PASS" SIGNAL_IDENTITY=/tmp/sc-sb.id \
  /tmp/sc-sb >/tmp/sc-sb.log 2>&1 & PIDS+=($!)
for _ in $(seq 1 40); do curl -fsS http://127.0.0.1:8484/healthz >/dev/null 2>&1 && break; sleep 0.5; done
curl -fsS http://127.0.0.1:8484/healthz >/dev/null 2>&1 || { log "signal-bridge did not come up"; tail /tmp/sc-sb.log; exit 1; }
log "signal-bridge live"

# register the carrier webhook → returns the HMAC secret the carrier verifies with
SECRET=$(post http://127.0.0.1:8484/webhooks '{"topic":"shipment","url":"http://127.0.0.1:8494/hook"}' | python3 -c 'import sys,json;print(json.load(sys.stdin).get("secret",""))')
[ -n "$SECRET" ] || { log "failed to register carrier webhook"; tail /tmp/sc-sb.log; exit 1; }
log "registered carrier webhook"

# ── carrier (external) ─────────────────────────────────────────────────────
log "building + starting carrier…"
build "$HERE/carrier" /tmp/sc-carrier
CARRIER_LISTEN=127.0.0.1:8494 CARRIER_HMAC_SECRET="$SECRET" /tmp/sc-carrier >/tmp/sc-carrier.log 2>&1 & PIDS+=($!)

# ── dispatch-svc (first, to learn its node id for the inventory allow-list) ─
log "building + starting dispatch-svc…"
build "$HERE/dispatch-svc" /tmp/sc-dispatch
DISPATCH_CONSOLE=$C DISPATCH_SEEDS=$SEEDS DISPATCH_ADVERTISE=http://127.0.0.1:8492 DISPATCH_LISTEN=127.0.0.1:8492 \
  DISPATCH_IDENTITY=/tmp/sc-dispatch.id DISPATCH_VAULT=/tmp/sc-dispatch-vault.enc DISPATCH_VAULT_PASSPHRASE="$PASS" \
  /tmp/sc-dispatch >/tmp/sc-dispatch.log 2>&1 & PIDS+=($!)
waitlog /tmp/sc-dispatch.log 'node id' 'dispatch-svc'

# ── inventory-svc (allow-lists dispatch for the restricted reserve) ────────
log "building + starting inventory-svc…"
build "$HERE/inventory-svc" /tmp/sc-inventory
INV_CONSOLE=$C INV_SEEDS=$SEEDS INV_ADVERTISE=http://127.0.0.1:8490 INV_LISTEN=127.0.0.1:8490 \
  INV_IDENTITY=/tmp/sc-inventory.id INV_ALLOW_URLS=http://127.0.0.1:8492 /tmp/sc-inventory >/tmp/sc-inventory.log 2>&1 & PIDS+=($!)
waitlog /tmp/sc-inventory.log 'live' 'inventory-svc'

# ── quote-svc + desk ───────────────────────────────────────────────────────
log "building + starting quote-svc + desk…"
build "$HERE/quote-svc" /tmp/sc-quote
QUOTE_CONSOLE=$C QUOTE_SEEDS=$SEEDS QUOTE_ADVERTISE=http://127.0.0.1:8491 QUOTE_LISTEN=127.0.0.1:8491 \
  QUOTE_IDENTITY=/tmp/sc-quote.id /tmp/sc-quote >/tmp/sc-quote.log 2>&1 & PIDS+=($!)
build "$HERE/desk" /tmp/sc-desk
DESK_CONSOLE=$C DESK_SEEDS=$SEEDS DESK_ADVERTISE=http://127.0.0.1:8493 DESK_LISTEN=127.0.0.1:8493 \
  DESK_IDENTITY=/tmp/sc-desk.id /tmp/sc-desk >/tmp/sc-desk.log 2>&1 & PIDS+=($!)
waitlog /tmp/sc-quote.log 'live' 'quote-svc'
waitlog /tmp/sc-desk.log 'live' 'desk'

# ── room-view (the human) ──────────────────────────────────────────────────
log "building + starting room-view…"
buildWS room-view /tmp/sc-roomview
ROOMVIEW_CONSOLE=$C ROOMVIEW_SEEDS=$SEEDS ROOMVIEW_ROOM=desk ROOMVIEW_NAME=patron \
  ROOMVIEW_LISTEN=0.0.0.0:8485 ROOMVIEW_ADVERTISE=http://127.0.0.1:8485 ROOMVIEW_HTTP=127.0.0.1:8487 \
  ROOMVIEW_IDENTITY=/tmp/sc-roomview.id /tmp/sc-roomview >/tmp/sc-roomview.log 2>&1 & PIDS+=($!)
# wait until room-view has joined the desk room
for _ in $(seq 1 40); do curl -fsS http://127.0.0.1:8487/api/state 2>/dev/null | grep -q '"joined":true' && break; sleep 0.5; done
curl -fsS http://127.0.0.1:8487/api/state 2>/dev/null | grep -q '"joined":true' || { log "room-view did not join the desk room"; tail /tmp/sc-roomview.log; exit 1; }
log "room-view joined the desk room"

if [ "${INTERACTIVE:-0}" = "1" ]; then
  log "INTERACTIVE — open http://127.0.0.1:8487 and type 1 or 2. Ctrl-C to stop."
  wait
fi

# ── drive the human choices and assert ─────────────────────────────────────
choose(){ # choose <text> <label>
  log "patron → \"$1\""
  post http://127.0.0.1:8487/api/post "{\"text\":\"$1\"}" >/dev/null
  for _ in $(seq 1 30); do
    if curl -fsS "http://127.0.0.1:8487/api/messages?since=0" 2>/dev/null | grep -q '✓.*shipped'; then return 0; fi
    sleep 0.5
  done
  log "FAIL ($2): no shipment confirmation in the room"; curl -fsS "http://127.0.0.1:8487/api/messages?since=0"; return 1
}
sleep 2
choose "1 GADGET 1" "quote→dispatch" || exit 1
log "✓ choice 1 (quote → dispatch) shipped"
choose "2 WIDGET 1" "dispatch→quote"  || exit 1
log "✓ choice 2 (dispatch → quote) shipped"
grep -q '✓ accepted signed' /tmp/sc-carrier.log && log "✓ carrier received HMAC-signed webhook" || { log "FAIL: carrier never accepted a signed webhook"; tail /tmp/sc-carrier.log; exit 1; }

log "ALL CHECKS PASSED — discovery, peer tool calls, restricted reserve+CallProof, shared kernel, vault sign, signal→carrier, human-in-room."
