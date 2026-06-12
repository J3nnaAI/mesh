#!/usr/bin/env bash
# Local-first runner — proves the order-fulfillment choreography against an already-running console (:18455)
# and room-agent (:18482). Starts a DEV loopback auto-approver, the kernel-service, the 3 agents, then the
# verifier (whose exit code is this script's). The self-contained, no-prereq path is `docker compose up`.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
C=${OFX_CONSOLE:-http://127.0.0.1:18455}
SEED=${OFX_SEEDS:-http://127.0.0.1:18482}
export OFX_CONSOLE="$C" OFX_SEEDS="$SEED" OFX_ROOM="ops-$(date +%s)" \
       OFX_SEED="$HERE/inventory.jsonl" J3NNA_SDK="$HERE/../../sdks/python/src"
MON=${OFX_MONITOR:-}   # set OFX_MONITOR=http://127.0.0.1:19000/events to stream into the telemetry monitor
log(){ echo "[run-local] $*"; }

curl -fsS "$C/authority" >/dev/null 2>&1 || { log "console $C not up — start the console + room-agent first (see QUICKSTART)"; exit 1; }

# DEV-ONLY loopback auto-approver
( while true; do
    curl -fsS "$C/enroll/pending" 2>/dev/null | python3 -c '
import sys,json,urllib.request
for r in json.load(sys.stdin).get("pending",[]):
    b=json.dumps({"oob":r["oob"]}).encode()
    rq=urllib.request.Request("'"$C"'/enroll/%s/approve"%r["id"],data=b,headers={"content-type":"application/json"},method="POST")
    try: urllib.request.urlopen(rq)
    except Exception: pass
' 2>/dev/null
    sleep 0.5
  done ) & APPROVER=$!

cleanup(){ kill $APPROVER $KSVC $VSVC $PRICING $FULFILL $INTAKE 2>/dev/null; }
trap cleanup EXIT

# kernel-service (shared memory)
log "building + starting kernel-service…"
( cd "$HERE/kernel-service" && GOWORK=off GOTOOLCHAIN=auto go build -o ksvc . ) || { log "kernel-service build failed"; exit 1; }
rm -f /tmp/ofx-ksvc.id
( cd "$HERE/kernel-service" && KSVC_CONSOLE="$C" KSVC_SEEDS="$SEED" KSVC_ADVERTISE=http://127.0.0.1:18490 \
    KSVC_LISTEN=127.0.0.1:18490 KSVC_IDENTITY=/tmp/ofx-ksvc.id KSVC_SEED="$HERE/inventory.jsonl" \
    JIP_TELEMETRY_URL="$MON" ./ksvc ) >/tmp/ofx-ksvc.log 2>&1 & KSVC=$!
for i in $(seq 1 30); do grep -q 'live — mem' /tmp/ofx-ksvc.log 2>/dev/null && break; sleep 1; done
grep -q 'live — mem' /tmp/ofx-ksvc.log || { log "kernel-service did not come up"; tail /tmp/ofx-ksvc.log; exit 1; }
log "kernel-service live"

# vault-service (secrets)
log "building + starting vault-service…"
( cd "$HERE/vault-service" && GOWORK=off GOTOOLCHAIN=auto go build -o vsvc . ) || { log "vault-service build failed"; exit 1; }
rm -f /tmp/ofx-vsvc.id "$HERE/vault-service/ofx-vault.enc"
( cd "$HERE/vault-service" && VSVC_CONSOLE="$C" VSVC_SEEDS="$SEED" VSVC_ADVERTISE=http://127.0.0.1:18491 \
    VSVC_LISTEN=127.0.0.1:18491 VSVC_IDENTITY=/tmp/ofx-vsvc.id OFX_VAULT_PASSPHRASE=dev-passphrase \
    JIP_TELEMETRY_URL="$MON" ./vsvc ) >/tmp/ofx-vsvc.log 2>&1 & VSVC=$!
for i in $(seq 1 30); do grep -q 'live — secret' /tmp/ofx-vsvc.log 2>/dev/null && break; sleep 1; done
grep -q 'live — secret' /tmp/ofx-vsvc.log || { log "vault-service did not come up"; tail /tmp/ofx-vsvc.log; exit 1; }
log "vault-service live"

cd "$HERE/agents"
rm -f /tmp/ofx-{intake,pricing,fulfillment,verifier}.id
OFX_IDENTITY=/tmp/ofx-pricing.id     python3 pricing.py     >/tmp/ofx-pricing.log     2>&1 & PRICING=$!
OFX_IDENTITY=/tmp/ofx-fulfillment.id python3 fulfillment.py >/tmp/ofx-fulfillment.log 2>&1 & FULFILL=$!
sleep 5   # let the reactive agents connect + join before intake floods events
OFX_IDENTITY=/tmp/ofx-intake.id      python3 intake.py      >/tmp/ofx-intake.log      2>&1 & INTAKE=$!

log "running verifier…"
OFX_IDENTITY=/tmp/ofx-verifier.id python3 verifier.py
rc=$?
echo; log "agent logs: /tmp/ofx-{intake,pricing,fulfillment}.log"
exit $rc
