#!/usr/bin/env bash
# Live dashboard for the order-fulfillment example. Brings the WHOLE telemetry-wired mesh up in the
# background (console + room-agent + kernel-service + vault-service + the 3 agents) and runs the monitor in
# THIS terminal, so the monitor owns the TTY and renders the flicker-free live dashboard. One command;
# Ctrl-C tears it all down. Needs Go + Python3 + the `cryptography` package; no Docker, no prerequisites.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
MESH="$(cd "$HERE/../.." && pwd)"
BIN=/tmp/ofx-dashboard
MON=http://127.0.0.1:19000
C=http://127.0.0.1:18455
RA=http://127.0.0.1:18482
export OFX_CONSOLE=$C OFX_SEEDS=$RA OFX_ROOM=ops OFX_SEED="$HERE/inventory.jsonl" \
       J3NNA_SDK="$HERE/../../sdks/python/src"
log(){ echo "[dashboard] $*" >&2; }
die(){ log "$*"; exit 1; }

mkdir -p "$BIN"; rm -f "$BIN"/*.id "$BIN"/*.enc "$BIN"/*.key 2>/dev/null
log "building binaries (first run only is slow)…"
( cd "$MESH/console"        && GOTOOLCHAIN=auto go build -o "$BIN/console" . )            || die "console build failed"
( cd "$MESH/room-agent"     && GOTOOLCHAIN=auto go build -o "$BIN/room-agent" . )         || die "room-agent build failed"
( cd "$MESH/monitor"        && GOWORK=off GOTOOLCHAIN=auto go build -o "$BIN/monitor" . ) || die "monitor build failed"
( cd "$HERE/kernel-service" && GOWORK=off GOTOOLCHAIN=auto go build -o "$BIN/ksvc" . )    || die "kernel-service build failed"
( cd "$HERE/vault-service"  && GOWORK=off GOTOOLCHAIN=auto go build -o "$BIN/vsvc" . )    || die "vault-service build failed"

cleanup(){ echo; log "tearing down…"; pkill -f '[/]tmp/ofx-dashboard' 2>/dev/null; pkill -f '[o]rder-fulfillment/agents' 2>/dev/null; }
trap cleanup EXIT INT TERM

# Bring the mesh up only AFTER the monitor is listening, so the dashboard catches everything from the very
# first grant. Every peer points its telemetry at the monitor.
(
  for _ in $(seq 1 80); do curl -fsS "$MON/healthz" >/dev/null 2>&1 && break; sleep 0.2; done
  ( cd "$BIN" && CONSOLE_ADDR=127.0.0.1:18455 CONSOLE_VAULT_PASSPHRASE=change-me CONSOLE_DEV_AUTOAPPROVE=1 \
      JIP_TELEMETRY_URL="$MON/events" ./console ) >/dev/null 2>&1 &
  for _ in $(seq 1 60); do curl -fsS "$C/authority" >/dev/null 2>&1 && break; sleep 0.3; done
  ROOM_AGENT_CONSOLE=$C ROOM_AGENT_ADVERTISE=$RA ROOM_AGENT_LISTEN=127.0.0.1:18482 ROOM_AGENT_DISCOVER=false \
    ROOM_AGENT_IDENTITY="$BIN/room-agent.id" JIP_TELEMETRY_URL="$MON/events" "$BIN/room-agent" >/dev/null 2>&1 &
  for _ in $(seq 1 60); do curl -fsS "$RA/whoami" >/dev/null 2>&1 && break; sleep 0.3; done
  KSVC_CONSOLE=$C KSVC_SEEDS=$RA KSVC_ADVERTISE=http://127.0.0.1:18490 KSVC_LISTEN=127.0.0.1:18490 \
    KSVC_IDENTITY="$BIN/ksvc.id" KSVC_SEED="$HERE/inventory.jsonl" JIP_TELEMETRY_URL="$MON/events" "$BIN/ksvc" >/dev/null 2>&1 &
  VSVC_CONSOLE=$C VSVC_SEEDS=$RA VSVC_ADVERTISE=http://127.0.0.1:18491 VSVC_LISTEN=127.0.0.1:18491 \
    VSVC_IDENTITY="$BIN/vsvc.id" VSVC_VAULT="$BIN/ofx-vault.enc" OFX_VAULT_PASSPHRASE=dev-passphrase \
    JIP_TELEMETRY_URL="$MON/events" "$BIN/vsvc" >/dev/null 2>&1 &
  sleep 4
  OFX_IDENTITY="$BIN/pricing.id"     python3 "$HERE/agents/pricing.py"     >/dev/null 2>&1 &
  OFX_IDENTITY="$BIN/fulfillment.id" python3 "$HERE/agents/fulfillment.py" >/dev/null 2>&1 &
  sleep 4
  OFX_IDENTITY="$BIN/intake.id"      python3 "$HERE/agents/intake.py"      >/dev/null 2>&1 &
  log "mesh up — orders flowing; watch the dashboard"
) &

log "starting live dashboard — Ctrl-C to stop"
sleep 0.4
MONITOR_ADDR=127.0.0.1:19000 "$BIN/monitor"
