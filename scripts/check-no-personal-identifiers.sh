#!/usr/bin/env bash
# Release gate: NO personal / deployment-specific identifiers in shippable source (code or comments).
# Personal names belong in config/data, never in the public infrastructure. Non-zero exit = blocked.
set -euo pipefail
# Personal names + private personas that must never ship. (AI product names — Claude, Cursor, Codex,
# Copilot — are NOT here: they are named intentionally in AGENTS.md / CLAUDE.md as supported assistants.)
DENY='Jason|Amber|Wes|Mariah|Roni|Mira|Jade'
roots=("$@"); [ ${#roots[@]} -eq 0 ] && roots=(.)
hits="$(grep -rnIE "\b(${DENY})\b" "${roots[@]}" --include='*.go' --include='*.md' --include='*.sh' --exclude='check-no-personal-identifiers.sh' 2>/dev/null | grep -v '_test.go' || true)"
if [ -n "$hits" ]; then
  echo "✗ personal identifiers found in Mesh source (move to config/data):"
  echo "$hits"
  exit 1
fi
echo "✓ clean — no personal identifiers in Mesh source"
