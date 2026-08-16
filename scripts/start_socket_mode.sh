#!/usr/bin/env bash
# Start Aegis in Socket Mode — no public URL, no tunnel.
#
#   bash scripts/start_socket_mode.sh
#
# Reads .env if present. See docs/E2E.md for the full two-workspace setup.
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ -f .env ]]; then
  echo "Loading .env"
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

missing=()
for var in SLACK_BOT_TOKEN SLACK_APP_TOKEN OUR_TEAM_ID; do
  [[ -n "${!var:-}" ]] || missing+=("$var")
done

if (( ${#missing[@]} )); then
  echo "Missing required settings: ${missing[*]}" >&2
  echo >&2
  echo "Copy .env.example to .env and fill it in. OUR_TEAM_ID is your own workspace's" >&2
  echo "team ID — messages from it are treated as internal and never scanned." >&2
  exit 1
fi

if [[ "${SLACK_APP_TOKEN}" != xapp-* ]]; then
  echo "SLACK_APP_TOKEN should start with 'xapp-' (app-level token, connections:write)." >&2
  exit 1
fi

if [[ "${SLACK_BOT_TOKEN}" != xoxb-* ]]; then
  echo "SLACK_BOT_TOKEN should start with 'xoxb-' (bot token)." >&2
  exit 1
fi

export SLACK_MODE=socket
export VENDOR_KEY="${VENDOR_KEY:-acme_supplies}"

echo "Vendor on file: ${VENDOR_KEY}"
echo "Our team (not scanned): ${OUR_TEAM_ID}"
echo "History source: ${HISTORY_SOURCE:-conversations}"
exec python app.py --socket
