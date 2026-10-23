#!/usr/bin/env bash
# Start the USB Shield local scanning agent (development configuration).
set -euo pipefail
cd "$(dirname "$0")/.."

VENV="agent/.venv"
if [ ! -x "$VENV/bin/python" ]; then
  echo "creating virtualenv..."
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install --quiet --upgrade pip
  "$VENV/bin/pip" install --quiet -r agent/requirements-dev.txt
fi

# In a sandboxed preview environment (E2B), allow the preview origin so the
# browser may reach the agent through the Vite same-origin proxy.
ORIGINS="http://localhost:3847,http://127.0.0.1:3847"
if [ -n "${E2B_SANDBOX_ID:-}" ]; then
  PORT="${VITE_PORT:-3847}"
  ORIGINS="$ORIGINS,https://${PORT}-${E2B_SANDBOX_ID}.e2b.app,http://${PORT}-${E2B_SANDBOX_ID}.e2b.app"
fi

export USBSHIELD_ALLOWED_ORIGINS="${USBSHIELD_ALLOWED_ORIGINS:-$ORIGINS}"
export USBSHIELD_DEV_DEMO="${USBSHIELD_DEV_DEMO:-true}"
export USBSHIELD_DATA_DIR="${USBSHIELD_DATA_DIR:-$PWD/agent/data}"
export USBSHIELD_SESSION_SECURE="${USBSHIELD_SESSION_SECURE:-false}"

echo "USB Shield agent → http://127.0.0.1:8765"
echo "  data dir : $USBSHIELD_DATA_DIR"
echo "  origins  : $USBSHIELD_ALLOWED_ORIGINS"
echo "  demo     : $USBSHIELD_DEV_DEMO (development only)"
cd agent
exec ".venv/bin/python" -m usb_shield
