#!/usr/bin/env bash
# Start the USB Shield web dashboard (Vite dev server).
set -euo pipefail
cd "$(dirname "$0")/../frontend"
if [ ! -d node_modules ]; then
  npm install --no-audit --no-fund
fi
export VITE_PORT="${VITE_PORT:-3847}"
exec npm run dev -- --host 0.0.0.0 --port "$VITE_PORT"
