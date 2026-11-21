#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
PORT="${PORT:-8765}"
URL="http://localhost:${PORT}/"

echo "Starting Khazna locally at ${URL} (100% offline, 127.0.0.1 only)..."

if command -v open >/dev/null 2>&1; then
  (sleep 1 && open "${URL}") &
elif command -v xdg-open >/dev/null 2>&1; then
  (sleep 1 && xdg-open "${URL}") &
fi

if command -v node >/dev/null 2>&1; then
  PORT="${PORT}" node ./local-server.mjs
elif command -v python3 >/dev/null 2>&1; then
  python3 -m http.server "${PORT}" --bind 127.0.0.1
else
  echo "Please install Node.js or Python 3, or serve this folder over http://localhost."
  exit 1
fi
