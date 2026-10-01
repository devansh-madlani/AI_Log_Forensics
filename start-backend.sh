#!/usr/bin/env bash
# Start the backend on Linux or macOS with the rights live collection needs.
#
#   ./start-backend.sh
#
# Auth logs (SSH, sudo, useradd) and the safe test incident need root, so
# this re-runs itself with sudo when it isn't already root.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Requesting root (sudo)..."
  exec sudo "$0" "$@"
fi

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT/backend"

for candidate in "$ROOT/backend/venv/bin/python" "$ROOT/.venv/bin/python"; do
  if [[ -x "$candidate" ]]; then PYTHON="$candidate"; break; fi
done
if [[ -z "${PYTHON:-}" ]]; then
  echo "No virtual environment found (backend/venv or .venv). Set it up first (see README: Backend setup)." >&2
  exit 1
fi

echo "Backend running as root on http://127.0.0.1:8000  (Ctrl+C to stop)"
exec "$PYTHON" -m uvicorn app.main:app --host 127.0.0.1 --port 8000
