#!/usr/bin/env bash
# Start FastAPI backend (uvicorn)
set -euo pipefail

VENV_DIR="${VENV_DIR:-$HOME/systemBoam-service/.venv}"
BACKEND_DIR="${BACKEND_DIR:-$HOME/systemBoam-service/backend-main}"

HOST="${HOST:-127.0.0.1}"   # keep loopback; Next.js rewrite hits this on same EC2
PORT="${PORT:-8000}"

# Activate venv
# shellcheck disable=SC1090
source "$VENV_DIR/bin/activate"

cd "$BACKEND_DIR"

export PYTHONUNBUFFERED=1

echo "[backend] Starting uvicorn on http://$HOST:$PORT"
exec uvicorn app.main:app --host "$HOST" --port "$PORT" --reload
