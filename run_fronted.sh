#!/usr/bin/env bash
# Start Next.js frontend (pnpm dev)
set -euo pipefail

FRONTEND_DIR="${FRONTEND_DIR:-$HOME/systemBoam-service/frontend-main}"
PORT="${PORT:-3000}"
HOSTNAME="${HOSTNAME:-0.0.0.0}"

# Load nvm
export NVM_DIR="$HOME/.nvm"
if [[ -s "$NVM_DIR/nvm.sh" ]]; then
  # shellcheck disable=SC1091
  . "$NVM_DIR/nvm.sh"
else
  echo "nvm not found. Install: https://github.com/nvm-sh/nvm"
  exit 1
fi

# Ensure Node 22
nvm install 22 >/dev/null
nvm use 22

# Ensure pnpm via Corepack
if ! command -v pnpm >/dev/null 2>&1; then
  corepack enable
  corepack prepare pnpm@latest --activate
fi

cd "$FRONTEND_DIR"

# Install deps (idempotent)
pnpm install

echo "[frontend] Starting Next.js on http://$HOSTNAME:$PORT"
exec pnpm dev --port "$PORT" --hostname "$HOSTNAME"
