#!/usr/bin/env bash
# Activate Python venv and show versions
set -euo pipefail

VENV_DIR="${VENV_DIR:-$HOME/systemBoam-service/.venv}"

if [[ ! -d "$VENV_DIR" ]]; then
  echo "venv not found at: $VENV_DIR"
  echo "Create it:  python3 -m venv \"$VENV_DIR\""
  exit 1
fi

# shellcheck disable=SC1090
source "$VENV_DIR/bin/activate"

echo "[venv] $(python -V)  pip $(pip -V | awk '{print $2}')"
