#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${VENV_DIR:-$ROOT_DIR/.venv}"
PYTHON_BIN="${PYTHON:-python3}"

if [ ! -d "$VENV_DIR" ]; then
  echo "[bootstrap] Creating virtual environment in $VENV_DIR"
  "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

source "$VENV_DIR/bin/activate"

pip install --upgrade pip wheel
pip install -r "$ROOT_DIR/requirements.txt"
pip install -r "$ROOT_DIR/apps/api/requirements.txt"
if [ -f "$ROOT_DIR/enterprise/requirements.txt" ]; then
  pip install -r "$ROOT_DIR/enterprise/requirements.txt"
fi
if [ -f "$ROOT_DIR/requirements.dev.txt" ]; then
  pip install -r "$ROOT_DIR/requirements.dev.txt"
fi

pre-commit install --install-hooks

echo "[bootstrap] Environment ready. Activate with: source $VENV_DIR/bin/activate"
