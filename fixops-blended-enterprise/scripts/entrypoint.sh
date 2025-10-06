#!/usr/bin/env bash
set -euo pipefail

if [[ "${FIXOPS_AUTH_DISABLED:-false}" == "true" ]]; then
  echo "Refusing to start FixOps backend with FIXOPS_AUTH_DISABLED=true" >&2
  exit 1
fi

if [[ -z "${FIXOPS_API_TOKEN:-}" && -z "${FIXOPS_API_TOKENS:-}" ]]; then
  echo "Missing FIXOPS_API_TOKEN(S) environment variables" >&2
  exit 2
fi

WORKERS="${FIXOPS_UVICORN_WORKERS:-1}"
if ! [[ "$WORKERS" =~ ^[0-9]+$ ]] || [ "$WORKERS" -lt 1 ]; then
  echo "Invalid FIXOPS_UVICORN_WORKERS value '$WORKERS'; must be a positive integer" >&2
  exit 3
fi

exec python -m uvicorn src.main:app --host 0.0.0.0 --port 8001 --workers "$WORKERS" --loop uvloop

