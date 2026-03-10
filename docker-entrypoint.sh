#!/bin/bash
set -e

echo "╔══════════════════════════════════════════════════╗"
echo "║   ALdeci FixOps CTEM+ Enterprise Platform        ║"
echo "║   Starting production services...                ║"
echo "╚══════════════════════════════════════════════════╝"

# Validate required secrets
if [ -z "$FIXOPS_API_TOKEN" ]; then
  echo "FATAL: FIXOPS_API_TOKEN not set. Generate with: openssl rand -base64 32"
  exit 1
fi

if [ -z "$FIXOPS_JWT_SECRET" ]; then
  echo "FATAL: FIXOPS_JWT_SECRET not set. Generate with: openssl rand -hex 32"
  exit 1
fi

echo "[1/2] Starting API backend (port 8000)..."
python3 -m uvicorn api.app:create_app \
  --factory \
  --host 0.0.0.0 \
  --port 8000 \
  --workers ${API_WORKERS:-4} \
  --app-dir suite-api/apps \
  --log-level ${LOG_LEVEL:-info} &

API_PID=$!

# Wait for API to be ready
echo "[1/2] Waiting for API to initialize..."
for i in $(seq 1 30); do
  if curl -sf http://localhost:8000/api/v1/health > /dev/null 2>&1; then
    echo "[1/2] API backend ready."
    break
  fi
  sleep 1
done

echo "[2/2] Starting production server (port 3000)..."
exec node serve.js
