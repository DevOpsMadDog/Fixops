#!/bin/bash
# E2E test runner — starts backend + frontend, runs Playwright, then cleans up.
set -e

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
UI_DIR="$ROOT/suite-ui/aldeci-ui-new"

cleanup() {
  echo "Cleaning up..."
  [ -n "$BACKEND_PID" ] && kill "$BACKEND_PID" 2>/dev/null || true
  [ -n "$FRONTEND_PID" ] && kill "$FRONTEND_PID" 2>/dev/null || true
}
trap cleanup EXIT

# Kill any existing servers
kill $(lsof -t -i :8000) 2>/dev/null || true
kill $(lsof -t -i :5173) 2>/dev/null || true
sleep 1

# Start backend
cd "$ROOT"
source .venv/bin/activate 2>/dev/null || true
export OTEL_SDK_DISABLED=true
python -m uvicorn apps.api.app:create_app --factory --port 8000 > /tmp/e2e-backend.log 2>&1 &
BACKEND_PID=$!
echo "Backend PID: $BACKEND_PID"

# Start frontend
cd "$UI_DIR"
npx vite --port 5173 > /tmp/e2e-frontend.log 2>&1 &
FRONTEND_PID=$!
echo "Frontend PID: $FRONTEND_PID"

# Wait for both to be ready
echo "Waiting for servers..."
for i in $(seq 1 30); do
  if curl -sf http://localhost:8000/health > /dev/null 2>&1; then
    echo "Backend ready (attempt $i)"
    break
  fi
  sleep 1
done
for i in $(seq 1 15); do
  if curl -sf http://localhost:5173 > /dev/null 2>&1; then
    echo "Frontend ready (attempt $i)"
    break
  fi
  sleep 1
done

# Verify
curl -sf http://localhost:8000/health > /dev/null || { echo "FAIL: Backend not ready"; exit 1; }
curl -sf http://localhost:5173 > /dev/null || { echo "FAIL: Frontend not ready"; exit 1; }
echo "Both servers ready."

# Run Playwright
cd "$UI_DIR"
export VITE_API_URL=http://localhost:8000
npx playwright test --reporter=list 2>&1
EXIT_CODE=$?

echo "Tests finished with exit code: $EXIT_CODE"
exit $EXIT_CODE

