#!/bin/bash
# E2E test runner - starts servers, runs Playwright, cleans up
# All output goes to /tmp/e2e_results.txt

REPO_ROOT="/Users/devops.ai/developement/fixops/Fixops"
UI_DIR="$REPO_ROOT/suite-ui/aldeci-ui-new"
RESULTS="/tmp/e2e_results.txt"

cd "$REPO_ROOT"

echo "=== Killing existing processes ==="
# Use lsof to kill processes on the specific ports (avoids killing ourselves)
for PORT in 8000 5173; do
  PIDS=$(lsof -t -i ":$PORT" 2>/dev/null || true)
  if [ -n "$PIDS" ]; then
    echo "Killing PIDs on port $PORT: $PIDS"
    echo "$PIDS" | xargs kill -9 2>/dev/null || true
  fi
done
sleep 2

echo "=== Starting backend ==="
source .venv/bin/activate 2>/dev/null || true
export OTEL_SDK_DISABLED=true
export OTEL_TRACES_EXPORTER=none
export OTEL_METRICS_EXPORTER=none
export OTEL_LOGS_EXPORTER=none
python -m uvicorn apps.api.app:create_app --factory --port 8000 > /tmp/e2e_backend.log 2>&1 &
BACKEND_PID=$!
echo "Backend PID: $BACKEND_PID"

echo "=== Starting frontend ==="
cd "$UI_DIR"
npx vite --port 5173 > /tmp/e2e_frontend.log 2>&1 &
FRONTEND_PID=$!
echo "Frontend PID: $FRONTEND_PID"

cleanup() {
  kill "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null || true
}
trap cleanup EXIT

echo "=== Waiting for backend (max 60s) ==="
READY=0
for i in $(seq 1 30); do
  if curl -sf http://localhost:8000/health > /dev/null 2>&1; then
    echo "Backend ready (attempt $i)"
    READY=1
    break
  fi
  sleep 2
done
if [ "$READY" -eq 0 ]; then
  echo "ERROR: Backend failed to start"
  tail -30 /tmp/e2e_backend.log
  exit 1
fi

echo "=== Waiting for frontend (max 15s) ==="
READY=0
for i in $(seq 1 15); do
  if curl -sf http://localhost:5173 > /dev/null 2>&1; then
    echo "Frontend ready (attempt $i)"
    READY=1
    break
  fi
  sleep 1
done
if [ "$READY" -eq 0 ]; then
  echo "ERROR: Frontend failed to start"
  tail -10 /tmp/e2e_frontend.log
  exit 1
fi

echo "=== Both servers ready ==="
curl -sf http://localhost:8000/health || echo "HEALTH_FAIL"

echo ""
echo "=== Running Playwright E2E Tests ==="
cd "$UI_DIR"
npx playwright test --reporter=list 2>&1
PW_EXIT=$?
echo "=== Playwright Exit Code: $PW_EXIT ==="
exit $PW_EXIT

