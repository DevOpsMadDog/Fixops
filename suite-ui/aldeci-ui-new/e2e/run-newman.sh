#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════
# ALdeci CTEM+ — Newman API Contract Validation Runner
# ═══════════════════════════════════════════════════════
#
# Runs the Postman collection via Newman with HTML reporting.
# Usage:
#   ./run-newman.sh                          # defaults: localhost:8000
#   ./run-newman.sh https://staging.aldeci.io YOUR_API_KEY
#
set -euo pipefail

BASE_URL="${1:-http://localhost:8000}"
API_KEY="${2:-fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COLLECTION="$SCRIPT_DIR/postman/ALdeci-CTEM-25-Personas.postman_collection.json"
REPORT_DIR="$SCRIPT_DIR/../newman-reports"

mkdir -p "$REPORT_DIR"

echo "╔═══════════════════════════════════════════════════════╗"
echo "║  ALdeci CTEM+ — Newman API Contract Validation       ║"
echo "╠═══════════════════════════════════════════════════════╣"
echo "║  Base URL : $BASE_URL"
echo "║  Report   : $REPORT_DIR/newman-report.html"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""

# Check newman is installed
if ! command -v npx &>/dev/null; then
  echo "ERROR: npx not found. Install Node.js first."
  exit 1
fi

# Wait for backend health
echo "⏳ Waiting for backend at $BASE_URL/health ..."
for i in $(seq 1 30); do
  if curl -sf "$BASE_URL/health" > /dev/null 2>&1; then
    echo "✅ Backend healthy"
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "❌ Backend not reachable after 60s"
    exit 1
  fi
  sleep 2
done

echo ""
echo "🚀 Running Newman..."
echo ""

npx newman run "$COLLECTION" \
  --env-var "baseUrl=$BASE_URL" \
  --env-var "apiKey=$API_KEY" \
  --reporters cli,htmlextra \
  --reporter-htmlextra-export "$REPORT_DIR/newman-report.html" \
  --reporter-htmlextra-title "ALdeci CTEM+ API Contract Report" \
  --reporter-htmlextra-browserTitle "ALdeci Newman" \
  --delay-request 100 \
  --timeout-request 10000 \
  --color on \
  || EXIT_CODE=$?

echo ""
if [ "${EXIT_CODE:-0}" -eq 0 ]; then
  echo "✅ All API contract tests passed"
  echo "📊 Report: $REPORT_DIR/newman-report.html"
else
  echo "❌ Some API contract tests failed (exit code: $EXIT_CODE)"
  echo "📊 Report: $REPORT_DIR/newman-report.html"
  exit "${EXIT_CODE}"
fi

