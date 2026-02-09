#!/usr/bin/env bash
# ALdeci / FixOps E2E API Test Suite
# Runs against http://localhost:8000 with X-API-Key auth
set -euo pipefail

BASE="http://localhost:8000"
TOKEN="${FIXOPS_API_TOKEN:-test-token-123}"
H="X-API-Key: $TOKEN"
PASS=0; FAIL=0; TOTAL=0

ok() { ((PASS++)); ((TOTAL++)); echo "  ✅ PASS: $1"; }
fail() { ((FAIL++)); ((TOTAL++)); echo "  ❌ FAIL: $1 — $2"; }

check() {
  local name="$1" url="$2" expected_status="${3:-200}" body_check="${4:-}"
  local status body
  body=$(curl -s -w "\n%{http_code}" -H "$H" "$BASE$url" 2>/dev/null)
  status=$(echo "$body" | tail -1)
  body=$(echo "$body" | sed '$d')
  if [ "$status" != "$expected_status" ]; then
    fail "$name" "expected $expected_status got $status"
    return
  fi
  if [ -n "$body_check" ]; then
    if echo "$body" | grep -q "$body_check"; then
      ok "$name"
    else
      fail "$name" "body missing '$body_check'"
    fi
  else
    ok "$name"
  fi
}

check_post() {
  local name="$1" url="$2" data="$3" expected_status="${4:-200}" body_check="${5:-}"
  local status body
  body=$(curl -s -w "\n%{http_code}" -H "$H" -H "Content-Type: application/json" -X POST -d "$data" "$BASE$url" 2>/dev/null)
  status=$(echo "$body" | tail -1)
  body=$(echo "$body" | sed '$d')
  if [ "$status" != "$expected_status" ]; then
    fail "$name" "expected $expected_status got $status"
    return
  fi
  if [ -n "$body_check" ]; then
    if echo "$body" | grep -q "$body_check"; then ok "$name"; else fail "$name" "body missing '$body_check'"; fi
  else
    ok "$name"
  fi
}

check_noauth() {
  local name="$1" url="$2"
  local status
  status=$(curl -s -o /dev/null -w "%{http_code}" "$BASE$url" 2>/dev/null)
  if [ "$status" = "401" ]; then ok "$name"; else fail "$name" "expected 401 got $status"; fi
}

echo "══════════════════════════════════════════════════"
echo "  ALdeci E2E API Test Suite"
echo "  Target: $BASE  Token: ${TOKEN:0:8}..."
echo "══════════════════════════════════════════════════"

echo ""
echo "── 1. Health & Status ──"
check "API Status"          "/api/v1/status"         200 '"status":"ok"'
check "Copilot Health"      "/api/v1/copilot/health" 200 '"status":"healthy"'
check "Feeds Health"        "/api/v1/feeds/health"   200 '"status":"healthy"'
check "Attack-Sim Health"   "/api/v1/attack-sim/health" 200 '"status":"healthy"'

echo ""
echo "── 2. Nerve Center ──"
check "Nerve Pulse"         "/api/v1/nerve-center/pulse"     200 '"level"'

echo ""
echo "── 3. Copilot ──"
check "Copilot Sessions"    "/api/v1/copilot/sessions" 200
check_post "Create Session" "/api/v1/copilot/sessions" '{"title":"E2E Test"}' 200

echo ""
echo "── 4. Pipeline ──"
check "Pipeline Runs"       "/api/v1/pipeline/pipeline/runs" 200 '"runs"'

echo ""
echo "── 5. Risk & Evidence ──"
# /api/v1/risk/ returns 404 "No risk reports available" when DB is empty – that's valid
RISK_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -H "$H" "$BASE/api/v1/risk/" 2>/dev/null)
if [ "$RISK_STATUS" = "200" ] || [ "$RISK_STATUS" = "404" ]; then ok "Risk Reports (status=$RISK_STATUS)"; else fail "Risk Reports" "expected 200|404 got $RISK_STATUS"; fi
check "Evidence List"       "/api/v1/evidence/"       200 '"count"'

echo ""
echo "── 6. Attack Suite ──"
check "SAST Status"         "/api/v1/sast/status"     200
check "Container Status"    "/api/v1/container/status" 200
check "DAST Status"         "/api/v1/dast/status"     200

echo ""
echo "── 7. Brain & Intelligence ──"
check "Brain Stats"         "/api/v1/brain/stats"     200
check "Decisions Recent"    "/api/v1/decisions/recent" 200
check_post "Predictions Risk" "/api/v1/predictions/risk-trajectory" '{"cve_id":"CVE-2024-0001"}' 200 '"trajectory"'
check "ML Analytics"        "/api/v1/ml/analytics/stats" 200

echo ""
echo "── 8. SSE Streaming ──"
SSE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 -H "$H" "$BASE/api/v1/stream/events" 2>/dev/null || true)
if [ "$SSE_STATUS" = "200" ] || [ "$SSE_STATUS" = "000" ]; then ok "SSE Events endpoint"; else fail "SSE Events" "status=$SSE_STATUS"; fi

echo ""
echo "── 9. Auth ──"
check_noauth "Reject no token" "/api/v1/nerve-center/pulse"

echo ""
echo "── 10. Integrations ──"
check "Integrations List"   "/api/v1/integrations"     200

echo ""
echo "══════════════════════════════════════════════════"
echo "  RESULTS: $PASS passed, $FAIL failed, $TOTAL total"
echo "══════════════════════════════════════════════════"

[ "$FAIL" -eq 0 ] && echo "  🎉 ALL TESTS PASSED" || echo "  ⚠️  SOME TESTS FAILED"
exit "$FAIL"

