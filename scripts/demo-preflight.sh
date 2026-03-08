#!/bin/bash
# ============================================================================
# ALdeci Demo Pre-Flight Validation Script
# Version: 9.0 — 2026-03-08
# Validates ALL 26 demo endpoints before an enterprise demo.
# Usage: bash scripts/demo-preflight.sh [base_url]
# ============================================================================

set -uo pipefail

BASE="${1:-http://localhost:8000}"
API_BASE="$BASE/api/v1"

# Load API key from environment
if [ -z "${FIXOPS_API_TOKEN:-}" ]; then
  if [ -f .env ]; then
    export $(grep -E '^FIXOPS_API_TOKEN=' .env | head -1)
  fi
fi
API_KEY="${FIXOPS_API_TOKEN:-test-key}"

# Colors
RED='\033[0;31m' GREEN='\033[0;32m' YELLOW='\033[1;33m' CYAN='\033[0;36m'
BOLD='\033[1m' NC='\033[0m'

PASS=0
FAIL=0
WARN=0
RESULTS=()

check_get() {
  local path="$1"
  local label="$2"
  local persona="$3"
  local status
  status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
    "$API_BASE/$path" -H "X-API-Key: $API_KEY" 2>/dev/null)
  if [ "$status" = "200" ]; then
    PASS=$((PASS+1))
    RESULTS+=("${GREEN}  PASS${NC}  GET /$path  ($persona)")
  else
    FAIL=$((FAIL+1))
    RESULTS+=("${RED}  FAIL${NC}  GET /$path → HTTP $status  ($persona)")
  fi
}

check_post() {
  local path="$1"
  local data="$2"
  local label="$3"
  local persona="$4"
  local expected="${5:-200}"
  local status
  status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 \
    -X POST "$API_BASE/$path" \
    -H "X-API-Key: $API_KEY" \
    -H "Content-Type: application/json" \
    -d "$data" 2>/dev/null)
  if [ "$status" = "$expected" ] || [ "$status" = "200" ] || [ "$status" = "201" ]; then
    PASS=$((PASS+1))
    RESULTS+=("${GREEN}  PASS${NC}  POST /$path → $status  ($persona)")
  else
    FAIL=$((FAIL+1))
    RESULTS+=("${RED}  FAIL${NC}  POST /$path → HTTP $status (expected $expected)  ($persona)")
  fi
}

echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     ALdeci Demo Pre-Flight Validation v9.0             ║${NC}"
echo -e "${CYAN}║     Checking 26 demo endpoints...                       ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# --- Health Check ---
HEALTH=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$BASE/health" 2>/dev/null)
if [ "$HEALTH" != "200" ]; then
  echo -e "${RED}CRITICAL: API is DOWN (HTTP $HEALTH at $BASE/health)${NC}"
  echo -e "${YELLOW}Try: source .env && python -m uvicorn apps.api.app:create_app --factory --port 8000${NC}"
  exit 1
fi
echo -e "${GREEN}API Health: OK${NC}"
echo ""

# --- CISO Endpoints (6) ---
echo -e "${BOLD}Persona 1: CISO${NC}"
check_get "analytics/dashboard/overview" "Dashboard" "CISO"
check_get "cases" "Cases" "CISO"
check_get "brain/stats" "Brain Stats" "CISO"
check_get "compliance-engine/frameworks" "Compliance" "CISO"
check_get "mpte/stats" "MPTE Stats" "CISO"
check_get "evidence/" "Evidence" "CISO"

# --- DevSecOps Endpoints (5) ---
echo -e "${BOLD}Persona 2: DevSecOps${NC}"
check_post "sast/scan/code" \
  '{"code": "x = input(); eval(x)", "language": "python"}' \
  "SAST Scan" "DevSecOps"
check_post "mpte/verify" \
  '{"finding_id": "preflight-001", "target_url": "http://test:8080", "vulnerability_type": "sqli", "evidence": "test"}' \
  "MPTE Verify" "DevSecOps" "201"
check_get "sast/status" "SAST Status" "DevSecOps"
check_get "autofix/fix-types" "Fix Types" "DevSecOps"
# AutoFix generate skipped in preflight (LLM-dependent, 10-20s, costs tokens)
echo -e "${YELLOW}  SKIP${NC}  POST /autofix/generate (LLM-dependent, use --full flag)"
WARN=$((WARN+1))

# --- Auditor Endpoints (6) ---
echo -e "${BOLD}Persona 3: Auditor${NC}"
check_get "compliance-engine/frameworks" "Frameworks" "Auditor"
check_post "evidence/export" \
  '{"framework": "SOC2", "findings": [{"id": "pf-001", "title": "Test", "severity": "HIGH", "cwe": "CWE-89"}]}' \
  "Evidence Export" "Auditor"
check_post "compliance-engine/map-findings" \
  '{"findings": [{"id": "pf-001", "title": "SQLi", "severity": "HIGH", "cwe": "CWE-89"}], "framework": "SOC2"}' \
  "Map Findings" "Auditor"
check_get "audit/logs" "Audit Logs" "Auditor"
check_get "audit/decision-trail" "Decision Trail" "Auditor"
check_get "policies" "Policies" "Auditor"

# --- Developer Endpoints (6) ---
echo -e "${BOLD}Persona 4: Developer${NC}"
check_get "remediation/tasks" "Remed Tasks" "Developer"
check_get "analytics/findings" "Findings" "Developer"
# AutoFix generate skipped (same reason)
echo -e "${YELLOW}  SKIP${NC}  POST /autofix/generate (LLM-dependent)"
WARN=$((WARN+1))
check_post "autofix/apply" \
  '{"fix_id": "pf-fix-001", "repository": "https://github.com/test/test", "create_pr": false, "auto_merge": false}' \
  "Apply Fix" "Developer"
check_get "autofix/stats" "Fix Stats" "Developer"
check_get "workflows" "Workflows" "Developer"

# --- CTO Endpoints (6) ---
echo -e "${BOLD}Persona 5: CTO${NC}"
check_get "brain/stats" "Brain Stats" "CTO"
check_get "knowledge-graph/status" "KG Status" "CTO"
check_post "knowledge-graph/attack-paths" \
  '{"source_id": "app-frontend", "target_id": "db-production", "max_depth": 5}' \
  "Attack Paths" "CTO"
check_get "mcp/tools" "MCP Tools" "CTO"
check_get "inventory/applications" "Inventory" "CTO"
check_get "sandbox/status" "Sandbox" "CTO"

# --- MOAT Endpoints ---
echo -e "${BOLD}MOAT Demos${NC}"
check_get "scanner-ingest/supported" "Scanner Parsers" "MOAT-A"
check_get "scanner-ingest/stats" "Ingest Stats" "MOAT-A"
check_post "sandbox/verify" \
  '{"language": "python", "code": "print(1)", "cve_id": "CVE-2024-0001", "finding_id": "pf-sb-001", "expected_indicators": ["test"], "timeout_seconds": 5}' \
  "Sandbox Verify" "MOAT-B"
check_get "sandbox/health" "Sandbox Health" "MOAT-B"

# --- Results ---
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""
for r in "${RESULTS[@]}"; do
  echo -e "$r"
done
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

TOTAL=$((PASS+FAIL))
if [ "$FAIL" -eq 0 ]; then
  echo -e "${GREEN}${BOLD}PRE-FLIGHT PASSED: $PASS/$TOTAL endpoints OK ($WARN skipped)${NC}"
  echo -e "${GREEN}Demo environment is READY.${NC}"
  exit 0
else
  echo -e "${RED}${BOLD}PRE-FLIGHT FAILED: $PASS/$TOTAL passed, $FAIL FAILED ($WARN skipped)${NC}"
  echo -e "${YELLOW}Fix failing endpoints before demo. Check logs: docker logs fixops-api${NC}"
  exit 1
fi
