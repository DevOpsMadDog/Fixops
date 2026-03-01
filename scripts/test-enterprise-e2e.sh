#!/usr/bin/env bash
# =============================================================================
# ALdeci Enterprise E2E Functional Test Suite
# =============================================================================
# Tests the entire CTEM+ pipeline end-to-end:
#   1. Platform Health (all engines alive)
#   2. DISCOVER — Scanner endpoints, finding ingestion, SBOM
#   3. VALIDATE — MPTE, micro-pentest, attack simulation
#   4. REMEDIATE — AutoFix, remediation tasks, workflows
#   5. COMPLY — Evidence, compliance frameworks, audit
#   6. Full CTEM Pipeline — Ingest → Brain → Deduplicate → Fix → Evidence
#
# Usage:
#   ./scripts/test-enterprise-e2e.sh                       # All tests
#   ./scripts/test-enterprise-e2e.sh --section health      # Just health checks
#   ./scripts/test-enterprise-e2e.sh --section discover    # Just Discover
#   ./scripts/test-enterprise-e2e.sh --section validate    # Just Validate
#   ./scripts/test-enterprise-e2e.sh --section remediate   # Just Remediate
#   ./scripts/test-enterprise-e2e.sh --section comply      # Just Comply
#   ./scripts/test-enterprise-e2e.sh --section pipeline    # Full CTEM pipeline
#
# Exit codes: 0 = all pass, 1 = failures detected
# =============================================================================

set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8000}"
API_KEY="${API_KEY:-aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh}"
H="X-API-Key: $API_KEY"
SECTION="${1:-all}"
[[ "$SECTION" == "--section" ]] && SECTION="${2:-all}"

PASS=0
FAIL=0
SKIP=0
TOTAL=0
FAILURES=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
api() {
  local method="$1" path="$2"
  shift 2
  curl -s -w "\n%{http_code}" -X "$method" -H "$H" -H "Content-Type: application/json" "$@" "$BASE_URL/$path"
}

assert_status() {
  local test_name="$1" method="$2" path="$3" expected="$4"
  shift 4
  TOTAL=$((TOTAL + 1))
  local response
  response=$(api "$method" "$path" "$@")
  local code
  code=$(echo "$response" | tail -1)
  local body
  body=$(echo "$response" | sed '$d')

  if [[ "$code" == "$expected" ]]; then
    PASS=$((PASS + 1))
    printf "  ${GREEN}✓${NC} %s ${CYAN}(%s %s → %s)${NC}\n" "$test_name" "$method" "$path" "$code"
  else
    FAIL=$((FAIL + 1))
    FAILURES="$FAILURES\n  ✗ $test_name ($method $path → $code, expected $expected)"
    printf "  ${RED}✗${NC} %s ${RED}(%s %s → %s, expected %s)${NC}\n" "$test_name" "$method" "$path" "$code" "$expected"
    # Show body snippet on failure
    echo "$body" | head -2 | sed 's/^/    /'
  fi
}

# assert_json_key: checks response contains a key
assert_json_key() {
  local test_name="$1" method="$2" path="$3" key="$4"
  shift 4
  TOTAL=$((TOTAL + 1))
  local response
  response=$(api "$method" "$path" "$@")
  local code
  code=$(echo "$response" | tail -1)
  local body
  body=$(echo "$response" | sed '$d')

  if [[ "$code" -ge 200 && "$code" -lt 300 ]]; then
    if echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); assert '$key' in d" 2>/dev/null; then
      PASS=$((PASS + 1))
      printf "  ${GREEN}✓${NC} %s ${CYAN}(has '%s')${NC}\n" "$test_name" "$key"
    else
      FAIL=$((FAIL + 1))
      FAILURES="$FAILURES\n  ✗ $test_name (missing key '$key')"
      printf "  ${RED}✗${NC} %s ${RED}(missing key '%s')${NC}\n" "$test_name" "$key"
    fi
  else
    FAIL=$((FAIL + 1))
    FAILURES="$FAILURES\n  ✗ $test_name ($method $path → $code)"
    printf "  ${RED}✗${NC} %s ${RED}(%s %s → %s)${NC}\n" "$test_name" "$method" "$path" "$code"
  fi
}

# assert_post_returns: POST with body, check status
assert_post() {
  local test_name="$1" path="$2" expected="$3" body="$4"
  TOTAL=$((TOTAL + 1))
  local response
  response=$(api "POST" "$path" -d "$body")
  local code
  code=$(echo "$response" | tail -1)
  local rbody
  rbody=$(echo "$response" | sed '$d')

  # Accept 2xx codes as success (200, 201) and 409 as idempotent success
  if [[ "$code" == "$expected" ]] || [[ "$code" == "409" && ("$expected" == "200" || "$expected" == "201") ]]; then
    PASS=$((PASS + 1))
    printf "  ${GREEN}✓${NC} %s ${CYAN}(POST %s → %s)${NC}\n" "$test_name" "$path" "$code"
    echo "$rbody"  # return body for chaining
  else
    FAIL=$((FAIL + 1))
    FAILURES="$FAILURES\n  ✗ $test_name (POST $path → $code, expected $expected)"
    printf "  ${RED}✗${NC} %s ${RED}(POST %s → %s, expected %s)${NC}\n" "$test_name" "$path" "$code" "$expected"
    echo "$rbody" | head -2 | sed 's/^/    /'
    echo ""
  fi
}

section() {
  printf "\n${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
  printf "${BOLD}  $1${NC}\n"
  printf "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

# ==========================================================================
# SECTION 1: PLATFORM HEALTH
# ==========================================================================
test_health() {
  section "🏥 PLATFORM HEALTH — All Engines Alive"

  # Core health
  assert_status "Platform health" GET "health" 200
  assert_json_key "Health has status" GET "health" "status"

  # Brain Pipeline (V3 — Decision Intelligence)
  assert_status "Brain health" GET "api/v1/brain/health" 200
  assert_status "Brain stats" GET "api/v1/brain/stats" 200

  # FAIL Engine (V3)
  assert_status "FAIL engine health" GET "api/v1/fail/health" 200
  assert_status "FAIL engine stats" GET "api/v1/fail/stats" 200

  # AutoFix Engine (V3)
  assert_status "AutoFix health" GET "api/v1/autofix/health" 200
  assert_status "AutoFix stats" GET "api/v1/autofix/stats" 200

  # MPTE (V5 — Verification)
  assert_status "MPTE stats" GET "api/v1/mpte/stats" 200
  assert_status "Micro-pentest health" GET "api/v1/micro-pentest/health" 200

  # Attack Simulation
  assert_status "Attack-sim health" GET "api/v1/attack-sim/health" 200

  # MCP Gateway (V7)
  assert_status "MCP health" GET "api/v1/mcp/health" 200
  assert_status "MCP tools list" GET "api/v1/mcp/tools" 200

  # Native Scanners (V9 — Air-gapped)
  assert_status "SAST scanner" GET "api/v1/sast/status" 200
  assert_status "DAST scanner" GET "api/v1/dast/status" 200
  assert_status "Secrets scanner" GET "api/v1/secrets/status" 200
  assert_status "Container scanner" GET "api/v1/container/status" 200
  assert_status "Malware scanner" GET "api/v1/malware/status" 200
  assert_status "API fuzzer" GET "api/v1/api-fuzzer/status" 200

  # Support services
  assert_status "Feeds health" GET "api/v1/feeds/health" 200
  assert_status "Copilot health" GET "api/v1/copilot/health" 200
  assert_status "LLM status" GET "api/v1/llm/status" 200
  assert_status "Sandbox health" GET "api/v1/sandbox/health" 200
  assert_status "Knowledge-graph status" GET "api/v1/knowledge-graph/status" 200
  assert_status "Deduplication stats" GET "api/v1/deduplication/stats" 200
  assert_status "Scanner-ingest supported" GET "api/v1/scanner-ingest/supported" 200
  assert_status "IaC scanners status" GET "api/v1/iac/scanners/status" 200
  assert_status "Connectors list" GET "api/v1/connectors" 200
}

# ==========================================================================
# SECTION 2: DISCOVER — Scanning, Findings, SBOM
# ==========================================================================
test_discover() {
  section "🔍 DISCOVER — Scanner Endpoints & Finding Ingestion"

  # SAST scan
  assert_post "SAST scan Python code" "api/v1/sast/scan/code" 200 '{
    "code": "import os\npassword = \"hardcoded123\"\nos.system(input())",
    "language": "python",
    "filename": "test.py"
  }'

  # Secrets scan (correct path: /scan/content)
  assert_post "Secrets scan code" "api/v1/secrets/scan/content" 200 '{
    "content": "AWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE\npassword=hunter2",
    "filename": "config.env"
  }'

  # Scanner ingest — multipart file upload
  TOTAL=$((TOTAL + 1))
  TRIVY_REPORT=$(mktemp /tmp/trivy-report-XXXXXX.json)
  cat > "$TRIVY_REPORT" << 'TRIVYEOF'
{"Results": [{"Target": "package-lock.json", "Vulnerabilities": [{"VulnerabilityID": "CVE-2024-3094", "PkgName": "xz-utils", "InstalledVersion": "5.6.0", "FixedVersion": "5.6.2", "Severity": "CRITICAL", "Title": "XZ Utils backdoor"}]}]}
TRIVYEOF
  INGEST_RESP=$(curl -s -w "\n%{http_code}" -X POST -H "$H" -F "file=@$TRIVY_REPORT" -F "scanner_type=trivy" "$BASE_URL/api/v1/scanner-ingest/upload")
  INGEST_CODE=$(echo "$INGEST_RESP" | tail -1)
  if [[ "$INGEST_CODE" == "200" ]]; then
    PASS=$((PASS + 1))
    printf "  ${GREEN}✓${NC} Ingest Trivy finding ${CYAN}(multipart upload → %s)${NC}\n" "$INGEST_CODE"
  else
    FAIL=$((FAIL + 1))
    FAILURES="$FAILURES\n  ✗ Ingest Trivy finding (POST scanner-ingest/upload → $INGEST_CODE, expected 200)"
    printf "  ${RED}✗${NC} Ingest Trivy finding ${RED}(POST scanner-ingest/upload → %s, expected 200)${NC}\n" "$INGEST_CODE"
  fi
  rm -f "$TRIVY_REPORT"

  # Analytics / Findings
  assert_status "Analytics findings" GET "api/v1/analytics/findings" 200
  assert_status "Analytics stats" GET "api/v1/analytics/stats" 200
  assert_status "Dashboard overview" GET "api/v1/analytics/dashboard/overview" 200

  # Deduplication
  assert_status "Dedup stats" GET "api/v1/deduplication/stats" 200

  # Inventory
  assert_status "App inventory" GET "api/v1/inventory/applications" 200

  # Cases
  assert_status "Exposure cases" GET "api/v1/cases" 200
}

# ==========================================================================
# SECTION 3: VALIDATE — MPTE, Micro-Pentest, Attack Sim
# ==========================================================================
test_validate() {
  section "⚡ VALIDATE — Exploit Verification"

  # MPTE verification request (requires evidence field, returns 201)
  assert_post "MPTE verification request" "api/v1/mpte/verify" 201 '{
    "finding_id": "test-finding-001",
    "vulnerability_type": "sql_injection",
    "target_url": "http://test.example.com/api",
    "evidence": "SQL injection detected in login form: user input concatenated into query string without parameterization"
  }'

  # List MPTE requests
  assert_status "MPTE requests" GET "api/v1/mpte/requests" 200

  # Attack simulation scenarios
  assert_status "Attack scenarios" GET "api/v1/attack-sim/scenarios" 200

  # FAIL scoring
  assert_post "FAIL score finding" "api/v1/fail/score" 200 '{
    "finding_id": "test-finding-001",
    "cvss_score": 9.8,
    "has_exploit": true,
    "is_internet_facing": true,
    "asset_criticality": "high"
  }'

  # FAIL top risks (correct path: /top-risks not /rankings)
  assert_status "FAIL top-risks" GET "api/v1/fail/top-risks" 200
}

# ==========================================================================
# SECTION 4: REMEDIATE — AutoFix, Tasks, Workflows
# ==========================================================================
test_remediate() {
  section "🔧 REMEDIATE — AutoFix & Remediation"

  # AutoFix generate fix
  assert_post "AutoFix generate" "api/v1/autofix/generate" 200 '{
    "finding_id": "test-finding-001",
    "fix_type": "CODE_PATCH",
    "vulnerability_type": "sql_injection",
    "code_context": "query = \"SELECT * FROM users WHERE id = \" + user_input",
    "language": "python"
  }'

  # AutoFix stats
  assert_status "AutoFix stats" GET "api/v1/autofix/stats" 200

  # Remediation tasks
  assert_status "Remediation tasks" GET "api/v1/remediation/tasks" 200

  # Workflows
  assert_status "Workflows list" GET "api/v1/workflows" 200

  # Create a workflow (returns 201 for creation)
  assert_post "Create workflow" "api/v1/workflows" 201 '{
    "name": "Enterprise-SQL-Fix",
    "description": "Auto-remediation for SQL injection findings",
    "trigger": "finding_severity_critical",
    "actions": ["autofix", "create_ticket", "notify_slack"]
  }'

  # Policies
  assert_status "Policies list" GET "api/v1/policies" 200
}

# ==========================================================================
# SECTION 5: COMPLY — Evidence, Compliance, Audit
# ==========================================================================
test_comply() {
  section "🛡️ COMPLY — Evidence & Compliance"

  # Evidence
  assert_status "Evidence list" GET "api/v1/evidence/" 200

  # Compliance frameworks
  assert_status "Compliance frameworks" GET "api/v1/compliance-engine/frameworks" 200
  assert_status "Compliance status" GET "api/v1/compliance-engine/status" 200

  # Audit logs
  assert_status "Audit logs" GET "api/v1/audit/logs" 200

  # Reports
  assert_status "Reports list" GET "api/v1/reports" 200
}

# ==========================================================================
# SECTION 6: INTEGRATIONS — Connectors, Webhooks, MCP
# ==========================================================================
test_integrations() {
  section "🔌 INTEGRATIONS — Connectors & MCP"

  # Integrations CRUD
  assert_status "Integrations list" GET "api/v1/integrations" 200

  # Create integration (returns 201 for creation)
  assert_post "Create Jira integration" "api/v1/integrations" 201 '{
    "integration_type": "jira",
    "name": "Enterprise Jira",
    "config": {
      "url": "https://enterprise.atlassian.net",
      "project_key": "SEC",
      "api_key": "test-key"
    }
  }'

  # Connectors
  assert_status "Connectors list" GET "api/v1/connectors" 200

  # MCP tools discovery
  assert_status "MCP tools" GET "api/v1/mcp/tools" 200
  assert_status "MCP stats" GET "api/v1/mcp/stats" 200

  # Teams & Users
  assert_status "Teams list" GET "api/v1/teams" 200
  assert_status "Users list" GET "api/v1/users" 200
}

# ==========================================================================
# SECTION 7: FULL CTEM PIPELINE — End-to-End Flow
# ==========================================================================
test_pipeline() {
  section "🔄 FULL CTEM PIPELINE — Ingest → Brain → Deduplicate → Fix → Evidence"

  # Step 1: Ingest a finding via Brain pipeline (correct: /pipeline/run)
  printf "\n  ${CYAN}Step 1: Ingest finding via Brain Pipeline${NC}\n"
  assert_post "Brain pipeline run" "api/v1/brain/pipeline/run" 200 '{
    "findings": [{
      "id": "ctem-e2e-001",
      "title": "SQL Injection in login endpoint",
      "severity": "critical",
      "source": "sast",
      "cve_id": "CVE-2024-3094",
      "asset_name": "payment-gateway",
      "description": "User input concatenated directly into SQL query",
      "code_context": {"file": "login.py", "line": 42, "snippet": "cursor.execute(sql + user_input)"}
    }],
    "org_id": "enterprise-demo",
    "source": "e2e-test"
  }'

  # Step 2: Check deduplication
  printf "\n  ${CYAN}Step 2: Check deduplication${NC}\n"
  assert_status "Dedup clusters" GET "api/v1/deduplication/clusters?org_id=enterprise-demo" 200

  # Step 3: FAIL score the finding
  printf "\n  ${CYAN}Step 3: FAIL score${NC}\n"
  assert_post "FAIL score" "api/v1/fail/score" 200 '{
    "finding_id": "ctem-e2e-001",
    "cvss_score": 9.8,
    "has_exploit": true,
    "is_internet_facing": true,
    "asset_criticality": "critical"
  }'

  # Step 4: MPTE verification (returns 201)
  printf "\n  ${CYAN}Step 4: MPTE verification${NC}\n"
  assert_post "MPTE verify" "api/v1/mpte/verify" 201 '{
    "finding_id": "ctem-e2e-001",
    "vulnerability_type": "sql_injection",
    "target_url": "http://payment-gw.internal:8080/auth/login",
    "evidence": "SQL injection detected: user input concatenated into query at line 42 of login.py"
  }'

  # Step 5: AutoFix
  printf "\n  ${CYAN}Step 5: AutoFix${NC}\n"
  assert_post "AutoFix generate" "api/v1/autofix/generate" 200 '{
    "finding_id": "ctem-e2e-001",
    "fix_type": "CODE_PATCH",
    "vulnerability_type": "sql_injection",
    "code_context": "cursor.execute(\"SELECT * FROM users WHERE username=\" + request.form[\"username\"])",
    "language": "python"
  }'

  # Step 6: Create remediation task (requires cluster_id, org_id, app_id)
  printf "\n  ${CYAN}Step 6: Remediation task${NC}\n"
  assert_post "Create remediation task" "api/v1/remediation/tasks" 200 '{
    "title": "Fix SQL Injection CVE-2024-3094",
    "severity": "critical",
    "cluster_id": "cluster-ctem-e2e",
    "org_id": "enterprise-demo",
    "app_id": "payment-gateway",
    "assignee": "security-ops",
    "description": "SQL injection in login.py line 42"
  }'

  # Step 7: Compliance check
  printf "\n  ${CYAN}Step 7: Compliance status${NC}\n"
  assert_status "Compliance status" GET "api/v1/compliance-engine/status" 200

  printf "\n  ${GREEN}✓ CTEM Pipeline E2E complete${NC}\n"
}

# ==========================================================================
# SECTION 8: PERSONA TESTS — Each persona's owned endpoints
# ==========================================================================
test_personas() {
  section "🎭 PERSONA E2E — Agent-Owned Endpoints"

  printf "\n  ${CYAN}backend-hardener${NC}\n"
  assert_status "  Connectors" GET "api/v1/connectors" 200
  assert_status "  Audit logs" GET "api/v1/audit/logs" 200
  assert_status "  Users" GET "api/v1/users" 200
  assert_status "  Teams" GET "api/v1/teams" 200
  assert_status "  Integrations" GET "api/v1/integrations" 200
  assert_status "  Workflows" GET "api/v1/workflows" 200

  printf "\n  ${CYAN}threat-architect${NC}\n"
  assert_status "  MPTE stats" GET "api/v1/mpte/stats" 200
  assert_status "  Micro-pentest health" GET "api/v1/micro-pentest/health" 200
  assert_status "  FAIL health" GET "api/v1/fail/health" 200
  assert_status "  Attack-sim health" GET "api/v1/attack-sim/health" 200
  assert_status "  Malware status" GET "api/v1/malware/status" 200
  assert_status "  API fuzzer" GET "api/v1/api-fuzzer/status" 200
  assert_status "  Feeds health" GET "api/v1/feeds/health" 200

  printf "\n  ${CYAN}security-analyst${NC}\n"
  assert_status "  SAST" GET "api/v1/sast/status" 200
  assert_status "  DAST" GET "api/v1/dast/status" 200
  assert_status "  Secrets" GET "api/v1/secrets/status" 200
  assert_status "  Container" GET "api/v1/container/status" 200
  assert_status "  IaC scanners" GET "api/v1/iac/scanners/status" 200

  printf "\n  ${CYAN}enterprise-architect${NC}\n"
  assert_status "  Brain health" GET "api/v1/brain/health" 200
  assert_status "  KG status" GET "api/v1/knowledge-graph/status" 200
  assert_status "  Dedup stats" GET "api/v1/deduplication/stats" 200

  printf "\n  ${CYAN}ai-researcher${NC}\n"
  assert_status "  LLM status" GET "api/v1/llm/status" 200
  assert_status "  Copilot health" GET "api/v1/copilot/health" 200

  printf "\n  ${CYAN}qa-engineer${NC}\n"
  assert_status "  AutoFix health" GET "api/v1/autofix/health" 200

  printf "\n  ${CYAN}devops-engineer${NC}\n"
  assert_status "  MCP health" GET "api/v1/mcp/health" 200
  assert_status "  MCP tools" GET "api/v1/mcp/tools" 200

  printf "\n  ${CYAN}data-scientist${NC}\n"
  assert_status "  Analytics overview" GET "api/v1/analytics/dashboard/overview" 200
  assert_status "  Analytics stats" GET "api/v1/analytics/stats" 200
  assert_status "  Predictions" GET "api/v1/predictions/markov/states" 200

  printf "\n  ${CYAN}vision-agent${NC}\n"
  assert_status "  Compliance frameworks" GET "api/v1/compliance-engine/frameworks" 200
  assert_status "  Evidence" GET "api/v1/evidence/" 200

  printf "\n  ${CYAN}scrum-master${NC}\n"
  assert_status "  Workflows" GET "api/v1/workflows" 200
  assert_status "  Remediation" GET "api/v1/remediation/tasks" 200
  assert_status "  Reports" GET "api/v1/reports" 200
  assert_status "  Policies" GET "api/v1/policies" 200

  printf "\n  ${CYAN}sales-engineer${NC}\n"
  assert_status "  Inventory" GET "api/v1/inventory/applications" 200

  printf "\n  ${CYAN}context-engineer${NC}\n"
  assert_status "  Copilot agents" GET "api/v1/copilot/agents/status" 200
}

# ==========================================================================
# AUTH TESTS
# ==========================================================================
test_auth() {
  section "🔒 AUTH — Reject unauthorized requests"

  TOTAL=$((TOTAL + 1))
  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/api/v1/brain/health")
  if [[ "$code" == "401" || "$code" == "403" ]]; then
    PASS=$((PASS + 1))
    printf "  ${GREEN}✓${NC} No-auth request rejected ($code)\n"
  else
    FAIL=$((FAIL + 1))
    FAILURES="$FAILURES\n  ✗ No-auth request should be rejected (got $code)"
    printf "  ${RED}✗${NC} No-auth request should be rejected ${RED}(got $code)${NC}\n"
  fi

  TOTAL=$((TOTAL + 1))
  code=$(curl -s -o /dev/null -w "%{http_code}" -H "X-API-Key: invalid-key" "$BASE_URL/api/v1/brain/health")
  if [[ "$code" == "401" || "$code" == "403" ]]; then
    PASS=$((PASS + 1))
    printf "  ${GREEN}✓${NC} Invalid API key rejected ($code)\n"
  else
    FAIL=$((FAIL + 1))
    FAILURES="$FAILURES\n  ✗ Invalid API key should be rejected (got $code)"
    printf "  ${RED}✗${NC} Invalid API key should be rejected ${RED}(got $code)${NC}\n"
  fi
}

# ==========================================================================
# MAIN
# ==========================================================================
printf "\n${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}\n"
printf "${BOLD}║      ALdeci Enterprise E2E Functional Test Suite            ║${NC}\n"
printf "${BOLD}║      CTEM+ Decision Intelligence Platform                   ║${NC}\n"
printf "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}\n"
printf "  Base URL: $BASE_URL\n"
printf "  Section:  $SECTION\n"
printf "  Date:     $(date '+%Y-%m-%d %H:%M:%S')\n"

# Check server is up
if ! curl -s --max-time 5 "$BASE_URL/health" > /dev/null 2>&1; then
  printf "\n${RED}ERROR: Server not reachable at $BASE_URL${NC}\n"
  printf "Start it with: python -m uvicorn apps.api.app:create_app --factory --port 8000\n"
  exit 1
fi

case "$SECTION" in
  all)
    test_auth
    test_health
    test_discover
    test_validate
    test_remediate
    test_comply
    test_integrations
    test_pipeline
    test_personas
    ;;
  health)     test_health ;;
  discover)   test_discover ;;
  validate)   test_validate ;;
  remediate)  test_remediate ;;
  comply)     test_comply ;;
  integrate*) test_integrations ;;
  pipeline)   test_pipeline ;;
  persona*)   test_personas ;;
  auth)       test_auth ;;
  *)
    printf "${RED}Unknown section: $SECTION${NC}\n"
    printf "Valid: all, health, discover, validate, remediate, comply, integrations, pipeline, personas, auth\n"
    exit 1
    ;;
esac

# ==========================================================================
# RESULTS
# ==========================================================================
printf "\n${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
printf "${BOLD}  RESULTS${NC}\n"
printf "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
printf "  Total:  $TOTAL\n"
printf "  ${GREEN}Pass:   $PASS${NC}\n"
if [[ $FAIL -gt 0 ]]; then
  printf "  ${RED}Fail:   $FAIL${NC}\n"
  printf "\n${RED}  FAILURES:${NC}\n"
  printf "$FAILURES\n"
fi
printf "\n"

RATE=$(( PASS * 100 / (TOTAL > 0 ? TOTAL : 1) ))
if [[ $FAIL -eq 0 ]]; then
  printf "  ${GREEN}${BOLD}★ ALL TESTS PASSED ($PASS/$TOTAL — 100%%)${NC}\n"
else
  printf "  ${YELLOW}${BOLD}Pass rate: $RATE%% ($PASS/$TOTAL)${NC}\n"
fi
printf "\n"

exit $( [[ $FAIL -eq 0 ]] && echo 0 || echo 1 )
