#!/usr/bin/env bash
# ============================================
# ALdeci CTEM+ Platform — Demo Health Check
# ============================================
# Verifies that the ALdeci stack is running and
# healthy after `docker compose up`.
#
# Usage:
#   ./scripts/demo-healthcheck.sh              # Default: localhost
#   ./scripts/demo-healthcheck.sh 192.168.1.5  # Custom host
#   TIMEOUT=60 ./scripts/demo-healthcheck.sh   # Custom timeout
#
# Exit codes:
#   0 = All checks passed
#   1 = One or more checks failed
# ============================================
set -euo pipefail

# ─── Configuration ──────────────────────────────────────────
HOST="${1:-localhost}"
API_PORT="${FIXOPS_PORT:-8000}"
UI_PORT="${ALDECI_UI_PORT:-3001}"
API_BASE="http://${HOST}:${API_PORT}"
UI_BASE="http://${HOST}:${UI_PORT}"
TIMEOUT="${TIMEOUT:-30}"
API_TOKEN="${FIXOPS_API_TOKEN:-demo-token-change-me}"

# ─── Colors ─────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ─── Counters ───────────────────────────────────────────────
PASS=0
FAIL=0
WARN=0
TOTAL=0
FAILURES=""

# ─── Functions ──────────────────────────────────────────────

banner() {
    echo -e "${CYAN}"
    echo "  ┌─────────────────────────────────────────────┐"
    echo "  │     ALdeci CTEM+ Platform Health Check       │"
    echo "  │     Enterprise Demo Verification             │"
    echo "  └─────────────────────────────────────────────┘"
    echo -e "${NC}"
    echo -e "  ${BOLD}API:${NC} ${API_BASE}"
    echo -e "  ${BOLD}UI:${NC}  ${UI_BASE}"
    echo -e "  ${BOLD}Timeout:${NC} ${TIMEOUT}s"
    echo ""
}

check() {
    local name="$1"
    local url="$2"
    local expected_status="${3:-200}"
    local auth="${4:-false}"

    TOTAL=$((TOTAL + 1))

    local curl_args=("-s" "-o" "/dev/null" "-w" "%{http_code}" "--max-time" "5")
    if [[ "$auth" == "true" ]]; then
        curl_args+=("-H" "X-API-Key: ${API_TOKEN}")
    fi

    local status
    status=$(curl "${curl_args[@]}" "$url" 2>/dev/null) || status="000"

    if [[ "$status" == "$expected_status" ]]; then
        echo -e "  ${GREEN}✅${NC} ${name} ${CYAN}(${status})${NC}"
        PASS=$((PASS + 1))
    elif [[ "$status" == "000" ]]; then
        echo -e "  ${RED}❌${NC} ${name} ${RED}(unreachable)${NC}"
        FAIL=$((FAIL + 1))
        FAILURES="${FAILURES}\n  - ${name}: unreachable at ${url}"
    else
        echo -e "  ${YELLOW}⚠️${NC}  ${name} ${YELLOW}(${status}, expected ${expected_status})${NC}"
        WARN=$((WARN + 1))
        FAILURES="${FAILURES}\n  - ${name}: got ${status}, expected ${expected_status}"
    fi
}

check_json_field() {
    local name="$1"
    local url="$2"
    local field="$3"
    local expected="$4"
    local auth="${5:-false}"

    TOTAL=$((TOTAL + 1))

    local curl_args=("-s" "--max-time" "5")
    if [[ "$auth" == "true" ]]; then
        curl_args+=("-H" "X-API-Key: ${API_TOKEN}")
    fi

    local response
    response=$(curl "${curl_args[@]}" "$url" 2>/dev/null) || response=""

    if [[ -z "$response" ]]; then
        echo -e "  ${RED}❌${NC} ${name} ${RED}(no response)${NC}"
        FAIL=$((FAIL + 1))
        FAILURES="${FAILURES}\n  - ${name}: no response from ${url}"
        return
    fi

    local value
    value=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('${field}',''))" 2>/dev/null) || value=""

    if [[ "$value" == "$expected" ]]; then
        echo -e "  ${GREEN}✅${NC} ${name} ${CYAN}(${field}=${value})${NC}"
        PASS=$((PASS + 1))
    else
        echo -e "  ${YELLOW}⚠️${NC}  ${name} ${YELLOW}(${field}=${value:-empty}, expected ${expected})${NC}"
        WARN=$((WARN + 1))
    fi
}

wait_for_api() {
    echo -e "${BOLD}Waiting for API server...${NC}"
    local elapsed=0
    while [[ $elapsed -lt $TIMEOUT ]]; do
        if curl -sf "${API_BASE}/health" --max-time 2 > /dev/null 2>&1; then
            echo -e "  ${GREEN}✅${NC} API server ready after ${elapsed}s"
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
        # Print progress every 5 seconds
        if [[ $((elapsed % 5)) -eq 0 ]]; then
            echo -e "  ${YELLOW}⏳${NC} Still waiting... (${elapsed}s/${TIMEOUT}s)"
        fi
    done
    echo -e "  ${RED}❌${NC} API server not ready after ${TIMEOUT}s"
    return 1
}

# ─── Main ───────────────────────────────────────────────────

banner

# Phase 1: Wait for API readiness
if ! wait_for_api; then
    echo ""
    echo -e "${RED}${BOLD}FAILED:${NC} API server did not start within ${TIMEOUT}s"
    echo -e "${YELLOW}Troubleshooting:${NC}"
    echo "  1. Check if Docker is running: docker info"
    echo "  2. Check container logs: docker compose -f docker/docker-compose.yml logs fixops"
    echo "  3. Check port conflicts: lsof -i :${API_PORT}"
    exit 1
fi

echo ""

# Phase 2: Core Health Endpoints
echo -e "${BOLD}Core Services${NC}"
check "API Health" "${API_BASE}/health"
check_json_field "API Status" "${API_BASE}/health" "status" "healthy"
check "UI Frontend" "${UI_BASE}/" "200"
check "UI Nginx Health" "${UI_BASE}/nginx-health" "200"
check "API via UI Proxy" "${UI_BASE}/health" "200"

echo ""

# Phase 3: API v1 Endpoints (key routes from coordination-notes.md)
# These endpoints require API key auth (X-API-Key header)
echo -e "${BOLD}CTEM+ Pipeline [V3]${NC}"
check "Brain Pipeline Stats"   "${API_BASE}/api/v1/brain/stats"        "200" "true"
check "AutoFix Health"         "${API_BASE}/api/v1/autofix/health"     "200" "true"
check "FAIL Engine Health"     "${API_BASE}/api/v1/fail/health"        "200" "true"
check "Analytics Dashboard"    "${API_BASE}/api/v1/analytics/dashboard/overview" "200" "true"
check "Findings List"          "${API_BASE}/api/v1/analytics/findings" "200" "true"
check "Exposure Cases"         "${API_BASE}/api/v1/cases"              "200" "true"

echo ""
echo -e "${BOLD}MPTE Verification [V5]${NC}"
check "MPTE Stats"             "${API_BASE}/api/v1/mpte/stats"         "200" "true"
check "Micro-Pentest Health"   "${API_BASE}/api/v1/micro-pentest/health" "200" "true"

echo ""
echo -e "${BOLD}MCP Gateway [V7]${NC}"
check "MCP Protocol Status"    "${API_BASE}/api/v1/mcp-protocol/status" "200" "true"
check "MCP Tools Discovery"    "${API_BASE}/api/v1/mcp/tools"          "200" "true"

echo ""
echo -e "${BOLD}8 Native Scanners [V9]${NC}"
check "SAST Scanner"           "${API_BASE}/api/v1/sast/status"        "200" "true"
check "DAST Scanner"           "${API_BASE}/api/v1/dast/status"        "200" "true"
check "Secrets Scanner"        "${API_BASE}/api/v1/secrets/status"     "200" "true"
check "Container Scanner"      "${API_BASE}/api/v1/container/status"   "200" "true"
check "CSPM/IaC Scanner"       "${API_BASE}/api/v1/cspm/status"       "200" "true"
check "Sandbox Health"         "${API_BASE}/api/v1/sandbox/health"     "200" "true"
# API Fuzzer and Malware Scanner share the MPTE/attack surface
check "Attack Surface"         "${API_BASE}/api/v1/mpte/stats"         "200" "true"

echo ""
echo -e "${BOLD}Evidence & Compliance [V10]${NC}"
check "Evidence Vault"         "${API_BASE}/api/v1/evidence/"          "200" "true"
check "Compliance Frameworks"  "${API_BASE}/api/v1/compliance-engine/frameworks" "200" "true"
check "Knowledge Graph"        "${API_BASE}/api/v1/knowledge-graph/status" "200" "true"

echo ""
echo -e "${BOLD}Platform Services${NC}"
check "Workflows"              "${API_BASE}/api/v1/workflows"          "200" "true"
check "Policies"               "${API_BASE}/api/v1/policies"           "200" "true"
check "Reports"                "${API_BASE}/api/v1/reports"            "200" "true"
check "Audit Logs"             "${API_BASE}/api/v1/audit/logs"         "200" "true"
check "Remediation Tasks"      "${API_BASE}/api/v1/remediation/tasks"  "200" "true"
check "Inventory Apps"         "${API_BASE}/api/v1/inventory/applications" "200" "true"
check "Users"                  "${API_BASE}/api/v1/users"              "200" "true"
check "Teams"                  "${API_BASE}/api/v1/teams"              "200" "true"
check "Feeds Health"           "${API_BASE}/api/v1/feeds/health"       "200" "true"

echo ""

# Phase 4: Docker container health (only when running in Docker)
echo -e "${BOLD}Docker Container Status${NC}"
if command -v docker &> /dev/null && docker info &> /dev/null; then
    DOCKER_RUNNING=false
    for container in fixops-api aldeci-ui; do
        local_status=$(docker inspect --format='{{.State.Health.Status}}' "$container" 2>/dev/null) || local_status=""
        if [[ -n "$local_status" ]]; then
            DOCKER_RUNNING=true
            TOTAL=$((TOTAL + 1))
            case "$local_status" in
                healthy)
                    echo -e "  ${GREEN}✅${NC} ${container} ${CYAN}(${local_status})${NC}"
                    PASS=$((PASS + 1))
                    ;;
                starting)
                    echo -e "  ${YELLOW}⚠️${NC}  ${container} ${YELLOW}(${local_status})${NC}"
                    WARN=$((WARN + 1))
                    ;;
                *)
                    echo -e "  ${RED}❌${NC} ${container} ${RED}(${local_status})${NC}"
                    FAIL=$((FAIL + 1))
                    FAILURES="${FAILURES}\n  - Docker container ${container}: ${local_status}"
                    ;;
            esac
        fi
    done
    if [[ "$DOCKER_RUNNING" != "true" ]]; then
        echo -e "  ${CYAN}ℹ${NC}  No Docker containers found — running locally (OK)"
    fi
else
    echo -e "  ${CYAN}ℹ${NC}  Docker not available — skipping container checks (OK for local dev)"
fi

echo ""

# ─── Summary ────────────────────────────────────────────────
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${BOLD}Results:${NC} ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}, ${YELLOW}${WARN} warnings${NC} / ${TOTAL} total"

if [[ $FAIL -eq 0 && $WARN -eq 0 ]]; then
    echo -e "  ${GREEN}${BOLD}✅ ALL CHECKS PASSED — Demo ready!${NC}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    exit 0
elif [[ $FAIL -eq 0 ]]; then
    echo -e "  ${YELLOW}${BOLD}⚠️  PASSED with ${WARN} warnings${NC}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    exit 0
else
    echo -e "  ${RED}${BOLD}❌ FAILED — ${FAIL} checks did not pass${NC}"
    if [[ -n "$FAILURES" ]]; then
        echo -e "\n  ${RED}Failures:${NC}${FAILURES}"
    fi
    echo ""
    echo -e "  ${YELLOW}Troubleshooting:${NC}"
    echo "    docker compose -f docker/docker-compose.yml logs fixops"
    echo "    docker compose -f docker/docker-compose.yml logs aldeci-ui"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    exit 1
fi
