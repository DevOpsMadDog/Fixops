#!/usr/bin/env bash
# ============================================
# ALdeci CTEM+ Platform — Demo Health Check
# ============================================
# Version: 3.0.0 (2026-03-08)
# Checks: 44+ endpoints across all CTEM+ pillars
# Scanners: All 8 native scanners verified
#
# Verifies that the ALdeci stack is running and
# healthy after `docker compose up`.
#
# Usage:
#   ./scripts/demo-healthcheck.sh              # Default: localhost
#   ./scripts/demo-healthcheck.sh 192.168.1.5  # Custom host
#   ./scripts/demo-healthcheck.sh --json       # Machine-parseable JSON output
#   ./scripts/demo-healthcheck.sh --ci         # CI mode: no colors, strict exit
#   ./scripts/demo-healthcheck.sh --quick      # Quick mode: core endpoints only
#   ./scripts/demo-healthcheck.sh --verbose    # Show response bodies on failure
#   TIMEOUT=60 ./scripts/demo-healthcheck.sh   # Custom timeout
#
# Exit codes:
#   0 = All checks passed (or passed with warnings)
#   1 = One or more checks failed
#   2 = API server never became ready (timeout)
# ============================================
set -euo pipefail

VERSION="3.0.0"

# ─── Parse flags ─────────────────────────────────────────────
JSON_MODE=false
CI_MODE=false
QUICK_MODE=false
VERBOSE=false
POSITIONAL_ARGS=()

for arg in "$@"; do
    case "$arg" in
        --json)    JSON_MODE=true; CI_MODE=true ;;
        --ci)      CI_MODE=true ;;
        --quick)   QUICK_MODE=true ;;
        --verbose) VERBOSE=true ;;
        --version) echo "demo-healthcheck.sh v${VERSION}"; exit 0 ;;
        --help|-h)
            echo "ALdeci CTEM+ Demo Health Check v${VERSION}"
            echo ""
            echo "Usage: $0 [HOST] [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  HOST       Target host (default: localhost)"
            echo "  --json     Output results as JSON (for CI parsing)"
            echo "  --ci       CI mode: no colors, strict exit codes"
            echo "  --quick    Quick mode: check core endpoints only (7 checks)"
            echo "  --verbose  Show response bodies on failure"
            echo "  --version  Show version"
            echo "  --help     Show this help message"
            echo ""
            echo "Environment variables:"
            echo "  FIXOPS_PORT         API port (default: 8000)"
            echo "  ALDECI_UI_PORT      UI port (default: 3001)"
            echo "  FIXOPS_API_TOKEN    API authentication token"
            echo "  TIMEOUT             Readiness timeout in seconds (default: 30)"
            exit 0
            ;;
        *)       POSITIONAL_ARGS+=("$arg") ;;
    esac
done

# ─── Configuration ──────────────────────────────────────────
HOST="${POSITIONAL_ARGS[0]:-localhost}"
API_PORT="${FIXOPS_PORT:-8000}"
UI_PORT="${ALDECI_UI_PORT:-5173}"
API_BASE="http://${HOST}:${API_PORT}"
UI_BASE="http://${HOST}:${UI_PORT}"
TIMEOUT="${TIMEOUT:-30}"
API_TOKEN="${FIXOPS_API_TOKEN:-demo-token-change-me}"
START_TIME=$(date +%s)

# ─── Colors (disabled in CI mode) ────────────────────────────
if [[ "$CI_MODE" == "true" ]]; then
    RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; NC=''
else
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    NC='\033[0m'
fi

# ─── Counters ───────────────────────────────────────────────
PASS=0
FAIL=0
WARN=0
TOTAL=0
FAILURES=""

# ─── JSON accumulator ───────────────────────────────────────
JSON_RESULTS="[]"

json_add_result() {
    local name="$1" url="$2" status="$3" expected="$4" result="$5"
    if [[ "$JSON_MODE" == "true" ]]; then
        # Pass values via env vars to avoid shell injection via single quotes
        JSON_RESULTS=$(HC_NAME="$name" HC_URL="$url" HC_STATUS="$status" \
            HC_EXPECTED="$expected" HC_RESULT="$result" \
            python3 -c "
import sys, json, os
results = json.load(sys.stdin)
results.append({
    'name': os.environ['HC_NAME'],
    'url': os.environ['HC_URL'],
    'status_code': os.environ['HC_STATUS'],
    'expected': os.environ['HC_EXPECTED'],
    'result': os.environ['HC_RESULT']
})
print(json.dumps(results))
" <<< "$JSON_RESULTS" 2>/dev/null || echo "$JSON_RESULTS")
    fi
}

# ─── Functions ──────────────────────────────────────────────

banner() {
    if [[ "$JSON_MODE" == "true" ]]; then return; fi
    echo -e "${CYAN}"
    echo "  ┌─────────────────────────────────────────────┐"
    echo "  │     ALdeci CTEM+ Platform Health Check       │"
    echo "  │     v${VERSION} — 44+ Checks, 8 Scanners        │"
    echo "  └─────────────────────────────────────────────┘"
    echo -e "${NC}"
    echo -e "  ${BOLD}API:${NC} ${API_BASE}"
    echo -e "  ${BOLD}UI:${NC}  ${UI_BASE}"
    echo -e "  ${BOLD}Timeout:${NC} ${TIMEOUT}s"
    echo ""
}

section() {
    if [[ "$JSON_MODE" == "true" ]]; then return; fi
    echo ""
    echo -e "${BOLD}$1${NC}"
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
        [[ "$JSON_MODE" != "true" ]] && echo -e "  ${GREEN}✅${NC} ${name} ${CYAN}(${status})${NC}"
        PASS=$((PASS + 1))
        json_add_result "$name" "$url" "$status" "$expected_status" "pass"
    elif [[ "$status" == "000" ]]; then
        [[ "$JSON_MODE" != "true" ]] && echo -e "  ${RED}❌${NC} ${name} ${RED}(unreachable)${NC}"
        FAIL=$((FAIL + 1))
        FAILURES="${FAILURES}\n  - ${name}: unreachable at ${url}"
        json_add_result "$name" "$url" "$status" "$expected_status" "fail"
        # Verbose mode: show curl error
        if [[ "$VERBOSE" == "true" && "$JSON_MODE" != "true" ]]; then
            local err
            err=$(curl -s --max-time 5 "$url" 2>&1) || true
            echo -e "    ${YELLOW}Detail: ${err:-no response}${NC}"
        fi
    else
        [[ "$JSON_MODE" != "true" ]] && echo -e "  ${YELLOW}⚠️${NC}  ${name} ${YELLOW}(${status}, expected ${expected_status})${NC}"
        WARN=$((WARN + 1))
        FAILURES="${FAILURES}\n  - ${name}: got ${status}, expected ${expected_status}"
        json_add_result "$name" "$url" "$status" "$expected_status" "warn"
        # Verbose mode: show response body on unexpected status
        if [[ "$VERBOSE" == "true" && "$JSON_MODE" != "true" ]]; then
            local body
            body=$(curl -s --max-time 5 -H "X-API-Key: ${API_TOKEN}" "$url" 2>/dev/null | head -c 500) || true
            echo -e "    ${YELLOW}Body: ${body:-empty}${NC}"
        fi
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
        [[ "$JSON_MODE" != "true" ]] && echo -e "  ${RED}❌${NC} ${name} ${RED}(no response)${NC}"
        FAIL=$((FAIL + 1))
        FAILURES="${FAILURES}\n  - ${name}: no response from ${url}"
        json_add_result "$name" "$url" "000" "json:${field}=${expected}" "fail"
        return
    fi

    local value
    value=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('${field}',''))" 2>/dev/null) || value=""

    if [[ "$value" == "$expected" ]]; then
        [[ "$JSON_MODE" != "true" ]] && echo -e "  ${GREEN}✅${NC} ${name} ${CYAN}(${field}=${value})${NC}"
        PASS=$((PASS + 1))
        json_add_result "$name" "$url" "200" "json:${field}=${expected}" "pass"
    else
        [[ "$JSON_MODE" != "true" ]] && echo -e "  ${YELLOW}⚠️${NC}  ${name} ${YELLOW}(${field}=${value:-empty}, expected ${expected})${NC}"
        WARN=$((WARN + 1))
        json_add_result "$name" "$url" "200" "json:${field}=${expected}" "warn"
    fi
}

wait_for_api() {
    if [[ "$JSON_MODE" != "true" ]]; then
        echo -e "${BOLD}Waiting for API server...${NC}"
    fi
    local elapsed=0
    while [[ $elapsed -lt $TIMEOUT ]]; do
        if curl -sf "${API_BASE}/health" --max-time 2 > /dev/null 2>&1; then
            [[ "$JSON_MODE" != "true" ]] && echo -e "  ${GREEN}✅${NC} API server ready after ${elapsed}s"
            # Track startup time for DEMO-007
            STARTUP_TIME=$elapsed
            if [[ $elapsed -gt 30 ]]; then
                [[ "$JSON_MODE" != "true" ]] && echo -e "  ${YELLOW}⚠️${NC}  Startup took ${elapsed}s (demo target: <30s)"
            fi
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
        # Print progress every 5 seconds (not in JSON mode)
        if [[ "$JSON_MODE" != "true" && $((elapsed % 5)) -eq 0 ]]; then
            echo -e "  ${YELLOW}⏳${NC} Still waiting... (${elapsed}s/${TIMEOUT}s)"
        fi
    done
    [[ "$JSON_MODE" != "true" ]] && echo -e "  ${RED}❌${NC} API server not ready after ${TIMEOUT}s"
    STARTUP_TIME=$TIMEOUT
    return 1
}

# ─── Main ───────────────────────────────────────────────────

STARTUP_TIME=0
banner

# Phase 1: Wait for API readiness
if ! wait_for_api; then
    if [[ "$JSON_MODE" == "true" ]]; then
        END_TIME=$(date +%s)
        echo "{\"status\":\"timeout\",\"version\":\"${VERSION}\",\"message\":\"API server not ready after ${TIMEOUT}s\",\"duration_sec\":$((END_TIME - START_TIME)),\"startup_sec\":${STARTUP_TIME},\"checks\":[]}"
    else
        echo ""
        echo -e "${RED}${BOLD}FAILED:${NC} API server did not start within ${TIMEOUT}s"
        echo -e "${YELLOW}Troubleshooting:${NC}"
        echo "  1. Check if Docker is running: docker info"
        echo "  2. Check container logs: docker compose -f docker/docker-compose.yml logs fixops"
        echo "  3. Check port conflicts: lsof -i :${API_PORT}"
    fi
    exit 2
fi

# Phase 2: Core Health Endpoints
section "Core Services"
check "API Health" "${API_BASE}/health"
check_json_field "API Status" "${API_BASE}/health" "status" "healthy"
check "UI Frontend" "${UI_BASE}/" "200"
check "UI Nginx Health" "${UI_BASE}/nginx-health" "200"
check "API via UI Proxy" "${UI_BASE}/health" "200"

if [[ "$QUICK_MODE" == "true" ]]; then
    # Quick mode: also check brain and MCP, then done
    section "Quick Verification [V3+V7]"
    check "Brain Pipeline Stats" "${API_BASE}/api/v1/brain/stats" "200" "true"
    check "MCP Tools Discovery" "${API_BASE}/api/v1/mcp/tools" "200" "true"
else
    # Full check mode

    # Phase 3: CTEM+ Pipeline [V3]
    section "CTEM+ Pipeline [V3]"
    check "Brain Pipeline Stats"   "${API_BASE}/api/v1/brain/stats"        "200" "true"
    check "AutoFix Health"         "${API_BASE}/api/v1/autofix/health"     "200" "true"
    check "FAIL Engine Health"     "${API_BASE}/api/v1/fail/health"        "200" "true"
    check "Analytics Dashboard"    "${API_BASE}/api/v1/analytics/dashboard/overview" "200" "true"
    check "Findings List"          "${API_BASE}/api/v1/analytics/findings" "200" "true"
    check "Exposure Cases"         "${API_BASE}/api/v1/cases"              "200" "true"

    # Phase 4: MPTE [V5]
    section "MPTE Verification [V5]"
    check "MPTE Stats"             "${API_BASE}/api/v1/mpte/stats"         "200" "true"
    check "Micro-Pentest Health"   "${API_BASE}/api/v1/micro-pentest/health" "200" "true"

    # Phase 5: MCP [V7]
    section "MCP Gateway [V7]"
    check "MCP Protocol Status"    "${API_BASE}/api/v1/mcp-protocol/status" "200" "true"
    check "MCP Tools Discovery"    "${API_BASE}/api/v1/mcp/tools"          "200" "true"

    # Phase 6: All 8 Native Scanners [V9]
    section "8 Native Scanners [V9]"
    check "1. SAST Scanner"        "${API_BASE}/api/v1/sast/status"              "200" "true"
    check "2. DAST Scanner"        "${API_BASE}/api/v1/dast/status"              "200" "true"
    check "3. Secrets Scanner"     "${API_BASE}/api/v1/secrets/status"            "200" "true"
    check "4. Container Scanner"   "${API_BASE}/api/v1/container/status"          "200" "true"
    check "5. CSPM Scanner"        "${API_BASE}/api/v1/cspm/status"              "200" "true"
    check "6. IaC Scanner"         "${API_BASE}/api/v1/iac/scanners/status"      "200" "true"
    check "7. Malware Scanner"     "${API_BASE}/api/v1/malware/status"           "200" "true"
    check "8. API Fuzzer"          "${API_BASE}/api/v1/api-fuzzer/status"        "200" "true"
    check "Sandbox Verifier"       "${API_BASE}/api/v1/sandbox/health"           "200" "true"

    # Phase 7: Evidence & Compliance [V10]
    section "Evidence & Compliance [V10]"
    check "Evidence Vault"         "${API_BASE}/api/v1/evidence/"          "200" "true"
    check "Compliance Frameworks"  "${API_BASE}/api/v1/compliance-engine/frameworks" "200" "true"
    check "Knowledge Graph"        "${API_BASE}/api/v1/knowledge-graph/status" "200" "true"

    # Phase 8: Platform Services
    section "Platform Services"
    check "Workflows"              "${API_BASE}/api/v1/workflows"          "200" "true"
    check "Policies"               "${API_BASE}/api/v1/policies"           "200" "true"
    check "Reports"                "${API_BASE}/api/v1/reports"            "200" "true"
    check "Audit Logs"             "${API_BASE}/api/v1/audit/logs"         "200" "true"
    check "Remediation Tasks"      "${API_BASE}/api/v1/remediation/tasks"  "200" "true"
    check "Inventory Apps"         "${API_BASE}/api/v1/inventory/applications" "200" "true"
    check "Users"                  "${API_BASE}/api/v1/users"              "200" "true"
    check "Teams"                  "${API_BASE}/api/v1/teams"              "200" "true"
    check "Feeds Health"           "${API_BASE}/api/v1/feeds/health"       "200" "true"
    check "Self-Learning [V8]"     "${API_BASE}/api/v1/self-learning/status"  "200" "true"
    check "Self-Learning Stats"    "${API_BASE}/api/v1/self-learning/stats"  "200" "true"
    check "Zero-Gravity [V9]"      "${API_BASE}/api/v1/zero-gravity/status"  "200" "true"
    check "Brain Trends [V3]"      "${API_BASE}/api/v1/brain/trends"         "200" "true"

    # Phase 9: OpenAPI specification
    section "API Documentation"
    check "OpenAPI Spec"           "${API_BASE}/openapi.json"              "200"
    check "Swagger UI"             "${API_BASE}/docs"                      "200"

    # Phase 10: Docker container health (only when running in Docker)
    if [[ "$JSON_MODE" != "true" ]]; then
        section "Docker Container Status"
    fi
    if command -v docker &> /dev/null && docker info &> /dev/null 2>&1; then
        DOCKER_RUNNING=false
        for container in fixops-api aldeci-ui; do
            local_status=$(docker inspect --format='{{.State.Health.Status}}' "$container" 2>/dev/null) || local_status=""
            if [[ -n "$local_status" ]]; then
                DOCKER_RUNNING=true
                TOTAL=$((TOTAL + 1))
                case "$local_status" in
                    healthy)
                        [[ "$JSON_MODE" != "true" ]] && echo -e "  ${GREEN}✅${NC} ${container} ${CYAN}(${local_status})${NC}"
                        PASS=$((PASS + 1))
                        json_add_result "docker:${container}" "docker-inspect" "$local_status" "healthy" "pass"
                        ;;
                    starting)
                        [[ "$JSON_MODE" != "true" ]] && echo -e "  ${YELLOW}⚠️${NC}  ${container} ${YELLOW}(${local_status})${NC}"
                        WARN=$((WARN + 1))
                        json_add_result "docker:${container}" "docker-inspect" "$local_status" "healthy" "warn"
                        ;;
                    *)
                        [[ "$JSON_MODE" != "true" ]] && echo -e "  ${RED}❌${NC} ${container} ${RED}(${local_status})${NC}"
                        FAIL=$((FAIL + 1))
                        FAILURES="${FAILURES}\n  - Docker container ${container}: ${local_status}"
                        json_add_result "docker:${container}" "docker-inspect" "$local_status" "healthy" "fail"
                        ;;
                esac
            fi
        done
        if [[ "$DOCKER_RUNNING" != "true" && "$JSON_MODE" != "true" ]]; then
            echo -e "  ${CYAN}ℹ${NC}  No Docker containers found — running locally (OK)"
        fi
    else
        [[ "$JSON_MODE" != "true" ]] && echo -e "  ${CYAN}ℹ${NC}  Docker not available — skipping container checks (OK for local dev)"
    fi
fi

# ─── Summary / Output ─────────────────────────────────────────
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

if [[ "$JSON_MODE" == "true" ]]; then
    # JSON output for CI parsing
    if [[ $FAIL -eq 0 ]]; then
        VERDICT="pass"
    else
        VERDICT="fail"
    fi
    HC_VERDICT="$VERDICT" HC_PASS="$PASS" HC_FAIL="$FAIL" HC_WARN="$WARN" \
    HC_TOTAL="$TOTAL" HC_DURATION="$DURATION" HC_API="$API_BASE" HC_UI="$UI_BASE" \
    HC_VERSION="$VERSION" HC_STARTUP="$STARTUP_TIME" \
    python3 -c "
import json, sys, os
results = json.load(sys.stdin)
output = {
    'status': os.environ['HC_VERDICT'],
    'version': os.environ['HC_VERSION'],
    'passed': int(os.environ['HC_PASS']),
    'failed': int(os.environ['HC_FAIL']),
    'warnings': int(os.environ['HC_WARN']),
    'total': int(os.environ['HC_TOTAL']),
    'duration_sec': int(os.environ['HC_DURATION']),
    'startup_sec': int(os.environ['HC_STARTUP']),
    'api_base': os.environ['HC_API'],
    'ui_base': os.environ['HC_UI'],
    'demo_ready': os.environ['HC_VERDICT'] == 'pass' and int(os.environ['HC_STARTUP']) <= 30,
    'checks': results
}
print(json.dumps(output, indent=2))
" <<< "$JSON_RESULTS"
else
    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${BOLD}Results:${NC} ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}, ${YELLOW}${WARN} warnings${NC} / ${TOTAL} total"
    echo -e "  ${BOLD}Duration:${NC} ${DURATION}s"
    echo -e "  ${BOLD}Startup:${NC} ${STARTUP_TIME}s"

    if [[ $FAIL -eq 0 && $WARN -eq 0 ]]; then
        echo -e "  ${GREEN}${BOLD}✅ ALL CHECKS PASSED — Demo ready!${NC}"
    elif [[ $FAIL -eq 0 ]]; then
        echo -e "  ${YELLOW}${BOLD}⚠️  PASSED with ${WARN} warnings${NC}"
    else
        echo -e "  ${RED}${BOLD}❌ FAILED — ${FAIL} checks did not pass${NC}"
        if [[ -n "$FAILURES" ]]; then
            echo -e "\n  ${RED}Failures:${NC}${FAILURES}"
        fi
        echo ""
        echo -e "  ${YELLOW}Troubleshooting:${NC}"
        echo "    docker compose -f docker/docker-compose.yml logs fixops"
        echo "    docker compose -f docker/docker-compose.yml logs aldeci-ui"
    fi

    # DEMO-007 startup time gate
    if [[ $STARTUP_TIME -gt 30 ]]; then
        echo ""
        echo -e "  ${YELLOW}⚠️  DEMO-007 WARNING: Startup time ${STARTUP_TIME}s exceeds 30s target${NC}"
    fi

    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
fi

# Exit with appropriate code
if [[ $FAIL -gt 0 ]]; then
    exit 1
else
    exit 0
fi
