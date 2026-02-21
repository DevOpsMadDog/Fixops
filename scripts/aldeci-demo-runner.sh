#!/usr/bin/env bash
# ============================================================================
#  ALDECI - Application Lifecycle DevSecOps CI
#  Enterprise Demo Runner — Real API Calls, Real Data
#  All phases hit the live FixOps API with curl.
# ============================================================================

set -euo pipefail

# ============================================================================
# CONFIGURATION
# ============================================================================
FIXOPS_API_URL="${FIXOPS_API_URL:-http://127.0.0.1:8000}"
FIXOPS_API_TOKEN="${FIXOPS_API_TOKEN:?ERROR: FIXOPS_API_TOKEN must be set. Generate: python3 -c \"import secrets; print(secrets.token_urlsafe(48))\"}"
# Strip 'KEY=value' prefix if present (e.g. ENTERPRISE_TOKEN=xxx → xxx)
[[ "$FIXOPS_API_TOKEN" == *"="* ]] && FIXOPS_API_TOKEN="${FIXOPS_API_TOKEN#*=}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
PASS=0; FAIL=0; TOTAL=0

# ============================================================================
# COLORS & FORMATTING
# ============================================================================
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; WHITE='\033[1;37m'
BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
ORANGE='\033[38;5;208m'; PURPLE='\033[38;5;141m'

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================
hr()      { echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"; }
section() { echo ""; hr; echo -e "${WHITE}  $1${NC}"; hr; }
ok()      { echo -e "  ${GREEN}✅ $1${NC}"; }
fail()    { echo -e "  ${RED}❌ $1${NC}"; }
info()    { echo -e "  ${CYAN}ℹ  $1${NC}"; }
warn()    { echo -e "  ${YELLOW}⚠  $1${NC}"; }

# call METHOD PATH [DATA] [DESCRIPTION]
call() {
    local method="$1" path="$2" data="${3:-}" desc="${4:-$method $path}"
    TOTAL=$((TOTAL+1))
    local args=(-s -L -w "\n%{http_code}" -X "$method" --max-time 30 --connect-timeout 5)
    args+=(-H "X-API-Key: $FIXOPS_API_TOKEN" -H "Content-Type: application/json")
    [[ -n "$data" ]] && args+=(-d "$data")
    local raw; raw=$(curl "${args[@]}" "${FIXOPS_API_URL}${path}" 2>/dev/null || echo -e "\n000")
    local code; code=$(echo "$raw" | tail -1)
    local body; body=$(echo "$raw" | sed '$d')
    if [[ "$code" =~ ^2 ]]; then
        printf "  ${GREEN}✅ %-55s [%s]${NC}\n" "$desc" "$code"
        PASS=$((PASS+1))
    else
        printf "  ${RED}❌ %-55s [%s]${NC}\n" "$desc" "$code"
        FAIL=$((FAIL+1))
    fi
    LAST_BODY="$body"
    LAST_CODE="$code"
}

# call_quiet — same but no output, stores body+code
call_quiet() {
    local method="$1" path="$2" data="${3:-}"
    local args=(-s -L -w "\n%{http_code}" -X "$method" --max-time 30 --connect-timeout 5)
    args+=(-H "X-API-Key: $FIXOPS_API_TOKEN" -H "Content-Type: application/json")
    [[ -n "$data" ]] && args+=(-d "$data")
    local raw; raw=$(curl "${args[@]}" "${FIXOPS_API_URL}${path}" 2>/dev/null || echo -e "\n000")
    LAST_CODE=$(echo "$raw" | tail -1)
    LAST_BODY=$(echo "$raw" | sed '$d')
}

# pretty-print a JSON field
jq_field() { echo "$LAST_BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('$1','N/A'))" 2>/dev/null || echo "N/A"; }

# ============================================================================
# BANNER
# ============================================================================
show_banner() {
    clear
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  ${BOLD}${WHITE}  A L D E C I  —  Enterprise Demo Runner${NC}                  ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${DIM}Application Lifecycle DevSecOps CI Platform${NC}                ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${DIM}All calls hit the live API — zero fake data${NC}                ${CYAN}║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  API : ${WHITE}${FIXOPS_API_URL}${NC}                              ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  Auth: ${GREEN}Enterprise token configured${NC}                       ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# ============================================================================
# PHASE 0: HEALTH & CONNECTIVITY
# ============================================================================
phase_health() {
    section "PHASE 0 — Health & Connectivity"
    call GET "/health" "" "Health check"
    call GET "/api/v1/feeds/health" "" "Feeds health"
    call GET "/api/v1/brain/health" "" "Brain health"
    call GET "/api/v1/dast/status" "" "DAST status"
    call GET "/api/v1/metrics" "" "Platform metrics"
    call GET "/api/v1/copilot/agents/status" "" "Copilot agents status"
    call GET "/api/v1/autofix/health" "" "Autofix engine health"
    call GET "/api/v1/reachability/health" "" "Reachability engine health"
    echo ""
}

# ============================================================================
# PHASE 1: SCOPE — Asset Registration & Configuration
# ============================================================================
phase_scope() {
    section "CTEM STAGE 1 — SCOPE (Asset Registration)"
    call GET  "/api/v1/inventory/assets" "" "List inventory assets"
    call POST "/api/v1/brain/ingest/asset" '{"asset_id":"payment-gateway","name":"payment-gateway","criticality":0.95,"type":"web-app"}' "Register asset: payment-gateway"
    call POST "/api/v1/brain/ingest/asset" '{"asset_id":"user-identity-svc","name":"user-identity-svc","criticality":0.9,"type":"api"}' "Register asset: user-identity-svc"
    call GET  "/api/v1/inventory/applications" "" "List applications"
    call GET  "/api/v1/brain/nodes" "" "Brain nodes (assets + CVEs)"
    echo ""
}

# ============================================================================
# PHASE 2: DISCOVER — Feeds, Vulns, SBOM, Scans
# ============================================================================
phase_discover() {
    section "CTEM STAGE 2 — DISCOVER (Feeds & Vulnerability Ingestion)"
    call GET  "/api/v1/feeds/health" "" "Feeds health"
    call GET  "/api/v1/feeds/sources" "" "List feed sources"
    call GET  "/api/v1/feeds/stats" "" "Feed statistics"
    call GET  "/api/v1/feeds/epss?limit=3" "" "EPSS scores (top 3)"
    call GET  "/api/v1/feeds/kev?limit=3" "" "KEV catalog (top 3)"
    call GET  "/api/v1/feeds/categories" "" "Feed categories"
    call POST "/api/v1/feeds/enrich" '{"findings":[{"cve_id":"CVE-2021-44228"},{"cve_id":"CVE-2024-3094"}]}' "Enrich CVE findings"
    call POST "/api/v1/brain/ingest/cve" '{"cve_id":"CVE-2021-44228","severity":"critical","description":"Log4Shell RCE"}' "Ingest CVE-2021-44228"
    call GET  "/api/v1/vulns/discovered" "" "Discovered vulnerabilities"
    call GET  "/api/v1/vulns/stats" "" "Vulnerability statistics"
    call GET  "/api/v1/sast/status" "" "SAST scanner status"
    call GET  "/api/v1/dast/status" "" "DAST scanner status"
    call GET  "/api/v1/cspm/status" "" "Cloud security posture (CSPM)"
    call GET  "/api/v1/deduplication/stats" "" "Deduplication stats"
    echo ""
}

# ============================================================================
# PHASE 3: PRIORITIZE — SSVC, Brain Graph, EPSS, Bayesian Risk
# ============================================================================
phase_prioritize() {
    section "CTEM STAGE 3 — PRIORITIZE (Risk Scoring & Decisions)"
    call POST "/api/v1/decisions/make-decision" \
        '{"cve_id":"CVE-2024-3094","exploitation":"active","exposure":"open","impact":"high","mission_prevalence":"essential"}' \
        "SSVC decision: CVE-2024-3094"
    info "SSVC result: $(jq_field decision)"

    call GET  "/api/v1/graph/" "" "Brain knowledge graph"
    info "Graph: $(echo "$LAST_BODY" | python3 -c "import sys,json;d=json.load(sys.stdin);print(str(d.get('node_count','?'))+' nodes, '+str(d.get('edge_count','?'))+' edges')" 2>/dev/null || echo "N/A")"

    call POST "/api/v1/predictions/bayesian/risk-assessment" \
        '{"asset":"payment-gateway","threats":["CVE-2024-3094","CVE-2021-44228"],"controls":["WAF","IDS"]}' \
        "Bayesian risk assessment"

    call GET  "/api/v1/decisions/core-components" "" "Decision core components"
    call GET  "/api/v1/decisions/recent" "" "Recent decisions"
    call GET  "/api/v1/decisions/metrics" "" "Decision metrics"
    call GET  "/api/v1/feeds/exploit-confidence/CVE-2021-44228" "" "Exploit confidence: Log4Shell"
    echo ""
}

# ============================================================================
# PHASE 4: VALIDATE — Micro-Pentest, Attack Surface, Reachability
# ============================================================================
phase_validate() {
    section "CTEM STAGE 4 — VALIDATE (Exploit & Attack Surface)"
    call GET  "/api/v1/micro-pentest/health" "" "Micro-pentest engine health"
    call GET  "/api/v1/micro-pentest/enterprise/health" "" "Enterprise pentest health"
    call GET  "/api/v1/micro-pentest/enterprise/attack-vectors" "" "Attack vectors catalog"
    call GET  "/api/v1/micro-pentest/enterprise/scan-modes" "" "Scan modes available"
    call GET  "/api/v1/attack-sim/health" "" "Attack simulation health"
    call GET  "/api/v1/attack-sim/campaigns" "" "Attack sim campaigns"
    call GET  "/api/v1/reachability/health" "" "Reachability engine health"
    call GET  "/api/v1/reachability/metrics" "" "Reachability metrics"
    call GET  "/api/v1/container/status" "" "Container scanner status"
    echo ""
}

# ============================================================================
# PHASE 5: MOBILIZE — Integrations, Reports, Compliance, Autofix
# ============================================================================
phase_mobilize() {
    section "CTEM STAGE 5 — MOBILIZE (Remediation & Reporting)"
    call GET  "/api/v1/integrations" "" "Integration connectors"
    call GET  "/api/v1/reports" "" "List reports"
    call POST "/api/v1/reports/generate" '{"type":"executive","format":"json"}' "Generate executive report"
    call GET  "/api/v1/reports/stats" "" "Report statistics"
    call GET  "/api/v1/audit/compliance/frameworks" "" "Compliance frameworks"
    call GET  "/api/v1/autofix/health" "" "Autofix engine health"
    call GET  "/api/v1/autofix/stats" "" "Autofix stats"
    call GET  "/api/v1/remediation/statuses" "" "Remediation statuses"
    call GET  "/api/v1/remediation/tasks" "" "Remediation tasks"
    echo ""
}

# ============================================================================
# BONUS: Advanced Endpoints (Copilot, Marketplace, Predictions)
# ============================================================================
phase_advanced() {
    section "ADVANCED — Copilot, Marketplace, Predictions"
    call GET  "/api/v1/copilot/agents/status" "" "Copilot agents status"
    call GET  "/api/v1/copilot/health" "" "Copilot health"
    call GET  "/api/v1/marketplace/browse" "" "Marketplace browse"
    call GET  "/api/v1/marketplace/stats" "" "Marketplace stats"
    call GET  "/api/v1/marketplace/recommendations" "" "Marketplace recommendations"
    call GET  "/api/v1/predictions/markov/states" "" "Prediction Markov states"
    call GET  "/api/v1/predictions/markov/transitions" "" "Prediction Markov transitions"
    call GET  "/api/v1/business-context/formats" "" "Business context formats"
    call GET  "/api/v1/business-context/stored" "" "Stored business contexts"
    call GET  "/api/v1/enhanced/capabilities" "" "Enhanced analysis capabilities"
    call GET  "/api/v1/nerve-center/pulse" "" "Nerve center pulse"
    echo ""
}

# ============================================================================
# RUN ALL PHASES
# ============================================================================
run_all() {
    show_banner
    phase_health
    phase_scope
    phase_discover
    phase_prioritize
    phase_validate
    phase_mobilize
    phase_advanced
    summary
}

# ============================================================================
# SUMMARY
# ============================================================================
summary() {
    section "RESULTS SUMMARY"
    echo -e "  ${WHITE}Total : ${BOLD}${TOTAL}${NC}"
    echo -e "  ${GREEN}Pass  : ${BOLD}${PASS}${NC}"
    echo -e "  ${RED}Fail  : ${BOLD}${FAIL}${NC}"
    echo ""
    if [[ "$FAIL" -eq 0 ]]; then
        echo -e "  ${GREEN}${BOLD}ALL ENDPOINTS PASSED — Enterprise Ready${NC}"
    else
        echo -e "  ${RED}${BOLD}${FAIL} ENDPOINT(S) FAILED — Review above${NC}"
    fi
    echo ""
}

# ============================================================================
# INTERACTIVE MENU
# ============================================================================
show_menu() {
    show_banner
    echo -e "  ${WHITE}Select a phase to run:${NC}"
    echo ""
    echo -e "  ${CYAN}[0]${NC}  Health & connectivity"
    echo -e "  ${CYAN}[1]${NC}  CTEM Stage 1 — Scope"
    echo -e "  ${CYAN}[2]${NC}  CTEM Stage 2 — Discover"
    echo -e "  ${CYAN}[3]${NC}  CTEM Stage 3 — Prioritize"
    echo -e "  ${CYAN}[4]${NC}  CTEM Stage 4 — Validate"
    echo -e "  ${CYAN}[5]${NC}  CTEM Stage 5 — Mobilize"
    echo -e "  ${CYAN}[6]${NC}  Advanced (Copilot, Marketplace, Predictions)"
    echo -e "  ${CYAN}[a]${NC}  Run ALL phases end-to-end"
    echo -e "  ${CYAN}[q]${NC}  Quit"
    echo ""
    echo -en "  ${YELLOW}⟩ Choice: ${NC}"
}

# ============================================================================
# MAIN
# ============================================================================
main() {
    if [[ "${1:-}" == "--all" ]] || [[ "${1:-}" == "-a" ]]; then
        run_all
        exit $FAIL
    fi

    while true; do
        show_menu
        read -r choice
        case "$choice" in
            0) phase_health ;;
            1) phase_scope ;;
            2) phase_discover ;;
            3) phase_prioritize ;;
            4) phase_validate ;;
            5) phase_mobilize ;;
            6) phase_advanced ;;
            a|A) run_all ;;
            q|Q)
                echo ""
                echo -e "  ${GREEN}Done. ${PASS}/${TOTAL} passed.${NC}"
                exit $FAIL
                ;;
            *)
                echo -e "  ${RED}Invalid choice.${NC}"
                sleep 0.5
                ;;
        esac
    done
}

main "$@"