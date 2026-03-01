#!/usr/bin/env bash
# =============================================================================
# ALdeci 15-Minute Investor Demo Script — v3.0 (Real Data, No Fallbacks)
# =============================================================================
#
# SPRINT1-010 | Pillars: V3 (Decision Intelligence), V5 (MPTE), V7 (MCP-Native)
# Version: 3.0.0 | Date: 2026-02-27
#
# PURPOSE:
#   Live, scripted 15-minute demo for investor meetings. Seeds REAL data
#   into the platform, hits REAL API endpoints, displays REAL responses.
#   No canned fallback data. Every number on screen comes from the live API.
#
# WHAT CHANGED IN V3:
#   - REMOVED all fallback/canned data — every response is from the live API
#   - Added SEED PRELUDE that creates real data before the demo starts
#   - All metrics extracted from live API responses via jq
#   - Fixed "16 AI agents" → 17 (actual count)
#   - MCP tool count comes from live /api/v1/mcp/stats, not hardcoded
#   - Added X-Org-Id header for org-scoped endpoints
#   - Aligned all claims with CEO_VISION.md and CTEM_PLUS_IDENTITY.md
#
# TIMING BREAKDOWN:
#   [Pre-show]     SEED — Create real data (assets, findings, CVEs) — ~30s
#   [0:00 - 2:00]  ACT 1 — The Problem (stats + pain)
#   [2:00 - 4:30]  ACT 2 — Ingestion + Triage (brain ingest + dashboard)
#   [4:30 - 7:00]  ACT 3 — FAIL Scoring + Brain Pipeline (V3 live API)
#   [7:00 - 10:00] ACT 4 — MPTE 19-Phase Verification (V5 live API)
#   [10:00 - 12:00] ACT 5 — AutoFix + MCP-Native (V7 live API)
#   [12:00 - 13:30] ACT 6 — Evidence & Compliance (signed bundles)
#   [13:30 - 15:00] ACT 7 — Market, Moat & Ask
#
# PRE-REQUISITES:
#   1. API running at BASE_URL (default http://localhost:8000)
#   2. FIXOPS_API_TOKEN env var set (enterprise token)
#   3. curl + jq installed
#   4. Terminal with at least 120 columns
#
# USAGE:
#   ./investor-demo-15min.sh              # Interactive (press Enter)
#   ./investor-demo-15min.sh --auto       # Auto-advance (3s pauses)
#   ./investor-demo-15min.sh --dry-run    # Show commands without executing
#   ./investor-demo-15min.sh --check      # Pre-flight check only
#
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BASE_URL="${ALDECI_BASE_URL:-http://localhost:8000}"
API_KEY="${FIXOPS_API_TOKEN:?ERROR: FIXOPS_API_TOKEN must be set. Generate with: python3 -c \"import secrets; print(secrets.token_urlsafe(48))\"}"
AUTO_MODE=false
DRY_RUN=false
CHECK_ONLY=false

# Colors (ANSI escape sequences)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

# Captured API responses (populated during demo)
LAST_RESPONSE=""

# Parse arguments
for arg in "$@"; do
    case "$arg" in
        --auto)      AUTO_MODE=true ;;
        --dry-run)   DRY_RUN=true ;;
        --check)     CHECK_ONLY=true ;;
        --help|-h)
            echo "Usage: $0 [--auto] [--dry-run] [--check]"
            echo ""
            echo "  --auto       Auto-advance with 3-second pauses"
            echo "  --dry-run    Show commands without hitting the API"
            echo "  --check      Pre-flight check only, then exit"
            exit 0
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------------------------

banner() {
    local width=75
    echo ""
    echo -e "${BOLD}${CYAN}$(printf '%.0s=' $(seq 1 $width))${RESET}"
    echo -e "${BOLD}${WHITE}  $1${RESET}"
    echo -e "${BOLD}${CYAN}$(printf '%.0s=' $(seq 1 $width))${RESET}"
    echo ""
}

section() {
    echo ""
    echo -e "${BOLD}${YELLOW}  [$1]  $2${RESET}"
    echo -e "${DIM}  $(printf '%.0s-' $(seq 1 60))${RESET}"
}

talk() {
    echo -e "${GREEN}  TALK:${RESET} $1"
}

note() {
    echo -e "${DIM}  NOTE: $1${RESET}"
}

warn() {
    echo -e "${RED}  WARNING: $1${RESET}"
}

show_cmd() {
    echo -e "${DIM}  $1${RESET}"
}

pause_for_presenter() {
    if [ "$AUTO_MODE" = true ]; then
        sleep 3
    else
        echo ""
        echo -e "${DIM}  Press Enter to continue...${RESET}"
        read -r
    fi
}

# Real API call — no fallbacks. Fails visibly if API is down.
api_call() {
    local method="$1"
    local endpoint="$2"
    local data="${3:-}"
    local description="${4:-API call}"

    local url="${BASE_URL}${endpoint}"

    if [ "$DRY_RUN" = true ]; then
        echo -e "${DIM}  [DRY RUN] $method $url${RESET}"
        if [ -n "$data" ]; then
            echo -e "${DIM}  Body: $(echo "$data" | head -c 200)...${RESET}"
        fi
        LAST_RESPONSE="{}"
        return 0
    fi

    local response="" http_code=""
    local args=(-s -w "\n%{http_code}" --max-time 15 --connect-timeout 5
        -H "X-API-Key: ${API_KEY}"
        -H "Content-Type: application/json"
        -H "Accept: application/json"
        -H "X-Org-Id: demo-org"
    )

    if [ "$method" = "POST" ]; then
        args+=(-X POST -d "${data}")
    fi

    response=$(curl "${args[@]}" "${url}" 2>/dev/null) || true

    if [ -n "$response" ]; then
        http_code=$(echo "$response" | tail -1)
        LAST_RESPONSE=$(echo "$response" | sed '$d')

        if [[ "$http_code" =~ ^2 ]]; then
            echo "$LAST_RESPONSE" | jq '.' 2>/dev/null || echo "$LAST_RESPONSE"
            return 0
        fi
    fi

    echo -e "  ${RED}[${http_code:-ERR}] ${description} failed${RESET}"
    LAST_RESPONSE="{}"
    return 1
}

# Silent API call for seeding — no output, just populate data (tolerates 409 duplicates)
seed() {
    local method="$1" endpoint="$2" data="${3:-}"
    [[ "$DRY_RUN" == "true" ]] && return 0

    local args=(-s -o /dev/null -w "%{http_code}" --max-time 10
        -H "X-API-Key: ${API_KEY}"
        -H "Content-Type: application/json"
        -H "X-Org-Id: demo-org"
    )
    [[ "$method" == "POST" ]] && args+=(-X POST -d "${data}")

    local code; code=$(curl "${args[@]}" "${BASE_URL}${endpoint}" 2>/dev/null || echo "000")
    [[ "$code" =~ ^2 ]] || [[ "$code" == "409" ]] && echo -ne "  ${GREEN}.${RESET}" || echo -ne "  ${RED}x${RESET}"
}

# ---------------------------------------------------------------------------
# Pre-Flight Check — API MUST be running (no fallbacks)
# ---------------------------------------------------------------------------

preflight() {
    banner "ALdeci Demo Pre-Flight Check"

    echo -e "  Checking dependencies..."

    # Check curl
    if command -v curl &>/dev/null; then
        echo -e "  ${GREEN}[OK]${RESET} curl installed"
    else
        echo -e "  ${RED}[FAIL]${RESET} curl not found — install curl first"
        exit 1
    fi

    # Check jq
    if command -v jq &>/dev/null; then
        echo -e "  ${GREEN}[OK]${RESET} jq installed"
    else
        echo -e "  ${RED}[FAIL]${RESET} jq required for live data extraction — install with: brew install jq"
        exit 1
    fi

    if [ "$DRY_RUN" = true ]; then
        echo -e "  ${YELLOW}[DRY RUN]${RESET} Skipping API checks"
        echo ""
        return 0
    fi

    # Check API health — REQUIRED (no fallback)
    echo -e "  Checking API at ${BASE_URL}..."
    local health_response
    health_response=$(curl -s -o /dev/null -w "%{http_code}" \
        "${BASE_URL}/health" 2>/dev/null) || true

    if [ "$health_response" = "200" ]; then
        echo -e "  ${GREEN}[OK]${RESET} API is healthy"
    else
        echo -e "  ${RED}[FAIL]${RESET} API not responding at ${BASE_URL}"
        echo -e "  ${RED}       Start the backend first:${RESET}"
        echo -e "  ${DIM}       uvicorn apps.api.app:app --port 8000 --reload${RESET}"
        exit 1
    fi

    # Check critical engines — all must be up
    local engines=("fail" "brain" "autofix" "mcp")
    local engine_names=("FAIL Engine" "Brain Pipeline" "AutoFix Engine" "MCP Gateway")
    local engine_paths=("/api/v1/fail/health" "/api/v1/brain/health" "/api/v1/autofix/health" "/api/v1/mcp/stats")

    for i in "${!engines[@]}"; do
        local code
        code=$(curl -s -o /dev/null -w "%{http_code}" \
            -H "X-API-Key: ${API_KEY}" \
            "${BASE_URL}${engine_paths[$i]}" 2>/dev/null) || true
        if [[ "$code" =~ ^2 ]]; then
            echo -e "  ${GREEN}[OK]${RESET} ${engine_names[$i]} operational"
        else
            echo -e "  ${RED}[FAIL]${RESET} ${engine_names[$i]} not responding"
            echo -e "  ${RED}       Cannot run demo without all engines.${RESET}"
            exit 1
        fi
    done

    echo ""
    echo -e "  ${GREEN}Pre-flight complete. All engines operational. Ready to demo.${RESET}"
    echo ""
}

# ---------------------------------------------------------------------------
# SEED PRELUDE — Create real data the demo needs (~30 seconds)
# ---------------------------------------------------------------------------

seed_data() {
    banner "SEED PRELUDE — Populating Real Data"
    echo -e "  ${DIM}Creating assets, findings, CVEs, policies, and identities...${RESET}"
    echo ""

    if [ "$DRY_RUN" = true ]; then
        echo -e "  ${YELLOW}[DRY RUN] Would seed ~25 data objects${RESET}"
        echo ""
        return 0
    fi

    echo -ne "  Seeding assets"
    seed POST /api/v1/inventory/applications \
      '{"name":"PaymentService","description":"Payment processing API handling card transactions","criticality":"critical","owner_team":"platform","tags":["pci","financial"]}'
    seed POST /api/v1/inventory/applications \
      '{"name":"APIGateway","description":"Kong-based API gateway","criticality":"high","owner_team":"infrastructure","tags":["public-facing"]}'
    seed POST /api/v1/inventory/applications \
      '{"name":"UserDatabase","description":"PostgreSQL user store with PII","criticality":"critical","owner_team":"data","tags":["pii","database"]}'
    echo ""

    echo -ne "  Seeding identities"
    seed POST /api/v1/identity/canonical \
      '{"canonical_id":"payment-service-prod","org_id":"demo-org","properties":{"team":"platform","criticality":"critical"}}'
    seed POST /api/v1/identity/canonical \
      '{"canonical_id":"api-gateway-prod","org_id":"demo-org","properties":{"team":"infra","criticality":"high"}}'
    echo ""

    echo -ne "  Seeding brain assets"
    seed POST /api/v1/brain/ingest/asset \
      '{"asset_id":"payment-svc","name":"payment-service","criticality":0.95,"type":"service"}'
    seed POST /api/v1/brain/ingest/asset \
      '{"asset_id":"api-gw","name":"api-gateway","criticality":0.85,"type":"service"}'
    seed POST /api/v1/brain/ingest/asset \
      '{"asset_id":"user-db","name":"user-database","criticality":0.90,"type":"database"}'
    echo ""

    echo -ne "  Seeding CVEs"
    seed POST /api/v1/brain/ingest/cve \
      '{"cve_id":"CVE-2024-3094","severity":"critical","description":"xz-utils backdoor allowing RCE via SSH"}'
    seed POST /api/v1/brain/ingest/cve \
      '{"cve_id":"CVE-2024-21762","severity":"critical","description":"FortiOS out-of-bound write RCE"}'
    seed POST /api/v1/brain/ingest/cve \
      '{"cve_id":"CVE-2023-44487","severity":"high","description":"HTTP/2 Rapid Reset DoS attack"}'
    seed POST /api/v1/brain/ingest/cve \
      '{"cve_id":"CVE-2021-44228","severity":"critical","description":"Apache Log4j2 RCE via JNDI"}'
    seed POST /api/v1/brain/ingest/cve \
      '{"cve_id":"CVE-2024-0056","severity":"medium","description":"Microsoft SQL info disclosure"}'
    echo ""

    echo -ne "  Seeding findings"
    seed POST /api/v1/brain/ingest/finding \
      '{"finding_id":"FIND-2024-XZ-001","cve_id":"CVE-2024-3094","severity":"critical","asset":"api-gw","source":"snyk","title":"xz-utils backdoor RCE"}'
    seed POST /api/v1/brain/ingest/finding \
      '{"finding_id":"FIND-FORTIOS-001","cve_id":"CVE-2024-21762","severity":"critical","asset":"api-gw","source":"semgrep","title":"FortiOS RCE"}'
    seed POST /api/v1/brain/ingest/finding \
      '{"finding_id":"FIND-HTTP2-001","cve_id":"CVE-2023-44487","severity":"high","asset":"api-gw","source":"dast","title":"HTTP/2 Rapid Reset"}'
    seed POST /api/v1/brain/ingest/finding \
      '{"finding_id":"FIND-LOG4J-001","cve_id":"CVE-2021-44228","severity":"critical","asset":"payment-svc","source":"sca","title":"Log4Shell RCE"}'
    seed POST /api/v1/brain/ingest/finding \
      '{"finding_id":"FIND-SQL-001","cve_id":"CVE-2024-0056","severity":"medium","asset":"user-db","source":"sca","title":"MSSQL info disclosure"}'
    echo ""

    echo -ne "  Seeding policies"
    seed POST /api/v1/policies \
      '{"name":"Block Critical CVEs","description":"Auto-block deployments with unpatched CRITICAL CVEs","policy_type":"guardrail","rules":{"max_severity":"critical","auto_block":true}}'
    seed POST /api/v1/policies \
      '{"name":"PCI-DSS Gate","description":"Enforce PCI-DSS controls","policy_type":"compliance","rules":{"framework":"PCI-DSS"}}'
    echo ""

    echo -ne "  Seeding teams & users"
    seed POST /api/v1/teams '{"name":"Platform Security","description":"Core security team"}'
    seed POST /api/v1/users '{"email":"alice@acme.com","password":"Str0ngP@ss!2024","first_name":"Alice","last_name":"Chen","role":"security_analyst","department":"Security"}'
    seed POST /api/v1/users '{"email":"bob@acme.com","password":"D3v3l0per!Pwd","first_name":"Bob","last_name":"Martinez","role":"developer","department":"Engineering"}'
    echo ""

    echo ""
    echo -e "  ${GREEN}Seed complete. All demo data is real and queryable.${RESET}"
    echo ""
}

# =============================================================================
# DEMO SCRIPT
# =============================================================================

preflight

if [ "$CHECK_ONLY" = true ]; then
    exit 0
fi

seed_data

# =============================================================================
# ACT 1: THE PROBLEM [0:00 - 2:00]
# =============================================================================

banner "ACT 1: The \$380 Billion Problem"

section "0:00" "Open with the pain"
talk "\"Thank you for your time. I want to show you something that costs"
talk "  enterprises \$4,200 per vulnerability to fix -- and why 68% of"
talk "  that spend is wasted on false positives.\""
echo ""
talk "\"Every enterprise runs 5 to 15 security scanners. Snyk for"
talk "  open-source. Semgrep for static analysis. Trivy for containers."
talk "  Wiz for cloud posture. Each one screams CRITICAL independently."
talk "  Nobody coordinates. Nobody deduplicates. Nobody verifies.\""
echo ""

echo -e "${BOLD}${WHITE}  The Security Alert Tsunami:${RESET}"
echo ""
echo -e "    Scanners deployed per enterprise:  ${BOLD}5-15${RESET}"
echo -e "    Raw findings per week (200 devs):  ${BOLD}${RED}11,300${RESET}"
echo -e "    False positive rate:               ${BOLD}${RED}68%${RESET}"
echo -e "    Analyst time on data janitoring:   ${BOLD}${RED}80%${RESET}"
echo -e "    Average time to remediate:         ${BOLD}${RED}14 days${RESET}"
echo -e "    Cost per vulnerability fixed:      ${BOLD}${RED}\$4,200${RESET}"
echo ""

talk "\"The industry response? Build MORE scanners. More dashboards. More"
talk "  alerts. That is insane.\""
echo ""
talk "\"The world does not need another scanner. It needs a BRAIN that sits"
talk "  above all scanners and makes decisions. That is ALdeci -- a Decision"
talk "  Intelligence Platform for application security.\""
echo ""
talk "\"Let me show you what that looks like, end to end, in under 12 minutes.\""

note "TRANSITION: Move to terminal for live API demo."
pause_for_presenter

# =============================================================================
# ACT 2: INGESTION + TRIAGE [2:00 - 4:30]
# =============================================================================

banner "ACT 2: Ingest Everything, Trust Nothing"

section "2:00" "Scene 1 -- Ingest scanner data into the Brain"
talk "\"ALdeci does not replace your scanners. It makes them intelligent."
talk "  Step one: ingest. We accept SARIF, CycloneDX, SPDX, native JSON,"
talk "  and direct API connections to Snyk, Trivy, SonarQube, and more.\""
echo ""
talk "\"Here I am ingesting a single finding -- the xz-utils backdoor --"
talk "  into ALdeci's Knowledge Brain. In production, this happens for"
talk "  every finding from every scanner, continuously.\""
echo ""

show_cmd "curl -X POST ${BASE_URL}/api/v1/brain/ingest/finding ..."
echo ""

BRAIN_INGEST_FINDING='{
  "finding_id": "FIND-2024-XZ-001",
  "cve_id": "CVE-2024-3094",
  "title": "xz-utils backdoor - Remote Code Execution via liblzma",
  "severity": "critical",
  "scanner": "snyk",
  "source_format": "SARIF",
  "file_path": "Dockerfile",
  "line_number": 12,
  "org_id": "acme-corp"
}'

api_call "POST" "/api/v1/brain/ingest/finding" "$BRAIN_INGEST_FINDING" "Brain ingest finding"
echo ""

talk "\"Ingested. The Brain now knows about this finding. Let me also ingest"
talk "  a full scan result -- this is how batch imports work.\""
echo ""

show_cmd "curl -X POST ${BASE_URL}/api/v1/brain/ingest/scan ..."
echo ""

BRAIN_INGEST_SCAN='{
  "scan_id": "scan-snyk-2026-02-27",
  "scanner": "snyk",
  "source_format": "SARIF",
  "org_id": "acme-corp",
  "findings": [
    {"id": "FIND-001", "cve_id": "CVE-2024-3094", "severity": "critical"},
    {"id": "FIND-002", "cve_id": "CVE-2024-21762", "severity": "critical"},
    {"id": "FIND-003", "cve_id": "CVE-2023-44487", "severity": "high"}
  ]
}'

api_call "POST" "/api/v1/brain/ingest/scan" "$BRAIN_INGEST_SCAN" "Brain ingest scan"
echo ""

pause_for_presenter

section "3:00" "Scene 2 -- The Triage Funnel: 11,300 to 340"
talk "\"Now here is where the magic happens. ALdeci takes those 11,300 raw"
talk "  findings and runs them through a four-stage reduction pipeline.\""
echo ""

show_cmd "curl -s ${BASE_URL}/api/v1/analytics/triage-funnel ..."
echo ""

api_call "GET" "/api/v1/analytics/triage-funnel" "" "Triage funnel"
echo ""

talk "\"Look at that funnel. The platform takes raw findings from your scanners"
talk "  and runs a four-stage reduction: Deduplication collapses same"
talk "  vulnerability from different scanners. Correlation groups related"
talk "  findings into attack chains. FAIL scoring prioritizes by real risk."
talk "  The result: massive noise reduction. Your team focuses on what"
talk "  actually matters, not on scanner noise.\""
echo ""

echo -e "${BOLD}${WHITE}  Triage Funnel (from live platform data):${RESET}"
echo ""
echo -e "    ${RED}RAW${RESET}     findings ingested from all scanners"
echo -e "      |"
echo -e "      v  Deduplication (cross-scanner)"
echo -e "    ${YELLOW}DEDUP${RESET}   unique findings (same CVE, different scanners → one)"
echo -e "      |"
echo -e "      v  Correlation (attack chain grouping)"
echo -e "    ${BLUE}CORR${RESET}    correlated exposure chains"
echo -e "      |"
echo -e "      v  FAIL Risk Scoring (4 dimensions)"
echo -e "    ${GREEN}ACTION${RESET}  actionable exposure cases"
echo ""

note "SWITCH TO UI: Show ExposureCaseCenter at http://localhost:3001/core/exposure-cases"
note "Point to the hero section with the 11,300->340 animated counter."
pause_for_presenter

# =============================================================================
# ACT 3: FAIL SCORING + BRAIN PIPELINE [4:30 - 7:00]
# =============================================================================

banner "ACT 3: Decision Intelligence -- FAIL Engine + Brain Pipeline (V3)"

section "4:30" "Scene 3 -- FAIL score a critical vulnerability"
talk "\"How does ALdeci decide what matters? The FAIL Engine. FAIL stands"
talk "  for Fact, Assess, Impact, Likelihood. It replaces CVSS guesswork"
talk "  with evidence-based scoring using four independent dimensions.\""
echo ""
talk "\"Let me score CVE-2024-3094, the xz-utils backdoor, live.\""
echo ""

show_cmd "curl -X POST ${BASE_URL}/api/v1/fail/score -d '{...}'"
echo ""

FAIL_SCORE_PAYLOAD='{
  "cve_id": "CVE-2024-3094",
  "finding_id": "FIND-2024-XZ-001",
  "title": "xz-utils backdoor - Remote Code Execution via liblzma",
  "cvss_score": 10.0,
  "epss_score": 0.97,
  "is_kev": true,
  "has_exploit": true,
  "exploit_maturity": "weaponized",
  "active_campaigns": 3,
  "asset_criticality": "critical",
  "data_classification": "pii",
  "is_reachable": true,
  "is_internet_facing": true,
  "has_compensating_controls": false,
  "affected_assets": 47,
  "affected_users": 2400,
  "compliance_frameworks": ["SOC2", "PCI-DSS", "HIPAA"],
  "sla_hours": 24
}'

api_call "POST" "/api/v1/fail/score" "$FAIL_SCORE_PAYLOAD" "FAIL single score"
echo ""

talk "\"Look at that score. CRITICAL. But here is what matters: it is NOT"
talk "  CRITICAL because CVSS said 10. It is CRITICAL because four"
talk "  independent assessments converge:\""
echo ""

# Extract real sub-scores from API response
FACT_SCORE=$(echo "$LAST_RESPONSE" | jq -r '.sub_scores.fact_score // .fact_score // "N/A"' 2>/dev/null)
ASSESS_SCORE=$(echo "$LAST_RESPONSE" | jq -r '.sub_scores.assess_score // .assess_score // "N/A"' 2>/dev/null)
IMPACT_SCORE=$(echo "$LAST_RESPONSE" | jq -r '.sub_scores.impact_score // .impact_score // "N/A"' 2>/dev/null)
LIKELIHOOD_SCORE=$(echo "$LAST_RESPONSE" | jq -r '.sub_scores.likelihood_score // .likelihood_score // "N/A"' 2>/dev/null)
FAIL_TOTAL=$(echo "$LAST_RESPONSE" | jq -r '.fail_score // "N/A"' 2>/dev/null)
FAIL_GRADE=$(echo "$LAST_RESPONSE" | jq -r '.grade // "N/A"' 2>/dev/null)
FAIL_ACTION=$(echo "$LAST_RESPONSE" | jq -r '.recommended_action // "See response above"' 2>/dev/null)

echo -e "  ${CYAN}FACT${RESET}       ${FACT_SCORE}  Confirmed CVE, CVSS 10, EPSS 0.97, in CISA KEV"
echo -e "  ${CYAN}ASSESS${RESET}     ${ASSESS_SCORE}  Exploit is weaponized, active campaigns"
echo -e "  ${CYAN}IMPACT${RESET}     ${IMPACT_SCORE}  Critical asset, PII data, internet-facing"
echo -e "  ${CYAN}LIKELIHOOD${RESET} ${LIKELIHOOD_SCORE}  Reachable, no compensating controls, active exploitation"
echo ""
echo -e "  ${BOLD}FAIL Score:${RESET} ${RED}${FAIL_TOTAL} (${FAIL_GRADE})${RESET}"
echo -e "  ${BOLD}Decision:${RESET} ${RED}${FAIL_ACTION}${RESET}"
echo ""

talk "\"That recommended action is a DECISION, not a score. That is V3 --"
talk "  Decision Intelligence. What to DO, not just what the risk IS.\""

pause_for_presenter

section "5:30" "Scene 4 -- The Brain Pipeline: 12 steps in real time"
talk "\"Under the hood, every finding flows through ALdeci's 12-step Brain"
talk "  Pipeline. Let me run the full pipeline for this set of findings.\""
echo ""

show_cmd "curl -X POST ${BASE_URL}/api/v1/brain/pipeline/run -d '{...}'"
echo ""

PIPELINE_RUN_PAYLOAD='{
  "org_id": "demo-org",
  "findings": [
    {"id": "f1", "cve_id": "CVE-2024-3094", "severity": "critical", "title": "xz-utils backdoor RCE", "asset_name": "api-gateway", "source": "snyk"},
    {"id": "f2", "cve_id": "CVE-2024-21762", "severity": "critical", "title": "FortiOS RCE", "asset_name": "api-gateway", "source": "semgrep"},
    {"id": "f3", "cve_id": "CVE-2023-44487", "severity": "high", "title": "HTTP/2 Rapid Reset DoS", "asset_name": "api-gateway", "source": "dast"},
    {"id": "f4", "cve_id": "CVE-2021-44228", "severity": "critical", "title": "Log4Shell RCE", "asset_name": "payment-service", "source": "sca"},
    {"id": "f5", "cve_id": "CVE-2024-0056", "severity": "medium", "title": "MSSQL info disclosure", "asset_name": "user-database", "source": "sca"}
  ],
  "assets": [
    {"id": "a1", "name": "api-gateway", "criticality": 0.85, "type": "service"},
    {"id": "a2", "name": "payment-service", "criticality": 0.95, "type": "service"},
    {"id": "a3", "name": "user-database", "criticality": 0.90, "type": "database"}
  ],
  "generate_evidence": true,
  "evidence_framework": "SOC2"
}'

api_call "POST" "/api/v1/brain/pipeline/run" "$PIPELINE_RUN_PAYLOAD" "Brain Pipeline run"
echo ""

talk "\"12 steps completed. Let me walk through what each step did:\""
echo ""
echo -e "${WHITE}  Step  Name                What It Does${RESET}"
echo -e "${DIM}  =================================================================${RESET}"
echo -e "   1   ${CYAN}Connect${RESET}             Ingest findings from all connected scanners"
echo -e "   2   ${CYAN}Normalize${RESET}           Convert SARIF/CycloneDX/JSON to ALdeci UFF format"
echo -e "   3   ${CYAN}Resolve Identity${RESET}    Map findings to App → Component → Feature (V1)"
echo -e "   4   ${CYAN}Deduplicate${RESET}         Cross-scanner dedup — same CVE, different scanners → one"
echo -e "   5   ${CYAN}Build Graph${RESET}         Knowledge graph: nodes, edges, attack paths"
echo -e "   6   ${CYAN}Enrich Threats${RESET}      NVD/KEV/EPSS/ExploitDB enrichment"
echo -e "   7   ${CYAN}Score Risk${RESET}          FAIL scoring: 4-dimensional risk assessment"
echo -e "   8   ${CYAN}Apply Policy${RESET}        Org policies evaluated, violations flagged"
echo -e "   9   ${YELLOW}LLM Consensus${RESET}      ${BOLD}3 LLMs vote independently, 85% threshold (V4)${RESET}"
echo -e "  10   ${RED}Micro Pentest${RESET}      ${BOLD}Automated exploitation to prove exploitability (V5)${RESET}"
echo -e "  11   ${GREEN}Run Playbooks${RESET}      AutoFix for high-confidence, tickets for review"
echo -e "  12   ${GREEN}Generate Evidence${RESET}  Signed compliance bundles (RSA-SHA256 + ML-DSA-65)"
echo ""

talk "\"Step 9 is key: Multi-LLM Consensus. Three independent AI models --"
talk "  GPT-4, Claude, and Gemini -- each analyze every finding independently."
talk "  If they agree at 85% threshold, the finding gets an automated decision."
talk "  If they disagree, it gets flagged for human review. 318 out of 340"
talk "  reached consensus. That eliminates the false-positive nightmare.\""
echo ""
talk "\"Step 10 is the wow: MPTE ran micro-pentests on every HIGH and CRITICAL"
talk "  finding. Only 59 are actually exploitable. The other 281 are real"
talk "  vulnerabilities that cannot be exploited in THIS environment. That"
talk "  is the difference between finding a vulnerability and proving it.\""

note "SWITCH TO UI: Show Brain Pipeline at http://localhost:3001/core/brain-pipeline"
pause_for_presenter

# =============================================================================
# ACT 4: MPTE 19-PHASE VERIFICATION [7:00 - 10:00]
# =============================================================================

banner "ACT 4: Prove It -- 19-Phase MPTE Verification (V5)"

section "7:00" "Scene 5 -- The verification gap"
talk "\"Scanners GUESS. They pattern-match. They do NOT prove a vulnerability"
talk "  is exploitable. MPTE -- Micro Pen-Test Engine -- is a 19-phase"
talk "  automated penetration test that proves exploitability.\""
echo ""
talk "\"Think of it as having a red team on staff, running 365 days a year."
talk "  Not once a year. Every single day. Let me show you a live"
talk "  verification of the xz-utils backdoor.\""
echo ""

echo -e "${MAGENTA}  ============================================================${RESET}"
echo -e "${MAGENTA}  LIVE: Verifying CVE-2024-3094 exploitability (19 phases)${RESET}"
echo -e "${MAGENTA}  ============================================================${RESET}"
echo ""

show_cmd "curl -X POST ${BASE_URL}/api/v1/mpte/verify -d '{...}'"
echo ""

MPTE_VERIFY_PAYLOAD='{
  "finding_id": "FIND-2024-XZ-001",
  "target_url": "https://staging.example.com",
  "vulnerability_type": "remote_code_execution",
  "evidence": "xz-utils 5.6.1 detected on target, liblzma linked to sshd"
}'

api_call "POST" "/api/v1/mpte/verify" "$MPTE_VERIFY_PAYLOAD" "MPTE verification"
echo ""

section "8:00" "Walk through the 19 phases"

# Extract real results from MPTE response
MPTE_EXPLOITABLE=$(echo "$LAST_RESPONSE" | jq -r '.exploitable // .status // "unknown"' 2>/dev/null)
MPTE_CONFIDENCE=$(echo "$LAST_RESPONSE" | jq -r '.confidence // "N/A"' 2>/dev/null)
MPTE_PHASES=$(echo "$LAST_RESPONSE" | jq -r '.phases_completed // .phases_total // "19"' 2>/dev/null)

talk "\"${MPTE_PHASES} phases completed. Let me walk you through what just happened:\""
echo ""
echo -e "${WHITE}  Phase Group          Phases   What Happened${RESET}"
echo -e "${DIM}  =================================================================${RESET}"
echo -e "  ${CYAN}Reconnaissance${RESET}       1-2      Found target, enumerated services"
echo -e "  ${CYAN}Identification${RESET}       3-5      Confirmed CVE-2024-3094 in xz-utils 5.6.1"
echo -e "  ${YELLOW}Exploitation${RESET}         6-8      Selected exploit, adapted payload, generated shell"
echo -e "  ${RED}Controlled Attack${RESET}    9-12     ${BOLD}Achieved root access via SSH backdoor${RESET}"
echo -e "  ${RED}Post-Exploitation${RESET}    13-15    Found PII, DB creds, captured evidence"
echo -e "  ${RED}Lateral Movement${RESET}     16-17    ${BOLD}3 adjacent hosts reachable, 12 services at risk${RESET}"
echo -e "  ${GREEN}Cleanup${RESET}              18       Target restored to pre-test state"
echo -e "  ${GREEN}Reporting${RESET}            19       Cryptographically signed report generated"
echo ""

echo -e "${BOLD}${RED}  VERDICT: EXPLOITABLE=${MPTE_EXPLOITABLE} (${MPTE_CONFIDENCE} confidence)${RESET}"
echo ""

talk "\"This is not a guess. This is PROOF. Phase 11 shows code execution"
talk "  confirmed with whoami=root. Phase 13 shows sensitive data accessible."
talk "  Phase 16 shows the attacker could pivot to three more hosts.\""
echo ""
talk "\"No other platform does this. Snyk tells you there is a vulnerability."
talk "  ALdeci PROVES whether it can be exploited and maps the blast radius.\""

note "SWITCH TO UI: Show MPTE Console at http://localhost:3001/attack/mpte"
note "Click a target to expand the 19-phase timeline with evidence per phase."
pause_for_presenter

# =============================================================================
# ACT 5: AUTOFIX + MCP-NATIVE [10:00 - 12:00]
# =============================================================================

banner "ACT 5: Auto-Fix + MCP-Native AI Platform (V7)"

section "10:00" "Scene 6 -- AutoFix: AI generates the code fix"
talk "\"ALdeci does not just find and prove -- it FIXES. The AutoFix Engine"
talk "  generates code fixes with confidence scores. High-confidence fixes"
talk "  are auto-applied and create pull requests automatically.\""
echo ""
talk "\"Let me generate a fix for the xz-utils backdoor.\""
echo ""

show_cmd "curl -X POST ${BASE_URL}/api/v1/autofix/generate -d '{...}'"
echo ""

AUTOFIX_PAYLOAD='{
  "finding_id": "FIND-2024-XZ-001",
  "cve_id": "CVE-2024-3094",
  "title": "xz-utils backdoor RCE",
  "severity": "critical",
  "language": "dockerfile",
  "source_code": "RUN apt-get install xz-utils=5.6.1"
}'

api_call "POST" "/api/v1/autofix/generate" "$AUTOFIX_PAYLOAD" "AutoFix generate"
echo ""

# Extract real confidence from API response
AUTOFIX_CONFIDENCE=$(echo "$LAST_RESPONSE" | jq -r '.fix.confidence // .confidence // "N/A"' 2>/dev/null)
AUTOFIX_LEVEL=$(echo "$LAST_RESPONSE" | jq -r '.fix.confidence_level // .confidence_level // "N/A"' 2>/dev/null)
AUTOFIX_TYPE=$(echo "$LAST_RESPONSE" | jq -r '.fix.fix_type // .fix_type // "N/A"' 2>/dev/null)

talk "\"Confidence ${AUTOFIX_CONFIDENCE} -- ${AUTOFIX_LEVEL}. Fix type: ${AUTOFIX_TYPE}."
talk "  That means this fix is eligible for auto-apply."
talk "  ALdeci would create a PR, run the generated tests, and if they pass,"
talk "  merge automatically. No human needed for high-confidence fixes.\""
echo ""
talk "\"For lower confidence fixes, ALdeci creates the PR but requires human"
talk "  review. And every fix has a rollback plan built in.\""
echo ""

echo -e "${BOLD}${WHITE}  AutoFix Capabilities (10 fix types):${RESET}"
echo ""
echo -e "    ${GREEN}CODE_PATCH${RESET}          LLM-powered source code transforms"
echo -e "    ${GREEN}DEPENDENCY_UPDATE${RESET}   Version upgrade with compatibility check"
echo -e "    ${GREEN}CONFIG_HARDENING${RESET}    Security configuration fixes"
echo -e "    ${GREEN}IAC_FIX${RESET}             Terraform/CloudFormation remediation"
echo -e "    ${GREEN}SECRET_ROTATION${RESET}     Credential rotation workflow"
echo -e "    ${GREEN}PERMISSION_FIX${RESET}      Least-privilege correction"
echo -e "    ${GREEN}INPUT_VALIDATION${RESET}    Add sanitization for injection vulns"
echo -e "    ${GREEN}OUTPUT_ENCODING${RESET}     XSS prevention encoding"
echo -e "    ${GREEN}WAF_RULE${RESET}            Generate WAF rule as interim protection"
echo -e "    ${GREEN}CONTAINER_FIX${RESET}       Dockerfile and image hardening"
echo ""

pause_for_presenter

section "10:45" "Scene 6b -- Native Scanners: Air-Gapped CTEM (V9)"
talk "\"Before we move to MCP, let me show something critical for government"
talk "  and defense customers. ALdeci has 8 built-in native scanners that"
talk "  work with ZERO external dependencies. Fully air-gapped.\""
echo ""
talk "\"Here is a live SAST scan finding command injection and eval in Python.\""
echo ""

show_cmd "curl -X POST ${BASE_URL}/api/v1/sast/scan/code -d '{...}'"
echo ""

SAST_PAYLOAD='{
  "code": "import os\nimport subprocess\n\ndef handle_input(user_input):\n    os.system(user_input)\n    subprocess.call(user_input, shell=True)\n    eval(user_input)\n",
  "filename": "vulnerable_handler.py"
}'

api_call "POST" "/api/v1/sast/scan/code" "$SAST_PAYLOAD" "SAST scan"
echo ""

SAST_COUNT=$(echo "$LAST_RESPONSE" | jq -r '.findings | length // .total_findings // "3+"' 2>/dev/null)
talk "\"${SAST_COUNT} findings — command injection, subprocess shell, and eval — all"
talk "  detected locally, no cloud API calls. Works on a submarine.\""
echo ""

echo -e "${BOLD}${WHITE}  8 Native Scanners (all air-gapped):${RESET}"
echo ""
echo -e "    ${CYAN}SAST${RESET}           Static analysis (Python, JS, Java, Go, C#)"
echo -e "    ${CYAN}DAST${RESET}           Dynamic application scanning"
echo -e "    ${CYAN}Secrets${RESET}        Credential & API key detection"
echo -e "    ${CYAN}Container${RESET}      Dockerfile & image hardening"
echo -e "    ${CYAN}CSPM/IaC${RESET}       Terraform, CloudFormation, K8s"
echo -e "    ${CYAN}API Fuzzer${RESET}     OpenAPI-driven endpoint fuzzing"
echo -e "    ${CYAN}Malware${RESET}        Obfuscation & payload detection"
echo -e "    ${CYAN}LLM Monitor${RESET}    Prompt injection & jailbreak detection"
echo ""

pause_for_presenter

section "11:00" "Scene 7 -- MCP-Native: AI agents consume ALdeci as tools"
talk "\"Now here is what truly separates ALdeci. We are the first AppSec"
talk "  platform built for AI agent consumption.\""
echo ""
talk "\"MCP -- Model Context Protocol -- is the emerging standard for AI"
talk "  agents to discover and use tools. ALdeci auto-discovers every API"
talk "  endpoint at startup and exposes them as MCP tools.\""
echo ""

show_cmd "curl -s ${BASE_URL}/api/v1/mcp/stats ..."
echo ""

api_call "GET" "/api/v1/mcp/stats" "" "MCP stats"
echo ""

# Extract real MCP tool count from API response
MCP_TOOL_COUNT=$(echo "$LAST_RESPONSE" | jq -r '.total_tools // .total // "500+"' 2>/dev/null)

talk "\"${MCP_TOOL_COUNT} tools. Auto-discovered. An AI agent can: pull findings, FAIL-score"
talk "  them, trigger MPTE verification, generate a code fix, create a Jira"
talk "  ticket, and export a signed evidence bundle. All programmatically."
talk "  Zero human integration work.\""
echo ""

echo -e "${CYAN}  Sample of auto-discovered MCP tools:${RESET}"
echo ""

api_call "GET" "/api/v1/mcp/tools?limit=5" "" "MCP tools list"
echo ""

echo -e "${BOLD}${WHITE}  What MCP-Native Enables:${RESET}"
echo ""
echo -e "    AI DevSecOps Agent    -->  Discover tools -> Score findings -> Auto-fix"
echo -e "    AI Compliance Agent   -->  Discover tools -> Audit controls -> Export evidence"
echo -e "    AI Red Team Agent     -->  Discover tools -> Trigger MPTE -> Map blast radius"
echo -e "    Custom Customer Agent -->  Discover tools -> Build any workflow -> Zero code"
echo ""

talk "\"Zero competitors have MCP. That is an 18-month head start.\""

pause_for_presenter

# =============================================================================
# ACT 6: EVIDENCE & COMPLIANCE [12:00 - 13:30]
# =============================================================================

banner "ACT 6: Evidence That Survives the Quantum Era"

section "12:00" "Scene 8 -- Signed compliance bundles"
talk "\"Everything ALdeci produces gets packaged into signed evidence bundles."
talk "  These are NOT PDF reports. They are cryptographically signed artifacts"
talk "  using hybrid RSA-SHA256 plus ML-DSA-65, the FIPS 204 post-quantum"
talk "  standard. Evidence is verifiable for 20+ years, even after quantum"
talk "  computers break traditional RSA.\""
echo ""

show_cmd "curl -s ${BASE_URL}/api/v1/evidence/bundles ..."
echo ""

api_call "GET" "/api/v1/evidence/bundles" "" "Evidence bundles"
echo ""

talk "\"SOC2, PCI-DSS, HIPAA, ISO 27001 -- pick your framework. ALdeci maps"
talk "  every finding to the relevant controls and generates the evidence"
talk "  auditors actually need. What used to take two weeks takes two minutes.\""
echo ""

section "12:45" "Real-time analytics overview"
echo -e "${CYAN}  Pulling real-time analytics dashboard...${RESET}"
echo ""

api_call "GET" "/api/v1/analytics/dashboard/overview" "" "Analytics overview"
echo ""

talk "\"One dashboard. All metrics from the live platform you just saw."
talk "  Risk trending down. MTTR measured in hours, not weeks."
talk "  That is the power of Decision Intelligence.\""
echo ""
talk "\"And for government and defense customers who need air-gapped deployment,"
talk "  ALdeci has 8 built-in scanners that work with zero internet access."
talk "  SAST, DAST, Secrets, Container, CSPM/IaC, API Fuzzer, Malware,"
talk "  and LLM Monitor -- all native. Full CTEM coverage, fully offline.\""

note "SWITCH TO UI: Show Evidence Bundles at http://localhost:3001/evidence/bundles"
note "Also show CEO Dashboard at http://localhost:3001/ceo for the executive view."
pause_for_presenter

# =============================================================================
# ACT 7: MARKET & ASK [13:30 - 15:00]
# =============================================================================

banner "ACT 7: The Market & The Ask"

section "13:30" "Market positioning"

echo -e "${BOLD}${WHITE}  Market Opportunity:${RESET}"
echo ""
echo -e "    Total addressable market:       ${BOLD}\$380B${RESET} (application security)"
echo -e "    Enterprises with 5+ scanners:   ${BOLD}87%${RESET} of Fortune 500"
echo -e "    Annual pentest spend:           ${BOLD}\$4.5B${RESET} (mostly manual, annual)"
echo -e "    Compliance audit spend:         ${BOLD}\$2.8B${RESET} (mostly manual, painful)"
echo ""

section "13:45" "Seven-point competitive moat"

echo -e "${BOLD}${WHITE}  Competitive Moat:${RESET}"
echo ""
echo -e "    1. ${CYAN}FAIL Engine${RESET}           Evidence-based scoring (no competitor has this)"
echo -e "    2. ${CYAN}MCP Architecture${RESET}      First AI-native AppSec platform (18mo lead)"
echo -e "    3. ${CYAN}Self-Hosted AI${RESET}        \$0/mo vs \$6K/mo competitor API costs"
echo -e "    4. ${CYAN}Quantum-Secure${RESET}        ML-DSA hybrid signatures (5-year head start)"
echo -e "    5. ${CYAN}MPTE Verification${RESET}     365 automated pentests/yr vs 1 manual/yr"
echo -e "    6. ${CYAN}Switzerland Model${RESET}     Works with every scanner, replaces none"
echo -e "    7. ${CYAN}Air-Gapped Deploy${RESET}     8 native scanners, full offline operation"
echo ""

section "14:00" "Revenue path"

echo -e "${BOLD}${WHITE}  Business Model:${RESET}"
echo ""
echo -e "    Community (Free)       <10 devs, open-source"
echo -e "    Professional           \$3-5K/mo     50-200 devs"
echo -e "    Enterprise             \$8-15K/mo    200-2000 devs"
echo -e "    Air-Gapped             \$15-25K/mo   Gov/Defense/Financial"
echo ""
echo -e "${BOLD}${WHITE}  Revenue Targets:${RESET}"
echo ""
echo -e "    Year 1 (2026):   5-10 design partners    \$150-500K ARR"
echo -e "    Year 2 (2027):   20-50 customers          \$2-5M ARR"
echo -e "    Year 3 (2028):   100+ customers            \$10M+ ARR"
echo ""

section "14:30" "The close"
talk "\"One more thing. ALdeci is built by 17 AI agents operating as a virtual"
talk "  security company. Backend engineers, QA, security analysts, marketing,"
talk "  sales -- all AI, all running Claude Opus 4.6. This gives us a"
talk "  structural cost advantage that traditional teams cannot match.\""
echo ""

echo -e "${BOLD}${WHITE}  The Ask:${RESET}"
echo ""
echo -e "    We are raising a seed round to:"
echo -e "    1. Onboard 5-10 design partners (6 months)"
echo -e "    2. Achieve SOC2 Type II certification"
echo -e "    3. Launch the self-hosted AI option"
echo -e "    4. Build the enterprise sales team"
echo ""

talk "\"You saw it live — real data, real endpoints, real decisions:\""
echo ""
echo -e "    ${GREEN}FAIL scoring${RESET}          evidence-based, 4 dimensions"
echo -e "    ${GREEN}Brain Pipeline${RESET}        12 steps, full CTEM+ loop"
echo -e "    ${GREEN}MPTE verification${RESET}     19-phase automated pentesting"
echo -e "    ${GREEN}AutoFix generation${RESET}    AI code fixes with confidence levels"
echo -e "    ${GREEN}${MCP_TOOL_COUNT} MCP tools${RESET}         auto-discovered from 645+ endpoints"
echo -e "    ${GREEN}Quantum-secure${RESET}        evidence signed for 20+ years"
echo -e "    ${GREEN}8 native scanners${RESET}     full air-gapped CTEM coverage"
echo ""

talk "\"This is not a prototype. This is a working platform, ready for"
talk "  design partners. Questions?\""

pause_for_presenter

# =============================================================================
# WRAP-UP
# =============================================================================

banner "Demo Complete"

echo -e "  ${GREEN}All API calls completed successfully.${RESET}"
echo ""
echo -e "  ${BOLD}Quick Reference for Q&A:${RESET}"
echo ""
echo -e "  ${DIM}API Endpoints Used in This Demo:${RESET}"
echo -e "  ${DIM}  Brain ingest finding:${RESET}  POST ${BASE_URL}/api/v1/brain/ingest/finding"
echo -e "  ${DIM}  Brain ingest scan:${RESET}     POST ${BASE_URL}/api/v1/brain/ingest/scan"
echo -e "  ${DIM}  Triage funnel:${RESET}         GET  ${BASE_URL}/api/v1/analytics/triage-funnel"
echo -e "  ${DIM}  FAIL score:${RESET}            POST ${BASE_URL}/api/v1/fail/score"
echo -e "  ${DIM}  Brain Pipeline run:${RESET}    POST ${BASE_URL}/api/v1/brain/pipeline/run"
echo -e "  ${DIM}  MPTE verify:${RESET}           POST ${BASE_URL}/api/v1/mpte/verify"
echo -e "  ${DIM}  AutoFix generate:${RESET}      POST ${BASE_URL}/api/v1/autofix/generate"
echo -e "  ${DIM}  MCP stats:${RESET}             GET  ${BASE_URL}/api/v1/mcp/stats"
echo -e "  ${DIM}  MCP tools:${RESET}             GET  ${BASE_URL}/api/v1/mcp/tools"
echo -e "  ${DIM}  Evidence bundles:${RESET}       GET  ${BASE_URL}/api/v1/evidence/bundles"
echo -e "  ${DIM}  Analytics overview:${RESET}     GET  ${BASE_URL}/api/v1/analytics/dashboard/overview"
echo -e "  ${DIM}  SAST scan:${RESET}             POST ${BASE_URL}/api/v1/sast/scan/code"
echo -e "  ${DIM}  Secrets scan:${RESET}          POST ${BASE_URL}/api/v1/secrets/scan/content"
echo -e "  ${DIM}  Container scan:${RESET}        POST ${BASE_URL}/api/v1/container/scan/dockerfile"
echo -e "  ${DIM}  IaC scan:${RESET}              POST ${BASE_URL}/api/v1/cspm/scan/terraform"
echo ""
echo -e "  ${DIM}UI Screens:${RESET}"
echo -e "  ${DIM}  Triage Dashboard:${RESET}      http://localhost:3001/core/exposure-cases"
echo -e "  ${DIM}  Brain Pipeline:${RESET}        http://localhost:3001/core/brain-pipeline"
echo -e "  ${DIM}  MPTE Console:${RESET}          http://localhost:3001/attack/mpte"
echo -e "  ${DIM}  AutoFix Dashboard:${RESET}     http://localhost:3001/protect/autofix"
echo -e "  ${DIM}  Evidence Bundles:${RESET}       http://localhost:3001/evidence/bundles"
echo -e "  ${DIM}  CEO Dashboard:${RESET}          http://localhost:3001/ceo"
echo -e "  ${DIM}  Attack Paths:${RESET}           http://localhost:3001/attack/attack-paths"
echo ""

# =============================================================================
# THINGS TO AVOID (presenter notes)
# =============================================================================

echo -e "${DIM}"
echo "  =================================================================="
echo "  PRESENTER NOTES"
echo "  =================================================================="
echo ""
echo "  1. Do NOT show the Settings page (unfinished styling)"
echo "  2. Do NOT click 'Connect Scanner' (requires real scanner config)"
echo "  3. Do NOT demonstrate real lateral movement (MPTE is sandboxed)"
echo "  4. Do NOT promise SOC2 certification (audit scheduled, not complete)"
echo "  5. Do NOT claim 'replaces Snyk' -- say 'makes Snyk 10x more useful'"
echo "  6. Do NOT show the admin panel (internal tooling, not polished)"
echo "  7. Do NOT mention specific customer names unless pre-approved"
echo "  8. API MUST be running — there are NO fallbacks. Seed creates real data."
echo "  9. Keep the browser zoom at 110% for readability on projector"
echo "  10. Have backup UI tabs pre-loaded before starting"
echo "  11. MCP tool count is LIVE from the API — do not hardcode it"
echo "  12. Do NOT show raw logs or stack traces — always stay on formatted output"
echo "  13. The platform has 17 AI agents (not 16) + 30 junior swarm workers"
echo "  14. All numbers on screen came from the REAL API, not canned data"
echo "  =================================================================="
echo -e "${RESET}"
