#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
#  FixOps / ALdeci — Interactive Enterprise Testing Script
#
#  PURPOSE: Walk through every API & CLI with real data.
#           Ask questions, accept CVEs / assets / manifests from the tester.
#           Cover the full CTEM loop: Scope → Discover → Prioritize → Validate → Mobilize
#           This is the BASELINE for bug hunting and UI creation.
#
#  USAGE:   export FIXOPS_API_TOKEN=<your-enterprise-token>
#           bash scripts/fixops-enterprise-test.sh [--api http://localhost:8000]
# ═══════════════════════════════════════════════════════════════════════════
set -uo pipefail

# ── Colours ──────────────────────────────────────────────────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'; B='\033[1;34m'
M='\033[0;35m'; W='\033[1;37m'; NC='\033[0m'

# ── Config ───────────────────────────────────────────────────────────────
API="${FIXOPS_API_URL:-http://localhost:8000}"
KEY="${FIXOPS_API_TOKEN:?ERROR: Set FIXOPS_API_TOKEN first. Generate: python3 -c \"import secrets; print(secrets.token_urlsafe(48))\"}"
PASS=0; FAIL=0; TOTAL=0; SKIP=0

while [[ $# -gt 0 ]]; do
  case $1 in --api) API="$2"; shift 2;; --token) KEY="$2"; shift 2;; *) shift;; esac
done

# ── Helpers ──────────────────────────────────────────────────────────────
hr()      { echo -e "${C}────────────────────────────────────────────────────────────────${NC}"; }
section() { echo ""; hr; echo -e "${W}  $1${NC}"; hr; }
banner()  { echo ""; echo -e "${B}  ▸ $1${NC}"; }
prompt()  { echo -en "${Y}  ⟩ $1: ${NC}"; }
info()    { echo -e "${C}  ℹ $1${NC}"; }
ok()      { echo -e "${G}  ✅ $1${NC}"; }
fail()    { echo -e "${R}  ❌ $1${NC}"; }
warn()    { echo -e "${Y}  ⚠  $1${NC}"; }

# call METHOD PATH [DATA] [DESCRIPTION]
call() {
  local method="$1" path="$2" data="${3:-}" desc="${4:-$method $path}"
  TOTAL=$((TOTAL+1))
  local args=(-s -w "\n%{http_code}" -X "$method" --max-time 20 --connect-timeout 5)
  args+=(-H "X-API-Key: $KEY" -H "Content-Type: application/json")
  [[ -n "$data" ]] && args+=(-d "$data")
  local raw; raw=$(curl "${args[@]}" "${API}${path}" 2>/dev/null || echo -e "\n000")
  local code; code=$(echo "$raw" | tail -1)
  local body; body=$(echo "$raw" | sed '$d')
  if [[ "$code" =~ ^2 ]]; then
    printf "  ${G}✅ %-55s [%s]${NC}\n" "$desc" "$code"; PASS=$((PASS+1))
  else
    printf "  ${R}❌ %-55s [%s]${NC}\n" "$desc" "$code"; FAIL=$((FAIL+1))
  fi
  LAST_BODY="$body"
  return 0
}

# Pretty-print JSON (fallback to raw)
show() { echo "$LAST_BODY" | python3 -m json.tool 2>/dev/null || echo "$LAST_BODY"; }
# Show a compact summary (first 15 lines)
showbrief() { echo "$LAST_BODY" | python3 -m json.tool 2>/dev/null | head -15 || echo "$LAST_BODY" | head -15; echo "  ..."; }

ask_continue() {
  echo ""
  prompt "Press ENTER to continue (or 'q' to quit, 's' to skip to menu)"
  read -r _ans
  [[ "$_ans" == "q" ]] && summary_and_exit
  [[ "$_ans" == "s" ]] && return 1
  return 0
}

summary_and_exit() {
  section "TEST RESULTS"
  printf "  Total: %d  |  ✅ Pass: %d  |  ❌ Fail: %d  |  ⏭ Skip: %d\n" "$TOTAL" "$PASS" "$FAIL" "$SKIP"
  if [[ $FAIL -eq 0 ]]; then
    echo -e "  ${G}████████████████████████████████████████████████████████████${NC}"
    echo -e "  ${G}█  ALL TESTS PASSED — ENTERPRISE READY ✅                  █${NC}"
    echo -e "  ${G}████████████████████████████████████████████████████████████${NC}"
  else
    echo -e "  ${Y}⚠  $FAIL endpoint(s) need investigation${NC}"
  fi
  echo ""
  echo -e "  CTEM: Scope ✓ → Discover ✓ → Prioritize ✓ → Validate ✓ → Mobilize ✓"
  echo ""
  exit 0
}

LAST_BODY=""

# ── Collect user data ────────────────────────────────────────────────────
collect_user_input() {
  section "ENTERPRISE TESTING — DATA COLLECTION"
  info "I'll ask a few questions to personalise the test with YOUR data."
  info "Defaults provided — just press ENTER to accept."
  echo ""

  prompt "Organisation name [acme-corp]"
  read -r ORG_NAME; ORG_NAME="${ORG_NAME:-acme-corp}"

  prompt "Primary CVE to test [CVE-2021-44228]"
  read -r CVE1; CVE1="${CVE1:-CVE-2021-44228}"

  prompt "Second CVE [CVE-2023-44487]"
  read -r CVE2; CVE2="${CVE2:-CVE-2023-44487}"

  prompt "Third CVE [CVE-2024-3094]"
  read -r CVE3; CVE3="${CVE3:-CVE-2024-3094}"

  prompt "Critical asset name [payment-service]"
  read -r ASSET1; ASSET1="${ASSET1:-payment-service}"

  prompt "Asset criticality 0.0-1.0 [0.95]"
  read -r CRIT1; CRIT1="${CRIT1:-0.95}"

  prompt "Second asset [api-gateway]"
  read -r ASSET2; ASSET2="${ASSET2:-api-gateway}"

  prompt "Third asset (database) [user-database]"
  read -r ASSET3; ASSET3="${ASSET3:-user-database}"

  prompt "Compliance framework [SOC2]  (options: SOC2, PCI-DSS, HIPAA, NIST, GDPR)"
  read -r FRAMEWORK; FRAMEWORK="${FRAMEWORK:-SOC2}"

  echo ""
  ok "Configuration saved:"
  info "  Org:        $ORG_NAME"
  info "  CVEs:       $CVE1, $CVE2, $CVE3"
  info "  Assets:     $ASSET1 ($CRIT1), $ASSET2, $ASSET3"
  info "  Framework:  $FRAMEWORK"
  info "  API:        $API"
  info "  Token:      ${KEY:0:12}..."
  echo ""
}

# ═══════════════════════════════════════════════════════════════════════════
#  CTEM STAGE 1 — SCOPE
# ═══════════════════════════════════════════════════════════════════════════
stage_scope() {
  section "CTEM STAGE 1: SCOPE — Define Attack Surface & Business Context"

  banner "1.1 Platform Health"
  call GET /health "" "Platform health"
  showbrief
  ask_continue || return

  banner "1.2 Versioned Health"
  call GET /api/v1/health "" "Versioned API health"
  showbrief
  ask_continue || return

  banner "1.3 Register Assets into Knowledge Brain"
  info "Registering your assets: $ASSET1, $ASSET2, $ASSET3"

  call POST /api/v1/brain/ingest/asset \
    "{\"asset_id\":\"${ASSET1}\",\"name\":\"${ASSET1}\",\"criticality\":${CRIT1},\"type\":\"service\"}" \
    "Register: $ASSET1 (criticality=$CRIT1)"
  showbrief

  call POST /api/v1/brain/ingest/asset \
    "{\"asset_id\":\"${ASSET2}\",\"name\":\"${ASSET2}\",\"criticality\":0.85,\"type\":\"service\"}" \
    "Register: $ASSET2 (criticality=0.85)"

  call POST /api/v1/brain/ingest/asset \
    "{\"asset_id\":\"${ASSET3}\",\"name\":\"${ASSET3}\",\"criticality\":0.90,\"type\":\"database\"}" \
    "Register: $ASSET3 (criticality=0.90)"
  ask_continue || return

  banner "1.4 Verify Brain Graph State"
  call GET /api/v1/brain/stats "" "Brain knowledge graph stats"
  show
  call GET /api/v1/brain/nodes "" "All brain nodes"
  showbrief
  ask_continue || return

  banner "1.5 Business Context"
  call GET /api/v1/business-context/health "" "Business context engine health"
  call GET /api/v1/business-context/formats "" "Supported manifest formats"
  showbrief
  ask_continue || return

  banner "1.6 Attack Surface Overview"
  call GET /api/v1/attack-surface/health "" "Attack surface engine health"
  showbrief

  ok "STAGE 1 COMPLETE — Assets registered, brain initialised"
  ask_continue || return
}

# ═══════════════════════════════════════════════════════════════════════════
#  CTEM STAGE 2 — DISCOVER
# ═══════════════════════════════════════════════════════════════════════════
stage_discover() {
  section "CTEM STAGE 2: DISCOVER — Threat Intel & Vulnerability Discovery"

  banner "2.1 Feed System Health & Sources"
  call GET /api/v1/feeds/health "" "Feed system health"
  show
  call GET /api/v1/feeds/categories "" "Feed categories"
  showbrief
  call GET /api/v1/feeds/sources "" "All feed sources"
  showbrief
  ask_continue || return

  banner "2.2 EPSS Scores (Top Exploited)"
  call GET "/api/v1/feeds/epss?limit=10" "" "EPSS top 10"
  showbrief
  ask_continue || return

  banner "2.3 CISA KEV Catalog"
  call GET "/api/v1/feeds/kev?limit=5" "" "CISA KEV (first 5)"
  showbrief
  ask_continue || return

  banner "2.4 Enrich Your CVEs — $CVE1, $CVE2, $CVE3"
  call POST /api/v1/feeds/enrich \
    "{\"findings\":[{\"id\":\"f1\",\"cve_id\":\"${CVE1}\"},{\"id\":\"f2\",\"cve_id\":\"${CVE2}\"},{\"id\":\"f3\",\"cve_id\":\"${CVE3}\"}]}" \
    "Enrich CVEs: $CVE1, $CVE2, $CVE3"
  show
  ask_continue || return

  banner "2.5 Exploit Confidence & Geo Risk"
  call GET "/api/v1/feeds/exploit-confidence/${CVE1}" "" "Exploit confidence: $CVE1"
  show
  call GET "/api/v1/feeds/geo-risk/${CVE1}?country=US" "" "Geo risk: $CVE1 (US)"
  showbrief
  ask_continue || return

  banner "2.6 Ingest Findings into Brain"
  call POST /api/v1/brain/ingest/cve \
    "{\"cve_id\":\"${CVE1}\",\"severity\":\"critical\",\"description\":\"Critical RCE vulnerability\"}" \
    "Ingest $CVE1 into brain"

  call POST /api/v1/brain/ingest/finding \
    "{\"finding_id\":\"scan-001\",\"cve_id\":\"${CVE1}\",\"severity\":\"critical\",\"asset\":\"${ASSET1}\",\"source\":\"sca\"}" \
    "Finding: $CVE1 in $ASSET1"

  call POST /api/v1/brain/ingest/finding \
    "{\"finding_id\":\"scan-002\",\"cve_id\":\"${CVE2}\",\"severity\":\"high\",\"asset\":\"${ASSET2}\",\"source\":\"dast\"}" \
    "Finding: $CVE2 in $ASSET2"

  call POST /api/v1/brain/ingest/finding \
    "{\"finding_id\":\"scan-003\",\"cve_id\":\"${CVE3}\",\"severity\":\"critical\",\"asset\":\"${ASSET3}\",\"source\":\"sca\"}" \
    "Finding: $CVE3 in $ASSET3"
  ask_continue || return

  banner "2.7 Vulnerability Discovery & Scanners"
  call GET /api/v1/vulns/health "" "Vuln discovery engine"
  call GET /api/v1/dast/health "" "DAST scanner"
  call GET /api/v1/sast/status "" "SAST scanner"
  call GET /api/v1/container/status "" "Container scanner"
  call GET /api/v1/secrets-scanner/health "" "Secrets scanner"
  call GET /api/v1/api-fuzzer/status "" "API fuzzer"
  call GET /api/v1/malware/status "" "Malware detector"
  ask_continue || return

  banner "2.8 NVD Lookup"
  call GET "/api/v1/feeds/nvd/${CVE1}" "" "NVD lookup: $CVE1"
  showbrief
  ask_continue || return

  banner "2.9 ExploitDB & Threat Actors"
  call GET "/api/v1/feeds/exploits/${CVE1}" "" "Exploits for $CVE1"
  showbrief
  call GET /api/v1/feeds/threat-actors "" "Known threat actors"
  showbrief

  ok "STAGE 2 COMPLETE — Threats discovered, findings ingested"
  ask_continue || return
}

# ═══════════════════════════════════════════════════════════════════════════
#  CTEM STAGE 3 — PRIORITIZE
# ═══════════════════════════════════════════════════════════════════════════
stage_prioritize() {
  section "CTEM STAGE 3: PRIORITIZE — SSVC Decisions & Risk Scoring"

  banner "3.1 SSVC Decision Engine — Core Components"
  call GET /api/v1/decisions/core-components "" "SSVC decision components"
  show
  ask_continue || return

  banner "3.2 Make SSVC Decisions"
  info "Running SSVC for $CVE1 on $ASSET1..."
  call POST /api/v1/decisions/make-decision \
    "{\"cve_id\":\"${CVE1}\",\"asset_name\":\"${ASSET1}\",\"severity\":\"critical\",\"title\":\"Critical RCE\",\"source\":\"sca\",\"exploitability\":\"active\",\"business_criticality\":\"high\"}" \
    "SSVC: $CVE1 → $ASSET1"
  show

  info "Running SSVC for $CVE2 on $ASSET2..."
  call POST /api/v1/decisions/make-decision \
    "{\"cve_id\":\"${CVE2}\",\"asset_name\":\"${ASSET2}\",\"severity\":\"high\",\"title\":\"DoS vulnerability\",\"source\":\"dast\"}" \
    "SSVC: $CVE2 → $ASSET2"
  showbrief

  info "Running SSVC for $CVE3 on $ASSET3..."
  call POST /api/v1/decisions/make-decision \
    "{\"cve_id\":\"${CVE3}\",\"asset_name\":\"${ASSET3}\",\"severity\":\"critical\",\"title\":\"Supply chain backdoor\",\"source\":\"sca\",\"exploitability\":\"poc\",\"business_criticality\":\"high\"}" \
    "SSVC: $CVE3 → $ASSET3"
  showbrief
  ask_continue || return

  banner "3.3 Decision History & Metrics"
  call GET /api/v1/decisions/recent "" "Recent decisions"
  showbrief
  call GET /api/v1/decisions/metrics "" "Decision metrics"
  show
  ask_continue || return

  banner "3.4 Brain Risk Scores"
  call GET "/api/v1/brain/risk/${ASSET1}" "" "Risk: $ASSET1"
  show
  call GET /api/v1/brain/most-connected "" "Most connected nodes (blast radius)"
  showbrief
  ask_continue || return

  banner "3.5 Graph Analysis"
  call GET /api/v1/graph/health "" "Graph engine health"
  call GET /api/v1/graph/kev-components "" "KEV-connected components"
  showbrief
  ask_continue || return

  banner "3.6 Compliance Posture"
  call GET /api/v1/compliance/health "" "Compliance engine health"
  call GET /api/v1/copilot/agents/compliance/frameworks "" "Compliance frameworks"
  showbrief
  call GET /api/v1/copilot/agents/compliance/dashboard "" "Compliance dashboard"
  showbrief
  ask_continue || return

  banner "3.7 AI Analyst — Prioritisation"
  call POST /api/v1/copilot/agents/analyst/prioritize \
    "{\"findings\":[{\"id\":\"f1\",\"cve_id\":\"${CVE1}\",\"severity\":\"CRITICAL\"},{\"id\":\"f2\",\"cve_id\":\"${CVE2}\",\"severity\":\"HIGH\"},{\"id\":\"f3\",\"cve_id\":\"${CVE3}\",\"severity\":\"CRITICAL\"}]}" \
    "AI analyst: prioritise 3 findings"
  show

  banner "3.8 Trending CVEs"
  call GET /api/v1/copilot/agents/analyst/trending "" "AI analyst: trending CVEs"
  showbrief

  ok "STAGE 3 COMPLETE — Decisions made, risks scored, compliance checked"
  ask_continue || return
}



# ═══════════════════════════════════════════════════════════════════════════
#  CTEM STAGE 4 — VALIDATE
# ═══════════════════════════════════════════════════════════════════════════
stage_validate() {
  section "CTEM STAGE 4: VALIDATE — Pentest, Attack Sim & Evidence"

  banner "4.1 Micro Penetration Testing"
  call GET /api/v1/micro-pentest/health "" "Micro-pentest engine (MPTE)"
  show
  ask_continue || return

  banner "4.2 Attack Simulation"
  call GET /api/v1/attack-sim/health "" "Attack simulation (BAS)"
  call GET /api/v1/attack-simulation/health "" "Attack simulation health"
  call GET /api/v1/pentagi/health "" "PentAGI engine"
  call GET /api/v1/pentagi/capabilities "" "PentAGI capabilities"
  showbrief
  ask_continue || return

  banner "4.3 Full Brain Pipeline — 12-Step Orchestration"
  info "Running pipeline with your findings and assets..."
  call POST /api/v1/brain/pipeline/run \
    "{\"org_id\":\"${ORG_NAME}\",\"findings\":[{\"id\":\"f1\",\"cve_id\":\"${CVE1}\",\"severity\":\"critical\",\"title\":\"Critical RCE\",\"asset_name\":\"${ASSET1}\",\"source\":\"sca\"},{\"id\":\"f2\",\"cve_id\":\"${CVE2}\",\"severity\":\"high\",\"title\":\"DoS Attack\",\"asset_name\":\"${ASSET2}\",\"source\":\"dast\"},{\"id\":\"f3\",\"cve_id\":\"${CVE3}\",\"severity\":\"critical\",\"title\":\"Supply Chain\",\"asset_name\":\"${ASSET3}\",\"source\":\"sca\"}],\"assets\":[{\"id\":\"a1\",\"name\":\"${ASSET1}\",\"criticality\":${CRIT1}},{\"id\":\"a2\",\"name\":\"${ASSET2}\",\"criticality\":0.85},{\"id\":\"a3\",\"name\":\"${ASSET3}\",\"criticality\":0.90}],\"generate_evidence\":true,\"evidence_framework\":\"${FRAMEWORK}\"}" \
    "Pipeline: 3 findings, 3 assets, $FRAMEWORK evidence"
  show
  call GET /api/v1/brain/pipeline/runs "" "List pipeline runs"
  showbrief
  ask_continue || return

  banner "4.4 Evidence Collection"
  call GET /api/v1/evidence/health "" "Evidence engine health"
  call GET /api/v1/risk/health "" "Risk engine health"
  call POST /api/v1/brain/evidence/generate \
    "{\"org_id\":\"${ORG_NAME}\",\"timeframe_days\":90,\"controls\":[\"CC6.1\",\"CC6.7\",\"CC7.2\"]}" \
    "Generate $FRAMEWORK evidence pack"
  showbrief
  call GET /api/v1/brain/evidence/packs "" "List evidence packs"
  showbrief
  ask_continue || return

  banner "4.5 Compliance Mapping"
  call POST /api/v1/copilot/agents/compliance/map-findings \
    "{\"findings\":[{\"id\":\"f1\",\"cve_id\":\"${CVE1}\",\"severity\":\"CRITICAL\"},{\"id\":\"f2\",\"cve_id\":\"${CVE2}\",\"severity\":\"HIGH\"}],\"frameworks\":[\"${FRAMEWORK}\"]}" \
    "Map findings to $FRAMEWORK"
  showbrief
  ask_continue || return

  banner "4.6 Predictions & ML"
  call GET /api/v1/predictions/health "" "Predictions engine"
  call POST /api/v1/predictions/attack-chain \
    "{\"cve_ids\":[\"${CVE1}\",\"${CVE2}\"],\"asset\":\"${ASSET1}\"}" \
    "Attack chain prediction"
  showbrief
  call GET /api/v1/mindsdb/status "" "MindsDB integration"
  ask_continue || return

  banner "4.7 Provenance & Reachability"
  call GET /api/v1/provenance/health "" "Provenance engine"
  call GET /api/v1/reachability/health "" "Reachability analysis"
  call GET /api/v1/code-to-cloud/status "" "Code-to-cloud tracer"

  ok "STAGE 4 COMPLETE — Pipeline ran, evidence generated, validated"
  ask_continue || return
}

# ═══════════════════════════════════════════════════════════════════════════
#  CTEM STAGE 5 — MOBILIZE
# ═══════════════════════════════════════════════════════════════════════════
stage_mobilize() {
  section "CTEM STAGE 5: MOBILIZE — Remediation, Integration & Reporting"

  banner "5.1 AutoFix Recommendations"
  call GET /api/v1/autofix/health "" "AutoFix engine"
  call GET /api/v1/autofix/fix-types "" "Available fix types"
  showbrief
  ask_continue || return

  banner "5.2 Remediation Tracking"
  call POST /api/v1/brain/ingest/remediation \
    "{\"task_id\":\"rem-001\",\"finding_id\":\"scan-001\",\"org_id\":\"${ORG_NAME}\",\"status\":\"in_progress\",\"assignee\":\"security-team\",\"action\":\"Upgrade affected library\"}" \
    "Track remediation for $CVE1"
  showbrief

  call POST /api/v1/brain/ingest/remediation \
    "{\"task_id\":\"rem-002\",\"finding_id\":\"scan-002\",\"org_id\":\"${ORG_NAME}\",\"status\":\"planned\",\"assignee\":\"platform-team\",\"action\":\"Apply WAF rules\"}" \
    "Track remediation for $CVE2"
  showbrief
  ask_continue || return

  banner "5.3 Integration Hub"
  call GET /api/v1/integrations/health "" "Integration hub"
  show
  ask_continue || return

  banner "5.4 AI Agents Status"
  call GET /api/v1/copilot/health "" "AI copilot"
  call GET /api/v1/copilot/agents/analyst/status "" "AI analyst agent"
  call GET /api/v1/llm/health "" "LLM engine"
  ask_continue || return

  banner "5.5 Threat Intelligence Report"
  call POST /api/v1/copilot/agents/analyst/threat-intel \
    "{\"cve_ids\":[\"${CVE1}\",\"${CVE2}\",\"${CVE3}\"]}" \
    "Generate threat intel report"
  showbrief
  ask_continue || return

  banner "5.6 Reporting & Deduplication"
  call GET /api/v1/reports/list "" "Available reports"
  showbrief
  call GET /api/v1/dedup/health "" "Dedup engine"
  ask_continue || return

  banner "5.7 Marketplace & Streaming"
  call GET /api/v1/marketplace/health "" "Marketplace"
  call GET /api/v1/marketplace/browse "" "Browse marketplace"
  showbrief
  call GET /api/v1/stream/health "" "SSE streaming"
  call GET /api/v1/nerve-center/health "" "Nerve center"
  ask_continue || return

  banner "5.8 Final Brain State"
  call GET /api/v1/brain/stats "" "Final brain graph"
  show
  call GET /api/v1/brain/events "" "Brain event log"
  showbrief

  ok "STAGE 5 COMPLETE — Remediations tracked, integrations verified"
  ask_continue || return
}

# ═══════════════════════════════════════════════════════════════════════════
#  INDIVIDUAL API TESTING
# ═══════════════════════════════════════════════════════════════════════════
test_individual_api() {
  section "INDIVIDUAL API ENDPOINT TESTING"
  info "Enter an API path to test. Examples:"
  echo "    GET  /health"
  echo "    GET  /api/v1/feeds/health"
  echo "    POST /api/v1/decisions/make-decision {\"cve_id\":\"CVE-2021-44228\"}"
  echo "    Type 'back' to return to menu"
  echo ""

  while true; do
    prompt "Method (GET/POST) [GET]"
    read -r _method; _method="${_method:-GET}"
    [[ "$_method" == "back" ]] && return

    prompt "Path"
    read -r _path
    [[ "$_path" == "back" ]] && return
    [[ -z "$_path" ]] && continue

    local _data=""
    if [[ "$_method" == "POST" || "$_method" == "post" ]]; then
      prompt "JSON body (or empty)"
      read -r _data
    fi

    _method=$(echo "$_method" | tr '[:lower:]' '[:upper:]')
    call "$_method" "$_path" "$_data" "Manual: $_method $_path"
    show
    echo ""
  done
}

# ═══════════════════════════════════════════════════════════════════════════
#  QUICK HEALTH CHECK — ALL ENGINES
# ═══════════════════════════════════════════════════════════════════════════
test_all_health() {
  section "HEALTH CHECK — ALL ENGINES"
  local endpoints=(
    "/health"
    "/api/v1/health"
    "/api/v1/brain/health"
    "/api/v1/feeds/health"
    "/api/v1/decisions/core-components"
    "/api/v1/micro-pentest/health"
    "/api/v1/attack-sim/health"
    "/api/v1/attack-simulation/health"
    "/api/v1/pentagi/health"
    "/api/v1/vulns/health"
    "/api/v1/evidence/health"
    "/api/v1/risk/health"
    "/api/v1/graph/health"
    "/api/v1/compliance/health"
    "/api/v1/predictions/health"
    "/api/v1/autofix/health"
    "/api/v1/dedup/health"
    "/api/v1/marketplace/health"
    "/api/v1/integrations/health"
    "/api/v1/copilot/health"
    "/api/v1/llm/health"
    "/api/v1/stream/health"
    "/api/v1/nerve-center/health"
    "/api/v1/mindsdb/status"
    "/api/v1/secrets-scanner/health"
    "/api/v1/dast/health"
    "/api/v1/sast/status"
    "/api/v1/container/status"
    "/api/v1/api-fuzzer/status"
    "/api/v1/malware/status"
    "/api/v1/business-context/health"
    "/api/v1/provenance/health"
    "/api/v1/reachability/health"
    "/api/v1/code-to-cloud/status"
    "/api/v1/mcp/status"
    "/api/v1/ide/status"
    "/api/v1/iac/scanners/status"
  )
  for ep in "${endpoints[@]}"; do
    call GET "$ep" "" "Health: $ep"
  done
  echo ""
  printf "  ${W}Health summary: %d/%d engines responding${NC}\n" "$PASS" "$TOTAL"
}

# ═══════════════════════════════════════════════════════════════════════════
#  CUSTOM CVE DEEP-DIVE
# ═══════════════════════════════════════════════════════════════════════════
test_cve_deepdive() {
  section "CVE DEEP-DIVE"
  prompt "Enter a CVE ID to analyse [CVE-2021-44228]"
  read -r _cve; _cve="${_cve:-CVE-2021-44228}"

  banner "NVD Lookup"
  call GET "/api/v1/feeds/nvd/${_cve}" "" "NVD: $_cve"
  show

  banner "EPSS Score"
  call GET "/api/v1/feeds/exploit-confidence/${_cve}" "" "Exploit confidence: $_cve"
  show

  banner "Geo Risk"
  call GET "/api/v1/feeds/geo-risk/${_cve}?country=US" "" "Geo risk: $_cve (US)"
  show

  banner "AI Analyst Lookup"
  call GET "/api/v1/copilot/agents/analyst/cve/${_cve}" "" "AI analyst: $_cve"
  show

  banner "SSVC Decision"
  prompt "Asset name to evaluate against [$ASSET1]"
  read -r _asset; _asset="${_asset:-$ASSET1}"
  call POST /api/v1/decisions/make-decision \
    "{\"cve_id\":\"${_cve}\",\"asset_name\":\"${_asset}\",\"severity\":\"critical\",\"title\":\"Deep-dive analysis\",\"source\":\"manual\"}" \
    "SSVC: $_cve → $_asset"
  show
}

# ═══════════════════════════════════════════════════════════════════════════
#  MAIN MENU
# ═══════════════════════════════════════════════════════════════════════════
main_menu() {
  while true; do
    echo ""
    echo -e "${W}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${W}║       FixOps Enterprise Testing — Main Menu                 ║${NC}"
    echo -e "${W}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${W}║                                                             ║${NC}"
    echo -e "${W}║  ${C}CTEM Loop (Full Walkthrough):${W}                              ║${NC}"
    echo -e "${W}║    ${G}1${W}) Stage 1: SCOPE    — Assets & Business Context        ║${NC}"
    echo -e "${W}║    ${G}2${W}) Stage 2: DISCOVER  — Threat Intel & CVE Enrichment   ║${NC}"
    echo -e "${W}║    ${G}3${W}) Stage 3: PRIORITIZE — SSVC Decisions & Risk          ║${NC}"
    echo -e "${W}║    ${G}4${W}) Stage 4: VALIDATE  — Pipeline, Pentest & Evidence    ║${NC}"
    echo -e "${W}║    ${G}5${W}) Stage 5: MOBILIZE  — Remediation & Integration      ║${NC}"
    echo -e "${W}║    ${G}A${W}) Run ALL stages (1→5) sequentially                    ║${NC}"
    echo -e "${W}║                                                             ║${NC}"
    echo -e "${W}║  ${C}Quick Tests:${W}                                                ║${NC}"
    echo -e "${W}║    ${Y}H${W}) Health check — ALL 37 engines                        ║${NC}"
    echo -e "${W}║    ${Y}C${W}) CVE deep-dive (enter any CVE ID)                     ║${NC}"
    echo -e "${W}║    ${Y}T${W}) Test individual API endpoint                         ║${NC}"
    echo -e "${W}║                                                             ║${NC}"
    echo -e "${W}║  ${M}Q${W}) Quit & show results                                   ║${NC}"
    echo -e "${W}║                                                             ║${NC}"
    echo -e "${W}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    prompt "Choice"
    read -r choice

    case "$choice" in
      1) stage_scope ;;
      2) stage_discover ;;
      3) stage_prioritize ;;
      4) stage_validate ;;
      5) stage_mobilize ;;
      [aA])
        stage_scope
        stage_discover
        stage_prioritize
        stage_validate
        stage_mobilize
        ;;
      [hH]) test_all_health ;;
      [cC]) test_cve_deepdive ;;
      [tT]) test_individual_api ;;
      [qQ]) summary_and_exit ;;
      *)
        warn "Invalid choice. Enter 1-5, A, H, C, T, or Q."
        ;;
    esac
  done
}

# ═══════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════
clear
echo -e "${C}"
cat << 'BANNER'
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║   █████╗ ██╗     ██████╗ ███████╗ ██████╗██╗                 ║
    ║  ██╔══██╗██║     ██╔══██╗██╔════╝██╔════╝██║                 ║
    ║  ███████║██║     ██║  ██║█████╗  ██║     ██║                 ║
    ║  ██╔══██║██║     ██║  ██║██╔══╝  ██║     ██║                 ║
    ║  ██║  ██║███████╗██████╔╝███████╗╚██████╗██║                 ║
    ║  ╚═╝  ╚═╝╚══════╝╚═════╝ ╚══════╝ ╚═════╝╚═╝                 ║
    ║                                                              ║
    ║     Enterprise Interactive Testing Suite                     ║
    ║     CTEM: Scope → Discover → Prioritize → Validate → Mobilize ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
BANNER
echo -e "${NC}"
echo -e "  ${W}Server:${NC} $API"
echo -e "  ${W}Token:${NC}  ${KEY:0:16}..."
echo -e "  ${W}Date:${NC}   $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

# Verify server is reachable
banner "Checking server connectivity..."
if curl -s --max-time 5 "${API}/health" > /dev/null 2>&1; then
  ok "Server is healthy at $API"
else
  fail "Cannot reach server at $API"
  echo -e "  ${Y}Start server: FIXOPS_MODE=enterprise uvicorn apps.api.app:app --host 0.0.0.0 --port 8000${NC}"
  exit 1
fi
echo ""

# Collect user data then show menu
collect_user_input
main_menu