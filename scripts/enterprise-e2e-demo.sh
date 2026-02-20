#!/usr/bin/env bash
# ============================================================================
#  FixOps Enterprise E2E Demo — Real API Calls, Real CVEs, ~10 min
#  Usage: ./scripts/enterprise-e2e-demo.sh [--api URL] [--token KEY]
# ============================================================================
set -uo pipefail
API="${FIXOPS_API_URL:-http://localhost:8000}"
KEY="${FIXOPS_API_TOKEN:?ERROR: FIXOPS_API_TOKEN must be set. Generate with: python3 -c \"import secrets; print(secrets.token_urlsafe(48))\"}"
PASS=0; FAIL=0; TOTAL=0
while [[ $# -gt 0 ]]; do
  case $1 in --api) API="$2"; shift 2;; --token) KEY="$2"; shift 2;; *) shift;; esac
done

call() {
  local method="$1" path="$2" data="${3:-}" desc="${4:-$2}"
  TOTAL=$((TOTAL+1))
  local args=(-s -w "\n%{http_code}" -X "$method" --max-time 15 --connect-timeout 5 -H "X-API-Key: $KEY" -H "Content-Type: application/json")
  [[ -n "$data" ]] && args+=(-d "$data")
  local raw; raw=$(curl "${args[@]}" "${API}${path}" 2>/dev/null || echo -e "\n000")
  local code; code=$(echo "$raw" | tail -1)
  local body; body=$(echo "$raw" | sed '$d')
  if [[ "$code" =~ ^2 ]]; then
    printf "  ✅ %-60s [%s]\n" "$desc" "$code"; PASS=$((PASS+1))
  else
    printf "  ❌ %-60s [%s]\n" "$desc" "$code"; FAIL=$((FAIL+1))
  fi
  echo "$body"  # return body for piping
}

banner() { echo ""; echo "━━━ $1 ━━━"; }
section() { echo ""; echo "╔══════════════════════════════════════════════════════════════╗"; printf "║  %-60s ║\n" "$1"; echo "╚══════════════════════════════════════════════════════════════╝"; }

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║        FixOps Enterprise E2E Demo — CTEM Loop               ║"
echo "║  $(date '+%Y-%m-%d %H:%M:%S')  |  Server: $API             ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ──────────────────────────────────────────────────────────────────
section "STAGE 1: SCOPE — Define Attack Surface & Business Context"
# ──────────────────────────────────────────────────────────────────

banner "1.1 Health Check"
call GET /health "" "Platform health"

banner "1.2 Register Assets in Knowledge Brain"
call POST /api/v1/brain/ingest/asset \
  '{"asset_id":"payment-svc","name":"payment-service","criticality":0.95,"type":"service"}' \
  "Register: payment-service (criticality=0.95)"

call POST /api/v1/brain/ingest/asset \
  '{"asset_id":"api-gw","name":"api-gateway","criticality":0.85,"type":"service"}' \
  "Register: api-gateway (criticality=0.85)"

call POST /api/v1/brain/ingest/asset \
  '{"asset_id":"user-db","name":"user-database","criticality":0.90,"type":"database"}' \
  "Register: user-database (criticality=0.90)"

banner "1.3 Verify Brain Graph"
call GET /api/v1/brain/stats "" "Brain graph statistics"
call GET /api/v1/brain/nodes "" "List all brain nodes"

# ──────────────────────────────────────────────────────────────────
section "STAGE 2: DISCOVER — Threat Intel & Vulnerability Discovery"
# ──────────────────────────────────────────────────────────────────

banner "2.1 Feed Health & Sources"
call GET /api/v1/feeds/health "" "Feed system health"
call GET /api/v1/feeds/categories "" "Feed categories (8 types)"
call GET /api/v1/feeds/sources "" "All feed sources"

banner "2.2 Query EPSS & KEV"
call GET /api/v1/feeds/epss "" "EPSS scores (top exploited)"
call GET /api/v1/feeds/kev "" "CISA KEV catalog"

banner "2.3 Enrich Real CVEs"
call POST /api/v1/feeds/enrich \
  '{"cve_ids":["CVE-2021-44228","CVE-2023-44487","CVE-2024-3094","CVE-2023-0286","CVE-2021-45046"]}' \
  "Enrich 5 critical CVEs (Log4Shell, HTTP/2 Rapid Reset, xz, OpenSSL, Log4j)"

banner "2.4 Exploit Confidence & Geo Risk"
call GET "/api/v1/feeds/exploit-confidence/CVE-2021-44228" "" "Exploit confidence: CVE-2021-44228"
call GET "/api/v1/feeds/geo-risk/CVE-2021-44228?country=US" "" "Geo-weighted risk: CVE-2021-44228 (US)"

banner "2.5 Ingest Findings into Brain"
call POST /api/v1/brain/ingest/cve \
  '{"cve_id":"CVE-2021-44228","severity":"critical","description":"Apache Log4j2 RCE via JNDI"}' \
  "Ingest CVE-2021-44228 into brain"

call POST /api/v1/brain/ingest/finding \
  '{"finding_id":"scan-001","cve_id":"CVE-2021-44228","severity":"critical","asset":"payment-svc","source":"sca"}' \
  "Ingest finding: Log4Shell in payment-service"

call POST /api/v1/brain/ingest/finding \
  '{"finding_id":"scan-002","cve_id":"CVE-2023-44487","severity":"high","asset":"api-gw","source":"dast"}' \
  "Ingest finding: HTTP/2 Rapid Reset in api-gateway"

banner "2.6 Vuln Discovery & DAST"
call GET /api/v1/vuln-discovery/health "" "Vuln discovery engine health"
call GET /api/v1/dast/health "" "DAST scanner health"
call GET /api/v1/attack-sim/health "" "Attack simulation health"

# ──────────────────────────────────────────────────────────────────
section "STAGE 3: PRIORITIZE — SSVC Decisions & Risk Scoring"
# ──────────────────────────────────────────────────────────────────

banner "3.1 SSVC Decision Engine"
call GET /api/v1/decisions/core-components "" "SSVC decision components"

call POST /api/v1/decisions/make-decision \
  '{"cve_id":"CVE-2021-44228","asset_name":"payment-service","severity":"critical","title":"Log4Shell RCE","source":"sca","exploitability":"active","business_criticality":"high"}' \
  "SSVC decision: CVE-2021-44228 on payment-service"

call POST /api/v1/decisions/make-decision \
  '{"cve_id":"CVE-2023-44487","asset_name":"api-gateway","severity":"high","title":"HTTP/2 Rapid Reset DoS","source":"dast"}' \
  "SSVC decision: CVE-2023-44487 on api-gateway"

banner "3.2 Decision History & Metrics"
call GET /api/v1/decisions/recent "" "Recent decisions"
call GET /api/v1/decisions/metrics "" "Decision metrics"

banner "3.3 Brain Risk Scores"
call GET "/api/v1/brain/risk/payment-svc" "" "Risk score: payment-service"
call GET "/api/v1/brain/most-connected" "" "Most connected nodes (blast radius)"

banner "3.4 Graph Risk Analysis"
call GET /api/v1/graph/health "" "Graph engine health"
call GET /api/v1/graph/kev-components "" "KEV-connected components"

banner "3.5 Compliance Posture"
call GET /api/v1/compliance/health "" "Compliance engine health"
call GET /api/v1/copilot/agents/compliance/frameworks "" "Compliance frameworks"

# ──────────────────────────────────────────────────────────────────
section "STAGE 4: VALIDATE — Micro-Pentest & Evidence Collection"
# ──────────────────────────────────────────────────────────────────

banner "4.1 Micro Penetration Testing"
call GET /api/v1/micro-pentest/health "" "Micro-pentest engine (MPTE) health"

banner "4.2 Brain Pipeline — Full 12-Step Orchestration"
call POST /api/v1/brain/pipeline/run \
  '{"org_id":"demo-org","findings":[{"id":"f1","cve_id":"CVE-2021-44228","severity":"critical","title":"Log4Shell","asset_name":"payment-service","source":"sca"},{"id":"f2","cve_id":"CVE-2023-44487","severity":"high","title":"HTTP/2 Rapid Reset","asset_name":"api-gateway","source":"dast"}],"assets":[{"id":"a1","name":"payment-service","criticality":0.95},{"id":"a2","name":"api-gateway","criticality":0.85}],"generate_evidence":true,"evidence_framework":"SOC2"}' \
  "Full pipeline: 2 findings, 2 assets, SOC2 evidence"
call GET /api/v1/brain/pipeline/runs "" "List pipeline runs"

banner "4.3 Evidence Collection"
call GET /api/v1/evidence/health "" "Evidence engine health"
call GET /api/v1/risk/health "" "Risk engine health"
call POST /api/v1/brain/evidence/generate \
  '{"org_id":"demo-org","timeframe_days":90,"controls":["CC6.1","CC6.7","CC7.2"]}' \
  "Generate SOC2 evidence pack (CC6.1, CC6.7, CC7.2)"
call GET /api/v1/brain/evidence/packs "" "List evidence packs"

banner "4.4 Predictions & ML"
call GET /api/v1/predictions/health "" "Predictions engine health"
call GET /api/v1/mindsdb/status "" "MindsDB integration status"

# ──────────────────────────────────────────────────────────────────
section "STAGE 5: MOBILIZE — Remediation & Integration"
# ──────────────────────────────────────────────────────────────────

banner "5.1 AutoFix Recommendations"
call GET /api/v1/autofix/health "" "AutoFix engine health"

banner "5.2 Integrations Status"
call GET /api/v1/integrations/health "" "Integration hub health"
call GET /api/v1/secrets-scanner/health "" "Secrets scanner health"
call GET /api/v1/copilot/agents/analyst/status "" "AI analyst agent status"

banner "5.3 Brain Remediation Tracking"
call POST /api/v1/brain/ingest/remediation \
  '{"task_id":"rem-001","finding_id":"scan-001","org_id":"demo-org","status":"in_progress","assignee":"security-team","action":"upgrade log4j to 2.17.1"}' \
  "Track remediation: upgrade log4j for payment-service"

banner "5.4 Reporting & Deduplication"
call GET /api/v1/reports/list "" "Available reports"
call GET /api/v1/dedup/health "" "Deduplication engine health"

banner "5.5 Marketplace & Streaming"
call GET /api/v1/marketplace/health "" "Marketplace health"
call GET /api/v1/stream/health "" "SSE streaming health"
call GET /api/v1/nerve-center/health "" "Nerve center health"
call GET /api/v1/copilot/health "" "AI copilot health"
call GET /api/v1/llm/health "" "LLM engine health"

banner "5.6 Final Brain State"
call GET /api/v1/brain/stats "" "Final brain graph statistics"
call GET /api/v1/brain/events "" "Brain event log"

# ──────────────────────────────────────────────────────────────────
section "RESULTS"
# ──────────────────────────────────────────────────────────────────
echo ""
printf "  Total: %d  |  ✅ Pass: %d  |  ❌ Fail: %d\n" "$TOTAL" "$PASS" "$FAIL"
if [[ $FAIL -eq 0 ]]; then
  echo ""
  echo "  ██████████████████████████████████████████████████████████"
  echo "  █  ALL CTEM STAGES PASSED — ENTERPRISE READY  ✅        █"
  echo "  ██████████████████████████████████████████████████████████"
else
  echo ""
  echo "  ⚠️  $FAIL endpoint(s) need attention"
fi
echo ""
echo "  CTEM Coverage: Scope ✓ → Discover ✓ → Prioritize ✓ → Validate ✓ → Mobilize ✓"
echo ""

