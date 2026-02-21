#!/usr/bin/env bash
# ============================================================================
#  FixOps Enterprise Smoke Test — hits every major endpoint, prints PASS/FAIL
#  Requires: FIXOPS_API_TOKEN env var (enterprise token)
# ============================================================================
set -uo pipefail   # NOTE: no -e — we handle errors ourselves
API="${FIXOPS_API_URL:-http://localhost:8000}"
KEY="${FIXOPS_API_TOKEN:?ERROR: FIXOPS_API_TOKEN must be set. Generate with: python3 -c \"import secrets; print(secrets.token_urlsafe(48))\"}"
PASS=0; FAIL=0; SKIP=0; TOTAL=0

hit() {
  local method="$1" path="$2" data="${3:-}"
  TOTAL=$((TOTAL+1))
  local args=(-s -o /dev/null -w "%{http_code}" -X "$method" --max-time 10 --connect-timeout 5 -H "X-API-Key: $KEY" -H "Content-Type: application/json")
  [[ -n "$data" ]] && args+=(-d "$data")
  local code
  code=$(curl "${args[@]}" "${API}${path}" 2>/dev/null || echo "000")
  if [[ "$code" =~ ^2 ]]; then
    printf "  ✅ %s %-50s %s\n" "$method" "$path" "$code"; PASS=$((PASS+1))
  elif [[ "$code" == "000" ]]; then
    printf "  ⏭️  %s %-50s SKIP\n" "$method" "$path"; SKIP=$((SKIP+1))
  else
    printf "  ❌ %s %-50s %s\n" "$method" "$path" "$code"; FAIL=$((FAIL+1))
  fi
}

echo "═══════════════════════════════════════════════════════════════"
echo "  FixOps Enterprise Smoke Test — $(date '+%Y-%m-%d %H:%M:%S')"
echo "  Server: $API  |  Token: ${KEY:0:8}..."
echo "═══════════════════════════════════════════════════════════════"
echo ""

echo "── Health ──"
hit GET /health
hit GET /api/v1/feeds/health
hit GET /api/v1/brain/health
hit GET /api/v1/decisions/core-components

echo "── Feeds (Threat Intel) ──"
hit GET /api/v1/feeds/epss
hit GET /api/v1/feeds/kev
hit GET /api/v1/feeds/categories
hit GET /api/v1/feeds/sources
hit GET /api/v1/feeds/stats
hit GET /api/v1/feeds/exploit-confidence/CVE-2021-44228
hit GET /api/v1/feeds/geo-risk/CVE-2021-44228
hit POST /api/v1/feeds/enrich '{"cve_ids":["CVE-2021-44228","CVE-2023-0286"]}'

echo "── Knowledge Brain ──"
hit GET /api/v1/brain/nodes
hit GET /api/v1/brain/stats
hit GET /api/v1/brain/meta/entity-types
hit GET /api/v1/brain/meta/edge-types
hit GET /api/v1/brain/all-edges
hit GET /api/v1/brain/most-connected
hit POST /api/v1/brain/nodes '{"node_id":"smoke-cve-1","node_type":"cve","label":"CVE-2021-44228","properties":{"severity":"critical"}}'
hit POST /api/v1/brain/ingest/cve '{"cve_id":"CVE-2021-44228","severity":"critical","description":"Log4Shell RCE"}'
hit POST /api/v1/brain/ingest/finding '{"finding_id":"f-1","cve_id":"CVE-2021-44228","severity":"critical","asset":"web-app"}'
hit POST /api/v1/brain/ingest/asset '{"asset_id":"web-app","name":"web-app","criticality":0.9,"type":"service"}'

echo "── Brain Pipeline ──"
hit GET /api/v1/brain/pipeline/runs
hit POST /api/v1/brain/pipeline/run '{"org_id":"demo-org","findings":[{"id":"f1","cve_id":"CVE-2021-44228","severity":"critical","title":"Log4Shell"}],"assets":[{"id":"a1","name":"web-app","criticality":0.95}]}'

echo "── Decisions ──"
hit GET /api/v1/decisions/core-components
hit GET /api/v1/decisions/recent
hit GET /api/v1/decisions/metrics
hit POST /api/v1/decisions/make-decision '{"cve_id":"CVE-2021-44228","asset_name":"web-app","severity":"critical","title":"Log4Shell RCE"}'

echo "── Attack Surface ──"
hit GET /api/v1/attack-sim/health
hit GET /api/v1/vuln-discovery/health
hit GET /api/v1/micro-pentest/health
hit GET /api/v1/dast/health

echo "── Evidence & Risk ──"
hit GET /api/v1/evidence/health
hit GET /api/v1/risk/health
hit GET /api/v1/graph/health
hit GET /api/v1/graph/kev-components

echo "── Core Intelligence ──"
hit GET /api/v1/nerve-center/health
hit GET /api/v1/copilot/health
hit GET /api/v1/marketplace/health
hit GET /api/v1/compliance/health
hit GET /api/v1/reports/list
hit GET /api/v1/stream/health

echo "── Integrations ──"
hit GET /api/v1/integrations/health
hit GET /api/v1/secrets-scanner/health

echo "── Enterprise ──"
hit GET /api/v1/copilot/agents/analyst/status
hit GET /api/v1/copilot/agents/compliance/frameworks
hit GET /api/v1/predictions/health
hit GET /api/v1/llm/health
hit GET /api/v1/mindsdb/status
hit GET /api/v1/dedup/health
hit GET /api/v1/autofix/health

echo ""
echo "═══════════════════════════════════════════════════════════════"
printf "  RESULTS: %d total | ✅ %d pass | ❌ %d fail | ⏭️  %d skip\n" "$TOTAL" "$PASS" "$FAIL" "$SKIP"
if [[ $FAIL -eq 0 ]]; then
  echo "  STATUS: ALL PASSING ✅"
else
  echo "  STATUS: $FAIL FAILURES ❌"
fi
echo "═══════════════════════════════════════════════════════════════"
exit $FAIL

