#!/bin/bash
# Probe failing endpoints to understand their required schemas
API_KEY="aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh"
BASE="http://localhost:8000/api/v1"

probe() {
    local method=$1
    local endpoint=$2
    local body=$3
    echo "=== $method $endpoint ==="
    if [ -z "$body" ]; then
        curl -s -w "\nHTTP_CODE: %{http_code}\n" -X "$method" "${BASE}${endpoint}" -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" 2>&1 | tail -20
    else
        curl -s -w "\nHTTP_CODE: %{http_code}\n" -X "$method" "${BASE}${endpoint}" -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" -d "$body" 2>&1 | tail -20
    fi
    echo ""
}

echo "====== SCHEMA MISMATCH ENDPOINTS (422) ======"

probe POST /feeds/enrich '{}'
probe POST /validate/input '{}'
probe POST /deduplication/correlate/cross-stage '{}'
probe POST /api-fuzzer/discover '{}'
probe POST /predictions/attack-chain '{}'
probe POST /algorithms/monte-carlo/cve '{}'
probe POST /algorithms/gnn/attack-surface '{}'
probe POST /reachability/analyze '{}'
probe POST /code-to-cloud/trace '{}'
probe POST /identity/canonical '{}'
probe POST /mpte/verify '{}'
probe POST /micro-pentest/run '{}'
probe POST /micro-pentest/enterprise/scan '{}'
probe POST /micro-pentest/report/generate '{}'
probe POST /autofix/validate '{}'
probe POST /workflows '{}'
probe POST /copilot/agents/analyst/attack-paths '{}'
probe PUT /analytics/findings/test-finding-1 '{}'
probe POST /inputs/sarif '{}'
probe POST /inputs/sbom '{}'
probe POST /inputs/cve '{}'
probe POST /inputs/design '{}'

echo "====== MISSING ENDPOINT CANDIDATES (404) ======"

probe GET /risk/ ''
probe GET /risk/cve/CVE-2024-3094 ''
probe GET /marketplace ''
probe GET /business-context ''
probe GET /remediation/tasks/test-task-1 ''
probe GET /autofix/fixes/test-fix-1 ''
probe POST /autofix/validate '{}'
probe GET /audit/compliance/soc2/status ''
probe GET /audit/compliance/soc2/gaps ''
probe GET /evidence/bundles/test-bundle-1 ''
probe GET /mpte/findings/test-finding-1/exploitability ''
probe GET /attack-sim/campaigns/test-campaign-1/attack-paths ''
probe GET /attack-sim/campaigns/test-campaign-1/breach-impact ''
probe POST /copilot/agents/analyst/attack-paths '{}'
probe POST /audit/compliance/frameworks/soc2/report '{}'

echo "====== TEST LOGIC ENDPOINTS ======"

probe POST /teams '{"name":"test-team","description":"Test team"}'
probe POST /workflows '{"name":"test-wf","description":"Test","steps":[]}'
probe PATCH /cases/test-case-1 '{"status":"in_progress"}'
probe PUT /remediation/tasks/test-task-1/status '{"status":"in_progress"}'
probe POST /evidence/bundles/test-bundle-1/verify '{}'

echo "====== SEARCH (500 BUG) ======"
probe GET "/search?q=test" ''
probe GET "/search?keyword=test" ''
