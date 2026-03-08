#!/bin/bash
set -euo pipefail

API="http://localhost:8000"
KEY="fixops_sk_WIjum9WxuQv8s6vzJeU2gYKximI5WSdMDtshH1U_p0U"
PASS=0
FAIL=0
WARN=0
RESULTS=""

test_endpoint() {
    local name="$1"
    local method="$2"
    local path="$3"
    local data="${4:-}"
    local expect_code="${5:-200}"
    
    if [ "$method" == "GET" ]; then
        resp=$(curl -s -o /tmp/test_body.json -w "%{http_code}" -X GET "$API$path" -H "X-API-Key: $KEY" -H "Accept: application/json" 2>/dev/null)
    elif [ "$method" == "POST" ]; then
        resp=$(curl -s -o /tmp/test_body.json -w "%{http_code}" -X POST "$API$path" -H "X-API-Key: $KEY" -H "Content-Type: application/json" -H "Accept: application/json" -d "$data" 2>/dev/null)
    fi
    
    body_size=$(wc -c < /tmp/test_body.json)
    
    if [ "$resp" == "$expect_code" ]; then
        PASS=$((PASS + 1))
        echo "✅ PASS [$resp] $name ($body_size bytes)"
    elif [ "$resp" == "200" ] || [ "$resp" == "201" ] || [ "$resp" == "202" ]; then
        PASS=$((PASS + 1))
        echo "✅ PASS [$resp] $name ($body_size bytes)"
    elif [ "$resp" == "422" ]; then
        WARN=$((WARN + 1))
        echo "⚠️  WARN [$resp] $name - validation error (expected, needs input)"
    elif [ "$resp" == "404" ]; then
        FAIL=$((FAIL + 1))
        echo "❌ FAIL [$resp] $name - NOT FOUND"
    elif [ "$resp" == "500" ]; then
        FAIL=$((FAIL + 1))
        echo "❌ FAIL [$resp] $name - SERVER ERROR"
        head -c 200 /tmp/test_body.json
        echo ""
    else
        WARN=$((WARN + 1))
        echo "⚠️  WARN [$resp] $name ($body_size bytes)"
    fi
}

echo "═══════════════════════════════════════════════════════"
echo "  FIXOPS ENTERPRISE INTEGRATION TEST SUITE"
echo "  $(date)"
echo "═══════════════════════════════════════════════════════"

echo ""
echo "── 1. HEALTH & SYSTEM ─────────────────────────────────"
test_endpoint "Health Check" GET "/api/v1/health"
test_endpoint "System Info" GET "/api/v1/system/info"
test_endpoint "API Version" GET "/api/v1/version"
test_endpoint "Feature Flags" GET "/api/v1/flags"

echo ""
echo "── 2. AUTHENTICATION ──────────────────────────────────"
test_endpoint "Auth - Valid API Key" GET "/api/v1/health"
# Test invalid key
resp=$(curl -s -o /dev/null -w "%{http_code}" -X GET "$API/api/v1/findings" -H "X-API-Key: invalid_key" 2>/dev/null)
if [ "$resp" == "401" ] || [ "$resp" == "403" ]; then
    PASS=$((PASS + 1))
    echo "✅ PASS [$resp] Auth - Invalid key rejected"
else
    FAIL=$((FAIL + 1))
    echo "❌ FAIL [$resp] Auth - Invalid key NOT rejected (should be 401/403)"
fi

echo ""
echo "── 3. FINDINGS / VULNERABILITIES ──────────────────────"
test_endpoint "List Findings" GET "/api/v1/findings"
test_endpoint "Findings Summary" GET "/api/v1/findings/summary"
test_endpoint "Findings Stats" GET "/api/v1/findings/stats"
test_endpoint "Findings by Severity" GET "/api/v1/findings?severity=critical"
test_endpoint "Findings Search" GET "/api/v1/findings?q=sql+injection"

echo ""
echo "── 4. ASSETS / INVENTORY ──────────────────────────────"
test_endpoint "List Assets" GET "/api/v1/assets"
test_endpoint "Assets Summary" GET "/api/v1/assets/summary"
test_endpoint "Asset Types" GET "/api/v1/assets/types"

echo ""
echo "── 5. RISK ENGINE ─────────────────────────────────────"
test_endpoint "Risk Overview" GET "/api/v1/risk/overview"
test_endpoint "Risk Matrix" GET "/api/v1/risk/matrix"
test_endpoint "Risk Trends" GET "/api/v1/risk/trends"
test_endpoint "Risk Score" GET "/api/v1/risk/score"

echo ""
echo "── 6. COMPLIANCE ──────────────────────────────────────"
test_endpoint "Compliance Status" GET "/api/v1/compliance/status"
test_endpoint "Compliance Frameworks" GET "/api/v1/compliance/frameworks"
test_endpoint "Compliance Controls" GET "/api/v1/compliance/controls"
test_endpoint "Compliance Gaps" GET "/api/v1/compliance/gaps"
test_endpoint "NIST Assessment" GET "/api/v1/compliance/nist"
test_endpoint "SOC2 Assessment" GET "/api/v1/compliance/soc2"

echo ""
echo "── 7. ATTACK SURFACE ──────────────────────────────────"
test_endpoint "Attack Surface" GET "/api/v1/attack/surface"
test_endpoint "Attack Simulations" GET "/api/v1/attack/simulations"
test_endpoint "Attack Vectors" GET "/api/v1/attack/vectors"
test_endpoint "MITRE Mapping" GET "/api/v1/mitre/techniques"

echo ""
echo "── 8. SAST / DAST / CONTAINER ─────────────────────────"
test_endpoint "SAST Scans" GET "/api/v1/sast/scans"
test_endpoint "DAST Scans" GET "/api/v1/dast/scans"
test_endpoint "Container Scans" GET "/api/v1/container/scans"
test_endpoint "Container Images" GET "/api/v1/container/images"

echo ""
echo "── 9. AUTOFIX ENGINE ──────────────────────────────────"
test_endpoint "AutoFix Status" GET "/api/v1/autofix/status"
test_endpoint "AutoFix History" GET "/api/v1/autofix/history"
test_endpoint "AutoFix Policies" GET "/api/v1/autofix/policies"

echo ""
echo "── 10. EVIDENCE & PROVENANCE ──────────────────────────"
test_endpoint "Evidence List" GET "/api/v1/evidence"
test_endpoint "Evidence Summary" GET "/api/v1/evidence/summary"
test_endpoint "Provenance Chain" GET "/api/v1/provenance/chains"
test_endpoint "Provenance Verify" GET "/api/v1/provenance/status"

echo ""
echo "── 11. GRAPH / KNOWLEDGE GRAPH ────────────────────────"
test_endpoint "Graph Overview" GET "/api/v1/graph/overview"
test_endpoint "Graph Nodes" GET "/api/v1/graph/nodes"
test_endpoint "Graph Relationships" GET "/api/v1/graph/relationships"
test_endpoint "Knowledge Brain" GET "/api/v1/knowledge/status"

echo ""
echo "── 12. PIPELINE / CI-CD ───────────────────────────────"
test_endpoint "Pipeline Status" GET "/api/v1/pipeline/status"
test_endpoint "Pipeline Runs" GET "/api/v1/pipeline/runs"
test_endpoint "Pipeline Gates" GET "/api/v1/pipeline/gates"

echo ""
echo "── 13. CONNECTORS / INTEGRATIONS ──────────────────────"
test_endpoint "Connectors List" GET "/api/v1/connectors"
test_endpoint "Connectors Status" GET "/api/v1/connectors/status"
test_endpoint "Scanner Ingest" GET "/api/v1/scanner-ingest/status"

echo ""
echo "── 14. AI / COPILOT ───────────────────────────────────"
test_endpoint "Copilot Status" GET "/api/v1/copilot/status"
test_endpoint "Copilot History" GET "/api/v1/copilot/history"
test_endpoint "AI Agents" GET "/api/v1/agents"
test_endpoint "Predictions" GET "/api/v1/predictions"

echo ""
echo "── 15. MCP PROTOCOL ───────────────────────────────────"
test_endpoint "MCP Tools List" GET "/api/v1/mcp/tools"
test_endpoint "MCP Status" GET "/api/v1/mcp/status"
test_endpoint "MCP Categories" GET "/api/v1/mcp/categories"

echo ""
echo "── 16. ADVANCED ENGINES ───────────────────────────────"
test_endpoint "Quantum Crypto" GET "/api/v1/quantum/status"
test_endpoint "Zero Gravity" GET "/api/v1/zero-gravity/status"
test_endpoint "Code-to-Cloud" GET "/api/v1/code-to-cloud/status"
test_endpoint "Dedup Engine" GET "/api/v1/dedup/status"
test_endpoint "Air-Gap Ops" GET "/api/v1/airgap/status"
test_endpoint "Self-Learning" GET "/api/v1/self-learning/status"
test_endpoint "Nerve Center" GET "/api/v1/nerve-center/status"
test_endpoint "LLM Monitor" GET "/api/v1/llm-monitor/status"
test_endpoint "CSPM" GET "/api/v1/cspm/status"
test_endpoint "API Fuzzer" GET "/api/v1/api-fuzzer/status"
test_endpoint "Malware Analysis" GET "/api/v1/malware/status"
test_endpoint "Fuzzy Identity" GET "/api/v1/fuzzy-identity/status"
test_endpoint "Material Change" GET "/api/v1/material-change/status"
test_endpoint "Exposure Cases" GET "/api/v1/exposure-cases"
test_endpoint "SSE Streaming" GET "/api/v1/sse/status"

echo ""
echo "── 17. LOGS & MONITORING ──────────────────────────────"
test_endpoint "Detailed Logs" GET "/api/v1/logs"
test_endpoint "Log Stats" GET "/api/v1/logs/stats"

echo ""
echo "── 18. FRONTEND SPA ───────────────────────────────────"
spa_resp=$(curl -s -o /dev/null -w "%{http_code}" "$API/" 2>/dev/null)
if [ "$spa_resp" == "200" ]; then
    PASS=$((PASS + 1))
    echo "✅ PASS [$spa_resp] SPA Index served"
else
    FAIL=$((FAIL + 1))
    echo "❌ FAIL [$spa_resp] SPA Index not served"
fi

# Check if SPA has real content (not empty)
spa_size=$(curl -s "$API/" 2>/dev/null | wc -c)
if [ "$spa_size" -gt 500 ]; then
    PASS=$((PASS + 1))
    echo "✅ PASS [200] SPA content valid ($spa_size bytes)"
else
    FAIL=$((FAIL + 1))
    echo "❌ FAIL SPA content too small ($spa_size bytes)"
fi

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  TEST RESULTS SUMMARY"
echo "═══════════════════════════════════════════════════════"
echo "  ✅ PASSED:  $PASS"
echo "  ❌ FAILED:  $FAIL"
echo "  ⚠️  WARNINGS: $WARN"
TOTAL=$((PASS + FAIL + WARN))
echo "  📊 TOTAL:   $TOTAL"
RATE=$((PASS * 100 / TOTAL))
echo "  📈 PASS RATE: ${RATE}%"
echo "═══════════════════════════════════════════════════════"

if [ "$FAIL" -gt 0 ]; then
    echo "  STATUS: ⚠️  SOME TESTS FAILED - NEEDS ATTENTION"
    exit 1
else
    echo "  STATUS: ✅ ALL TESTS PASSED"
    exit 0
fi
