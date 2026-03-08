#!/bin/bash
set -euo pipefail

API="http://localhost:8000"
KEY="fixops_sk_WIjum9WxuQv8s6vzJeU2gYKximI5WSdMDtshH1U_p0U"
PASS=0
FAIL=0
WARN=0

test_ep() {
    local name="$1"
    local method="$2"
    local path="$3"
    local data="${4:-}"
    
    if [ "$method" == "GET" ]; then
        resp=$(curl -s -o /tmp/tb.json -w "%{http_code}" "$API$path" -H "X-API-Key: $KEY" -H "Accept: application/json" 2>/dev/null)
    elif [ "$method" == "POST" ]; then
        resp=$(curl -s -o /tmp/tb.json -w "%{http_code}" -X POST "$API$path" -H "X-API-Key: $KEY" -H "Content-Type: application/json" -d "$data" 2>/dev/null)
    fi
    
    ct=$(head -c 20 /tmp/tb.json)
    body_size=$(wc -c < /tmp/tb.json)
    
    # Check if it's HTML (SPA fallback = route doesn't exist)
    if echo "$ct" | grep -q "<!DOCTYPE\|<html"; then
        FAIL=$((FAIL + 1))
        echo "❌ FAIL [$resp] $name — got SPA HTML (route not found)"
        return
    fi
    
    if [ "$resp" == "200" ] || [ "$resp" == "201" ] || [ "$resp" == "202" ]; then
        PASS=$((PASS + 1))
        echo "✅ PASS [$resp] $name ($body_size bytes)"
    elif [ "$resp" == "422" ]; then
        WARN=$((WARN + 1))
        echo "⚠️  WARN [$resp] $name (validation — needs input)"
    elif [ "$resp" == "500" ]; then
        FAIL=$((FAIL + 1))
        echo "❌ FAIL [$resp] $name — SERVER ERROR"
        head -c 200 /tmp/tb.json
        echo ""
    elif [ "$resp" == "503" ]; then
        WARN=$((WARN + 1))
        echo "⚠️  WARN [$resp] $name (service unavailable — external dep)"
    else
        WARN=$((WARN + 1))
        echo "⚠️  WARN [$resp] $name ($body_size bytes)"
    fi
}

echo "═══════════════════════════════════════════════════════════"
echo "  FIXOPS ENTERPRISE INTEGRATION TEST SUITE v2"
echo "  $(date)"
echo "═══════════════════════════════════════════════════════════"

echo ""
echo "── 1. HEALTH & SYSTEM ─────────────────────────────────────"
test_ep "Health Check" GET "/api/v1/health"
test_ep "Ready Check" GET "/api/v1/ready"
test_ep "System Health" GET "/api/v1/system/health"
test_ep "System Config" GET "/api/v1/system/config"
test_ep "API Version" GET "/api/v1/version"
test_ep "Metrics" GET "/api/v1/metrics"

echo ""
echo "── 2. AUTHENTICATION ──────────────────────────────────────"
# Test valid key
resp=$(curl -s -o /dev/null -w "%{http_code}" "$API/api/v1/analytics/findings" -H "X-API-Key: $KEY" 2>/dev/null)
if [ "$resp" == "200" ]; then
    PASS=$((PASS + 1))
    echo "✅ PASS [$resp] Valid API key accepted"
else
    FAIL=$((FAIL + 1))
    echo "❌ FAIL [$resp] Valid API key rejected"
fi
# Test invalid key
resp=$(curl -s -o /dev/null -w "%{http_code}" "$API/api/v1/analytics/findings" -H "X-API-Key: invalid_key" 2>/dev/null)
if [ "$resp" == "401" ]; then
    PASS=$((PASS + 1))
    echo "✅ PASS [$resp] Invalid API key rejected"
else
    FAIL=$((FAIL + 1))
    echo "❌ FAIL [$resp] Invalid key NOT rejected"
fi
# Test no key
resp=$(curl -s -o /dev/null -w "%{http_code}" "$API/api/v1/inventory/apis" 2>/dev/null)
if [ "$resp" == "401" ]; then
    PASS=$((PASS + 1))
    echo "✅ PASS [$resp] Missing key rejected"
else
    FAIL=$((FAIL + 1))
    echo "❌ FAIL [$resp] Missing key NOT rejected"
fi

echo ""
echo "── 3. ANALYTICS & FINDINGS ────────────────────────────────"
test_ep "Analytics Findings" GET "/api/v1/analytics/findings"
test_ep "Analytics Coverage" GET "/api/v1/analytics/coverage"
test_ep "Analytics Summary" GET "/api/v1/analytics/summary"
test_ep "Analytics Timeline" GET "/api/v1/analytics/timeline"

echo ""
echo "── 4. INVENTORY / ASSETS ──────────────────────────────────"
test_ep "Inventory APIs" GET "/api/v1/inventory/apis"
test_ep "Inventory Assets" GET "/api/v1/inventory/assets"
test_ep "Inventory Summary" GET "/api/v1/inventory/summary"

echo ""
echo "── 5. RISK ENGINE ─────────────────────────────────────────"
test_ep "Risk Overview" GET "/api/v1/risk/"
test_ep "Risk Health" GET "/api/v1/risk/health"

echo ""
echo "── 6. COMPLIANCE ENGINE ───────────────────────────────────"
test_ep "Compliance Health" GET "/api/v1/compliance-engine/health"
test_ep "Compliance Frameworks" GET "/api/v1/compliance-engine/frameworks"
test_ep "Compliance Status" GET "/api/v1/compliance-engine/status"

echo ""
echo "── 7. ATTACK SIMULATION ───────────────────────────────────"
test_ep "Attack Campaigns" GET "/api/v1/attack-sim/campaigns"
test_ep "Attack Capabilities" GET "/api/v1/attack-sim/capabilities"
test_ep "Attack Health" GET "/api/v1/attack-sim/health"
test_ep "MITRE Techniques" GET "/api/v1/feeds/mitre/techniques"
test_ep "MITRE Health" GET "/api/v1/mitre/health"

echo ""
echo "── 8. SAST / DAST / CONTAINER ─────────────────────────────"
test_ep "SAST Health" GET "/api/v1/sast/health"
test_ep "SAST Rules" GET "/api/v1/sast/rules"
test_ep "DAST Health" GET "/api/v1/dast/health"
test_ep "Container Health" GET "/api/v1/container/health"

echo ""
echo "── 9. AUTOFIX ENGINE ──────────────────────────────────────"
test_ep "AutoFix Status" GET "/api/v1/autofix/status"
test_ep "AutoFix History" GET "/api/v1/autofix/history"
test_ep "AutoFix Confidence" GET "/api/v1/autofix/confidence-levels"

echo ""
echo "── 10. EVIDENCE & PROVENANCE ──────────────────────────────"
test_ep "Evidence List" GET "/api/v1/evidence/"
test_ep "Evidence Health" GET "/api/v1/evidence/health"
test_ep "Evidence Status" GET "/api/v1/evidence/status"
test_ep "Evidence Stats" GET "/api/v1/evidence/stats"
test_ep "Evidence Summary" GET "/api/v1/evidence/summary"
test_ep "Evidence Bundles" GET "/api/v1/evidence/bundles"
test_ep "Provenance List" GET "/api/v1/provenance/"
test_ep "Provenance Health" GET "/api/v1/provenance/health"
test_ep "Provenance Status" GET "/api/v1/provenance/status"
test_ep "Provenance Chains" GET "/api/v1/provenance/chains"

echo ""
echo "── 11. KNOWLEDGE GRAPH ────────────────────────────────────"
test_ep "Graph Overview" GET "/api/v1/graph/"
test_ep "Knowledge Graph Analytics" GET "/api/v1/knowledge-graph/analytics"
test_ep "Knowledge Graph Attack Paths" GET "/api/v1/knowledge-graph/attack-paths"
test_ep "Brain Edges" GET "/api/v1/brain/edges"
test_ep "Brain Status" GET "/api/v1/brain/health"

echo ""
echo "── 12. PIPELINE / REMEDIATION ─────────────────────────────"
test_ep "Remediation Backlog" GET "/api/v1/remediation/backlog"
test_ep "Remediation Metrics" GET "/api/v1/remediation/metrics"
test_ep "Workflows" GET "/api/v1/workflows"

echo ""
echo "── 13. CONNECTORS / INTEGRATIONS ──────────────────────────"
test_ep "Connectors List" GET "/api/v1/connectors"
test_ep "Connectors Health" GET "/api/v1/connectors/health"
test_ep "Scanner Ingest Health" GET "/api/v1/scanner-ingest/health"
test_ep "Scanner Formats" GET "/api/v1/scanner-ingest/detect"

echo ""
echo "── 14. AI / COPILOT ───────────────────────────────────────"
test_ep "AI Agent Backends" GET "/api/v1/ai-agent/backends"
test_ep "Predictions Attack Chain" GET "/api/v1/predictions/attack-chain"
test_ep "Copilot Agents Analysis" GET "/api/v1/copilot/agents/analyst/analyze"

echo ""
echo "── 15. MCP PROTOCOL ───────────────────────────────────────"
test_ep "MCP Discover" GET "/api/v1/mcp-protocol/discover"
test_ep "MCP Health" GET "/api/v1/mcp-protocol/health"
test_ep "MCP Tools" GET "/api/v1/mcp/tools"
test_ep "MCP Stats" GET "/api/v1/mcp/stats"
test_ep "MCP Categories" GET "/api/v1/mcp/categories"

echo ""
echo "── 16. ADVANCED ENGINES ───────────────────────────────────"
test_ep "Quantum Crypto Health" GET "/api/v1/quantum-crypto/health"
test_ep "Quantum Crypto Keys" GET "/api/v1/quantum-crypto/keys"
test_ep "Zero Gravity Health" GET "/api/v1/zero-gravity/health"
test_ep "Zero Gravity Forecast" GET "/api/v1/zero-gravity/forecast"
test_ep "Code-to-Cloud Status" GET "/api/v1/code-to-cloud/status"
test_ep "Dedup Clusters" GET "/api/v1/deduplication/clusters"
test_ep "Dedup Health" GET "/api/v1/deduplication/health"
test_ep "Air-Gap Status" GET "/api/v1/airgap/status"
test_ep "Air-Gap Health" GET "/api/v1/airgap/health"
test_ep "Self-Learning Status" GET "/api/v1/self-learning/status"
test_ep "Self-Learning Health" GET "/api/v1/self-learning/health"
test_ep "Nerve Center Map" GET "/api/v1/nerve-center/intelligence-map"
test_ep "LLM Monitor Analyze" GET "/api/v1/llm-monitor/analyze"
test_ep "CSPM Health" GET "/api/v1/cspm/health"
test_ep "CSPM Rules" GET "/api/v1/cspm/rules"
test_ep "API Fuzzer Status" GET "/api/v1/api-fuzzer/status"
test_ep "Malware Scan Health" GET "/api/v1/malware/health"
test_ep "Fuzzy Identity Canonical" GET "/api/v1/identity/canonical"

echo ""
echo "── 17. REPORTS & AUDIT ────────────────────────────────────"
test_ep "Reports List" GET "/api/v1/reports"
test_ep "Audit Controls" GET "/api/v1/audit/compliance/controls"
test_ep "Policies List" GET "/api/v1/policies"

echo ""
echo "── 18. MICRO-PENTEST ──────────────────────────────────────"
test_ep "Micro-Pentest Vectors" GET "/api/v1/micro-pentest/enterprise/attack-vectors"
test_ep "Micro-Pentest Health" GET "/api/v1/micro-pentest/health"

echo ""
echo "── 19. LOGS & STREAMING ───────────────────────────────────"
test_ep "Detailed Logs" GET "/api/v1/logs"
test_ep "Recent Logs" GET "/api/v1/logs/recent"
test_ep "SSE Health" GET "/api/v1/stream/health"

echo ""
echo "── 20. MARKETPLACE & COLLABORATION ────────────────────────"
test_ep "Marketplace Browse" GET "/api/v1/marketplace/browse"
test_ep "Collaboration Activities" GET "/api/v1/collaboration/activities"

echo ""
echo "── 21. APPS & TEAMS ───────────────────────────────────────"
test_ep "Apps List" GET "/api/v1/apps/"
test_ep "Apps Health" GET "/api/v1/apps/health"
test_ep "Teams List" GET "/api/v1/teams"
test_ep "Users List" GET "/api/v1/users"

echo ""
echo "── 22. FRONTEND SPA ───────────────────────────────────────"
spa_resp=$(curl -s -o /dev/null -w "%{http_code}" "$API/" 2>/dev/null)
spa_size=$(curl -s "$API/" 2>/dev/null | wc -c)
if [ "$spa_resp" == "200" ] && [ "$spa_size" -gt 500 ]; then
    PASS=$((PASS + 1))
    echo "✅ PASS [$spa_resp] SPA Index served ($spa_size bytes)"
else
    FAIL=$((FAIL + 1))
    echo "❌ FAIL [$spa_resp] SPA ($spa_size bytes)"
fi
# Check assets directory
assets_resp=$(curl -s -o /dev/null -w "%{http_code}" "$API/assets/" 2>/dev/null)
if [ "$assets_resp" == "200" ] || [ "$assets_resp" == "301" ] || [ "$assets_resp" == "307" ]; then
    PASS=$((PASS + 1))
    echo "✅ PASS [$assets_resp] Assets directory served"
else
    WARN=$((WARN + 1))
    echo "⚠️  WARN [$assets_resp] Assets directory"
fi

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  TEST RESULTS SUMMARY"
echo "═══════════════════════════════════════════════════════════"
echo "  ✅ PASSED:    $PASS"
echo "  ❌ FAILED:    $FAIL"
echo "  ⚠️  WARNINGS:  $WARN"
TOTAL=$((PASS + FAIL + WARN))
echo "  📊 TOTAL:     $TOTAL"
if [ "$TOTAL" -gt 0 ]; then
    RATE=$((PASS * 100 / TOTAL))
    echo "  📈 PASS RATE: ${RATE}%"
fi
echo "═══════════════════════════════════════════════════════════"

if [ "$FAIL" -gt 0 ]; then
    echo "  STATUS: ⚠️  SOME TESTS FAILED"
    exit 1
else
    echo "  STATUS: ✅ ALL TESTS PASSED"
    exit 0
fi
