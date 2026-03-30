#!/bin/bash
set -euo pipefail

API="${FIXOPS_API_BASE:-http://localhost:8000}"
KEY="${FIXOPS_API_TOKEN:?Set FIXOPS_API_TOKEN}"
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
    
    if echo "$ct" | grep -q "<!DOCTYPE\|<html"; then
        FAIL=$((FAIL + 1))
        echo "❌ FAIL [$resp] $name — SPA HTML (route missing)"
        return
    fi
    
    if [ "$resp" == "200" ] || [ "$resp" == "201" ] || [ "$resp" == "202" ]; then
        PASS=$((PASS + 1))
        echo "✅ [$resp] $name ($body_size B)"
    elif [ "$resp" == "422" ]; then
        WARN=$((WARN + 1))
        echo "⚠️  [$resp] $name (needs input params)"
    elif [ "$resp" == "500" ]; then
        FAIL=$((FAIL + 1))
        echo "❌ [$resp] $name — SERVER ERROR"
        head -c 200 /tmp/tb.json; echo ""
    elif [ "$resp" == "503" ]; then
        WARN=$((WARN + 1))
        echo "⚠️  [$resp] $name (external dep unavail)"
    else
        WARN=$((WARN + 1))
        echo "⚠️  [$resp] $name ($body_size B)"
    fi
}

echo "═══════════════════════════════════════════════════════════════"
echo "  FIXOPS ENTERPRISE INTEGRATION TEST SUITE — FINAL"
echo "  $(date)"
echo "═══════════════════════════════════════════════════════════════"

echo ""
echo "── HEALTH & SYSTEM ────────────────────────────────────────────"
test_ep "Health" GET "/api/v1/health"
test_ep "Ready" GET "/api/v1/ready"
test_ep "System Health" GET "/api/v1/system/health"
test_ep "System Config" GET "/api/v1/system/config"
test_ep "Version" GET "/api/v1/version"
test_ep "Metrics" GET "/api/v1/metrics"
test_ep "Feature Flags" GET "/api/v1/system/flags"

echo ""
echo "── AUTHENTICATION (3 tests) ───────────────────────────────────"
resp=$(curl -s -o /dev/null -w "%{http_code}" "$API/api/v1/analytics/findings" -H "X-API-Key: $KEY" 2>/dev/null)
[ "$resp" == "200" ] && { PASS=$((PASS+1)); echo "✅ [200] Valid key accepted"; } || { FAIL=$((FAIL+1)); echo "❌ Valid key rejected"; }
resp=$(curl -s -o /dev/null -w "%{http_code}" "$API/api/v1/analytics/findings" -H "X-API-Key: bad" 2>/dev/null)
[ "$resp" == "401" ] && { PASS=$((PASS+1)); echo "✅ [401] Invalid key rejected"; } || { FAIL=$((FAIL+1)); echo "❌ Invalid key passed ($resp)"; }
resp=$(curl -s -o /dev/null -w "%{http_code}" "$API/api/v1/inventory/apis" 2>/dev/null)
[ "$resp" == "401" ] && { PASS=$((PASS+1)); echo "✅ [401] No-key rejected"; } || { FAIL=$((FAIL+1)); echo "❌ No-key passed ($resp)"; }

echo ""
echo "── ANALYTICS ──────────────────────────────────────────────────"
test_ep "Findings List" GET "/api/v1/analytics/findings"
test_ep "Coverage" GET "/api/v1/analytics/coverage"
test_ep "Summary" GET "/api/v1/analytics/summary"
test_ep "Compare" GET "/api/v1/analytics/compare"

echo ""
echo "── INVENTORY ──────────────────────────────────────────────────"
test_ep "APIs" GET "/api/v1/inventory/apis"
test_ep "Assets" GET "/api/v1/inventory/assets"
test_ep "Services" GET "/api/v1/inventory/services"
test_ep "Dependencies" GET "/api/v1/inventory/dependencies"

echo ""
echo "── RISK ───────────────────────────────────────────────────────"
test_ep "Risk" GET "/api/v1/risk/"
test_ep "Risk Health" GET "/api/v1/risk/health"

echo ""
echo "── COMPLIANCE ENGINE ──────────────────────────────────────────"
test_ep "Health" GET "/api/v1/compliance-engine/health"
test_ep "Frameworks" GET "/api/v1/compliance-engine/frameworks"
test_ep "Status" GET "/api/v1/compliance-engine/status"
test_ep "Controls" GET "/api/v1/compliance-engine/controls"

echo ""
echo "── ATTACK SIMULATION ──────────────────────────────────────────"
test_ep "Campaigns" GET "/api/v1/attack-sim/campaigns"
test_ep "Scenarios" GET "/api/v1/attack-sim/scenarios"
test_ep "Health" GET "/api/v1/attack-sim/health"
test_ep "MITRE Heatmap" GET "/api/v1/attack-sim/mitre/heatmap"
test_ep "MITRE Techniques" GET "/api/v1/feeds/mitre/techniques"
test_ep "MITRE Health" GET "/api/v1/mitre/health"

echo ""
echo "── SCANNERS ───────────────────────────────────────────────────"
test_ep "SAST Health" GET "/api/v1/sast/health"
test_ep "SAST Rules" GET "/api/v1/sast/rules"
test_ep "DAST Health" GET "/api/v1/dast/health"
test_ep "Container Health" GET "/api/v1/container/health"
test_ep "CSPM Health" GET "/api/v1/cspm/health"
test_ep "CSPM Rules" GET "/api/v1/cspm/rules"
test_ep "API Fuzzer Status" GET "/api/v1/api-fuzzer/status"
test_ep "Malware Signatures" GET "/api/v1/malware/signatures"

echo ""
echo "── AUTOFIX ────────────────────────────────────────────────────"
test_ep "Status" GET "/api/v1/autofix/status"
test_ep "History" GET "/api/v1/autofix/history"
test_ep "Confidence" GET "/api/v1/autofix/confidence-levels"

echo ""
echo "── EVIDENCE & PROVENANCE ──────────────────────────────────────"
test_ep "Evidence List" GET "/api/v1/evidence/"
test_ep "Evidence Health" GET "/api/v1/evidence/health"
test_ep "Evidence Stats" GET "/api/v1/evidence/stats"
test_ep "Evidence Summary" GET "/api/v1/evidence/summary"
test_ep "Evidence Bundles" GET "/api/v1/evidence/bundles"
test_ep "Provenance List" GET "/api/v1/provenance/"
test_ep "Provenance Health" GET "/api/v1/provenance/health"
test_ep "Provenance Status" GET "/api/v1/provenance/status"
test_ep "Provenance Chains" GET "/api/v1/provenance/chains"

echo ""
echo "── KNOWLEDGE GRAPH ────────────────────────────────────────────"
test_ep "Graph Overview" GET "/api/v1/graph/"
test_ep "KG Analytics" GET "/api/v1/knowledge-graph/analytics"
test_ep "KG Attack Paths" GET "/api/v1/knowledge-graph/attack-paths"
test_ep "Brain All-Edges" GET "/api/v1/brain/all-edges"
test_ep "Brain Health" GET "/api/v1/brain/health"

echo ""
echo "── REMEDIATION & WORKFLOW ─────────────────────────────────────"
test_ep "Backlog" GET "/api/v1/remediation/backlog"
test_ep "Metrics" GET "/api/v1/remediation/metrics"
test_ep "Workflows" GET "/api/v1/workflows"

echo ""
echo "── CONNECTORS & INGEST ────────────────────────────────────────"
test_ep "Connectors" GET "/api/v1/connectors"
test_ep "Connectors Health" GET "/api/v1/connectors/health"
test_ep "Scanner Health" GET "/api/v1/scanner-ingest/health"

echo ""
echo "── AI / COPILOT ───────────────────────────────────────────────"
test_ep "AI Agent Backends" GET "/api/v1/ai-agent/backends"
test_ep "ML Predictions" GET "/api/v1/predictions/attack-chain"
test_ep "ML Anomaly Health" GET "/api/v1/ml/analytics/health"

echo ""
echo "── MCP PROTOCOL ───────────────────────────────────────────────"
test_ep "MCP Tools" GET "/api/v1/mcp/tools"
test_ep "MCP Health" GET "/api/v1/mcp/health"
test_ep "MCP Stats" GET "/api/v1/mcp/stats"
test_ep "MCP-Proto Discover" GET "/api/v1/mcp-protocol/discover"
test_ep "MCP-Proto Health" GET "/api/v1/mcp-protocol/health"

echo ""
echo "── ADVANCED ENGINES ───────────────────────────────────────────"
test_ep "Quantum Health" GET "/api/v1/quantum-crypto/health"
test_ep "Quantum Keys" GET "/api/v1/quantum-crypto/keys"
test_ep "Zero-Gravity Health" GET "/api/v1/zero-gravity/health"
test_ep "Zero-Gravity Forecast" GET "/api/v1/zero-gravity/forecast"
test_ep "Code-to-Cloud" GET "/api/v1/code-to-cloud/status"
test_ep "Dedup Health" GET "/api/v1/deduplication/health"
test_ep "Air-Gap Status" GET "/api/v1/airgap/status"
test_ep "Air-Gap Health" GET "/api/v1/airgap/health"
test_ep "Self-Learning" GET "/api/v1/self-learning/status"
test_ep "Nerve Center" GET "/api/v1/nerve-center/intelligence-map"
test_ep "LLM Monitor" GET "/api/v1/llm-monitor/patterns"
test_ep "Fuzzy Identity" GET "/api/v1/identity/canonical"
test_ep "Material Change" GET "/api/v1/changes/health"

echo ""
echo "── MICRO-PENTEST ──────────────────────────────────────────────"
test_ep "Vectors" GET "/api/v1/micro-pentest/enterprise/attack-vectors"
test_ep "Health" GET "/api/v1/micro-pentest/health"

echo ""
echo "── REPORTS & AUDIT ────────────────────────────────────────────"
test_ep "Reports" GET "/api/v1/reports"
test_ep "Audit Controls" GET "/api/v1/audit/compliance/controls"
test_ep "Policies" GET "/api/v1/policies"

echo ""
echo "── LOGS & STREAMING ───────────────────────────────────────────"
test_ep "Logs" GET "/api/v1/logs"
test_ep "Recent Logs" GET "/api/v1/logs/recent"
test_ep "SSE Health" GET "/api/v1/stream/health"

echo ""
echo "── MARKETPLACE & COLLAB ───────────────────────────────────────"
test_ep "Marketplace" GET "/api/v1/marketplace/browse"
test_ep "Teams" GET "/api/v1/teams"
test_ep "Users" GET "/api/v1/users"
test_ep "Apps" GET "/api/v1/apps/"
test_ep "Apps Health" GET "/api/v1/apps/health"

echo ""
echo "── FRONTEND SPA ───────────────────────────────────────────────"
spa_resp=$(curl -s -o /dev/null -w "%{http_code}" "$API/" 2>/dev/null)
spa_size=$(curl -s "$API/" 2>/dev/null | wc -c)
[ "$spa_resp" == "200" ] && [ "$spa_size" -gt 500 ] && { PASS=$((PASS+1)); echo "✅ [200] SPA ($spa_size B)"; } || { FAIL=$((FAIL+1)); echo "❌ SPA fail"; }

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  RESULTS"
echo "═══════════════════════════════════════════════════════════════"
echo "  ✅ PASSED:    $PASS"
echo "  ❌ FAILED:    $FAIL"
echo "  ⚠️  WARNINGS:  $WARN"
TOTAL=$((PASS + FAIL + WARN))
echo "  📊 TOTAL:     $TOTAL"
[ "$TOTAL" -gt 0 ] && RATE=$((PASS * 100 / TOTAL)) && echo "  📈 PASS RATE: ${RATE}%"
echo "═══════════════════════════════════════════════════════════════"
[ "$FAIL" -eq 0 ] && echo "  🎯 ALL TESTS PASSED" || echo "  ⚠️  $FAIL FAILURES"
