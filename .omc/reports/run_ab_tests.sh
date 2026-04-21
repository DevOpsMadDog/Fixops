#!/bin/bash
# API Test Script for A-B routers
# Tests every endpoint in router files matching A-B alphabetically

BASE="http://localhost:8000"
KEY="fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_"
REPORT="/Users/devops.ai/fixops/Fixops/.omc/reports/api_test_batch_AB.md"
ORG="default"

PASS=0
FAIL=0
TOTAL=0

# Write header
cat > "$REPORT" << 'HEADER'
# API Test Report: A-B Routers
**Date**: 2026-04-22
**Target**: http://localhost:8000
**Auth**: X-API-Key header

| # | Method | Path | Status | Time (ms) | Pass/Fail |
|---|--------|------|--------|-----------|-----------|
HEADER

test_endpoint() {
    local METHOD="$1"
    local PATH="$2"
    local BODY="$3"
    TOTAL=$((TOTAL + 1))

    if [ "$METHOD" = "GET" ] || [ "$METHOD" = "DELETE" ]; then
        RESULT=$(curl -s -o /dev/null -w "%{http_code}|%{time_total}" \
            -X "$METHOD" \
            "${BASE}${PATH}?org_id=${ORG}" \
            -H "X-API-Key: ${KEY}" \
            -H "Content-Type: application/json" \
            --max-time 10 2>/dev/null)
    else
        RESULT=$(curl -s -o /dev/null -w "%{http_code}|%{time_total}" \
            -X "$METHOD" \
            "${BASE}${PATH}?org_id=${ORG}" \
            -H "X-API-Key: ${KEY}" \
            -H "Content-Type: application/json" \
            -d "${BODY:-{}}" \
            --max-time 10 2>/dev/null)
    fi

    STATUS=$(echo "$RESULT" | cut -d'|' -f1)
    TIME_SEC=$(echo "$RESULT" | cut -d'|' -f2)
    TIME_MS=$(echo "$TIME_SEC" | awk '{printf "%.0f", $1 * 1000}')

    if [ -z "$STATUS" ] || [ "$STATUS" = "000" ]; then
        STATUS="TIMEOUT"
        VERDICT="FAIL"
        FAIL=$((FAIL + 1))
    elif [ "$STATUS" -ge 200 ] && [ "$STATUS" -lt 500 ]; then
        VERDICT="PASS"
        PASS=$((PASS + 1))
    else
        VERDICT="FAIL"
        FAIL=$((FAIL + 1))
    fi

    echo "| ${TOTAL} | ${METHOD} | \`${PATH}\` | ${STATUS} | ${TIME_MS} | ${VERDICT} |" >> "$REPORT"
    echo "${TOTAL}. ${METHOD} ${PATH} -> ${STATUS} (${TIME_MS}ms) ${VERDICT}"
}

echo "=== Testing A-B Router Endpoints ==="
echo ""

# ============================================================
# access_anomaly_router.py - prefix: /api/v1/access-anomaly
# ============================================================
echo "--- access_anomaly_router.py ---"
test_endpoint GET "/api/v1/access-anomaly/"
test_endpoint POST "/api/v1/access-anomaly/events" '{"org_id":"default","username":"testuser","event_type":"login","source_ip":"10.0.0.1"}'
test_endpoint POST "/api/v1/access-anomaly/baseline" '{"org_id":"default","username":"testuser"}'
test_endpoint GET "/api/v1/access-anomaly/anomalies"
test_endpoint GET "/api/v1/access-anomaly/high-risk-users"
test_endpoint GET "/api/v1/access-anomaly/summary"

# ============================================================
# access_control_router.py - prefix: /api/v1/access-control
# ============================================================
echo "--- access_control_router.py ---"
test_endpoint POST "/api/v1/access-control/policies" '{"org_id":"default","name":"test-policy","resource":"server-1","action":"read","effect":"allow"}'
test_endpoint GET "/api/v1/access-control/policies"
test_endpoint GET "/api/v1/access-control/grants"
test_endpoint GET "/api/v1/access-control/check"
test_endpoint GET "/api/v1/access-control/stats"

# ============================================================
# access_governance_router.py - prefix: /api/v1/access-governance
# ============================================================
echo "--- access_governance_router.py ---"
test_endpoint GET "/api/v1/access-governance/"
test_endpoint POST "/api/v1/access-governance/entitlements" '{"org_id":"default","user_id":"user1","entitlement":"admin","resource":"db1"}'
test_endpoint POST "/api/v1/access-governance/sod/detect" '{"org_id":"default","user_id":"user1"}'
test_endpoint POST "/api/v1/access-governance/roles" '{"org_id":"default","name":"test-role","description":"Test role"}'
test_endpoint GET "/api/v1/access-governance/expiring"
test_endpoint GET "/api/v1/access-governance/summary"

# ============================================================
# access_matrix_router.py - prefix: /api/v1/access-matrix
# ============================================================
echo "--- access_matrix_router.py ---"
test_endpoint POST "/api/v1/access-matrix/rules" '{"org_id":"default","role":"admin","resource_type":"server","action":"read","effect":"allow"}'
test_endpoint GET "/api/v1/access-matrix/rules"
test_endpoint POST "/api/v1/access-matrix/check" '{"org_id":"default","role":"admin","resource_type":"server","action":"read"}'
test_endpoint GET "/api/v1/access-matrix/stats"
test_endpoint GET "/api/v1/access-matrix/matrix"

# ============================================================
# access_request_management_router.py - prefix: /api/v1/access-requests
# ============================================================
echo "--- access_request_management_router.py ---"
test_endpoint POST "/api/v1/access-requests/requests" '{"org_id":"default","requester":"user1","resource":"db1","access_type":"read","justification":"testing"}'
test_endpoint GET "/api/v1/access-requests/requests"
test_endpoint GET "/api/v1/access-requests/stats"

# ============================================================
# admin_router.py - prefix: /api/v1/admin
# ============================================================
echo "--- admin_router.py ---"
test_endpoint GET "/api/v1/admin/users"
test_endpoint POST "/api/v1/admin/users" '{"email":"test@test.com","username":"testuser","role":"viewer"}'
test_endpoint GET "/api/v1/admin/teams"
test_endpoint POST "/api/v1/admin/teams" '{"name":"test-team","description":"Test team"}'

# ============================================================
# agents_router.py - prefix: /api/v1/copilot/agents
# ============================================================
echo "--- agents_router.py ---"
test_endpoint POST "/api/v1/copilot/agents/analyst/analyze" '{"query":"test analysis","org_id":"default"}'
test_endpoint POST "/api/v1/copilot/agents/analyst/threat-intel" '{"query":"APT29","org_id":"default"}'
test_endpoint POST "/api/v1/copilot/agents/analyst/prioritize" '{"findings":[],"org_id":"default"}'
test_endpoint GET "/api/v1/copilot/agents/analyst/trending"
test_endpoint GET "/api/v1/copilot/agents/analyst/cve/CVE-2024-0001"
test_endpoint POST "/api/v1/copilot/agents/compliance/map-findings" '{"findings":[],"framework":"SOC2","org_id":"default"}'
test_endpoint GET "/api/v1/copilot/agents/compliance/dashboard"
test_endpoint POST "/api/v1/copilot/agents/remediation/generate-fix" '{"finding_id":"test","org_id":"default"}'
test_endpoint GET "/api/v1/copilot/agents/remediation/queue"
test_endpoint GET "/api/v1/copilot/agents/status"
test_endpoint GET "/api/v1/copilot/agents/health"

# ============================================================
# ai_governance_router.py - prefix: /api/v1/ai-governance
# ============================================================
echo "--- ai_governance_router.py ---"
test_endpoint POST "/api/v1/ai-governance/models" '{"org_id":"default","name":"gpt-4","model_type":"llm","owner":"ml-team"}'
test_endpoint GET "/api/v1/ai-governance/models"
test_endpoint POST "/api/v1/ai-governance/assessments" '{"org_id":"default","model_id":"m1","assessment_type":"bias","findings":[]}'
test_endpoint GET "/api/v1/ai-governance/assessments"
test_endpoint POST "/api/v1/ai-governance/incidents" '{"org_id":"default","model_id":"m1","incident_type":"bias","description":"test"}'
test_endpoint GET "/api/v1/ai-governance/incidents"
test_endpoint GET "/api/v1/ai-governance/stats"

# ============================================================
# ai_orchestrator_router.py - prefix: /api/v1/ai-orchestrator
# ============================================================
echo "--- ai_orchestrator_router.py ---"
test_endpoint POST "/api/v1/ai-orchestrator/tasks" '{"agent":"analyst","prompt":"test","org_id":"default"}'
test_endpoint GET "/api/v1/ai-orchestrator/tasks"
test_endpoint GET "/api/v1/ai-orchestrator/stats"

# ============================================================
# ai_powered_soc_router.py - prefix: /api/v1/ai-soc
# ============================================================
echo "--- ai_powered_soc_router.py ---"
test_endpoint POST "/api/v1/ai-soc/detections" '{"org_id":"default","title":"test detection","severity":"high","source":"siem"}'
test_endpoint GET "/api/v1/ai-soc/detections"
test_endpoint POST "/api/v1/ai-soc/models" '{"org_id":"default","name":"anomaly-v1","model_type":"anomaly","version":"1.0"}'
test_endpoint GET "/api/v1/ai-soc/models"
test_endpoint POST "/api/v1/ai-soc/automation" '{"org_id":"default","name":"auto-triage","trigger":"detection","action":"triage"}'
test_endpoint GET "/api/v1/ai-soc/automation"
test_endpoint GET "/api/v1/ai-soc/stats"

# ============================================================
# ai_security_advisor_router.py - prefix: /api/v1/ai-advisor
# ============================================================
echo "--- ai_security_advisor_router.py ---"
test_endpoint POST "/api/v1/ai-advisor/posture-review" '{"org_id":"default"}'
test_endpoint POST "/api/v1/ai-advisor/analyze-incident" '{"org_id":"default","incident_id":"test"}'
test_endpoint POST "/api/v1/ai-advisor/ask" '{"org_id":"default","question":"What is my risk?"}'
test_endpoint GET "/api/v1/ai-advisor/sessions"
test_endpoint GET "/api/v1/ai-advisor/recommendations"
test_endpoint GET "/api/v1/ai-advisor/stats"

# ============================================================
# airgap_router.py - prefix: /api/v1/airgap
# ============================================================
echo "--- airgap_router.py ---"
test_endpoint GET "/api/v1/airgap/status"
test_endpoint GET "/api/v1/airgap/health"
test_endpoint GET "/api/v1/airgap/fips/status"
test_endpoint GET "/api/v1/airgap/fips/algorithms"
test_endpoint GET "/api/v1/airgap/dependencies"
test_endpoint GET "/api/v1/airgap/vuln-db/info"
test_endpoint GET "/api/v1/airgap/threat-intel/info"
test_endpoint GET "/api/v1/airgap/updates/history"
test_endpoint POST "/api/v1/airgap/detect-isolation" '{}'
test_endpoint POST "/api/v1/airgap/enable" '{}'
test_endpoint POST "/api/v1/airgap/network-check" '{}'

# ============================================================
# alert_enrichment_router.py - prefix: /api/v1/alert-enrichment
# ============================================================
echo "--- alert_enrichment_router.py ---"
test_endpoint GET "/api/v1/alert-enrichment/"
test_endpoint POST "/api/v1/alert-enrichment/alerts" '{"org_id":"default","title":"test alert","severity":"high","source":"siem"}'
test_endpoint POST "/api/v1/alert-enrichment/sources" '{"org_id":"default","name":"virustotal","source_type":"threat_intel","api_key":"test"}'
test_endpoint GET "/api/v1/alert-enrichment/queue"
test_endpoint GET "/api/v1/alert-enrichment/summary"
test_endpoint GET "/api/v1/alert-enrichment/high-risk"

# ============================================================
# alert_triage_router.py - prefix: /api/v1/alert-triage
# ============================================================
echo "--- alert_triage_router.py ---"
test_endpoint GET "/api/v1/alert-triage/"
test_endpoint POST "/api/v1/alert-triage/alerts" '{"org_id":"default","title":"test alert","severity":"high","source":"siem"}'
test_endpoint GET "/api/v1/alert-triage/alerts"
test_endpoint GET "/api/v1/alert-triage/queue"
test_endpoint GET "/api/v1/alert-triage/stats"

# ============================================================
# alerting_notification_router.py - prefix: /api/v1/alerting
# ============================================================
echo "--- alerting_notification_router.py ---"
test_endpoint POST "/api/v1/alerting/policies" '{"org_id":"default","name":"critical-alert","severity_threshold":"critical","channels":["email"]}'
test_endpoint GET "/api/v1/alerting/policies"
test_endpoint POST "/api/v1/alerting/trigger" '{"org_id":"default","policy_id":"p1","title":"test","severity":"high"}'
test_endpoint GET "/api/v1/alerting/alerts"
test_endpoint GET "/api/v1/alerting/history"
test_endpoint GET "/api/v1/alerting/stats"

# ============================================================
# algorithmic_router.py - prefix: /api/v1/algorithms
# ============================================================
echo "--- algorithmic_router.py ---"
test_endpoint POST "/api/v1/algorithms/monte-carlo/quantify" '{"asset_value":1000000,"threat_frequency":0.1,"vulnerability_factor":0.5}'
test_endpoint POST "/api/v1/algorithms/causal/analyze" '{"events":[{"id":"1","type":"login_failure"}]}'
test_endpoint GET "/api/v1/algorithms/health"
test_endpoint GET "/api/v1/algorithms/status"
test_endpoint GET "/api/v1/algorithms/capabilities"

# ============================================================
# analytics_dashboard_router.py - prefix: /api/v1/analytics
# ============================================================
echo "--- analytics_dashboard_router.py ---"
test_endpoint GET "/api/v1/analytics/trends"
test_endpoint GET "/api/v1/analytics/mttr"
test_endpoint GET "/api/v1/analytics/mttd"
test_endpoint GET "/api/v1/analytics/severity"
test_endpoint GET "/api/v1/analytics/severity-trend"
test_endpoint GET "/api/v1/analytics/scanners"
test_endpoint GET "/api/v1/analytics/risk-trajectory"
test_endpoint GET "/api/v1/analytics/recurring"
test_endpoint GET "/api/v1/analytics/executive-summary"

# ============================================================
# analytics_engine_router.py - prefix: /api/v1/analytics-engine
# ============================================================
echo "--- analytics_engine_router.py ---"
test_endpoint GET "/api/v1/analytics-engine/summary"
test_endpoint GET "/api/v1/analytics-engine/asset-vuln"
test_endpoint GET "/api/v1/analytics-engine/threat-ioc"
test_endpoint GET "/api/v1/analytics-engine/compliance-trend"
test_endpoint GET "/api/v1/analytics-engine/executive"
test_endpoint GET "/api/v1/analytics-engine/domains"
test_endpoint GET "/api/v1/analytics-engine/query"

# ============================================================
# analytics_router.py - prefix: /api/v1/analytics
# ============================================================
echo "--- analytics_router.py ---"
test_endpoint GET "/api/v1/analytics/dashboard/overview"
test_endpoint GET "/api/v1/analytics/dashboard/summary"
test_endpoint GET "/api/v1/analytics/dashboard/severity"
test_endpoint GET "/api/v1/analytics/dashboard/scanners"
test_endpoint GET "/api/v1/analytics/dashboard/executive"
test_endpoint GET "/api/v1/analytics/overview"
test_endpoint GET "/api/v1/analytics/dashboard/trends"
test_endpoint GET "/api/v1/analytics/dashboard/top-risks"
test_endpoint GET "/api/v1/analytics/dashboard/compliance-status"
test_endpoint GET "/api/v1/analytics/findings"
test_endpoint POST "/api/v1/analytics/findings" '{"title":"test finding","severity":"high","source":"scanner"}'
test_endpoint GET "/api/v1/analytics/decisions"
test_endpoint GET "/api/v1/analytics/stats"
test_endpoint GET "/api/v1/analytics/summary"
test_endpoint GET "/api/v1/analytics/coverage"
test_endpoint GET "/api/v1/analytics/roi"
test_endpoint GET "/api/v1/analytics/noise-reduction"
test_endpoint GET "/api/v1/analytics/executive"
test_endpoint GET "/api/v1/analytics/risk-overview"
test_endpoint GET "/api/v1/analytics/sla"
test_endpoint GET "/api/v1/analytics/live-feed"
test_endpoint GET "/api/v1/analytics/false-positive-rate"

# ============================================================
# anomaly_ml_router.py - prefix: /api/v1/anomaly-ml
# ============================================================
echo "--- anomaly_ml_router.py ---"
test_endpoint POST "/api/v1/anomaly-ml/events" '{"metric":"cpu","value":95.0,"timestamp":"2026-04-22T00:00:00Z"}'
test_endpoint POST "/api/v1/anomaly-ml/detect/zscore" '{"metric":"cpu","threshold":3.0}'
test_endpoint POST "/api/v1/anomaly-ml/detect/isolation" '{"metric":"cpu"}'
test_endpoint POST "/api/v1/anomaly-ml/detect/timeseries" '{"metric":"cpu"}'
test_endpoint GET "/api/v1/anomaly-ml/groups"
test_endpoint GET "/api/v1/anomaly-ml/anomalies"
test_endpoint POST "/api/v1/anomaly-ml/feedback" '{"anomaly_id":"a1","is_true_positive":true}'

# ============================================================
# anomaly_router.py - prefix: /api/v1/anomalies
# ============================================================
echo "--- anomaly_router.py ---"
test_endpoint POST "/api/v1/anomalies/metrics" '{"metric_name":"cpu_usage","value":95.0,"org_id":"default"}'
test_endpoint POST "/api/v1/anomalies/detect" '{"org_id":"default"}'
test_endpoint GET "/api/v1/anomalies"
test_endpoint GET "/api/v1/anomalies/stats"

# ============================================================
# anti_phishing_router.py - prefix: /api/v1/anti-phishing
# ============================================================
echo "--- anti_phishing_router.py ---"
test_endpoint POST "/api/v1/anti-phishing/urls" '{"org_id":"default","url":"https://example.com","submitted_by":"user1"}'
test_endpoint GET "/api/v1/anti-phishing/urls"
test_endpoint POST "/api/v1/anti-phishing/simulations" '{"org_id":"default","name":"Q1 test","target_count":100}'
test_endpoint GET "/api/v1/anti-phishing/simulations"
test_endpoint GET "/api/v1/anti-phishing/stats"

# ============================================================
# api_abuse_detection_router.py - prefix: /api/v1/api-abuse
# ============================================================
echo "--- api_abuse_detection_router.py ---"
test_endpoint POST "/api/v1/api-abuse/endpoints" '{"org_id":"default","path":"/api/v1/test","method":"GET"}'
test_endpoint GET "/api/v1/api-abuse/endpoints"
test_endpoint POST "/api/v1/api-abuse/incidents" '{"org_id":"default","endpoint_id":"e1","abuse_type":"rate_limit","source_ip":"10.0.0.1"}'
test_endpoint GET "/api/v1/api-abuse/incidents"
test_endpoint POST "/api/v1/api-abuse/rules" '{"org_id":"default","name":"rate-limit","pattern":".*","threshold":100}'
test_endpoint GET "/api/v1/api-abuse/rules"
test_endpoint GET "/api/v1/api-abuse/stats"

# ============================================================
# api_analytics_router.py - prefix: /api/v1/api-analytics
# ============================================================
echo "--- api_analytics_router.py ---"
test_endpoint POST "/api/v1/api-analytics/calls" '{"endpoint":"/api/v1/test","method":"GET","status_code":200,"response_time_ms":50}'
test_endpoint GET "/api/v1/api-analytics/top-endpoints"
test_endpoint GET "/api/v1/api-analytics/slowest-endpoints"
test_endpoint GET "/api/v1/api-analytics/error-endpoints"
test_endpoint GET "/api/v1/api-analytics/usage-over-time"

# ============================================================
# api_discovery_router.py - prefix: /api/v1/api-discovery
# ============================================================
echo "--- api_discovery_router.py ---"
test_endpoint POST "/api/v1/api-discovery/endpoints" '{"org_id":"default","path":"/api/test","method":"GET","discovered_from":"traffic"}'
test_endpoint GET "/api/v1/api-discovery/endpoints"
test_endpoint POST "/api/v1/api-discovery/scans" '{"org_id":"default","scan_type":"traffic","target":"internal"}'
test_endpoint GET "/api/v1/api-discovery/changes"
test_endpoint GET "/api/v1/api-discovery/stats"

# ============================================================
# api_docs_router.py - prefix: /api/v1/docs
# ============================================================
echo "--- api_docs_router.py ---"
test_endpoint GET "/api/v1/docs/openapi.json"
test_endpoint GET "/api/v1/docs/postman.json"
test_endpoint GET "/api/v1/docs/summary"
test_endpoint GET "/api/v1/docs/stats"
test_endpoint GET "/api/v1/docs/endpoints"

# ============================================================
# api_fuzzer_router.py - prefix: /api/v1/api-fuzzer
# ============================================================
echo "--- api_fuzzer_router.py ---"
test_endpoint POST "/api/v1/api-fuzzer/discover" '{"target_url":"http://localhost:8000","org_id":"default"}'
test_endpoint GET "/api/v1/api-fuzzer/health"
test_endpoint GET "/api/v1/api-fuzzer/status"

# ============================================================
# api_gateway_router.py - prefix: /api/v1/gateway
# ============================================================
echo "--- api_gateway_router.py ---"
test_endpoint POST "/api/v1/gateway/check" '{"path":"/api/v1/test","method":"GET","ip":"10.0.0.1"}'
test_endpoint GET "/api/v1/gateway/rate-limits"
test_endpoint GET "/api/v1/gateway/ip-rules"
test_endpoint GET "/api/v1/gateway/analytics"
test_endpoint GET "/api/v1/gateway/version-stats"
test_endpoint GET "/api/v1/gateway/health"

# ============================================================
# api_gateway_security_router.py - prefix: /api/v1/api-gateway-security
# ============================================================
echo "--- api_gateway_security_router.py ---"
test_endpoint POST "/api/v1/api-gateway-security/gateways" '{"org_id":"default","name":"main-gw","provider":"aws"}'
test_endpoint GET "/api/v1/api-gateway-security/gateways"
test_endpoint POST "/api/v1/api-gateway-security/apis" '{"org_id":"default","gateway_id":"gw1","name":"payments","path_prefix":"/api/v1/payments"}'
test_endpoint GET "/api/v1/api-gateway-security/apis"
test_endpoint POST "/api/v1/api-gateway-security/events" '{"org_id":"default","api_id":"api1","event_type":"threat","details":"sql injection attempt"}'
test_endpoint GET "/api/v1/api-gateway-security/events"
test_endpoint GET "/api/v1/api-gateway-security/stats"

# ============================================================
# api_inventory_router.py - prefix: /api/v1/api-inventory
# ============================================================
echo "--- api_inventory_router.py ---"
test_endpoint POST "/api/v1/api-inventory/apis" '{"org_id":"default","name":"payments","api_type":"rest","auth_type":"api_key"}'
test_endpoint GET "/api/v1/api-inventory/apis"
test_endpoint GET "/api/v1/api-inventory/endpoints"
test_endpoint GET "/api/v1/api-inventory/stats"

# ============================================================
# api_security_engine_router.py - prefix: /api/v1/api-security-engine
# ============================================================
echo "--- api_security_engine_router.py ---"
test_endpoint POST "/api/v1/api-security-engine/endpoints" '{"org_id":"default","name":"test-api","path":"/api/test","method":"GET"}'
test_endpoint GET "/api/v1/api-security-engine/endpoints"
test_endpoint POST "/api/v1/api-security-engine/keys" '{"org_id":"default","name":"test-key","owner":"user1"}'
test_endpoint GET "/api/v1/api-security-engine/keys"
test_endpoint POST "/api/v1/api-security-engine/abuse-events" '{"org_id":"default","endpoint_id":"e1","event_type":"rate_limit"}'
test_endpoint GET "/api/v1/api-security-engine/abuse-events"
test_endpoint POST "/api/v1/api-security-engine/scans" '{"org_id":"default","endpoint_id":"e1"}'
test_endpoint GET "/api/v1/api-security-engine/scans"
test_endpoint GET "/api/v1/api-security-engine/stats"

# ============================================================
# api_security_router.py - prefix: /api/v1/api-security
# ============================================================
echo "--- api_security_router.py ---"
test_endpoint POST "/api/v1/api-security/scan" '{"target":"http://localhost:8000/api/v1/test"}'
test_endpoint GET "/api/v1/api-security/findings"
test_endpoint GET "/api/v1/api-security/inventory"
test_endpoint GET "/api/v1/api-security/auth-analysis"
test_endpoint GET "/api/v1/api-security/rate-limits"
test_endpoint GET "/api/v1/api-security/schema-issues"
test_endpoint GET "/api/v1/api-security/health"

# ============================================================
# api_threat_protection_router.py - prefix: /api/v1/api-threat-protection
# ============================================================
echo "--- api_threat_protection_router.py ---"
test_endpoint POST "/api/v1/api-threat-protection/rules" '{"org_id":"default","name":"sql-injection","threat_type":"injection","pattern":".*union.*select.*","action":"block"}'
test_endpoint GET "/api/v1/api-threat-protection/rules"
test_endpoint POST "/api/v1/api-threat-protection/events" '{"org_id":"default","rule_id":"r1","source_ip":"10.0.0.1","request_path":"/api/test"}'
test_endpoint GET "/api/v1/api-threat-protection/events"
test_endpoint GET "/api/v1/api-threat-protection/stats"

# ============================================================
# apikey_router.py - prefix: /api/v1/auth/keys
# ============================================================
echo "--- apikey_router.py ---"
test_endpoint POST "/api/v1/auth/keys" '{"name":"test-key","prefix":"test","org_id":"default"}'
test_endpoint GET "/api/v1/auth/keys"

# ============================================================
# app_config_router.py - prefix: /api/v1/apps
# ============================================================
echo "--- app_config_router.py ---"
test_endpoint GET "/api/v1/apps/health"
test_endpoint GET "/api/v1/apps/"

# ============================================================
# app_security_router.py - prefix: /api/v1/app-security
# ============================================================
echo "--- app_security_router.py ---"
test_endpoint GET "/api/v1/app-security/apps"
test_endpoint POST "/api/v1/app-security/apps" '{"org_id":"default","name":"web-app","app_type":"web","language":"python"}'
test_endpoint GET "/api/v1/app-security/scans"
test_endpoint GET "/api/v1/app-security/findings"
test_endpoint GET "/api/v1/app-security/stats"

# ============================================================
# application_risk_router.py - prefix: /api/v1/app-risk
# ============================================================
echo "--- application_risk_router.py ---"
test_endpoint POST "/api/v1/app-risk/applications" '{"org_id":"default","name":"web-app","app_type":"web","owner":"team1"}'
test_endpoint GET "/api/v1/app-risk/applications"
test_endpoint GET "/api/v1/app-risk/findings"
test_endpoint GET "/api/v1/app-risk/stats"

# ============================================================
# application_security_router.py - prefix: /api/v1/appsec
# ============================================================
echo "--- application_security_router.py ---"
test_endpoint POST "/api/v1/appsec/apps" '{"org_id":"default","name":"web-app","language":"python","repo_url":"https://github.com/test/app"}'
test_endpoint GET "/api/v1/appsec/apps"
test_endpoint GET "/api/v1/appsec/stats"

# ============================================================
# asset_criticality_router.py - prefix: /api/v1/asset-criticality
# ============================================================
echo "--- asset_criticality_router.py ---"
test_endpoint POST "/api/v1/asset-criticality/assets" '{"org_id":"default","name":"prod-db","asset_type":"database","business_unit":"engineering"}'
test_endpoint GET "/api/v1/asset-criticality/assets"
test_endpoint GET "/api/v1/asset-criticality/summary"

# ============================================================
# asset_group_router.py - prefix: /api/v1/asset-groups
# ============================================================
echo "--- asset_group_router.py ---"
test_endpoint POST "/api/v1/asset-groups/groups" '{"org_id":"default","name":"prod-servers","group_type":"environment","description":"Production servers"}'
test_endpoint GET "/api/v1/asset-groups/groups"
test_endpoint GET "/api/v1/asset-groups/stats"

# ============================================================
# asset_inventory_router.py - prefix: /api/v1/assets
# ============================================================
echo "--- asset_inventory_router.py ---"
test_endpoint GET "/api/v1/assets/stats"
test_endpoint GET "/api/v1/assets/unowned"
test_endpoint GET "/api/v1/assets/stale"
test_endpoint GET "/api/v1/assets/exposed"
test_endpoint GET "/api/v1/assets"
test_endpoint POST "/api/v1/assets" '{"hostname":"test-server","ip":"10.0.0.1","asset_type":"server","org_id":"default"}'

# ============================================================
# asset_lifecycle_router.py - prefix: /api/v1/asset-lifecycle
# ============================================================
echo "--- asset_lifecycle_router.py ---"
test_endpoint POST "/api/v1/asset-lifecycle/assets" '{"org_id":"default","name":"server-1","asset_type":"server","lifecycle_phase":"active"}'
test_endpoint GET "/api/v1/asset-lifecycle/assets"
test_endpoint GET "/api/v1/asset-lifecycle/stats"

# ============================================================
# asset_risk_calculator_router.py - prefix: /api/v1/asset-risk
# ============================================================
echo "--- asset_risk_calculator_router.py ---"
test_endpoint POST "/api/v1/asset-risk/assets" '{"org_id":"default","name":"prod-db","asset_type":"database"}'
test_endpoint GET "/api/v1/asset-risk/assets"
test_endpoint GET "/api/v1/asset-risk/scores"
test_endpoint GET "/api/v1/asset-risk/stats"

# ============================================================
# asset_tagging_router.py - prefix: /api/v1/asset-tags
# ============================================================
echo "--- asset_tagging_router.py ---"
test_endpoint POST "/api/v1/asset-tags/tags" '{"org_id":"default","name":"production","category":"environment"}'
test_endpoint GET "/api/v1/asset-tags/tags"
test_endpoint POST "/api/v1/asset-tags/assets" '{"org_id":"default","asset_id":"a1","name":"server-1","asset_type":"server"}'
test_endpoint GET "/api/v1/asset-tags/assets"
test_endpoint GET "/api/v1/asset-tags/stats"

# ============================================================
# attack_chain_router.py - prefix: /api/v1/attack-chains
# ============================================================
echo "--- attack_chain_router.py ---"
test_endpoint POST "/api/v1/attack-chains/chains" '{"org_id":"default","name":"lateral-movement","description":"test chain","kill_chain_phase":"exploitation"}'
test_endpoint GET "/api/v1/attack-chains/chains"
test_endpoint GET "/api/v1/attack-chains/stats"

# ============================================================
# attack_path_router.py - prefix: /api/v1/attack-paths
# ============================================================
echo "--- attack_path_router.py ---"
test_endpoint POST "/api/v1/attack-paths/nodes" '{"org_id":"default","hostname":"web-server","node_type":"server","is_entry_point":true}'
test_endpoint GET "/api/v1/attack-paths/nodes"
test_endpoint GET "/api/v1/attack-paths/stats"
test_endpoint GET "/api/v1/attack-paths/crown-jewels-at-risk"
test_endpoint GET "/api/v1/attack-paths/toxic-combinations"

# ============================================================
# attack_sim_router.py - prefix: /api/v1/attack-sim
# ============================================================
echo "--- attack_sim_router.py ---"
test_endpoint GET "/api/v1/attack-sim/scenarios"
test_endpoint GET "/api/v1/attack-sim/campaigns"
test_endpoint GET "/api/v1/attack-sim/mitre/heatmap"
test_endpoint GET "/api/v1/attack-sim/mitre/techniques"
test_endpoint GET "/api/v1/attack-sim/health"
test_endpoint GET "/api/v1/attack-sim/status"

# ============================================================
# attack_surface_engine_router.py - prefix: /api/v1/attack-surface-mgmt
# ============================================================
echo "--- attack_surface_engine_router.py ---"
test_endpoint POST "/api/v1/attack-surface-mgmt/assets" '{"org_id":"default","name":"web-server","asset_type":"server","exposure_type":"external"}'
test_endpoint GET "/api/v1/attack-surface-mgmt/assets"
test_endpoint GET "/api/v1/attack-surface-mgmt/exposures"
test_endpoint GET "/api/v1/attack-surface-mgmt/scans"
test_endpoint GET "/api/v1/attack-surface-mgmt/changes"
test_endpoint GET "/api/v1/attack-surface-mgmt/stats"

# ============================================================
# attack_surface_manager_router.py - prefix: /api/v1/attack-surface
# ============================================================
echo "--- attack_surface_manager_router.py ---"
test_endpoint GET "/api/v1/attack-surface/assets"
test_endpoint GET "/api/v1/attack-surface/score"
test_endpoint GET "/api/v1/attack-surface/exposed"
test_endpoint GET "/api/v1/attack-surface/shadow-it"
test_endpoint GET "/api/v1/attack-surface/paths"
test_endpoint GET "/api/v1/attack-surface/changes"
test_endpoint GET "/api/v1/attack-surface/certificates"
test_endpoint GET "/api/v1/attack-surface/prioritized"

# ============================================================
# attack_surface_mgmt_router.py - prefix: /api/v1/asm
# ============================================================
echo "--- attack_surface_mgmt_router.py ---"
test_endpoint POST "/api/v1/asm/assets" '{"org_id":"default","name":"server-1","asset_type":"server","exposure_type":"external"}'
test_endpoint GET "/api/v1/asm/assets"
test_endpoint GET "/api/v1/asm/exposures"
test_endpoint GET "/api/v1/asm/scans"
test_endpoint GET "/api/v1/asm/changes"
test_endpoint GET "/api/v1/asm/stats"

# ============================================================
# attack_surface_monitor_router.py - prefix: /api/v1/attack-surface/monitor
# ============================================================
echo "--- attack_surface_monitor_router.py ---"
test_endpoint POST "/api/v1/attack-surface/monitor/snapshot" '{"target":"example.com","org_id":"default"}'
test_endpoint GET "/api/v1/attack-surface/monitor/snapshots"

# ============================================================
# attack_surface_router.py - prefix: /api/v1/attack-surface
# (some paths overlap with attack_surface_manager_router)
# ============================================================
echo "--- attack_surface_router.py ---"
test_endpoint GET "/api/v1/attack-surface/summary"
test_endpoint GET "/api/v1/attack-surface/external"

# ============================================================
# audit_analytics_router.py - prefix: /api/v1/audit-analytics
# ============================================================
echo "--- audit_analytics_router.py ---"
test_endpoint POST "/api/v1/audit-analytics/ingest" '{"org_id":"default","actor":"user1","action":"login","resource":"web-app","timestamp":"2026-04-22T00:00:00Z"}'
test_endpoint GET "/api/v1/audit-analytics/search"
test_endpoint GET "/api/v1/audit-analytics/anomalies"
test_endpoint POST "/api/v1/audit-analytics/anomalies/detect" '{"org_id":"default"}'
test_endpoint GET "/api/v1/audit-analytics/retention-policy"

# ============================================================
# audit_management_router.py - prefix: /api/v1/audit-management
# ============================================================
echo "--- audit_management_router.py ---"
test_endpoint POST "/api/v1/audit-management/audits" '{"org_id":"default","title":"Q1 Audit","framework":"SOC2","auditor":"auditor1"}'
test_endpoint GET "/api/v1/audit-management/audits"
test_endpoint GET "/api/v1/audit-management/stats"

# ============================================================
# audit_router.py - prefix: /api/v1/audit
# ============================================================
echo "--- audit_router.py ---"
test_endpoint GET "/api/v1/audit/logs"
test_endpoint GET "/api/v1/audit/user-activity"
test_endpoint GET "/api/v1/audit/policy-changes"
test_endpoint GET "/api/v1/audit/decision-trail"
test_endpoint GET "/api/v1/audit/compliance/frameworks"
test_endpoint GET "/api/v1/audit/compliance/controls"
test_endpoint GET "/api/v1/audit/retention"

# ============================================================
# auth_router.py - prefix: /api/v1/auth
# ============================================================
echo "--- auth_router.py ---"
test_endpoint GET "/api/v1/auth/sso"
test_endpoint GET "/api/v1/auth/keys"
test_endpoint GET "/api/v1/auth/keys/expiring"

# ============================================================
# auto_evidence_router.py - prefix: /api/v1/auto-evidence
# ============================================================
echo "--- auto_evidence_router.py ---"
test_endpoint GET "/api/v1/auto-evidence/frameworks"
test_endpoint POST "/api/v1/auto-evidence/collect/audit-logs" '{"org_id":"default"}'
test_endpoint POST "/api/v1/auto-evidence/collect/scan-results" '{"org_id":"default"}'
test_endpoint GET "/api/v1/auto-evidence/coverage"
test_endpoint GET "/api/v1/auto-evidence/"

# ============================================================
# auto_pentest_router.py - prefix: /api/v1/auto-pentest
# ============================================================
echo "--- auto_pentest_router.py ---"
test_endpoint POST "/api/v1/auto-pentest/run" '{"target":"http://localhost:8000","org_id":"default"}'
test_endpoint GET "/api/v1/auto-pentest/health"

# ============================================================
# autofix_router.py - prefix: /api/v1/autofix
# ============================================================
echo "--- autofix_router.py ---"
test_endpoint POST "/api/v1/autofix/generate" '{"finding_id":"f1","org_id":"default"}'
test_endpoint GET "/api/v1/autofix/history"
test_endpoint GET "/api/v1/autofix/stats"
test_endpoint GET "/api/v1/autofix/health"
test_endpoint GET "/api/v1/autofix/status"
test_endpoint GET "/api/v1/autofix/fix-types"
test_endpoint GET "/api/v1/autofix/confidence-levels"
test_endpoint GET "/api/v1/autofix/queue"
test_endpoint GET "/api/v1/autofix/tasks"
test_endpoint GET "/api/v1/autofix/summary"

# ============================================================
# autofix_verify_router.py - prefix: /api/v1/autofix/verify
# ============================================================
echo "--- autofix_verify_router.py ---"
test_endpoint POST "/api/v1/autofix/verify" '{"fix_id":"f1","org_id":"default"}'
test_endpoint GET "/api/v1/autofix/verify/stats"

# ============================================================
# autonomous_remediation_router.py - prefix: /api/v1/autonomous-remediation
# ============================================================
echo "--- autonomous_remediation_router.py ---"
test_endpoint POST "/api/v1/autonomous-remediation/workflows" '{"org_id":"default","name":"auto-patch","trigger":"critical_vuln","action":"patch"}'
test_endpoint GET "/api/v1/autonomous-remediation/workflows"
test_endpoint POST "/api/v1/autonomous-remediation/playbooks" '{"org_id":"default","name":"patch-playbook","steps":["scan","patch","verify"]}'
test_endpoint GET "/api/v1/autonomous-remediation/playbooks"
test_endpoint GET "/api/v1/autonomous-remediation/stats"

# ============================================================
# awareness_campaign_router.py - prefix: /api/v1/awareness-campaigns
# ============================================================
echo "--- awareness_campaign_router.py ---"
test_endpoint POST "/api/v1/awareness-campaigns/campaigns" '{"org_id":"default","name":"Q1 Security","campaign_type":"phishing","target_audience":"all"}'
test_endpoint GET "/api/v1/awareness-campaigns/campaigns"
test_endpoint GET "/api/v1/awareness-campaigns/participations"
test_endpoint GET "/api/v1/awareness-campaigns/stats"

# ============================================================
# awareness_score_router.py - prefix: /api/v1/awareness-score
# ============================================================
echo "--- awareness_score_router.py ---"
test_endpoint POST "/api/v1/awareness-score/orgs/default/employees" '{"employee_id":"emp1","name":"John Doe","department":"engineering","email":"john@test.com"}'
test_endpoint GET "/api/v1/awareness-score/orgs/default/employees"
test_endpoint GET "/api/v1/awareness-score/orgs/default/scores"
test_endpoint GET "/api/v1/awareness-score/orgs/default/department-summary"
test_endpoint GET "/api/v1/awareness-score/orgs/default/stats"

# ============================================================
# aws_security_hub_router.py - prefix: /api/v1/scan/aws-security-hub
# ============================================================
echo "--- aws_security_hub_router.py ---"
test_endpoint GET "/api/v1/scan/aws-security-hub/status"
test_endpoint GET "/api/v1/scan/aws-security-hub/findings"
test_endpoint GET "/api/v1/scan/aws-security-hub/insights"
test_endpoint GET "/api/v1/scan/aws-security-hub/standards"
test_endpoint GET "/api/v1/scan/aws-security-hub/history"

# ============================================================
# azure_defender_router.py - prefix: /api/v1/scan/azure-defender
# ============================================================
echo "--- azure_defender_router.py ---"
test_endpoint GET "/api/v1/scan/azure-defender/status"
test_endpoint GET "/api/v1/scan/azure-defender/alerts"
test_endpoint GET "/api/v1/scan/azure-defender/secure-score"
test_endpoint GET "/api/v1/scan/azure-defender/recommendations"
test_endpoint GET "/api/v1/scan/azure-defender/history"

# ============================================================
# backup_router.py - prefix: /api/v1/backups
# ============================================================
echo "--- backup_router.py ---"
test_endpoint POST "/api/v1/backups" '{"backup_type":"full","target":"database","org_id":"default"}'
test_endpoint GET "/api/v1/backups"
test_endpoint GET "/api/v1/backups/schedules"
test_endpoint GET "/api/v1/backups/stats"

# ============================================================
# backup_validator_router.py - prefix: /api/v1/backup-dr
# ============================================================
echo "--- backup_validator_router.py ---"
test_endpoint POST "/api/v1/backup-dr/jobs" '{"name":"daily-backup","backup_type":"full","target":"database","schedule":"0 2 * * *","org_id":"default"}'
test_endpoint GET "/api/v1/backup-dr/jobs"
test_endpoint GET "/api/v1/backup-dr/rpo"
test_endpoint GET "/api/v1/backup-dr/verifications"
test_endpoint GET "/api/v1/backup-dr/dr-plans"
test_endpoint GET "/api/v1/backup-dr/dr-tests"
test_endpoint GET "/api/v1/backup-dr/geo-redundancy"
test_endpoint GET "/api/v1/backup-dr/bc-score"

# ============================================================
# bandwidth_analysis_router.py - prefix: /api/v1/bandwidth-analysis
# ============================================================
echo "--- bandwidth_analysis_router.py ---"
test_endpoint POST "/api/v1/bandwidth-analysis/links" '{"org_id":"default","name":"wan-link-1","capacity_mbps":1000,"link_type":"wan"}'
test_endpoint GET "/api/v1/bandwidth-analysis/links"
test_endpoint POST "/api/v1/bandwidth-analysis/qos-policies" '{"org_id":"default","name":"voip-priority","priority":1,"bandwidth_pct":30}'
test_endpoint GET "/api/v1/bandwidth-analysis/qos-policies"
test_endpoint GET "/api/v1/bandwidth-analysis/stats"

# ============================================================
# behavioral_analytics_router.py - prefix: /api/v1/behavioral-analytics
# ============================================================
echo "--- behavioral_analytics_router.py ---"
test_endpoint POST "/api/v1/behavioral-analytics/baselines" '{"org_id":"default","user_id":"user1","metric":"login_frequency","baseline_value":5.0}'
test_endpoint GET "/api/v1/behavioral-analytics/baselines"
test_endpoint POST "/api/v1/behavioral-analytics/anomalies" '{"org_id":"default","user_id":"user1","anomaly_type":"unusual_login","severity":"medium"}'
test_endpoint GET "/api/v1/behavioral-analytics/anomalies"
test_endpoint GET "/api/v1/behavioral-analytics/stats"

# ============================================================
# brain_router.py - prefix: /api/v1/brain
# ============================================================
echo "--- brain_router.py ---"
test_endpoint POST "/api/v1/brain/nodes" '{"org_id":"default","entity_type":"cve","entity_id":"CVE-2024-0001","label":"Test CVE","properties":{}}'
test_endpoint GET "/api/v1/brain/nodes"
test_endpoint GET "/api/v1/brain/all-edges"
test_endpoint GET "/api/v1/brain/stats"
test_endpoint GET "/api/v1/brain/most-connected"
test_endpoint GET "/api/v1/brain/events"
test_endpoint GET "/api/v1/brain/meta/entity-types"
test_endpoint GET "/api/v1/brain/meta/edge-types"
test_endpoint GET "/api/v1/brain/health"
test_endpoint GET "/api/v1/brain/pipeline/status"
test_endpoint GET "/api/v1/brain/status"
test_endpoint GET "/api/v1/brain/trends"

# ============================================================
# breach_detection_router.py - prefix: /api/v1/breach-detection
# ============================================================
echo "--- breach_detection_router.py ---"
test_endpoint POST "/api/v1/breach-detection/rules" '{"org_id":"default","name":"data-exfil","pattern":"large_outbound","severity":"critical"}'
test_endpoint GET "/api/v1/breach-detection/rules"
test_endpoint POST "/api/v1/breach-detection/events" '{"org_id":"default","rule_id":"r1","source":"network","details":"large outbound transfer"}'
test_endpoint GET "/api/v1/breach-detection/events"
test_endpoint GET "/api/v1/breach-detection/stats"

# ============================================================
# breach_response_router.py - prefix: /api/v1/breach-response
# ============================================================
echo "--- breach_response_router.py ---"
test_endpoint GET "/api/v1/breach-response/cases"
test_endpoint POST "/api/v1/breach-response/cases" '{"org_id":"default","title":"Data breach Q1","severity":"critical","breach_type":"data_exfiltration"}'
test_endpoint GET "/api/v1/breach-response/stats"

# ============================================================
# breach_simulation_router.py - prefix: /api/v1/breach-sim
# ============================================================
echo "--- breach_simulation_router.py ---"
test_endpoint POST "/api/v1/breach-sim/run" '{"scenario":"ransomware","org_id":"default"}'
test_endpoint GET "/api/v1/breach-sim/scenarios"
test_endpoint GET "/api/v1/breach-sim/health"

# ============================================================
# browser_security_router.py - prefix: /api/v1/browser-security
# ============================================================
echo "--- browser_security_router.py ---"
test_endpoint POST "/api/v1/browser-security/policies" '{"org_id":"default","name":"no-extensions","settings":{}}'
test_endpoint GET "/api/v1/browser-security/policies"
test_endpoint POST "/api/v1/browser-security/events" '{"org_id":"default","event_type":"malicious_download","browser":"chrome","user":"user1"}'
test_endpoint GET "/api/v1/browser-security/events"
test_endpoint POST "/api/v1/browser-security/extensions" '{"org_id":"default","name":"ad-blocker","extension_id":"ext1","browser":"chrome"}'
test_endpoint GET "/api/v1/browser-security/extensions"
test_endpoint GET "/api/v1/browser-security/stats"

# ============================================================
# bug_bounty_router.py - prefix: /api/v1/bounty
# ============================================================
echo "--- bug_bounty_router.py ---"
test_endpoint POST "/api/v1/bounty/programs" '{"org_id":"default","name":"web-app-bounty","scope":"*.example.com","min_bounty":100,"max_bounty":10000}'
test_endpoint GET "/api/v1/bounty/programs"
test_endpoint GET "/api/v1/bounty/submissions"

# ============================================================
# bulk_operations_router.py - prefix: /api/v1/bulk
# ============================================================
echo "--- bulk_operations_router.py ---"
test_endpoint GET "/api/v1/bulk/import-history"
test_endpoint GET "/api/v1/bulk/export-history"
test_endpoint GET "/api/v1/bulk/stats"

# ============================================================
# bulk_router.py - prefix: /api/v1/bulk
# ============================================================
echo "--- bulk_router.py ---"
test_endpoint GET "/api/v1/bulk/jobs"
test_endpoint GET "/api/v1/bulk/status"

# Write summary
echo "" >> "$REPORT"
echo "## Summary" >> "$REPORT"
echo "" >> "$REPORT"
echo "| Metric | Count |" >> "$REPORT"
echo "|--------|-------|" >> "$REPORT"
echo "| Total Endpoints Tested | ${TOTAL} |" >> "$REPORT"
echo "| Passed (2xx-4xx) | ${PASS} |" >> "$REPORT"
echo "| Failed (5xx/timeout) | ${FAIL} |" >> "$REPORT"
echo "| Pass Rate | $(echo "scale=1; $PASS * 100 / $TOTAL" | bc)% |" >> "$REPORT"
echo "" >> "$REPORT"
echo "**Legend**: PASS = 2xx/3xx/4xx (endpoint exists and responds). FAIL = 5xx or timeout (server error)." >> "$REPORT"
echo "" >> "$REPORT"
echo "Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')" >> "$REPORT"

echo ""
echo "=== DONE ==="
echo "Total: ${TOTAL} | Pass: ${PASS} | Fail: ${FAIL}"
echo "Report: ${REPORT}"
