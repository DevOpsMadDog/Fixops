#!/bin/bash
# FixOps Comprehensive API Test Script v2
# Tests all API endpoints based on actual OpenAPI spec

BASE_URL="http://localhost:8000"
API_KEY="${FIXOPS_API_TOKEN:?ERROR: FIXOPS_API_TOKEN must be set}"
HEADER="X-API-Key: $API_KEY"
RESULTS_FILE="/tmp/api_test_results_v2.json"
FAILED_FILE="/tmp/api_test_failures_v2.txt"

# Initialize results
echo '{"total": 0, "passed": 0, "failed": 0, "failures": []}' > $RESULTS_FILE
> $FAILED_FILE

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

test_endpoint() {
    local method=$1
    local endpoint=$2
    local data=$3
    local acceptable_codes=${4:-"200,201,204,422"}
    
    if [ -z "$data" ] || [ "$data" == "null" ]; then
        response=$(curl -s -w "\n%{http_code}" -X $method "$BASE_URL$endpoint" -H "$HEADER" -H "Content-Type: application/json" 2>/dev/null)
    else
        response=$(curl -s -w "\n%{http_code}" -X $method "$BASE_URL$endpoint" -H "$HEADER" -H "Content-Type: application/json" -d "$data" 2>/dev/null)
    fi
    
    status_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')
    
    # Update totals
    total=$(jq '.total' $RESULTS_FILE)
    passed=$(jq '.passed' $RESULTS_FILE)
    failed=$(jq '.failed' $RESULTS_FILE)
    
    # Check if status code is acceptable
    if echo ",$acceptable_codes," | grep -q ",$status_code,"; then
        echo -e "${GREEN}✓${NC} $method $endpoint - $status_code"
        jq ".total = $((total+1)) | .passed = $((passed+1))" $RESULTS_FILE > /tmp/tmp.json && mv /tmp/tmp.json $RESULTS_FILE
    else
        echo -e "${RED}✗${NC} $method $endpoint - $status_code"
        echo "  Response: $(echo "$body" | head -c 200)"
        echo "$method $endpoint - Status: $status_code - Response: $(echo "$body" | head -c 100)" >> $FAILED_FILE
        jq ".total = $((total+1)) | .failed = $((failed+1)) | .failures += [{\"endpoint\": \"$endpoint\", \"method\": \"$method\", \"status\": $status_code}]" $RESULTS_FILE > /tmp/tmp.json && mv /tmp/tmp.json $RESULTS_FILE
    fi
}

echo "=============================================="
echo "  FixOps Comprehensive API Test Suite v2"
echo "=============================================="
echo ""

# ============================================
# SECTION 1: HEALTH & CORE APIs
# ============================================
echo -e "${YELLOW}=== Section 1: Health & Core APIs ===${NC}"
test_endpoint "GET" "/health"
test_endpoint "GET" "/api/v1/health"
test_endpoint "GET" "/openapi.json"
test_endpoint "GET" "/api/v1/status"

# ============================================
# SECTION 2: ANALYTICS APIs
# ============================================
echo -e "${YELLOW}=== Section 2: Analytics APIs ===${NC}"
test_endpoint "GET" "/api/v1/analytics/dashboard/overview?org_id=test-org"
test_endpoint "GET" "/api/v1/analytics/dashboard/trends?org_id=test-org"
test_endpoint "GET" "/api/v1/analytics/dashboard/top-risks?org_id=test-org"
test_endpoint "GET" "/api/v1/analytics/dashboard/compliance-status"
test_endpoint "GET" "/api/v1/analytics/findings"
test_endpoint "GET" "/api/v1/analytics/decisions"
test_endpoint "GET" "/api/v1/analytics/coverage"
test_endpoint "GET" "/api/v1/analytics/mttr"
test_endpoint "GET" "/api/v1/analytics/roi"
test_endpoint "GET" "/api/v1/analytics/noise-reduction"
test_endpoint "POST" "/api/v1/analytics/custom-query" '{"query": "SELECT * FROM findings LIMIT 10"}'

# ============================================
# SECTION 3: AUDIT APIs
# ============================================
echo -e "${YELLOW}=== Section 3: Audit APIs ===${NC}"
test_endpoint "GET" "/api/v1/audit/logs"
test_endpoint "GET" "/api/v1/audit/decision-trail"
test_endpoint "GET" "/api/v1/audit/policy-changes"
test_endpoint "GET" "/api/v1/audit/user-activity?user_id=test-user"
test_endpoint "GET" "/api/v1/audit/compliance/frameworks"
test_endpoint "GET" "/api/v1/audit/compliance/controls"

# ============================================
# SECTION 4: FEEDS APIs
# ============================================
echo -e "${YELLOW}=== Section 4: Threat Feeds APIs ===${NC}"
test_endpoint "GET" "/api/v1/feeds/health"
test_endpoint "GET" "/api/v1/feeds/stats"
test_endpoint "GET" "/api/v1/feeds/sources"
test_endpoint "GET" "/api/v1/feeds/categories"
test_endpoint "GET" "/api/v1/feeds/epss"
test_endpoint "GET" "/api/v1/feeds/kev"
test_endpoint "GET" "/api/v1/feeds/exploits"
test_endpoint "GET" "/api/v1/feeds/exploits/CVE-2024-1234"
test_endpoint "GET" "/api/v1/feeds/threat-actors"
test_endpoint "GET" "/api/v1/feeds/threat-actors/CVE-2024-1234"
test_endpoint "GET" "/api/v1/feeds/supply-chain"
test_endpoint "GET" "/api/v1/feeds/supply-chain/lodash"
test_endpoint "GET" "/api/v1/feeds/scheduler/status"
test_endpoint "POST" "/api/v1/feeds/enrich" '{"cve_ids": ["CVE-2024-1234"], "include_epss": true, "include_kev": true}'
test_endpoint "GET" "/api/v1/feeds/exploit-confidence/CVE-2024-1234"
test_endpoint "GET" "/api/v1/feeds/geo-risk/CVE-2024-1234"

# ============================================
# SECTION 5: ENHANCED/LLM APIs
# ============================================
echo -e "${YELLOW}=== Section 5: Enhanced/LLM APIs ===${NC}"
test_endpoint "GET" "/api/v1/enhanced/capabilities"
test_endpoint "POST" "/api/v1/enhanced/analysis" '{"findings": [{"id": "test-1", "severity": "high", "description": "SQL Injection"}], "service_name": "test-api"}'
test_endpoint "POST" "/api/v1/enhanced/compare-llms" '{"service_name": "test-api", "security_findings": [{"rule_id": "SQL001", "severity": "high"}], "business_context": {"environment": "production"}}'
test_endpoint "GET" "/api/v1/enhanced/signals"

# ============================================
# SECTION 6: IAC SCANNER APIs
# ============================================
echo -e "${YELLOW}=== Section 6: IaC Scanner APIs ===${NC}"
test_endpoint "GET" "/api/v1/iac/scanners/status"
test_endpoint "GET" "/api/v1/iac"
test_endpoint "POST" "/api/v1/iac/scan/content" '{"content": "resource \"aws_s3_bucket\" \"test\" {\n  bucket = \"test\"\n  acl = \"public-read\"\n}", "filename": "main.tf"}'

# ============================================
# SECTION 7: SECRETS SCANNER APIs
# ============================================
echo -e "${YELLOW}=== Section 7: Secrets Scanner APIs ===${NC}"
test_endpoint "GET" "/api/v1/secrets/scanners/status"
test_endpoint "GET" "/api/v1/secrets"
test_endpoint "POST" "/api/v1/secrets/scan/content" '{"content": "API_KEY=sk_live_1234567890abcdef", "filename": "config.py"}'

# ============================================
# SECTION 8: MICRO PENTEST APIs
# ============================================
echo -e "${YELLOW}=== Section 8: Micro Pentest APIs ===${NC}"
test_endpoint "GET" "/api/v1/micro-pentest/enterprise/health"
test_endpoint "GET" "/api/v1/micro-pentest/enterprise/scans"
test_endpoint "GET" "/api/v1/micro-pentest/enterprise/attack-vectors"
test_endpoint "GET" "/api/v1/micro-pentest/enterprise/scan-modes"
test_endpoint "GET" "/api/v1/micro-pentest/enterprise/threat-categories"
test_endpoint "GET" "/api/v1/micro-pentest/enterprise/compliance-frameworks"
test_endpoint "POST" "/api/v1/micro-pentest/enterprise/scan" '{"name": "Test Scan", "attack_surface": {"name": "Test App", "target_url": "https://httpbin.org"}, "threat_model": {"name": "OWASP", "attack_vectors": ["sql_injection"]}}'
test_endpoint "POST" "/api/v1/micro-pentest/run" '{"cve_ids": ["CVE-2024-1234"], "target_urls": ["https://httpbin.org/get"]}'
test_endpoint "POST" "/api/v1/micro-pentest/batch" '{"scans": [{"cve_id": "CVE-2024-1234", "target": "https://httpbin.org/get"}]}'

# ============================================
# SECTION 9: DEDUPLICATION APIs
# ============================================
echo -e "${YELLOW}=== Section 9: Deduplication APIs ===${NC}"
test_endpoint "GET" "/api/v1/deduplication/stats"
test_endpoint "GET" "/api/v1/deduplication/clusters?org_id=test-org"
test_endpoint "GET" "/api/v1/deduplication/correlations"
test_endpoint "GET" "/api/v1/deduplication/graph?org_id=test-org"
test_endpoint "POST" "/api/v1/deduplication/process" '{"finding_id": "test-finding-1", "org_id": "test-org"}'
test_endpoint "POST" "/api/v1/deduplication/process/batch" '{"finding_ids": ["test-1", "test-2"], "org_id": "test-org"}'
test_endpoint "POST" "/api/v1/deduplication/correlate/cross-stage" '{"finding_ids": ["test-1", "test-2"]}'

# ============================================
# SECTION 10: BULK OPERATIONS APIs
# ============================================
echo -e "${YELLOW}=== Section 10: Bulk Operations APIs ===${NC}"
test_endpoint "GET" "/api/v1/bulk/jobs"
test_endpoint "POST" "/api/v1/bulk/findings/update" '{"finding_ids": ["test-1"], "updates": {"status": "resolved"}, "org_id": "test-org"}'
test_endpoint "POST" "/api/v1/bulk/findings/assign" '{"finding_ids": ["test-1"], "assignee_id": "user-1", "org_id": "test-org"}'
test_endpoint "POST" "/api/v1/bulk/export" '{"format": "json", "org_id": "test-org"}'

# ============================================
# SECTION 11: COLLABORATION APIs
# ============================================
echo -e "${YELLOW}=== Section 11: Collaboration APIs ===${NC}"
test_endpoint "GET" "/api/v1/collaboration/activity-types"
test_endpoint "GET" "/api/v1/collaboration/entity-types"
test_endpoint "GET" "/api/v1/collaboration/comments?entity_id=test-1"
test_endpoint "GET" "/api/v1/collaboration/activities?entity_id=test-1"
test_endpoint "GET" "/api/v1/collaboration/watchers?entity_id=test-1"
test_endpoint "GET" "/api/v1/collaboration/notifications/pending"

# ============================================
# SECTION 12: SSO/AUTH APIs
# ============================================
echo -e "${YELLOW}=== Section 12: SSO/Auth APIs ===${NC}"
test_endpoint "GET" "/api/v1/auth/sso"
test_endpoint "POST" "/api/v1/auth/sso" '{"name": "Test SSO", "provider": "okta", "client_id": "test-client", "client_secret": "test-secret", "issuer_url": "https://test.okta.com"}'

# ============================================
# SECTION 13: GRAPH APIs
# ============================================
echo -e "${YELLOW}=== Section 13: Graph APIs ===${NC}"
test_endpoint "GET" "/graph/"
test_endpoint "GET" "/api/v1/graph"
test_endpoint "GET" "/graph/anomalies"
test_endpoint "GET" "/graph/kev-components"

# ============================================
# SECTION 14: INVENTORY APIs
# ============================================
echo -e "${YELLOW}=== Section 14: Inventory APIs ===${NC}"
test_endpoint "GET" "/api/v1/inventory/applications"
test_endpoint "GET" "/api/v1/inventory/services"

# ============================================
# SECTION 15: MARKETPLACE APIs
# ============================================
echo -e "${YELLOW}=== Section 15: Marketplace APIs ===${NC}"
test_endpoint "GET" "/api/v1/marketplace/browse"
test_endpoint "GET" "/api/v1/marketplace/stats"
test_endpoint "GET" "/api/v1/marketplace/contributors"
test_endpoint "GET" "/api/v1/marketplace/recommendations"

# ============================================
# SECTION 16: POLICY APIs
# ============================================
echo -e "${YELLOW}=== Section 16: Policy APIs ===${NC}"
test_endpoint "GET" "/api/v1/policies"
test_endpoint "POST" "/api/v1/policies" '{"name": "test-policy", "rules": [{"severity": "critical", "action": "block"}], "description": "Test policy"}'

# ============================================
# SECTION 17: PROVENANCE APIs
# ============================================
echo -e "${YELLOW}=== Section 17: Provenance APIs ===${NC}"
test_endpoint "GET" "/provenance/"

# ============================================
# SECTION 18: REMEDIATION APIs
# ============================================
echo -e "${YELLOW}=== Section 18: Remediation APIs ===${NC}"
test_endpoint "GET" "/api/v1/remediation/metrics"
test_endpoint "GET" "/api/v1/remediation/statuses"
test_endpoint "GET" "/api/v1/remediation/tasks?org_id=test-org"
test_endpoint "POST" "/api/v1/remediation/sla/check" '{"finding_id": "test-1", "severity": "critical"}'

# ============================================
# SECTION 19: REPORTS APIs
# ============================================
echo -e "${YELLOW}=== Section 19: Reports APIs ===${NC}"
test_endpoint "GET" "/api/v1/reports"
test_endpoint "GET" "/api/v1/reports/stats"
test_endpoint "GET" "/api/v1/reports/templates/list"
test_endpoint "GET" "/api/v1/reports/schedules/list"
test_endpoint "GET" "/api/v1/reports/export/json"
test_endpoint "POST" "/api/v1/reports/export/csv" '{"org_id": "test-org"}'
test_endpoint "POST" "/api/v1/reports/schedule" '{"name": "Weekly Report", "schedule": "weekly", "format": "json", "org_id": "test-org"}'

# ============================================
# SECTION 20: TEAMS APIs
# ============================================
echo -e "${YELLOW}=== Section 20: Teams APIs ===${NC}"
test_endpoint "GET" "/api/v1/teams"
test_endpoint "POST" "/api/v1/teams" '{"name": "New Security Team", "description": "Main security team"}' "201,409"

# ============================================
# SECTION 21: USERS APIs
# ============================================
echo -e "${YELLOW}=== Section 21: Users APIs ===${NC}"
test_endpoint "GET" "/api/v1/users"
test_endpoint "POST" "/api/v1/users" '{"username": "testuser", "email": "test@example.com", "role": "analyst", "name": "Test User"}'

# ============================================
# SECTION 22: WORKFLOWS APIs
# ============================================
echo -e "${YELLOW}=== Section 22: Workflows APIs ===${NC}"
test_endpoint "GET" "/api/v1/workflows"
test_endpoint "POST" "/api/v1/workflows" '{"name": "Auto Remediation", "trigger": "finding_created", "steps": []}'

# ============================================
# SECTION 23: WEBHOOKS APIs
# ============================================
echo -e "${YELLOW}=== Section 23: Webhooks APIs ===${NC}"
test_endpoint "GET" "/api/v1/webhooks/mappings"
test_endpoint "GET" "/api/v1/webhooks/outbox"
test_endpoint "GET" "/api/v1/webhooks/outbox/stats"
test_endpoint "GET" "/api/v1/webhooks/outbox/pending"
test_endpoint "GET" "/api/v1/webhooks/events"
test_endpoint "GET" "/api/v1/webhooks/drift"
test_endpoint "POST" "/api/v1/webhooks/mappings" '{"source": "jira", "event_type": "issue_created", "handler": "create_finding"}'
test_endpoint "GET" "/api/v1/webhooks/alm/work-items"

# ============================================
# SECTION 24: INTEGRATIONS APIs
# ============================================
echo -e "${YELLOW}=== Section 24: Integrations APIs ===${NC}"
test_endpoint "GET" "/api/v1/integrations"
test_endpoint "POST" "/api/v1/integrations" '{"type": "jira", "name": "Jira Cloud", "config": {"url": "https://test.atlassian.net", "api_token": "test"}}'

# ============================================
# SECTION 25: EVIDENCE APIs
# ============================================
echo -e "${YELLOW}=== Section 25: Evidence APIs ===${NC}"
test_endpoint "GET" "/evidence/"
test_endpoint "POST" "/evidence/verify" '{"bundle_id": "test-bundle"}'

# ============================================
# SECTION 26: PENTAGI APIs
# ============================================
echo -e "${YELLOW}=== Section 26: PentAGI APIs ===${NC}"
test_endpoint "GET" "/api/v1/pentagi/configs"
test_endpoint "GET" "/api/v1/pentagi/requests"
test_endpoint "GET" "/api/v1/pentagi/results"
test_endpoint "GET" "/api/v1/pentagi/stats"
test_endpoint "POST" "/api/v1/pentagi/monitoring" '{"targets": ["https://httpbin.org"], "interval_minutes": 60}'
test_endpoint "POST" "/api/v1/pentagi/verify" '{"target_url": "https://httpbin.org"}'
test_endpoint "POST" "/api/v1/pentagi/scan/comprehensive" '{"target": "https://httpbin.org", "scan_type": "quick"}' "200,201,422,503"

# ============================================
# SECTION 27: INPUT/PIPELINE APIs
# ============================================
echo -e "${YELLOW}=== Section 27: Input/Pipeline APIs ===${NC}"
test_endpoint "POST" "/inputs/sbom" '{"bomFormat": "CycloneDX", "specVersion": "1.4", "components": [{"name": "test", "version": "1.0.0"}]}'
test_endpoint "POST" "/inputs/sarif" '{"version": "2.1.0", "runs": []}'
test_endpoint "POST" "/inputs/cve" '{"cves": []}'
test_endpoint "POST" "/inputs/design" '{"design": "test"}'
test_endpoint "POST" "/inputs/context" '{"context": {}}'
test_endpoint "POST" "/pipeline/run" '{"stages": ["sbom", "sarif"]}'
test_endpoint "POST" "/api/v1/validate/input" '{"type": "sbom", "content": {"bomFormat": "CycloneDX"}}'

# ============================================
# SECTION 28: IDE APIs
# ============================================
echo -e "${YELLOW}=== Section 28: IDE APIs ===${NC}"
test_endpoint "GET" "/api/v1/ide/status"
test_endpoint "GET" "/api/v1/ide/config"

# ============================================
# SUMMARY
# ============================================
echo ""
echo "=============================================="
echo -e "${YELLOW}  TEST SUMMARY${NC}"
echo "=============================================="

total=$(jq '.total' $RESULTS_FILE)
passed=$(jq '.passed' $RESULTS_FILE)
failed=$(jq '.failed' $RESULTS_FILE)

echo "Total Tests: $total"
echo -e "Passed: ${GREEN}$passed${NC}"
echo -e "Failed: ${RED}$failed${NC}"
echo ""

if [ "$failed" -gt 0 ]; then
    echo -e "${RED}Failed Endpoints:${NC}"
    cat $FAILED_FILE
fi

echo ""
echo "Detailed results saved to: $RESULTS_FILE"
echo "Failures list saved to: $FAILED_FILE"
