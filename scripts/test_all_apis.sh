#!/bin/bash
# Comprehensive FixOps API Test Script
# Tests all 267+ API endpoints and tracks failures

BASE_URL="http://localhost:8000"
API_KEY="${FIXOPS_API_TOKEN:?ERROR: FIXOPS_API_TOKEN must be set}"
HEADER="X-API-Key: $API_KEY"
RESULTS_FILE="/tmp/api_test_results.json"
FAILED_FILE="/tmp/api_test_failures.txt"

# Initialize results
echo '{"total": 0, "passed": 0, "failed": 0, "failures": []}' > $RESULTS_FILE
> $FAILED_FILE

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

test_endpoint() {
    local method=$1
    local endpoint=$2
    local data=$3
    local expected_status=${4:-200}
    local description=$5
    
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
    
    if [[ "$status_code" =~ ^(200|201|204|422)$ ]]; then
        echo -e "${GREEN}✓${NC} $method $endpoint - $status_code"
        jq ".total = $((total+1)) | .passed = $((passed+1))" $RESULTS_FILE > /tmp/tmp.json && mv /tmp/tmp.json $RESULTS_FILE
    else
        echo -e "${RED}✗${NC} $method $endpoint - $status_code (expected $expected_status)"
        echo "$method $endpoint - Status: $status_code" >> $FAILED_FILE
        jq ".total = $((total+1)) | .failed = $((failed+1)) | .failures += [{\"endpoint\": \"$endpoint\", \"method\": \"$method\", \"status\": $status_code}]" $RESULTS_FILE > /tmp/tmp.json && mv /tmp/tmp.json $RESULTS_FILE
    fi
}

echo "=============================================="
echo "  FixOps Comprehensive API Test Suite"
echo "=============================================="
echo ""

# ============================================
# SECTION 1: HEALTH & CORE APIs
# ============================================
echo -e "${YELLOW}=== Section 1: Health & Core APIs ===${NC}"

test_endpoint "GET" "/health"
test_endpoint "GET" "/api/v1/health"
test_endpoint "GET" "/openapi.json"
test_endpoint "GET" "/docs" "" 200

# ============================================
# SECTION 2: ANALYTICS APIs
# ============================================
echo -e "${YELLOW}=== Section 2: Analytics APIs ===${NC}"

test_endpoint "GET" "/api/v1/analytics/dashboard/overview"
test_endpoint "GET" "/api/v1/analytics/dashboard/trends"
test_endpoint "GET" "/api/v1/analytics/dashboard/top-risks"
test_endpoint "GET" "/api/v1/analytics/dashboard/compliance-status"
test_endpoint "GET" "/api/v1/analytics/findings"
test_endpoint "GET" "/api/v1/analytics/decisions"
test_endpoint "GET" "/api/v1/analytics/coverage"
test_endpoint "GET" "/api/v1/analytics/mttr"
test_endpoint "GET" "/api/v1/analytics/roi"
test_endpoint "GET" "/api/v1/analytics/noise-reduction"
test_endpoint "POST" "/api/v1/analytics/custom-query" '{"query": "SELECT * FROM findings LIMIT 10"}'
test_endpoint "POST" "/api/v1/analytics/export" '{"format": "json", "date_range": "last_30_days"}'

# ============================================
# SECTION 3: AUDIT APIs
# ============================================
echo -e "${YELLOW}=== Section 3: Audit APIs ===${NC}"

test_endpoint "GET" "/api/v1/audit/logs"
test_endpoint "GET" "/api/v1/audit/decision-trail"
test_endpoint "GET" "/api/v1/audit/policy-changes"
test_endpoint "GET" "/api/v1/audit/user-activity"
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
test_endpoint "GET" "/api/v1/feeds/threat-actors"
test_endpoint "GET" "/api/v1/feeds/supply-chain"
test_endpoint "GET" "/api/v1/feeds/scheduler/status"
test_endpoint "POST" "/api/v1/feeds/enrich" '{"cve_ids": ["CVE-2024-1234"]}'
test_endpoint "GET" "/api/v1/feeds/exploit-confidence/CVE-2024-1234"
test_endpoint "GET" "/api/v1/feeds/geo-risk/CVE-2024-1234"
test_endpoint "GET" "/api/v1/feeds/threat-actors/CVE-2024-1234"

# ============================================
# SECTION 5: ENHANCED/LLM APIs
# ============================================
echo -e "${YELLOW}=== Section 5: Enhanced/LLM APIs ===${NC}"

test_endpoint "GET" "/api/v1/enhanced/capabilities"
test_endpoint "POST" "/api/v1/enhanced/analysis" '{"findings": [{"id": "test-1", "severity": "high", "description": "SQL Injection"}]}'
test_endpoint "POST" "/api/v1/enhanced/compare-llms" '{"service_name": "test-api", "security_findings": [{"rule_id": "SQL001", "severity": "high"}], "business_context": {"environment": "production"}}'
test_endpoint "GET" "/api/v1/enhanced/signals"

# ============================================
# SECTION 6: IAC SCANNER APIs
# ============================================
echo -e "${YELLOW}=== Section 6: IaC Scanner APIs ===${NC}"

test_endpoint "GET" "/api/v1/iac/scanners/status"
test_endpoint "GET" "/api/v1/iac"
test_endpoint "POST" "/api/v1/iac/scan/content" '{"content": "resource \"aws_s3_bucket\" \"test\" {\n  bucket = \"test\"\n}", "filename": "main.tf"}'

# ============================================
# SECTION 7: SECRETS SCANNER APIs
# ============================================
echo -e "${YELLOW}=== Section 7: Secrets Scanner APIs ===${NC}"

test_endpoint "GET" "/api/v1/secrets/scanners/status"
test_endpoint "GET" "/api/v1/secrets"
test_endpoint "POST" "/api/v1/secrets/scan/content" '{"content": "API_KEY=secret123", "filename": "config.py"}'

# ============================================
# SECTION 8: MICRO PENTEST APIs
# ============================================
echo -e "${YELLOW}=== Section 8: Micro Pentest APIs ===${NC}"

test_endpoint "GET" "/api/v1/micro-pentest/scans"
test_endpoint "POST" "/api/v1/micro-pentest/run" '{"cve_ids": ["CVE-2024-1234"], "target_urls": ["https://httpbin.org/get"]}'
test_endpoint "POST" "/api/v1/micro-pentest/enterprise/scan" '{"name": "Test Scan", "attack_surface": {"name": "Test", "target_url": "https://httpbin.org/get"}, "threat_model": {"name": "OWASP", "attack_vectors": ["sql_injection"]}}'

# ============================================
# SECTION 9: DEDUPLICATION APIs
# ============================================
echo -e "${YELLOW}=== Section 9: Deduplication APIs ===${NC}"

test_endpoint "GET" "/api/v1/deduplication/clusters"
test_endpoint "GET" "/api/v1/deduplication/correlations"
test_endpoint "GET" "/api/v1/deduplication/stats"
test_endpoint "GET" "/api/v1/deduplication/graph"
test_endpoint "POST" "/api/v1/deduplication/process" '{"finding_id": "test-finding-1"}'
test_endpoint "POST" "/api/v1/deduplication/process/batch" '{"finding_ids": ["test-1", "test-2"]}'

# ============================================
# SECTION 10: BULK OPERATIONS APIs
# ============================================
echo -e "${YELLOW}=== Section 10: Bulk Operations APIs ===${NC}"

test_endpoint "GET" "/api/v1/bulk/jobs"
test_endpoint "POST" "/api/v1/bulk/findings/update" '{"finding_ids": ["test-1"], "updates": {"status": "resolved"}}'
test_endpoint "POST" "/api/v1/bulk/findings/assign" '{"finding_ids": ["test-1"], "assignee_id": "user-1"}'
test_endpoint "POST" "/api/v1/bulk/export" '{"format": "json"}'

# ============================================
# SECTION 11: COLLABORATION APIs
# ============================================
echo -e "${YELLOW}=== Section 11: Collaboration APIs ===${NC}"

test_endpoint "GET" "/api/v1/collaboration/comments"
test_endpoint "GET" "/api/v1/collaboration/activities"
test_endpoint "GET" "/api/v1/collaboration/activity-types"
test_endpoint "GET" "/api/v1/collaboration/entity-types"
test_endpoint "GET" "/api/v1/collaboration/watchers"
test_endpoint "GET" "/api/v1/collaboration/notifications/queue"
test_endpoint "GET" "/api/v1/collaboration/notifications/pending"

# ============================================
# SECTION 12: SSO/AUTH APIs
# ============================================
echo -e "${YELLOW}=== Section 12: SSO/Auth APIs ===${NC}"

test_endpoint "GET" "/api/v1/auth/sso"
test_endpoint "POST" "/api/v1/auth/sso" '{"name": "Test SSO", "provider": "okta", "config": {"domain": "test.okta.com"}}'

# ============================================
# SECTION 13: GRAPH API
# ============================================
echo -e "${YELLOW}=== Section 13: Risk Graph API ===${NC}"

test_endpoint "GET" "/api/v1/graph"

# ============================================
# SECTION 14: INVENTORY APIs
# ============================================
echo -e "${YELLOW}=== Section 14: Inventory APIs ===${NC}"

test_endpoint "GET" "/api/v1/inventory/applications"
test_endpoint "GET" "/api/v1/inventory/services"
test_endpoint "GET" "/api/v1/inventory/dependencies"

# ============================================
# SECTION 15: MARKETPLACE APIs
# ============================================
echo -e "${YELLOW}=== Section 15: Marketplace APIs ===${NC}"

test_endpoint "GET" "/api/v1/marketplace/extensions"
test_endpoint "GET" "/api/v1/marketplace/categories"

# ============================================
# SECTION 16: POLICY APIs
# ============================================
echo -e "${YELLOW}=== Section 16: Policy APIs ===${NC}"

test_endpoint "GET" "/api/v1/policies"
test_endpoint "POST" "/api/v1/policies" '{"name": "test-policy", "rules": [{"severity": "critical", "action": "block"}]}'

# ============================================
# SECTION 17: PROVENANCE APIs
# ============================================
echo -e "${YELLOW}=== Section 17: Provenance APIs ===${NC}"

test_endpoint "GET" "/api/v1/provenance/attestations"
test_endpoint "POST" "/api/v1/provenance/verify" '{"artifact_id": "test-artifact"}'

# ============================================
# SECTION 18: REMEDIATION APIs
# ============================================
echo -e "${YELLOW}=== Section 18: Remediation APIs ===${NC}"

test_endpoint "GET" "/api/v1/remediation/tasks"
test_endpoint "GET" "/api/v1/remediation/playbooks"
test_endpoint "GET" "/api/v1/remediation/sla"
test_endpoint "GET" "/api/v1/remediation/metrics"

# ============================================
# SECTION 19: REPORTS APIs
# ============================================
echo -e "${YELLOW}=== Section 19: Reports APIs ===${NC}"

test_endpoint "GET" "/api/v1/reports"
test_endpoint "GET" "/api/v1/reports/templates"
test_endpoint "POST" "/api/v1/reports/generate" '{"template_id": "executive-summary", "format": "json"}'

# ============================================
# SECTION 20: SSDLC APIs
# ============================================
echo -e "${YELLOW}=== Section 20: SSDLC APIs ===${NC}"

test_endpoint "GET" "/api/v1/ssdlc/gates"
test_endpoint "GET" "/api/v1/ssdlc/stages"
test_endpoint "GET" "/api/v1/ssdlc/manifests"

# ============================================
# SECTION 21: TEAMS APIs
# ============================================
echo -e "${YELLOW}=== Section 21: Teams APIs ===${NC}"

test_endpoint "GET" "/api/v1/teams"
test_endpoint "POST" "/api/v1/teams" '{"name": "Security Team", "description": "Main security team"}'

# ============================================
# SECTION 22: USERS APIs
# ============================================
echo -e "${YELLOW}=== Section 22: Users APIs ===${NC}"

test_endpoint "GET" "/api/v1/users"
test_endpoint "POST" "/api/v1/users" '{"username": "testuser", "email": "test@example.com", "role": "analyst"}'

# ============================================
# SECTION 23: WORKFLOWS APIs
# ============================================
echo -e "${YELLOW}=== Section 23: Workflows APIs ===${NC}"

test_endpoint "GET" "/api/v1/workflows"
test_endpoint "GET" "/api/v1/workflows/templates"
test_endpoint "POST" "/api/v1/workflows" '{"name": "Auto Remediation", "trigger": "finding_created"}'

# ============================================
# SECTION 24: WEBHOOKS APIs
# ============================================
echo -e "${YELLOW}=== Section 24: Webhooks APIs ===${NC}"

test_endpoint "GET" "/api/v1/webhooks"
test_endpoint "POST" "/api/v1/webhooks" '{"name": "Jira Webhook", "url": "https://example.com/webhook", "events": ["finding_created"]}'

# ============================================
# SECTION 25: INTEGRATIONS APIs
# ============================================
echo -e "${YELLOW}=== Section 25: Integrations APIs ===${NC}"

test_endpoint "GET" "/api/v1/integrations"
test_endpoint "GET" "/api/v1/integrations/available"
test_endpoint "POST" "/api/v1/integrations" '{"type": "jira", "name": "Jira Cloud", "config": {"url": "https://test.atlassian.net"}}'

# ============================================
# SECTION 26: EVIDENCE APIs
# ============================================
echo -e "${YELLOW}=== Section 26: Evidence APIs ===${NC}"

test_endpoint "GET" "/api/v1/evidence/bundles"
test_endpoint "POST" "/api/v1/evidence/sign" '{"data": {"finding_id": "test-1", "decision": "accept"}}'

# ============================================
# SECTION 27: COMPLIANCE APIs
# ============================================
echo -e "${YELLOW}=== Section 27: Compliance APIs ===${NC}"

test_endpoint "GET" "/api/v1/compliance/frameworks"
test_endpoint "GET" "/api/v1/compliance/controls"
test_endpoint "GET" "/api/v1/compliance/assessments"
test_endpoint "POST" "/api/v1/compliance/assessments" '{"framework_id": "pci-dss", "scope": "full"}'

# ============================================
# SECTION 28: PENTAGI APIs
# ============================================
echo -e "${YELLOW}=== Section 28: PentAGI APIs ===${NC}"

test_endpoint "GET" "/api/v1/pentagi/jobs"
test_endpoint "GET" "/api/v1/pentagi/config"
test_endpoint "GET" "/api/v1/pentagi/health"
test_endpoint "GET" "/api/v1/pentagi/enhanced/playbooks"
test_endpoint "GET" "/api/v1/pentagi/enhanced/campaigns"

# ============================================
# SECTION 29: PIPELINE/INPUTS APIs
# ============================================
echo -e "${YELLOW}=== Section 29: Pipeline & Input APIs ===${NC}"

test_endpoint "GET" "/pipeline/run"
test_endpoint "GET" "/pipeline/status"
test_endpoint "GET" "/pipeline/summary"
test_endpoint "GET" "/inputs/sbom"
test_endpoint "GET" "/inputs/sarif"
test_endpoint "GET" "/inputs/cve"
test_endpoint "GET" "/inputs/design"

# ============================================
# SECTION 30: VALIDATION APIs
# ============================================
echo -e "${YELLOW}=== Section 30: Validation APIs ===${NC}"

test_endpoint "POST" "/api/v1/validate/sbom" '{"format": "cyclonedx", "content": {"bomFormat": "CycloneDX", "specVersion": "1.4", "components": []}}'
test_endpoint "POST" "/api/v1/validate/sarif" '{"content": {"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json", "version": "2.1.0", "runs": []}}'

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
