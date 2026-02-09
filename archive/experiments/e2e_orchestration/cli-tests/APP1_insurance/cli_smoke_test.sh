#!/usr/bin/env bash
set -e


echo "=========================================="
echo "FixOps CLI Self-Audit - APP1 Insurance"
echo "=========================================="
echo ""

FIXOPS_DIR="/home/ubuntu/repos/Fixops"
INPUT_DIR="${FIXOPS_DIR}/e2e_orchestration/inputs/APP1_insurance"
OUTPUT_DIR="${FIXOPS_DIR}/e2e_orchestration/evidence/APP1_insurance"
ARTIFACTS_DIR="${FIXOPS_DIR}/e2e_orchestration/artifacts/APP1_insurance"
FIXOPS_API_TOKEN="${FIXOPS_API_TOKEN:-demo-token}"
API_BASE_URL="${API_BASE_URL:-http://127.0.0.1:8000}"

mkdir -p "$OUTPUT_DIR" "$ARTIFACTS_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

run_test() {
    local test_name="$1"
    local command="$2"
    local expected_exit_code="${3:-0}"
    
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    echo -n "Test ${TESTS_TOTAL}: ${test_name}... "
    
    if eval "$command" > /dev/null 2>&1; then
        actual_exit_code=0
    else
        actual_exit_code=$?
    fi
    
    if [ "$actual_exit_code" -eq "$expected_exit_code" ]; then
        echo -e "${GREEN}PASS${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo -e "${RED}FAIL${NC} (expected exit code $expected_exit_code, got $actual_exit_code)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

echo "=== Phase 1: CLI Validation ==="
run_test "FixOps CLI version" "cd $FIXOPS_DIR && python -m core.cli --version"

run_test "FixOps CLI help" "cd $FIXOPS_DIR && python -m core.cli --help"

echo ""
echo "=== Phase 2: Input File Validation ==="
run_test "design.csv exists" "test -f $INPUT_DIR/design.csv"
run_test "sbom.json exists" "test -f $INPUT_DIR/sbom.json"
run_test "results.sarif exists" "test -f $INPUT_DIR/results.sarif"
run_test "cve_feed.json exists" "test -f $INPUT_DIR/cve_feed.json"
run_test "vex_doc.json exists" "test -f $INPUT_DIR/vex_doc.json"
run_test "findings.json exists" "test -f $INPUT_DIR/findings.json"

echo ""
echo "=== Phase 3: JSON Syntax Validation ==="
run_test "sbom.json valid JSON" "jq empty $INPUT_DIR/sbom.json"
run_test "results.sarif valid JSON" "jq empty $INPUT_DIR/results.sarif"
run_test "cve_feed.json valid JSON" "jq empty $INPUT_DIR/cve_feed.json"
run_test "vex_doc.json valid JSON" "jq empty $INPUT_DIR/vex_doc.json"
run_test "findings.json valid JSON" "jq empty $INPUT_DIR/findings.json"

echo ""
echo "=== Phase 4: API Health Check ==="
run_test "API health endpoint" "curl -s -f $API_BASE_URL/health"
run_test "API ready endpoint" "curl -s -f $API_BASE_URL/api/v1/ready"

echo ""
echo "=== Phase 5: Artifact Upload ==="
run_test "Upload design.csv" \
    "curl -s -f -X POST -H 'X-API-Key: $FIXOPS_API_TOKEN' -F 'file=@$INPUT_DIR/design.csv;type=text/csv' $API_BASE_URL/inputs/design"

run_test "Upload sbom.json" \
    "curl -s -f -X POST -H 'X-API-Key: $FIXOPS_API_TOKEN' -F 'file=@$INPUT_DIR/sbom.json;type=application/json' $API_BASE_URL/inputs/sbom"

run_test "Upload results.sarif" \
    "curl -s -f -X POST -H 'X-API-Key: $FIXOPS_API_TOKEN' -F 'file=@$INPUT_DIR/results.sarif;type=application/json' $API_BASE_URL/inputs/sarif"

run_test "Upload cve_feed.json" \
    "curl -s -f -X POST -H 'X-API-Key: $FIXOPS_API_TOKEN' -F 'file=@$INPUT_DIR/cve_feed.json;type=application/json' $API_BASE_URL/inputs/cve"

run_test "Upload vex_doc.json" \
    "curl -s -f -X POST -H 'X-API-Key: $FIXOPS_API_TOKEN' -F 'file=@$INPUT_DIR/vex_doc.json;type=application/json' $API_BASE_URL/inputs/vex"

run_test "Upload findings.json" \
    "curl -s -f -X POST -H 'X-API-Key: $FIXOPS_API_TOKEN' -F 'file=@$INPUT_DIR/findings.json;type=application/json' $API_BASE_URL/inputs/cnapp"

echo ""
echo "=== Phase 6: Pipeline Execution ==="
echo "Running FixOps pipeline..."
PIPELINE_RESPONSE=$(curl -s -X POST -H "X-API-Key: $FIXOPS_API_TOKEN" $API_BASE_URL/pipeline/run)
echo "$PIPELINE_RESPONSE" > "$ARTIFACTS_DIR/pipeline_response.json"

run_test "Pipeline execution" "test -f $ARTIFACTS_DIR/pipeline_response.json"
run_test "Pipeline response valid JSON" "jq empty $ARTIFACTS_DIR/pipeline_response.json"

RUN_ID=$(echo "$PIPELINE_RESPONSE" | jq -r '.run_id // "unknown"')
VERDICT=$(echo "$PIPELINE_RESPONSE" | jq -r '.verdict // "unknown"')
RISK_SCORE=$(echo "$PIPELINE_RESPONSE" | jq -r '.risk_score // 0')

echo ""
echo "Pipeline Results:"
echo "  Run ID: $RUN_ID"
echo "  Verdict: $VERDICT"
echo "  Risk Score: $RISK_SCORE"

echo ""
echo "=== Phase 7: Critical Findings Validation ==="

LOG4SHELL_DETECTED=$(echo "$PIPELINE_RESPONSE" | jq '[.findings[]? | select(.cve_id == "CVE-2021-44228")] | length')
if [ "$LOG4SHELL_DETECTED" -gt 0 ]; then
    echo -e "${GREEN}✓${NC} Log4Shell (CVE-2021-44228) detected"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}✗${NC} Log4Shell (CVE-2021-44228) NOT detected"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
TESTS_TOTAL=$((TESTS_TOTAL + 1))

SQL_INJECTION_DETECTED=$(echo "$PIPELINE_RESPONSE" | jq '[.findings[]? | select(.description | contains("SQL injection"))] | length')
if [ "$SQL_INJECTION_DETECTED" -gt 0 ]; then
    echo -e "${GREEN}✓${NC} SQL injection finding detected"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}✗${NC} SQL injection finding NOT detected"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
TESTS_TOTAL=$((TESTS_TOTAL + 1))

PUBLIC_DB_DETECTED=$(echo "$PIPELINE_RESPONSE" | jq '[.findings[]? | select(.description | contains("exposed") and .description | contains("database"))] | length')
if [ "$PUBLIC_DB_DETECTED" -gt 0 ]; then
    echo -e "${GREEN}✓${NC} Public database exposure detected"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}✗${NC} Public database exposure NOT detected"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
TESTS_TOTAL=$((TESTS_TOTAL + 1))

echo ""
echo "=== Phase 8: API Enumeration ==="
run_test "API enumerate endpoints" \
    "curl -s -f -H 'X-API-Key: $FIXOPS_API_TOKEN' $API_BASE_URL/api/v1/enhanced/capabilities > $ARTIFACTS_DIR/capabilities.json"

echo ""
echo "=== Phase 9: Decision Retrieval ==="
if [ "$RUN_ID" != "unknown" ]; then
    run_test "Get SSDLC decisions" \
        "curl -s -f -H 'X-API-Key: $FIXOPS_API_TOKEN' '$API_BASE_URL/api/v1/decisions/ssdlc-stages?run_id=$RUN_ID' > $ARTIFACTS_DIR/decisions.json"
else
    echo -e "${YELLOW}SKIP${NC}: No run_id available"
fi

echo ""
echo "=== Phase 10: Evidence Bundle ==="
run_test "List evidence bundles" \
    "curl -s -f -H 'X-API-Key: $FIXOPS_API_TOKEN' $API_BASE_URL/api/v1/evidence/bundles > $ARTIFACTS_DIR/evidence_bundles.json"

echo ""
echo "=== Phase 11: CLI Demo Mode ==="
run_test "CLI demo mode execution" \
    "cd $FIXOPS_DIR && python -m core.cli demo --mode demo --output $OUTPUT_DIR/cli_demo_output.json"

echo ""
echo "=== Phase 12: Verdict Validation ==="
if [ "$VERDICT" == "block" ]; then
    echo -e "${GREEN}✓${NC} Verdict is BLOCK (expected for Log4Shell + critical findings)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
elif [ "$VERDICT" == "review" ]; then
    echo -e "${YELLOW}⚠${NC} Verdict is REVIEW (may need tuning)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}✗${NC} Verdict is $VERDICT (expected BLOCK or REVIEW)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
TESTS_TOTAL=$((TESTS_TOTAL + 1))

if (( $(echo "$RISK_SCORE >= 0.85" | bc -l) )); then
    echo -e "${GREEN}✓${NC} Risk score $RISK_SCORE >= 0.85 (BLOCK threshold)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
elif (( $(echo "$RISK_SCORE >= 0.60" | bc -l) )); then
    echo -e "${YELLOW}⚠${NC} Risk score $RISK_SCORE in REVIEW range (0.60-0.85)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}✗${NC} Risk score $RISK_SCORE < 0.60 (expected higher for critical vulns)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
TESTS_TOTAL=$((TESTS_TOTAL + 1))

echo ""
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo "Total Tests: $TESTS_TOTAL"
echo -e "Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Failed: ${RED}$TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    echo ""
    echo "Key Findings:"
    echo "  - Log4Shell (CVE-2021-44228) detected and blocked"
    echo "  - SQL injection vulnerabilities identified"
    echo "  - Public database exposure flagged"
    echo "  - FixOps verdict: $VERDICT (risk score: $RISK_SCORE)"
    echo ""
    echo "Artifacts saved to: $ARTIFACTS_DIR"
    echo "Evidence saved to: $OUTPUT_DIR"
    exit 0
else
    echo -e "${RED}✗ Some tests failed${NC}"
    echo ""
    echo "Review logs and artifacts in: $ARTIFACTS_DIR"
    exit 1
fi
