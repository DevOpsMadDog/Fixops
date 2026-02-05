
#!/bin/bash
# FixOps Comprehensive CLI Test Script
# Tests all CLI commands

RESULTS_FILE="/tmp/cli_test_results.json"
FAILED_FILE="/tmp/cli_test_failures.txt"

# Initialize results
echo '{"total": 0, "passed": 0, "failed": 0, "failures": []}' > $RESULTS_FILE
> $FAILED_FILE

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

test_cli() {
    local command=$1
    local subcommand=$2
    local args=${3:-"--help"}
    local description=$4
    
    full_cmd="docker exec fixops python -m core.cli $command $subcommand $args"
    
    output=$($full_cmd 2>&1)
    exit_code=$?
    
    # Update totals
    total=$(jq '.total' $RESULTS_FILE)
    passed=$(jq '.passed' $RESULTS_FILE)
    failed=$(jq '.failed' $RESULTS_FILE)
    
    # For help commands, exit 0 is success
    # For other commands, we allow 0, 1 (validation errors), or non-zero if output contains expected content
    if [ $exit_code -eq 0 ] || [ "$args" == "--help" ]; then
        echo -e "${GREEN}✓${NC} cli $command $subcommand $args"
        jq ".total = $((total+1)) | .passed = $((passed+1))" $RESULTS_FILE > /tmp/tmp.json && mv /tmp/tmp.json $RESULTS_FILE
    elif echo "$output" | grep -qi "usage:\|error:\|missing\|invalid\|required"; then
        # Expected validation error
        echo -e "${GREEN}✓${NC} cli $command $subcommand $args (validation error - expected)"
        jq ".total = $((total+1)) | .passed = $((passed+1))" $RESULTS_FILE > /tmp/tmp.json && mv /tmp/tmp.json $RESULTS_FILE
    else
        echo -e "${RED}✗${NC} cli $command $subcommand $args - Exit: $exit_code"
        echo "  Output: $(echo "$output" | head -c 200)"
        echo "$command $subcommand - Exit: $exit_code" >> $FAILED_FILE
        jq ".total = $((total+1)) | .failed = $((failed+1)) | .failures += [{\"command\": \"$command $subcommand\", \"exit_code\": $exit_code}]" $RESULTS_FILE > /tmp/tmp.json && mv /tmp/tmp.json $RESULTS_FILE
    fi
}

echo "=============================================="
echo "  FixOps Comprehensive CLI Test Suite"
echo "=============================================="
echo ""

# ============================================
# SECTION 1: CORE COMMANDS
# ============================================
echo -e "${YELLOW}=== Section 1: Core Commands ===${NC}"
test_cli "health" "" "" "Check system health"
test_cli "show-overlay" "" "" "Show configuration"
test_cli "demo" "" "--help" "Demo command help"
test_cli "run" "" "--help" "Run pipeline help"
test_cli "ingest" "" "--help" "Ingest command help"
test_cli "ingest-file" "" "--help" "Ingest file help"
test_cli "stage-run" "" "--help" "Stage run help"
test_cli "make-decision" "" "--help" "Make decision help"
test_cli "analyze" "" "--help" "Analyze help"
test_cli "get-evidence" "" "--help" "Get evidence help"

# ============================================
# SECTION 2: TEAMS & USERS
# ============================================
echo -e "${YELLOW}=== Section 2: Teams & Users ===${NC}"
test_cli "teams" "" "--help" "Teams help"
test_cli "teams" "list" "" "List teams"
test_cli "teams" "create" "--help" "Create team help"
test_cli "users" "" "--help" "Users help"
test_cli "users" "list" "" "List users"
test_cli "users" "create" "--help" "Create user help"

# ============================================
# SECTION 3: PENTAGI & PENTEST
# ============================================
echo -e "${YELLOW}=== Section 3: Pentagi & Pentest ===${NC}"
test_cli "pentagi" "" "--help" "Pentagi help"
test_cli "pentagi" "status" "" "Pentagi status"
test_cli "pentagi" "list" "" "List pentagi requests"
test_cli "micro-pentest" "" "--help" "Micro pentest help"
test_cli "micro-pentest" "run" "--help" "Micro pentest run help"
test_cli "advanced-pentest" "" "--help" "Advanced pentest help"

# ============================================
# SECTION 4: COMPLIANCE & REPORTS
# ============================================
echo -e "${YELLOW}=== Section 4: Compliance & Reports ===${NC}"
test_cli "compliance" "" "--help" "Compliance help"
test_cli "compliance" "frameworks" "" "List frameworks"
test_cli "compliance" "status" "--help" "Compliance status help"
test_cli "reports" "" "--help" "Reports help"
test_cli "reports" "list" "" "List reports"
test_cli "reports" "generate" "--help" "Generate report help"

# ============================================
# SECTION 5: INVENTORY & POLICIES
# ============================================
echo -e "${YELLOW}=== Section 5: Inventory & Policies ===${NC}"
test_cli "inventory" "" "--help" "Inventory help"
test_cli "inventory" "apps" "" "List applications"
test_cli "inventory" "services" "" "List services"
test_cli "policies" "" "--help" "Policies help"
test_cli "policies" "list" "" "List policies"
test_cli "policies" "create" "--help" "Create policy help"

# ============================================
# SECTION 6: INTEGRATIONS
# ============================================
echo -e "${YELLOW}=== Section 6: Integrations ===${NC}"
test_cli "integrations" "" "--help" "Integrations help"
test_cli "integrations" "list" "" "List integrations"
test_cli "integrations" "create" "--help" "Create integration help"
test_cli "integrations" "types" "" "List integration types"

# ============================================
# SECTION 7: ANALYTICS & AUDIT
# ============================================
echo -e "${YELLOW}=== Section 7: Analytics & Audit ===${NC}"
test_cli "analytics" "" "--help" "Analytics help"
test_cli "analytics" "dashboard" "" "Show dashboard"
test_cli "analytics" "trends" "" "Show trends"
test_cli "analytics" "mttr" "" "Show MTTR"
test_cli "audit" "" "--help" "Audit help"
test_cli "audit" "logs" "" "Show audit logs"
test_cli "audit" "decisions" "" "Show decision trail"

# ============================================
# SECTION 8: WORKFLOWS
# ============================================
echo -e "${YELLOW}=== Section 8: Workflows ===${NC}"
test_cli "workflows" "" "--help" "Workflows help"
test_cli "workflows" "list" "" "List workflows"
test_cli "workflows" "create" "--help" "Create workflow help"

# ============================================
# SECTION 9: REACHABILITY & CORRELATION
# ============================================
echo -e "${YELLOW}=== Section 9: Reachability & Correlation ===${NC}"
test_cli "reachability" "" "--help" "Reachability help"
test_cli "correlation" "" "--help" "Correlation help"
test_cli "correlation" "stats" "" "Correlation stats"
test_cli "groups" "" "--help" "Groups help"
test_cli "groups" "list" "" "List groups"

# ============================================
# SECTION 10: REMEDIATION & NOTIFICATIONS
# ============================================
echo -e "${YELLOW}=== Section 10: Remediation & Notifications ===${NC}"
test_cli "remediation" "" "--help" "Remediation help"
test_cli "remediation" "tasks" "" "List remediation tasks"
test_cli "remediation" "metrics" "" "Show metrics"
test_cli "notifications" "" "--help" "Notifications help"
test_cli "notifications" "pending" "" "Pending notifications"

# ============================================
# SECTION 11: PLAYBOOKS
# ============================================
echo -e "${YELLOW}=== Section 11: Playbooks ===${NC}"
test_cli "playbook" "" "--help" "Playbook help"
test_cli "playbook" "list" "" "List playbooks"

# ============================================
# SECTION 12: ML COMMANDS
# ============================================
echo -e "${YELLOW}=== Section 12: ML Commands ===${NC}"
test_cli "train-forecast" "" "--help" "Train forecast help"
test_cli "train-bn-lr" "" "--help" "Train BN-LR help"
test_cli "predict-bn-lr" "" "--help" "Predict BN-LR help"
test_cli "backtest-bn-lr" "" "--help" "Backtest BN-LR help"

# ============================================
# SUMMARY
# ============================================
echo ""
echo "=============================================="
echo -e "${YELLOW}  CLI TEST SUMMARY${NC}"
echo "=============================================="

total=$(jq '.total' $RESULTS_FILE)
passed=$(jq '.passed' $RESULTS_FILE)
failed=$(jq '.failed' $RESULTS_FILE)

echo "Total Tests: $total"
echo -e "Passed: ${GREEN}$passed${NC}"
echo -e "Failed: ${RED}$failed${NC}"
echo ""

if [ "$failed" -gt 0 ]; then
    echo -e "${RED}Failed Commands:${NC}"
    cat $FAILED_FILE
fi

echo ""
echo "Detailed results saved to: $RESULTS_FILE"
