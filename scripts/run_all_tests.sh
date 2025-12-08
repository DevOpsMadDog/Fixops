#!/bin/bash
# Run All Tests for FixOps (Unit, Integration, E2E)

set -e

echo "🧪 FixOps Comprehensive Test Suite"
echo "=================================="

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

FAILED=0
PASSED=0

# Function to run test suite
run_test_suite() {
    local suite_name=$1
    local test_command=$2
    
    echo -e "\n${YELLOW}Running $suite_name...${NC}"
    
    if eval "$test_command"; then
        echo -e "${GREEN}✅ $suite_name passed${NC}"
        ((PASSED++))
        return 0
    else
        echo -e "${RED}❌ $suite_name failed${NC}"
        ((FAILED++))
        return 1
    fi
}

# 1. Unit Tests
run_test_suite "Unit Tests" "pytest tests/ -m 'unit' -v --tb=short -x"

# 2. Integration Tests
run_test_suite "Integration Tests" "pytest tests/ -m 'integration' -v --tb=short -x"

# 3. E2E Tests (with API server)
echo -e "\n${YELLOW}Starting API server for E2E tests...${NC}"
./scripts/start_api_server.sh > /tmp/fixops_server.log 2>&1 &
SERVER_PID=$!

# Wait for server
sleep 5
for i in {1..30}; do
    if curl -s http://localhost:8000/health > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Server is running${NC}"
        break
    fi
    sleep 1
done

# Run E2E tests
run_test_suite "E2E Tests" "pytest tests/e2e/ -v --tb=short -x"

# Cleanup
echo -e "\n${YELLOW}Stopping API server...${NC}"
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

# Summary
echo -e "\n${YELLOW}=================================="
echo "Test Summary"
echo "==================================${NC}"
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"

if [ $FAILED -eq 0 ]; then
    echo -e "\n${GREEN}✅ All tests passed!${NC}"
    exit 0
else
    echo -e "\n${RED}❌ Some tests failed${NC}"
    exit 1
fi
