#!/bin/bash
# Comprehensive Test Suite Runner for FixOps
# Runs all tests with coverage, performance, and quality checks

set -e

echo "🧪 FixOps Comprehensive Test Suite"
echo "=================================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test results
TESTS_PASSED=0
TESTS_FAILED=0

# Function to run tests
run_tests() {
    local test_type=$1
    local test_command=$2
    
    echo -e "\n${YELLOW}Running $test_type tests...${NC}"
    
    if eval "$test_command"; then
        echo -e "${GREEN}✅ $test_type tests passed${NC}"
        ((TESTS_PASSED++))
        return 0
    else
        echo -e "${RED}❌ $test_type tests failed${NC}"
        ((TESTS_FAILED++))
        return 1
    fi
}

# 1. Unit Tests
run_tests "Unit" "pytest tests/ -m 'unit' -v --cov --cov-report=term-missing"

# 2. Integration Tests
run_tests "Integration" "pytest tests/ -m 'integration' -v"

# 3. Performance Tests
run_tests "Performance" "pytest tests/ -m 'performance' -v --benchmark-only"

# 4. Security Tests
run_tests "Security" "pytest tests/ -m 'security' -v"

# 5. Code Quality
echo -e "\n${YELLOW}Running code quality checks...${NC}"
if pylint risk automation cli apps --disable=all --enable=E,F; then
    echo -e "${GREEN}✅ Code quality checks passed${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}❌ Code quality checks failed${NC}"
    ((TESTS_FAILED++))
fi

# 6. Type Checking
echo -e "\n${YELLOW}Running type checks...${NC}"
if mypy risk automation cli apps --ignore-missing-imports; then
    echo -e "${GREEN}✅ Type checks passed${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}❌ Type checks failed${NC}"
    ((TESTS_FAILED++))
fi

# 7. Security Linting
echo -e "\n${YELLOW}Running security linting...${NC}"
if bandit -r risk automation cli apps -f json -o bandit-report.json; then
    echo -e "${GREEN}✅ Security linting passed${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}❌ Security linting found issues${NC}"
    ((TESTS_FAILED++))
fi

# Summary
echo -e "\n${YELLOW}=================================="
echo "Test Summary"
echo "==================================${NC}"
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Failed: $TESTS_FAILED${NC}"

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "\n${GREEN}✅ All tests passed!${NC}"
    exit 0
else
    echo -e "\n${RED}❌ Some tests failed${NC}"
    exit 1
fi
