#!/bin/bash
# Run End-to-End Tests for FixOps

set -e

echo "🧪 Running FixOps End-to-End Tests"
echo "=================================="

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Start API server in background
echo -e "${YELLOW}Starting API server...${NC}"
./scripts/start_api_server.sh &
SERVER_PID=$!

# Wait for server to start
echo -e "${YELLOW}Waiting for server to start...${NC}"
sleep 5

# Check if server is running
for i in {1..30}; do
    if curl -s http://localhost:8000/health > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Server is running${NC}"
        break
    fi
    if [ $i -eq 30 ]; then
        echo -e "${RED}❌ Server failed to start${NC}"
        kill $SERVER_PID 2>/dev/null || true
        exit 1
    fi
    sleep 1
done

# Run E2E tests
echo -e "${YELLOW}Running end-to-end tests...${NC}"
pytest tests/e2e/ -v -s --tb=short || TEST_EXIT_CODE=$?

# Cleanup
echo -e "${YELLOW}Stopping API server...${NC}"
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

# Exit with test result
if [ -z "$TEST_EXIT_CODE" ]; then
    echo -e "${GREEN}✅ All E2E tests passed${NC}"
    exit 0
else
    echo -e "${RED}❌ Some E2E tests failed${NC}"
    exit $TEST_EXIT_CODE
fi
