#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
cat << 'BANNER'
    ███████╗██╗██╗  ██╗ ██████╗ ██████╗ ███████╗
    ██╔════╝██║╚██╗██╔╝██╔═══██╗██╔══██╗██╔════╝
    █████╗  ██║ ╚███╔╝ ██║   ██║██████╔╝███████╗
    ██╔══╝  ██║ ██╔██╗ ██║   ██║██╔═══╝ ╚════██║
    ██║     ██║██╔╝ ██╗╚██████╔╝██║     ███████║
    ╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚══════╝
BANNER
echo -e "${NC}"
echo -e "${GREEN}Interactive API & CLI Testing Suite${NC}"
echo ""

# Check if we should start the API server
if [[ "${START_API_SERVER:-true}" == "true" ]]; then
    echo -e "${YELLOW}Starting FixOps API server in background...${NC}"
    uvicorn apps.api.app:app --host 0.0.0.0 --port 8000 --log-level warning &
    API_PID=$!
    
    # Wait for API to be ready
    echo -e "${CYAN}Waiting for API server to be ready...${NC}"
    API_READY=false
    for i in {1..30}; do
        if curl -s http://localhost:8000/health > /dev/null 2>&1; then
            echo -e "${GREEN}API server is ready!${NC}"
            API_READY=true
            break
        fi
        sleep 1
        echo -n "."
    done
    echo ""
    
    # Exit with error if API failed to start
    if [[ "$API_READY" != "true" ]]; then
        echo -e "${RED}ERROR: API server failed to start within 30 seconds${NC}"
        echo -e "${YELLOW}Check the logs above for errors${NC}"
        exit 1
    fi
fi

# Handle different modes
case "${1:-interactive}" in
    python)
        # Pass through python commands directly (for CI compatibility)
        shift
        exec python "$@"
        ;;
    uvicorn)
        # Pass through uvicorn commands directly
        shift
        exec uvicorn "$@"
        ;;
    interactive|"")
        echo -e "${CYAN}Starting interactive tester...${NC}"
        echo ""
        exec /app/scripts/fixops-interactive.sh
        ;;
    api-only)
        # In api-only mode, ensure API server is running regardless of START_API_SERVER setting
        if [[ -z "${API_PID:-}" ]]; then
            echo -e "${YELLOW}Starting API server for api-only mode...${NC}"
            uvicorn apps.api.app:app --host 0.0.0.0 --port 8000 --log-level warning &
            API_PID=$!
            # Wait for API to be ready
            API_READY=false
            for i in {1..30}; do
                if curl -s http://localhost:8000/health > /dev/null 2>&1; then
                    API_READY=true
                    break
                fi
                sleep 1
            done
            # Exit with error if API failed to start
            if [[ "$API_READY" != "true" ]]; then
                echo -e "${RED}ERROR: API server failed to start within 30 seconds${NC}"
                echo -e "${YELLOW}Check the logs above for errors${NC}"
                exit 1
            fi
        fi
        echo -e "${CYAN}Running in API-only mode...${NC}"
        echo -e "${GREEN}API server running at http://localhost:8000${NC}"
        echo -e "${YELLOW}Use 'docker exec -it <container> /app/scripts/fixops-interactive.sh' to start tester${NC}"
        wait $API_PID
        ;;
    demo)
        echo -e "${CYAN}Starting ALDECI demo runner...${NC}"
        echo ""
        exec /app/scripts/aldeci-demo-runner.sh
        ;;
    test-all)
        echo -e "${CYAN}Running all API tests...${NC}"
        export FIXOPS_RUN_ALL_TESTS=true
        exec /app/scripts/fixops-interactive.sh
        ;;
    cli)
        shift
        echo -e "${CYAN}Running CLI command: $@${NC}"
        exec python -m core.cli "$@"
        ;;
    shell)
        echo -e "${CYAN}Starting shell...${NC}"
        exec /bin/bash
        ;;
    *)
        echo -e "${RED}Unknown mode: $1${NC}"
        echo ""
        echo "Available modes:"
        echo "  interactive  - Start interactive API tester (default)"
        echo "  api-only     - Start only the API server"
        echo "  demo         - Start ALDECI animated demo runner"
        echo "  test-all     - Run all API tests automatically"
        echo "  cli <args>   - Run FixOps CLI with arguments"
        echo "  shell        - Start a bash shell"
        exit 1
        ;;
esac
