#!/bin/bash
# ============================================
# ALdeci CTEM+ Platform — Docker Entrypoint
# ============================================
# Modes: api-only | interactive | enterprise | test-all | cli | shell | python | uvicorn | bash | pytest
# ============================================
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
cat << 'BANNER'
     █████╗ ██╗     ██████╗ ███████╗ ██████╗██╗
    ██╔══██╗██║     ██╔══██╗██╔════╝██╔════╝██║
    ███████║██║     ██║  ██║█████╗  ██║     ██║
    ██╔══██║██║     ██║  ██║██╔══╝  ██║     ██║
    ██║  ██║███████╗██████╔╝███████╗╚██████╗██║
    ╚═╝  ╚═╝╚══════╝╚═════╝ ╚══════╝ ╚═════╝╚═╝
BANNER
echo -e "${NC}"
echo -e "${GREEN}ALdeci — CTEM+ Decision Intelligence Platform${NC}"
echo ""

# ─── Enterprise defaults ─────────────────────────────────────
export FIXOPS_MODE="${FIXOPS_MODE:-enterprise}"
export FIXOPS_LOG_LEVEL="${FIXOPS_LOG_LEVEL:-warning}"

if [[ -z "${FIXOPS_JWT_SECRET:-}" ]]; then
    export FIXOPS_JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
fi
if [[ -z "${FIXOPS_API_TOKEN:-}" ]]; then
    export FIXOPS_API_TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
    echo -e "${GREEN}Generated enterprise token: ${FIXOPS_API_TOKEN}${NC}"
fi

# ─── Helper: Start API server and wait for health ────────────
# Scaling:
#   FIXOPS_WORKERS=1          → uvicorn (single process, default)
#   FIXOPS_WORKERS=4          → gunicorn with 4 uvicorn workers
#   FIXOPS_WORKERS=auto       → gunicorn with (2 * CPU cores + 1) workers
#   Recommendation: 2-4 workers per CPU core for I/O-bound workloads
start_api_server() {
    local log_level="${1:-${FIXOPS_LOG_LEVEL}}"
    local workers="${FIXOPS_WORKERS:-1}"
    echo -e "${YELLOW}Starting ALdeci API server (${FIXOPS_MODE} mode)...${NC}"
    local start_ts=$(date +%s)

    if [[ "$workers" == "1" ]]; then
        # Single-process uvicorn (fastest startup, simplest debugging)
        uvicorn apps.api.app:create_app --factory --host 0.0.0.0 --port 8000 --log-level "$log_level" &
    else
        # Multi-worker gunicorn with uvicorn workers (production scaling)
        if [[ "$workers" == "auto" ]]; then
            workers=$(python3 -c "import os; print(os.cpu_count() * 2 + 1)")
        fi
        echo -e "${CYAN}Scaling: ${workers} gunicorn workers${NC}"
        gunicorn apps.api.app:create_app \
            --worker-class uvicorn.workers.UvicornWorker \
            --workers "$workers" \
            --bind 0.0.0.0:8000 \
            --timeout 120 \
            --graceful-timeout 30 \
            --keep-alive 5 \
            --access-logfile - \
            --error-logfile - \
            --log-level "$log_level" &
    fi
    API_PID=$!

    echo -e "${CYAN}Waiting for API server to be ready (up to 180s)...${NC}"
    local api_ready=false
    for i in {1..180}; do
        # Try both legacy /health and v1 /api/v1/health
        if curl -fs http://localhost:8000/api/v1/health > /dev/null 2>&1 \
           || curl -fs http://localhost:8000/health > /dev/null 2>&1; then
            local elapsed=$(($(date +%s) - start_ts))
            echo -e "${GREEN}API server ready in ${elapsed}s${NC}"
            api_ready=true
            break
        fi
        # Detect early process death so we don't wait the full 180s on a crashed proc
        if ! kill -0 "$API_PID" 2>/dev/null; then
            echo -e "${RED}ERROR: uvicorn process exited prematurely (PID $API_PID dead after ${i}s)${NC}"
            echo -e "${YELLOW}Check the logs above for the underlying Python traceback${NC}"
            exit 1
        fi
        sleep 1
        echo -n "."
    done
    echo ""

    if [[ "$api_ready" != "true" ]]; then
        echo -e "${YELLOW}WARN: API server didn't pass readiness probe within 180s — leaving it running${NC}"
        echo -e "${YELLOW}Fly.io healthcheck will continue probing via the LB${NC}"
    fi
}

# ─── Mode dispatch ────────────────────────────────────────────
case "${1:-interactive}" in
    api-only)
        # Primary mode for Docker Compose: start API and keep alive
        start_api_server
        echo -e "${CYAN}Running in API-only mode...${NC}"
        echo -e "${GREEN}API:     http://localhost:8000${NC}"
        echo -e "${GREEN}Health:  http://localhost:8000/health${NC}"
        echo -e "${GREEN}Docs:    http://localhost:8000/docs${NC}"
        echo -e "${YELLOW}Exec into container for interactive mode:${NC}"
        echo -e "${YELLOW}  docker exec -it <container> /app/scripts/fixops-interactive.sh${NC}"
        wait $API_PID
        ;;
    interactive|"")
        start_api_server
        echo -e "${CYAN}Starting interactive tester...${NC}"
        echo ""
        exec /app/scripts/fixops-interactive.sh
        ;;
    enterprise)
        start_api_server
        echo -e "${CYAN}Running enterprise E2E validation...${NC}"
        echo ""
        export FIXOPS_API_URL="http://localhost:8000"
        exec /app/scripts/enterprise-e2e-demo.sh
        ;;
    test-all)
        start_api_server
        echo -e "${CYAN}Running all API tests...${NC}"
        export FIXOPS_RUN_ALL_TESTS=true
        exec /app/scripts/fixops-interactive.sh
        ;;
    cli)
        shift
        echo -e "${CYAN}Running CLI command: $*${NC}"
        exec python -m core.cli "$@"
        ;;
    shell)
        echo -e "${CYAN}Starting shell...${NC}"
        exec /bin/bash
        ;;
    python)
        shift
        exec python "$@"
        ;;
    uvicorn)
        shift
        exec uvicorn "$@"
        ;;
    bash)
        shift
        exec bash "$@"
        ;;
    pytest)
        shift
        exec pytest "$@"
        ;;
    *)
        # Pass-through for executable commands (CI compatibility)
        if command -v "$1" > /dev/null 2>&1 || [[ -x "$1" ]]; then
            exec "$@"
        else
            echo -e "${RED}Unknown mode: $1${NC}"
            echo ""
            echo "Available modes:"
            echo "  api-only     — Start only the API server (default for compose)"
            echo "  interactive  — Start interactive API tester"
            echo "  enterprise   — Run enterprise E2E validation suite"
            echo "  test-all     — Run all API tests automatically"
            echo "  cli <args>   — Run FixOps CLI with arguments"
            echo "  shell        — Start a bash shell"
            echo "  python ...   — Pass through to python"
            echo "  pytest ...   — Pass through to pytest"
            echo ""
            echo "Or pass any executable command directly."
            exit 1
        fi
        ;;
esac
