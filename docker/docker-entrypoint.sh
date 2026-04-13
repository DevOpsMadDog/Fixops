#!/bin/bash
# ============================================
# ALdeci CTEM+ Platform — Docker Entrypoint
# ============================================
# Modes: api-only | interactive | enterprise | test-all | cli | shell | python | uvicorn | bash | pytest
# Env:   ALDECI_SEED_DEMO=1  — seed demo data on startup
#        FIXOPS_WORKERS=1|N|auto  — uvicorn (1) or gunicorn (N/auto)
# ============================================
set -e

# ─── Colors ──────────────────────────────────────────────────
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

# ─── SIGTERM handler ─────────────────────────────────────────
API_PID=""
_shutdown() {
    echo -e "\n${YELLOW}Caught SIGTERM — shutting down gracefully...${NC}"
    if [[ -n "${API_PID:-}" ]] && kill -0 "$API_PID" 2>/dev/null; then
        kill -SIGTERM "$API_PID"
        wait "$API_PID" 2>/dev/null || true
    fi
    echo -e "${GREEN}ALdeci shutdown complete.${NC}"
    exit 0
}
trap _shutdown SIGTERM SIGINT

# ─── Database initialization ─────────────────────────────────
run_db_init() {
    local data_dir="${FIXOPS_DATA_DIR:-/app/data}"
    echo -e "${CYAN}Initializing databases in ${data_dir}...${NC}"
    if python3 /app/scripts/init_databases.py --data-dir "$data_dir"; then
        echo -e "${GREEN}Database initialization complete.${NC}"
    else
        echo -e "${YELLOW}Warning: Some databases failed to initialize (non-fatal).${NC}"
    fi
}

# ─── Demo data seeding ───────────────────────────────────────
run_seed_demo() {
    if [[ "${ALDECI_SEED_DEMO:-0}" == "1" ]]; then
        echo -e "${CYAN}ALDECI_SEED_DEMO=1 — seeding demo data...${NC}"
        local seed_script="/app/scripts/seed_demo_data.py"
        if [[ -f "$seed_script" ]]; then
            if python3 "$seed_script"; then
                echo -e "${GREEN}Demo data seeded successfully.${NC}"
            else
                echo -e "${YELLOW}Warning: Demo data seeding failed (non-fatal).${NC}"
            fi
        else
            echo -e "${YELLOW}Warning: seed_demo_data.py not found at ${seed_script} — skipping.${NC}"
        fi
    fi
}

# ─── API server startup ──────────────────────────────────────
# Scaling:
#   FIXOPS_WORKERS=1     → uvicorn (single process, default)
#   FIXOPS_WORKERS=4     → gunicorn with 4 uvicorn workers
#   FIXOPS_WORKERS=auto  → gunicorn with (2 * CPU cores + 1) workers
start_api_server() {
    local log_level="${1:-${FIXOPS_LOG_LEVEL}}"
    local workers="${FIXOPS_WORKERS:-1}"
    echo -e "${YELLOW}Starting ALdeci API server (${FIXOPS_MODE} mode)...${NC}"
    local start_ts
    start_ts=$(date +%s)

    if [[ "$workers" == "1" ]]; then
        uvicorn apps.api.app:create_app \
            --factory \
            --host 0.0.0.0 \
            --port 8000 \
            --log-level "$log_level" &
    else
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

    echo -e "${CYAN}Waiting for API server to be ready...${NC}"
    local api_ready=false
    for i in {1..30}; do
        if curl -sf http://localhost:8000/health > /dev/null 2>&1; then
            local elapsed=$(( $(date +%s) - start_ts ))
            echo -e "${GREEN}API server ready in ${elapsed}s${NC}"
            api_ready=true
            break
        fi
        sleep 1
        echo -n "."
    done
    echo ""

    if [[ "$api_ready" != "true" ]]; then
        echo -e "${RED}ERROR: API server failed to start within 30 seconds${NC}"
        exit 1
    fi
}

# ─── Mode dispatch ────────────────────────────────────────────
case "${1:-api-only}" in
    api-only)
        run_db_init
        run_seed_demo
        start_api_server
        echo -e "${GREEN}API:     http://localhost:8000${NC}"
        echo -e "${GREEN}Health:  http://localhost:8000/health${NC}"
        echo -e "${GREEN}Docs:    http://localhost:8000/docs${NC}"
        wait $API_PID
        ;;
    interactive|"")
        run_db_init
        run_seed_demo
        start_api_server
        echo -e "${CYAN}Starting interactive tester...${NC}"
        exec /app/scripts/fixops-interactive.sh
        ;;
    enterprise)
        run_db_init
        run_seed_demo
        start_api_server
        export FIXOPS_API_URL="http://localhost:8000"
        exec /app/scripts/enterprise-e2e-demo.sh
        ;;
    test-all)
        run_db_init
        start_api_server
        export FIXOPS_RUN_ALL_TESTS=true
        exec /app/scripts/fixops-interactive.sh
        ;;
    cli)
        shift
        exec python -m core.cli "$@"
        ;;
    shell)
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
        if command -v "$1" > /dev/null 2>&1 || [[ -x "$1" ]]; then
            exec "$@"
        else
            echo -e "${RED}Unknown mode: $1${NC}"
            echo ""
            echo "Available modes:"
            echo "  api-only     — Start API (default; runs db init + optional seed)"
            echo "  interactive  — Start interactive API tester"
            echo "  enterprise   — Run enterprise E2E validation suite"
            echo "  test-all     — Run all API tests automatically"
            echo "  cli <args>   — Run FixOps CLI"
            echo "  shell        — Start a bash shell"
            echo "  python ...   — Pass through to python"
            echo "  pytest ...   — Pass through to pytest"
            echo ""
            echo "Environment:"
            echo "  ALDECI_SEED_DEMO=1   — Seed demo data on startup"
            echo "  FIXOPS_WORKERS=N     — Number of gunicorn workers (default: 1 = uvicorn)"
            exit 1
        fi
        ;;
esac
