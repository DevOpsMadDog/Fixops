#!/usr/bin/env bash
# =============================================================================
# ALDECI — Local Development Setup (no Docker)
# =============================================================================
# Usage:
#   ./scripts/deploy_local.sh                   # full local dev setup
#   ./scripts/deploy_local.sh --no-seed         # skip demo data seeding
#   ./scripts/deploy_local.sh --no-browser      # don't open browser on finish
#   ./scripts/deploy_local.sh --no-frontend     # API only, skip UI dev server
#   ./scripts/deploy_local.sh --stop            # kill running dev servers
#
# Idempotent: safe to re-run.
#   - venv is reused if it exists
#   - pip install is skipped if packages already satisfy requirements.txt
#   - demo data seed is idempotent (engines skip duplicates)
#
# Ports:
#   API  → http://localhost:8000
#   UI   → http://localhost:5173   (Vite dev server)
#
# Prerequisites:
#   - python3.11 (or python3 >= 3.11)
#   - node >= 18 + npm  (for UI)
# =============================================================================
set -euo pipefail

# ── Script location so relative paths always resolve correctly ────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
UI_DIR="${REPO_ROOT}/suite-ui/aldeci-ui-new"
VENV_DIR="${REPO_ROOT}/.venv"
PID_FILE="${REPO_ROOT}/.aldeci-dev.pids"
LOG_DIR="${REPO_ROOT}/.aldeci-dev-logs"
ENV_LOCAL="${REPO_ROOT}/.env.local"

# ── CLI flags ─────────────────────────────────────────────────────────────────
DO_SEED=true
DO_BROWSER=true
DO_FRONTEND=true
DO_STOP=false

for arg in "$@"; do
    case "$arg" in
        --no-seed)     DO_SEED=false ;;
        --no-browser)  DO_BROWSER=false ;;
        --no-frontend) DO_FRONTEND=false ;;
        --stop)        DO_STOP=true ;;
        --help|-h)
            sed -n '2,17p' "$0" | sed 's/^# //' | sed 's/^#//'
            exit 0
            ;;
        *)
            echo "Unknown flag: $arg  (use --help for usage)"
            exit 1
            ;;
    esac
done

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${CYAN}[local]${NC} $*"; }
success() { echo -e "${GREEN}[local]${NC} $*"; }
warn()    { echo -e "${YELLOW}[local]${NC} $*"; }
error()   { echo -e "${RED}[local] ERROR:${NC} $*" >&2; }
die()     { error "$*"; exit 1; }
step()    { echo -e "\n${BOLD}${CYAN}══ $* ══${NC}"; }

# =============================================================================
# 0. STOP MODE
# =============================================================================
if [[ "$DO_STOP" == "true" ]]; then
    step "Stopping ALDECI local dev servers"
    if [[ -f "$PID_FILE" ]]; then
        while IFS= read -r pid; do
            if kill -0 "$pid" 2>/dev/null; then
                kill "$pid" 2>/dev/null && success "Killed PID ${pid}" || warn "Could not kill PID ${pid}"
            fi
        done < "$PID_FILE"
        rm -f "$PID_FILE"
        success "Dev servers stopped."
    else
        warn "No PID file found at ${PID_FILE}. Are servers running?"
    fi
    exit 0
fi

# =============================================================================
# BANNER
# =============================================================================
echo -e "${CYAN}"
cat << 'BANNER'
     █████╗ ██╗     ██████╗ ███████╗ ██████╗██╗
    ██╔══██╗██║     ██╔══██╗██╔════╝██╔════╝██║
    ███████║██║     ██║  ██║█████╗  ██║     ██║
    ██╔══██║██║     ██║  ██║██╔══╝  ██║     ██║
    ██║  ██║███████╗██████╔╝███████╗╚██████╗██║
    ╚═╝  ╚═╝╚══════╝╚═════╝ ╚══════╝ ╚═════╝╚═╝

    ALDECI — Local Development Setup
BANNER
echo -e "${NC}"

# Prepare log directory and PID file (reset on each run)
mkdir -p "${LOG_DIR}"
> "${PID_FILE}"  # truncate / create

# =============================================================================
# 1. PREREQUISITES
# =============================================================================
step "Checking prerequisites"

# Resolve python executable (prefer python3.11, fall back to python3 >= 3.11)
PYTHON=""
for candidate in python3.11 python3.12 python3.13 python3; do
    if command -v "$candidate" &>/dev/null; then
        ver=$("$candidate" -c "import sys; print(sys.version_info[:2])" 2>/dev/null)
        # ver looks like "(3, 11)"
        major=$(echo "$ver" | tr -d '(),() ' | cut -c1)
        minor=$(echo "$ver" | tr -d '(),() ' | cut -c2-3 | sed 's/ //g')
        minor=$(echo "$ver" | python3 -c "import sys; t=eval(input()); print(t[1])" 2>/dev/null || echo 0)
        if [[ "$major" -ge 3 && "$minor" -ge 11 ]]; then
            PYTHON="$candidate"
            break
        fi
    fi
done

if [[ -z "$PYTHON" ]]; then
    # Last-ditch: just use python3 and warn
    if command -v python3 &>/dev/null; then
        PYTHON=python3
        warn "python3.11+ not found — using $(python3 --version). Some features may not work."
    else
        die "python3 not found. Install Python 3.11+ from https://python.org"
    fi
else
    success "${PYTHON} found: $("${PYTHON}" --version)"
fi

# Node / npm (for UI)
if [[ "$DO_FRONTEND" == "true" ]]; then
    if command -v node &>/dev/null; then
        NODE_VER=$(node --version | tr -d 'v' | cut -d. -f1)
        if [[ "$NODE_VER" -lt 18 ]]; then
            warn "Node $(node --version) found — v18+ recommended. UI may not build correctly."
        else
            success "node $(node --version) found"
        fi
    else
        warn "node not found — skipping UI dev server. Install Node 18+ for the frontend."
        DO_FRONTEND=false
    fi

    if command -v npm &>/dev/null; then
        success "npm $(npm --version) found"
    else
        warn "npm not found — skipping UI dev server."
        DO_FRONTEND=false
    fi
fi

# =============================================================================
# 2. ENVIRONMENT / SECRETS
# =============================================================================
step "Configuring local environment"

generate_secret() {
    "${PYTHON}" -c "import secrets; print(secrets.token_urlsafe(48))" 2>/dev/null \
        || openssl rand -base64 48 | tr -d '\n/+=' | head -c 64
}

if [[ ! -f "$ENV_LOCAL" ]]; then
    info "Creating ${ENV_LOCAL} with auto-generated secrets..."
    API_TOKEN="$(generate_secret)"
    JWT_SECRET="$(generate_secret)"
    cat > "$ENV_LOCAL" << EOF
# ALDECI Local Dev Environment — auto-generated by deploy_local.sh
# DO NOT commit this file to git.

FIXOPS_MODE=development
FIXOPS_LOG_LEVEL=info
FIXOPS_API_TOKEN=${API_TOKEN}
FIXOPS_JWT_SECRET=${JWT_SECRET}
FIXOPS_DATA_DIR=${REPO_ROOT}/data
FIXOPS_SQLITE_DIR=${REPO_ROOT}/data
FIXOPS_DISABLE_TELEMETRY=1
PYTHONUNBUFFERED=1

# LLM providers (optional)
OPENROUTER_API_KEY=
ANTHROPIC_API_KEY=
OPENAI_API_KEY=
EOF
    success "Created ${ENV_LOCAL}"
else
    info "Using existing ${ENV_LOCAL}"
fi

# Load env vars for this shell
set -o allexport
# shellcheck disable=SC1090
source "$ENV_LOCAL"
set +o allexport

# Ensure data directory exists
DATA_DIR="${FIXOPS_DATA_DIR:-${REPO_ROOT}/data}"
mkdir -p "${DATA_DIR}"
success "Data directory: ${DATA_DIR}"

# =============================================================================
# 3. PYTHON VIRTUALENV + DEPENDENCIES
# =============================================================================
step "Installing Python dependencies"

# Create venv if it doesn't exist
if [[ ! -d "$VENV_DIR" ]]; then
    info "Creating virtualenv at ${VENV_DIR}..."
    "${PYTHON}" -m venv "${VENV_DIR}"
    success "Virtualenv created."
else
    info "Reusing existing virtualenv at ${VENV_DIR}"
fi

PY="${VENV_DIR}/bin/python"
PIP="${VENV_DIR}/bin/pip"

# Upgrade pip silently
"${PIP}" install --quiet --upgrade pip setuptools wheel

# Install requirements — pip will skip already-satisfied packages
info "Running pip install -r requirements.txt (skips already-installed packages)..."
"${PIP}" install --quiet -r "${REPO_ROOT}/requirements.txt" \
    2>&1 | grep -E "^(Collecting|Installing|Successfully|ERROR|error)" | sed 's/^/  /' || true

success "Python dependencies installed."

# =============================================================================
# 4. DATABASE MIGRATIONS (SQLite schema init)
# =============================================================================
step "Initializing databases"

PYTHONPATH="${REPO_ROOT}/suite-api:${REPO_ROOT}/suite-core:${REPO_ROOT}/suite-attack:${REPO_ROOT}/suite-feeds:${REPO_ROOT}/suite-evidence-risk:${REPO_ROOT}/suite-integrations:${REPO_ROOT}"
export PYTHONPATH

info "Running init_databases.py --data-dir ${DATA_DIR} ..."
"${PY}" "${SCRIPT_DIR}/init_databases.py" \
    --data-dir "${DATA_DIR}" \
    --org-id aldeci-demo \
    2>&1 | grep -v "^$" | sed 's/^/  /' \
    || warn "Some databases failed to initialize (non-fatal — engines self-init on first request)."

success "Databases initialized."

# =============================================================================
# 5. SEED DEMO DATA
# =============================================================================
if [[ "$DO_SEED" == "true" ]]; then
    step "Seeding demo data"
    info "Running seed_demo_data.py ..."
    "${PY}" "${SCRIPT_DIR}/seed_demo_data.py" \
        --org-id aldeci-demo \
        2>&1 | grep -v "^$" | sed 's/^/  /' \
        || warn "Demo seeding returned non-zero — some engines may have partial data (non-fatal)."
    success "Demo data seeded."
else
    info "Skipping demo data seeding (--no-seed)."
fi

# =============================================================================
# 6. START UVICORN (API SERVER) IN BACKGROUND
# =============================================================================
step "Starting API server (uvicorn)"

API_LOG="${LOG_DIR}/api.log"
API_PORT=8000

# Kill any existing uvicorn on port 8000 (idempotent re-run)
if lsof -ti tcp:${API_PORT} &>/dev/null; then
    warn "Port ${API_PORT} already in use — killing existing process..."
    lsof -ti tcp:${API_PORT} | xargs kill -9 2>/dev/null || true
    sleep 1
fi

info "Starting uvicorn on port ${API_PORT} (logs → ${API_LOG})"
FIXOPS_API_TOKEN="${FIXOPS_API_TOKEN}" \
FIXOPS_JWT_SECRET="${FIXOPS_JWT_SECRET}" \
FIXOPS_DATA_DIR="${DATA_DIR}" \
FIXOPS_SQLITE_DIR="${DATA_DIR}" \
FIXOPS_MODE=development \
FIXOPS_LOG_LEVEL=info \
FIXOPS_DISABLE_TELEMETRY=1 \
PYTHONPATH="${PYTHONPATH}" \
"${VENV_DIR}/bin/uvicorn" \
    apps.api.app:create_app \
    --factory \
    --host 0.0.0.0 \
    --port "${API_PORT}" \
    --log-level info \
    --reload \
    --reload-dir "${REPO_ROOT}/suite-api" \
    --reload-dir "${REPO_ROOT}/suite-core" \
    > "${API_LOG}" 2>&1 &

API_PID=$!
echo "${API_PID}" >> "${PID_FILE}"
info "uvicorn PID: ${API_PID}"

# Wait for API to be ready
info "Waiting for API to be ready at http://localhost:${API_PORT}/health ..."
API_WAIT=0
until curl -sf "http://localhost:${API_PORT}/health" &>/dev/null; do
    API_WAIT=$((API_WAIT + 1))
    if [[ $API_WAIT -gt 45 ]]; then
        error "API did not start within 45 seconds."
        error "Check logs: ${API_LOG}"
        tail -20 "${API_LOG}" | sed 's/^/  /' >&2
        die "API startup failed."
    fi
    # Check if process died
    if ! kill -0 "${API_PID}" 2>/dev/null; then
        error "uvicorn process (PID ${API_PID}) died unexpectedly."
        error "Check logs: ${API_LOG}"
        tail -20 "${API_LOG}" | sed 's/^/  /' >&2
        die "API process died."
    fi
    sleep 1
    echo -n "."
done
echo ""
success "API is ready (${API_WAIT}s)."

# =============================================================================
# 7. START VITE DEV SERVER (FRONTEND) IN BACKGROUND
# =============================================================================
UI_PORT=5173  # Vite default

if [[ "$DO_FRONTEND" == "true" ]]; then
    step "Starting frontend dev server (Vite)"

    if [[ ! -d "${UI_DIR}" ]]; then
        warn "UI directory not found at ${UI_DIR} — skipping frontend."
        DO_FRONTEND=false
    else
        UI_LOG="${LOG_DIR}/ui.log"

        # Kill any existing Vite on port 5173
        if lsof -ti tcp:${UI_PORT} &>/dev/null; then
            warn "Port ${UI_PORT} already in use — killing existing process..."
            lsof -ti tcp:${UI_PORT} | xargs kill -9 2>/dev/null || true
            sleep 1
        fi

        # Install npm deps if node_modules is missing or package.json is newer
        if [[ ! -d "${UI_DIR}/node_modules" ]] || \
           [[ "${UI_DIR}/package.json" -nt "${UI_DIR}/node_modules/.install-stamp" ]]; then
            info "Installing npm dependencies in ${UI_DIR} ..."
            (cd "${UI_DIR}" && npm install --silent) 2>&1 | grep -E "^(added|warn|error)" | sed 's/^/  /' || true
            touch "${UI_DIR}/node_modules/.install-stamp"
            success "npm dependencies installed."
        else
            info "npm dependencies up-to-date (node_modules exists)."
        fi

        info "Starting Vite dev server on port ${UI_PORT} (logs → ${UI_LOG})"
        (cd "${UI_DIR}" && VITE_API_URL="http://localhost:${API_PORT}" \
            npm run dev -- --port "${UI_PORT}" --host 0.0.0.0) \
            > "${UI_LOG}" 2>&1 &

        UI_PID=$!
        echo "${UI_PID}" >> "${PID_FILE}"
        info "Vite PID: ${UI_PID}"

        # Wait for Vite to be ready
        info "Waiting for Vite to be ready at http://localhost:${UI_PORT} ..."
        UI_WAIT=0
        until curl -sf "http://localhost:${UI_PORT}" &>/dev/null; do
            UI_WAIT=$((UI_WAIT + 1))
            if [[ $UI_WAIT -gt 30 ]]; then
                warn "Vite did not respond within 30 seconds — it may still be compiling."
                warn "Check logs: ${UI_LOG}"
                break
            fi
            if ! kill -0 "${UI_PID}" 2>/dev/null; then
                warn "Vite process died. Check logs: ${UI_LOG}"
                DO_FRONTEND=false
                break
            fi
            sleep 1
            echo -n "."
        done
        echo ""
        if kill -0 "${UI_PID}" 2>/dev/null; then
            success "Frontend dev server is running (${UI_WAIT}s)."
        fi
    fi
fi

# =============================================================================
# 8. OPEN BROWSER
# =============================================================================
if [[ "$DO_BROWSER" == "true" ]]; then
    step "Opening browser"
    TARGET_URL="http://localhost:${UI_PORT}"
    if [[ "$DO_FRONTEND" == "false" ]]; then
        TARGET_URL="http://localhost:${API_PORT}/docs"
    fi

    info "Opening ${TARGET_URL} ..."
    if command -v open &>/dev/null; then          # macOS
        open "${TARGET_URL}" 2>/dev/null || true
    elif command -v xdg-open &>/dev/null; then    # Linux
        xdg-open "${TARGET_URL}" 2>/dev/null || true
    elif command -v start &>/dev/null; then       # Windows (Git Bash)
        start "${TARGET_URL}" 2>/dev/null || true
    else
        info "Could not detect browser launcher — open ${TARGET_URL} manually."
    fi
fi

# =============================================================================
# 9. SUMMARY
# =============================================================================
step "Local dev environment is running"

echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║           ALDECI local dev is up!                            ║${NC}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
if [[ "$DO_FRONTEND" == "true" ]]; then
echo -e "  ${BOLD}UI (Vite):${NC}       http://localhost:${UI_PORT}"
fi
echo -e "  ${BOLD}API:${NC}             http://localhost:${API_PORT}"
echo -e "  ${BOLD}API Docs:${NC}        http://localhost:${API_PORT}/docs"
echo -e "  ${BOLD}Health:${NC}          http://localhost:${API_PORT}/health"
echo ""
echo -e "  ${BOLD}Credentials:${NC}"
echo -e "    API Token:   ${CYAN}${FIXOPS_API_TOKEN}${NC}"
echo -e "    Org ID:      ${CYAN}aldeci-demo${NC}"
echo ""
echo -e "  ${BOLD}Logs:${NC}"
echo -e "    API log:     ${LOG_DIR}/api.log"
if [[ "$DO_FRONTEND" == "true" ]]; then
echo -e "    UI log:      ${LOG_DIR}/ui.log"
fi
echo -e "    PID file:    ${PID_FILE}"
echo ""
echo -e "  ${BOLD}Useful commands:${NC}"
echo -e "    Tail API:    tail -f ${LOG_DIR}/api.log"
if [[ "$DO_FRONTEND" == "true" ]]; then
echo -e "    Tail UI:     tail -f ${LOG_DIR}/ui.log"
fi
echo -e "    Stop all:    ./scripts/deploy_local.sh --stop"
echo -e "    Re-seed:     python3 scripts/seed_demo_data.py --org-id aldeci-demo"
echo ""
echo -e "  ${BOLD}Hot reload:${NC}      Both API (uvicorn --reload) and UI (Vite HMR) support"
echo -e "               live reload — edit files and changes apply instantly."
echo ""

# Keep script running so Ctrl-C cleanly kills children
info "Press Ctrl-C to stop all servers."

_cleanup() {
    echo ""
    warn "Shutting down ALDECI local dev servers..."
    if [[ -f "$PID_FILE" ]]; then
        while IFS= read -r pid; do
            kill "$pid" 2>/dev/null || true
        done < "$PID_FILE"
        rm -f "$PID_FILE"
    fi
    success "Stopped. Goodbye."
    exit 0
}
trap _cleanup SIGINT SIGTERM

# Wait for child processes (uvicorn is the primary one)
wait
