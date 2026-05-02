#!/usr/bin/env bash
# ============================================
# ALdeci CTEM+ Platform — Local Dev Setup
# ============================================
# Zero-config setup from clone to running.
# Detects your OS, installs dependencies,
# creates .env, and starts the platform.
#
# Usage:
#   git clone https://github.com/aldeci/fixops.git
#   cd fixops
#   ./scripts/local-dev-setup.sh
#
# Modes:
#   ./scripts/local-dev-setup.sh              # Full setup (Python + Node + Docker)
#   ./scripts/local-dev-setup.sh --python     # Backend only (no Docker, no Node)
#   ./scripts/local-dev-setup.sh --docker     # Docker only (no local Python)
#   ./scripts/local-dev-setup.sh --check      # Check environment, don't install
#
# Time estimates:
#   First run:  3-5 minutes (fresh install)
#   Cached run: 30-60 seconds (deps cached)
# ============================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ─── Parse flags ─────────────────────────────────────────────
MODE="full"
CHECK_ONLY=false
for arg in "$@"; do
    case "$arg" in
        --python)  MODE="python" ;;
        --docker)  MODE="docker" ;;
        --check)   CHECK_ONLY=true ;;
        --help|-h)
            echo "Usage: $0 [--python|--docker|--check]"
            echo "  (none)    Full setup: Python + Node + Docker"
            echo "  --python  Backend only: Python venv + deps"
            echo "  --docker  Docker only: build and run containers"
            echo "  --check   Check environment without installing"
            exit 0
            ;;
    esac
done

# ─── Colors ──────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${CYAN}ℹ${NC}  $1"; }
success() { echo -e "${GREEN}✅${NC} $1"; }
warn()    { echo -e "${YELLOW}⚠️${NC}  $1"; }
fail()    { echo -e "${RED}❌${NC} $1"; }
step()    { echo -e "\n${BOLD}$1${NC}"; }

# ─── OS Detection ────────────────────────────────────────────
detect_os() {
    case "$(uname -s)" in
        Darwin)  OS="macos" ;;
        Linux)   OS="linux" ;;
        MINGW*|MSYS*) OS="windows" ;;
        *)       OS="unknown" ;;
    esac
    ARCH="$(uname -m)"
    info "Detected: ${OS} (${ARCH})"
}

# ─── Prerequisite Checks ────────────────────────────────────
check_python() {
    if command -v python3 &>/dev/null; then
        PY_VER=$(python3 --version 2>&1 | cut -d' ' -f2)
        PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
        PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
        if [ "$PY_MAJOR" -ge 3 ] && [ "$PY_MINOR" -ge 10 ]; then
            success "Python ${PY_VER} (>= 3.10 required)"
            return 0
        else
            warn "Python ${PY_VER} — need >= 3.10"
            return 1
        fi
    else
        fail "Python 3 not found"
        return 1
    fi
}

check_node() {
    if command -v node &>/dev/null; then
        NODE_VER=$(node --version | tr -d 'v')
        NODE_MAJOR=$(echo "$NODE_VER" | cut -d. -f1)
        if [ "$NODE_MAJOR" -ge 18 ]; then
            success "Node.js v${NODE_VER} (>= 18 required)"
            return 0
        else
            warn "Node.js v${NODE_VER} — need >= 18"
            return 1
        fi
    else
        fail "Node.js not found"
        return 1
    fi
}

check_docker() {
    if command -v docker &>/dev/null; then
        if docker info &>/dev/null 2>&1; then
            DOCKER_VER=$(docker --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
            success "Docker ${DOCKER_VER} (running)"
            return 0
        else
            warn "Docker installed but daemon not running"
            echo "    Start Docker Desktop and re-run this script"
            return 1
        fi
    else
        fail "Docker not installed"
        echo "    Install: https://docs.docker.com/desktop/"
        return 1
    fi
}

check_ports() {
    local all_clear=true
    for port in 8000 3001; do
        if lsof -i ":${port}" -sTCP:LISTEN &>/dev/null 2>&1; then
            warn "Port ${port} already in use"
            echo "    Run: lsof -i :${port}   to see what's using it"
            all_clear=false
        else
            success "Port ${port} available"
        fi
    done
    $all_clear
}

# ─── Environment Check ──────────────────────────────────────
do_check() {
    step "Environment Check"

    echo ""
    echo -e "${BOLD}Prerequisites:${NC}"
    PY_OK=false; NODE_OK=false; DOCKER_OK=false
    check_python && PY_OK=true
    check_node && NODE_OK=true
    check_docker && DOCKER_OK=true

    echo ""
    echo -e "${BOLD}Port Availability:${NC}"
    check_ports || true

    echo ""
    echo -e "${BOLD}Files:${NC}"
    [ -f "${REPO_ROOT}/.env" ] && success ".env exists" || warn ".env missing (will be created from .env.example)"
    [ -f "${REPO_ROOT}/.env.example" ] && success ".env.example exists" || fail ".env.example missing!"
    [ -f "${REPO_ROOT}/requirements.txt" ] && success "requirements.txt exists" || fail "requirements.txt missing!"
    [ -d "${REPO_ROOT}/suite-ui/aldeci-ui-new" ] && success "UI source exists" || warn "UI source missing"

    echo ""
    if $PY_OK && $NODE_OK && $DOCKER_OK; then
        success "All prerequisites met — ready to develop!"
        return 0
    else
        warn "Some prerequisites missing — see above"
        return 1
    fi
}

# ─── Setup Functions ─────────────────────────────────────────

setup_env_file() {
    if [ ! -f "${REPO_ROOT}/.env" ]; then
        if [ -f "${REPO_ROOT}/.env.example" ]; then
            cp "${REPO_ROOT}/.env.example" "${REPO_ROOT}/.env"
            success "Created .env from .env.example"
            warn "Edit .env to add your API keys (OpenAI, etc.)"
        else
            # Create minimal .env
            cat > "${REPO_ROOT}/.env" << 'ENVEOF'
# ALdeci CTEM+ Platform — Local Development
FIXOPS_MODE=enterprise
FIXOPS_API_TOKEN=dev-token-local
FIXOPS_JWT_SECRET=dev-jwt-secret-local-only
FIXOPS_DISABLE_TELEMETRY=1
FIXOPS_DISABLE_RATE_LIMIT=1
# Add your LLM API keys below:
# OPENAI_API_KEY=sk-proj-...
# ANTHROPIC_API_KEY=sk-ant-...
ENVEOF
            success "Created minimal .env file"
        fi
    else
        success ".env already exists"
    fi
}

setup_python_env() {
    step "Setting up Python environment"

    # Create virtual environment if needed
    if [ ! -d "${REPO_ROOT}/.venv" ]; then
        info "Creating Python virtual environment..."
        python3 -m venv "${REPO_ROOT}/.venv"
        success "Virtual environment created at .venv/"
    else
        success "Virtual environment exists"
    fi

    # Activate venv
    source "${REPO_ROOT}/.venv/bin/activate"

    # Install dependencies
    info "Installing Python dependencies (this may take 2-3 minutes on first run)..."
    pip install --quiet --upgrade pip
    pip install --quiet -r "${REPO_ROOT}/requirements.txt" 2>&1 | tail -1 || {
        warn "Some optional dependencies failed — trying without constraints"
        pip install --quiet -r "${REPO_ROOT}/requirements.txt" --no-deps 2>/dev/null || true
    }
    success "Python dependencies installed"

    # Install test dependencies if available
    if [ -f "${REPO_ROOT}/requirements-test.txt" ]; then
        pip install --quiet -r "${REPO_ROOT}/requirements-test.txt" 2>/dev/null || true
        success "Test dependencies installed"
    fi
}

setup_node_env() {
    step "Setting up Node.js environment"

    UI_DIR="${REPO_ROOT}/suite-ui/aldeci-ui-new"
    if [ ! -d "$UI_DIR" ]; then
        warn "UI directory not found at suite-ui/aldeci-ui-new/ — skipping"
        return 0
    fi

    cd "$UI_DIR"
    if [ -f "package-lock.json" ]; then
        info "Installing Node.js dependencies..."
        npm ci --ignore-scripts 2>/dev/null || npm install --ignore-scripts
    else
        info "Installing Node.js dependencies (no lockfile)..."
        npm install --ignore-scripts
    fi
    success "Node.js dependencies installed"
    cd "${REPO_ROOT}"
}

setup_docker_env() {
    step "Setting up Docker environment"

    if ! docker info &>/dev/null 2>&1; then
        fail "Docker daemon not running — start Docker Desktop first"
        return 1
    fi

    setup_env_file

    info "Building Docker images (first build takes 3-5 minutes)..."
    docker compose -f "${REPO_ROOT}/docker/docker-compose.yml" build 2>&1 | tail -5

    success "Docker images built"
    info "Start with: docker compose -f docker/docker-compose.yml up -d"
    info "Or use:     ./scripts/demo-start.sh"
}

verify_setup() {
    step "Verification"

    if [[ "$MODE" == "python" || "$MODE" == "full" ]]; then
        # Verify Python imports work
        info "Verifying Python imports..."
        if PYTHONPATH="${REPO_ROOT}/suite-api:${REPO_ROOT}/suite-core:${REPO_ROOT}/suite-attack:${REPO_ROOT}/suite-feeds:${REPO_ROOT}/suite-evidence-risk:${REPO_ROOT}/suite-integrations:${REPO_ROOT}" \
            python3 -c "from apps.api.app import create_app; print('FastAPI app loads OK')" 2>/dev/null; then
            success "Python imports work"
        else
            warn "Python import check failed — some optional deps may be missing"
        fi
    fi

    echo ""
    echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}${BOLD}  ✅ Development environment ready!${NC}"
    echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  ${BOLD}Quick Start:${NC}"

    if [[ "$MODE" == "docker" ]]; then
        echo -e "    ${CYAN}Start:${NC}      ./scripts/demo-start.sh"
        echo -e "    ${CYAN}Health:${NC}     ./scripts/demo-healthcheck.sh"
    else
        echo -e "    ${CYAN}Activate:${NC}   source .venv/bin/activate"
        echo -e "    ${CYAN}Run API:${NC}    python -m uvicorn apps.api.app:create_app --factory --port 8000"
        echo -e "    ${CYAN}Run UI:${NC}     cd suite-ui/aldeci-ui-new && npm run dev"
        echo -e "    ${CYAN}Run tests:${NC}  python -m pytest tests/ --timeout=10 -x -q"
    fi

    echo ""
    echo -e "  ${BOLD}Useful URLs:${NC}"
    echo -e "    ${CYAN}API:${NC}        http://localhost:8000"
    echo -e "    ${CYAN}UI:${NC}         http://localhost:3001"
    echo -e "    ${CYAN}Swagger:${NC}    http://localhost:8000/docs"
    echo -e "    ${CYAN}Health:${NC}     http://localhost:8000/health"
    echo ""
}

# ─── Main ────────────────────────────────────────────────────

echo -e "${CYAN}"
echo "  ┌─────────────────────────────────────────────┐"
echo "  │     ALdeci CTEM+ — Development Setup         │"
echo "  └─────────────────────────────────────────────┘"
echo -e "${NC}"

detect_os

if [[ "$CHECK_ONLY" == "true" ]]; then
    do_check
    exit $?
fi

setup_env_file

case "$MODE" in
    python)
        check_python || { fail "Python 3.10+ required"; exit 1; }
        setup_python_env
        ;;
    docker)
        check_docker || { fail "Docker required"; exit 1; }
        setup_docker_env
        ;;
    full)
        check_python || { warn "Python not found — skipping backend setup"; }
        check_node || { warn "Node.js not found — skipping UI setup"; }
        check_docker || { warn "Docker not running — skipping Docker setup"; }

        setup_python_env 2>/dev/null || warn "Python setup had issues"
        setup_node_env 2>/dev/null || warn "Node setup had issues"
        # Docker build is optional in full mode
        if docker info &>/dev/null 2>&1; then
            info "Docker available — skipping build (use --docker to build images)"
        fi
        ;;
esac

verify_setup
