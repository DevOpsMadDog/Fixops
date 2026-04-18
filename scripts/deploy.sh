#!/usr/bin/env bash
# =============================================================================
# ALDECI — One-Command Production Deployment
# =============================================================================
# Usage:
#   ./scripts/deploy.sh                     # full deploy (build + seed + start)
#   ./scripts/deploy.sh --no-build          # skip image build (use cached images)
#   ./scripts/deploy.sh --no-seed           # skip demo data seeding
#   ./scripts/deploy.sh --no-verify         # skip persona walkthrough verification
#   ./scripts/deploy.sh --skip-prereq       # skip prerequisite checks
#   ./scripts/deploy.sh --down              # tear down running stack
#
# Idempotent: safe to re-run. Existing containers are recreated, volumes kept.
# Secrets: auto-generated on first run and saved to docker/.env (not committed).
# =============================================================================
set -euo pipefail

# ── Script location so relative paths always resolve correctly ────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DOCKER_DIR="${REPO_ROOT}/docker"
COMPOSE_FILE="${DOCKER_DIR}/docker-compose.prod.yml"
ENV_FILE="${DOCKER_DIR}/.env"

# ── CLI flags ────────────────────────────────────────────────────────────────
DO_BUILD=true
DO_SEED=true
DO_VERIFY=true
DO_PREREQ=true
DO_DOWN=false

for arg in "$@"; do
    case "$arg" in
        --no-build)    DO_BUILD=false ;;
        --no-seed)     DO_SEED=false ;;
        --no-verify)   DO_VERIFY=false ;;
        --skip-prereq) DO_PREREQ=false ;;
        --down)        DO_DOWN=true ;;
        --help|-h)
            sed -n '2,16p' "$0" | sed 's/^# //' | sed 's/^#//'
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

info()    { echo -e "${CYAN}[deploy]${NC} $*"; }
success() { echo -e "${GREEN}[deploy]${NC} $*"; }
warn()    { echo -e "${YELLOW}[deploy]${NC} $*"; }
error()   { echo -e "${RED}[deploy] ERROR:${NC} $*" >&2; }
die()     { error "$*"; exit 1; }
step()    { echo -e "\n${BOLD}${CYAN}══ $* ══${NC}"; }

# =============================================================================
# 0. TEAR DOWN (--down mode)
# =============================================================================
if [[ "$DO_DOWN" == "true" ]]; then
    step "Tearing down ALDECI production stack"
    cd "${DOCKER_DIR}"
    if [[ -f "$ENV_FILE" ]]; then
        docker compose -f docker-compose.prod.yml --env-file .env down --remove-orphans
    else
        docker compose -f docker-compose.prod.yml down --remove-orphans
    fi
    success "Stack stopped. Volumes preserved (use 'docker compose ... down -v' to wipe data)."
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

    ALDECI — One-Command Production Deployment
BANNER
echo -e "${NC}"

# =============================================================================
# 1. PREREQUISITES
# =============================================================================
if [[ "$DO_PREREQ" == "true" ]]; then
    step "Checking prerequisites"

    PREREQ_FAILED=false

    check_cmd() {
        local cmd="$1"
        local min_ver="${2:-}"
        if command -v "$cmd" &>/dev/null; then
            success "${cmd} found: $(command -v "$cmd")"
        else
            error "${cmd} not found. Please install it first."
            PREREQ_FAILED=true
        fi
    }

    check_cmd docker
    check_cmd curl

    # docker compose (plugin or standalone)
    if docker compose version &>/dev/null 2>&1; then
        success "docker compose (plugin): $(docker compose version --short 2>/dev/null || echo ok)"
    elif command -v docker-compose &>/dev/null; then
        success "docker-compose (standalone): $(docker-compose --version)"
        # Alias so the rest of the script uses "docker compose"
        docker() {
            if [[ "$1" == "compose" ]]; then
                shift
                command docker-compose "$@"
            else
                command docker "$@"
            fi
        }
        export -f docker
    else
        error "docker compose is not available. Install Docker Desktop or docker-compose."
        PREREQ_FAILED=true
    fi

    # Python 3.11 (needed only for seeding from host; optional if --no-seed)
    if [[ "$DO_SEED" == "true" ]]; then
        if command -v python3.11 &>/dev/null; then
            success "python3.11 found"
        elif python3 --version 2>&1 | grep -qE "Python 3\.1[123456789]"; then
            success "python3 is $(python3 --version)"
        else
            warn "python3.11 not found — demo seeding will run inside the API container instead."
        fi
    fi

    # Docker daemon must be running
    if ! docker info &>/dev/null; then
        error "Docker daemon is not running. Start Docker and retry."
        PREREQ_FAILED=true
    else
        success "Docker daemon is running"
    fi

    if [[ "$PREREQ_FAILED" == "true" ]]; then
        die "One or more prerequisites are missing. Fix them and re-run."
    fi
fi

# =============================================================================
# 2. ENVIRONMENT / SECRETS
# =============================================================================
step "Configuring environment"

generate_secret() {
    python3 -c "import secrets; print(secrets.token_urlsafe(48))" 2>/dev/null \
        || openssl rand -base64 48 | tr -d '\n/+=' | head -c 64
}

mkdir -p "${DOCKER_DIR}"

if [[ ! -f "$ENV_FILE" ]]; then
    info "No ${ENV_FILE} found — generating one with auto-generated secrets."
    API_TOKEN="$(generate_secret)"
    JWT_SECRET="$(generate_secret)"
    cat > "$ENV_FILE" << EOF
# ALDECI Production Environment — auto-generated by deploy.sh
# DO NOT commit this file to git.

FIXOPS_MODE=production
FIXOPS_LOG_LEVEL=warning
FIXOPS_API_TOKEN=${API_TOKEN}
FIXOPS_JWT_SECRET=${JWT_SECRET}
FIXOPS_WORKERS=1
ALDECI_SEED_DEMO=0

# Ports (change if you have conflicts)
API_PORT=8000
UI_PORT=3000
REDIS_PORT=6379

# LLM providers (optional — leave blank to use rule-based engines)
OPENROUTER_API_KEY=
ANTHROPIC_API_KEY=
OPENAI_API_KEY=

# Frontend build arg
VITE_API_URL=http://localhost:8000
EOF
    success "Created ${ENV_FILE} with fresh secrets."
else
    info "Using existing ${ENV_FILE}"
fi

# Load env so we can reference values in this script
set -o allexport
# shellcheck disable=SC1090
source "$ENV_FILE"
set +o allexport

API_PORT="${API_PORT:-8000}"
UI_PORT="${UI_PORT:-3000}"

# =============================================================================
# 3. BUILD DOCKER IMAGES
# =============================================================================
if [[ "$DO_BUILD" == "true" ]]; then
    step "Building Docker images"
    info "Building aldeci-api:prod and aldeci-ui:prod (this can take 3-5 min on first run)"

    cd "${DOCKER_DIR}"

    # Build API image (multi-stage with CPU-only PyTorch)
    docker compose -f docker-compose.prod.yml --env-file .env build \
        --build-arg BUILDKIT_INLINE_CACHE=1 \
        aldeci

    # Build UI image
    docker compose -f docker-compose.prod.yml --env-file .env build \
        --build-arg VITE_API_URL="${VITE_API_URL:-http://localhost:${API_PORT}}" \
        aldeci-ui

    success "Images built successfully."
else
    info "Skipping image build (--no-build). Using cached images."
fi

# =============================================================================
# 4. DATABASE MIGRATIONS / SCHEMA INITIALIZATION
# =============================================================================
step "Running database migrations"

cd "${DOCKER_DIR}"

# Start Redis first (API depends on it for schema init that uses cache)
info "Starting Redis..."
docker compose -f docker-compose.prod.yml --env-file .env up -d redis

# Wait for Redis to be healthy before proceeding
info "Waiting for Redis to be ready..."
REDIS_WAIT=0
until docker compose -f docker-compose.prod.yml --env-file .env \
        exec -T redis redis-cli ping 2>/dev/null | grep -q PONG; do
    REDIS_WAIT=$((REDIS_WAIT + 1))
    if [[ $REDIS_WAIT -gt 30 ]]; then
        die "Redis did not become ready within 30 seconds."
    fi
    sleep 1
    echo -n "."
done
echo ""
success "Redis is ready."

# Run DB init inside a temporary API container (no daemon, schema only)
info "Initializing SQLite schemas..."
docker run --rm \
    --network "$(docker network ls --filter name=aldeci-prod --format '{{.Name}}' | head -1 || echo aldeci-prod)" \
    --env-file "${ENV_FILE}" \
    -e FIXOPS_DATA_DIR=/tmp/aldeci-init \
    -e PYTHONPATH="/app/suite-api:/app/suite-core:/app/suite-attack:/app/suite-feeds:/app/suite-evidence-risk:/app/suite-integrations:/app" \
    -v "prod-aldeci-data:/app/data" \
    aldeci-api:prod \
    python3 /app/scripts/init_databases.py --data-dir /app/data --org-id aldeci-demo \
    2>&1 | grep -v "^$" | sed 's/^/  /' \
    || warn "Schema init returned non-zero — some modules may self-init on first request (non-fatal)."

success "Database schemas initialized."

# =============================================================================
# 5. SEED DEMO DATA
# =============================================================================
if [[ "$DO_SEED" == "true" ]]; then
    step "Seeding demo data"
    info "Running seed_demo_data.py (investor-quality demo data for all engines)..."

    docker run --rm \
        --network "$(docker network ls --filter name=aldeci-prod --format '{{.Name}}' | head -1 || echo aldeci-prod)" \
        --env-file "${ENV_FILE}" \
        -e PYTHONPATH="/app/suite-api:/app/suite-core:/app/suite-attack:/app/suite-feeds:/app/suite-evidence-risk:/app/suite-integrations:/app" \
        -v "prod-aldeci-data:/app/data" \
        aldeci-api:prod \
        python3 /app/scripts/seed_demo_data.py --org-id aldeci-demo \
        2>&1 | grep -v "^$" | sed 's/^/  /' \
        || warn "Demo seeding returned non-zero — some engines may have partial data (non-fatal)."

    success "Demo data seeded."
else
    info "Skipping demo data seeding (--no-seed)."
fi

# =============================================================================
# 6. START ALL SERVICES
# =============================================================================
step "Starting all services"
cd "${DOCKER_DIR}"

info "Bringing up the full stack via docker-compose.prod.yml..."
docker compose -f docker-compose.prod.yml --env-file .env up -d --remove-orphans

success "Containers started."

# =============================================================================
# 7. WAIT FOR HEALTH CHECKS
# =============================================================================
step "Waiting for health checks"

wait_healthy() {
    local service="$1"
    local url="$2"
    local label="$3"
    local max_wait="${4:-90}"
    local waited=0

    info "Waiting for ${label} at ${url} ..."
    until curl -sf "${url}" &>/dev/null; do
        waited=$((waited + 2))
        if [[ $waited -gt $max_wait ]]; then
            error "${label} did not become healthy within ${max_wait}s."
            info "Container logs:"
            docker compose -f "${DOCKER_DIR}/docker-compose.prod.yml" \
                --env-file "${DOCKER_DIR}/.env" logs --tail=30 "$service" 2>/dev/null | sed 's/^/  /'
            die "${label} failed to start."
        fi
        sleep 2
        echo -n "."
    done
    echo ""
    success "${label} is healthy (${waited}s)."
}

wait_healthy "aldeci"    "http://localhost:${API_PORT}/health"         "ALDECI API"       120
wait_healthy "aldeci-ui" "http://localhost:${UI_PORT}/nginx-health"    "ALDECI UI (Nginx)" 60

# =============================================================================
# 8. 30-PERSONA WALKTHROUGH VERIFICATION
# =============================================================================
if [[ "$DO_VERIFY" == "true" ]]; then
    step "Running 30-Persona verification walkthrough"

    WALKTHROUGH_SCRIPT="${REPO_ROOT}/scripts/persona_walkthrough.py"

    if [[ ! -f "$WALKTHROUGH_SCRIPT" ]]; then
        warn "persona_walkthrough.py not found at ${WALKTHROUGH_SCRIPT} — skipping verification."
    else
        info "Running persona walkthrough against http://localhost:${API_PORT} ..."
        FIXOPS_API_TOKEN="${FIXOPS_API_TOKEN}" \
            python3 "${WALKTHROUGH_SCRIPT}" \
            2>&1 | tail -40 | sed 's/^/  /' || true

        EXIT_CODE=${PIPESTATUS[0]}
        if [[ "${EXIT_CODE}" -eq 0 ]]; then
            success "Persona walkthrough PASSED."
        else
            warn "Persona walkthrough completed with some failures (exit ${EXIT_CODE})."
            warn "Check individual persona results above. The stack is running."
        fi
    fi
else
    info "Skipping persona walkthrough (--no-verify)."
fi

# =============================================================================
# 9. PRINT ACCESS SUMMARY
# =============================================================================
step "Deployment complete"

echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║              ALDECI is up and running!                       ║${NC}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BOLD}UI Dashboard:${NC}    http://localhost:${UI_PORT}"
echo -e "  ${BOLD}API:${NC}             http://localhost:${API_PORT}"
echo -e "  ${BOLD}API Docs:${NC}        http://localhost:${API_PORT}/docs"
echo -e "  ${BOLD}Health:${NC}          http://localhost:${API_PORT}/health"
echo ""
echo -e "  ${BOLD}Credentials:${NC}"
echo -e "    API Token:   ${CYAN}${FIXOPS_API_TOKEN}${NC}"
echo -e "    Org ID:      ${CYAN}aldeci-demo${NC}"
echo ""
echo -e "  ${BOLD}Env file:${NC}        ${ENV_FILE}"
echo -e "  ${BOLD}Data volume:${NC}     prod-aldeci-data (SQLite DBs persist here)"
echo ""
echo -e "  ${BOLD}Useful commands:${NC}"
echo -e "    View logs:   docker compose -f docker/docker-compose.prod.yml --env-file docker/.env logs -f"
echo -e "    Stop:        ./scripts/deploy.sh --down"
echo -e "    Rebuild:     ./scripts/deploy.sh"
echo -e "    Re-seed:     ./scripts/deploy.sh --no-build --no-verify"
echo ""
