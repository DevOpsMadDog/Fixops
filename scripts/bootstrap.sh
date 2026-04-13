#!/usr/bin/env bash
# =============================================================================
# ALdeci Bootstrap — docker compose up → wait healthy → self_scan.py
#
# One command: real platform with real security data from ALDECI itself.
#
# Usage:
#   bash scripts/bootstrap.sh                   # full stack + self-scan
#   bash scripts/bootstrap.sh --no-scan         # docker compose only
#   bash scripts/bootstrap.sh --scan-only       # self-scan against running API
#   bash scripts/bootstrap.sh --no-build        # skip image rebuild
#
# Environment:
#   ALDECI_BASE_URL      Override API URL (default: http://localhost:8000)
#   FIXOPS_API_TOKEN     API key passed to self-scan
#   ALDECI_PORT          API port (default: 8000)
#   ALDECI_UI_PORT       UI port (default: 3000)
#   COMPOSE_FILE         Override compose file path
#   BOOTSTRAP_TIMEOUT    Seconds to wait for healthy (default: 120)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

ALDECI_PORT="${ALDECI_PORT:-8000}"
ALDECI_UI_PORT="${ALDECI_UI_PORT:-3000}"
BASE_URL="${ALDECI_BASE_URL:-http://localhost:${ALDECI_PORT}}"
COMPOSE_FILE="${COMPOSE_FILE:-$ROOT_DIR/docker-compose.yml}"
TIMEOUT="${BOOTSTRAP_TIMEOUT:-120}"

RUN_COMPOSE=true
RUN_SCAN=true
DO_BUILD=true

# Parse flags
for arg in "$@"; do
    case "$arg" in
        --no-scan)    RUN_SCAN=false ;;
        --scan-only)  RUN_COMPOSE=false ;;
        --no-build)   DO_BUILD=false ;;
        --help|-h)
            grep '^#' "$0" | sed 's/^# \?//'
            exit 0
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------
_GREEN='\033[0;32m'
_YELLOW='\033[0;33m'
_RED='\033[0;31m'
_CYAN='\033[0;36m'
_BOLD='\033[1m'
_RESET='\033[0m'

info()    { echo -e "${_CYAN}[bootstrap]${_RESET} $*"; }
success() { echo -e "${_GREEN}[bootstrap]${_RESET} $*"; }
warn()    { echo -e "${_YELLOW}[bootstrap]${_RESET} $*"; }
error()   { echo -e "${_RED}[bootstrap] ERROR:${_RESET} $*" >&2; }

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
preflight() {
    info "Pre-flight checks..."

    if ! command -v docker &>/dev/null; then
        error "docker not found. Install Docker Desktop: https://docs.docker.com/get-docker/"
        exit 1
    fi

    if ! docker info &>/dev/null; then
        error "Docker daemon is not running. Start Docker Desktop and retry."
        exit 1
    fi

    if ! docker compose version &>/dev/null 2>&1; then
        error "docker compose v2 not found. Update Docker Desktop to latest."
        exit 1
    fi

    if [ ! -f "$COMPOSE_FILE" ]; then
        error "Compose file not found: $COMPOSE_FILE"
        exit 1
    fi

    success "Docker OK — $(docker compose version --short 2>/dev/null || docker compose version | head -1)"
}

# ---------------------------------------------------------------------------
# Docker compose up
# ---------------------------------------------------------------------------
compose_up() {
    info "Starting ALdeci platform..."
    cd "$ROOT_DIR"

    BUILD_FLAG=""
    if [ "$DO_BUILD" = true ]; then
        BUILD_FLAG="--build"
        info "Building images (use --no-build to skip)..."
    fi

    docker compose -f "$COMPOSE_FILE" up -d $BUILD_FLAG \
        2>&1 | while IFS= read -r line; do echo "  $line"; done

    success "Containers started."
}

# ---------------------------------------------------------------------------
# Wait for API healthy
# ---------------------------------------------------------------------------
wait_healthy() {
    info "Waiting for ALdeci API at $BASE_URL/health (timeout: ${TIMEOUT}s)..."
    local elapsed=0
    local interval=3

    until curl -sf "$BASE_URL/health" >/dev/null 2>&1 || \
          curl -sf "$BASE_URL/api/v1/health" >/dev/null 2>&1; do
        if [ "$elapsed" -ge "$TIMEOUT" ]; then
            error "API did not become healthy within ${TIMEOUT}s."
            warn "Check logs: docker compose logs aldeci"
            warn "Or try: docker compose ps"
            exit 1
        fi
        printf "  waiting... %ds\r" "$elapsed"
        sleep "$interval"
        elapsed=$((elapsed + interval))
    done

    echo ""
    success "ALdeci API is healthy after ${elapsed}s."
}

# ---------------------------------------------------------------------------
# Run self-scan
# ---------------------------------------------------------------------------
run_self_scan() {
    info "Running self-scan bootstrap..."
    info "ALDECI will scan its own codebase — this IS the demo data."
    echo ""

    PYTHON_BIN="${PYTHON:-python3}"
    if ! command -v "$PYTHON_BIN" &>/dev/null; then
        PYTHON_BIN=python
    fi

    export ALDECI_BASE_URL="$BASE_URL"

    cd "$ROOT_DIR"
    "$PYTHON_BIN" scripts/self_scan.py
    SCAN_EXIT=$?

    if [ "$SCAN_EXIT" -eq 0 ]; then
        success "Self-scan complete. Real data populated."
    else
        warn "Self-scan exited with code $SCAN_EXIT — check output above."
    fi
    return $SCAN_EXIT
}

# ---------------------------------------------------------------------------
# Print access info
# ---------------------------------------------------------------------------
print_access() {
    echo ""
    echo -e "${_BOLD}${_GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${_RESET}"
    echo -e "${_BOLD}  ALdeci is running with real self-scan data${_RESET}"
    echo -e "${_GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${_RESET}"
    echo ""
    echo -e "  API:       ${_CYAN}${BASE_URL}${_RESET}"
    echo -e "  UI:        ${_CYAN}http://localhost:${ALDECI_UI_PORT}${_RESET}"
    echo -e "  API docs:  ${_CYAN}${BASE_URL}/docs${_RESET}"
    echo -e "  Health:    ${_CYAN}${BASE_URL}/health${_RESET}"
    echo ""
    echo -e "  Findings:  ${_CYAN}${BASE_URL}/api/v1/findings${_RESET}"
    echo -e "  SBOM:      ${ROOT_DIR}/data/self-scan/latest.json"
    echo ""
    echo -e "  Stop:   ${_BOLD}docker compose down${_RESET}"
    echo -e "  Logs:   ${_BOLD}docker compose logs -f aldeci${_RESET}"
    echo -e "  Rescan: ${_BOLD}python scripts/self_scan.py${_RESET}"
    echo ""
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
echo ""
echo -e "${_BOLD}${_CYAN}════════════════════════════════════════════════════════════════════${_RESET}"
echo -e "${_BOLD}${_CYAN}  ALdeci Self-Scan Bootstrap${_RESET}"
echo -e "${_BOLD}${_CYAN}  One command: real platform with real data from itself${_RESET}"
echo -e "${_BOLD}${_CYAN}════════════════════════════════════════════════════════════════════${_RESET}"
echo ""

preflight

if [ "$RUN_COMPOSE" = true ]; then
    compose_up
    wait_healthy
else
    info "--scan-only: skipping docker compose, expecting API at $BASE_URL"
    wait_healthy
fi

if [ "$RUN_SCAN" = true ]; then
    run_self_scan
fi

print_access
