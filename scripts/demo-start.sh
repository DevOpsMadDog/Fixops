#!/usr/bin/env bash
# ============================================
# ALdeci CTEM+ Platform — One-Command Demo
# ============================================
# Run this script to start the full ALdeci stack.
#
# Prerequisites:
#   - Docker Desktop running
#   - Ports 8000 and 3001 available
#
# Usage:
#   ./scripts/demo-start.sh          # Build and start
#   ./scripts/demo-start.sh --quick  # Skip rebuild (use cached images)
#   ./scripts/demo-start.sh --stop   # Stop all services
#   ./scripts/demo-start.sh --reset  # Stop, remove volumes, rebuild
# ============================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/docker/docker-compose.yml"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

banner() {
    echo -e "${CYAN}"
    echo "     █████╗ ██╗     ██████╗ ███████╗ ██████╗██╗"
    echo "    ██╔══██╗██║     ██╔══██╗██╔════╝██╔════╝██║"
    echo "    ███████║██║     ██║  ██║█████╗  ██║     ██║"
    echo "    ██╔══██║██║     ██║  ██║██╔══╝  ██║     ██║"
    echo "    ██║  ██║███████╗██████╔╝███████╗╚██████╗██║"
    echo "    ╚═╝  ╚═╝╚══════╝╚═════╝ ╚══════╝ ╚═════╝╚═╝"
    echo -e "${NC}"
    echo -e "    ${BOLD}CTEM+ Decision Intelligence Platform${NC}"
    echo -e "    ${CYAN}Enterprise Demo${NC}"
    echo ""
}

check_prereqs() {
    # Check Docker
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}ERROR: Docker is not installed.${NC}"
        echo "  Install Docker Desktop: https://docs.docker.com/desktop/"
        exit 1
    fi

    if ! docker info &> /dev/null 2>&1; then
        echo -e "${RED}ERROR: Docker daemon is not running.${NC}"
        echo "  Start Docker Desktop and try again."
        exit 1
    fi

    # Check ports
    for port in 8000 3001; do
        if lsof -i ":${port}" -sTCP:LISTEN &> /dev/null 2>&1; then
            echo -e "${YELLOW}WARNING: Port ${port} is already in use.${NC}"
            echo "  Run: lsof -i :${port}    to see what's using it"
            echo "  Or set FIXOPS_PORT / ALDECI_UI_PORT environment variables"
        fi
    done
}

do_stop() {
    echo -e "${YELLOW}Stopping ALdeci services...${NC}"
    docker compose -f "${COMPOSE_FILE}" down 2>/dev/null || true
    echo -e "${GREEN}Services stopped.${NC}"
}

do_reset() {
    echo -e "${YELLOW}Resetting ALdeci (removing volumes and images)...${NC}"
    docker compose -f "${COMPOSE_FILE}" down -v --rmi local 2>/dev/null || true
    echo -e "${GREEN}Reset complete.${NC}"
}

do_start() {
    local quick="${1:-false}"

    check_prereqs

    echo -e "${BOLD}Starting ALdeci CTEM+ Platform...${NC}"
    echo ""

    if [[ "$quick" == "true" ]]; then
        echo -e "  ${CYAN}Mode:${NC} Quick start (using cached images)"
        docker compose -f "${COMPOSE_FILE}" up -d
    else
        echo -e "  ${CYAN}Mode:${NC} Full build + start"
        echo -e "  ${CYAN}Note:${NC} First build takes 3-5 minutes (downloads dependencies)"
        echo ""
        docker compose -f "${COMPOSE_FILE}" up --build -d
    fi

    echo ""
    echo -e "${BOLD}Waiting for services to become healthy...${NC}"

    # Wait for health with timeout
    local elapsed=0
    local timeout=60
    local api_ready=false
    local ui_ready=false

    while [[ $elapsed -lt $timeout ]]; do
        if [[ "$api_ready" != "true" ]] && curl -sf "http://localhost:${FIXOPS_PORT:-8000}/health" --max-time 2 > /dev/null 2>&1; then
            echo -e "  ${GREEN}✅${NC} API server ready (${elapsed}s)"
            api_ready=true
        fi

        if [[ "$ui_ready" != "true" ]] && curl -sf "http://localhost:${ALDECI_UI_PORT:-3001}/nginx-health" --max-time 2 > /dev/null 2>&1; then
            echo -e "  ${GREEN}✅${NC} UI server ready (${elapsed}s)"
            ui_ready=true
        fi

        if [[ "$api_ready" == "true" && "$ui_ready" == "true" ]]; then
            break
        fi

        sleep 1
        elapsed=$((elapsed + 1))
        if [[ $((elapsed % 10)) -eq 0 ]]; then
            echo -e "  ${YELLOW}⏳${NC} Still waiting... (${elapsed}s/${timeout}s)"
        fi
    done

    echo ""

    if [[ "$api_ready" == "true" && "$ui_ready" == "true" ]]; then
        echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${GREEN}${BOLD}  ✅ ALdeci is running!${NC}"
        echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo -e "  ${BOLD}Open in your browser:${NC}"
        echo -e "    ${CYAN}UI Dashboard:${NC}  http://localhost:${ALDECI_UI_PORT:-3001}"
        echo -e "    ${CYAN}API Swagger:${NC}   http://localhost:${FIXOPS_PORT:-8000}/docs"
        echo -e "    ${CYAN}API Health:${NC}    http://localhost:${FIXOPS_PORT:-8000}/health"
        echo ""
        echo -e "  ${BOLD}Quick commands:${NC}"
        echo -e "    ${CYAN}View logs:${NC}     docker compose -f docker/docker-compose.yml logs -f"
        echo -e "    ${CYAN}Health check:${NC}  ./scripts/demo-healthcheck.sh"
        echo -e "    ${CYAN}Stop:${NC}          ./scripts/demo-start.sh --stop"
        echo ""

        # Run the health check
        echo -e "${BOLD}Running full health check...${NC}"
        echo ""
        "${SCRIPT_DIR}/demo-healthcheck.sh" || true
    else
        echo -e "${RED}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${RED}${BOLD}  ❌ ALdeci failed to start within ${timeout}s${NC}"
        echo -e "${RED}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo -e "  ${YELLOW}Troubleshooting:${NC}"
        echo "    docker compose -f docker/docker-compose.yml logs fixops"
        echo "    docker compose -f docker/docker-compose.yml logs aldeci-ui"
        echo "    docker compose -f docker/docker-compose.yml ps"
        exit 1
    fi
}

# ─── Main ───────────────────────────────────────────────────

banner

case "${1:-}" in
    --stop|-s)
        do_stop
        ;;
    --reset|-r)
        do_reset
        ;;
    --quick|-q)
        do_start true
        ;;
    --help|-h)
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  (none)     Build and start all services"
        echo "  --quick    Start without rebuilding (use cached images)"
        echo "  --stop     Stop all services"
        echo "  --reset    Stop, remove volumes and images, rebuild"
        echo "  --help     Show this help message"
        ;;
    *)
        do_start false
        ;;
esac
