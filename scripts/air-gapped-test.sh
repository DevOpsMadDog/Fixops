#!/usr/bin/env bash
# ============================================
# ALdeci CTEM+ Air-Gapped Deployment Test
# ============================================
# Proves ALdeci works with ZERO internet access.
# MOAT 3: $2.3B defense/gov market.
#
# Usage:
#   ./scripts/air-gapped-test.sh             # Full test
#   ./scripts/air-gapped-test.sh --build     # Force rebuild
#   ./scripts/air-gapped-test.sh --cleanup   # Remove containers/images
#
# Exit codes:
#   0 = All checks passed (air-gapped deployment works)
#   1 = One or more checks failed
# ============================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/docker/docker-compose.air-gapped-test.yml"
LOG_FILE="${REPO_ROOT}/logs/air-gapped-test-$(date +%Y%m%d-%H%M%S).log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ─── Functions ──────────────────────────────────────────────

banner() {
    echo -e "${CYAN}"
    echo "  ┌─────────────────────────────────────────────────┐"
    echo "  │   ALdeci CTEM+ Air-Gapped Deployment Test        │"
    echo "  │   MOAT 3: \$2.3B Defense/Gov Market               │"
    echo "  │   Proving ZERO-internet operation                │"
    echo "  └─────────────────────────────────────────────────┘"
    echo -e "${NC}"
}

check_prereqs() {
    # Docker daemon
    if ! docker info &> /dev/null 2>&1; then
        echo -e "${RED}ERROR: Docker daemon is not running.${NC}"
        echo "  Start Docker Desktop and try again."
        exit 1
    fi

    # Compose file
    if [[ ! -f "$COMPOSE_FILE" ]]; then
        echo -e "${RED}ERROR: Compose file not found: ${COMPOSE_FILE}${NC}"
        exit 1
    fi

    # Validate compose syntax
    if ! docker compose -f "$COMPOSE_FILE" config --quiet 2>/dev/null; then
        echo -e "${RED}ERROR: Invalid compose file.${NC}"
        docker compose -f "$COMPOSE_FILE" config 2>&1 | tail -5
        exit 1
    fi

    echo -e "  ${GREEN}✅${NC} Prerequisites OK"
}

cleanup() {
    echo -e "${YELLOW}Cleaning up air-gapped test containers...${NC}"
    docker compose -f "$COMPOSE_FILE" down -v --remove-orphans 2>/dev/null || true
    echo -e "${GREEN}Cleanup complete.${NC}"
}

run_test() {
    local build_flag="${1:-}"
    local timeout=180  # 3 minutes max
    local start_time=$(date +%s)

    mkdir -p "$(dirname "$LOG_FILE")"

    echo -e "${BOLD}Step 1: Building images...${NC}"
    if [[ "$build_flag" == "--build" ]] || [[ "$build_flag" == "--force-build" ]]; then
        docker compose -f "$COMPOSE_FILE" build --no-cache 2>&1 | tee -a "$LOG_FILE"
    else
        docker compose -f "$COMPOSE_FILE" build 2>&1 | tee -a "$LOG_FILE"
    fi
    echo ""

    echo -e "${BOLD}Step 2: Starting air-gapped services (internal network, no internet)...${NC}"
    # Start only the API service first
    docker compose -f "$COMPOSE_FILE" up -d aldeci-airgapped 2>&1 | tee -a "$LOG_FILE"
    echo ""

    echo -e "${BOLD}Step 3: Waiting for API health check...${NC}"
    local elapsed=0
    while [[ $elapsed -lt 60 ]]; do
        local health
        health=$(docker inspect --format='{{.State.Health.Status}}' aldeci-airgapped 2>/dev/null) || health="unknown"
        if [[ "$health" == "healthy" ]]; then
            echo -e "  ${GREEN}✅${NC} API server healthy after ${elapsed}s"
            break
        fi
        sleep 2
        elapsed=$((elapsed + 2))
        if [[ $((elapsed % 10)) -eq 0 ]]; then
            echo -e "  ${YELLOW}⏳${NC} Waiting for API... (${elapsed}s, status: ${health})"
        fi
    done

    if [[ $elapsed -ge 60 ]]; then
        echo -e "  ${RED}❌${NC} API server failed to become healthy within 60s"
        echo -e "${YELLOW}Logs:${NC}"
        docker compose -f "$COMPOSE_FILE" logs aldeci-airgapped 2>&1 | tail -20
        cleanup
        exit 1
    fi
    echo ""

    echo -e "${BOLD}Step 4: Running air-gapped test suite...${NC}"
    echo ""

    # Run the tester container — it runs the full validation suite
    # and exits with code = number of failures
    local exit_code=0
    docker compose -f "$COMPOSE_FILE" up --exit-code-from aldeci-airgap-tester aldeci-airgap-tester 2>&1 | tee -a "$LOG_FILE" || exit_code=$?

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${BOLD}Duration:${NC} ${duration}s"
    echo -e "  ${BOLD}Log:${NC} ${LOG_FILE}"

    if [[ $exit_code -eq 0 ]]; then
        echo -e "  ${GREEN}${BOLD}✅ AIR-GAPPED TEST PASSED${NC}"
        echo -e "  ${GREEN}${BOLD}   ALdeci works with ZERO internet access.${NC}"
        echo -e "  ${GREEN}${BOLD}   Defense/Gov deployment: VALIDATED.${NC}"
    else
        echo -e "  ${RED}${BOLD}❌ AIR-GAPPED TEST FAILED (exit code: ${exit_code})${NC}"
        echo -e "  ${YELLOW}Check logs:${NC} docker compose -f $COMPOSE_FILE logs"
    fi
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    # Cleanup
    cleanup

    exit $exit_code
}

# ─── Main ───────────────────────────────────────────────────

banner

case "${1:-}" in
    --cleanup|-c)
        cleanup
        ;;
    --build|-b)
        check_prereqs
        run_test "--build"
        ;;
    --help|-h)
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  (none)      Build and run air-gapped test"
        echo "  --build     Force rebuild without cache"
        echo "  --cleanup   Remove test containers and volumes"
        echo "  --help      Show this help message"
        echo ""
        echo "This script proves ALdeci works offline by:"
        echo "  1. Building the enterprise image"
        echo "  2. Starting it in a Docker network with internal:true (no internet)"
        echo "  3. Running 30+ health checks and CTEM loop validation"
        echo "  4. Verifying external network access is blocked"
        ;;
    *)
        check_prereqs
        run_test
        ;;
esac
