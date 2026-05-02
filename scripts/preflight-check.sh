#!/usr/bin/env bash
# ============================================
# ALdeci CTEM+ — Pre-Flight Check
# ============================================
# Run BEFORE `docker compose up` to catch issues early.
# No Docker daemon or build required.
#
# Usage:
#   ./scripts/preflight-check.sh
#
# Exit codes:
#   0 = Ready to build and run
#   1 = Issues found — fix before proceeding
# ============================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0

pass() { echo -e "  ${GREEN}✅${NC} $1"; PASS=$((PASS + 1)); }
fail() { echo -e "  ${RED}❌${NC} $1"; FAIL=$((FAIL + 1)); }
warn() { echo -e "  ${YELLOW}⚠️${NC}  $1"; WARN=$((WARN + 1)); }

echo -e "${CYAN}"
echo "  ┌─────────────────────────────────────────────┐"
echo "  │     ALdeci CTEM+ Pre-Flight Check            │"
echo "  │     Run before docker compose up             │"
echo "  └─────────────────────────────────────────────┘"
echo -e "${NC}"

# ── 1. Docker ──────────────────────────────────────────────
echo -e "${BOLD}Docker Environment${NC}"

if command -v docker &>/dev/null; then
    pass "Docker CLI installed"
else
    fail "Docker not installed — see https://docs.docker.com/desktop/"
fi

if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
    DOCKER_VER=$(docker --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    pass "Docker daemon running (v${DOCKER_VER})"
else
    fail "Docker daemon not running — start Docker Desktop"
fi

if command -v docker &>/dev/null && docker compose version &>/dev/null 2>&1; then
    COMPOSE_VER=$(docker compose version --short 2>/dev/null || echo "unknown")
    pass "Docker Compose available (v${COMPOSE_VER})"
else
    fail "Docker Compose not available"
fi

# ── 2. Ports ───────────────────────────────────────────────
echo ""
echo -e "${BOLD}Port Availability${NC}"

for port in 8000 3001; do
    if command -v lsof &>/dev/null; then
        if lsof -i ":${port}" -sTCP:LISTEN &>/dev/null 2>&1; then
            PID=$(lsof -ti ":${port}" -sTCP:LISTEN 2>/dev/null | head -1)
            fail "Port ${port} in use (PID: ${PID:-unknown})"
        else
            pass "Port ${port} available"
        fi
    else
        pass "Port ${port} (cannot verify — lsof not available)"
    fi
done

# ── 3. Required Files ─────────────────────────────────────
echo ""
echo -e "${BOLD}Required Files${NC}"

REQUIRED_FILES=(
    "docker/docker-compose.yml"
    "docker/Dockerfile"
    "docker/Dockerfile.aldeci-ui"
    "docker/nginx-aldeci.conf"
    "scripts/docker-entrypoint.sh"
    "scripts/demo-healthcheck.sh"
    "requirements.txt"
    "sitecustomize.py"
    ".dockerignore"
)

for f in "${REQUIRED_FILES[@]}"; do
    if [ -f "${REPO_ROOT}/${f}" ]; then
        pass "${f}"
    else
        fail "${f} missing!"
    fi
done

# ── 4. Suite Directories ──────────────────────────────────
echo ""
echo -e "${BOLD}Suite Directories${NC}"

for suite in suite-api suite-core suite-attack suite-feeds suite-evidence-risk suite-integrations; do
    if [ -d "${REPO_ROOT}/${suite}" ]; then
        file_count=$(find "${REPO_ROOT}/${suite}" -name "*.py" -type f | wc -l | tr -d ' ')
        pass "${suite}/ (${file_count} Python files)"
    else
        fail "${suite}/ missing!"
    fi
done

if [ -d "${REPO_ROOT}/suite-ui/aldeci-ui-new" ]; then
    pass "suite-ui/aldeci-ui-new/ (UI source)"
else
    fail "suite-ui/aldeci-ui-new/ missing!"
fi

# ── 5. Compose Validation ─────────────────────────────────
echo ""
echo -e "${BOLD}Compose Validation${NC}"

if docker compose -f "${REPO_ROOT}/docker/docker-compose.yml" config --quiet 2>/dev/null; then
    pass "docker-compose.yml valid"
else
    fail "docker-compose.yml has syntax errors"
fi

# ── 6. Disk Space ─────────────────────────────────────────
echo ""
echo -e "${BOLD}System Resources${NC}"

if command -v df &>/dev/null; then
    AVAIL_GB=$(df -BG "${REPO_ROOT}" 2>/dev/null | tail -1 | awk '{print $4}' | tr -d 'G' || echo "0")
    if [ -n "$AVAIL_GB" ] && [ "$AVAIL_GB" -gt 0 ] 2>/dev/null; then
        if [ "$AVAIL_GB" -ge 10 ]; then
            pass "Disk space: ${AVAIL_GB}GB available (need ~5GB)"
        elif [ "$AVAIL_GB" -ge 5 ]; then
            warn "Disk space: ${AVAIL_GB}GB available (may be tight)"
        else
            fail "Disk space: ${AVAIL_GB}GB available (need at least 5GB)"
        fi
    else
        pass "Disk space check skipped (non-standard df output)"
    fi
fi

if command -v sysctl &>/dev/null; then
    RAM_GB=$(sysctl -n hw.memsize 2>/dev/null | awk '{printf "%.0f", $1/1073741824}' || echo "0")
    if [ -n "$RAM_GB" ] && [ "$RAM_GB" -gt 0 ] 2>/dev/null; then
        if [ "$RAM_GB" -ge 8 ]; then
            pass "RAM: ${RAM_GB}GB (recommend 8GB+)"
        else
            warn "RAM: ${RAM_GB}GB (recommend 8GB+ for smooth demo)"
        fi
    fi
elif [ -f /proc/meminfo ]; then
    RAM_GB=$(awk '/MemTotal/ {printf "%.0f", $2/1048576}' /proc/meminfo)
    if [ "$RAM_GB" -ge 8 ]; then
        pass "RAM: ${RAM_GB}GB (recommend 8GB+)"
    else
        warn "RAM: ${RAM_GB}GB (recommend 8GB+ for smooth demo)"
    fi
fi

# ── Summary ────────────────────────────────────────────────
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${BOLD}Results:${NC} ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}, ${YELLOW}${WARN} warnings${NC}"

if [[ $FAIL -eq 0 ]]; then
    echo -e "  ${GREEN}${BOLD}✅ Pre-flight check PASSED — ready to build!${NC}"
    echo ""
    echo -e "  ${BOLD}Next steps:${NC}"
    echo "    ./scripts/demo-start.sh          # Build and start"
    echo "    ./scripts/demo-healthcheck.sh     # Verify health"
    echo ""
else
    echo -e "  ${RED}${BOLD}❌ Pre-flight check FAILED — fix issues above first${NC}"
fi
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

exit $FAIL
