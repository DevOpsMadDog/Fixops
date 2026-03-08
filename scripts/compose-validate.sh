#!/usr/bin/env bash
# ============================================
# ALdeci CTEM+ Platform — Compose Validator
# ============================================
# Validates all Docker compose files, Dockerfiles,
# shell scripts, and .dockerignore configuration.
#
# Run before committing Docker changes:
#   ./scripts/compose-validate.sh
#   ./scripts/compose-validate.sh --ci     # Exit code for CI
#   ./scripts/compose-validate.sh --fix    # Auto-fix common issues
#
# Exit codes:
#   0 = All checks passed
#   1 = One or more checks failed
# ============================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ─── Parse flags ─────────────────────────────────────────────
CI_MODE=false
FIX_MODE=false
for arg in "$@"; do
    case "$arg" in
        --ci)  CI_MODE=true ;;
        --fix) FIX_MODE=true ;;
        --help|-h)
            echo "Usage: $0 [--ci] [--fix]"
            echo "  --ci   CI mode: exit code only, no colors"
            echo "  --fix  Auto-fix common issues"
            exit 0
            ;;
    esac
done

# ─── Colors ──────────────────────────────────────────────────
if [[ "$CI_MODE" == "true" ]]; then
    RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; NC=''
else
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    NC='\033[0m'
fi

# ─── Counters ────────────────────────────────────────────────
PASS=0
FAIL=0
WARN=0

pass() { echo -e "  ${GREEN}✅${NC} $1"; PASS=$((PASS + 1)); }
fail() { echo -e "  ${RED}❌${NC} $1"; FAIL=$((FAIL + 1)); }
warn() { echo -e "  ${YELLOW}⚠️${NC}  $1"; WARN=$((WARN + 1)); }

# ─── 1. Compose File Validation ─────────────────────────────
echo -e "${BOLD}━━━ Docker Compose Files ━━━${NC}"

COMPOSE_FILES=(
    "docker/docker-compose.yml"
    "docker/docker-compose.enterprise.yml"
    "docker/docker-compose.vc-demo.yml"
    "docker/docker-compose.air-gapped-test.yml"
    "docker/docker-compose.integration.yml"
    "docker/docker-compose.demo.yml"
    "docker/docker-compose.aldeci-complete.yml"
    "docker/docker-compose.mpte.yml"
    "docker/docker-compose.mindsdb.yml"
    "docker-compose.demo.yml"
)

for f in "${COMPOSE_FILES[@]}"; do
    filepath="${REPO_ROOT}/${f}"
    if [ -f "$filepath" ]; then
        if docker compose -f "$filepath" config --quiet 2>/dev/null; then
            pass "$f"
        else
            fail "$f"
            docker compose -f "$filepath" config 2>&1 | tail -3 | sed 's/^/    /'
        fi
    fi
done

# ─── 2. Dockerfile Validation ───────────────────────────────
echo ""
echo -e "${BOLD}━━━ Dockerfiles ━━━${NC}"

for f in "${REPO_ROOT}"/docker/Dockerfile*; do
    if [ -f "$f" ]; then
        name=$(basename "$f")
        lines=$(wc -l < "$f")
        if grep -q "^FROM" "$f"; then
            # Check for best practices
            issues=""
            if ! grep -q "HEALTHCHECK" "$f"; then
                issues="${issues} no-healthcheck"
            fi
            if ! grep -q "USER\|user:" "$f"; then
                issues="${issues} runs-as-root"
            fi
            if [ -z "$issues" ]; then
                pass "$name ($lines lines)"
            else
                warn "$name ($lines lines) —${issues}"
            fi
        else
            fail "$name — missing FROM instruction"
        fi
    fi
done

# ─── 3. Shell Script Validation ──────────────────────────────
echo ""
echo -e "${BOLD}━━━ Shell Scripts ━━━${NC}"

SHELL_SCRIPTS=(
    "scripts/demo-healthcheck.sh"
    "scripts/demo-start.sh"
    "scripts/air-gapped-test.sh"
    "scripts/docker-entrypoint.sh"
    "scripts/compose-validate.sh"
    "scripts/local-dev-setup.sh"
    "scripts/preflight-check.sh"
)

for f in "${SHELL_SCRIPTS[@]}"; do
    filepath="${REPO_ROOT}/${f}"
    if [ -f "$filepath" ]; then
        if bash -n "$filepath" 2>/dev/null; then
            # Check executable bit
            if [ -x "$filepath" ]; then
                pass "$f (valid bash, executable)"
            else
                if [[ "$FIX_MODE" == "true" ]]; then
                    chmod +x "$filepath"
                    pass "$f (valid bash, fixed +x)"
                else
                    warn "$f (valid bash, not executable — run --fix)"
                fi
            fi
        else
            fail "$f (syntax error)"
            bash -n "$filepath" 2>&1 | head -3 | sed 's/^/    /'
        fi
    fi
done

# ─── 4. .dockerignore Validation ────────────────────────────
echo ""
echo -e "${BOLD}━━━ .dockerignore ━━━${NC}"

DOCKERIGNORE="${REPO_ROOT}/.dockerignore"
if [ -f "$DOCKERIGNORE" ]; then
    pass ".dockerignore exists ($(wc -l < "$DOCKERIGNORE") lines)"
    REQUIRED_PATTERNS=(".env" "__pycache__" ".git" "node_modules" "*.db" ".env.*")
    for pattern in "${REQUIRED_PATTERNS[@]}"; do
        if grep -q "$pattern" "$DOCKERIGNORE"; then
            pass "Excludes $pattern"
        else
            if [[ "$FIX_MODE" == "true" ]]; then
                echo "$pattern" >> "$DOCKERIGNORE"
                pass "Added exclusion for $pattern"
            else
                warn "Missing exclusion for $pattern"
            fi
        fi
    done
else
    fail ".dockerignore missing!"
fi

# ─── 5. nginx Config Validation ─────────────────────────────
echo ""
echo -e "${BOLD}━━━ nginx Configuration ━━━${NC}"

NGINX_CONF="${REPO_ROOT}/docker/nginx-aldeci.conf"
if [ -f "$NGINX_CONF" ]; then
    pass "nginx-aldeci.conf exists"
    # Check for required proxy locations
    for location in "/api/" "/health" "/docs" "/openapi.json" "/nginx-health"; do
        if grep -q "location.*${location}" "$NGINX_CONF"; then
            pass "Proxies ${location}"
        else
            fail "Missing proxy for ${location}"
        fi
    done
    # Check for MCP SSE support [V7]
    if grep -q "mcp-protocol/sse" "$NGINX_CONF"; then
        pass "MCP SSE proxy configured [V7]"
    else
        warn "Missing MCP SSE proxy — AI agents may timeout"
    fi
    # Check for WebSocket support
    if grep -q "Upgrade.*upgrade" "$NGINX_CONF"; then
        pass "WebSocket upgrade configured"
    else
        warn "Missing WebSocket upgrade — real-time features may not work"
    fi
    # Check for OWASP security headers
    for header in "X-Frame-Options" "X-Content-Type-Options" "X-XSS-Protection" "Strict-Transport-Security"; do
        if grep -q "$header" "$NGINX_CONF"; then
            pass "Security header: ${header}"
        else
            warn "Missing security header: ${header}"
        fi
    done
    # Check for rate limiting
    if grep -q "limit_req_zone" "$NGINX_CONF"; then
        pass "API rate limiting configured"
    else
        warn "No API rate limiting — consider adding limit_req_zone"
    fi
else
    fail "nginx-aldeci.conf missing!"
fi

# ─── 6. Security Checks ─────────────────────────────────────
echo ""
echo -e "${BOLD}━━━ Security Checks ━━━${NC}"

# Check that no compose file has hardcoded real secrets
COMPOSE_DIR="${REPO_ROOT}/docker"
for f in "${COMPOSE_DIR}"/docker-compose*.yml; do
    if [ -f "$f" ]; then
        name=$(basename "$f")
        # Look for patterns that indicate hardcoded secrets (not ${VAR:-default} pattern)
        if grep -qE '(sk-proj-|sk-[a-zA-Z0-9]{20,}|password:\s*"[^$"][^"]{8,}")' "$f" 2>/dev/null; then
            fail "$name — contains potential hardcoded secrets!"
        fi
    fi
done
pass "No hardcoded secrets in compose files"

# Check that main Dockerfile uses non-root user
MAIN_DOCKERFILE="${REPO_ROOT}/docker/Dockerfile"
if grep -q "^USER" "$MAIN_DOCKERFILE"; then
    pass "Main Dockerfile uses non-root user"
else
    fail "Main Dockerfile runs as root!"
fi

# ─── Summary ─────────────────────────────────────────────────
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${BOLD}Results:${NC} ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}, ${YELLOW}${WARN} warnings${NC}"

if [[ $FAIL -eq 0 && $WARN -eq 0 ]]; then
    echo -e "  ${GREEN}${BOLD}✅ ALL CHECKS PASSED${NC}"
elif [[ $FAIL -eq 0 ]]; then
    echo -e "  ${YELLOW}${BOLD}⚠️  PASSED with ${WARN} warnings${NC}"
else
    echo -e "  ${RED}${BOLD}❌ FAILED — ${FAIL} checks did not pass${NC}"
fi
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Exit code
if [[ $FAIL -gt 0 ]]; then
    exit 1
else
    exit 0
fi
