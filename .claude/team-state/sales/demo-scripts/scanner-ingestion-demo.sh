#!/bin/bash
# =============================================================================
# ALdeci MOAT Demo: Scanner Ingestion — "25 Parsers, Zero Rip-and-Replace"
# =============================================================================
# Pillar: [V7] MCP-Native AI Platform
# Duration: 2 minutes
# Prerequisites: API running at localhost:8000 with valid API key
# Last validated: 2026-03-02 (all endpoints 200 OK)
# =============================================================================

set -euo pipefail

BASE="${ALDECI_BASE_URL:-http://localhost:8000/api/v1}"
API_KEY="${FIXOPS_API_TOKEN:-${ALDECI_API_KEY:-}}"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'
BOLD='\033[1m'

print_step() { echo -e "\n${CYAN}━━━ Step $1: $2 ━━━${NC}"; }
print_say() { echo -e "${YELLOW}💬 SAY:${NC} $1"; }
print_ok() { echo -e "${GREEN}✅ $1${NC}"; }
print_fail() { echo -e "${RED}❌ $1${NC}"; }

echo -e "${BOLD}${BLUE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   ALdeci MOAT Demo: Scanner Ingestion                       ║"
echo "║   '25 Parsers, Zero Rip-and-Replace, Day 1 Value'           ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Pre-flight
if [ -z "$API_KEY" ]; then
    echo -e "${RED}ERROR: Set FIXOPS_API_TOKEN or ALDECI_API_KEY${NC}"
    exit 1
fi

STATUS=$(curl -sf -o /dev/null -w "%{http_code}" -H "X-API-Key: $API_KEY" "$BASE/scanner-ingest/status" 2>/dev/null || echo "000")
if [ "$STATUS" = "200" ]; then
    print_ok "Scanner Ingestion API is healthy"
else
    print_fail "Scanner Ingestion API returned HTTP $STATUS — check API is running"
    exit 1
fi

# =============================================================================
print_step "1" "Scanner Ingestion Status — What parsers are available?"
# =============================================================================
print_say "ALdeci supports 25 scanner formats out of the box. Let me show you what's available."

echo -e "\n${BOLD}Request:${NC}"
echo "  GET $BASE/scanner-ingest/status"
echo -e "\n${BOLD}Response:${NC}"
curl -s -H "X-API-Key: $API_KEY" "$BASE/scanner-ingest/status" | python3 -m json.tool 2>/dev/null || \
    curl -s -H "X-API-Key: $API_KEY" "$BASE/scanner-ingest/status"

print_say "25 scanner parsers — Snyk, Semgrep, Nessus, Qualys, ZAP, Burp, Trivy, Grype, and more. No plugins to install, no connectors to configure."

# =============================================================================
print_step "2" "Auto-Detect Scanner Format — Smart Format Recognition"
# =============================================================================
print_say "Upload any report and ALdeci auto-detects the format. Watch."

SNYK_SAMPLE='{"vulnerabilities":[{"id":"SNYK-JS-LODASH-567746","title":"Prototype Pollution in lodash","severity":"high","packageName":"lodash","version":"4.17.20","fixedIn":["4.17.21"]}],"ok":false,"dependencyCount":342}'

echo -e "\n${BOLD}Request:${NC}"
echo "  POST $BASE/scanner-ingest/detect"
echo "  Body: {Snyk-format JSON report}"
echo -e "\n${BOLD}Response:${NC}"
curl -s -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
    -X POST "$BASE/scanner-ingest/detect" \
    -d "{\"content\": $(echo "$SNYK_SAMPLE" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))'), \"filename\": \"snyk-report.json\"}" | python3 -m json.tool 2>/dev/null || echo "(see raw output)"

print_say "Auto-detected as Snyk format with high confidence. Zero configuration needed."

# =============================================================================
print_step "3" "Webhook Ingestion — CI/CD Pipeline Integration"
# =============================================================================
print_say "In your CI/CD, just POST findings to our webhook. Zero rip-and-replace."

echo -e "\n${BOLD}Request:${NC}"
echo "  POST $BASE/scanner-ingest/webhook/snyk"
echo -e "\n${BOLD}Response:${NC}"
curl -s -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
    -X POST "$BASE/scanner-ingest/webhook/snyk" \
    -d "$SNYK_SAMPLE" | python3 -m json.tool 2>/dev/null || echo "(see raw output)"

print_say "Your existing Snyk CI/CD pipeline stays unchanged. Just add one webhook URL. Day 1 value from your existing scanner investment."

# =============================================================================
echo -e "\n${BOLD}${GREEN}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   KEY DIFFERENTIATOR:                                        ║"
echo "║   25 scanner parsers. Zero rip-and-replace.                  ║"
echo "║   Your existing tools keep working. ALdeci makes them       ║"
echo "║   smarter with Brain Pipeline + MPTE + AutoFix on top.     ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

print_say "25 parsers, zero rip-and-replace, Day 1 value. That's the Switzerland of AppSec."
echo -e "\n${BLUE}Demo complete. Duration: ~2 minutes.${NC}"
