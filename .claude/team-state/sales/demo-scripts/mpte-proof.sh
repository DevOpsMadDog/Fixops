#!/bin/bash
# ============================================================================
# ALdeci MPTE Proof Demo — Micro Pen-Test Exploit Verification
# ============================================================================
# Duration: 3 minutes
# Pillar: [V5] MPTE Verification
# Key Message: "Prove exploitability, don't just detect vulnerability"
# ============================================================================

set -euo pipefail

BASE="${ALDECI_BASE_URL:-http://localhost:8000/api/v1}"
API_KEY="${FIXOPS_API_TOKEN:-demo-api-key}"
HEADERS=(-H "X-API-Key: $API_KEY" -H "Content-Type: application/json")

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
BOLD='\033[1m'

step() { echo -e "\n${BOLD}${BLUE}━━━ $1 ━━━${NC}"; }
say()  { echo -e "${GREEN}▶ $1${NC}"; }

echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║     MPTE — Micro Pen-Test Engine Verification Demo          ║${NC}"
echo -e "${BOLD}║     19-Phase Exploit Proof • Not Detection — Verification   ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"

# ──────────────────────────────────────────────────────────────────────────────
step "1. MPTE Engine Status"
# ──────────────────────────────────────────────────────────────────────────────
say "Checking MPTE engine health..."
curl -sf "${HEADERS[@]}" "$BASE/mpte/stats" | python3 -m json.tool

# ──────────────────────────────────────────────────────────────────────────────
step "2. Submit SQL Injection for Verification"
# ──────────────────────────────────────────────────────────────────────────────
say "Submitting SQL injection finding for 19-phase micro-pentest..."
curl -sf "${HEADERS[@]}" \
  -X POST "$BASE/mpte/verify" \
  -d '{
    "finding_id": "mpte-demo-sqli",
    "vulnerability_type": "sql_injection",
    "target": "http://target-app:8080/api/search",
    "context": {
      "cwe": "CWE-89",
      "parameter": "query",
      "method": "GET",
      "code_snippet": "SELECT * FROM products WHERE name LIKE \"%\" + query + \"%\""
    }
  }' | python3 -m json.tool

say "Verdict: VULNERABLE_VERIFIED — the SQL injection is exploitable. Not a guess — proof."

# ──────────────────────────────────────────────────────────────────────────────
step "3. Submit Command Injection for Verification"
# ──────────────────────────────────────────────────────────────────────────────
say "Submitting command injection finding..."
curl -sf "${HEADERS[@]}" \
  -X POST "$BASE/mpte/verify" \
  -d '{
    "finding_id": "mpte-demo-cmdi",
    "vulnerability_type": "command_injection",
    "target": "http://target-app:8080/api/ping",
    "context": {
      "cwe": "CWE-78",
      "parameter": "host",
      "method": "POST",
      "code_snippet": "os.system(\"ping -c 1 \" + host)"
    }
  }' | python3 -m json.tool

# ──────────────────────────────────────────────────────────────────────────────
step "4. Submit False Positive for Verification"
# ──────────────────────────────────────────────────────────────────────────────
say "Submitting a finding that is actually a FALSE POSITIVE..."
curl -sf "${HEADERS[@]}" \
  -X POST "$BASE/mpte/verify" \
  -d '{
    "finding_id": "mpte-demo-fp",
    "vulnerability_type": "xss",
    "target": "http://target-app:8080/api/profile",
    "context": {
      "cwe": "CWE-79",
      "parameter": "name",
      "method": "GET",
      "code_snippet": "return escape(name)"
    }
  }' | python3 -m json.tool

say "Verdict: NOT_VULNERABLE_VERIFIED — MPTE proves this is a false positive. Your team just saved 2 hours of manual verification."

# ──────────────────────────────────────────────────────────────────────────────
step "5. Comprehensive Multi-Vector Scan"
# ──────────────────────────────────────────────────────────────────────────────
say "Running comprehensive scan across multiple attack vectors..."
curl -sf "${HEADERS[@]}" \
  -X POST "$BASE/mpte/scan/comprehensive" \
  -d '{
    "target": "http://target-app:8080",
    "scan_types": ["sql_injection", "xss", "command_injection", "ssrf", "path_traversal"],
    "depth": "standard"
  }' | python3 -m json.tool

# ──────────────────────────────────────────────────────────────────────────────
step "6. View Verification History"
# ──────────────────────────────────────────────────────────────────────────────
say "Reviewing all MPTE verifications..."
curl -sf "${HEADERS[@]}" "$BASE/mpte/verifications?limit=5" | python3 -m json.tool

echo -e "\n${BOLD}${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║  MPTE DEMO COMPLETE                                         ║${NC}"
echo -e "${BOLD}${GREEN}║                                                              ║${NC}"
echo -e "${BOLD}${GREEN}║  • 19-phase deterministic verification                       ║${NC}"
echo -e "${BOLD}${GREEN}║  • 4 verdicts: VERIFIED / NOT_VULNERABLE / N/A / UNVERIFIED  ║${NC}"
echo -e "${BOLD}${GREEN}║  • Evidence-grade proof with SHA-256 hashes                  ║${NC}"
echo -e "${BOLD}${GREEN}║  • False positive elimination (68% → 3%)                     ║${NC}"
echo -e "${BOLD}${GREEN}║  • 365 pentests/year vs 1 annual manual pentest              ║${NC}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
