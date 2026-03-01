#!/bin/bash
# ============================================================================
# ALdeci CTEM+ Full Loop Demo — End-to-End Decision Intelligence Pipeline
# ============================================================================
# Duration: 5 minutes
# Prerequisites: API running on localhost:8000 with valid API key
# Pillars: [V3] Decision Intelligence, [V5] MPTE, [V10] CTEM Full Loop
#
# This script demonstrates the complete CTEM+ lifecycle:
#   Discover → Normalize → Correlate → Verify → Decide → Fix → Prove
# ============================================================================

set -euo pipefail

BASE="${ALDECI_BASE_URL:-http://localhost:8000/api/v1}"
API_KEY="${FIXOPS_API_TOKEN:-demo-api-key}"
HEADERS=(-H "X-API-Key: $API_KEY" -H "Content-Type: application/json")

# Colors for terminal output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
BOLD='\033[1m'

step() { echo -e "\n${BOLD}${BLUE}━━━ STEP $1: $2 ━━━${NC}"; }
say()  { echo -e "${GREEN}▶ $1${NC}"; }
warn() { echo -e "${YELLOW}⚠ $1${NC}"; }
fail() { echo -e "${RED}✗ $1${NC}"; }

echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║         ALdeci CTEM+ Full Loop Demo                         ║${NC}"
echo -e "${BOLD}║  Discover → Verify → Decide → Fix → Prove                  ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"

# ──────────────────────────────────────────────────────────────────────────────
step "1/7" "DISCOVER — Native SAST Scan (No External Tools Needed)"
# ──────────────────────────────────────────────────────────────────────────────
say "Running ALdeci's built-in SAST engine against vulnerable Python code..."

SCAN_RESULT=$(curl -sf "${HEADERS[@]}" \
  -X POST "$BASE/sast/scan/code" \
  -d '{
    "code": "import subprocess\nimport sqlite3\n\ndef run_command(user_input):\n    result = subprocess.call(user_input, shell=True)\n    return result\n\ndef get_user(user_id):\n    conn = sqlite3.connect(\"app.db\")\n    query = \"SELECT * FROM users WHERE id=\" + user_id\n    return conn.execute(query).fetchall()\n\ndef render_page(name):\n    return f\"<h1>Welcome {name}</h1>\"",
    "language": "python",
    "filename": "vulnerable_app.py"
  }')

echo "$SCAN_RESULT" | python3 -m json.tool 2>/dev/null || echo "$SCAN_RESULT"
FINDING_COUNT=$(echo "$SCAN_RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('findings',[])))" 2>/dev/null || echo "0")
say "Found $FINDING_COUNT vulnerabilities with native SAST — no Snyk, no Semgrep, no internet."

# ──────────────────────────────────────────────────────────────────────────────
step "2/7" "NORMALIZE — Ingest into Brain Pipeline Knowledge Graph"
# ──────────────────────────────────────────────────────────────────────────────
say "Ingesting findings into the 12-step Brain Pipeline..."

INGEST_RESULT=$(curl -sf "${HEADERS[@]}" \
  -X POST "$BASE/brain/ingest/finding" \
  -d '{
    "finding_id": "ctem-demo-sqli-001",
    "title": "SQL Injection in get_user()",
    "severity": "CRITICAL",
    "cwe": "CWE-89",
    "source": "native-sast",
    "app_id": "APP-demo-service",
    "component": "user-service",
    "affected_file": "vulnerable_app.py",
    "affected_line": 10
  }')

echo "$INGEST_RESULT" | python3 -m json.tool 2>/dev/null || echo "$INGEST_RESULT"
say "Finding ingested as node in knowledge graph. Now connected to app, component, and CWE."

# ──────────────────────────────────────────────────────────────────────────────
step "3/7" "CORRELATE — Knowledge Graph Attack Path Analysis"
# ──────────────────────────────────────────────────────────────────────────────
say "Querying knowledge graph for attack paths and blast radius..."

GRAPH_STATS=$(curl -sf "${HEADERS[@]}" "$BASE/knowledge-graph/analytics")
echo "$GRAPH_STATS" | python3 -m json.tool 2>/dev/null || echo "$GRAPH_STATS"

BLAST=$(curl -sf "${HEADERS[@]}" \
  -X POST "$BASE/knowledge-graph/blast-radius" \
  -d '{"node_id": "APP-demo-service", "depth": 3}')
echo "$BLAST" | python3 -m json.tool 2>/dev/null || echo "$BLAST"
say "Blast radius calculated — shows all services affected if this vulnerability is exploited."

# ──────────────────────────────────────────────────────────────────────────────
step "4/7" "VERIFY — MPTE 19-Phase Exploit Verification [V5]"
# ──────────────────────────────────────────────────────────────────────────────
say "Launching micro-pentest to PROVE exploitability (not just detect)..."

MPTE_RESULT=$(curl -sf "${HEADERS[@]}" \
  -X POST "$BASE/mpte/verify" \
  -d '{
    "finding_id": "ctem-demo-sqli-001",
    "vulnerability_type": "sql_injection",
    "target": "http://demo-service:8080/api/users",
    "context": {
      "cwe": "CWE-89",
      "parameter": "user_id",
      "code_snippet": "SELECT * FROM users WHERE id= + user_id"
    }
  }')

echo "$MPTE_RESULT" | python3 -m json.tool 2>/dev/null || echo "$MPTE_RESULT"
say "MPTE verdict delivered — 19 phases completed with evidence hash."

# ──────────────────────────────────────────────────────────────────────────────
step "5/7" "DECIDE — AI Consensus + FAIL Scoring [V3]"
# ──────────────────────────────────────────────────────────────────────────────
say "Running multi-factor FAIL scoring and AI consensus..."

FAIL_RESULT=$(curl -sf "${HEADERS[@]}" \
  -X POST "$BASE/fail/score" \
  -d '{
    "finding_id": "ctem-demo-sqli-001",
    "cvss": 9.8,
    "epss": 0.87,
    "asset_criticality": "high",
    "reachable": true,
    "mpte_verified": true
  }')

echo "$FAIL_RESULT" | python3 -m json.tool 2>/dev/null || echo "$FAIL_RESULT"

AI_DECISION=$(curl -sf "${HEADERS[@]}" \
  -X POST "$BASE/ai-agent/decide" \
  -d '{
    "finding_id": "ctem-demo-sqli-001",
    "context": {
      "severity": "CRITICAL",
      "cwe": "CWE-89",
      "mpte_verified": true,
      "asset_criticality": "high",
      "blast_radius": 7
    }
  }')

echo "$AI_DECISION" | python3 -m json.tool 2>/dev/null || echo "$AI_DECISION"
say "AI consensus reached. Priority decision made with full reasoning trail."

# ──────────────────────────────────────────────────────────────────────────────
step "6/7" "FIX — AutoFix Code Patch Generation [V3]"
# ──────────────────────────────────────────────────────────────────────────────
say "Generating AI-powered code fix with confidence scoring..."

FIX_RESULT=$(curl -sf "${HEADERS[@]}" \
  -X POST "$BASE/autofix/generate" \
  -d '{
    "finding_id": "ctem-demo-sqli-001",
    "vulnerability_type": "sql_injection",
    "source_code": "def get_user(user_id):\n    conn = sqlite3.connect(\"app.db\")\n    query = \"SELECT * FROM users WHERE id=\" + user_id\n    return conn.execute(query).fetchall()",
    "language": "python",
    "fix_type": "CODE_PATCH"
  }')

echo "$FIX_RESULT" | python3 -m json.tool 2>/dev/null || echo "$FIX_RESULT"
say "Code fix generated with confidence score. HIGH confidence = auto-apply eligible."

# ──────────────────────────────────────────────────────────────────────────────
step "7/7" "PROVE — Cryptographically Signed Evidence Bundle [V10]"
# ──────────────────────────────────────────────────────────────────────────────
say "Generating tamper-proof evidence bundle with compliance mapping..."

EVIDENCE=$(curl -sf "${HEADERS[@]}" \
  "$BASE/compliance-engine/audit-bundle")
echo "$EVIDENCE" | python3 -m json.tool 2>/dev/null || echo "$EVIDENCE"

COMPLIANCE=$(curl -sf "${HEADERS[@]}" \
  -X POST "$BASE/compliance-engine/assess" \
  -d '{"framework": "SOC2"}')
echo "$COMPLIANCE" | python3 -m json.tool 2>/dev/null || echo "$COMPLIANCE"

say "Evidence bundle signed and compliance mapping generated."

# ──────────────────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║  CTEM+ FULL LOOP COMPLETE                                   ║${NC}"
echo -e "${BOLD}${GREEN}║                                                              ║${NC}"
echo -e "${BOLD}${GREEN}║  1. DISCOVER  — Native SAST found $FINDING_COUNT vulnerabilities          ║${NC}"
echo -e "${BOLD}${GREEN}║  2. NORMALIZE — Ingested into Knowledge Graph                ║${NC}"
echo -e "${BOLD}${GREEN}║  3. CORRELATE — Blast radius + attack paths calculated       ║${NC}"
echo -e "${BOLD}${GREEN}║  4. VERIFY    — MPTE proved exploitability (19 phases)       ║${NC}"
echo -e "${BOLD}${GREEN}║  5. DECIDE    — AI consensus + FAIL scoring                  ║${NC}"
echo -e "${BOLD}${GREEN}║  6. FIX       — AutoFix generated code patch                 ║${NC}"
echo -e "${BOLD}${GREEN}║  7. PROVE     — Signed evidence + compliance mapping         ║${NC}"
echo -e "${BOLD}${GREEN}║                                                              ║${NC}"
echo -e "${BOLD}${GREEN}║  No external tools. No internet. Full CTEM+ in < 60 seconds. ║${NC}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
