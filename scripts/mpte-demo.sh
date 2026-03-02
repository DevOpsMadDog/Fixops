#!/usr/bin/env bash
#
# ALdeci MPTE Demo — Micro-Pentest Threat Evaluation
# ════════════════════════════════════════════════════
#
# Demonstrates the MPTE verification pipeline:
#   1. Submit vulnerability finding
#   2. Run comprehensive MPTE scan
#   3. Verify exploitability
#   4. Generate PoC via sandbox
#   5. Create signed evidence bundle
#
# Usage:
#   ./scripts/mpte-demo.sh
#   VERBOSE=1 ./scripts/mpte-demo.sh
#
# Pillar: V5 (MPTE Verification) + V10 (CTEM Evidence)
# Sprint: 2 — Enterprise Demo (2026-03-06)
#

set -euo pipefail

# ── Config ──────────────────────────────────────────────────────────────
BASE="${ALDECI_BASE_URL:-http://localhost:8000}"
TOKEN="${FIXOPS_API_TOKEN:-aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh}"
VERBOSE="${VERBOSE:-0}"
PASS=0
FAIL=0
TOTAL=0
START_TIME=$(date +%s)

# ── Colors ──────────────────────────────────────────────────────────────
GREEN='\033[92m'
RED='\033[91m'
CYAN='\033[96m'
MAGENTA='\033[95m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ── Helpers ─────────────────────────────────────────────────────────────
step() {
    TOTAL=$((TOTAL + 1))
    echo -e "\n  ${BOLD}${MAGENTA}Step ${TOTAL}:${RESET} $1"
}

ok() {
    PASS=$((PASS + 1))
    echo -e "    ${GREEN}✓${RESET} $1"
}

fail() {
    FAIL=$((FAIL + 1))
    echo -e "    ${RED}✗${RESET} $1"
}

api() {
    local method="$1"
    local path="$2"
    local data="${3:-}"
    local url="${BASE}/${path}"

    if [ -n "$data" ]; then
        RESPONSE=$(curl -s -w "\n%{http_code}" \
            -X "$method" \
            -H "X-API-Key: ${TOKEN}" \
            -H "Content-Type: application/json" \
            -d "$data" \
            "$url" 2>&1) || true
    else
        RESPONSE=$(curl -s -w "\n%{http_code}" \
            -X "$method" \
            -H "X-API-Key: ${TOKEN}" \
            "$url" 2>&1) || true
    fi

    HTTP_CODE=$(echo "$RESPONSE" | tail -1)
    HTTP_BODY=$(echo "$RESPONSE" | sed '$d')

    if [ "$VERBOSE" = "1" ]; then
        echo -e "    ${DIM}${method} ${path} → ${HTTP_CODE}${RESET}"
        echo -e "    ${DIM}$(echo "$HTTP_BODY" | head -c 200)${RESET}"
    fi
}

# ── Banner ──────────────────────────────────────────────────────────────
echo -e "${BOLD}${CYAN}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                                                              ║"
echo "║   ALdeci MPTE Demo — Micro-Pentest Threat Evaluation         ║"
echo "║   Verify exploitability → Generate PoC → Sign evidence       ║"
echo "║                                                              ║"
echo "║   $(date '+%Y-%m-%d %H:%M:%S')                                          ║"
echo "║   Target: ${BASE}                                     ║"
echo "║                                                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${RESET}"

# ── Pre-flight ──────────────────────────────────────────────────────────
echo -e "${BOLD}${CYAN}━━━ Pre-flight checks ━━━${RESET}"

step "API health check"
api GET "health"
if [ "$HTTP_CODE" = "200" ]; then
    ok "API is healthy at ${BASE}"
else
    fail "API unreachable (${HTTP_CODE})"
    echo -e "${RED}ERROR: Start API with: python -m uvicorn apps.api.app:create_app --factory --port 8000${RESET}"
    exit 1
fi

step "MPTE engine status"
api GET "api/v1/mpte/stats"
if [ "$HTTP_CODE" = "200" ]; then
    ok "MPTE engine operational"
else
    fail "MPTE engine not responding (${HTTP_CODE})"
fi

step "Sandbox verifier health"
api GET "api/v1/sandbox/health"
if [ "$HTTP_CODE" = "200" ]; then
    ok "Sandbox verifier operational"
else
    fail "Sandbox verifier not responding (${HTTP_CODE})"
fi

# ── Phase 1: Submit findings for verification ──────────────────────────
echo -e "\n${BOLD}${CYAN}━━━ Phase 1: Submit Findings ━━━${RESET}"

step "Submit SQL injection finding to brain pipeline"
api POST "api/v1/brain/pipeline/run" '{
    "org_id": "mpte-demo",
    "app_id": "vulnerable-webapp",
    "trigger": "mpte-demo",
    "findings": [
        {
            "id": "MPTE-SQLI-001",
            "type": "sql_injection",
            "severity": "critical",
            "cwe": "CWE-89",
            "cve_id": "CVE-2024-22259",
            "title": "SQL Injection in login endpoint — unsanitized user input concatenated into SQL query",
            "source": "sast",
            "app_id": "vulnerable-webapp",
            "cvss_score": 9.8,
            "epss_score": 0.12,
            "location": {
                "file": "src/main/java/com/webapp/LoginController.java",
                "line": 34
            }
        },
        {
            "id": "MPTE-XSS-001",
            "type": "cross_site_scripting",
            "severity": "high",
            "cwe": "CWE-79",
            "title": "Reflected XSS via search parameter — user input rendered without encoding",
            "source": "sast",
            "app_id": "vulnerable-webapp",
            "cvss_score": 7.1,
            "epss_score": 0.08,
            "location": {
                "file": "src/main/java/com/webapp/SearchController.java",
                "line": 22
            }
        },
        {
            "id": "MPTE-DESER-001",
            "type": "insecure_deserialization",
            "severity": "critical",
            "cwe": "CWE-502",
            "title": "Java ObjectInputStream deserialization of untrusted data",
            "source": "sast",
            "app_id": "vulnerable-webapp",
            "cvss_score": 9.0,
            "location": {
                "file": "src/main/java/com/webapp/SessionHandler.java",
                "line": 55
            }
        }
    ]
}'
if [ "$HTTP_CODE" = "200" ]; then
    RUN_ID=$(echo "$HTTP_BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('run_id','?'))" 2>/dev/null || echo "?")
    ok "Brain pipeline processed findings (run_id=${RUN_ID})"
else
    fail "Brain pipeline failed (${HTTP_CODE})"
fi

# ── Phase 2: MPTE Verification ─────────────────────────────────────────
echo -e "\n${BOLD}${CYAN}━━━ Phase 2: MPTE Verification ━━━${RESET}"

step "Run MPTE comprehensive scan"
api POST "api/v1/mpte/scan/comprehensive" '{
    "target": "localhost:8000",
    "scan_type": "full",
    "include_cve_verification": true,
    "cve_ids": ["CVE-2024-22259"]
}'
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
    ok "MPTE scan initiated (status=$(echo "$HTTP_BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','?'))" 2>/dev/null))"
else
    fail "MPTE scan failed (${HTTP_CODE})"
fi

step "Verify SQL injection exploitability"
api POST "api/v1/mpte/verify" '{
    "finding_id": "MPTE-SQLI-001",
    "target_url": "https://httpbin.org",
    "vulnerability_type": "sql_injection",
    "evidence": "SQL injection in login endpoint: SELECT * FROM users WHERE username = [user_input] AND password = [user_input]. Parameterized queries not used. Input directly concatenated into SQL string."
}'
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
    VERIFY_RESULT=$(echo "$HTTP_BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status', d.get('result','?')))" 2>/dev/null || echo "?")
    ok "Verification result: ${VERIFY_RESULT}"
else
    fail "Verification failed (${HTTP_CODE})"
fi

step "Sandbox PoC verification — SQL injection"
api POST "api/v1/sandbox/verify-finding" '{
    "finding": {
        "id": "MPTE-SQLI-001",
        "type": "sql_injection",
        "severity": "critical",
        "cwe": "CWE-89",
        "title": "SQL Injection in login endpoint",
        "app_id": "vulnerable-webapp",
        "cvss_score": 9.8,
        "code_snippet": "query = \"SELECT * FROM users WHERE username = \" + request.getParameter(\"user\")"
    },
    "target_url": "http://localhost:8000"
}'
if [ "$HTTP_CODE" = "200" ]; then
    SANDBOX_STATUS=$(echo "$HTTP_BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status', d.get('result','?')))" 2>/dev/null || echo "?")
    ok "Sandbox verification: ${SANDBOX_STATUS}"
else
    fail "Sandbox verification failed (${HTTP_CODE})"
fi

step "Micro-pentest engine health"
api GET "api/v1/micro-pentest/health"
if [ "$HTTP_CODE" = "200" ]; then
    ok "Micro-pentest engine operational"
else
    fail "Micro-pentest engine check failed (${HTTP_CODE})"
fi

# ── Phase 3: Generate Fix ──────────────────────────────────────────────
echo -e "\n${BOLD}${CYAN}━━━ Phase 3: AutoFix Generation ━━━${RESET}"

step "Generate fix for SQL injection"
api POST "api/v1/autofix/generate" '{
    "finding_id": "MPTE-SQLI-001",
    "finding_type": "sql_injection",
    "severity": "critical",
    "cwe": "CWE-89",
    "language": "java",
    "file_path": "src/main/java/com/webapp/LoginController.java",
    "code_snippet": "String query = \"SELECT * FROM users WHERE username = \" + request.getParameter(\"user\") + \" AND password = \" + request.getParameter(\"pass\");\nStatement stmt = conn.createStatement();\nResultSet rs = stmt.executeQuery(query);",
    "context": "Login endpoint handling user authentication"
}'
if [ "$HTTP_CODE" = "200" ]; then
    FIX_ID=$(echo "$HTTP_BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('fix',d).get('fix_id','?'))" 2>/dev/null || echo "?")
    FIX_CONF=$(echo "$HTTP_BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('fix',d).get('confidence_score', d.get('fix',d).get('confidence','?')))" 2>/dev/null || echo "?")
    ok "Fix generated: ${FIX_ID} (confidence=${FIX_CONF})"
else
    fail "Fix generation failed (${HTTP_CODE})"
fi

# ── Phase 4: Evidence Bundle ───────────────────────────────────────────
echo -e "\n${BOLD}${CYAN}━━━ Phase 4: Evidence Bundle ━━━${RESET}"

step "Generate signed evidence bundle"
api POST "api/v1/evidence/bundles/generate" '{
    "title": "MPTE Verification Evidence — SQL Injection",
    "description": "Evidence bundle proving SQL injection exploitability via MPTE micro-pentest verification",
    "framework": "SOC2",
    "frameworks": ["SOC2", "PCI-DSS"],
    "date_range": {
        "start": "2026-01-01",
        "end": "2026-03-01"
    },
    "categories": ["findings", "mpte_verifications", "remediations"]
}'
if [ "$HTTP_CODE" = "200" ]; then
    BUNDLE_ID=$(echo "$HTTP_BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id','?'))" 2>/dev/null || echo "?")
    BUNDLE_HASH=$(echo "$HTTP_BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('hash','?')[:50])" 2>/dev/null || echo "?")
    ok "Evidence bundle: ${BUNDLE_ID}"
    echo -e "    ${DIM}Hash: ${BUNDLE_HASH}...${RESET}"
    EVIDENCE_PRODUCED="YES"
else
    fail "Evidence bundle failed (${HTTP_CODE})"
    EVIDENCE_PRODUCED="NO"
fi

step "SOC2 compliance assessment"
api POST "api/v1/brain/evidence/generate" '{
    "org_id": "mpte-demo",
    "framework": "SOC2",
    "scope": "all"
}'
if [ "$HTTP_CODE" = "200" ]; then
    PACK_ID=$(echo "$HTTP_BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('pack_id','?'))" 2>/dev/null || echo "?")
    SCORE=$(echo "$HTTP_BODY" | python3 -c "import sys,json; print(f\"{json.load(sys.stdin).get('overall_score',0)*100:.1f}%\")" 2>/dev/null || echo "?")
    ok "Compliance pack: ${PACK_ID} (score=${SCORE})"
else
    fail "Compliance assessment failed (${HTTP_CODE})"
fi

# ── Summary ─────────────────────────────────────────────────────────────
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

echo -e "\n${BOLD}════════════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  ALdeci MPTE Demo — Results${RESET}"
echo -e "${BOLD}════════════════════════════════════════════════════════════${RESET}"
echo -e "  Total time:    ${ELAPSED}s"
echo -e "  Steps:         ${PASS}/${TOTAL} passed, ${FAIL} failed"
echo -e "  Evidence:      ${EVIDENCE_PRODUCED:-NO}"

if [ "$FAIL" -eq 0 ]; then
    echo -e "\n  ${GREEN}${BOLD}ALL STEPS PASSED — MPTE DEMO COMPLETE${RESET}"
else
    echo -e "\n  ${RED}${BOLD}${FAIL} STEPS FAILED${RESET}"
fi
echo -e "${BOLD}════════════════════════════════════════════════════════════${RESET}"
echo ""

# Signed evidence bundle produced: YES/NO — key metric per competitive analysis
echo -e "${BOLD}Key Metric — Signed evidence bundle produced: ${EVIDENCE_PRODUCED:-NO}${RESET}"
echo ""

exit $FAIL
