#!/usr/bin/env bash
#
# ALdeci CTEM+ Full Loop — curl Demo Script
# ═══════════════════════════════════════════
#
# Copy-paste these curls into a terminal during an investor meeting.
# Each curl runs one step of the CTEM+ lifecycle:
#
#   DISCOVER → VALIDATE → REMEDIATE → COMPLY
#
# Prerequisites:
#   - ALdeci API running: python -m uvicorn apps.api.app:create_app --factory --port 8000
#   - Set FIXOPS_API_TOKEN in environment
#
# Usage:
#   ./scripts/ctem-demo-curls.sh          # runs all steps
#   source scripts/ctem-demo-curls.sh     # exports TOKEN for manual curls
#
# Pillar: V3 + V5 + V10
#

set -euo pipefail

BASE="${ALDECI_BASE_URL:-http://localhost:8000}"
TOKEN="${FIXOPS_API_TOKEN:-aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh}"

BOLD='\033[1m'
CYAN='\033[96m'
GREEN='\033[92m'
DIM='\033[2m'
RESET='\033[0m'

banner() {
    echo -e "\n${BOLD}${CYAN}━━━ $1 ━━━${RESET}"
}

run_curl() {
    echo -e "${DIM}$1${RESET}"
    eval "$1" | python3 -m json.tool 2>/dev/null | head -20
    echo -e "${GREEN}✓ Done${RESET}"
}

# Export for manual use
export TOKEN BASE

echo -e "${BOLD}${CYAN}"
echo "╔═══════════════════════════════════════════════╗"
echo "║  ALdeci CTEM+ Full Loop — curl Demo           ║"
echo "║  Discover → Validate → Remediate → Comply     ║"
echo "╚═══════════════════════════════════════════════╝"
echo -e "${RESET}"

# ═══════════════════════════════════════════════════════
banner "Step 1: DISCOVER — SAST Scan (find SQL injection, secrets, eval)"
# ═══════════════════════════════════════════════════════
run_curl 'curl -s -H "X-API-Key: '$TOKEN'" -H "Content-Type: application/json" -X POST '$BASE'/api/v1/sast/scan/code -d '"'"'{"code":"import os\npassword=\"secret123\"\nquery=\"SELECT * FROM users WHERE id=\" + user_input\nos.system(user_input)\neval(user_data)","language":"python","app_id":"demo-app"}'"'"''

# ═══════════════════════════════════════════════════════
banner "Step 2: DISCOVER — Secrets Scan (find AWS keys, tokens)"
# ═══════════════════════════════════════════════════════
run_curl 'curl -s -H "X-API-Key: '$TOKEN'" -H "Content-Type: application/json" -X POST '$BASE'/api/v1/secrets/scan/content -d '"'"'{"content":"aws_access_key_id=AKIAIOSFODNN7EXAMPLE\naws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nSTRIPE_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc","filename":"config.env","repository":"demo"}'"'"''

# ═══════════════════════════════════════════════════════
banner "Step 3: DISCOVER — IaC Scan (Terraform misconfigurations)"
# ═══════════════════════════════════════════════════════
run_curl 'curl -s -H "X-API-Key: '$TOKEN'" -H "Content-Type: application/json" -X POST '$BASE'/api/v1/cspm/scan/terraform -d '"'"'{"content":"resource \"aws_s3_bucket\" \"data\" {\n  bucket = \"prod-data\"\n  acl = \"public-read\"\n}\nresource \"aws_security_group\" \"api\" {\n  ingress {\n    from_port = 0\n    to_port = 65535\n    protocol = \"tcp\"\n    cidr_blocks = [\"0.0.0.0/0\"]\n  }\n}","filename":"main.tf"}'"'"''

# ═══════════════════════════════════════════════════════
banner "Step 4: VALIDATE — Brain Pipeline (12-step CTEM processing)"
# ═══════════════════════════════════════════════════════
run_curl 'curl -s -H "X-API-Key: '$TOKEN'" -H "Content-Type: application/json" -X POST '$BASE'/api/v1/brain/pipeline/run -d '"'"'{"org_id":"demo-org","app_id":"demo-app","trigger":"investor-demo","findings":[{"id":"DEMO-SQLI-001","type":"sql_injection","severity":"critical","cwe":"CWE-89","cve_id":"CVE-2024-22259","title":"SQL Injection in user search","source":"sast","app_id":"demo-app","cvss_score":9.8,"epss_score":0.12},{"id":"DEMO-S3-001","type":"cloud_misconfiguration","severity":"high","cwe":"CWE-284","title":"S3 bucket allows public read","source":"cnapp","app_id":"demo-infra"}]}'"'"''

# ═══════════════════════════════════════════════════════
banner "Step 5: VALIDATE — MPTE Verification (prove exploitability)"
# ═══════════════════════════════════════════════════════
run_curl 'curl -s -H "X-API-Key: '$TOKEN'" -H "Content-Type: application/json" -X POST '$BASE'/api/v1/mpte/verify -d '"'"'{"finding_id":"DEMO-SQLI-001","target_url":"http://localhost:8000","vulnerability_type":"sql_injection","evidence":"Parameterized query not used. User input concatenated into SQL string."}'"'"''

# ═══════════════════════════════════════════════════════
banner "Step 6: REMEDIATE — AutoFix (generate code patch)"
# ═══════════════════════════════════════════════════════
run_curl 'curl -s -H "X-API-Key: '$TOKEN'" -H "Content-Type: application/json" -X POST '$BASE'/api/v1/autofix/generate -d '"'"'{"finding_id":"DEMO-SQLI-001","finding_type":"sql_injection","severity":"critical","cwe":"CWE-89","language":"python","code_snippet":"query = \"SELECT * FROM users WHERE id=\" + user_input","context":"User search endpoint"}'"'"''

# ═══════════════════════════════════════════════════════
banner "Step 7: COMPLY — Generate Signed Evidence Bundle"
# ═══════════════════════════════════════════════════════
run_curl 'curl -s -H "X-API-Key: '$TOKEN'" -H "Content-Type: application/json" -X POST '$BASE'/api/v1/evidence/bundles/generate -d '"'"'{"title":"CTEM Demo Evidence Bundle","description":"Investor demo — complete CTEM lifecycle evidence","framework":"SOC2","frameworks":["SOC2","PCI-DSS"],"date_range":{"start":"2026-01-01","end":"2026-03-01"},"categories":["findings","remediations","risk_scores","mpte_verifications"]}'"'"''

# ═══════════════════════════════════════════════════════
banner "Step 8: COMPLY — SOC2 Compliance Assessment"
# ═══════════════════════════════════════════════════════
run_curl 'curl -s -H "X-API-Key: '$TOKEN'" -H "Content-Type: application/json" -X POST '$BASE'/api/v1/brain/evidence/generate -d '"'"'{"org_id":"demo-org","framework":"SOC2","scope":"all"}'"'"''

echo -e "\n${BOLD}${GREEN}━━━ CTEM+ Full Loop Complete ━━━${RESET}"
echo -e "${DIM}All 8 steps executed: Discover(3) → Validate(2) → Remediate(1) → Comply(2)${RESET}"
echo ""
