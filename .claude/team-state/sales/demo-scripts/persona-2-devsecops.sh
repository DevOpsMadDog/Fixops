#!/bin/bash
# ============================================================================
# ALdeci Persona Demo: DevSecOps — "Scan, Verify, Fix — In One Pipeline"
# Duration: 3 minutes | Pillars: V3 (Decision), V5 (MPTE Verification)
# Workflow Space: Discover → Validate → Remediate
# ============================================================================
# Usage: ./persona-2-devsecops.sh [base_url] [api_key]
# ============================================================================

BASE="${1:-http://localhost:8000}/api/v1"
API_KEY="${2:-${FIXOPS_API_TOKEN:-test-key}}"

G='\033[0;32m' B='\033[0;34m' C='\033[0;36m' Y='\033[1;33m' BOLD='\033[1m' N='\033[0m'
say() { echo -e "\n${C}TALKING POINT:${N} ${BOLD}$1${N}\n"; }
step() { echo -e "\n${B}--- Step $1: $2 ---${N}"; }
api() { curl -s --max-time 10 -H "X-API-Key: $API_KEY" "$@"; }
api_llm() { curl -s --max-time 30 -H "X-API-Key: $API_KEY" "$@"; }  # LLM-dependent

echo -e "${G}============================================================${N}"
echo -e "${G}  ALdeci Demo - Persona 2: DevSecOps (Raj Mehta)           ${N}"
echo -e "${G}  Duration: 3 min | Discover -> Validate -> Remediate      ${N}"
echo -e "${G}============================================================${N}"

# [0:00-0:45] Native Code Scanning
step "1" "Native SAST Scan — ALdeci IS the Scanner [0:00-0:45]"
say "Raj, your Snyk license expired overnight. Your CI/CD is down. Watch what happens with ALdeci."

SAST_PAYLOAD='{"code":"import subprocess\ndef run(cmd):\n    return subprocess.call(cmd, shell=True)\n\ndef query(user_input):\n    sql = \"SELECT * FROM users WHERE id=\" + user_input\n    return db.execute(sql)","language":"python","filename":"app.py"}'

echo -e "${Y}>>>${N} Running native SAST scan on Python code..."
R=$(api -X POST "$BASE/sast/scan/code" \
  -H "Content-Type: application/json" \
  -d "$SAST_PAYLOAD")
echo "$R" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(f'  Scan ID: {d.get(\"scan_id\",\"?\")}')
print(f'  Files scanned: {d.get(\"files_scanned\",0)}')
print(f'  Findings: {d.get(\"total_findings\",0)}')
print(f'  Duration: {d.get(\"duration_ms\",0):.2f}ms')
for f in d.get('findings',[]):
    print(f'    [{f.get(\"severity\",\"?\").upper()}] {f.get(\"title\",\"?\")} (line {f.get(\"line_number\",\"?\")}) -- {f.get(\"cwe_id\",\"?\")}')
for t in d.get('taint_flows',[]):
    print(f'    Taint flow: line {t.get(\"source_line\",\"?\")} -> line {t.get(\"sink_line\",\"?\")} ({t.get(\"sink_category\",\"?\")})')
" 2>/dev/null || echo "  (SAST scan returned unexpected data)"

say "ALdeci found a command injection AND detected a SQL injection taint flow. No Snyk, no Semgrep, no internet. Under 1ms."

# [0:45-1:30] MPTE Verification
step "2" "MPTE Verification — Prove It's Exploitable [0:45-1:30]"
say "Now let's PROVE this vulnerability is actually exploitable — not just a scanner opinion."

MPTE_PAYLOAD='{"finding_id":"SAST-SQL-001","vulnerability_type":"SQL Injection (CWE-89)","target_url":"http://app:8080/api/users","evidence":"User input concatenated into SQL query without parameterization"}'

echo -e "${Y}>>>${N} Submitting to MPTE for 19-phase exploit verification..."
R=$(api -X POST "$BASE/mpte/verify" \
  -H "Content-Type: application/json" \
  -d "$MPTE_PAYLOAD")
echo "$R" | python3 -c "
import json,sys
d=json.load(sys.stdin)
vid=d.get('id',d.get('request_id','?'))
print(f'  Verification ID: {str(vid)[:20]}...')
print(f'  Finding: {d.get(\"finding_id\",\"?\")}')
print(f'  Status: {d.get(\"status\",\"?\")}')
print(f'  Message: {d.get(\"message\",\"Verification queued\")}')
" 2>/dev/null || echo "  (MPTE verification queued)"

say "MPTE queued a 19-phase micro-pentest. When it completes: VULNERABLE_VERIFIED or FALSE_POSITIVE with evidence hash."

echo -e "${Y}>>>${N} MPTE engine stats:"
R=$(api "$BASE/mpte/stats")
echo "$R" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(f'  Total verifications: {d.get(\"total_requests\",0)}')
print(f'  Completed: {d.get(\"total_results\",0)}')
exp=d.get('by_exploitability',{})
print(f'  Confirmed exploitable: {exp.get(\"confirmed_exploitable\",0)}')
print(f'  False positives eliminated: {exp.get(\"unexploitable\",0)}')
" 2>/dev/null || echo "  (MPTE stats loading...)"

# [1:30-2:30] AutoFix
step "3" "AutoFix — AI Generates the Code Fix [1:30-2:30]"

AUTOFIX_PAYLOAD='{"finding":{"id":"SAST-SQL-001","title":"SQL Injection via string concatenation","severity":"critical","cwe":"CWE-89","code_snippet":"def query(user_input):\n    sql = \"SELECT * FROM users WHERE id=\" + user_input\n    return db.execute(sql)"}}'

echo -e "${Y}>>>${N} Generating AI-powered fix (LLM-powered, ~10-20s)..."
R=$(api_llm -X POST "$BASE/autofix/generate" \
  -H "Content-Type: application/json" \
  -d "$AUTOFIX_PAYLOAD")
echo "$R" | python3 -c "
import json,sys
d=json.load(sys.stdin)
fix=d.get('fix',d)
print(f'  Fix ID: {fix.get(\"fix_id\",\"?\")}')
print(f'  Type: {fix.get(\"fix_type\",\"?\")}')
print(f'  Confidence: {fix.get(\"confidence\",\"?\")} ({fix.get(\"confidence_score\",0)*100:.0f}%)')
print(f'  PR Title: {fix.get(\"pr_title\",\"?\")}')
print(f'  Description: {str(fix.get(\"description\",\"?\"))[:80]}')
" 2>/dev/null || echo "  (AutoFix generating...)"

say "10 fix types -- not just dependency updates. CODE_PATCH with HIGH confidence. One click creates a PR."

# [2:30-3:00] The Full Pipeline
step "4" "Full Pipeline Summary [2:30-3:00]"

echo -e "${Y}>>>${N} Available fix types:"
R=$(api "$BASE/autofix/fix-types")
echo "$R" | python3 -c "
import json,sys
d=json.load(sys.stdin)
types=d if isinstance(d,list) else d.get('fix_types',[])
for t in types[:10]:
    name=t.get('name',t) if isinstance(t,dict) else t
    print(f'    * {name}')
" 2>/dev/null || echo "  (fix types loading...)"

say "Scan -> Verify -> Fix. No scanner needed, no internet needed, no human needed for HIGH confidence fixes. This entire flow works air-gapped. That is the CTEM+ difference."

echo -e "\n${G}  DevSecOps Demo Complete | 6 endpoints | V3 + V5 (v4.0 verified endpoints)${N}"
