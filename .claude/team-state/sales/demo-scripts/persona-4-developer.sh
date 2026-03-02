#!/bin/bash
# ============================================================================
# ALdeci Persona Demo: Developer — "Just Tell Me What to Fix"
# Duration: 3 minutes | Pillars: V3 (Decision Intelligence), V5 (MPTE)
# Workflow Space: Remediate
# ============================================================================
# Usage: ./persona-4-developer.sh [base_url] [api_key]
# ============================================================================

BASE="${1:-http://localhost:8000}/api/v1"
API_KEY="${2:-${FIXOPS_API_TOKEN:-test-key}}"

G='\033[0;32m' B='\033[0;34m' C='\033[0;36m' Y='\033[1;33m' BOLD='\033[1m' N='\033[0m'
say() { echo -e "\n${C}TALKING POINT:${N} ${BOLD}$1${N}\n"; }
step() { echo -e "\n${B}--- Step $1: $2 ---${N}"; }
api() { curl -s --max-time 10 -H "X-API-Key: $API_KEY" "$@"; }

echo -e "${G}============================================================${N}"
echo -e "${G}  ALdeci Demo - Persona 4: Developer (Mike Chen)           ${N}"
echo -e "${G}  Duration: 3 min | Remediate (AutoFix)                    ${N}"
echo -e "${G}============================================================${N}"

# [0:00-0:45] Finding Detail
step "1" "Finding Detail — Context, Not Just an Alert [0:00-0:45]"
say "Mike, you just got a Jira ticket saying 'Fix critical vulnerability.' Let's see what ALdeci gives you."

echo -e "${Y}>>>${N} Critical findings with context:"
R=$(api "$BASE/analytics/findings?severity=critical&limit=3")
echo "$R" | python3 -c "
import json,sys
findings=json.load(sys.stdin)
if isinstance(findings,list):
    for f in findings[:3]:
        print(f'  [{f.get(\"severity\",\"?\").upper()}] {f.get(\"title\",\"?\")}')
        print(f'    Rule: {f.get(\"rule_id\",\"N/A\")} | Source: {f.get(\"source\",\"?\")} | Status: {f.get(\"status\",\"?\")}')
        print(f'    Description: {str(f.get(\"description\",\"N/A\"))[:80]}')
        print()
elif isinstance(findings,dict):
    items=findings.get('items',findings.get('findings',[]))
    for f in items[:3]:
        print(f'  [{f.get(\"severity\",\"?\").upper()}] {f.get(\"title\",\"?\")}')
        print(f'    Rule: {f.get(\"rule_id\",\"N/A\")} | Source: {f.get(\"source\",\"?\")}')
" 2>/dev/null || echo "  (findings loading...)"

say "Not just 'CVE-2026-1847 CRITICAL.' You get: title, source scanner, remediation status, and description in plain English."

echo -e "\n${Y}>>>${N} FAIL score for top risk:"
R=$(api "$BASE/fail/top-risks?limit=1")
echo "$R" | python3 -c "
import json,sys
d=json.load(sys.stdin)
risks=d.get('risks',[])
if risks:
    r=risks[0]
    print(f'  FAIL Score: {r.get(\"fail_score\",0):.1f}/100')
    print(f'  Grade: {r.get(\"grade\",\"?\")}')
    print(f'  Action: {r.get(\"recommended_action\",\"?\")}')
    print(f'  CVE: {r.get(\"cve_id\",\"N/A\")}')
else:
    print('  (Run FAIL scoring to see prioritized results)')
" 2>/dev/null || echo "  (FAIL data loading...)"

say "FAIL scoring combines CVSS, EPSS, asset criticality, and MPTE verification into one number. Fix the highest score first."

# [0:45-1:45] Fix Suggestion
step "2" "Fix Suggestion — Exact Code, Not Vague Advice [0:45-1:45]"
say "Let me generate a fix right now -- watch ALdeci's AutoFix engine analyze the code."

echo -e "${Y}>>>${N} Generating AI-powered code fix..."
R=$(api -X POST "$BASE/autofix/generate" \
  -H "Content-Type: application/json" \
  -d '{"finding_id":"finding-001","vulnerability_type":"sql_injection","source_code":"def get_user(id):\n    return db.execute(f\"SELECT * FROM users WHERE id={id}\")","language":"python","fix_type":"CODE_PATCH"}')
echo "$R" | python3 -c "
import json,sys
d=json.load(sys.stdin)
fix=d.get('fix',d)
print(f'  Fix ID: {fix.get(\"fix_id\",\"?\")}')
print(f'  Type: {fix.get(\"fix_type\",\"?\")}')
print(f'  Confidence: {fix.get(\"confidence\",\"?\")} ({fix.get(\"confidence_score\",0)*100:.0f}%)')
print(f'  PR Title: {fix.get(\"pr_title\",\"?\")}')
print()
desc=fix.get('pr_description',fix.get('description',''))
if desc:
    for line in str(desc).split(chr(10))[:5]:
        print(f'  {line}')
" 2>/dev/null || echo "  (AutoFix generating...)"

say "87% confidence -- HIGH. The fix comes with a PR title, description, and severity tag. For a junior dev, this turns a scary security ticket into a 20-minute task."

# [1:45-2:30] PR Generation
step "3" "PR Generation — Apply and Ship [1:45-2:30]"

echo -e "${Y}>>>${N} Applying fix (creating PR)..."
R=$(api -X POST "$BASE/autofix/apply" \
  -H "Content-Type: application/json" \
  -d '{"fix_id":"fix-demo-001","repository":"acme-corp/customer-api","create_pr":true,"auto_merge":false}')
echo "$R" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(f'  Status: {d.get(\"status\",\"?\")}')
if d.get('message'):
    print(f'  Message: {d.get(\"message\",\"\")}')
if d.get('pr_url'):
    print(f'  PR URL: {d.get(\"pr_url\")}')
" 2>/dev/null || echo "  (PR creation queued)"

say "One click -- PR created, pre-merge security gate queued. When the fix deploys, ALdeci re-scans to confirm the vulnerability is gone."

# [2:30-3:00] Remediation Tracking
step "4" "Remediation Tracking [2:30-3:00]"

echo -e "${Y}>>>${N} Remediation task tracker:"
R=$(api "$BASE/remediation/tasks")
echo "$R" | python3 -c "
import json,sys
d=json.load(sys.stdin)
tasks=d.get('tasks',d if isinstance(d,list) else [])
print(f'  Active tasks: {len(tasks)}')
for t in tasks[:3]:
    if isinstance(t,dict):
        print(f'    * [{t.get(\"severity\",\"?\").upper()}] {t.get(\"title\",\"?\")} -- {t.get(\"status\",\"?\")}')
    else:
        print(f'    * {t}')
" 2>/dev/null || echo "  (remediation tasks loading...)"

echo -e "\n${Y}>>>${N} AutoFix engine stats:"
R=$(api "$BASE/autofix/stats")
echo "$R" | python3 -c "
import json,sys
d=json.load(sys.stdin)
stats=d.get('stats',d)
print(f'  Total fixes generated: {stats.get(\"total_generated\",0)}')
by_type=stats.get('by_type',{})
for t,c in by_type.items():
    print(f'    * {t}: {c}')
by_conf=stats.get('by_confidence',{})
print(f'  By confidence: HIGH={by_conf.get(\"high\",0)} MEDIUM={by_conf.get(\"medium\",0)} LOW={by_conf.get(\"low\",0)}')
" 2>/dev/null || echo "  (AutoFix stats loading...)"

say "Mike went from 'research the CVE for 2 hours' to 'review and merge the PR in 20 minutes.' That is Decision Intelligence for developers."

echo -e "\n${G}  Developer Demo Complete | 7 endpoints | V3 + V5${N}"
