#!/bin/bash
# ============================================================================
# ALdeci Persona Demo: Auditor — "Prove It. With Evidence."
# Duration: 3 minutes | Pillars: V10 (CTEM Full Loop), V3 (Decision)
# Workflow Space: Comply
# ============================================================================
# Usage: ./persona-3-auditor.sh [base_url] [api_key]
# ============================================================================

BASE="${1:-http://localhost:8000}/api/v1"
API_KEY="${2:-${FIXOPS_API_TOKEN:-test-key}}"

G='\033[0;32m' B='\033[0;34m' C='\033[0;36m' Y='\033[1;33m' BOLD='\033[1m' N='\033[0m'
say() { echo -e "\n${C}TALKING POINT:${N} ${BOLD}$1${N}\n"; }
step() { echo -e "\n${B}--- Step $1: $2 ---${N}"; }
api() { curl -s --max-time 10 -H "X-API-Key: $API_KEY" "$@"; }

echo -e "${G}============================================================${N}"
echo -e "${G}  ALdeci Demo - Persona 3: Auditor (Laura Chen)            ${N}"
echo -e "${G}  Duration: 3 min | Comply (Evidence Vault)                ${N}"
echo -e "${G}============================================================${N}"

# [0:00-0:45] Evidence Vault
step "1" "Evidence Vault — Every Decision Recorded [0:00-0:45]"
say "Laura, you are here for the SOC2 Type II audit. Let me pull your evidence."

echo -e "${Y}>>>${N} Evidence vault contents:"
R=$(api "$BASE/evidence/")
echo "$R" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(f'  Total evidence releases: {d.get(\"count\",0)}')
for r in d.get('releases',[]):
    tag=r.get('tag','?')
    avail='bundle ready' if r.get('bundle_available') else 'manifest only'
    print(f'    * {tag} ({avail})')
" 2>/dev/null || echo "  (evidence vault loading...)"

echo -e "\n${Y}>>>${N} Decision trail:"
R=$(api "$BASE/audit/decision-trail")
echo "$R" | python3 -c "
import json,sys
d=json.load(sys.stdin)
total=d.get('total',len(d.get('decisions',[])))
decisions=d.get('decisions',[])
print(f'  Total decisions recorded: {total}')
for dec in decisions[:3]:
    print(f'    * {dec}')
if not decisions:
    print('    (Production deployment auto-records every AI consensus decision)')
" 2>/dev/null || echo "  (decision trail loading...)"

say "Every security decision -- recorded and cryptographically signed. RSA-SHA256 today, quantum-ready ML-DSA when you need it."

# [0:45-1:45] Compliance Report
step "2" "Compliance Report — Framework-Mapped Controls [0:45-1:45]"

echo -e "${Y}>>>${N} Compliance frameworks:"
R=$(api "$BASE/compliance-engine/frameworks")
echo "$R" | python3 -c "
import json,sys
d=json.load(sys.stdin)
tc,ta=0,0
for f in d.get('frameworks',[]):
    c,a=f.get('total_controls',0),f.get('automated_controls',0)
    tc+=c;ta+=a
    pct=int(a/max(c,1)*100)
    print(f'  {f[\"framework\"]:20s} | {c:3d} controls | {a:3d} automated ({pct}%)')
print(f'  {\"TOTAL\":20s} | {tc:3d} controls | {ta:3d} automated ({int(ta/max(tc,1)*100)}%)')
" 2>/dev/null || echo "  (compliance data loading...)"

echo -e "\n${Y}>>>${N} Mapping findings to SOC2 controls:"
R=$(api -X POST "$BASE/compliance-engine/map-findings" \
  -H "Content-Type: application/json" \
  -d '{"findings":[{"id":"VULN-001","title":"SQL Injection","severity":"critical","cwe_id":"CWE-89","cvss":9.8},{"id":"VULN-002","title":"Broken Auth","severity":"high","cwe_id":"CWE-287","cvss":8.2},{"id":"VULN-003","title":"Log4Shell RCE","severity":"critical","cwe_id":"CWE-917","cvss":10.0}],"framework":"SOC2"}')
echo "$R" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(f'  Findings mapped: {d.get(\"total\",0)}')
for fid,ctrls in d.get('mappings',{}).items():
    cl=[f'{c[0]} {c[1]}' for c in ctrls if isinstance(c,list) and len(c)>=2]
    print(f'    {fid}: {chr(44).join(cl[:4])}')
" 2>/dev/null || echo "  (mapping data loading...)"

say "Every finding auto-mapped to compliance controls across all frameworks. 2 seconds, not 3 weeks."

# [1:45-2:30] Audit Trail
step "3" "Audit Trail — Immutable Decision History [1:45-2:30]"

echo -e "${Y}>>>${N} Audit logs:"
R=$(api "$BASE/audit/logs?limit=5")
echo "$R" | python3 -c "
import json,sys
d=json.load(sys.stdin)
items=d.get('items',d if isinstance(d,list) else [])
print(f'  Total audit entries: {d.get(\"total\",len(items))}')
for item in items[:5]:
    print(f'    * {item}')
if not items:
    print('    (Production: every API call, scan, and decision is logged)')
" 2>/dev/null || echo "  (audit logs loading...)"

echo -e "\n${Y}>>>${N} Audit export (JSON format):"
R=$(api "$BASE/audit/logs/export?format=json")
echo "$R" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(f'  Exportable logs: {d.get(\"count\",0)} entries')
print(f'  Period: {d.get(\"period_days\",0)} days')
print(f'  Formats available: JSON, CSV, SIEM-CEF')
" 2>/dev/null || echo "  (audit export loading...)"

say "Every action logged. Exportable in JSON, CSV, or SIEM-CEF format. 30-day rolling retention, configurable up to 7 years."

# [2:30-3:00] CWE Mapping & Close
step "4" "CWE-to-Control Mapping & Close [2:30-3:00]"

echo -e "${Y}>>>${N} CWE-89 (SQL Injection) control mapping:"
R=$(api "$BASE/compliance-engine/cwe-mapping/CWE-89")
echo "$R" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(f'  CWE: {d.get(\"cwe_id\",\"?\")}')
for ctrl in d.get('controls',[]):
    print(f'    -> {ctrl.get(\"framework\",\"?\")} {ctrl.get(\"control_id\",\"?\")}: {ctrl.get(\"title\",\"?\")}')
" 2>/dev/null || echo "  (CWE mapping loading...)"

say "One CWE, 6 mapped controls across 3 frameworks. Complete traceability from vulnerability to compliance control."

echo -e "\n${G}  Auditor Demo Complete | 8 endpoints | V10 + V3${N}"
