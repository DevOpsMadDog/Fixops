#!/bin/bash
# ============================================================================
# ALdeci Persona Demo: CISO — "What Needs My Attention Right Now?"
# Duration: 3 minutes | Pillars: V3 (Decision Intelligence), V10 (CTEM)
# Workflow Space: Mission Control + Comply
# ============================================================================
# Usage: ./persona-1-ciso.sh [base_url] [api_key]
# ============================================================================

BASE="${1:-http://localhost:8000}/api/v1"
API_KEY="${2:-${FIXOPS_API_TOKEN:-test-key}}"

G='\033[0;32m' B='\033[0;34m' C='\033[0;36m' Y='\033[1;33m' BOLD='\033[1m' N='\033[0m'
say() { echo -e "\n${C}TALKING POINT:${N} ${BOLD}$1${N}\n"; }
step() { echo -e "\n${B}--- Step $1: $2 ---${N}"; }
api() { curl -s --max-time 10 -H "X-API-Key: $API_KEY" "$@"; }

echo -e "${G}============================================================${N}"
echo -e "${G}  ALdeci Demo - Persona 1: CISO (David Kim)                ${N}"
echo -e "${G}  Duration: 3 min | Mission Control + Comply               ${N}"
echo -e "${G}============================================================${N}"

# [0:00-0:30] Risk Overview Dashboard
step "1" "Risk Overview Dashboard [0:00-0:30]"
say "David, you just walked in Monday morning. The board meets Friday. Let me show you ALdeci."
echo -e "${Y}>>>${N} Dashboard overview:"
api "$BASE/analytics/dashboard/overview" | python3 -m json.tool 2>/dev/null

say "One glance - total findings, critical count, open items. 95% noise reduction."

# [0:30-1:15] Top Exposures
step "2" "Top Exposures - What is Actually Dangerous [0:30-1:15]"
say "These are not just CVSS rankings. Each finding ran through our 12-step Brain Pipeline."
echo -e "${Y}>>>${N} Brain pipeline stats:"
R=$(api "$BASE/brain/stats")
echo "$R" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(f'  Total nodes: {d.get(\"total_nodes\",0):,}')
print(f'  Total edges: {d.get(\"total_edges\",0):,}')
print(f'  Node types tracked: {len(d.get(\"node_types\",{}))}')
for nt,count in sorted(d.get('node_types',{}).items(),key=lambda x:-x[1])[:5]:
    print(f'    * {nt}: {count:,}')
" 2>/dev/null || echo "  (brain pipeline data loading...)"

echo -e "\n${Y}>>>${N} MPTE verification stats:"
R=$(api "$BASE/mpte/stats")
echo "$R" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(f'  Verifications: {d.get(\"total_requests\",0)} requests, {d.get(\"total_results\",0)} completed')
e=d.get('by_exploitability',{})
print(f'  Confirmed exploitable: {e.get(\"confirmed_exploitable\",0)}')
print(f'  Likely exploitable: {e.get(\"likely_exploitable\",0)}')
print(f'  FP eliminated: {e.get(\"unexploitable\",0)}')
" 2>/dev/null || echo "  (MPTE data loading...)"

say "Other tools give you 500 criticals. We give you 5 that matter, with proof."

# [1:15-2:15] Compliance Status
step "3" "Compliance Status - Board-Ready in Seconds [1:15-2:15]"
echo -e "${Y}>>>${N} Compliance frameworks:"
R=$(api "$BASE/compliance-engine/frameworks")
echo "$R" | python3 -c "
import json,sys
d=json.load(sys.stdin)
tc,ta=0,0
for f in d.get('frameworks',[]):
    c,a=f.get('total_controls',0),f.get('automated_controls',0)
    tc+=c;ta+=a
    print(f'  {f[\"framework\"]:20s} | {c:3d} controls | {a:3d} automated ({int(a/max(c,1)*100)}%)')
print(f'  {\"TOTAL\":20s} | {tc:3d} controls | {ta:3d} automated ({int(ta/max(tc,1)*100)}%)')
" 2>/dev/null || echo "  (compliance data loading...)"

echo -e "\n${Y}>>>${N} Mapping findings to compliance controls:"
R=$(api -X POST "$BASE/compliance-engine/map-findings" \
  -H "Content-Type: application/json" \
  -d '{"findings":[{"id":"VULN-001","title":"SQL Injection","severity":"critical","cwe_id":"CWE-89","cvss":9.8},{"id":"VULN-002","title":"Broken Auth","severity":"high","cwe_id":"CWE-287","cvss":8.2}],"framework":"SOC2"}')
echo "$R" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(f'  Findings mapped: {d.get(\"total\",0)}')
for fid,ctrls in d.get('mappings',{}).items():
    cl=[f'{c[0]} {c[1]}' for c in ctrls if isinstance(c,list) and len(c)>=2]
    print(f'    {fid}: {chr(44).join(cl[:4])}')
" 2>/dev/null || echo "  (mapping data loading...)"

say "4 frameworks, 95 controls, 84 automated. 2 seconds, not 3 weeks."

# [2:15-2:45] Evidence Bundle
step "4" "Evidence Bundle - Cryptographically Signed [2:15-2:45]"
echo -e "${Y}>>>${N} Evidence vault:"
R=$(api "$BASE/evidence/")
echo "$R" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(f'  Evidence releases: {d.get(\"count\",0)}')
for r in d.get('releases',[]):
    a='bundle ready' if r.get('bundle_available') else 'manifest only'
    print(f'    * {r[\"tag\"]} ({a})')
" 2>/dev/null || echo "  (evidence vault loading...)"

echo -e "\n${Y}>>>${N} Audit decision trail:"
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
" 2>/dev/null || echo "  (audit trail loading...)"

say "RSA-SHA256 signed. Quantum-ready ML-DSA when you need it."

# [2:45-3:00] Close
step "5" "CISO Close [2:45-3:00]"
say "David, 3 minutes ago you walked in. Now you know your risk posture, top 5 exposures with proof, compliance across 4 frameworks, and have signed evidence for the board. That is Decision Intelligence."

echo -e "\n${G}  CISO Demo Complete | 6 endpoints | V3 + V10 (v5.0 — verified 2026-03-02 05:51 UTC)${N}"
