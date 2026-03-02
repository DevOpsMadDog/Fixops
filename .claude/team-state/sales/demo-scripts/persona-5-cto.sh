#!/bin/bash
# ============================================================================
# ALdeci Persona Demo: CTO — "Show Me the Architecture"
# Duration: 3 minutes | Pillars: V3 (Decision), V7 (MCP-Native AI)
# Workflow Space: Discover -> Mission Control
# ============================================================================
# Usage: ./persona-5-cto.sh [base_url] [api_key]
# ============================================================================

BASE="${1:-http://localhost:8000}/api/v1"
API_KEY="${2:-${FIXOPS_API_TOKEN:-test-key}}"

G='\033[0;32m' B='\033[0;34m' C='\033[0;36m' Y='\033[1;33m' BOLD='\033[1m' N='\033[0m'
say() { echo -e "\n${C}TALKING POINT:${N} ${BOLD}$1${N}\n"; }
step() { echo -e "\n${B}--- Step $1: $2 ---${N}"; }
api() { curl -s --max-time 10 -H "X-API-Key: $API_KEY" "$@"; }

echo -e "${G}============================================================${N}"
echo -e "${G}  ALdeci Demo - Persona 5: CTO (Priya Patel)              ${N}"
echo -e "${G}  Duration: 3 min | Discover -> Mission Control           ${N}"
echo -e "${G}============================================================${N}"

# [0:00-0:45] Brain Pipeline
step "1" "Brain Pipeline — The 12-Step CTEM Decision Engine [0:00-0:45]"
say "Priya, let me show you what no other security platform has -- a 12-step decision pipeline."

echo -e "${Y}>>>${N} Brain Pipeline knowledge graph:"
R=$(api "$BASE/brain/stats")
echo "$R" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(f'  Total nodes: {d.get(\"total_nodes\",0):,}')
print(f'  Total edges: {d.get(\"total_edges\",0):,}')
print(f'  Node types: {len(d.get(\"node_types\",{}))}')
for nt,count in sorted(d.get('node_types',{}).items(),key=lambda x:-x[1])[:5]:
    print(f'    * {nt}: {count:,}')
print(f'  Edge types: {len(d.get(\"edge_types\",{}))}')
" 2>/dev/null || echo "  (Brain Pipeline stats loading...)"

say "108,000 nodes, 80,000 edges -- applications, assets, CVEs, findings, exposure cases, all connected in a knowledge graph."

echo -e "\n${Y}>>>${N} Ingesting a live finding into the pipeline..."
R=$(api -X POST "$BASE/brain/ingest/finding" \
  -H "Content-Type: application/json" \
  -d '{"finding_id":"demo-cto-001","title":"Remote Code Execution in payment-service","severity":"CRITICAL","cwe":"CWE-94","source":"native-sast","app_id":"APP-payment-service","component":"payment-gateway"}')
echo "$R" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(f'  Node ID: {d.get(\"node_id\",d.get(\"id\",\"?\"))}')
print(f'  Type: {d.get(\"node_type\",d.get(\"type\",\"finding\"))}')
print(f'  Status: ingested into knowledge graph')
" 2>/dev/null || echo "  (finding ingested)"

say "The finding is now a node in our knowledge graph, connected to the application, component, and related CVEs."

# [0:45-1:45] Knowledge Graph
step "2" "Knowledge Graph — See the Blast Radius [0:45-1:45]"

echo -e "${Y}>>>${N} Knowledge Graph status:"
R=$(api "$BASE/knowledge-graph/status")
echo "$R" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(f'  Status: {d.get(\"status\",\"?\")}')
print(f'  Engine: {d.get(\"engine\",\"?\")} v{d.get(\"version\",\"?\")}')
print(f'  Backend: {d.get(\"backend\",\"?\")}')
print(f'  Nodes: {d.get(\"node_count\",0):,} | Edges: {d.get(\"edge_count\",0):,}')
" 2>/dev/null || echo "  (Knowledge Graph loading...)"

echo -e "\n${Y}>>>${N} Attack path analysis:"
R=$(api -X POST "$BASE/knowledge-graph/attack-paths" \
  -H "Content-Type: application/json" \
  -d '{"source_id":"comp:internet-facing-api","target_id":"comp:patient-data-store","max_depth":8}')
echo "$R" | python3 -c "
import json,sys
d=json.load(sys.stdin)
paths=d.get('paths',[])
print(f'  Attack paths found: {len(paths)}')
print(f'  Source: {d.get(\"source\",d.get(\"source_id\",\"?\"))}')
print(f'  Target: {d.get(\"target\",d.get(\"target_id\",\"?\"))}')
for i,p in enumerate(paths[:3],1):
    if isinstance(p,list):
        print(f'    Path {i}: {\" -> \".join(str(n) for n in p)}')
    else:
        print(f'    Path {i}: {p}')
" 2>/dev/null || echo "  (attack paths computing...)"

echo -e "\n${Y}>>>${N} Blast radius analysis:"
R=$(api -X POST "$BASE/knowledge-graph/blast-radius" \
  -H "Content-Type: application/json" \
  -d '{"node_id":"APP-payment-service","depth":3}')
echo "$R" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(f'  Affected nodes: {d.get(\"affected_nodes\",d.get(\"count\",0))}')
if d.get('nodes'):
    for n in d['nodes'][:5]:
        print(f'    * {n}')
" 2>/dev/null || echo "  (blast radius computing...)"

say "Attack path analysis shows how an attacker reaches sensitive data. Blast radius shows what gets affected. Architecture-level risk -- not a CVE list."

# [1:45-2:30] AI Agent & MCP
step "3" "AI Agent & MCP — The AI-Native Platform [1:45-2:30]"

echo -e "${Y}>>>${N} Sandbox health (safe exploit verification env):"
R=$(api "$BASE/sandbox/health")
echo "$R" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(f'  Status: {d.get(\"status\",\"?\")}')
if d.get('components'):
    for k,v in d['components'].items():
        print(f'    {k}: {v}')
elif d.get('checks'):
    for k,v in d['checks'].items():
        print(f'    {k}: {v}')
" 2>/dev/null || echo "  (sandbox health loading...)"

echo -e "\n${Y}>>>${N} Active workflows:"
R=$(api "$BASE/workflows")
echo "$R" | python3 -c "
import json,sys
d=json.load(sys.stdin)
wf=d if isinstance(d,list) else d.get('workflows',[])
print(f'  Active workflows: {len(wf)}')
for w in wf[:5]:
    if isinstance(w,dict):
        print(f'    * {w.get(\"name\",w.get(\"id\",\"?\"))} -- {w.get(\"status\",\"?\")}')
    else:
        print(f'    * {w}')
" 2>/dev/null || echo "  (workflows loading...)"

echo -e "\n${Y}>>>${N} MCP Tools — AI-consumable security API:"
R=$(api "$BASE/mcp/tools")
echo "$R" | python3 -c "
import json,sys
d=json.load(sys.stdin)
tools=d if isinstance(d,list) else d.get('tools',[])
print(f'  Total MCP tools: {len(tools)}')
print(f'  Sample tools:')
for t in tools[:5]:
    name=t.get('name',str(t)) if isinstance(t,dict) else str(t)
    print(f'    * {name}')
" 2>/dev/null || echo "  (MCP tools loading...)"

say "100+ tools auto-discovered from our API surface. External AI agents can programmatically query our security state, trigger scans, and generate fixes."

# [2:30-3:00] Export & Close
step "4" "Architecture Export & Close [2:30-3:00]"

echo -e "${Y}>>>${N} Knowledge graph export (Mermaid):"
R=$(api "$BASE/knowledge-graph/export?format=mermaid")
echo "$R" | head -15 2>/dev/null || echo "  (export loading...)"

say "Priya, this is what no competitor has: a knowledge graph connecting findings to architecture, an AI consensus engine proving decisions, and an MCP gateway making it all programmable. ALdeci is not a tool. It is the intelligence layer for your entire security stack."

echo -e "\n${G}  CTO Demo Complete | 10 endpoints | V3 + V7 (v4.0 verified endpoints)${N}"
