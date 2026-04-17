# Plan: Graphify → LLM Council → PRD → Multica Pipeline

## Overview
Reverse-engineer PRDs from ALDECI's actual code using Graphify knowledge graph + multi-LLM analysis, then manage execution via Multica board.

## Prerequisites (ALL INSTALLED)
- Graphify: `graphify-out/graph.json` — 109,339 nodes, 374,264 edges, 878 communities
- LLM Council: Qwen 3.6+ (free), DeepSeek R1 (free), Kimi K2 (free), Opus 4.7 (review only)
- Multica: http://localhost:3000 (self-hosted, login with any email + code 888888)
- OpenRouter API key: in .env as OPENROUTER_API_KEY / MULEROUTER_API_KEY

## Pipeline Steps

### Step 1: Graphify Community Analysis (FREE — no LLM)
```bash
graphify update .
# Output: graphify-out/graph.json (109K nodes, 374K edges, 878 communities)
# Each community = a cluster of related code
```
Key communities to analyze:
- Community 0: stdlib/utility (largest, skip)
- Community 2: Brain pipeline + AutoFix + Knowledge Brain + Event Bus (CORE)
- Community 3: Auth middleware + Brain Pipeline orchestration (CORE)
- Community 4: FastAPI app + middleware (INFRA)
- Community 5: TrustGraph backbone (CORE)
- Community 12: API Gateway (CORE)
- Community 18: Auth models + deployment (CORE)
- Community 48: Threat Intel correlator + CVE enrichment (CORE)
- Community 89: Tenant isolation (CORE)
- Communities 100-878: Wave engines (CRUD islands — main PRD targets)

### Step 2: LLM Council Semantic Analysis (FREE via OpenRouter)

For each of the 878 communities, send to LLM Council:

```python
# Script: scripts/graphify_to_prd.py

import json
import httpx

OPENROUTER_KEY = os.getenv("OPENROUTER_API_KEY")
GRAPH = json.load(open("graphify-out/graph.json"))

# Group nodes by community
communities = {}
for node in GRAPH["nodes"]:
    cid = node.get("community", -1)
    communities.setdefault(cid, []).append(node)

# For each community, ask 3 free LLMs in parallel:
for cid, nodes in communities.items():
    if len(nodes) < 5:
        continue  # Skip tiny communities
    
    node_summary = "\n".join([f"- {n['label']} ({n.get('src','')})" for n in nodes[:50]])
    
    prompt = f"""Analyze this code community (cluster of related code):

{node_summary}

Answer:
1. DOMAIN: What security domain does this cover?
2. CURRENT STATE: What does it actually do? (CRUD only? Real logic? Connected?)
3. MISSING: What SHOULD it do but doesn't?
4. CONNECTIONS: Which other domains should it integrate with?
5. PRD: Write a mini-PRD with acceptance criteria for making this community production-ready.
"""
    
    # Send to Qwen 3.6+ (free)
    qwen_response = call_openrouter("qwen/qwen3.6-plus:free", prompt)
    
    # Send to DeepSeek R1 (free)  
    deepseek_response = call_openrouter("deepseek/deepseek-r1:free", prompt)
    
    # Synthesize (use cheapest model)
    synthesis = synthesize(qwen_response, deepseek_response)
    
    # Save PRD
    save_prd(cid, synthesis)
```

LLM routing:
- Qwen 3.6+: Primary analysis (free)
- DeepSeek R1: Reasoning/logic gaps (free)
- Kimi K2: Security review (free)
- Opus 4.7: CTO review of top 20 PRDs only ($0.05 each = $1 total)

### Step 3: PRD Generation

For each community, generate structured PRD:
```markdown
# PRD: [Community Name] — [Domain]

## Current State
- Files: [list]
- LOC: [count]
- Status: CRUD_ONLY / PARTIAL / PRODUCTION_READY

## What It Does
[LLM analysis from Step 2]

## What It Should Do
[Gap analysis from Step 2]

## Missing Connections
- Should subscribe to: [events]
- Should query: [TrustGraph / other engines]
- Should emit: [events]

## Acceptance Criteria
- [ ] [Testable criterion 1]
- [ ] [Testable criterion 2]
- [ ] Tests pass (716+ Beast Mode)

## Priority
HIGH / MEDIUM / LOW based on customer impact
```

Output: `.omc/prds/community_{cid}.md` for each community

### Step 4: Feed to Multica Board

```python
# Script: scripts/prds_to_multica.py

import httpx

MULTICA_API = "http://localhost:8080"

# Create workspace
workspace = create_workspace("ALDECI Beast Mode")

# For each PRD, create an issue
for prd_file in glob(".omc/prds/community_*.md"):
    prd = parse_prd(prd_file)
    
    # Determine status
    if prd.status == "PRODUCTION_READY":
        status = "done"
    elif prd.status == "PARTIAL":
        status = "in_progress"  
    else:
        status = "todo"
    
    create_issue(
        workspace=workspace,
        title=prd.title,
        description=prd.content,
        status=status,
        priority=prd.priority,
        labels=[prd.domain],
    )
```

### Step 5: Agent Execution via Multica

Agents pick up "todo" issues from Multica board:
- Beast Mode free LLMs (Qwen/DeepSeek/Kimi) do implementation
- Each agent: claim issue → implement → test → submit → move to "review"
- You review on Multica board → approve (done) or reject (back to todo)

### Step 6: Opus 4.7 CTO Review Gate

Only for issues marked "review":
- Opus reviews against PRD acceptance criteria
- Approve → done
- Reject → back to in_progress with feedback

## Cost Estimate
- Graphify AST: $0
- 878 community analyses × 2 free LLMs: $0
- 20 Opus CTO reviews × $0.05: $1
- Multica: $0 (self-hosted)
- Total: ~$1 per full codebase analysis

## Files Created
- `scripts/graphify_to_prd.py` — Graphify → LLM Council → PRD generator
- `scripts/prds_to_multica.py` — PRD → Multica issue creator
- `.omc/prds/` — Generated PRDs directory

## Verification
- All 878 communities analyzed
- PRDs generated for communities with 5+ nodes
- Multica board populated with issues
- Status correctly assigned (done/in_progress/todo)
- 716/716 Beast Mode tests still pass
