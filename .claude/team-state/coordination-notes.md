# Coordination Notes — Enterprise Demo Sprint (2026-03-01 → 2026-03-06)

> **Updated by**: CEO via Copilot
> **Mode**: ENTERPRISE DEMO — 5 DAYS
> **Sprint 1 Status**: ARCHIVED (21/23 done, 91.3%)

## HEADLINE: ENTERPRISE DEMO IN 5 DAYS — ALL AGENTS RESET AND REDEPLOYED

Sprint 2 started. 12 demo items. All 17 agents reset to READY. Crash state cleared. Deferred queue emptied. Sprint 1 archived.

## CRITICAL DIRECTIVES

### 1. DO NOT WRITE PYTHON UNIT TESTS
Root cause of coverage plateau FOUND: `pyproject.toml` only measures 5 modules but agents wrote 2,010 tests for UNMEASURED modules. Fix the config (DEMO-006), don't write more tests.

### 2. DO NOT BUILD aldeci-ui-new
`suite-ui/aldeci-ui-new/` does NOT EXIST on disk. Work in `suite-ui/aldeci/` — the existing, shipping UI. Wire pages to real API data.

### 3. POSTMAN IS THE PRIMARY TEST METHOD
Newman runs against live API = highest trust. All 7 collections must pass. Python pytest is SECONDARY.

### 4. NO CASCADE STOPS
If one agent fails, others continue. Every demo item is independent.

## 7 Vision Engines BUILT & LIVE (Sprint 1 Achievement)

| Vision | Engine File | Endpoint | Status |
|--------|------------|----------|--------|
| V3 | `core/falkordb_client.py` (835 LOC) | `/api/v1/knowledge-graph/*` | LIVE 200 |
| V4 | `core/single_agent.py` (819 LOC) | `/api/v1/ai-agent/*` | LIVE 200 |
| V6 | `core/quantum_crypto.py` (666 LOC) | `/api/v1/quantum-crypto/*` | LIVE 200 |
| V7 | `core/mcp_server.py` (979 LOC) | `/api/v1/mcp-protocol/*` | LIVE 200 |
| V7+ | `apps/api/mcp_router.py` (977 LOC) | `/api/v1/mcp/*` | LIVE 200 |
| V8 | `core/self_learning.py` (832 LOC) | `/api/v1/self-learning/*` | LIVE 200 |
| V9 | `core/zero_gravity.py` (857 LOC) | `/api/v1/zero-gravity/*` | LIVE 200 |
| V10 | `core/compliance_engine.py` | `/api/v1/compliance-engine/*` | LIVE 200 |

## API Route Corrections (VERIFIED by Copilot on Mar 1)

The following routes were probed against live server. Use CORRECT column:

| What You Expect | CORRECT Route | Status |
|----------------|---------------|--------|
| brain status | `/api/v1/brain/stats` | 200 ✅ |
| autofix status | `/api/v1/autofix/health` | 200 ✅ |
| mpte status | `/api/v1/mpte/stats` | 200 ✅ |
| micro-pentest status | `/api/v1/micro-pentest/health` | 200 ✅ |
| feeds status | `/api/v1/feeds/health` | 200 ✅ |
| fail status | `/api/v1/fail/health` | 200 ✅ |
| findings list | `/api/v1/analytics/findings` | 200 ✅ |
| exposure cases | `/api/v1/cases` | 200 ✅ |
| compliance frameworks | `/api/v1/compliance-engine/frameworks` | 200 ✅ |
| analytics dashboard | `/api/v1/analytics/dashboard/overview` | 200 ✅ |
| mcp server status | `/api/v1/mcp-protocol/status` | 200 ✅ |
| knowledge graph | `/api/v1/knowledge-graph/status` | 200 ✅ |
| sast scanner | `/api/v1/sast/status` | 200 ✅ |
| dast scanner | `/api/v1/dast/status` | 200 ✅ |
| secrets scanner | `/api/v1/secrets/status` | 200 ✅ |
| container scanner | `/api/v1/container/status` | 200 ✅ |
| cspm/iac scanner | `/api/v1/cspm/status` | 200 ✅ |
| evidence | `/api/v1/evidence/` | 200 ✅ |
| mcp tools | `/api/v1/mcp/tools` | 200 ✅ |
| workflows | `/api/v1/workflows` | 200 ✅ |
| policies | `/api/v1/policies` | 200 ✅ |
| reports | `/api/v1/reports` | 200 ✅ |
| audit logs | `/api/v1/audit/logs` | 200 ✅ |
| remediation | `/api/v1/remediation/tasks` | 200 ✅ |
| inventory | `/api/v1/inventory/applications` | 200 ✅ |
| users | `/api/v1/users` | 200 ✅ |
| teams | `/api/v1/teams` | 200 ✅ |
| sandbox | `/api/v1/sandbox/health` | 200 ✅ |

## Agent Assignments

| Agent | Task | Priority |
|-------|------|----------|
| backend-hardener | DEMO-001: Fix broken endpoints + OpenAPI | P0 |
| qa-engineer | DEMO-002: Postman GREEN + DEMO-006: Fix coverage | P0 |
| frontend-craftsman | DEMO-003: Wire UI to real APIs | P0 |
| threat-architect | DEMO-004: CTEM full loop demo script | P0 |
| sales-engineer | DEMO-005: 5 persona scripts | P0 |
| devops-engineer | DEMO-007: Docker demo | P1 |
| technical-writer | DEMO-008: API docs | P1 |
| data-scientist | DEMO-009: MCP demo | P1 |
| ai-researcher | DEMO-010: Knowledge Graph demo data | P1 |
| security-analyst | DEMO-011: Evidence export demo | P1 |
| enterprise-architect | DEMO-012: Self-learning demo | P2 |
| vision-agent | Post-flight alignment check | Support |
| agent-doctor | Engine health verification | Support |
| context-engineer | Codebase map update | Support |
| scrum-master | Sprint progress tracking | Support |
| marketing-head | Demo talking points | Support |
| swarm-controller | Agent coordination — NO cascade stops | Support |

## Data-Flow (Unchanged from Sprint 1)

- context-engineer produces: codebase-map.json, briefing, architecture-context.md
- vision-agent produces: vision-alignment, vision-preflight
- agent-doctor produces: health-dashboard.json, health-report
- All agents READ: sprint-board.json, this file, briefing-2026-03-01-enterprise-demo.md
