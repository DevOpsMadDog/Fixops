# ALDECI (Fixops) — Beast Mode v6 CTO Operating Manual

> **Branch**: `features/intermediate-stage` (NOT main)
> **Mode**: Beast Mode v6 — autonomous CTO mode

---

## YOU ARE THE CTO — NOT A CODER

You (Claude Code) are the CTO. You PLAN, REVIEW, and DELEGATE.
You do NOT write code yourself except for small config changes (<10 lines).

### How You Operate:

**If OMC is installed** (check: `which omc`):
- `/team "task description"` — delegates to cheaper models via OMC pipeline (PLAN → PRD → EXEC → VERIFY → FIX)
- `omc autoresearch "question"` — autonomous investigation
- `omc ask "quick question"` — routes to cheapest model

**If OMC is NOT installed** (fallback):
- Use Claude Code's built-in Task/Agent tool to spawn subagents for implementation
- You review what they produce, run tests, commit
- Still: delegate, don't write code yourself

**Token budget**: You are Opus ($15/M tokens). Haiku is $0.25/M. That's 60x. Delegate.

### Auto-Save Rule (CRITICAL):

**Every 15-20 minutes, you MUST save your work to git:**
```bash
git add -A && git commit -m "beast-mode(wip): [brief description of what changed]" && git push origin features/intermediate-stage
```
This is non-negotiable. Work that isn't committed doesn't exist. Set a mental timer.
If a task takes longer than 20 minutes, commit the partial progress anyway.

### Session Routine:

**Start:**
1. `git pull origin features/intermediate-stage`
2. `code-review-graph stats` — load codebase structure into context (46x cheaper than reading files)
3. Run Beast Mode tests only: `python -m pytest tests/test_phase*.py tests/test_connector_framework.py tests/test_trustgraph.py tests/test_pipeline_api.py tests/test_persona_workflows.py -x --tb=short --timeout=10 -q`
4. Read "What To Build Next" below
5. Delegate the highest priority task

**Every 15-20 minutes:**
- `git add -A && git commit -m "beast-mode(wip): progress on [task]" && git push origin features/intermediate-stage`

**End of session (Nightly Handoff to SwarmClaw):**
- Update "Recent Changes" at bottom of this file
- Queue remaining tasks to SwarmClaw for overnight agents (see SwarmClaw API below)
- Final commit: `beast-mode(status): summary of today's work + queued N tasks to SwarmClaw`

**Morning (Pull SwarmClaw overnight results):**
- Check what SwarmClaw agents did: `curl -s http://localhost:3456/api/tasks | python3 -m json.tool`
- Review any PRs agents created: `gh pr list --state open`
- Pull latest: `git pull origin features/intermediate-stage`
- Rebuild graph if stale: `code-review-graph build`

---

## NO MOCKS RULE — UI TASK COMPLETION CRITERIA (MANDATORY)

**Every UI task — new page, edit, bug fix, demo prep — has the same completion gate:**

1. **Open the page in a real browser** via the Playwright MCP server installed at `playwright` (`mcp__playwright__browser_navigate`, `_screenshot`, `_snapshot`).
   - Dev server runs on `http://localhost:5173` (Vite 6 default). If you hit `:3000` and it 404s, switch to `:5173`.
2. **Take a screenshot** of the rendered page. Save it under `docs/ui-snapshots/<page>-<iso8601>.png` if it's worth keeping for diff history; otherwise inline-inspect.
3. **Inspect the DOM** for tell-tale mock signatures:
   - String literals like `MOCK_`, `mock`, `lorem ipsum`, `sample-`, `demo-org`, `Acme Corp`, `John Doe`, hardcoded UUIDs that never change between reloads
   - Numbers that look like obvious magic constants (42, 1337, 999999, perfectly round counts)
   - Arrays from JSON files in `src/data/` or `src/fixtures/` instead of an `apiFetch()` call
   - Identical data on every reload (no `useEffect` / `useQuery` triggering a network call)
4. **Check the network tab** (MCP `_network_requests`) — at least one real `/api/v1/...` call MUST fire on page mount. If zero API calls, you're looking at a static page = task fails.
5. **If mock data is present, the task is NOT done.** Fix the API integration:
   - Replace `import { MOCK_X }` with `const { data } = useQuery(...)` against the real endpoint
   - If the endpoint returns empty, that's an *onboarding* problem (see "REAL CUSTOMERS, NOT SEEDED DATA" below) — do not paper over with a mock
   - If the endpoint doesn't exist, build it (or wire to the closest existing one) — do not stub it client-side
6. **Re-screenshot** after the fix. The page must show real-tenant data or a real, branded EmptyState (not a hardcoded `[]`).

**Skipping any of steps 1–5 = the task is not done.** Don't claim a UI fix is complete based on TypeScript compiling — types pass on mock pages too.

### Tooling — Playwright MCP

Installed via `claude mcp add playwright -- npx -y @playwright/mcp@latest` (see `~/.claude.json`). Available tools start with `mcp__playwright__`. Common ones:
- `mcp__playwright__browser_navigate({url})` — open page
- `mcp__playwright__browser_snapshot()` — DOM accessibility tree
- `mcp__playwright__browser_take_screenshot({filename})` — visual capture
- `mcp__playwright__browser_evaluate({function})` — run arbitrary JS in the page (use to grep DOM text for mock signatures)
- `mcp__playwright__browser_network_requests()` — confirm real API calls fire
- `mcp__playwright__browser_console_messages()` — surface React errors / failed fetches

### REAL CUSTOMERS, NOT SEEDED DATA

When the user says "test with real apps", that means **onboard them as real tenants through the actual customer flow** (org creation → connector → repo enrollment → sync → Brain Pipeline). It does NOT mean writing seed scripts that INSERT directly into DBs. Direct seed = the same as a mock — bypasses ingestion APIs, connector framework, pipeline, and tenant isolation. See `docs/multi_tenant_onboarding_results_2026-04-24.md` for the canonical onboarding flow.

---

## YOU CONTROL SWARMCLAW (Orchestrator API)

SwarmClaw is your nighttime workforce. You (Claude Code) queue tasks, agents execute overnight.

### SwarmClaw API (http://localhost:3456):

**List agents:**
```bash
curl -s http://localhost:3456/api/agents | python3 -m json.tool
```

**Create a task for an agent:**
```bash
curl -s -X POST http://localhost:3456/api/tasks \
  -H "Content-Type: application/json" \
  -d '{"title": "TASK TITLE", "agent_id": "AGENT_ID", "prompt": "Detailed instructions...", "status": "ready", "priority": "high"}'
```

**Check task status:**
```bash
curl -s http://localhost:3456/api/tasks | python3 -m json.tool
```

**Create a schedule:**
```bash
swarmclaw schedules create --base-url http://localhost:3456 \
  --name "Schedule Name" --agent-id AGENT_ID \
  --task-prompt "What to do" --schedule-type cron --cron "0 22 * * *"
```

**Check schedules:**
```bash
curl -s http://localhost:3456/api/schedules | python3 -m json.tool
```

### Model routing (all FREE via OpenRouter):
| Agent | Model | Use for |
|-------|-------|---------|
| Code Builder | `qwen/qwen3.6-plus:free` | Implementation, features, bug fixes |
| Test Writer | `qwen/qwen3.6-plus:free` | Unit, integration, e2e tests |
| Doc Generator | `gemma4` (local Ollama) | API docs, guides, changelogs |
| Security Reviewer | Council: Qwen 3.6+ + Kimi K2 | Vulnerability scanning, OWASP |
| Code Reviewer | Council: Qwen 3.6+ + Kimi K2 | Quality, patterns, best practices |

### Nightly handoff workflow:
1. At end of day, identify tasks you didn't finish
2. Queue each to SwarmClaw via API (use Code Builder agent for implementation tasks)
3. Agents pick up tasks, write code, commit to `features/intermediate-stage`
4. Morning: you review what they did, run tests, approve or fix

### Example — queue a task before signing off:
```bash
curl -s -X POST http://localhost:3456/api/tasks \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Add tests for brain_pipeline.py error handling",
    "prompt": "Write pytest tests covering all error paths in core/brain_pipeline.py. Use code-review-graph impact to find callers. Commit with beast-mode(nightly): prefix.",
    "status": "ready",
    "priority": "high"
  }'
```

---

## WHAT IS BEAST MODE v6

Beast Mode is NOT custom code. It's a configuration/integration layer that wires together 7 existing open-source tools to build ALDECI autonomously.

**Rule #1: Don't build what already exists.**

### The 8-Tool Stack:

| Tool | Purpose | Stars |
|------|---------|-------|
| **code-review-graph** | **AST codebase map — 46x token reduction. ALWAYS use before reading files.** | — |
| oh-my-claudecode (OMC) | 19 agents, team pipeline, autoresearch, smart routing | 15K+ |
| everything-claude-code | 156+ skills, 38 subagents, continuous learning | 140K+ |
| SwarmClaw | Kanban control plane, scheduling, agent lifecycle | 21K+ |
| TrustGraph (MCP) | Knowledge graph, GraphRAG, 5 Context Cores | — |
| OMNI | CLI token compression (90% reduction) | — |
| Context7 (MCP) | Live library documentation | — |
| Ollama | Local free models (Gemma 4) | — |

### code-review-graph — WHY IT'S TOOL #1:
- Parses entire codebase via Tree-sitter AST → SQLite graph (34,301 nodes, 216,476 edges for ALDECI)
- Graph DB lives at `.code-review-graph/graph.db` (169 MB)
- **BEFORE reading any file**, query the graph: `code-review-graph query "what calls brain_pipeline.py"`
- **For blast radius**: `code-review-graph impact "core/connectors.py"` → shows all affected files
- **For understanding structure**: `code-review-graph stats` → function count, class hierarchy, import map
- **Rebuilt nightly at 6am** via SwarmClaw schedule (after agents finish, before Opus review)
- Install: `pip install code-review-graph` → Build: `code-review-graph build` (runs in project root)

### Two Layers:

**Layer 1 — Claude Code Supercharged (Daytime):**
Claude Code + OMC + everything-claude-code + TrustGraph + OMNI + Context7.
You (CTO) review and approve. OMC agents do the coding.

**Layer 2 — SwarmClaw Autonomous (Nighttime, 10pm-8am):**
SwarmClaw + OpenClaw agents (Qwen 3.6 Plus, Kimi K2, Gemma 4 local) + Hermes.
Free models write code. Opus reviews via quality gate.

### Beast Mode Framework Repo:

Location: **`../best-mode-dev-framework/`** (sibling to this Fixops repo)
GitHub: `DevOpsMadDog/best-mode-dev-framework`

```
best-mode-dev-framework/
├── setup.sh                          # One-command installer for all 7 tools
├── layer1-claude-supercharged/       # OMC config, Claude settings, install script
├── layer2-swarmclaw-autonomous/      # Docker compose, agent YAMLs, schedules
│   ├── docker-compose.yml            # SwarmClaw + TrustGraph + Ollama + Redis + PostgreSQL
│   ├── agents/                       # code-builder, test-writer, doc-generator, security-reviewer, code-reviewer
│   └── schedules/                    # nightly-build (10pm), morning-review (7am), weekly-health (Sun 3am)
├── quality-gate/                     # Opus CTO review config, checklist, escalation rules
├── project-templates/                # python-fastapi, react-frontend, fullstack templates
├── examples/aldeci/                  # ALDECI-specific kanban seed, trustgraph cores, nightly priorities
└── docs/                             # architecture.md, daily-workflow.md
```

---

## WHAT IS ALDECI

ALDECI is an **ASPM + CTEM + CSPM platform** — a unified, self-hosted, AI-native security intelligence platform.
- Replaces $50K-500K/yr enterprise tools — tiered pricing: Starter $199/mo, Pro $499/mo, Enterprise $1,499/mo
- TrustGraph (5 Knowledge Cores) for versioned security knowledge
- Karpathy LLM Consensus (4 free models + Opus escalation) for decisions
- 28+ threat intelligence feeds, 32 scanner normalizers, 13 PULL + 7 bidirectional connectors
- 30 personas, 6 RBAC roles, 7 compliance frameworks
- Full architecture: `docs/ALDECI_REARCHITECTURE_v2.md`

---

## TESTING STRATEGY

There are ~327 test files. **Only run Beast Mode tests** for day-to-day work:

### Beast Mode Tests (run these — 709 tests passing):
```bash
python -m pytest \
  tests/test_phase2_connectors.py tests/test_phase3_llm_council.py \
  tests/test_phase4_integration.py tests/test_phase5_enterprise.py tests/test_phase6_streaming.py \
  tests/test_phase7_analytics.py tests/test_phase8_mcp.py tests/test_phase9_playbooks.py \
  tests/test_phase10_e2e.py tests/test_connector_framework.py tests/test_trustgraph.py \
  tests/test_pipeline_api.py tests/test_persona_workflows.py \
  -x --tb=short --timeout=10 -q -o "addopts="
```

### Legacy Tests (~190 files — DO NOT run routinely):
These test older modules (CLI, evidence, compliance, scanners, risk scoring, etc.).
Only run if you're modifying legacy code. They may have outdated assumptions.

### Full Suite (only for release validation):
```bash
python -m pytest tests/ --timeout=10 -x -q
```

---

## PROJECT STRUCTURE

```
.
├── suite-api/          # FastAPI gateway — 34 router mounts (22.6K LOC)
├── suite-core/         # Core engines — brain pipeline, connectors, CLI (140.1K LOC)
│   ├── core/           # Business logic
│   ├── connectors/     # New PullConnector framework
│   └── trustgraph/     # TrustGraph MCP server + KnowledgeStore
├── suite-attack/       # Offensive security — MPTE, attack sim (6.7K LOC)
├── suite-feeds/        # Threat intel feeds — 28+ sources (4.4K LOC)
├── suite-evidence-risk/# Evidence, risk scoring, compliance (20.3K LOC)
├── suite-integrations/ # External integrations — MCP, webhooks (6.8K LOC)
├── suite-ui/
│   ├── aldeci/         # Legacy React UI (FROZEN — do NOT modify)
│   └── aldeci-ui-new/  # Active UI (React 19 + Vite 6 + Tailwind v4)
├── tests/              # 327 test files (137 Beast Mode + 190 legacy)
├── docker/             # Docker + Kubernetes configs
├── docs/               # ALDECI_REARCHITECTURE_v2.md (source of truth)
├── sitecustomize.py    # Auto-injects suite paths into sys.path
└── requirements.txt
```

### Import Mechanism
`sitecustomize.py` auto-prepends all suite directories to `sys.path`:
```python
from core.brain_pipeline import BrainPipeline  # just works
```

---

## WHAT TO BUILD NEXT (Priority Order)

### HIGH PRIORITY
1. ✅ **Onboard 15 famous GitHub apps as REAL customers** — multi-tenant flow validation in progress. See `docs/multi_tenant_onboarding_results_2026-04-24.md`.
2. ✅ **All KEEP + MERGE + KILL gap dispositions shipped** — see `docs/GAP_PRD_RECONCILE_2026-04-22.md` for the full reconcile + `raw/competitive/gap-matrix.md` Session-Progress section.
3. ✅ **Graphify visual rebuilt** — densified 448 components → 95.8% largest component. `graphify-out/graph-filtered.html` viewable in browser.

### REMAINING
- **GAP-014** (IDE-gateway scope) + **GAP-058** (free-tier strategy) — UNCLEAR, need product decision (not engineering).
- **Legacy code-quality cleanup** — TrueCourse audit identified ~13,100 violations in pre-session engines (87.7% un-annotated fns, 2461 naive `datetime.now()`). Hot-paths already cleaned (`fa0b55a1`); rest is sprint-able.
- **Frontend mock-page conversion** — TrueCourse + UI dispatch flagged 216 no-fetch pages. 16 new dashboards (this session) are real-API; rest still need wiring per `docs/UI_OVERHAUL_DISPATCH_2026-04-22.md`.
- **NEW-G070 / NEW-G071 follow-up** — wire real tree-sitter / LSP / Prisma + Monaco-style code viewer in UI.
- **GAP-020 agentless_snapshot real cloud SDK** — currently mock adapter; needs boto3/Azure SDK for prod use.

### Full session-by-session DONE history
**Relocated to `docs/SESSION_HISTORY.md`** (1130 lines, ~76 KB). Includes every Wave 6 → Wave 60+ with engine list, router list, test counts, frontend pages, business artifacts, security fixes, multi-tenant findings.

## OPERATING RULES

1. **YOU ARE CTO** — delegate via `/team` or subagents, don't write code
2. **AUTO-SAVE every 15-20 minutes** — commit + push, no exceptions
3. **Run Beast Mode tests only** — not the full 14K test suite
4. **Zero regressions** — if Beast Mode tests fail, fix before moving on
5. **Extend existing code, don't rebuild** — many native tools already exist
6. **Every feature serves at least one of the 30 personas**
7. **NO MOCKS in UI** — see top-of-file rule. Real-customer onboarding only, not seed scripts.
8. **Commit format**: `beast-mode(feature): description` with `Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>`

---

## GIT CONFIG

- **Repo**: `DevOpsMadDog/Fixops`
- **Branch**: `features/intermediate-stage`
- **User**: DevOpsMadDog | Email: info@devopsai.co

---

## CONVENTIONS

- **Python**: FastAPI + Pydantic v2. Type hints. structlog logging.
- **Routers**: `*_router.py` with `router = APIRouter(prefix=...)`.
- **Auth**: `Depends(_verify_api_key)` or `require_auth`.
- **DB**: SQLite per domain. `PersistentDict` pattern.
- **Tests**: `test_*.py` in `tests/`. pytest-asyncio. 10s timeout.
- **UI**: Work in `suite-ui/aldeci-ui-new/` only. React 19, Vite 6, Tailwind v4.

---

## EXISTING INVENTORY (DO NOT REBUILD)

| Component | Count | Location |
|-----------|-------|----------|
| PULL connectors | 13 | suite-core/core/security_connectors.py |
| Bidirectional connectors | 7 | suite-core/core/connectors.py |
| Scanner normalizers | 32 | suite-core/core/scanner_parsers.py |
| Threat intel feeds | 28+ | suite-feeds/ |
| Backend engines | 334 | suite-core/core/*_engine.py |
| API router files | 568 | suite-api/apps/api/*_router.py |
| Engine test files | 334 | tests/test_*_engine.py |
| Frontend pages | 372 | suite-ui/aldeci-ui-new/src/pages/ |
| Beast Mode tests | 36,838+ | tests/ |
| PRDs | 332 | docs/prds/ |
| Docs | 24 | docs/ |

---

## CURRENT STATE (rolling — updated each session)

### Engine + router + test totals
| Layer | Count | Source-of-truth |
|-------|-------|-----------------|
| Backend engines | ~360 | `ls suite-core/core/*_engine.py | wc -l` |
| API routers | ~580 | `ls suite-api/apps/api/*_router.py | wc -l` |
| Frontend pages | ~290 | `ls suite-ui/aldeci-ui-new/src/pages/*.tsx | wc -l` |
| Beast Mode tests | 716 passing, zero regressions (last verified `5f17b5e6`) | `pytest tests/test_phase*.py ... -q` |
| Engine tests | ~37,000 across 350+ test files | `ls tests/test_*.py | wc -l` |

### Most recent strategic work
- **2026-04-26** — Pushed 101-commit branch to GitHub (`a1c2c854..7861f9fe`). Cleaned 658 generated files from git index (graphify-out, newman, .aldeci, etc.). Bulk-triage IDOR + posture-score bugs fixed. 7 engine routers wired (graphrag, context, duckdb_analytics, verification, intelligent_security, mitre_attack_coverage, privilege_escalation_detector). Multica board reconciled: 89 stale endpoint+frontend todos verified-and-closed (board: 2475→2565 done, 539→449 todo). Dependabot triage: top HIGH/MOD bumps applied (postcss, dompurify override, path-to-regexp, picomatch, follow-redirects). Graphify rebuilt: **119,351 nodes / 423,574 edges / 1520 communities**. See `docs/board_audit_2026-04-26.md` + `docs/HANDOFF_2026-04-26.md` + `docs/dependabot_triage_2026-04-26.md`.
- **2026-04-24/25** — Real-customer onboarding flow validation (15 apps). NO MOCKS rule + Playwright MCP added. Dashboard render bug fixed (5/5 verification routes pass). 7-of-8 commercial-vendor OSS substitutes wired (Snyk, CSPM, EDR, SIEM, Container, IAM, ThreatIntel; DAST in flight). 225 UI page conversions across ui-bulk-A1/A2/B1/B2/residual.
- **2026-04-22/23** — Beast Mode v6 reconcile: 14 KEEP engines + 30 MERGE extensions + 5 KILLs shipped. Graphify visual rebuilt. TrueCourse-audits-Fixops report.
- **2026-04-13 → 2026-04-22** — Wave 6 → Wave 60+ autonomous parallel build. Full per-wave detail in `docs/SESSION_HISTORY.md`.

### Storage technology
- DuckDB analytics layer (cross-domain queries across 60+ SQLite engines)
- SQLite: 100+ domain databases (correct for embedded CRUD per-engine)
- Markdown: docs only

### Key strategic docs (read when relevant)
| Doc | Purpose |
|-----|---------|
| `docs/CTEM_PLUS_IDENTITY.md` | 8 native engines + 12-step Brain Pipeline + MPTE + FAIL + AI consensus |
| `docs/GAP_PRD_RECONCILE_2026-04-22.md` | 48-row MERGE/KEEP/KILL/UNCLEAR reconcile |
| `docs/UI_OVERHAUL_DISPATCH_2026-04-22.md` | 22-unit UI overhaul plan + NEW-G071 |
| `docs/SPRINT_2_DEMO_BACKLOG_2026-04-22.md` | DEMO-001..005 P0 demo items |
| `docs/multi_tenant_onboarding_results_2026-04-24.md` | 15-tenant onboarding flow + UX bug surface |
| `docs/persona_coverage_after_seed.md` | 30-persona × UI-page coverage map |
| `docs/SESSION_HISTORY.md` | Full per-wave DONE history (Wave 6 → Wave 60+) |
| `raw/competitive/gap-matrix.md` | 71-row competitive gap matrix with session-progress annotations |
| `raw/competitive/truecourse-vs-fixops-comparison.md` | 40-row TrueCourse↔Fixops side-by-side |
| `raw/competitive/truecourse-audits-fixops.md` | TrueCourse running on Fixops codebase, ~13,100 legacy violations |

### Git state
**Branch:** `features/intermediate-stage`. **Latest commits:** `git log --oneline -10`. Push only when explicitly requested.


---

## BEAST MODE TOOL INSTALLATION & LOCATIONS

### Prerequisites
- Docker + Docker Compose
- Node.js (for npm)
- Homebrew (macOS) or apt (Linux)

### One-Shot Setup
```bash
cd ../best-mode-dev-framework
chmod +x setup.sh && ./setup.sh
```

### Start Beast Mode (from beast-mode-dev-framework, NOT from Fixops)
```bash
cd ../best-mode-dev-framework
./start.sh ../Fixops
```
This starts Layer 2 Docker services, rebuilds code-review-graph if stale, then launches Claude Code pointing at Fixops. Claude reads this CLAUDE.md and operates as CTO.

### Setup Details
This runs 11 steps:
1. Checks prerequisites (docker, docker-compose)
2. Installs Layer 1 (OMC, everything-claude-code skills, OMNI, Context7)
3. Installs Ollama (local LLM inference)
4. Pulls Gemma 7B model (~4GB download)
5. Prompts for OpenRouter API key (free — for Qwen 3.6+, DeepSeek V3)
6. Installs Layer 2 (SwarmClaw config)
7. Starts Docker containers (SwarmClaw, TrustGraph, Ollama, Redis, PostgreSQL)
8. Indexes codebase into TrustGraph
9. Seeds Kanban board with tasks
10. Prints summary with URLs

### Where Tools Live After Install

| Tool | Install Location | How To Access | Port |
|------|-----------------|---------------|------|
| **code-review-graph** | `pip install code-review-graph` | `code-review-graph stats/query/impact` — **USE FIRST** | — |
| OMC (oh-my-claudecode) | Claude Code plugin marketplace | `/team`, `omc autoresearch`, `omc ask` | — |
| everything-claude-code | `~/.claude-skills/ecc/` | Auto-loads based on context | — |
| OMNI | `npm -g` or `pip` global | `omni` CLI | — |
| Context7 MCP | Claude MCP config | Auto-available in Claude Code | — |
| SwarmClaw | Docker: `beast-swarmclaw` | Dashboard: http://localhost:3456 | 3456 |
| TrustGraph | `pip install trustgraph-cli` | Config: https://config-ui.demo.trustgraph.ai | 8888 |
| Ollama | Docker: `beast-ollama` OR native install | API: http://localhost:11434 | 11434 |
| Redis | Docker: `beast-redis` | localhost:6379 | 6379 |
| PostgreSQL | Docker: `beast-postgres` | localhost:5432 (user: swarmclaw) | 5432 |

### Docker Services (Layer 2)
```bash
cd ../best-mode-dev-framework/layer2-swarmclaw-autonomous

# Start all services
docker compose up -d

# Check status
docker compose ps

# View logs
docker compose logs -f

# Stop
docker compose down
```

### OpenRouter API Key (FREE models)
Sign up at https://openrouter.ai — free tier gives access to:
- Qwen 3.6 Plus (code-builder + test-writer agents) — qwen/qwen3.6-plus:free
- Kimi K2 (security + code reviewer council) — moonshotai/kimi-k2:free
- Gemma 4 (doc-generator, local via Ollama)
- Llama 4 (general tasks)

Save key in: `../best-mode-dev-framework/layer2-swarmclaw-autonomous/.env`
```
OPENROUTER_API_KEY=sk-or-v1-xxxxx
```

### Quick Verify Everything Works
```bash
# Check Layer 1
which omc && echo "OMC: OK" || echo "OMC: NOT INSTALLED"
ls ~/.claude-skills/ecc/ && echo "ECC: OK" || echo "ECC: NOT INSTALLED"
ollama --version && echo "Ollama: OK" || echo "Ollama: NOT INSTALLED"

# Check Layer 2 (Docker)
docker ps --format "{{.Names}}: {{.Status}}" | grep beast
# Should show: beast-swarmclaw, beast-ollama, beast-redis, beast-postgres

# Check SwarmClaw API
curl -s http://localhost:3456/api/healthz | head -1

# Check TrustGraph CLI
tg --version 2>/dev/null || echo "Install: pip install trustgraph-cli"
```

---

*Source of truth: `docs/ALDECI_REARCHITECTURE_v2.md` (v2.5). Beast Mode framework: `../best-mode-dev-framework/`*
