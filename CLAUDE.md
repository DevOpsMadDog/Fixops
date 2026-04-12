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
- Replaces $50K-500K/yr enterprise tools with $35-60/month self-hosted stack
- TrustGraph (5 Knowledge Cores) for versioned security knowledge
- Karpathy LLM Consensus (4 free models + Opus escalation) for decisions
- 28+ threat intelligence feeds, 32 scanner normalizers, 13 PULL + 7 bidirectional connectors
- 30 personas, 6 RBAC roles, 7 compliance frameworks
- Full architecture: `docs/ALDECI_REARCHITECTURE_v2.md`

---

## TESTING STRATEGY

There are ~327 test files. **Only run Beast Mode tests** for day-to-day work:

### Beast Mode Tests (run these — ~137 files, ~709 tests):
```bash
python -m pytest \
  tests/test_phase1_intake.py tests/test_phase2_connectors.py tests/test_phase3_llm_council.py \
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
1. **Increase Beast Mode test coverage** — Add tests for brain_pipeline.py, connectors.py, scanner_parsers.py
2. **Docker compose for full stack** — Single `docker compose up` runs API + UI + TrustGraph
3. **Wire Copilot to TrustGraph GraphRAG** — semantic graph queries instead of keyword search (P03, P04, P20)
4. **Error handling audit** — Replace bare `except Exception` with proper error hierarchy

### MEDIUM PRIORITY
5. **API documentation** — Auto-generate OpenAPI spec for all endpoints
6. **Material Change Detector** — Git webhook → blast radius → LLM Council risk assessment
7. **Frontend: SOC T1 Dashboard** — Alert triage view with LLM Council verdicts (P03)
8. **Frontend: Compliance Dashboard** — Framework status + evidence collection (P07)

### LOWER PRIORITY
9. Horizontal scaling (Redis queue mode)
10. SAML/OIDC auth (Enterprise SSO)
11. n8n connector orchestration (400+ integrations)
12. OpenClaw pentest swarm

---

## OPERATING RULES

1. **YOU ARE CTO** — delegate via `/team` or subagents, don't write code
2. **AUTO-SAVE every 15-20 minutes** — commit + push, no exceptions
3. **Run Beast Mode tests only** — not the full 14K test suite
4. **Zero regressions** — if Beast Mode tests fail, fix before moving on
5. **Extend existing code, don't rebuild** — 52 native tools already exist
6. **Every feature serves at least one of the 30 personas**
7. **Commit format**: `beast-mode(feature): description` with `Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>`

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
| API endpoints | 771 | 64 router files |
| Beast Mode tests | ~709 | tests/test_phase*.py + related |

---

## RECENT CHANGES (2026-04-12)

- Wired 3 new routers into app.py (trustgraph, findings, pipeline)
- Connected LLM Council to brain_pipeline.py (env: FIXOPS_USE_COUNCIL=1)
- Connected PipelineOrchestrator to 32 real scanner normalizers
- TrustGraph indexed with 162 entities across 5 Knowledge Cores
- CISO Dashboard built (React 19, /mission-control/ciso)
- 709 Beast Mode tests passing

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
