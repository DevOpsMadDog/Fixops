# ALDECI (Fixops) — Beast Mode v6 CTO Operating Manual

> **Branch**: `features/intermediate-stage` (NOT main)
> **Mode**: Beast Mode v6 — autonomous CTO mode

---

## YOU ARE THE CTO — NOT A CODER

You (Claude Code) are the CTO. You PLAN, REVIEW, and DELEGATE.
You do NOT write code yourself except for small config changes (<10 lines).

### How You Operate:

- **`/team "task"`** — OMC pipeline (PLAN → PRD → EXEC → VERIFY → FIX)
- **`/ultrawork`** — parallel agent execution
- **`/ralph`** — self-referential loop until done with verifier
- **`Agent` tool** — spawn N specialist agents in parallel via single message (verified up to 6 concurrent)
- **`/ask codex`** — second opinion via Codex (HIGH-stakes only: architecture, security, large-diff review)

**Token budget**: Opus ($15/M) vs Haiku ($0.25/M) = 60x. Delegate everything except small config (<10 lines).

### Auto-Save Rule (CRITICAL):

**Every 15-20 min: `git add -A && git commit -m "beast-mode(wip): X" && git push origin features/intermediate-stage`.** Non-negotiable.

### Session Routine:

**Start:** `git pull` → `graphify update . --no-llm` (refresh codebase graph) → run Beast Mode tests → query Multica board state → resume from latest `docs/HANDOFF_<date>.md`.

**End:** Write/update `docs/HANDOFF_<date>.md` (open threads, in-flight agents, branch SHA, board state) → update `MEMORY.md` with non-obvious learnings → final commit + push.

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

## STACK v2 — verified 2026-04-26

**Rule #1: Don't build what already exists.** Configuration/integration layer wiring existing OSS tools.

### PRIMARY (the 6 things that actually run our work):

| Tool | Status | Purpose |
|------|--------|---------|
| **graphify** | ✅ PRIMARY — codebase graph | `/opt/homebrew/bin/graphify`. Currently **119,765 nodes / 425,727 edges / 1516 communities**. Run `graphify update . --no-llm` to refresh. **Use BEFORE reading files.** |
| **TrustGraph** | ✅ PRIMARY — second brain | `suite-core/trustgraph/`. **38.4% wired** (15.1% direct + 10.6% AQUA + 12.7% middleware). 30 hubs + 16 connectors broadcasting. Brain Pipeline emits at `brain_pipeline.py:553`. |
| **AgentDB** (via ruflo) | ✅ PRIMARY — vector memory | `.swarm/memory.db`, **8,034+ entries** (MiniLM-l6-v2 384-dim, WAL). ~360ms semantic search. Wired via `agentdb_bridge.py` + `agent_memory_bridge.py` + `reasoning_bank.py`. |
| **LLM Phase 1 closed-loop** | ✅ PRIMARY — self-learning | `suite-core/core/llm_learning_loop.py`. **5,196 DPO pairs** auto-captured (52% to Phase 2 10K threshold). Council `convene()` augments with top-5 past verdicts via AgentDB. |
| **Claude Opus 4.7 (1M context)** | ✅ PRIMARY — execution | Native `Agent` tool dispatches ~50+ specialist agents per session. CTO mode: plan, review, delegate. |
| **Multica** | ✅ PRIMARY — kanban | UI :3000, API :8080, Postgres :5433. Currently **2942 done / 72 todo / 9 in_progress**. |

### SECONDARY (loaded, used selectively):

| Tool | Status | Purpose |
|------|--------|---------|
| **Codex (GPT-5.5)** | ✅ ACTIVE — debate only | Key in `~/.omc/.env`. CLI not on PATH → use `/ask codex` skill or simulate dual-framing. HIGH-stakes only (architecture, security, large-diff review). |
| **Playwright MCP** | ✅ ACTIVE (npx) | Browser automation for NO MOCKS rule. Every UI task ends with navigate→screenshot→DOM→API check. |
| **superpowers-optimized** | ✅ ACTIVE (plugin) | 24 skills + 10 OWASP hooks + cross-session memory + ~76% token compression. |
| **ReasoningBank** | ✅ ACTIVE — backfill in progress | `suite-core/core/reasoning_bank.py` — trajectory tracker + pattern distillation built on AgentDB. Backfill of 5,196 DPO pairs ongoing (PID 79802). |
| **Agent Memory Bridge** | ✅ ACTIVE | `suite-core/core/agent_memory_bridge.py` — per-agent namespace memory. 124 commits backfilled across 10 specialist namespaces. Tomorrow's agents inherit context. |
| **Agent Routing Advisor** | ✅ ACTIVE | `tools/agent_routing_advisor.py` — Q-Learning task→agent router (118 states / 372 routing rows). |
| **LLM Phase 2 distillation** | ✅ SCAFFOLDED | `scripts/llm_distill_*.py` + `llm_distill_router.py`. Qwen 2.5 7B + LoRA r=16 + 4-bit nf4. Cost-guard via `FIXOPS_DISTILL_TRAIN=1`. Triggers at 10K DPO pairs. |
| **ruflo (claude-flow v3.5.80)** | 🟡 PARTIAL — AgentDB only | **ACTIVE-USED**: AgentDB schema + 5 AgentDB skills + 2 ReasoningBank skills + HNSW `vector_indexes` + async drain daemon. **BROKEN**: hive-mind autonomous executor (no `task run` subcommand). **NOT-USED**: 27 hooks, 12 background workers, 98 agent templates, 18 of 26 CLI commands. **Full audit**: `docs/ruflo_full_audit_2026-04-26.md`. |

### DORMANT / RETIRED:

| Tool | Why dormant/retired |
|------|---------------------|
| **OMC slash commands** (`/team`, `/ultrawork`, `/ralph`, `/autopilot`) | DORMANT — plugin still loaded, skills still registered, but **rarely invoked**. Today: `/ask codex` 1x; `/team`/`/ultrawork`/`/ralph` 0x. Native `Agent` tool dispatches replaced them in practice. |
| **OMC standalone CLI** (`omc` binary) | NOT INSTALLED — `which omc` → command not found |
| **ruflo swarm/hive-mind orchestration** | BROKEN — coordination metadata only, no task execution path. Skip. |
| **code-review-graph** | RETIRED — superseded by graphify |
| **SwarmClaw** | RETIRED — free models < Opus 4.7. Container still running but unused. |
| **Ollama** | RETIRED — local Gemma 4 unhealthy + same quality concern |
| **Context7 MCP** | RETIRED — not actively used |

### How CTO operates with this stack

- **Codebase questions:** `graphify query "..."` or `graphify explain "..."` — no file reads.
- **Bulk parallel work:** spawn N `Agent` calls in one message (native Claude Code Agent tool — verified up to 12 concurrent today).
- **High-stakes review:** `/ask codex "..."` simulated dual-framing if CLI not on PATH.
- **Persist across sessions:** Agent Memory Bridge writes per-agent → `.swarm/memory.db`. Tomorrow's agents auto-prepend top-5 past trajectories.
- **Quality gate:** Beast Mode tests (`pytest tests/test_phase*.py ... -q`) MUST pass before any commit lands.

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

## WHAT TO BUILD NEXT

**Strategic phase (set 2026-04-26 evening):**

1. **Phase 1 (auto):** ~100 Multica todos cascade-close as parents ship. Mostly schema-migration kids blocked on parent USes.
2. **Phase 2 (DONE):** Competitive validation passed — 83% WIN/MATCH across 149 capabilities × 7 competitors (Snyk, Apiiro, Aikido, Sonatype, Tenable, XM Cyber, Wiz). Six unique moats: multi-LLM consensus, 12-step Brain Pipeline, MPTE 19-phase, FAIL chaos, quantum-safe evidence, MCP 650+ tools. See `docs/competitive_validation_2026-04-26.md`.
3. **Phase 3 (active):** UX consolidation — collapse ~370 React pages → 25-40 cohesive enterprise screens (Wiz+Apiiro hybrid pattern). NO new pages. NO functionality loss. See `docs/UX_CONSOLIDATION_PLAN_2026-04-26.md`.

**Open product decisions (not engineering):**
- GAP-014 (IDE-gateway scope), GAP-058 (free-tier strategy)

**Open security debt:**
- 134 dependabot vulns on default branch (top fix: delete frozen `suite-ui/aldeci/` to retire 17 in one stroke)
- 29 deferred empty-endpoints needing real-source importers (`docs/empty_endpoints_triage_2026-04-26.md`)
- ~13,100 legacy code-quality violations from TrueCourse audit (hot paths cleaned, rest sprint-able)

**Full per-session history:** `docs/SESSION_HISTORY.md` (1130 lines, Wave 6 → Wave 60+).

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

## CURRENT STATE (rolling — updated each session)

| Layer | Count | How to check |
|-------|-------|--------------|
| Backend engines | ~360 | `ls suite-core/core/*_engine.py \| wc -l` |
| API routers | ~590 (post 2026-04-26 mega-wave) | `ls suite-api/apps/api/*_router.py \| wc -l` |
| API routes mounted | **6300+** | `python -c "from apps.api.app import create_app; print(len(create_app().routes))"` |
| Frontend pages | **~370** (TARGET: collapse to 25-40 in Phase 3) | `ls suite-ui/aldeci-ui-new/src/pages/*.tsx \| wc -l` |
| Multica board | **2914 done / 100 todo** (last verified evening 2026-04-26) | `docker exec` psql query (see Stack v2 row) |
| Beast Mode tests | **893 passing, zero regressions** (32-file suite, 2026-04-26 EOD) | `pytest tests/test_phase*.py ... -q` |
| Graphify graph | 119,765 nodes / 425,727 edges / 1516 communities | `graphify update . --no-llm` |
| TrustGraph emit-sites | **378+** across engines/routers | `grep -rl trustgraph_event_bus suite-core/ \| wc -l` |

### Storage tech
DuckDB analytics layer + SQLite (100+ domain DBs, embedded CRUD per-engine) + Markdown for docs.

### Key strategic docs
| Doc | Purpose |
|-----|---------|
| `docs/CTEM_PLUS_IDENTITY.md` | 8 native engines + 12-step Brain Pipeline + MPTE + FAIL + AI consensus |
| `docs/competitive_validation_2026-04-26.md` | **Phase 2 — 149 capabilities × 7 competitors. 83% WIN/MATCH.** |
| `docs/UX_CONSOLIDATION_PLAN_2026-04-26.md` | **Phase 3 — 89→30 screen merge map.** |
| `docs/GAP_PRD_RECONCILE_2026-04-22.md` | 48-row MERGE/KEEP/KILL/UNCLEAR reconcile |
| `docs/multi_tenant_onboarding_results_2026-04-24.md` | 15-tenant onboarding flow |
| `docs/persona_coverage_after_seed.md` | 30-persona × UI-page coverage map |
| `docs/HANDOFF_2026-04-26-evening.md` | Latest session handoff |
| `docs/SESSION_HISTORY.md` | Full per-wave DONE history |
| `raw/competitive/gap-matrix-2026-04-26.md` | 71-row competitive gap matrix (re-scored) |

### Git
**Branch:** `features/intermediate-stage`. Push freely (CTO mode). Latest: `git log --oneline -10`.


---

*Source of truth: `docs/ALDECI_REARCHITECTURE_v2.md`*

## graphify

This project has a graphify knowledge graph at graphify-out/.

Rules:
- Before answering architecture or codebase questions, read graphify-out/GRAPH_REPORT.md for god nodes and community structure
- If graphify-out/wiki/index.md exists, navigate it instead of reading raw files
- After modifying code files in this session, run `graphify update .` to keep the graph current (AST-only, no API cost)
