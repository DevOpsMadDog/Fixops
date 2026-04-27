# Ruflo (claude-flow v3.5.80) — Full Capability Audit

**Auditor**: enterprise-architect
**Branch**: features/intermediate-stage
**Date**: 2026-04-27 (CTO mandate to stop under-counting)
**Method**: Filesystem inventory + sqlite queries + session jsonl grep + git log + ruflo's own CAPABILITIES.md cross-check

---

## Executive Summary

Ruflo ships **vastly more capability** than CLAUDE.md "ruflo AgentDB only" claims. The framework's CAPABILITIES.md advertises **15-agent swarm, 60+ agents, 26 CLI commands / 140+ subcommands, 27 hooks, 12 background workers, hive-mind consensus, SONA neural learning, MoE routing, HNSW vector search**. Of all that, we are honestly using:

- **AgentDB persistent memory** (live, 6,121 entries, MiniLM-encoded) — REAL
- **5 AgentDB skills + 2 ReasoningBank skills** auto-loaded — REAL
- **98 agent template markdown files** — present on disk, NEVER auto-imported by `Task` tool (our `subagent_type` resolves to our own 17-persona set in `.claude/agents/*.md`, not the 98 ruflo templates in subdirs)
- **Q-Learning routing concept** — we forked it ourselves (`926b8038 feat(routing): Q-Learning agent routing advisor (mirrors ruflo route)`) instead of calling `ruflo route`

Everything else (swarm, hive-mind, hooks, daemon, neural, security, performance, providers, plugins, migrate, embeddings, claims, doctor, completions) is **installed but idle, never invoked from sessions**, with one failed experiment (`b842715e experiment(ruflo): first hive-mind run + lessons learned`).

**Honest correction to CLAUDE.md**: ruflo footprint is "AgentDB + 7 active skills + 1 forked Q-routing advisor + 98 unused agent templates". Not "AgentDB only" (under-counts skills), not "all skills and capabilities" (over-counts — we use ~10% of the capability surface).

---

## Section 1 — Skills Inventory (`.claude/skills/`)

**Total skills directories**: 45. Of those, **ruflo-installed = 19**, the rest (26) are project skills (fixops, browser, etc.).

### Ruflo-installed skills (auto-loaded by Claude Code on session start)

| Skill | Status | Evidence |
|---|---|---|
| `agentdb-advanced` | **ACTIVE-USED** | Loaded as context. AgentDB live with 6,121 rows, used by `agentdb_bridge.py`. |
| `agentdb-learning` | **ACTIVE-USED** | Same — pattern learning code path active in `decision_memory.py`. |
| `agentdb-memory-patterns` | **ACTIVE-USED** | `agent_memory_bridge.py` reads/writes per-agent namespaces (30 entries for frontend-craftsman, 25 for enterprise-architect, etc.). |
| `agentdb-optimization` | **ACTIVE-IDLE** | Skill loaded; we never tuned HNSW params. |
| `agentdb-vector-search` | **ACTIVE-USED** | `find_similar_decisions()` in `agentdb_bridge.py`. 5,901 entries with `minilm-l6-v2` 384-dim embeddings. |
| `reasoningbank-agentdb` | **ACTIVE-USED** | `reasoning_bank.py` exists in suite-core. |
| `reasoningbank-intelligence` | **ACTIVE-IDLE** | Not invoked by any router. |
| `sparc-methodology` | **ACTIVE-IDLE** | SPARC mode (specification/pseudocode/architecture/refinement/coder) never used in sessions. |
| `swarm-orchestration` | **BROKEN** | `ruflo swarm` works for state-init but not as executor. `docs/ruflo_swarm_evaluation_2026-04-26.md`. |
| `swarm-advanced` | **BROKEN** | Same — depends on `swarm` substrate. |
| `hooks-automation` | **ACTIVE-IDLE** | Hooks exist (see Section 2) but NONE wired to `.claude/settings.json` (only `oh-my-claudecode@omc` is enabled). |
| `github-code-review` | **ACTIVE-IDLE** | Manual `gh` calls used instead. |
| `github-multi-repo` | **ACTIVE-IDLE** | Single-repo project. |
| `github-project-management` | **ACTIVE-IDLE** | We use SwarmClaw kanban, not ruflo's. |
| `github-release-management` | **ACTIVE-IDLE** | Manual git tags. |
| `github-workflow-automation` | **ACTIVE-IDLE** | None. |
| `pair-programming` | **ACTIVE-IDLE** | Not invoked. |
| `skill-builder` | **ACTIVE-IDLE** | Not used to build skills. |
| `stream-chain` | **ACTIVE-IDLE** | Not used. |
| `verification-quality` | **ACTIVE-IDLE** | Verification is via pytest, not ruflo. |
| `v3-cli-modernization` | **ACTIVE-IDLE** | V3 migration doc only. |
| `v3-core-implementation` | **ACTIVE-IDLE** | Reference. |
| `v3-ddd-architecture` | **ACTIVE-IDLE** | DDD progress = 0% (`metrics/v3-progress.json`). |
| `v3-integration-deep` | **ACTIVE-IDLE** | Integration check never run. |
| `v3-mcp-optimization` | **ACTIVE-IDLE** | MCP not started (autoStart=false). |
| `v3-memory-unification` | **ACTIVE-IDLE** | Reference. |
| `v3-performance-optimization` | **ACTIVE-IDLE** | Performance command never run. |
| `v3-security-overhaul` | **ACTIVE-IDLE** | Security `audit-status.json` shows status PENDING, lastScan null. |
| `v3-swarm-coordination` | **ACTIVE-IDLE** | Same as swarm. |
| `researcher` | **ACTIVE-IDLE** | Researcher skill, redundant with our `ai-researcher` persona. |

**Honest count**: ruflo skills = 19 directories. **ACTIVE-USED = 6** (5 AgentDB + 1 ReasoningBank). **ACTIVE-IDLE = 11**. **BROKEN = 2**.

---

## Section 2 — Hooks Inventory (`.claude/commands/hooks/`)

CAPABILITIES.md advertises **27 hooks + 12 background workers**. We installed the command markdown for them but **wired ZERO into `.claude/settings.json`**:

```json
{ "enabledPlugins": { "oh-my-claudecode@omc": true } }
```

That's it. No `hooks` block. The 7 ruflo hook command files (`pre-edit.md`, `post-edit.md`, `pre-task.md`, `post-task.md`, `session-end.md`, `setup.md`, `overview.md`) are **documentation, not active**.

**Status**: ALL 27 hooks = **ACTIVE-IDLE**. They self-describe as "auto-execute when enabled" but `hooks.enabled: true` in `.claude-flow/config.yaml` only matters for the daemon, which we never started (`ruflo daemon start` not in any session log).

The hook firing we DO see today (`PreToolUse:Bash` etc.) are from **OMC, not ruflo** — ruflo's hooks would route through `helpers/hook-handler.cjs` which is not invoked.

---

## Section 3 — Agent Templates Inventory (`.claude/agents/`)

**98 ruflo agent templates** present on disk across 13 subdirectories: `analysis/`, `architecture/`, `consensus/`, `core/`, `data/`, `development/`, `devops/`, `documentation/`, `flow-nexus/`, `github/`, `goal/`, `optimization/`, `payments/`, `sparc/`, `specialized/`, `sublinear/`, `swarm/`, `templates/`, `testing/`.

**Today's actual subagent dispatches** (extracted from session jsonl `458c90c7-0cc5-44cf-bf68-e94266fcf0a3.jsonl`):

```
ai-researcher, backend-hardener, context-engineer, data-scientist,
devops-engineer, enterprise-architect, frontend-craftsman, junior-worker,
marketing-head, qa-engineer, sales-engineer, scrum-master,
security-analyst, technical-writer, threat-architect, ux-architect
```

**Cross-reference**: ALL 16 dispatched personas resolve to top-level files in `.claude/agents/*.md` (our project personas), NOT to the 98 ruflo templates in subdirs. Example: when we dispatch `subagent_type: enterprise-architect`, Claude Code reads `.claude/agents/enterprise-architect.md` (project), not `.claude/agents/architecture/system-architect.md` (ruflo).

**Status**: 98 ruflo agent templates = **ACTIVE-IDLE** (loaded into context, never bound to dispatch).
**Bridge feasibility**: ruflo templates are markdown specs for agent personas. We could `cp .claude/agents/specialized/security-architect.md .claude/agents/security-architect.md` to start using one. **None done today.**

---

## Section 4 — MCP Server Inventory (`.mcp.json`)

```json
"claude-flow": {
  "command": "npx",
  "args": ["-y", "@claude-flow/cli@latest", "mcp", "start"],
  "env": { "CLAUDE_FLOW_MODE": "v3", "CLAUDE_FLOW_HOOKS_ENABLED": "true", ... },
  "autoStart": false
}
```

**`autoStart: false`**. MCP server NEVER ran today.

**Evidence**: `.claude-flow/metrics/swarm-activity.json` shows `mcp_server: 0`, `integration.mcp_active: false`. Zero `mcp__ruflo__*` or `mcp__claude-flow__*` tool invocations in any session jsonl from today (only `mcp__playwright__*` calls).

**Status**: MCP server = **ACTIVE-IDLE** (configured, autoStart disabled, never manually started).

---

## Section 5 — AgentDB Usage (`.swarm/memory.db`)

**Verified live**:
- File size: **73 MB** (was 4,642 entries on 2026-04-26 @ swarm eval; now **6,121 entries** as of 2026-04-27 13:00:54 UTC)
- WAL mode active (`memory.db-shm`, `memory.db-wal` present)
- Embeddings: **5,901 with `minilm-l6-v2` (384-dim)** + 220 fallback `hash-blake2b`

**Top namespaces by row count**:
| Namespace | Rows |
|---|---|
| `council_decisions` | 5,985 |
| `agent:frontend-craftsman` | 30 |
| `agent:enterprise-architect` | 25 |
| `agent:backend-hardener` | 15 |
| `agent:data-scientist` | 13 |
| `trustgraph` | 12 |
| `agent:qa-engineer` | 9 |
| `agent:technical-writer` | 8 |
| (other agent namespaces) | 22 |
| `default`, `fixops` | 2 |

**Wiring**:
- `suite-core/trustgraph/agentdb_bridge.py` — direct SQLite write + `find_similar_decisions()`
- `scripts/agentdb_async_worker.py` — async drain daemon for council writes
- `suite-core/core/llm_council.py`, `council_pipeline_adapter.py`, `council_enhanced.py`, `decision_memory.py`, `reasoning_bank.py`, `agent_memory_bridge.py`, `trustgraph_event_bus.py`, `backup_engine.py` — 8 source files reference AgentDB
- Async queue at `.aldeci/agentdb_async_queue.db`

**Status**: AgentDB = **ACTIVE-USED**, the only ruflo subsystem actually deeply integrated.

---

## Section 6 — CLI Usage (Session jsonl evidence)

Session `458c90c7` (today) — unique ruflo CLI invocations grep'd:

```
ruflo agent spawn          (1× — swarm eval)
ruflo daemon start         (mentioned, NOT executed)
ruflo hive-mind init/spawn/eval/task/workflow  (1× experiment, FAILED)
ruflo memory --help        (discovery)
ruflo memory init          (1× setup)
ruflo memory search        (1× test)
ruflo memory store         (1× test)
ruflo swarm init/status/evaluation  (1× swarm eval)
```

CAPABILITIES.md lists **26 commands × ~5 subcommands avg = ~140 subcommand invocations possible**. We invoked **8 distinct commands once** during yesterday's evaluation. **Zero invocations during regular work**.

`ruflo daemon` (5 subcommands), `ruflo neural` (5), `ruflo security` (6), `ruflo performance` (5), `ruflo providers` (5), `ruflo plugins` (5), `ruflo deployment` (5), `ruflo embeddings` (4), `ruflo claims` (4), `ruflo migrate` (5), `ruflo process` (4), `ruflo doctor`, `ruflo completions` (4), `ruflo workflow` (6), `ruflo session` (7), `ruflo task` (6), `ruflo config` (7), `ruflo status` (3), `ruflo route`, `ruflo explain`, `ruflo pretrain`, `ruflo build-agents`, `ruflo transfer`, `ruflo coverage-route`, `ruflo coverage-suggest`, `ruflo coverage-gaps` — **all NEVER invoked**.

---

## Section 7 — Hidden Integrations (Daemon / Background Workers)

CAPABILITIES.md lists **12 background workers**: `ultralearn`, `optimize`, `consolidate`, `predict`, `audit`, `map`, `preload`, `deepdive`, `document`, `refactor`, `benchmark`, `testgaps`.

**Verified NOT running**:
- `.claude-flow/metrics/swarm-activity.json`: `processes.agentic_flow: 0`, `processes.mcp_server: 0`, `estimated_agents: 0`
- `.claude-flow/metrics/learning.json`: `routing.decisions: 0`, `patterns.shortTerm: 0`, `patterns.longTerm: 0`, `sessions.total: 0`
- `.claude-flow/metrics/v3-progress.json`: `domains.completed: 0/5`, `learning.patternsLearned: 0`

**`.claude-flow/data/pending-insights.jsonl`**: 320 edit-event entries from today (auto-captured by something — likely OMC's `auto-memory-hook.mjs`, NOT ruflo daemon, since ruflo daemon never started). These are insights *waiting to be consumed by ruflo learn pipeline*. Pipeline not running ⇒ they'll never get distilled into AgentDB patterns.

**Status**: Background workers = **ALL 12 ACTIVE-IDLE**. The `pending-insights.jsonl` queue is a **silent leak** — 320 events captured, 0 processed, growing.

---

## Section 8 — Master Inventory Table

| Capability | Advertised by ruflo | Status | Evidence |
|---|---|---|---|
| Skills (auto-loaded) | 30+ | 19 installed, 6 USED, 11 IDLE, 2 BROKEN | `.claude/skills/` dir count + grep agentdb_bridge usage |
| Hooks | 27 | 27 IDLE (none in settings.json) | `.claude/settings.json` has only OMC plugin |
| Background workers | 12 | 12 IDLE (daemon never started) | `swarm-activity.json` processes: 0 |
| Agent templates | 98 | 98 IDLE (dispatch resolves to our 17 personas) | jsonl grep `subagent_type` |
| MCP server | 1 | IDLE (autoStart: false) | `.mcp.json` + zero `mcp__ruflo__*` calls |
| AgentDB | 1 vector DB | **ACTIVE-USED**, 6,121 entries, MiniLM 384-dim | sqlite count + 8 source files |
| CLI commands | 26 (140+ subs) | 8 commands invoked once during eval; 0 in regular work | session jsonl grep |
| Hive-mind | Queen + workers + 5 consensus mechs | BROKEN (failed first run, never re-tried) | `.claude-flow/hive-mind/state.json` initialized=false |
| Swarm orchestration | hierarchical-mesh, 15 agents | IDLE (1 idle coder agent in store, 0 tasks executed) | `agents/store.json` + status |
| SONA neural learning | <0.05ms adaptation | IDLE (never trained, patternsLearned: 0) | `learning.json` |
| Q-Learning router | `ruflo route` | NOT-USED (we forked our own at commit 926b8038) | git log |
| Knowledge Graph (PageRank) | enabled in config | IDLE (no insights consolidated) | `pending-insights.jsonl` 320 unprocessed |
| LearningBridge (ADR-049) | SONA + ReasoningBank pipeline | IDLE (consolidationThreshold=10, runs=0) | `consolidation_runs` table empty |
| HNSW vector search | 150x-12,500x faster | **ACTIVE-USED** via `vector_indexes` (2 indexes) | sqlite |
| Flash Attention | 2.49x-7.47x | NOT-IMPLEMENTED (CAPABILITIES says "🔄 In Progress") | upstream |
| 8 AgentDB controllers | causal, episodes, skills, etc. | PARTIAL — only `memory_entries` populated; patterns/skills/episodes/facts/causal_chains all = 0 rows | sqlite |

---

## Section 9 — CLAUDE.md Stack v2 Update (proposed replacement row)

Replacing the existing single-row claim:

> ~~**ruflo (claude-flow v3.5.80)** | ✅ ACTIVE — AgentDB only | Use ONLY for: AgentDB...~~

With the honest version:

```markdown
| **ruflo (claude-flow v3.5.80)** | 🟡 PARTIAL — 10% utilized | **ACTIVE-USED**: AgentDB (6,121 entries, MiniLM 384-dim, `.swarm/memory.db`), 5 AgentDB skills + 2 ReasoningBank skills auto-loaded, vector_indexes for HNSW search, async drain daemon (`agentdb_async_worker.py`). **Bridges**: `suite-core/trustgraph/agentdb_bridge.py` (8 source files reference AgentDB). **ACTIVE-IDLE (good candidates to adopt)**: `ruflo route` Q-Learning task router, `ruflo swarm status` real-time observability, `pending-insights.jsonl` consolidation pipeline (320 events unprocessed). **BROKEN**: hive-mind autonomous executor (`docs/ruflo_hive_mind_first_use_2026-04-26.md`). **NOT-USED**: 27 hooks, 12 background workers, 98 agent templates, MCP server (`autoStart: false`), 18 of 26 CLI commands. **Full audit**: `docs/ruflo_full_audit_2026-04-26.md`. |
```

---

## Section 10 — Top 3 ACTIVE-IDLE Candidates We SHOULD Start Using

### 1. **`pending-insights.jsonl` consolidation pipeline** (HIGHEST ROI)
320 edit events captured today, 0 distilled into patterns/skills. Running `ruflo daemon start` (or just `ruflo memory consolidate`) would feed these into the SONA pipeline → JUDGE/DISTILL/CONSOLIDATE → patterns table. Right now we have 5,901 council decisions in AgentDB but **0 learned patterns**. The bridge to "self-improving memory" is one daemon call away. **Effort: 1 LOC change to startup script.**

### 2. **`ruflo swarm status` for SwarmClaw overnight runs**
SwarmClaw (port 3456) gives us kanban. But mid-run agent health, token usage, consensus rounds, elapsed time, progress % are invisible — we wait until morning to see if work finished. `ruflo swarm status` is built for this. We'd wrap each SwarmClaw task in a ruflo swarm namespace and get real-time observability. **Effort: ~50 LOC wrapper in SwarmClaw task templates.**

### 3. **8 AgentDB controllers (skills, episodes, causal_chains)**
We use `memory_entries` only. Tables for `skills`, `skill_links`, `episodes`, `causal_chains`, `causal_edges`, `learning_experiences`, `recall_certificates`, `justification_paths` are all 0 rows. These are *the actual learning surface* — episodic memory of what worked, causal chains of why, justification paths for audit. Wiring our `agent_memory_bridge.py` to write episodic+causal records (not just k/v facts) would turn AgentDB from a vector store into a real ReasoningBank. **Effort: ~3-day extension to `agentdb_bridge.py`.**

---

## Files Modified by This Audit

- `docs/ruflo_full_audit_2026-04-26.md` (this file, NEW)
- `CLAUDE.md` — Stack v2 ruflo row replaced (Section 9 above)
