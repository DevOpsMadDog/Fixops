# Ruflo Swarm Evaluation — 2026-04-26

**Evaluator**: backend-hardener  
**Ruflo version**: v3.5.80  
**Branch**: features/intermediate-stage  
**Date**: 2026-04-26

---

## Test Results

### 1. `ruflo swarm init --topology hierarchical --max-agents 4`

**Result: WORKS**

Creates `.claude-flow/` directory with:
- `.claude-flow/swarm/swarm-state.json` — swarm registry (JSON, v3.0.0 schema)
- `.claude-flow/agents/store.json` — agent registry (JSON)
- `.claude-flow/graph/` — empty, reserved for dependency graph
- `.claude-flow/metrics/`, `logs/`, `sessions/` — pre-created empty dirs

Swarm state is metadata-only at init time: `status: running`, `agents: []`, `tasks: []`. No actual processes started. Topology, maxAgents, consensusMechanism, and communicationProtocol are recorded in config. Auto-scaling enabled by default.

**Key finding**: `swarm init` is a coordination namespace registration — not a process launcher. Agents must be explicitly attached or spawned after init.

---

### 2. `ruflo agent spawn --type coder --name swarm-test`

**Result: WORKS (registration only)**

Registers agent in `.claude-flow/agents/store.json` with:
- `agentId`: unique timestamp-based ID
- `status: idle` (not running)
- `provider: anthropic`, `model: sonnet`, `modelRoutedBy: default`
- `health: 1`, `taskCount: 0`

**Key finding**: This is a registry entry, not a live process. The spawned agent is not attached to the swarm automatically — it sits idle in the store. No Claude Code subprocess was launched. No API call was made. To actually execute, you must call `ruflo swarm start -o "objective"` or `ruflo hive-mind spawn --claude`.

---

### 3. `ruflo hive-mind spawn --consensus raft "Add comment to _emit.py"`

**Result: FAILED**

```
[ERROR] Hive-mind not initialized. Run hive-mind/init first.
```

Hive-mind requires a separate `ruflo hive-mind init` step before `spawn`. This is a two-phase init pattern (swarm init != hive-mind init). The `--consensus raft` flag and task description were accepted syntactically but execution blocked on missing init state. `_emit.py` was not modified.

**Key finding**: Hive-mind and swarm are separate subsystems. Hive-mind uses a Queen-led raft consensus model; swarm uses majority vote. They do not share init state.

---

### 4. Swarm Status After Init

```
Swarm: swarm-1777279691782-8cxcz7
Active agents: 0 | Idle: 0 | Total: 0
Tasks completed: 0 | In progress: 0 | Pending: 0
Consensus rounds: 0 | Messages sent: 0
Progress: 5% (metadata-init only)
```

Elapsed time tracked (18s shown). Token usage: unknown. No tasks executed.

---

### 5. `.swarm/memory.db` — AgentDB

A pre-existing `.swarm/memory.db` (SQLite) was found with **4,642 memory_entries** rows. Schema has 45 tables covering:
- `memory_entries`, `patterns`, `pattern_history`
- `episodes`, `skills`, `skill_links`, `facts`, `notes`
- `causal_chains`, `causal_edges`, `causal_experiments`
- `recall_certificates`, `justification_paths`
- `learning_experiences`, `learning_sessions`, `reasoning_patterns`
- `vector_indexes` (for semantic search)

This is the AgentDB — ruflo's persistent cross-session memory for agents. It has real data (4,642 entries) from prior sessions. Patterns and skills tables are empty (0 rows) — learning not yet triggered.

---

## Comparison: Ruflo Swarm vs Claude Code Agent Tool

| Category | Claude Code Agent Tool | Ruflo Swarm |
|----------|----------------------|-------------|
| **Speed to first agent running** | ~2s (direct Anthropic API call) | Multi-step: init → spawn → start. ~5-10s overhead before any execution begins |
| **Orchestration overhead** | Zero — CTO dispatches, agents run | Coordination layer: message-bus, consensus rounds, swarm state JSON, health checks |
| **Parallelism** | Native: 4-10 agents in one message, true parallel Anthropic API calls | Registered as idle, require `swarm start` to activate. Parallelism is architectural but not faster to invoke |
| **Observability** | None mid-run — fire and forget, get result back | `ruflo swarm status` shows progress %, agent health, task counts, elapsed time, token usage (when populated). Real-time visibility |
| **Our project agents** | Can call backend-hardener, frontend-craftsman etc. directly | Cannot — ruflo only knows its own agent types (coder, analyst, reviewer, etc.). No bridge to our persona system |
| **Persistence** | None — agent state dies with conversation | AgentDB (memory.db) persists skills, facts, patterns, causal chains across sessions |
| **Cost** | Full Anthropic API per agent | Same underlying model cost + ruflo overhead. No cost saving |
| **Consensus** | None — CTO reviews output manually | Built-in: majority vote (swarm) or raft (hive-mind). Agents vote on outputs before committing |
| **Task routing** | Manual — CTO decides which agent | Q-Learning router (`ruflo route`) can auto-assign tasks to best agent type |

---

## Recommendation

**HYBRID** — Use ruflo for AgentDB + two specific new use cases. Do NOT replace Claude Agent tool dispatch.

### ADOPT for:
1. **AgentDB / persistent memory** — Already working (4,642 entries). Agents accumulate skills, facts, causal patterns across sessions. Our current Agent tool has zero persistence — each session starts cold.
2. **`ruflo swarm status` observability** — When we run long overnight swarms (SwarmClaw tasks), ruflo's status dashboard gives real-time visibility (progress %, token usage, elapsed time) that Claude Agent tool lacks entirely.
3. **`ruflo route` Q-Learning task router** — Auto-routes tasks to the best agent type based on learned patterns. Useful for the ~30 daily agent dispatches to reduce manual CTO routing decisions.

### SKIP for:
- Replacing native Agent tool dispatch — ruflo's multi-step init adds latency and complexity with no speed benefit. Our current pattern (4-10 agents in one message) is faster.
- Hive-mind raft consensus for code edits — requires separate init, two-phase setup, and the task still didn't execute. Overkill for single-file edits.
- Inter-agent communication between ruflo agents and our persona system — no bridge exists. Ruflo agents cannot invoke backend-hardener, frontend-craftsman, etc.

### Current valid use: AgentDB only
Per Stack v2 memory, ruflo is already designated for AgentDB. This evaluation confirms that is the right scope. The swarm/hive-mind orchestration layer is real but adds ceremony without outperforming what we already have.

---

## Top 3 Capabilities Ruflo Offers That We Are NOT Using

1. **Persistent cross-session AgentDB** (`memory.db` — skills, facts, causal chains, recall certificates). Our agents start cold every session. Wiring our agents to read/write ruflo's AgentDB would let backend-hardener remember prior vulnerabilities found, autofix patterns that worked, and endpoints already hardened.

2. **`ruflo swarm status` real-time observability dashboard** — Progress %, per-agent health, token usage, elapsed time, consensus rounds. Completely absent from our current Agent tool dispatches. Critical gap for the overnight SwarmClaw runs where we have zero visibility until completion.

3. **`ruflo route` Q-Learning task router** — Routes tasks to optimal agent type using learned Q-table. Could replace CTO manual routing for the ~30 daily agent dispatches and improve match quality over time as it learns which agent types succeed on which task categories.

---

## Files Created by This Evaluation

- `.claude-flow/swarm/swarm-state.json` — swarm registry
- `.claude-flow/agents/store.json` — agent registry (1 idle coder agent)
- `.claude-flow/graph/` — empty
- `.swarm/memory.db` — pre-existing AgentDB, 4,642 memory entries
- `_emit.py` — NOT modified (hive-mind failed before executing)
