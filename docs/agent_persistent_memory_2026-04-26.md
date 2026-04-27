# Agent Persistent Memory via AgentDB
**Date**: 2026-04-26
**Branch**: `features/intermediate-stage`
**Driving doc**: `docs/ruflo_swarm_evaluation_2026-04-26.md` (commit `40e57f92`)
**Underlying bridge**: `suite-core/trustgraph/agentdb_bridge.py` (commit `73c05c0d`)

## Problem
Specialist agents — `backend-hardener`, `frontend-craftsman`, `qa-engineer`,
`agent-doctor`, `security-reviewer`, etc — start every Claude Code session
**cold**. Each invocation re-derives project state from scratch, even when the
exact same agent fixed the same issue yesterday.

The ruflo swarm evaluation flagged this as the biggest unrealised win: ruflo's
`.swarm/memory.db` already has 4,642 entries with an HNSW vector index. We
just weren't reading from it on agent startup, or writing to it on agent
completion.

## Solution
A thin adapter layer on top of the existing `AgentDBBridge` that gives every
specialist its own searchable, persistent task history. Two files:

| File | Purpose |
|---|---|
| `suite-core/core/agent_memory_bridge.py` | `AgentMemoryBridge` — `recall()` and `remember()` for specialists. Wraps `AgentDBBridge`, reuses its embedder, async queue, and ops counters. |
| `tools/agent_memory_prompt_wrapper.py` | `wrap_prompt()` and `record_agent_outcome()` — the pure-Python helpers the CTO/dispatcher calls before sending an agent prompt and after the agent finishes. |

No new SQLite store is created. We write into the same `.swarm/memory.db`
that AgentDBBridge already manages, just under a different namespace prefix.

## Namespace scheme
Each specialist gets its own AgentDB namespace, derived once and stable
forever:

```
agent:<agent-id>
```

Examples in use right now:

| Specialist | Namespace |
|---|---|
| backend-hardener | `agent:backend-hardener` |
| frontend-craftsman | `agent:frontend-craftsman` |
| qa-engineer | `agent:qa-engineer` |
| agent-doctor | `agent:agent-doctor` |
| security-reviewer | `agent:security-reviewer` |

The helper `agent_namespace("backend-hardener")` is the canonical builder —
it lower-cases, strips, and is idempotent against the `agent:` prefix.

By default, `recall()` searches **only** the calling specialist's namespace
so each agent stays in its own lane. Pass `cross_agent=True` to widen the
search (useful when, e.g., `backend-hardener` wants to know what
`qa-engineer` previously noted about an endpoint).

## How to use

### From inside the CTO dispatcher (or any orchestrator code)
```python
from tools.agent_memory_prompt_wrapper import wrap_prompt, record_agent_outcome

# Before dispatching the agent:
augmented = wrap_prompt(
    agent_id="backend-hardener",
    prompt="Fix IDOR in /admin/users endpoint, scope to org_id ...",
    k=5,                # top-K past similar tasks
    min_similarity=0.15,
)
# Send `augmented` to Task tool / OMC / SwarmClaw.

# After the agent finishes:
record_agent_outcome(
    agent_id="backend-hardener",
    task_brief="Fix IDOR in /admin/users endpoint, scope to org_id ...",
    outcome="success",                # success|partial|failed|blocked
    summary="Added tenant scoping; 4 tests; no regressions.",
    findings=["IDOR via ?org_id=", "Missing role guard"],
    commit_sha="abc1234",
    files_touched=["suite-api/apps/api/admin_router.py"],
)
```

### From inside a specialist agent (manual recall)
```python
from core.agent_memory_bridge import recall_for_agent

past = recall_for_agent(
    agent_id="backend-hardener",
    task_brief="Audit auth middleware for JWT replay",
    k=5,
)
for mem in past:
    print(mem.render_for_prompt())
```

## What's stored on `remember()`
For every persisted task, AgentDB receives:

| Field | Source |
|---|---|
| `namespace` | `agent:<agent-id>` |
| `key` | derived from `agent_id` + first 200 chars of `task_brief` (idempotent: same brief from same agent updates the row) |
| `content` (embedded) | `agent.task.completed | title=<brief>` + JSON tail of full payload |
| `embedding` | 384-dim from MiniLM (or hash fallback if MiniLM unavailable) |
| `metadata.event_type` | `"agent.task.completed"` |
| `metadata.embedder` | resolved embedder name |
| `metadata.ingested_at_ms` | epoch ms |
| `tags` | `["agent.task.completed", "agent:<agent-id>"]` |

Payload (rehydrated by recall):
- `agent_id`
- `task_brief`
- `outcome` — normalised to `success` / `partial` / `failed` / `blocked` / `unknown`
- `summary`
- `findings` (list of strings)
- `commit_sha`
- `files_touched`
- `completed_at_ms`
- Any `extra` fields the caller passed

## Retrieval semantics
- `recall()` returns up to `k` results, **sorted descending by cosine similarity**.
- Default similarity floor is **0.15** — weakly related and up. Hash-embedder
  cosine for unrelated tasks is typically <0.1, same-topic >0.3, so 0.15 is
  the conservative "anything that might be relevant".
- Results are reconstructed into typed `AgentTaskMemory` objects so callers
  don't parse JSON manually.

## Observability
`AgentMemoryBridge.health()` returns:
```json
{
  "available": true,
  "store_path": "./.swarm/memory.db",
  "embedder": "minilm-l6-v2",
  "recalls": 17,
  "remembers": 12,
  "failures": 0,
  "agentdb": { "...full AgentDBBridge.health() ..." }
}
```

Underlying AgentDB metrics (writes/searches/CLI fallbacks) and the
async-queue stats (`agentdb_async_queue.db`) remain available unchanged via
`get_agentdb_bridge().health()`.

## Retention policy
- Memory entries inherit the AgentDB lifecycle (`status='active'`).
- We do NOT delete on read. `dual_write` is idempotent on
  `(namespace, key)`, so the same brief from the same agent UPDATES the row
  in place rather than creating duplicates.
- Pruning policy is owned by the worker daemon
  (`scripts/agentdb_async_worker.py`). A future revision can age out
  `outcome='failed'` rows older than 90 days while keeping `success` rows
  indefinitely. Until that lands: rows live forever — fine for the current
  4,642-row baseline.

## Failure mode
**Best-effort everywhere.** If `.swarm/memory.db` is missing, AgentDB is
disabled, or the SQLite write fails:

- `recall()` returns `[]`
- `remember()` returns `False`
- `wrap_prompt()` returns the original prompt unchanged
- `record_agent_outcome()` returns `False`

The specialist agent never sees an exception from this layer.

## Tests
`tests/test_agent_memory_bridge.py` — three pytest cases:

1. **`test_remember_then_recall_round_trip`** — writes a backend-hardener
   task, reads it back via a related query, asserts the typed
   `AgentTaskMemory` round-trips faithfully (commit_sha, findings, files).
2. **`test_namespace_isolation_between_specialists`** — two agents writing
   in their own namespaces; default recall is single-namespace; passing
   `cross_agent=True` surfaces both. Also covers safety on empty inputs.
3. **`test_prompt_wrapper_prepends_memory_and_outcome_records`** — end-to-end
   through `tools/agent_memory_prompt_wrapper.py`: record an outcome, wrap a
   new prompt, assert the prefix appears with the past commit SHA, and that
   the original prompt is preserved verbatim at the end.

All three use the **real `AgentDBBridge`** against an isolated per-test
SQLite file (created fresh in `tmp_path`). No mocks of the underlying store.

## Out of scope (future work)
- Auto-summarisation: today the caller decides the `summary` and `findings`.
  A future hook could LLM-summarise the agent transcript before persisting.
- Per-agent decay: tune the `min_similarity` floor per specialist
  (e.g. tighter for QA who wants exact-repro recall, looser for security
  reviewers who want loose pattern matches).
- Auto-prefix in subagent tool: today CTO calls `wrap_prompt` explicitly.
  Wiring it into the SubagentStart hook would make memory injection
  transparent.
