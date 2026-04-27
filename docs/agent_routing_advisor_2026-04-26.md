# Agent Routing Advisor — Q-Learning Task Router

**Date**: 2026-04-26
**Module**: [`tools/agent_routing_advisor.py`](../tools/agent_routing_advisor.py)
**Tests**: [`tests/test_agent_routing_advisor.py`](../tests/test_agent_routing_advisor.py) — 9/9 passing
**Mirrors**: `ruflo route` (the second-biggest unused win in the ruflo swarm CLI)

---

## Why this exists

In a typical CTO session we manually route ~30 agent dispatches across 12
specialist agents (`backend-hardener`, `frontend-craftsman`, `qa-engineer`,
`technical-writer`, `marketing-head`, `devops-engineer`, `sales-engineer`,
`security-analyst`, `data-scientist`, `enterprise-architect`, `ux-architect`,
`agent-doctor`).

Roughly **20%** of those dispatches are wrong-routed:
- Lightweight task → opus model (waste of $)
- Opus-grade task → haiku junior (low-quality result, rework loop)
- Frontend task → backend-hardener (agent stalls / refuses)

A Q-Learning router that learns from outcomes auto-suggests the right agent.
After ~50 dispatches, the Q-table dominates the cold-start priors and the
advisor reflects what actually works *for this codebase*, not what sounds
right in the abstract.

This advisor mirrors `ruflo route task` but is wired specifically to **our 12
specialist agents** (vs ruflo's 8 generic ones) and our `.swarm/memory.db`
AgentDB store.

---

## What it learns

### State (the "situation")

For each task description, we extract the top-5 keywords (frequency-ranked,
stop-words filtered, sorted alphabetically for determinism), and that becomes
the state. Example:

| Task | State |
|------|-------|
| `fix the bulk-triage IDOR vuln in API router` | `api\|bulk-triage\|idor\|router\|vuln` |
| `rebuild the dashboard React component using useQuery` | `component\|dashboard\|react\|rebuild\|usequery` |
| `write documentation guide for the new API endpoints` | `api\|documentation\|endpoints\|guide\|write` |

State is deterministic — reordering the words in the input doesn't change
the state.

### Action (the "agent choice")

One of the 12 specialist agents listed above. Each has:
- A **model tier** hint: `haiku-junior` | `sonnet` | `opus`
- A **capability keyword list** (~15-25 keywords) that boost overlap score
- A **prior Q-value** (~0.45-0.55) for cold-start

### Reward

After a dispatch completes, the caller records the outcome:

| Outcome | Reward |
|---------|--------|
| Test passed + commit landed | `+1.0` |
| Stalled / rolled back / regression | `-1.0` |

### Update rule

Contextual bandit (γ=0):

```
Q(s, a) ← Q(s, a) + α (r − Q(s, a))     where α = 0.3
```

α=0.3 means each new outcome moves the Q estimate ~30% toward the observed
reward — fast enough to learn from few samples, slow enough not to be
whiplashed by one bad dispatch.

---

## How to use it

### Mode 1 — CLI (one-shot)

```bash
python tools/agent_routing_advisor.py "fix the bulk-triage IDOR vuln"
```

Outputs JSON to stdout:

```json
{
  "task": "fix the bulk-triage IDOR vuln",
  "agent": "backend-hardener",
  "tier": "sonnet",
  "confidence": 0.79,
  "state": "bulk-triage|idor|vuln",
  "q_value": 0.0,
  "visit_count": 0,
  "explored": true,
  "alternatives": [
    {"agent": "ux-architect", "score": 0.70},
    {"agent": "frontend-craftsman", "score": 0.55},
    {"agent": "qa-engineer", "score": 0.55}
  ],
  "similar": [
    {"key": "SAST-170978c0...", "snippet": "council.verdict ...",
     "namespace": "council_decisions", "score": 0.4}
  ],
  "reasoning": "State='bulk-triage|idor|vuln' (top-5 keywords). backend-hardener scored 0.990 ..."
}
```

Other CLI subcommands:

```bash
# After dispatch completes
python tools/agent_routing_advisor.py outcome "the task description" backend-hardener --success
python tools/agent_routing_advisor.py outcome "..." frontend-craftsman --fail --notes "agent stalled"

# Inspect the Q-table
python tools/agent_routing_advisor.py stats
```

### Mode 2 — Python library (inline use)

```python
from tools.agent_routing_advisor import route, record_outcome

rec = route("rebuild the dashboard React component using useQuery")
print(rec["agent"], rec["tier"], rec["confidence"])
# frontend-craftsman sonnet 0.78

# After the dispatch completes:
record_outcome(
    task="rebuild the dashboard React component using useQuery",
    agent="frontend-craftsman",
    success=True,
)
```

For finer control:

```python
from tools.agent_routing_advisor import AgentRoutingAdvisor
advisor = AgentRoutingAdvisor(
    qtable_path="data/agent_routing_qtable.db",
    agentdb_path=".swarm/memory.db",
)
decision = advisor.route("...")
print(decision.alternatives, decision.similar, decision.reasoning)
```

---

## Where data lives

| Path | Purpose |
|------|---------|
| `data/agent_routing_qtable.db` | Q-table (state, action, q, n) + history (auto-created) |
| `.swarm/memory.db` | AgentDB read-only source for similar-task justification |

Both are SQLite. The Q-table is created on first use; you don't need to
seed it. The AgentDB store is written by the existing TrustGraph bridge
(see `suite-core/trustgraph/agentdb_bridge.py`, commit `73c05c0d`) and read
in lexical-search-mode by this advisor.

---

## Retraining cadence

The advisor learns online — every `record_outcome()` call is an immediate
SARSA update. There is no "retraining job" to schedule.

**Recommended hooks**:

1. **Every dispatch close** — call `record_outcome()` from the orchestrator
   (CTO session script, SwarmClaw post-task hook, or `swarm-controller`).
2. **Nightly housekeeping** — optionally print `stats()` to the daily handoff
   so the human can see whether routing is converging.
3. **Q-table reset** — only after major refactors that change which agent
   should own which type of task. The Q-table file path is configurable;
   delete it to start over.

---

## Fallback behaviour when AgentDB is unavailable

If `.swarm/memory.db` is missing, locked, or corrupt:

- `decision.similar = []`
- `decision.reasoning` includes the string `"AgentDB unavailable — keyword-only mode"`
- Routing **still works** — it falls back to capability priors + keyword overlap
  + Q-table values. The Q-table is a separate SQLite file
  (`data/agent_routing_qtable.db`) and is never affected by AgentDB outages.

The advisor never raises on AgentDB failures. It catches `sqlite3.Error`
and degrades to keyword-only.

---

## Integration plan with existing CTO dispatch

**Phase 1 — Shadow mode (this commit)**: Advisor is callable but not
auto-invoked. CTO calls `python tools/agent_routing_advisor.py "task"` to
sanity-check routing before dispatch. No behaviour change.

**Phase 2 — Suggest mode**: Inject `route(task)` into the CTO session
prompt so each dispatch decision shows: *"Advisor suggests `backend-hardener`
(confidence 0.79). Override?"* CTO confirms or overrides. Outcomes recorded
manually.

**Phase 3 — Auto-record**: Wire `record_outcome()` into the post-task hook
for each dispatch (success = beast-mode tests pass + commit lands; fail =
stall, rollback, or regression). Q-table starts learning.

**Phase 4 — Auto-route**: For dispatches with `confidence > 0.85` and
`visit_count >= 5`, the advisor's choice is taken without CTO confirmation.
Below that threshold, ask. This eliminates the ~20% wrong-route rate
without losing human-in-the-loop on novel tasks.

---

## Tests

```bash
python -m pytest tests/test_agent_routing_advisor.py -v --timeout=15
# 9 passed in 0.30s
```

Coverage:

1. Security task → `backend-hardener`
2. Frontend task → `frontend-craftsman`
3. Doc task → `technical-writer`
4. Q-learning updates change routing after 8 negative outcomes
5. Real AgentDB SQLite store surfaces similar past tasks
6. Missing AgentDB falls back gracefully (no crash, `similar=[]`)
7. State extraction is deterministic and keyword-sorted
8. Empty/blank task raises `ValueError`
9. Unknown agent in `record_outcome()` raises `ValueError`

No mocks — both the Q-table and AgentDB tests use real SQLite databases
in `tmp_path`.

---

## Differences vs `ruflo route`

| Concern | ruflo route | This advisor |
|---------|-------------|--------------|
| Agent set | 8 generic (coder, tester, …) | 12 Fixops specialists |
| Model tier hint | No | Yes (`haiku-junior`/`sonnet`/`opus`) |
| AgentDB justification | No | Top-3 similar past tasks |
| Q-table persistence | Memory by default | SQLite at `data/agent_routing_qtable.db` |
| Cold-start | ε-greedy random | Capability priors + keyword overlap |
| Reward shaping | Generic | Test-pass + commit-landed signal |

We keep ruflo route as a generic fallback; this advisor is the Fixops-tuned
version we route through in the CTO session.
