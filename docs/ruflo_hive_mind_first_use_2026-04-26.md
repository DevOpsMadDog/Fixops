# Ruflo Hive-Mind First-Use Experiment — 2026-04-27

**Operator**: backend-hardener
**Ruflo version**: v3.5.80
**Branch**: features/intermediate-stage
**Goal**: Use `ruflo hive-mind` to optimize Brain Pipeline `_emit_event` hot path with multi-agent raft consensus
**Time budget**: 30 min (used: ~22 min)

---

## TL;DR

**Hive-mind worked: NO** (executed end-to-end). It initialized state, registered workers, and emitted a Queen-coordinator prompt template — but the CLI cannot submit tasks (`MCP tool not found: hive-mind_task`), workers never transition from idle, and no patches/code were produced. The system is designed for Claude Code (the IDE) to drive execution via `mcp__ruflo__*` MCP tools — not autonomous CLI.

**Output produced**:
- `.hive-mind/sessions/hive-mind-prompt-hive-1777295357855.txt` (98-line prompt template, raft consensus recorded)
- `.claude-flow/swarm/swarm-state.json` (registry only)
- 3 idle worker registrations in `.claude-flow/agents/store.json`
- Zero patches, zero analysis, zero code changes to `brain_pipeline.py`

**Recommendation**: Skip hive-mind for backend optimization tasks. Use Claude Agent tool dispatch (4-10 parallel agents in one message) instead. Keep ruflo for AgentDB persistence only (per the 2026-04-26 evaluation).

---

## What Succeeded

| Step | Command | Result |
|------|---------|--------|
| 1 | `ruflo hive-mind init` | OK — created hive `hive-1777295357855`, queen `queen-1777295357855`, topology `hierarchical-mesh`, consensus default `byzantine` |
| 2 | `ruflo hive-mind spawn -n 3` | OK — 3 worker registrations created, all `status: idle` |
| 3 | `ruflo hive-mind status` | OK — shows queen + 3 idle workers, 0 tasks, 0 consensus rounds |
| 4 | Prompt-template emission | `.hive-mind/sessions/hive-mind-prompt-*.txt` written with raft consensus and full MCP tool list |
| 5 | AgentDB persistence | `.swarm/memory.db` grew from 4.6 KB seed → 73 MB across sessions (6,121 memory entries) |

---

## What Failed

| Step | Command | Failure |
|------|---------|---------|
| 1 | `ruflo hive-mind task -d "..."` | `[ERROR] Task description is required` (rejects valid syntax shown in built-in examples) |
| 2 | `ruflo hive-mind task --description "..."` | `[ERROR] Task submission error: MCP tool not found: hive-mind_task` |
| 3 | `ruflo hive-mind task "positional arg"` | Same MCP-tool-not-found error |
| 4 | `ruflo hive-mind spawn --claude -o "..."` | Hangs indefinitely (subprocess attempt to launch Claude Code blocks; killed at 8s) |
| 5 | `ruflo hive-mind <subcommand> --help` | Always returns parent `hive-mind` help — subcommand-specific flags undocumented |
| 6 | `ruflo hive-mind shutdown` | Returns `Agents terminated: undefined`, `State saved: No`, `Shutdown time: undefined` — incomplete teardown |
| 7 | `ruflo memory search --query "brain pipeline"` | `No results found` — workers never wrote anything |

---

## What We Learned

1. **Hive-mind is a coordination prompt-generator, not an executor.** It writes a Queen-coordinator prompt template that instructs *Claude Code* to invoke `mcp__ruflo__*` tools. There is no autonomous worker process. CLI `task` submission depends on an MCP tool (`hive-mind_task`) that ruflo's MCP server does not register, even though `ruflo mcp status` confirms the server is running (PID 70370, stdio).

2. **The `--consensus raft` flag IS accepted and persisted** to the prompt template (line 13: `🤝 Consensus Algorithm: raft`). So the consensus algorithm switch works at the metadata layer — but since no work executes, raft never actually runs a vote.

3. **Worker spawning is registry-only.** `spawn -n 3` registered 3 workers but never started subprocesses. They sit `status: idle` forever. The intended trigger appears to be `spawn --claude -o "..."`, which hangs on subprocess launch (probably trying to exec `claude` CLI in a way that doesn't work in our sandbox).

4. **Help text is broken.** Every `ruflo hive-mind <X> --help` returns the parent `hive-mind` help, not subcommand-specific flags. Built-in examples (`hive-mind task -d "..."`) do not match real CLI behavior. This is a ruflo bug, not user error.

5. **Comparison vs. Claude Agent tool dispatch (single message, 4 parallel agents):**

| Dimension | Hive-mind first run | Claude Agent tool |
|-----------|---------------------|-------------------|
| Setup time | ~12s (init + 3 spawns) | 0s |
| Task submitted | NO (CLI broken) | YES (in prompt) |
| Code analysis produced | NO | YES (within seconds) |
| Patch produced | NO | YES (concrete edits) |
| Byzantine fault tolerance demonstrated | NO (no votes ran) | N/A (CTO reviews) |
| Parallel synthesis demonstrated | NO (workers idle) | YES (4 parallel) |
| Real value delivered | ZERO | Significant |

Hive-mind's coordination layer added **negative value** for this task: ceremony, no execution, no output.

---

## Recommendation

**SKIP hive-mind for backend optimization tasks.** It is not yet usable as an autonomous CLI workflow. The MCP-tool dependency means it only works when driven from inside Claude Code (the IDE) — at which point you already have Claude's native Agent tool, which is faster, simpler, and actually produces output.

**KEEP** the prior recommendation from `docs/ruflo_swarm_evaluation_2026-04-26.md`:
- Use ruflo for **AgentDB persistence** only (memory.db now at 73 MB, 6,121 entries — real value)
- Use ruflo for **`swarm status` observability** if we ever wire it in
- Use ruflo for **`route` Q-Learning task router** (untested)

**Re-evaluate** when:
- ruflo registers `hive-mind_task` as an MCP tool (file an upstream issue)
- `spawn --claude` subprocess launch is fixed (or replaced with a sandboxable alternative)
- Subcommand `--help` shows real flags

For Brain Pipeline `_emit_event` optimization: dispatch 1 backend-hardener via Claude Agent tool with explicit subtasks (profile → batch SQLite → pre-allocate → benchmark → commit). 4-agent raft consensus adds zero value when the hot path has a single owner and a deterministic profile-driven solution.

---

## Files Touched

- `.hive-mind/sessions/hive-mind-prompt-hive-1777295357855.txt` (created by ruflo)
- `.claude-flow/swarm/swarm-state.json` (existed; updated)
- `.claude-flow/agents/store.json` (existed; 3 worker registrations appended)
- `.swarm/memory.db` (grew, no relevant entries written by this run)
- `suite-core/core/brain_pipeline.py` — **NOT modified**
- `docs/ruflo_hive_mind_first_use_2026-04-26.md` — this report
