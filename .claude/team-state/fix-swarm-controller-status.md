# Fix Report: swarm-controller — Cycle 1/3

**Date:** 2026-03-02
**Fix Agent:** JARVIS Auto-Fix (Opus 4.6)
**Failed Agent:** swarm-controller
**Run ID:** swarm-2026-03-02_00-01-07
**Failure Reason:** Persona verification failed — D grade (40%), no output log
**Pillar(s) Served:** V3 (Decision Intelligence), V7 (MCP-Native)

---

## Root Cause Analysis

### Failure Chain
1. **Phase 3** (Builders: backend-hardener, frontend-craftsman, threat-architect) launched in parallel at 00:53:39
2. backend-hardener and threat-architect **exceeded the watchdog phase deadline** (~8.5 hours of runtime) and were killed at 09:26:30
3. Phase 3 was marked **FAILED** with "ALL agents failed (4/3)" — the 4/3 overcounting is because `launch_skipped` agents are added to `phase_failed`
4. Phase 3.5 (swarm-controller) had a hard dependency: `PHASE_DEPENDS_ON[3.5]="3"`
5. With `CASCADE_STOP=true`, the dependency check at `check_phase_dependency()` (line 5290) returned failure
6. swarm-controller was **SKIPPED entirely** — never spawned, no log produced, no checkpoint written
7. Persona verification correctly gave it **D grade (40%)** — "No output log", "No markers checked"

### Same failure occurred in both 2026-03-02 runs:
- `swarm-2026-03-02_00-01-07`: Phase 3 FAILED → Phase 3.5 SKIPPED
- `swarm-2026-03-02_00-05-50`: Phase 3 FAILED → Phase 3.5 SKIPPED

### Contributing Factor
The agent definition (`.claude/agents/swarm-controller.md`) explicitly states:
> `⚠️ ENTERPRISE DEMO SPRINT — NO CASCADE STOPS`
> `All 17 agents run independently. If one fails, others continue.`
> `Set CASCADE_STOP=false.`

But the launcher script had `CASCADE_STOP=true` and `[3.5]="3"`, contradicting the agent's own instructions.

---

## Fix Applied

### File: `scripts/run-ctem-swarm.sh` (line 257)

**Before:**
```bash
PHASE_DEPENDS_ON=(
  [0]="none" [1]="0" [2]="1" [3]="1" [3.5]="3" [4]="3" [5]="1"
  [6]="none" [7]="none" [8]="none" [9]="none" [10]="none"
)
```

**After:**
```bash
PHASE_DEPENDS_ON=(
  [0]="none" [1]="0" [2]="1" [3]="1" [3.5]="1" [4]="3" [5]="1"
  [6]="none" [7]="none" [8]="none" [9]="none" [10]="none"
)
```

### Rationale
- Phase 3.5 (swarm-controller) reads status files from ALL agents, not just Phase 3 builders
- It can operate on stale/existing status files from previous runs
- Its only real dependency is Phase 1 (context-engineer) which provides the codebase map
- Phase 4 (security-analyst, qa-engineer) keeps its Phase 3 dependency since it validates builder output

### Files Modified
1. `scripts/run-ctem-swarm.sh` — Changed `[3.5]="3"` to `[3.5]="1"`
2. `.claude/team-state/swarm-controller-status.md` — Updated with fix details
3. `.claude/team-state/fix-swarm-controller-status.md` — This report

---

## Verification

- `bash -n` syntax check: Pre-existing backtick warning in heredoc Python code (line 1120) — NOT introduced by this fix
- Dependency change is a single-value associative array update — no structural changes to the script
- Next JARVIS run will spawn swarm-controller regardless of Phase 3 outcome

---

## Recommendation for Next Cycle

If the swarm-controller still gets D-grade after this fix, the secondary issue is that Phase 4 (security-analyst, qa-engineer) also depends on Phase 3 and was also skipped. Consider:
1. Changing `[4]="3"` to `[4]="1"` as well
2. Or setting `CASCADE_STOP=false` globally for the enterprise demo sprint as the agent definition recommends

---

*Fix applied at 2026-03-02 by JARVIS Auto-Fix Agent (Cycle 1/3)*
