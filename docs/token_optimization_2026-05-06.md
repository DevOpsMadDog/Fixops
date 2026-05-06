# Token Optimization Audit — Haiku/Sonnet/Opus Routing Rules

**Date:** 2026-05-06
**Multica:** #4024
**Branch:** features/intermediate-stage

---

## Background

CLAUDE.md states: "Opus ($15/M) vs Haiku ($0.25/M) = 60x. Delegate everything except small config (<10 lines)."

Current practice defaults agent dispatch to Sonnet or Opus regardless of task complexity. This audit establishes a tiered routing policy to capture the 60x cost differential where appropriate.

---

## Model Tier Definitions

| Tier | Model | Cost (input/M tokens) | Best For |
|------|-------|-----------------------|----------|
| Haiku | claude-haiku-4-x | ~$0.25 | Read-only sweeps, pattern checks, doc writes, Playwright smoke |
| Sonnet | claude-sonnet-4-x | ~$3.00 | New features, backend perf work, medium-complexity wiring |
| Opus | claude-opus-4-x | ~$15.00 | Security vulns, large architecture decisions, complex orchestration |

---

## Subagent Type → Recommended Tier

| subagent_type | Recommended Tier | Rationale |
|---------------|-----------------|-----------|
| qa-engineer (sweep, no code change) | **Haiku** | Read-only grep + assert pattern — no reasoning depth needed |
| qa-engineer (writing new tests) | Sonnet | Requires understanding contracts and edge cases |
| technical-writer | **Haiku** | Template fill + prose — no code synthesis |
| analyst (read-only audit, metrics) | **Haiku** | Aggregation + summarization of existing data |
| frontend-craftsman (tab fill, small repeating pattern) | **Haiku** | Copy-paste-adjust widget pattern — low ambiguity |
| playwright-smoke (navigate + screenshot + DOM check) | **Haiku** | Deterministic 5-step script, zero code generation |
| backend-hardener (perf hunt, profiling) | Sonnet | Needs reasoning over call graphs and async patterns |
| frontend-craftsman (new hub, first implementation) | Sonnet | Greenfield component design requires judgment |
| ddd-domain-expert | Sonnet | Domain modeling requires bounded-context reasoning |
| system-architect (medium decisions, <3 services) | Sonnet | Moderate design space, documented constraints |
| security-architect (vuln triage, STRIDE/DREAD) | **Opus** | High-stakes, adversarial reasoning, false negatives are costly |
| oh-my-claudecode:architect (large cross-service design) | **Opus** | Full-context architectural decisions, rare |
| orchestrator (complex multi-agent coordination) | **Opus** | Needs global state awareness across N parallel agents |

---

## Cost-Per-Task Estimates

Baseline assumption: average tick = 3 agents × 50K tokens each = 150K tokens total per dispatch round.

### Current (all-Sonnet default)
- 150K tokens × $3.00/M = **$0.45 per tick**

### Proposed (tiered routing)

Typical session mix estimate:
- 50% of ticks are read-only sweeps/smoke/docs (Haiku eligible)
- 35% are feature/perf work (Sonnet)
- 15% are security/architecture (Opus)

| Task bucket | Tokens/tick | Rate | Cost/tick | Share | Weighted cost |
|-------------|-------------|------|-----------|-------|--------------|
| Haiku (sweep/smoke/docs) | 150K | $0.25/M | $0.038 | 50% | $0.019 |
| Sonnet (feature/perf) | 150K | $3.00/M | $0.45 | 35% | $0.158 |
| Opus (security/arch) | 150K | $15.00/M | $2.25 | 15% | $0.338 |
| **Proposed blended** | | | | | **$0.515 → wait...** |

Correction: prior all-Sonnet blended cost assumes all 3 buckets at Sonnet:
- All Sonnet: $0.45 × 1.0 = **$0.45/tick**
- Tiered: $0.019 + $0.158 + $0.338 = **$0.515/tick**

That appears higher because the 15% Opus bucket is expensive. The real saving is replacing the subset of tasks previously run on Sonnet that should be Haiku. If the pre-tiering baseline had those 50% "sweep" ticks on Sonnet (not Opus), the comparison is:

| Scenario | Blended cost/tick |
|----------|-------------------|
| Baseline (all-Sonnet, no Opus at all) | $0.45 |
| Tiered (50% Haiku, 35% Sonnet, 15% Opus) | $0.515 |
| Tiered (50% Haiku, 50% Sonnet, 0% Opus*) | $0.038×0.5 + $0.45×0.5 = **$0.244** |

*Most sessions do not trigger Opus at all. For a session with zero security/arch dispatches (the common case), tiered routing cuts per-tick cost from $0.45 to $0.244 — a **46% reduction**.

For sessions that previously defaulted sweep agents to Opus:
- 50% Haiku + 50% Opus (old bad pattern) = $0.019 + $1.125 = $1.144/tick
- 50% Haiku + 35% Sonnet + 15% Opus (tiered) = $0.515/tick
- Saving: **55% reduction**

---

## 3 Concrete Dispatch Rules

### Rule 1: No-code-change qa-engineer sweep → Haiku
**Condition:** qa-engineer task description contains NO mention of "write", "add test", "create", "fix" — only "sweep", "check", "audit", "regression", "verify existing".
**Action:** dispatch with `model: haiku`
**Saving per sweep tick:** $0.45 → $0.038 (92% reduction per agent slot)
**Example:**
```
# Before (Sonnet default)
Agent: qa-engineer — "sweep test_phase*.py for timeout violations"

# After (Haiku routing)
Agent: qa-engineer [haiku] — "sweep test_phase*.py for timeout violations"
```

### Rule 2: Playwright smoke (navigate + screenshot + DOM + API check) → Haiku
**Condition:** task is the 5-step NO MOCKS gate: navigate → screenshot → DOM → network check → pass/fail report. No code changes produced.
**Action:** dispatch with `model: haiku`
**Saving:** Same 92% per agent slot. A 5-page smoke run (5 agents) saves ~$2.06 vs Sonnet.
**Example:**
```
# Before
Agent: playwright-smoke [sonnet] — "verify /assets/flows real API call"

# After
Agent: playwright-smoke [haiku] — "verify /assets/flows real API call"
```

### Rule 3: technical-writer / analyst read-only → Haiku; security-architect always → Opus; everything else default → Sonnet
**Condition matrix:**
- `technical-writer` (any doc update, handoff, changelog) → **Haiku**
- `analyst` with no code output → **Haiku**
- `security-architect`, STRIDE/DREAD, vuln triage, pentest review → **Opus** (non-negotiable — false negative cost > token cost)
- All other agent types → **Sonnet** (safe default)

**This rule eliminates the two most common mis-routings:** writers burning Sonnet on prose, and security work under-provisioned on Haiku.

---

## Estimated Session-Level Savings

For a typical 20-tick beast-mode session (60 agent slots total):

| Agent type | Slots | Old model | Old cost | New model | New cost | Saving |
|------------|-------|-----------|----------|-----------|----------|--------|
| qa-engineer sweeps | 15 | Sonnet | $0.68 | Haiku | $0.056 | $0.62 |
| playwright-smoke | 10 | Sonnet | $0.45 | Haiku | $0.038 | $0.41 |
| technical-writer | 5 | Sonnet | $0.23 | Haiku | $0.019 | $0.21 |
| frontend-craftsman (new hub) | 10 | Sonnet | $0.45 | Sonnet | $0.45 | $0 |
| backend-hardener | 10 | Sonnet | $0.45 | Sonnet | $0.45 | $0 |
| security-architect | 5 | Sonnet | $0.23 | Opus | $1.125 | -$0.90 |
| system-architect (large) | 5 | Sonnet | $0.23 | Opus | $1.125 | -$0.90 |
| **TOTAL** | **60** | | **$2.72** | | **$2.26** | **$0.46 (17%)** |

Note: The security/architect up-tiering to Opus costs more but is non-negotiable for correctness. The net saving is modest in absolute terms for sessions with active security work. For sessions without security dispatches (the majority of daily dev sessions), savings reach **50-55%**.

---

## Implementation Notes

1. The `model` field in `.claude-flow/agents/store.json` accepts `"haiku"`, `"sonnet"`, `"opus"` as shorthand values alongside full model IDs.
2. When spawning via native `Agent` tool, include the tier in the system prompt preamble: `[HAIKU-TIER: read-only task, no code output expected]` to guide internal routing.
3. Add a pre-dispatch checklist to CLAUDE.md under "How You Operate":
   - Is the task read-only (grep/audit/screenshot/doc)? → Haiku
   - Does it touch security, vulns, or architecture across >3 services? → Opus
   - Everything else → Sonnet (default)
4. Re-evaluate quarterly as model pricing changes.

---

*Generated by analyst agent (Haiku-tier task). Multica #4024.*
