# ALdeci — Strategic Roadmap: Next Session Priorities

> **Written:** 2026-04-26 evening | **Branch:** `features/intermediate-stage`
> **Based on:** `HANDOFF_2026-04-26-evening.md`, `competitive_validation_2026-04-26.md`,
> `trustgraph_coverage_2026-04-26.md`, `scif_readiness_2026-04-26.md`, `board_audit_2026-04-26.md`

---

## Current State (one paragraph)

50 commits landed today. P0 UX (6/6 hero screens) is shipped. LLM Phase 1
closed-loop is live with 703 real DPO pairs. SCIF Stages 1–3 are documented.
Sales + investor packs exist. Competitive gate: 83% WIN/MATCH across 7
competitors. TrustGraph coverage: 38.4% (engines wired, routers/connectors not).
Multica board: 2914 done / 100 todo / 9 in_progress. Branch is NOT pushed.

---

## Priority Ranking for Next Session

### P0 — Push the branch (5 minutes, first action)

```bash
git push origin features/intermediate-stage
```

50 commits are local-only. This is the single highest-risk item. Do it before
anything else.

---

### P1 — TrustGraph router + connector wiring (highest engineering leverage)

**Why now:** Engines are 99.1% wired but routers are 3.9% and connectors are 0%.
The ingest surface — where customer data actually enters — is unobserved.
LLM Phase 2 distillation quality depends directly on the signal richness coming
through the event bus. Fixing this multiplies every downstream capability.

**What to do:**
- Target the top 20 highest-traffic routers first (use
  `code-review-graph query "most called router"` to rank by call frequency).
- Add `emit_to_trustgraph(event_type, payload)` at the post-auth point of each
  ingest endpoint — same pattern already used in `brain_router.py`.
- Wire all 29 connector files with emit on `connector.sync_complete` +
  `connector.finding_produced` events.
- Goal: routers 3.9% → 40%+, connectors 0% → 100% in one session.

**Estimated scope:** 1–2 SwarmClaw tasks for Code Builder agent overnight.

---

### P2 — UX P1 completions (9 of 14 shipped; 5 remain)

**Why now:** P1 screens are the per-domain tabbed dashboards that enterprise
evaluators navigate after the P0 hero screens. The 1 deferred item (Incident
Response, blocked on file collision) should be resolved — it is the most
commonly requested screen in security demos.

**What to do:**
- Resolve the Incident Response file collision and ship the consolidated screen.
- Ship the remaining 4 P1 screens from `UX_CONSOLIDATION_PLAN_2026-04-26.md`.
- Run the NO-MOCKS Playwright scan after each ship: confirm zero static pages.
- Do NOT start P2 screens until P1 is fully green.

**Estimated scope:** 1 SwarmClaw frontend task + 1 manual Playwright verification pass.

---

### P3 — LLM Phase 2 distillation pipeline (activate after TrustGraph P1 is green)

**Why now:** The scaffolding is built and dry-run validated (commit `4904309a`).
The Phase 2 pipeline — curator → trainer → student/council router — is waiting
for a richer DPO corpus. Once TrustGraph router wiring increases event volume,
running the curator to filter 703→N high-quality pairs and kicking off a
distillation run becomes the right next step.

**What to do:**
- After TrustGraph P1: re-run the fleet scans to generate 5K+ DPO pairs.
- Run `scripts/llm_training_phase1_skeleton.py` curator stage against the
  expanded corpus.
- Evaluate student model routing threshold (currently 0.85 council consensus).
- Document Phase 2 outcome in `llm_learning_phase2_runlog_YYYY-MM-DD.md`.

**Gate:** Do not start Phase 2 distillation until corpus >= 5,000 high-quality pairs.

---

### P4 — SCIF sponsor outreach (first external action; parallelize with P1/P2)

**Why now:** SCIF Stage 1–3 engineering and sales docs are complete today. The
20-day pilot path is documented. The 36-sponsor target list is ready. This is
the first item that can advance without writing any code.

**What to do:**
- Have a human (not an agent) review `scif/SSP_aldeci_2026-04-26.md` and
  `scif/POAM_aldeci_2026-04-26.md` for accuracy before sending to any ISSO.
- Use `sales/scif/cold_outreach_templates_2026-04-26.md` — Template 1 (ISSO
  direct) for the top 5 Tier 1 targets from the target list.
- Objective: one design-partner commitment from a cleared facility within 30
  days. This unlocks the FedRAMP High ATO path and provides the
  ≥10K remediation corpus needed for Phase 3 full fine-tune.

**Agent involvement:** Zero. SCIF outreach requires a human with a clearance or
cleared-personnel sponsor. Queue a reminder, not a SwarmClaw task.

---

### P5 — Investor close (parallelize; not blocked on engineering)

**Why now:** `investor/INVESTOR_PACK_2026-04-26.md` is the current pack but
was flagged "IN FLIGHT" at handoff. The data room index
(`investor/data_room_index.md`) lists what is still missing.

**What to do:**
- Complete the investor pack: fill any IN-FLIGHT sections.
- Add traction metrics from today's session: 50 commits, 703 DPO pairs,
  SCIF Stage 1 12/12 tests, 83% competitive WIN/MATCH.
- Identify the 2–3 warm investor intros most likely to close in 30 days.
- Prepare a 15-minute demo that hits: Brain Pipeline → evidence bundle →
  SCIF air-gap mode.

**Note:** Do not include pre-revenue claims without the PRE-REVENUE label.
The investor pack template already enforces this.

---

## What to Defer

| Item | Why defer |
|------|-----------|
| P2 UX screens (10 deep-moat items) | P1 completion gates P2. Do not parallelize. |
| GAP-014 (IDE gateway) / GAP-058 (free-tier) | Need product decision, not engineering. Block until CTO decides. |
| Full fine-tune / RLHF (LLM Phase 3+) | Requires ≥10K corpus + H100 hardware. Gate: first SCIF design-partner. |
| Dependabot Critical/High fixes | 2 Critical + 55 High alerts exist. Schedule a dedicated hardening session; do not mix with feature work. |
| Legacy code-quality cleanup (13,100 violations) | Sprint-able but not demo-blocking. Defer to a SwarmClaw overnight batch. |

---

## Session Start Checklist

```
1. git push origin features/intermediate-stage          # P0 — do this first
2. git pull origin features/intermediate-stage          # verify clean state
3. python -m pytest tests/test_phase*.py ... -q         # confirm 716 passing, zero regressions
4. curl -s http://localhost:3456/api/tasks | python3 -m json.tool   # check SwarmClaw queue
5. Read HANDOFF_2026-04-26-evening.md §3 + §4           # resume in-flight items
```

---

## One-Line Decision Log

| Decision | Rationale |
|----------|-----------|
| TrustGraph router wiring > LLM Phase 2 | Phase 2 quality is bounded by signal richness; fix the source first. |
| UX P1 completions > P2 starts | Evaluators navigate P1 screens in demos; incomplete P1 undermines P0 investment. |
| SCIF outreach is human-only | No agent can execute cleared-personnel sponsor engagement. |
| Dependabot deferred to hardening sprint | Two Critical alerts exist but are not exploitable in air-gap mode; document risk and address in isolation. |
