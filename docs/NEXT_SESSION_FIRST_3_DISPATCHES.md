# Next Session — First 3 Dispatches
**Prepared**: 2026-04-27 (end-of-session handoff)
**Branch**: `features/intermediate-stage`
**Board state entering session**: 2942 done / 72 todo / 9 in_progress
**v0.1.0-alpha tagged. ~150 commits today.**

---

## Step 0 — Verify overnight didn't break anything (run FIRST, ~2 min)

```bash
# 1. Pull latest
git pull origin features/intermediate-stage

# 2. Beast Mode test suite (must stay green — 716 passing baseline)
python -m pytest tests/test_phase2_connectors.py tests/test_phase3_llm_council.py \
  tests/test_phase4_integration.py tests/test_phase5_enterprise.py \
  tests/test_phase6_streaming.py tests/test_phase7_analytics.py \
  tests/test_phase8_mcp.py tests/test_phase9_playbooks.py \
  tests/test_phase10_e2e.py tests/test_connector_framework.py \
  tests/test_trustgraph.py tests/test_pipeline_api.py \
  tests/test_persona_workflows.py \
  -x --tb=short --timeout=10 -q -o "addopts="

# 3. DPO pair count (baseline entering this session: 5196 council_verdicts)
sqlite3 data/learning_signals.db \
  "SELECT 'council_verdicts', COUNT(*) FROM council_verdicts UNION ALL SELECT 'feedback_pairs', COUNT(*) FROM feedback_pairs;"

# 4. Board state sanity check (expect done=2942, todo=72)
sqlite3 data/multica.db \
  "SELECT status, COUNT(*) FROM issue GROUP BY status ORDER BY COUNT(*) DESC;" 2>/dev/null \
  || echo "SKIP — multica.db path may differ, check data/ for correct name"

# 5. Investor bundle still present
ls -lah dist/aldeci_data_room_2026-04-26.tar.gz
```

Expected: tests green, council_verdicts >= 5196, bundle present. If tests fail, fix before dispatching agents.

---

## Dispatch 1 — LLM Phase 1 DPO Pair Growth (council_verdicts 5196 → 7000+)

**Model tier**: Sonnet (orchestrator) + Junior swarm (batch workers)
**Expected runtime**: 45–90 min
**ROI**: Highest — Phase 2 distillation gate is 10K pairs. Every run here is irreversible progress toward a proprietary fine-tuned model that competitors cannot replicate.

**Current state**: 5196 `council_verdicts` in `data/learning_signals.db`. The overnight cron (0 2 * * *) may not have fired. Interim 5K target is already hit. Next milestone: 10K for Phase 2 GA distillation threshold. A single manual run yields ~1000–1500 new pairs across 15 tenants.

**Success criteria**:
- `SELECT COUNT(*) FROM council_verdicts` increases by >= 800 from baseline
- No test regressions after run
- New log file created at `data/cron/nightly_<today>.log` with `OK` header line

---

### PASTE THIS PROMPT VERBATIM:

```
You are the Data Scientist agent for ALDECI.

MISSION: Grow the LLM Phase 1 DPO council_verdicts dataset from its current
baseline of 5196 toward the 10K Phase 2 GA threshold.

CONTEXT:
- The nightly cron script is at scripts/nightly_fleet_scan_cron.sh
- It runs /api/v1/findings/batch across all 15 enrolled tenants
- Each tenant yields ~67 findings; each finding gets a council verdict = 1 DPO pair
- 15 tenants × ~67 findings = ~1005 new pairs per run
- The baseline entering this session is 5196 council_verdicts

STEPS:
1. Check if last night's cron ran successfully:
   head -1 data/cron/nightly_$(date +%F).log 2>/dev/null || echo "NO_LOG_YET"

2. If no log or log shows FAILED, run the cron manually:
   bash scripts/nightly_fleet_scan_cron.sh 2>&1 | tee /tmp/dpo_run_$(date +%s).log

3. While it runs, verify tenant enrollment:
   sqlite3 data/learning_signals.db \
     "SELECT COUNT(DISTINCT tenant_id) FROM council_verdicts;"
   (expect 15 tenants)

4. After completion, verify pair growth:
   sqlite3 data/learning_signals.db \
     "SELECT COUNT(*) FROM council_verdicts;"
   (expect >= 6000)

5. If count did not grow by >= 800, investigate:
   - Check if API server is running: curl -s http://localhost:8000/health
   - If server is down, start it: uvicorn suite_api.main:app --port 8000 &
   - Re-run step 2 with server up

6. If growth is confirmed, also check feedback_pairs for any UI-sourced signal:
   sqlite3 data/learning_signals.db \
     "SELECT COUNT(*) FROM feedback_pairs WHERE created_at > datetime('now', '-1 day');"

7. Commit the updated DB state:
   git add data/learning_signals.db
   git commit -m "beast-mode(dpo): council_verdicts grown to $(sqlite3 data/learning_signals.db 'SELECT COUNT(*) FROM council_verdicts;') pairs

   Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"

DONE SIGNAL: council_verdicts COUNT >= baseline + 800, commit pushed to local branch.
Do NOT push to remote — CTO reviews first.
```

---

## Dispatch 2 — Execute 23 Remaining 75-89% US-Parents (Real Implementation)

**Model tier**: Sonnet (orchestrator) + Junior swarm (5–7 parallel implementation agents)
**Expected runtime**: 3–6 hours (parallel across parents)
**ROI**: Second highest — closes the board from 72 todo to ~5 todo. These are the last substantive feature gaps before v0.2.0. Each parent has 1–2 genuinely missing children.

**Current state**: Per `docs/multica_final_clearance_2026-04-26.md`, 23 US-parents sit at 75–89% completion. The 90% cascade already ran and closed everything it could. These 23 need real code, not cascades.

**Success criteria**:
- At least 15 of 23 parents advance to >= 90% (triggering another cascade pass)
- Zero Beast Mode test regressions
- Each implementation commit references the US-parent ID

---

### PASTE THIS PROMPT VERBATIM:

```
You are the Backend Hardener + Swarm Controller acting jointly for ALDECI.

MISSION: Implement the missing children for the 23 remaining US-parents that sit
at 75–89% completion on the Multica board. These need real code — not closures,
not cascades, not stubs.

CONTEXT:
- Final clearance doc: docs/multica_final_clearance_2026-04-26.md
- These 23 parents have 1–2 genuinely incomplete child tasks each (11–25% remaining)
- The 90% cascade already ran; only real implementation will move these
- Branch: features/intermediate-stage

STEPS:

1. Pull the list of 23 remaining US-parents with their completion rates:
   sqlite3 data/multica.db "
     SELECT i.title, i.status,
       ROUND(100.0 * SUM(CASE WHEN c.status='done' THEN 1 ELSE 0 END) / COUNT(c.id), 1) AS pct,
       SUM(CASE WHEN c.status='todo' THEN 1 ELSE 0 END) AS todo_kids
     FROM issue i
     JOIN issue c ON c.parent_id = i.id
     WHERE i.title LIKE 'US-%' AND i.status = 'todo'
     GROUP BY i.id
     HAVING pct BETWEEN 75 AND 89
     ORDER BY pct DESC;
   " 2>/dev/null || echo "ADJUST_QUERY — check schema with .schema issue"

2. Sort by pct DESC (highest first = least work remaining). Take top 7 parents.

3. For each of the top 7, identify their todo children:
   sqlite3 data/multica.db "
     SELECT c.id, c.title, c.status, c.estimate_hours
     FROM issue c
     JOIN issue p ON c.parent_id = p.id
     WHERE p.title = '<US_PARENT_TITLE>' AND c.status = 'todo';
   "

4. Dispatch parallel implementation sub-agents — one per US-parent (7 in parallel):
   Each sub-agent receives:
   - The US-parent title and description
   - The specific todo child task title(s)
   - Instruction to find the relevant engine file in suite-core/core/
     (use: grep -r "US-XXXX\|<keyword>" suite-core/core/ --include="*.py" -l)
   - Instruction to implement the missing feature in the existing engine file
     (EXTEND, do not create new files unless truly necessary)
   - Instruction to write/update the corresponding test in tests/
   - Commit format: beast-mode(feature): implement <child-task-title> [US-XXXX]

5. After all 7 complete, run Beast Mode tests:
   python -m pytest tests/test_phase*.py tests/test_connector_framework.py \
     tests/test_trustgraph.py tests/test_pipeline_api.py \
     tests/test_persona_workflows.py -x --tb=short --timeout=10 -q -o "addopts="

6. If green, update child task status to done in Multica:
   sqlite3 data/multica.db "UPDATE issue SET status='done' WHERE title='<child-title>';"

7. Re-run the 90% cascade to close any newly-eligible parents:
   python scripts/multica_cascade_close.py --threshold 90 2>/dev/null \
     || echo "CASCADE_SCRIPT_MISSING — close parents manually via sqlite3"

8. Commit final board state:
   git add data/multica.db
   git commit -m "beast-mode(board): 23 US-parents implementation pass — N parents closed

   Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"

DONE SIGNAL: Beast Mode tests green, at least 15 of 23 parents advanced to >=90%,
board todo count reduced from 72 toward target of <=20.
Do NOT push to remote.
```

---

## Dispatch 3 — Federal Cold-Outreach EOD Send (CISA, DIU, SOCOM + Tracking Setup)

**Model tier**: Sonnet (drafting/personalizing) — LinkedIn DMs require USER ACTION (not agent)
**Expected runtime**: 20–30 min (agent drafts + sends emails; user handles LinkedIn)
**ROI**: Third highest — Friday EOD email lands in Monday inbox first-read slot. CISA JCDC, DIU Cyber Portfolio, and SOCOM SOFWERX are the three highest-probability federal design-partner leads. One yes = case study + credibility for Series A.

**Current state**: Templates ready at `docs/sales/scif/cold_outreach_templates_2026-04-26.md`.
Response tracker needs to be created at `docs/sales/scif/outreach_responses_2026-04-26.md`.
LinkedIn DMs to NGA + NRO require user action — flagged below.

**Success criteria**:
- Response tracker file created with empty table
- Three cold email drafts produced (CISA JCDC, DIU Cyber, SOCOM SOFWERX), personalized per template rules
- Drafts saved to `docs/sales/scif/outreach_drafts_2026-04-27.md` for user review before send
- NGA + NRO LinkedIn DM text produced and flagged for USER to paste manually

---

### PASTE THIS PROMPT VERBATIM:

```
You are the Sales Engineer agent for ALDECI.

MISSION: Prepare the federal cold-outreach EOD send package. Friday EOD emails
land in Monday morning first-read. This is a time-sensitive send window.

CONTEXT:
- Templates: docs/sales/scif/cold_outreach_templates_2026-04-26.md (Template 2 = federal email)
- Target list: docs/sales/scif/target_list_2026-04-26.md
- Send rules: 150-word cap, one specific personalization reference per email,
  single ask = 30-min discovery call, no attachments on first touch
- LinkedIn DMs (NGA, NRO): Template 1 from the same doc — USER must send manually

STEPS:

1. Read docs/sales/scif/target_list_2026-04-26.md to get the named contacts for:
   - CISA JCDC (Cyber and Infrastructure partner program)
   - DIU Cyber Portfolio (Defense Innovation Unit)
   - SOCOM SOFWERX (Special Operations Command tech accelerator)
   - NGA (National Geospatial-Intelligence Agency) — LinkedIn only
   - NRO (National Reconnaissance Office) — LinkedIn only

2. For each of the three email targets, draft a personalized cold email using
   Template 2 (Cold Email v1 — Federal Sponsor, 150-word cap):
   - Fill [First name] with the real contact name from target_list
   - Fill [Specific reference] with a real, verifiable public reference:
     * CISA JCDC: reference CISA's AI Roadmap CTEM line item (published Feb 2025)
     * DIU: reference DIU Cyber Portfolio CSO topic on offline vulnerability mgmt (Mar 2026)
     * SOFWERX: reference SOCOM's public SOFWERX open topic for cyber tools (2025 cycle)
   - Keep subject line exactly: "20-day SCIF pilot — air-gap CTEM with FIPS 140-3 + ML-DSA evidence signing"
   - Sender line: "— Shiva | DevOpsAI / ALDECI"
   - Replace all [bracketed placeholders] — no template artifacts in final draft

3. For NGA and NRO, draft LinkedIn DM text using Template 1 (200-word cap).
   These are for USER to paste manually — flag clearly: "### USER ACTION REQUIRED"

4. Create the response tracker:
   Create docs/sales/scif/outreach_responses_2026-04-26.md with this exact content:

   # SCIF Cold Outreach — Response Tracker
   **Campaign start**: 2026-04-28 (Monday delivery)
   **Send method**: Email (CISA, DIU, SOFWERX) + LinkedIn DM (NGA, NRO — user-sent)
   **Templates used**: Template 1 (LinkedIn), Template 2 (Cold Email v1)
   **Follow-up cadence**: Day +4 nudge, Day +11 final. Max 3 touches.

   | Target | Contact | Channel | Sent Date | Status | Notes |
   |--------|---------|---------|-----------|--------|-------|
   | CISA JCDC | TBD | Email | | pending | |
   | DIU Cyber Portfolio | TBD | Email | | pending | |
   | SOCOM SOFWERX | TBD | Email | | pending | |
   | NGA | TBD | LinkedIn DM | | user-action | |
   | NRO | TBD | LinkedIn DM | | user-action | |

5. Save all three email drafts + two LinkedIn DM drafts to:
   docs/sales/scif/outreach_drafts_2026-04-27.md
   Format: one H2 section per target, email body verbatim, word count noted.

6. Commit:
   git add docs/sales/scif/outreach_responses_2026-04-26.md \
           docs/sales/scif/outreach_drafts_2026-04-27.md
   git commit -m "beast-mode(sales): federal cold-outreach drafts + response tracker

   Targets: CISA JCDC, DIU Cyber, SOCOM SOFWERX (email) + NGA, NRO (LinkedIn — user action)
   Send window: Friday EOD → Monday AM first-read

   Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"

DONE SIGNAL: outreach_drafts_2026-04-27.md exists with 5 complete drafts (3 email + 2 LinkedIn),
response tracker created, USER ACTION items clearly flagged.
Do NOT email directly — drafts are for user review first.
Do NOT push to remote.
```

---

## Priority Order Summary

| # | Dispatch | Model | Runtime | Expected Delta |
|---|----------|-------|---------|----------------|
| 1 | DPO pair growth (cron run) | Sonnet + juniors | 45–90 min | +800–1500 council_verdicts (5196 → 6000+) |
| 2 | 23 US-parent implementation | Sonnet + 7 juniors | 3–6 hrs | 72 → ~20 todo; 15+ parents closed |
| 3 | Federal cold-outreach | Sonnet | 20–30 min | 5 drafts ready; tracker live |

Run 1 and 3 in parallel (independent). Run 2 after tests confirmed green from Step 0.

---

## Key Numbers to Know Entering Session

| Metric | Value |
|--------|-------|
| Board: done | 2942 |
| Board: todo | 72 |
| Board: in_progress | 9 |
| council_verdicts (DPO pairs) | 5196 |
| feedback_pairs | 5196 |
| Phase 2 distillation gate | 10,000 council_verdicts |
| Remaining to Phase 2 gate | ~4,804 pairs |
| Beast Mode tests baseline | 716 passing (last verified 5f17b5e6) |
| v0.1.0-alpha tag | present |
| Investor bundle | dist/aldeci_data_room_2026-04-26.tar.gz |
