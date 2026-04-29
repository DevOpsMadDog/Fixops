# Audit Methodology — Lessons from the MPTE Miss

**Date:** 2026-04-29
**Trigger:** User caught the depth audit (`docs/validation/depth_audit_2026-04-27.md`) calling MPTE "mostly stubs" when MPTE is actually substantial: 1098-LOC `builtin_scanner.py`, 50+ registered endpoints across `/api/v1/mpte/*`, `/api/v1/mpte-orchestrator/*`, `/api/v1/micro-pentest/*`, real `data/mpte.db`, real Yahoo pen-test report at `data/pentest_report_data.json` (27 KB, 5 detailed findings with reproduction commands).

---

## What the audit got wrong

1. **File-path heuristics over semantic search.** The auditor ran `find suite-attack/attack -name '*.py'` and landed on a tiny subdirectory (`fail_engine.py`) that is a sibling of MPTE, not MPTE itself. Bulk of MPTE lives under `suite-integrations/integrations/builtin_scanner.py` and `suite-api/apps/api/mpte_router.py` + `mpte_orchestrator_router.py` + `micro_pentest_router.py`.

2. **Did not query graphify communities.** The graph at `graphify-out/graph.json` has 1706 communities. Each "claimed feature" should be located in the graph and the WHOLE community walked. The auditor never did this.

3. **Did not enumerate registered endpoints.** Running `python -c "from apps.api.app import create_app; app=create_app(); ..."` reveals 50+ MPTE endpoints. The auditor relied on file inspection alone.

4. **Did not check supporting evidence.** Real DB tables (`data/mpte.db`: pen_test_configs/requests/results), real demo artifacts (`data/pentest_report_data.json` against yahoo.com), real htmlcov reports (`mpte_orchestrator_router_py`, `mpte_advanced_py`, etc.) all signaled real implementation.

5. **Did not cross-reference UI callers.** The UI's `mpteApi` block in `lib/api.ts` references 14 distinct MPTE methods — that volume of UI surface implies real backend, not a stub. Plus the broken UI `verify`/`stats`/`results` paths (which don't exist on backend) would have surfaced the path-mismatch bug earlier.

---

## What this means for the prior audit numbers

The audit's "31% completion (±8%)" used MPTE's "stub" finding to justify the Engine implementation depth score of 35%. Correcting MPTE pulls that dimension up.

- **Engine implementation depth**: 35% → estimated **48-52%** with MPTE corrected.
- **Overall completion**: 31% → estimated **35-40%**.

These corrections are pending a full re-audit using the methodology fix below.

---

## Methodology fix for the next audit

**Required steps for every "is this a stub?" determination:**

1. **Locate the feature in graphify**:
   - `grep -E "<feature_name>" graphify-out/GRAPH_REPORT.md` to find the community.
   - Read the community's full node list from `graphify-out/graph.json`.
   - Walk every file in the community, not just the obvious ones.

2. **Enumerate API surface**:
   - Always run `python -c "from apps.api.app import create_app; ..."` and grep for the feature's path prefix.
   - 5+ registered endpoints under one prefix = NOT a stub. Single 501 endpoint = stub candidate.

3. **Cross-reference UI callers**:
   - `grep -rn "<feature>" suite-ui/aldeci-ui-new/src/lib/api.ts` to count UI-side methods.
   - 5+ UI methods + missing backend = path-bug, not stub.
   - 1 UI method + 50 backend endpoints = under-utilized backend, not a stub.

4. **Check supporting artifacts**:
   - DB: `find data/ -name "<feature>*.db"` — real DB = real persistence layer.
   - Demo data: `grep -rli "<known_target>" data/ docs/ raw/` — e.g. yahoo.com, juice-shop.
   - Coverage: `ls htmlcov/ | grep <feature>` — coverage HTMLs imply tests ran against real production code.
   - Tests: `find tests/ -name "test_<feature>*.py" | wc -l` — 5+ test files = real implementation.

5. **Score honestly**:
   - All four signals (graph + endpoints + UI + DB/demo/coverage/tests) green = NOT a stub. Score 70-85%.
   - 3 of 4 green = partial. Score 50-70%.
   - 0-2 green = legitimate stub. Score 0-30%.

6. **When in doubt, ask the founder for one example use of the feature.** If they can name a real customer/demo/scan, treat it as evidence regardless of file count.

---

## What to re-audit immediately

The depth audit MUST be re-run with the methodology above against these claims (all flagged as suspect after the MPTE miss):

- **MPTE 19-phase** — confirmed wrong. Bump to 70-85% based on builtin_scanner.py + 50 endpoints + Yahoo report + DB + coverage.
- **FAIL chaos** (`suite-attack/attack/fail_engine.py`) — needs the same 4-signal check.
- **Brain Pipeline 12-step** — audit said "real" but only checked file existence. Re-verify with end-to-end run + graphify community walk.
- **Compliance frameworks** (SOC2/ISO27001/PCI-DSS/HIPAA mappings) — audit said "template-level". Re-check for real auto-generation from scan results.
- **CTEM Plus identity** — `docs/CTEM_PLUS_IDENTITY.md` claims 8 native engines. Audit didn't verify each one.
- **Threat hunting / threat actors** — audit didn't deep-check.

---

## Action item

Spawn a researcher (when org usage limit resets) using this methodology to produce `docs/validation/depth_audit_v2_2026-04-29.md` with corrected per-dimension scores and a revised overall completion %.
