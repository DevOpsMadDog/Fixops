# Next Session Priorities — Inherits HEAD a87aaac6

## Read first (5 min)

1. `docs/SESSION_2026-05-05_TLDR.md` — what just happened (278 commits, 25 QA sweeps)
2. `docs/PR_READINESS_2026-05-05.md` — merge plan + branch tally
3. `docs/HANDOFF_2026-05-05.md` Closing Note v16 — current state snapshot
4. `docs/regression_status_2026-05-05.md` — 25-sweep certification evidence

## Top 5 Priorities (ordered by ROI)

1. **Decide PR strategy for features/intermediate-stage → main** (1h)
   - 278 commits, fast-forward eligible
   - 125 dependabot vulns on main → all close on merge (legacy UI removed at 5f415a1d)
   - See `docs/dependabot_triage_2026-05-05.md` for triage evidence
   - Decision: squash, merge-commit, or keep history? Founder call.

2. **Frontend mock removal — finish the sweep** (4h)
   - Start: `grep -rl "MOCK_\|mockData\|mock_data" suite-ui/aldeci-ui-new/src/pages/ --include='*.tsx' | wc -l`
   - Batch-dispatch `frontend-craftsman` until count = 0
   - Every page must fire at least one `/api/v1/...` call on mount (NO MOCKS rule)
   - ~15 pages cleaned last session; unknown count remains

3. **suite-core OWASP hardening** (4h, highest risk surface)
   - 140K LOC — largest untouched package
   - Priority: `brain_pipeline.py` (subprocess), `scanner_parsers.py` (XML injection), `crypto.py` (key storage)
   - Pattern: 5+ fixes + new `tests/test_suite_core_hardening.py`
   - Dispatch `backend-hardener`

4. **TrustGraph batch-13 completion + batch-14** (2-4h)
   - Currently 547 emit-sites; batch-13 crashed mid-run (only `elastic_security_engine` salvaged)
   - Find remaining unwired engines: `grep -rL "emit_event\|_get_tg_bus" suite-core/core/*_engine.py`
   - Target: 560+ emit-sites

5. **BUG-2 router GET "/" — second batch** (2h)
   - 29 of ~165 routers fixed (commit e5a1acc9); ~136 remain
   - Enumerate: `grep -rL 'methods=\["GET"\]' suite-api/apps/api/*_router.py | wc -l`
   - Dispatch `backend-hardener` for next 29

## What to AVOID

- Re-running `tools/fix_orphaned_test_describes.py` until false-positive fix at `fbfa551e` is real-world validated (synthetic test only)
- Running broad `pytest tests/` without `-m perf` or `-m owasp` filter — 44K+ test import sweep is slow
- Building new UI screens — Phase 3 consolidation is EXHAUSTED; merge existing, fix mocks
- Touching the 4 dead pytest markers already removed at `cfd36eb2`

## Reusable Tools Under tools/

- `purge_dead_lazy_imports.py` — idempotent; already ran (280 dead imports removed at `3eb988a0`)
- `fix_orphaned_test_describes.py` — has `--dry-run` flag (fixed `fbfa551e`); validate before live run
- Agent routing: `tools/agent_routing_advisor.py` for Q-Learning task→agent dispatch

## State at Handoff

| Layer | Count |
|-------|-------|
| Beast Mode tests | 1005 passing, 0 failed (sweep #24, HEAD `2c72e3a0`) |
| TrustGraph emit-sites | 547 |
| Frontend pages | 529 recursive |
| OWASP hardening | 4 of ~6 packages done |
| BUG-2 router index | 29 of ~165 done |
