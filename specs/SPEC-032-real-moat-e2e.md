# SPEC-032 — Real-Moat E2E (the $100K value, end-to-end)

- **Status**: IMPLEMENTED (CI-safe gate + nightly live gate, 2026-06-18)
- **Owner family**: Moat / Intelligence / Customer-Readiness
- **Engines**: `core/scanner_parsers.py` (61 normalizers), `core/llm_council.py` (CouncilFactory /
  LLMCouncilEngine), `core/council_pipeline_adapter.py`, `core/brain_pipeline.py`, TrustGraph
- **Tests**: `tests/test_real_moat_e2e.py` (CI-safe), `tests/test_real_moat_live.py` (`-m live`, nightly)
- **Depends on**: SPEC-028/029 (NO-MOCKS / ingest-first), feedback_smoke_not_the_goal
- **Last updated**: 2026-06-18

## 1. Intent (the why)
The Beast smoke proves wiring; it does NOT prove the product's value. A SCIF buyer pays for the
**moat**: ingest existing scanner output → real correlation/dedup → a real multi-LLM council verdict.
This spec gates that end-to-end, split so CI stays fast/free/air-gappable while the paid path is still
proven nightly.

## 2. Scope — two halves
1. **CI-safe** (`test_real_moat_e2e.py`, blocking on PR→main): a REAL scanner file
   (`tests/fixtures/real_world/scan.sarif`) ingests via the real public API
   `parse_scanner_output()` into multiple real findings; and the council is **real-or-honestly-
   unconfigured** — `CouncilFactory.create_default_council()` builds a ≥2-member non-deterministic
   council when a key exists, else raises `CouncilNotConfiguredError` (skip). It must NEVER return an
   all-`Deterministic*` placebo council pretending to be real. No paid call.
2. **Live** (`test_real_moat_live.py`, `-m live`, nightly workflow): builds the real OpenRouter
   council and `convene()`s a real finding, asserting `verdict.cost_usd > 0` and ≥2 distinct member
   reasonings + non-empty chairman synthesis. Costs money + needs network — not on PRs, not air-gapped.

## 3. Contracts
```
real scanner file → parse_scanner_output() → ≥1 real findings (title/rule + severity)
council: keys present → real ≥2-member council (no Deterministic placebos)
         no keys      → CouncilNotConfiguredError (NO fabricated verdict)
live:    convene() → cost_usd > 0 + ≥2 distinct member reasonings
```

## 4. Functional requirements
- **REQ-032-01**: `parse_scanner_output(scan.sarif bytes)` returns ≥2 findings with real fields.
- **REQ-032-02**: the default council never silently fabricates (real, or honest `CouncilNotConfiguredError`).
- **REQ-032-03** (live): a convened verdict reports `cost_usd > 0` (real paid inference) + distinct reasoning.

## 5. Non-functional
- CI-safe half: no network, no paid call, runs in the standard PR gate (<60s).
- Live half: nightly cron + `workflow_dispatch`; fails loudly if `OPENROUTER_API_KEY` secret missing.

## 6. Acceptance criteria
- **AC-032-01** (verified 2026-06-18): `test_real_moat_e2e.py` → 3 passed / 1 (live) skipped locally;
  ingest yields ≥2 findings; council built real (not all-deterministic).
- **AC-032-02**: CI-safe gate wired into `regression-gates.yml` (owasp-lockdown), blocking on PR→main.
- **AC-032-03**: live gate wired into `.github/workflows/real-moat-live-nightly.yml` (`-m live`).
- **AC-032-04**: registered in `specs/INDEX.md`; `live` marker registered in `pyproject.toml`.

## 7. Debate log
| Date | Mode | Verdict |
|------|------|---------|
| 2026-06-18 | Founder strategic redirect ("smoke can be irrelevant to the goal") | Built the real-moat E2E both ways: CI-safe deterministic gate (proves ingest→findings + no fabricated council, every PR) + nightly live gate (proves cost>0 real inference). Smoke stays a tripwire; THIS is the customer-value gate. |
