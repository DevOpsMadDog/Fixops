# Sweep #10 Broken-Collectors Triage — 2026-05-05

## test_reachability_perf.py — NOW-FIXED (false alarm in sweep #10)

**Verdict**: NOT broken. Sweep #10 reported a false alarm.

Commit `dbcc1a20` fix is intact: `security_hardening.py` opens with a properly
closed triple-quoted docstring; `from __future__ import annotations` is at top.

- Isolated collect (no coverage): 12/12 tests collected. Clean.
- Isolated collect (with `--cov=suite-core`): 12/12 tests collected. Clean.

Root cause of sweep #10 false positive: sweep #10 likely ran the file as part of
a multi-file collection where `test_cspm.py` was included in the same run. A
hard `ImportError` in `test_cspm.py` causes pytest to abort collection mid-run,
making every subsequent file in that batch appear broken. `test_reachability_perf`
is alphabetically after `test_cspm`, so it gets swallowed by the abort.

## test_cspm.py — ACTUAL BROKEN

**Verdict**: ACTUAL BROKEN — import error, unrelated to dbcc1a20.

`tests/test_cspm.py:32` does `from core.cspm_engine import CISBenchmarkRule` but
`CISBenchmarkRule` does not exist in `suite-core/core/cspm_engine.py`. This is a
stale test referencing a renamed or removed class. Fix: add `CISBenchmarkRule` to
`cspm_engine.py` or update the import in the test. **Do not fix here — report only.**

## test_autonomous_cycle.py — NOW-FIXED

**Verdict**: Collects cleanly (at least 1 test found). No error.

## test_wave_a_code_intel_router.py — NOW-FIXED

**Verdict**: 20 tests collected cleanly (with coverage). No error.

## Summary

| File | Status | Root Cause |
|---|---|---|
| test_reachability_perf.py | NOW-FIXED (false alarm) | Poisoned by test_cspm abort in multi-file run |
| test_cspm.py | ACTUAL BROKEN | `CISBenchmarkRule` missing from `cspm_engine.py` |
| test_autonomous_cycle.py | NOW-FIXED | Collects cleanly |
| test_wave_a_code_intel_router.py | NOW-FIXED | 20 tests collected cleanly |

**Action required**: fix `test_cspm.py` import (backend-hardener task).
