# Test Collection Error Triage — 2026-05-05

Sweep #7/#8 flagged 4 legacy test files with collection errors. This document records the investigation, categorization, and action taken.

---

## Files Investigated

### 1. `tests/test_autonomous_cycle.py`

**Collection result**: PASSES — 49 tests collected in ~72s.

**Category**: NOT A COLLECTION ERROR

**Finding**: The file collects cleanly. The slow collection time (72s) is due to coverage instrumentation startup overhead, not a test error. Sweeps #7/#8 likely timed out before collection completed and misclassified this as an error.

**Action**: None required. Tests are healthy.

---

### 2. `tests/test_wave_a_code_intel_router.py`

**Collection result**: PASSES — 20 tests collected in ~71s.

**Category**: NOT A COLLECTION ERROR

**Finding**: Same situation as test_autonomous_cycle.py. Collects cleanly under `--no-cov`. Coverage startup overhead caused false positive in timed sweeps.

**Action**: None required. Tests are healthy.

---

### 3. `tests/test_cspm.py`

**Collection result**: FAILS

**Error**:
```
ImportError: cannot import name 'CISBenchmarkRule' from 'core.cspm_engine'
```

**Category**: DEEPER

**Root cause**: `test_cspm.py` was written against an older API of `cspm_engine.py`. The test imports 20+ names that no longer exist in the current engine:

| Imported by test | Current engine reality |
|---|---|
| `CISBenchmarkRule` | Does not exist — class was removed/renamed |
| `CloudResource` | Does not exist — no such class |
| `ComplianceFramework` | Does not exist |
| `CSPMFinding` | Exists as `CspmFinding` (case mismatch) |
| `DriftEvent` | Does not exist |
| `FindingStatus` | Does not exist |
| `OrgPosture` | Does not exist |
| `RemediationPlaybook` | Does not exist |
| `ResourceType` | Does not exist |
| `ScanResult` | Exists as `CspmScanResult` |
| `Severity` | Does not exist (engine uses `CspmSeverity`) |
| `_CIS_RULES`, `_RULES_BY_ID` | Do not exist (engine has `AWS_RULES`, `AZURE_RULES`, `GCP_RULES`, `ALL_RULES`) |
| `_build_playbook`, `_compliance_score`, `_detect_drift`, `_evaluate_rule`, `_get_applicable_rules`, `_posture_score`, `_score_from_findings` | None of these private functions exist |

**Recommended action**: The test file requires a full rewrite to match the current `cspm_engine.py` API (`CspmFinding`, `CspmScanResult`, `CspmSeverity`, `CSPMEngine`, `CloudProvider`, `get_cspm_engine`). Assign to backend-hardener — estimated 2-3h effort. Do NOT delete: the test intent is valid and covers a critical moat file.

**Source code change required**: No — engine is correct; test is stale.

---

### 4. `tests/real_world_tests/test_phase1_intake.py`

**Collection result**: FAILS (before fix), PASSES after fix

**Error**:
```
ImportError: attempted relative import with no known parent package
tests/real_world_tests/test_phase1_intake.py:12: from .conftest import PERSONAS
```

**Category**: QUICK-FIX (applied)

**Root cause**: `tests/real_world_tests/` had no `__init__.py`, so Python did not treat it as a package. The relative import `from .conftest import PERSONAS` requires package context. `tests/__init__.py` exists but the subdirectory did not.

**Fix applied**: Created `tests/real_world_tests/__init__.py` (1 line comment). Collection now succeeds: 18 tests collected in 0.33s.

**Regression**: `tests/test_phase4_integration.py` — 23/23 passed. No regressions.

---

## Summary Table

| File | Category | Status | Action |
|---|---|---|---|
| `tests/test_autonomous_cycle.py` | NOT AN ERROR | Healthy (49 tests) | None — false positive from coverage timeout |
| `tests/test_wave_a_code_intel_router.py` | NOT AN ERROR | Healthy (20 tests) | None — false positive from coverage timeout |
| `tests/test_cspm.py` | DEEPER | Blocked | Rewrite to match current cspm_engine API — assign to backend-hardener |
| `tests/real_world_tests/test_phase1_intake.py` | QUICK-FIX | FIXED | Added `__init__.py` — now collects 18 tests |

## Files Fixed

- `tests/real_world_tests/__init__.py` — created (1 line)

## Next Session Notes

- `test_cspm.py` rewrite: map old names to new ones using the table above. Key renames: `CSPMFinding`→`CspmFinding`, `ScanResult`→`CspmScanResult`, `Severity`→`CspmSeverity`. Private helper functions (`_build_playbook` etc.) no longer exist as standalone — test behaviour must be exercised through `CSPMEngine` public methods.
- The two "slow collect" files (`test_autonomous_cycle.py`, `test_wave_a_code_intel_router.py`) should be run with `--no-cov` in any sweep that has a tight timeout, or the sweep timeout should be raised to 120s for collection.
