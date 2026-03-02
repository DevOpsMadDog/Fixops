# Test Run Report: V3 Brain Pipeline + AutoFix (swarm-501)

**Date**: 2026-03-02
**Task**: Run tests/test_brain_pipeline.py, test_brain_pipeline_deep.py, test_autofix_engine.py, test_autofix_engine_unit.py
**Baseline**: 377/377 PASS in 13.11s
**Previous baseline was outdated** - actual test count is 534, not 377

## Summary

| Metric | Value |
|--------|-------|
| **Total Tests** | 534 |
| **Passed** | 533 |
| **Failed** | 1 |
| **Skipped** | 0 |
| **Duration** | 28.44s |
| **Pass Rate** | 99.81% |

## Test Files Executed

- `tests/test_brain_pipeline.py` - V3 pipeline model tests
- `tests/test_brain_pipeline_deep.py` - V3 pipeline integration/deep tests
- `tests/test_autofix_engine.py` - AutoFix engine integration tests
- `tests/test_autofix_engine_unit.py` - AutoFix engine unit tests

## Failed Test Details

### 1. test_block_autofix_exception_sets_skipped

**File**: `tests/test_brain_pipeline_deep.py::TestStepRunPlaybooksMocked::test_block_autofix_exception_sets_skipped`

**Error**:
```
KeyError: 'autofix'
```

**Root Cause Analysis**:

The test at line 1491-1509 sets up a scenario where:
1. A finding has `policy_action="block"` and `cve_id="CVE-2024-001"`
2. The AutoFixEngine import is mocked to raise `RuntimeError("LLM unavail")`
3. The test calls `p._step_run_playbooks(ctx, inp)`
4. The test expects `ctx["playbook_results"][0]["autofix"]["status"]` to be `"skipped"`

**What Actually Happens**:

In `suite-core/core/brain_pipeline.py` lines 1460-1467:
```python
autofix_engine = None
block_findings = [f for f in actionable if f.get("policy_action") == "block" and f.get("cve_id")]
if block_findings:
    try:
        from core.autofix_engine import AutoFixEngine
        autofix_engine = AutoFixEngine()
    except Exception:
        pass  # autofix_engine remains None
```

Then at line 1480-1491:
```python
if action == "block" and f.get("cve_id") and autofix_engine is not None:
    try:
        # ... generate fix
        pb["autofix"] = {"status": "generated", "fix_id": fix.get("fix_id")}
    except Exception:
        pb["autofix"] = {"status": "skipped"}
```

**The Problem**: The `pb["autofix"]` field is only created when `autofix_engine is not None`. When the import fails, `autofix_engine` stays `None`, so the entire condition at line 1480 fails and the autofix field is never added to the playbook result. The test then fails trying to access a non-existent key.

## Recommendation

This is a **code-logic mismatch**. Two options:

**Option A (Recommended)**: Modify `_step_run_playbooks` to always track autofix attempts:
```python
if action == "block" and f.get("cve_id"):
    if autofix_engine is not None:
        try:
            fix = autofix_engine.generate_fix(...)
            pb["autofix"] = {"status": "generated", "fix_id": fix.get("fix_id")}
        except Exception:
            pb["autofix"] = {"status": "skipped"}
    else:
        pb["autofix"] = {"status": "skipped"}  # Track engine initialization failure
```

**Option B**: Change the test to match current behavior (don't expect autofix field when engine fails to init). This seems less user-friendly as it loses visibility into why autofix wasn't attempted.

**Option A is recommended** because it provides better observability: users/logs can see that autofix was attempted but skipped due to initialization failure, rather than silently omitting the field.

## Performance Notes

- **Slowest test**: `test_large_findings_batch` (8.42s)
- **Second slowest**: `test_generate_evidence_with_high_risk_shows_needs_improvement` (3.07s)
- Most tests complete in <1s, which is healthy

## Coverage Impact

Project-wide coverage remains at ~24% (below 25% gate), but individual test file pass rate is excellent (99.81%).

## Status

- **NEEDS_SENIOR_REVIEW**: YES - Code change required to fix logic mismatch
- **Confidence**: 92% - Clear root cause identified, fix path obvious
- **Severity**: Low - Only 1 test fails, affects observability not functionality
