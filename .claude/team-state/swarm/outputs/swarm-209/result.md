# swarm-209: Fix F841 Unused Variable Warnings in suite-core/

**Date**: 2026-03-02
**Worker**: junior-worker (claude-sonnet-4-6)
**Status**: COMPLETED

## Summary

Fixed all 7 F841 (unused-variable) warnings in suite-core/ without changing any logic.
After fixes, `ruff check suite-core/ --select F841` reports 0 errors.
Regression tests: 127 passed, 0 failed.

## Fixes Applied

### 1. suite-core/automation/remediation.py (line 1041)
- **Variable**: `pathlib_used`
- **Fix**: Removed the assignment `pathlib_used = "pathlib" in source`
- **Reason**: The variable was computed but never referenced anywhere in the function.

### 2. suite-core/connectors/universal_connector.py (line 261)
- **Variable**: `start`
- **Fix**: Renamed to `_start = time.monotonic()` (underscore prefix signals intentionally unused)
- **Reason**: `time.monotonic()` is called but the timing result is never used — likely a stub for future latency tracking. Kept the call to signal intent; prefixed to silence the warning.

### 3. suite-core/core/autofix_engine.py (lines 1018-1019)
- **Variables**: `type_count` and (cascade) `ft`
- **Fix**: Removed both lines: `ft = suggestion.fix_type.value` and `type_count = self._stats["by_type"].get(ft, 0)`
- **Reason**: `type_count` was computed from `ft` but neither was used downstream. The return dict at line 1027 uses `suggestion.fix_type.value` directly (not via `ft`). Removing `type_count` made `ft` also unused, so both were removed.

### 4. suite-core/core/scanner_parsers.py (line 278) — BurpSuiteNormalizer
- **Variable**: `conf_map`
- **Fix**: Removed the dict assignment `conf_map = {"Certain": 0.95, "Firm": 0.85, "Tentative": 0.6}` from inside the loop
- **Reason**: The dict was defined on every loop iteration but never referenced; the confidence values were not used in the `_make_finding()` call.

### 5. suite-core/core/scanner_parsers.py (lines 375-380) — OpenVASNormalizer
- **Variables**: `port_text`, `port_num`
- **Fix**: Removed the entire block:
  ```python
  port_text = result.findtext("port", "0")
  port_num = 0
  try:
      port_num = int(port_text.split("/")[0])
  except (ValueError, IndexError):
      pass
  ```
- **Reason**: `port_num` was computed (parsing `port_text`) but the result was never passed to `_make_finding()` or used elsewhere in the loop body.

### 6. suite-core/core/self_learning.py (line 750)
- **Variable**: `f1`
- **Fix**: Renamed to `_f1 = mpte.get("f1_score", 0)`
- **Reason**: The f1 score was fetched but the conditional logic immediately after only checks false_positives vs false_negatives (not f1). Kept the fetch with underscore prefix to preserve the data access intent.

### 7. suite-core/core/self_learning.py (line 957)
- **Variable**: `accuracy`
- **Fix**: Renamed to `_accuracy = dec_analysis.get("weighted_accuracy", 50) / 100.0`
- **Reason**: The weighted accuracy was computed but the subsequent code only iterates per-source records directly. Prefixed to signal intentional fetch (may be used for future threshold comparisons).

## Verification

```
ruff check suite-core/ --select F841
# → All checks passed!

python -m pytest tests/test_brain_pipeline.py tests/test_autofix_engine_unit.py -q --timeout=15 --no-cov
# → 127 passed in 12.23s
```

## Files Modified

| File | Change |
|------|--------|
| `suite-core/automation/remediation.py` | Removed `pathlib_used` assignment |
| `suite-core/connectors/universal_connector.py` | Renamed `start` → `_start` |
| `suite-core/core/autofix_engine.py` | Removed `ft` and `type_count` assignments |
| `suite-core/core/scanner_parsers.py` | Removed `conf_map` assignment; removed `port_text`/`port_num` block |
| `suite-core/core/self_learning.py` | Renamed `f1` → `_f1`; renamed `accuracy` → `_accuracy` |
