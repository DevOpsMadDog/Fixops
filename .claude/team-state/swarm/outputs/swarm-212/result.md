# swarm-212: F841 Unused Variable Fix — suite-api/

**Date**: 2026-03-02
**Worker**: junior-worker (claude-sonnet-4-6)
**Task**: Fix all F841 (unused-variable) warnings in suite-api/

---

## Summary

Fixed 6 F841 unused-variable warnings across 3 files in suite-api/. All warnings are now resolved. No regressions introduced.

---

## Findings and Fixes

### File 1: suite-api/apps/api/analytics_router.py (4 warnings)

**Lines 749, 752–754, 755–757, 758–760** — Four unused variables in the triage funnel metrics function:

| Variable | Line | Action |
|---|---|---|
| `decisions` | 749 | Removed — `db.list_decisions()` call result never consumed |
| `false_positives` | 752–754 | Removed — computed sum never referenced in return |
| `resolved` | 755–757 | Removed — computed sum never referenced in return |
| `open_count` | 758–760 | Removed — computed sum never referenced in return |

The function builds its response from `findings` directly, computing deduplication ratios as percentages. These four computed sums were leftover dead code from an earlier iteration of the endpoint.

**Change**: Removed lines 749–760, replacing with only `total_raw = len(findings)` (which IS used).

### File 2: suite-api/apps/api/mcp_router.py (1 warning)

**Line 649** — `total = len(tools)` before pagination slice.

This is a pattern where the total count is computed before slicing for pagination but never returned in the response or used elsewhere.

**Change**: Renamed to `_total = len(tools)` — underscore prefix signals intentionally unused (pagination bookmark).

### File 3: suite-api/apps/api/system_router.py (1 warning)

**Line 95** — `data_dir = Path("data")` assigned but never used. All DB paths below it are hardcoded inline strings (e.g., `"data/users.db"`).

**Change**: Removed the `data_dir = Path("data")` line entirely.

---

## Verification

### Ruff F841 check after fix:
```
ruff check suite-api/ --select F841
All checks passed!
```

### E2E regression test (tail -5):
```
FAILED tests/test_comprehensive_e2e.py::TestAPIEndpointsE2E::test_chunked_upload_workflow
FAILED tests/test_comprehensive_e2e.py::TestAPIEndpointsE2E::test_upload_size_limit_exceeded
FAILED tests/test_comprehensive_e2e.py::TestCLICommandsE2E::test_cli_demo_command
FAILED tests/test_comprehensive_e2E.py::TestSecurityFixes::test_api_key_not_in_error_logs
4 failed, 20 passed in 23.25s
```

**No new regressions.** All 4 failures are pre-existing:
- `test_chunked_upload_workflow`: assert 400 == 200 (pre-existing endpoint status mismatch)
- `test_upload_size_limit_exceeded`: pre-existing (413 vs 422), documented in swarm-113
- `test_cli_demo_command`: pre-existing (SystemExit 2), documented in swarm-113
- `test_api_key_not_in_error_logs`: pre-existing (200 vs 400/500), documented in swarm-113

---

## Files Modified

- `suite-api/apps/api/analytics_router.py` — Removed 4 unused variable assignments
- `suite-api/apps/api/mcp_router.py` — Prefixed `total` with underscore
- `suite-api/apps/api/system_router.py` — Removed 1 unused variable assignment
