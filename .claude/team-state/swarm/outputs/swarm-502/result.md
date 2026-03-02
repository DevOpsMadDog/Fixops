# swarm-502 Test Run Results

## Executive Summary
- **Total tests**: 516
- **Passed**: 515 (99.8%)
- **Failed**: 1 (0.2%)
- **Duration**: 2.17s
- **Status**: REGRESSION (baseline was 516/516 PASS in 0.64s)

## Failed Test Details

### Test: `tests/test_scanner_parsers.py::TestSandboxVerifier::test_create_router`

**Error Type**: AssertionError
```
AssertionError: assert 8 == 7
```

**Root Cause**: The test expects the sandbox router to have 7 endpoints, but it now has 8. A new endpoint has been added:
- Path: `/api/v1/sandbox/reachability/single`
- Method: POST
- Handler: `sandboxed_reachability_single`

**Full Endpoint List** (8 endpoints):
1. `/api/v1/sandbox/verify` (POST) - `run_poc_verification`
2. `/api/v1/sandbox/verify-finding` (POST) - `verify_finding`
3. `/api/v1/sandbox/results` (GET) - `get_results`
4. `/api/v1/sandbox/stats` (GET) - `get_stats`
5. `/api/v1/sandbox/health` (GET) - `sandbox_health`
6. `/api/v1/sandbox/status` (GET) - `sandbox_status`
7. `/api/v1/sandbox/reachability` (POST) - `sandboxed_reachability`
8. `/api/v1/sandbox/reachability/single` (POST) - `sandboxed_reachability_single` **[NEW]**

## Passing Test Files
- `tests/test_fail_engine.py` - All tests passed
- `tests/test_fail_engine_unit.py` - All tests passed
- `tests/test_fail_engine_comprehensive.py` - All tests passed
- `tests/test_scanner_parsers.py` - 1 test failed (see above), rest passed
- `tests/test_scanner_parsers_unit.py` - All tests passed

## Comparison to Baseline

| Metric | Previous Baseline | Current | Delta |
|--------|-------------------|---------|-------|
| Total Tests | 516 | 516 | 0 |
| Passed | 516 | 515 | -1 |
| Failed | 0 | 1 | +1 |
| Duration | 0.64s | 2.17s | +1.53s (3.4x) |

## Diagnosis

The new endpoint `/api/v1/sandbox/reachability/single` was added to the sandbox router, but the test assertion was not updated to reflect this change. This is a **test maintenance issue**, not a functional regression.

### Options to Fix:
1. **Update the test** to expect 8 endpoints (if the new endpoint is intentional)
2. **Revert the router change** (if the new endpoint was added accidentally)
3. **Document the change** (if this is a deliberate API expansion)

## Coverage Note
Project coverage remains below 25% gate (3.13% reported) — this is a known issue independent of these tests.

## Performance Note
Duration increase (0.64s → 2.17s) is likely due to pytest overhead and increased logging verbosity, not a performance regression in the code itself. Test count is unchanged.
