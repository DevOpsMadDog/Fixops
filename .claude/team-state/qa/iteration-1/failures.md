# Iteration 1 — Failure Report (Sprint 2, 2026-03-02)

## Summary
- **Verdict**: ✅ PASS
- **Assertions**: 475/475 (100.0%)
- **Failed**: 0
- **Transport Errors**: 1 (non-blocking, Collection 2)

## Failures
None. All 7 collections passed with zero assertion failures.

## Transport Errors (Non-Blocking)
| Collection | Error | Impact |
|-----------|-------|--------|
| ALdeci-2-Discover | 1 transport error | Non-blocking — all assertions still passed |

## Stubs Detected
None. All endpoints return real computed data.

## Regressions
None. 475/475 maintained from previous run (was 411/411 before collection expansion).

## Recommendations
- Monitor Collection 2 transport error for flakiness
- Continue maintaining 100% pass rate as backend changes are made
- All 4 MOATs verified: V3 (Brain/AutoFix), V5 (MPTE), V7 (MCP/Scanners), V10 (Compliance/Evidence)
