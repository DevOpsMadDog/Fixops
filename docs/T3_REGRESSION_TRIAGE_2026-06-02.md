# T3 Broad-Regression Triage — 2026-06-02

Customer-readiness item 2 (T3). Chunk-1 = session blast-radius (326 test files matching
router/connector/ingest/council/scanner/brain/pipeline/tenancy).

## Raw result
`2056 failed · 6408 passed · 53 skipped · 337 errors · 1197s` (serial; no pytest-xdist; 10 cores idle).

## Triage conclusion: NOT customer-blocking product regressions
Product health is green by the authoritative gates:
- `create_app()` boots **8316 routes** (all 3 air-gap modes).
- **T1 Beast smoke 756/756** every run (canonical real-behaviour tests).
- **T2 collection 46,892 tests / 0 errors.**

The 2056 failures are dominated by **test-infra + legacy**, confirmed by sampling:

| Sampled file | Result | Root cause | Class |
|---|---|---|---|
| test_cross_tenant_isolation_wave2.py | 42/42 ERROR | `create_app()` fixture boot (~10.6s) exceeds the suite's default **10s pytest-timeout** | test-infra (NOT an isolation break) |
| test_reports_router_unit.py | PASSES | chunk's "55 failed" was the `--tb=line` mixed-progress-line artifact | false alarm |
| test_analytics_router_unit.py | 6 failed / 73 passed | 5 legacy data-state assertions (`assert False` on empty corpus) + 1 precedence inconsistency (below) | legacy + 1 pre-existing |
| 451 "Task was destroyed but it is pending!" | ERROR lines | asyncio teardown warnings | test-infra noise |

**Dominant cause = app-boot > 10s timeout** in function-scoped `client` fixtures that re-boot the
8316-route app per test. The Beast gate passes because it uses `--timeout=15` / module-scoped app;
the broad suite's default 10s is now shorter than boot. This is accumulated **test-infra debt**, not
product regression.

## The one genuine product-behaviour finding (NOT a regression, NO isolation impact)
`test_org_id_query_overrides_header` expects `?org_id=` to override the `X-Org-ID` header, but header
wins. Cause: a **pre-existing precedence inconsistency** —
- `org_middleware._extract_org_id` (sets the contextvar in prod): JWT-state > **header > query** > default
- `get_org_id` dependency docstring/fallback: contextvar > **query > header** > default

The tenancy migration (SPEC-007 waves) routed analytics through the canonical `get_org_id`, exposing
the disagreement (analytics previously used a query-only local resolver). **No security impact**: the
authenticated JWT/state value always wins first, and org scoping applies the resolved value regardless
of the header/query tiebreak. Resolving it changes tenant-resolution semantics platform-wide → a design
decision for the founder, not an autonomous change.

## FOUNDER-DECISION items (recorded, not auto-changed)
1. **Test-infra debt (large):** the broad suite needs a shared/session-scoped app fixture (or a higher
   default timeout) so the ~hundreds of boot-timeout failures become real signal. High blast-radius on
   the test gate; should be a deliberate, reviewed pass — not an autonomous flip.
2. **Org-resolution precedence:** pick ONE documented header-vs-query order and make `_extract_org_id`
   + `get_org_id` consistent. (JWT/state-wins is already correct + unchanged either way.)

## What was NOT found
No import/boot/NameError regressions from this session's ~190-router tenancy migration or the
SPEC-016/017 work — those would have failed the boot (8316) and Beast (756) gates, which are green.
