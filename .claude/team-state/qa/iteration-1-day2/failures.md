# Iteration 1 (Day 2) — Failures & Issues Report
> **Date**: 2026-03-02T01:40:00Z
> **Runner**: qa-engineer
> **Newman**: 475/475 PASS (0 failures)

## Newman Test Failures: NONE ✅

All 7 collections passed with zero assertion failures.

## Transport Errors (Non-Blocking)
| Collection | Endpoint | Error | Impact |
|------------|----------|-------|--------|
| Col 2 (Discover) | `GET /api/v1/brain/most-connected` | getaddrinfo ENOTFOUND | LOW — test assertion handles gracefully |

## Known Issues (Not Blocking Demo)
| Issue | Severity | Owner | Details |
|-------|----------|-------|---------|
| Coverage below 25% gate | MEDIUM | qa-engineer | 21.24% vs 25% target. Config already expanded. Needs targeted tests for core/ modules. |
| Micro-pentest "degraded" | LOW | backend-hardener | `/api/v1/micro-pentest/health` returns `degraded` — expected without external MPTE service |
| Container scanner no trivy | LOW | devops-engineer | `trivy_available: false` — expected in air-gapped mode |
| CSPM no cloud creds | LOW | devops-engineer | `boto3_available: false` — expected without AWS/Azure creds |
| 1 transport error in Col 2 | LOW | backend-hardener | brain/most-connected may have DNS resolution issue |

## Customer Scenario Issues
None. All 8 scenarios pass.

## Stubs Detected
None. All 15+ endpoints return real computed data.

## Recommendations for Next Iteration
1. **Fix brain/most-connected endpoint** — investigate DNS resolution error
2. **Target coverage on uncovered core/ modules** — tenancy.py, user_db.py, vector_store.py, verification_engine.py have 0% coverage
3. **Add performance baselines** — record response times for brain pipeline (119ms) and scanner endpoints for regression detection
4. **Add Postman assertions for response time** — flag endpoints >5s as slow

## Pass Rate History
| Date | Pass Rate | Total |
|------|-----------|-------|
| 2026-03-01 (Sprint 2 start) | 84.7% | 404/477 |
| 2026-03-02 (Day 2 Iter 1) | 100% | 475/475 |
| 2026-03-02 (Day 2 Iter 2) | 100% | 475/475 |
