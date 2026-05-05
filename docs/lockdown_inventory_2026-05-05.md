# Lockdown Test Inventory — 2026-05-05

Verified on branch `features/intermediate-stage`. All 14 files confirmed present via `ls`; test counts via `pytest --collect-only -q`.

## Per-File Table

| # | File | Tests | Protects |
|---|------|------:|----------|
| 1 | `test_owasp_regression_lockdown.py` | 47 | OWASP Top-10 regressions — injection, auth bypass, SSRF, XXE, misconfiguration |
| 2 | `test_engine_router_import_sweep.py` | 1317 | Every engine + router imports cleanly; no silent import-time crashes |
| 3 | `test_no_unsafe_asyncio_run.py` | 1 | Bans `asyncio.run()` inside async context (deadlock guard) |
| 4 | `test_no_unawaited_coroutines_at_import.py` | 10 | Catches unawaited coroutines triggered at module import time |
| 5 | `test_db_indexes.py` | 9 | Critical SQLite indexes present; query-path columns indexed |
| 6 | `test_memory_caps.py` | 5 | Per-engine memory caps enforced; no unbounded growth |
| 7 | `test_health_aggregator.py` | 3 | `/api/v1/health` aggregates sub-system status correctly |
| 8 | `test_prometheus_metrics.py` | 4 | Prometheus endpoint exposes required metric names and types |
| 9 | `test_admin_db_stats.py` | 4 | Admin DB-stats endpoint returns real counts, not stubs |
| 10 | `test_admin_connectors_inventory.py` | 3 | Connector inventory endpoint lists all registered connectors |
| 11 | `test_security_review_fixes.py` | 16 | Verifies STRIDE/DREAD security review fixes from 2026-05-02 |
| 12 | `test_logging_hygiene.py` | 12 | No secrets/PII in log output; structured log format enforced |
| 13 | `test_trustgraph_emit_assertions.py` | 14 | TrustGraph emit-sites fire correct event types and payloads |
| 14 | `test_router_index_routes.py` | 29 | Every router has a reachable GET `/` index route (no 404 on root) |

## Totals

| Metric | Value |
|--------|------:|
| Lockdown files | **14** |
| Total lockdown tests | **1474** |

## Claim vs Reality

CLAUDE.md / HANDOFF stated "11+ lockdown test files." Actual verified count: **14 files / 1474 tests**.

The large test count (1474) is dominated by `test_engine_router_import_sweep.py` (1317 tests — one per engine/router module). Excluding that file: 13 files, 157 focused lockdown tests.
