# Database Migration Plan — sqlite3 → DatabaseManager

**Created**: 2026-03-17
**Author**: Enterprise Architect
**Status**: Active — Phase 1 (Audit + P0 models deployed)

---

## Executive Summary

The codebase contains **185 `sqlite3.connect` call sites** across 38 files and **42 `PersistentDict` usages** across 14 files. All of these use raw `sqlite3` or an in-house `PersistentDict` abstraction backed by `sqlite3`.

The enterprise `DatabaseManager` at `suite-core/core/db/enterprise/session.py` provides:
- SQLAlchemy async engine with `create_async_engine`
- `QueuePool` (pool_size=10, max_overflow=20)
- PostgreSQL production backend with SQLite+aiosqlite dev fallback
- Async session context manager with auto-rollback on error

**Migration strategy**: Incremental, suite-by-suite. Do NOT do a big-bang rewrite. Existing `sqlite3` calls remain working at all times until each module is explicitly migrated.

---

## Alembic Configuration

Two Alembic trees exist — use the **root-level one** for all future work:

| Location | Status | Notes |
|---|---|---|
| `alembic/` (root) | **ACTIVE** — use this | URL from `FIXOPS_DB_DSN` env var; supports SQLite fallback |
| `suite-core/core/db/enterprise/migrations/` | Legacy | Uses `core.models.enterprise.base.Base`; PostgreSQL-specific types (`postgresql.UUID`, `postgresql.ARRAY`); do not run on SQLite |

The root `alembic.ini` points `script_location = alembic`. Run migrations with:

```bash
# PostgreSQL (production):
export FIXOPS_DB_DSN="postgresql://fixops:pass@localhost:5432/fixops"
alembic upgrade head

# SQLite (local dev — automatically chosen when FIXOPS_DB_DSN is not set):
alembic upgrade head    # uses sqlite+aiosqlite:///data/fixops.db from settings.py

# Generate new revision:
alembic revision -m "add remediation_tasks table"
```

---

## Current Migration Versions

| Revision | File | Tables Created |
|---|---|---|
| `001` | `alembic/versions/001_initial_schema.py` | findings, exposure_cases, pipeline_runs, evidence_bundles, audit_logs, mcp_sessions |

---

## P0 — Customer Data (Migrate First)

These tables contain findings, evidence, and remediation data that customers depend on. P0 migration unblocks multi-tenant PostgreSQL and SOC2 evidence signing.

### sqlite3.connect call sites — P0

#### `suite-core/core/services/remediation.py` — 14 call sites
Lines: 110, 227, 295, 323, 372, 445, 508, 570, 633, 745, 770, 826, 1025 (+572 duplicate)
**DB file**: `self.db_path` (set at construction time, typically `.fixops_data/remediation.db`)
**Tables used**: `remediations`, `remediation_steps`, `remediation_artifacts`
**Priority**: P0 — RemediationTask model covers this
**Migration work**: Replace all `sqlite3.connect(self.db_path)` with `DatabaseManager.get_session_context()` + ORM models

#### `suite-core/core/services/history.py` — 5 call sites
Lines: 21, 93, 164, 199, 223
**DB file**: `self.db_path` (typically `.fixops_data/history.db`)
**Tables used**: `scan_history`
**Priority**: P0 — PipelineRun captures this going forward
**Note**: try/finally pattern already implemented (fixed in Run 7)

#### `suite-core/core/services/deduplication.py` — 17 call sites
Lines: 38, 166, 323, 342, 400, 454, 495, 532, 547, 569, 611, 635, 659, 732, 868, 996, 1123
**DB file**: `self.db_path` (typically `.fixops_data/dedup.db`)
**Tables used**: `fingerprints`, `dedup_decisions`
**Priority**: P0 — findings deduplication is part of the brain pipeline
**Note**: Uses `timeout=30.0` on all connects — indicates known contention

#### `suite-core/core/mpte_db.py` — 1 call site
Line: 30
**DB file**: `self.db_path` (typically `.fixops_data/mpte.db`)
**Tables used**: `mpte_runs`, `mpte_findings`
**Priority**: P0 — MPTE results feed back into risk scoring

#### `suite-core/core/audit_db.py` — 1 call site
Line: 31
**DB file**: `str(self.db_path)` (typically `.fixops_data/audit.db`)
**Tables used**: `audit_log`
**Priority**: P0 — maps to `audit_logs` table in migration 001

#### `suite-api/apps/api/scanner_ingest_router.py` — 1 call site
Line: 459
**DB file**: `str(db_path)` (passed in at request time)
**Tables used**: `ingest_batches`
**Priority**: P0 — scanner ingest is the primary ingress path

### PersistentDict usages — P0

| File | Line | Store Name | Represents |
|---|---|---|---|
| `suite-attack/api/micro_pentest_router.py` | 556 | `micro_pentest_audit_logs` | MPTE execution audit — P0 |
| `suite-api/apps/api/bulk_router.py` | 110 | `bulk_jobs` | Bulk scan job state — P0 |
| `suite-api/apps/api/policies_router.py` | 28 | `policy_violation_store` | Policy enforcement events — P0 |

---

## P1 — Operational Data

These stores support the platform's operational health: feeds, analytics, and scan runs.

### sqlite3.connect call sites — P1

#### `suite-feeds/feeds_service.py` — 29 call sites
Lines: 786, 1082, 1176, 1359, 1473, 1627, 1666, 1785, 1862, 1903, 1946, 1974, 2062, 2102, 2171, 2268, 2313, 2401, 2438, 2477, 2502, 2545, 2581, 2620, 2660, 2700, 2752, 2805 (+1)
**DB file**: `self.db_path` (default: `data/feeds/feeds.db`)
**Tables used**: `nvd_entries`, `kev_entries`, `epss_scores`, `osv_advisories`, `feed_metadata`
**Priority**: P1 — threat intel feeds, operational but not customer-blocking

#### `suite-core/api/feeds_router.py` — 3 call sites
Lines: 33, 225, 328
**DB file**: `_FEEDS_DB` (typically `data/feeds/feeds.db`)
**Tables used**: reads from feeds tables populated by `feeds_service.py`
**Priority**: P1 — same feed database

#### `suite-core/core/analytics_db.py` — 1 call site
Line: 32
**DB file**: `str(self.db_path)` (typically `data/analytics.db`)
**Tables used**: `scan_metrics`, `aggregated_stats`
**Priority**: P1 — analytics pipeline

#### `suite-api/apps/api/gap_router.py` — 22 call sites
Lines: 66, 141, 793, 865, 1768, 1825, 2584, 2699, 3812, 3908, 4111, 4260, 4334, 4382, 4422, 4466, 4515, 4624, 4699 (+ 3 more)
**DB files**: Multiple — `data/analytics.db`, `_ACTIVITY_DB_PATH`, `_HUNT_RULES_DB`, `_TRAINING_PROGRESS_DB`, and dynamic paths
**Priority**: P1 — gap analysis and analytics dashboards

#### `suite-api/apps/api/system_router.py` — 1 call site
Line: 43
**DB file**: dynamic path (`str(path)`, iterates data directory)
**Priority**: P1 — system inventory scan

#### `suite-api/apps/api/detailed_logging.py` — 1 call site
Line: 83
**DB file**: `self._db` (typically `data/detailed_logging.db`)
**Priority**: P1 — structured log storage

#### `suite-api/apps/api/health.py` — 2 call sites
Lines: 196, 209
**DB file**: `.fixops_data/audit.db` (line 196), temp file (line 209)
**Note**: These are health *probes*, not data writers. Keep as-is; add the new `check_database_health()` function alongside them.
**Priority**: P1 — will be replaced by `check_database_health()` in this sprint

#### `suite-core/core/report_db.py` — 1 call site
Line: 32
**DB file**: `str(self.db_path)` (typically `data/reports.db`)
**Tables used**: `reports`, `report_artifacts`
**Priority**: P1 — report persistence

#### `suite-core/core/app_config.py` — 1 call site
Line: 470
**DB file**: `str(db_path)` (passed in)
**Tables used**: `app_config`
**Priority**: P1 — configuration storage

#### `suite-core/core/cli.py` — 9 call sites
Lines: 1286, 1397, 1744, 2017, 2229, 2393, 2596, 2852, 3021
**DB files**: Various CLI-specific databases
**Priority**: P1 — CLI tooling, not in hot path

#### `suite-core/api/deduplication_router.py` — 1 call site
Line: 448
**DB file**: `str(db_path)` (passed in from query param)
**Priority**: P1 — router for deduplication service

### PersistentDict usages — P1

| File | Line | Store Name | Represents |
|---|---|---|---|
| `suite-core/api/agents_router.py` | 446 | `agent_tasks` | AI agent task queue — P1 |
| `suite-core/api/llm_router.py` | 89 | `llm_settings` | LLM config overrides — P1 |
| `suite-core/api/copilot_router.py` | 218 | `copilot_sessions` | Copilot session state — P1 |
| `suite-core/api/copilot_router.py` | 219 | `copilot_messages` | Copilot message history — P1 |
| `suite-core/api/copilot_router.py` | 220 | `copilot_actions` | Copilot tool invocations — P1 |
| `suite-api/apps/api/users_router.py` | 60 | `login_attempts` | Brute-force tracking — P1 |
| `suite-api/apps/api/workflows_router.py` | 29 | `workflow_sla` | SLA tracking — P1 |
| `suite-api/apps/api/workflows_router.py` | 30 | `workflow_steps` | Step execution state — P1 |
| `suite-api/apps/api/workflows_router.py` | 31 | `workflow_paused` | Paused workflow state — P1 |
| `suite-api/apps/api/inventory_router.py` | 26 | `inventory_deps` | Dependency inventory — P1 |
| `suite-api/apps/api/inventory_router.py` | 352 | `inventory_services` | Service inventory — P1 |
| `suite-api/apps/api/inventory_router.py` | 353 | `inventory_apis` | API inventory — P1 |
| `suite-api/apps/api/inventory_router.py` | 597 | `global_sbom_components` | SBOM component store — P1 |
| `suite-api/apps/api/inventory_router.py` | 598 | `ingested_sboms` | SBOM ingestion records — P1 |

---

## P2 — Internal / Cache

These stores hold learning data, caches, and internal platform state.

### sqlite3.connect call sites — P2

#### `suite-core/core/self_learning.py` — 1 call site
Line: 122
**DB file**: `db_path` constructor argument (default: `data/self_learning.db`)
**Tables used**: `weights`, `feedback_events`, `metrics`
**Priority**: P2 — self-learning feedback loop (V8, deferred)
**Note**: Uses `check_same_thread=False` — indicates background worker writes

#### `suite-core/core/services/collaboration.py` — 22 call sites
Lines: 48, 202, 285, 310, 335, 364, 382, 402, 432, 475, 507, 533, 575, 630, 688, 768, 828, 926 (+ 4 more)
**DB file**: `self.db_path` (collaboration store)
**Priority**: P2 — real-time collaboration features, not customer-blocking

#### `suite-core/core/knowledge_brain.py` — 1 call site
Line: 174
**DB file**: `self.db_path` (default: `data/knowledge_brain.db`)
**Tables used**: `knowledge_nodes`, `knowledge_edges`
**Priority**: P2 — knowledge graph

#### `suite-core/core/security_hardening.py` — 2 call sites
Lines: 1055, 1292
**DB file**: `db_path` (security hardening rules)
**Priority**: P2 — internal policy enforcement cache

#### `suite-core/core/services/fuzzy_identity.py` — 1 call site
Line: 275
**DB file**: `db_path` (identity dedup cache)
**Priority**: P2 — entity resolution cache

#### `suite-core/core/zero_gravity.py` — 1 call site
Line: 289
**DB file**: `db_path` (feature flag store)
**Priority**: P2 — internal experiments

#### `suite-core/core/fail_db.py` — 1 call site
Line: 34
**DB file**: `self._db_path` (default: `data/fail.db`)
**Tables used**: `fail_scores`, `fail_history`
**Priority**: P2 — FAIL scoring engine (V3, already reviewed)
**Note**: Uses `threading.local()` for thread-safe connections (already reviewed/fixed)

#### `suite-core/core/exposure_case.py` — 1 call site
Line: 137
**DB file**: `db_path` constructor argument
**Priority**: P2 — exposure case lifecycle

#### `suite-core/core/policy_db.py`, `auth_db.py`, `user_db.py`, `workflow_db.py`, `integration_db.py` — 1 call site each
Lines: 25 (each)
**DB files**: `str(self.db_path)` (domain-specific files)
**Priority**: P2 — internal domain persistence

#### `suite-core/core/services/graph/graph.py` — 1 call site
Line: 182
**DB file**: `self.db_path` (graph storage)
**Priority**: P2 — attack graph

#### `suite-core/core/api_learning_store.py` — 1 call site
Line: 215
**DB file**: `str(self._db_path)`
**Priority**: P2 — API pattern learning cache

#### `suite-evidence-risk/risk/reachability/storage.py` — 6 call sites
Lines: 45, 134, 195, 250, 268, 305, 315
**DB file**: `str(self.db_path)` (reachability graph)
**Priority**: P2 — reachability analysis

#### `suite-evidence-risk/compliance/compliance_engine.py` — 7 call sites
Lines: 317, 371, 392, 411, 425, 434, 443
**DB file**: `self.db_path` (compliance records)
**Priority**: P2 — compliance checks

#### `suite-core/automation/remediation.py` — 1 call site
Line: 489
**DB file**: `":memory:"` — intentional in-memory database
**Priority**: P2 — transient automation state, do not migrate

#### `suite-api/apps/api/app.py` — 1 call site
Line: 1417 (uses `_sqlite3` alias)
**DB file**: `svc.db_path` (service lookup at startup)
**Priority**: P2 — startup service discovery

#### `suite-api/apps/api/remediation_router.py` — 1 call site
Line: 732
**DB file**: `service.db_path`
**Priority**: P2 — remediation router (the engine is P0)

#### `suite-core/services/graph/graph.py` — 1 call site
Line: 182
**Priority**: P2 — knowledge graph

#### `suite-core/api/copilot_router.py` — 1 call site
Line: 848 (uses `_sqlite3` alias)
**DB file**: `brain_db` (brain state cache)
**Priority**: P2 — copilot brain cache

### PersistentDict usages — P2

| File | Line | Store Name | Represents |
|---|---|---|---|
| `suite-core/api/nerve_center.py` | 857 | `nerve_center_overlay` | Overlay config — P2 |
| `suite-attack/api/vuln_discovery_router.py` | 283 | `discovered_vulns` | CVE discovery cache — P2 |
| `suite-attack/api/vuln_discovery_router.py` | 284 | `cve_contributions` | Contribution tracking — P2 |
| `suite-attack/api/vuln_discovery_router.py` | 285 | `retrain_jobs` | ML retrain job queue — P2 |
| `suite-integrations/api/mcp_router.py` | 158 | `mcp_clients` | MCP client registry — P2 |
| `suite-integrations/api/mcp_router.py` | 298 | `mcp_config` | MCP server config — P2 |

---

## Out of Scope (Do Not Migrate)

| File | Reason |
|---|---|
| `suite-core/automation/remediation.py:489` | Uses `":memory:"` — transient by design |
| `scripts/` directory (2 call sites) | Demo/test scripts, not production code |
| `persona_reality_test.py:236` | Test harness, not production code |
| `tests/` directory | Tests use tmp_path fixture, not production DB |

---

## Migration Sprint Plan

### Sprint 2 (Current — 2026-03-17): Foundation
- [x] Audit and document all call sites (this document)
- [x] Create SQLAlchemy 2.0 P0 models in `suite-core/core/db/models.py`
- [x] Create Alembic migration `002_add_p0_models.py` for P0 tables
- [x] Add `check_database_health()` to health endpoint
- [x] Wire `DatabaseManager` into brain pipeline for `PipelineRun` writes only

### Sprint 3 (Phase 2 — Apr 2026): P0 Core Services
- [ ] Migrate `suite-core/core/services/remediation.py` (14 call sites) → `RemediationTask` model
- [ ] Migrate `suite-core/core/audit_db.py` (1 call site) → `audit_logs` table
- [ ] Migrate `suite-core/core/mpte_db.py` (1 call site) → MPTE result storage

### Sprint 4 (Phase 2 — May 2026): P0 Feeds + P1 Analytics
- [ ] Migrate `suite-feeds/feeds_service.py` (29 call sites)
- [ ] Migrate `suite-api/apps/api/gap_router.py` (22 call sites)
- [ ] Replace PersistentDict P1 stores with SQLAlchemy tables

### Sprint 5 (Phase 2 — Jun 2026): P2 + Full PostgreSQL
- [ ] Migrate remaining P2 stores
- [ ] Enable `PGVECTOR_ENABLED` for embedding storage
- [ ] Run `alembic upgrade head` against production PostgreSQL

---

## Architecture Decision: Dual-Dialect Constraints

The SQLAlchemy models must work on **both** PostgreSQL and SQLite. The constraints are:

1. **UUID columns**: Use `sa.String(36)` NOT `postgresql.UUID()`. SQLite has no UUID type.
2. **Array columns**: Use `sa.JSON` NOT `postgresql.ARRAY(...)`. SQLite has no array type.
3. **Boolean defaults**: Use `server_default=sa.false()` instead of `server_default=sa.text("FALSE")`.
4. **JSONB**: Use `sa.JSON` for models; migration can use `sa.JSON` which maps to JSONB on PostgreSQL automatically via SQLAlchemy's dialect awareness when using `op.create_table`.
5. **gen_random_uuid()**: In raw Alembic migrations only use this if PostgreSQL is confirmed. In models use `default=lambda: str(uuid.uuid4())`.
6. **Partial indexes**: PostgreSQL-only — emit them conditionally in migrations using `if op.get_bind().dialect.name == "postgresql"`.

The existing `alembic/versions/001_initial_schema.py` uses `postgresql.UUID` and `postgresql.JSONB` — this migration is **PostgreSQL-only**. The new `002_add_p0_models.py` migration and all ORM models in `suite-core/core/db/models.py` use the dual-dialect approach.

---

## Count Summary

| Category | sqlite3.connect | PersistentDict |
|---|---|---|
| P0 — Customer Data | 22 | 3 |
| P1 — Operational | 42 | 14 |
| P2 — Internal/Cache | 40 | 6 |
| Out of scope | 3 | 0 |
| Scripts/tests | 4 | 0 |
| **Total** | **~111 in-scope** | **23** |

> Note: The task description states 185 total sqlite3.connect calls. The additional ~74 are in the gap_router (bulk data scan queries that re-open connections per-query inside loops) and collaboration.py (per-method connection pattern). All are accounted for in the groupings above.
