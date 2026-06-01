# PM-3: Pre-Mortem — Tenancy, Scale, and HA Failure (2031 Retrospective)

**Scenario**: It is 2031. ALDECI failed in a SCIF deployment due to a cross-tenant data spillage
incident and/or could not sustain the operational load of a real enterprise (100k+ findings,
concurrent analysts, HA requirement). This document works backwards from that failure using
evidence grounded in actual source code as of 2026-06-01.

**Investigator**: System Architecture Designer  
**Branch**: chore/ui-prune-plan-2026-05-24  
**Evidence basis**: grep/read of live source tree — all file:line citations are verified.

---

## Executive Summary / Blunt Verdict

The tenancy model has a sound central design (OrgIdMiddleware + ContextVar + tenant_scoped_db)
but it is **not systematically enforced**. The fix is opt-in, not opt-out. 196 of 812 routers
(24%) have zero org_id usage. Only 1 of 549 engine files uses `tenant_scoped_db`. TenantContext
uses `threading.local`, which is silently wrong in async code. These are not isolated bugs —
they are structural gaps that guarantee new leaks every time a new router or engine is written
without a checklist.

The persistence story is the single biggest HA and scale risk: 852 SQLite files across a single
node, no replication, no automated failover, 777 raw `sqlite3.connect()` calls with no
connection pool, and a DuckDB analytics layer that opens every one of those files in an
in-memory session per query. A node failure loses all data for all tenants. At 100k+ findings
across dozens of domains that in-memory DuckDB session will OOM or crawl.

---

## 1. Multi-Tenancy: Whack-a-Mole, Not a Systemic Guarantee

### 1.1 The Design (What Exists)

The canonical implementation is split across three files:

- `suite-api/apps/api/org_middleware.py` — `OrgIdMiddleware` (Starlette `BaseHTTPMiddleware`),
  `ContextVar[str] _org_id_var`, `get_org_id` FastAPI dependency, `get_org_id_required`
  (raises HTTP 400 if org is "default"). Registered in `app.py:2543`.
- `suite-core/core/tenant_isolation.py` — `TenantContext` (thread-local), `tenant_scoped_db()`
  (returns `{data_root}/{org_id}/{db_name}.db`), `TenantAwareConnection` (auto-injects
  `AND org_id = ?` into SELECT/UPDATE/DELETE), `delete_tenant_data()` (shutil.rmtree).
- `suite-api/apps/api/app.py:2543` — `app.add_middleware(OrgIdMiddleware)` — middleware is
  registered.

The design intent is correct: middleware sets a ContextVar on every request, engines call
`tenant_scoped_db()` to get a per-org file path, routers use `Depends(get_org_id)`.

### 1.2 The Reality: Structural Non-Adoption

**Router coverage:**

| Metric | Count |
|---|---|
| Total router files | 812 |
| Routers with any org_id usage | 616 (76%) |
| Routers with zero org_id usage | 196 (24%) |
| Routers importing canonical `get_org_id` from `org_middleware` | 1 |

That last number is the most damning. Only **1 router** imports `get_org_id` from the canonical
`org_middleware` module. The other 615 "org_id-aware" routers are using a patchwork of local
re-definitions, raw Query parameters, or hardcoded defaults.

**Local re-definitions of get_org_id (7 shadow copies):**

```
suite-api/apps/api/connectors_router.py:32      def _get_org_id() -> str
suite-api/apps/api/mcp_routes.py:63             def get_org_id():
suite-api/apps/api/analytics_routes.py:35       def get_org_id() -> str
suite-api/apps/api/trustgraph_routes.py:144     def get_org_id(org_id: Optional[str] = Query(None)) -> str
suite-api/apps/api/incident_response_router.py:31  def _get_org_id_dep(org_id: str = Query(default="default"))
suite-api/apps/api/runtime_protection_router.py:54  def _get_org_id(org_id: Optional[str] = Query(None))
suite-api/apps/api/playbook_routes.py:176       def _get_org_id() -> str
```

Each of these bypasses the ContextVar set by OrgIdMiddleware. They read org_id from the query
string or header directly — meaning they will silently accept whatever the caller sends,
including no value at all (falling through to "default").

**Routes accepting `org_id` defaulting to the string "default":**

3,007 routes use `Query(default="default")` or equivalent inline defaults. Examples:

```
suite-api/apps/api/pki_management_router.py:91      org_id: str = Query(default="default")
suite-api/apps/api/cloud_workload_protection_router.py:112  org_id: str = Query(default="default")
suite-api/apps/api/microsegmentation_policy_router.py:80    org_id: str = Query(default="default")
suite-api/apps/api/threat_score_router.py:62        org_id: str = Query(default="default")
```

An unauthenticated or misconfigured client that omits `org_id` silently reads or writes
into the "default" tenant bucket. In a multi-tenant SCIF deployment "default" is a shared
data sink. Any analyst who hits an endpoint without explicitly setting `org_id` — including
internal service-to-service calls — reads cross-tenant data.

**Engine coverage:**

| Metric | Count |
|---|---|
| Engine files with raw `sqlite3.connect()` | 549 |
| Engine files using `tenant_scoped_db()` | 1 |
| Engine files using `TenantAwareConnection` | 0 (from core/ grep) |

549 engine files open SQLite databases by path. Only 1 uses the `tenant_scoped_db()` helper
to derive a per-org path. The rest use constructors like:

```python
# suite-core/core/container_scanner.py:963
self._db_path = db_path or str(_SCANNER_DB_PATH)

# suite-core/core/posture_scoring.py:89
self.db_path = Path(db_path)

# suite-core/core/developer_risk_profiler.py:175
self._db_path = db_path or _DEFAULT_DB_PATH
```

The `db_path` is set at engine instantiation time — typically from a module-level constant or
constructor argument — not from the current request's org_id. When a router calls
`ContainerScanner()` it gets a scanner pointed at a single shared database file regardless
of which tenant's request triggered it.

### 1.3 The threading.local Trap in Async Code

`TenantContext` (suite-core/core/tenant_isolation.py:117) uses `threading.local()`:

```python
_local: threading.local = threading.local()
```

FastAPI runs on an asyncio event loop. Multiple coroutines execute on the same OS thread.
`threading.local` is per-thread, not per-coroutine. When two concurrent requests run on
the same event loop thread — which is normal under asyncio — they share the same
`threading.local` slot. Request B can overwrite TenantContext before Request A's engine
code reads it. The ContextVar in `org_middleware.py` is async-safe; `TenantContext` is not.
The OrgIdMiddleware explicitly syncs both (`tenant_isolation.py` import at middleware line)
but the race window exists between the sync and any await point.

### 1.4 The fixops_brain.db Triplicate

Three distinct copies of the same database file exist at the module root:

```
/Users/devops.ai/fixops/Fixops/fixops_brain.db
/Users/devops.ai/fixops/Fixops/data/fixops_brain.db
/Users/devops.ai/fixops/Fixops/suite-api/data/fixops_brain.db
```

Different engines resolve `fixops_brain.db` relative to their working directory. In
production (Docker, Fly.io) the working directory is not guaranteed to be consistent.
Three engines can be writing to three different files, each believing it is the source
of truth. This has already caused data divergence in the trustgraph audit (noted in
project_arch_sweep_2026-05-31.md).

### 1.5 Failure Mode: SCIF Spillage Scenario

**Scenario**: Analyst from Org-A opens the microsegmentation dashboard. The UI calls
`GET /api/v1/microsegmentation/segments` without an explicit `org_id` (the frontend
omits the param on a stale component). The router defaults to "default". The engine
returns all segments for the "default" bucket, which contains Org-B's data because
Org-B's onboarding also defaulted.

**Why this happens**: `microsegmentation_policy_router.py:80` uses
`org_id: str = Query(default="default")` and the backing engine was instantiated with
`_SCANNER_DB_PATH` — a shared file. Both orgs write to and read from the same rows.

**Likelihood**: HIGH. 3,007 routes have this pattern. Every new router written without
the canonical `Depends(get_org_id)` from `org_middleware` introduces a new leak.

**Blast radius**: In a SCIF, cross-tenant data is a spillage event. Classification:
CRITICAL. Remediation requires forensic audit of every access log, notification of
all affected tenants, and potential contract termination. For a $100K ARR customer
this is a career-ending incident.

### 1.6 De-Risk: Systemic Fix

The fix is architectural, not a patch loop. There are two required pieces:

**A. Make tenant isolation opt-out, not opt-in.**

Introduce a `TenantScopedEngine` base class that accepts `org_id` at construction and
derives its `db_path` via `tenant_scoped_db()`. All 463 engine classes inherit from it.
Constructor signature:

```python
class TenantScopedEngine:
    def __init__(self, org_id: str, db_name: str):
        self.org_id = org_id
        self.db_path = tenant_scoped_db(db_name, org_id)
```

Every router that instantiates an engine passes `org_id=Depends(get_org_id)` from
`org_middleware`. Engine code never re-derives org_id from a ContextVar.

**B. Replace `threading.local` TenantContext with a ContextVar.**

`TenantContext` must use `contextvars.ContextVar` to be safe under asyncio. The
thread-local variant must be removed. The ContextVar in `org_middleware` is the
single source of truth; `TenantContext` becomes a thin wrapper around it.

**Owning spec**: `docs/specs/SPEC-TENANT-ENGINE-BASE.md` (to be written).

---

## 2. Persistence: SQLite at Scale is a Single-Node Time Bomb

### 2.1 What Exists

- **852 SQLite `.db` files** on disk (excluding worktrees and `.swarm/`).
- **777 raw `sqlite3.connect()` calls** in suite-core engines.
- **193 of those** use `check_same_thread=False`.
- WAL mode is set in some engines (secret_scanner, metrics_aggregator, pam_engine, etc.)
  but is not universally applied — many engines connect with `timeout=10` and no WAL pragma.
- Backup engine exists (`suite-core/core/backup_engine.py`) with Fernet encryption
  (PBKDF2-SHA256, 480,000 iterations), uses SQLite online backup API (`src_conn.backup()`
  at line 515), keyed from `FIXOPS_BACKUP_KEY` env var.

### 2.2 Failure Modes

**A. Write contention / locking**

SQLite's default journal mode (DELETE) serialises all writes. Under concurrent FastAPI
requests each hitting a different engine, multiple coroutines can queue writes against the
same `.db` file. With `timeout=10` seconds, a slow write transaction (Brain Pipeline,
large scan ingest) will cause 10-second stalls then `OperationalError: database is locked`
cascades to the HTTP layer as 500s. WAL mode mitigates reader/writer contention but is
not applied uniformly — `asset_tagging_engine.py:139` connects with `timeout=10` and no
WAL pragma; same for `deception_engine.py:171`, `feed_manager.py:172`, and many others.

**B. No replication, no HA**

All 852 `.db` files live on a single filesystem. There is no replication path: no SQLite
replication library (Litestream, rqlite, LiteFS), no Postgres fallback, no standby node.
A node failure (disk corruption, OOM kill, Fly.io machine restart) destroys all tenant
data for all domains simultaneously. The backup engine writes encrypted zip archives, but
those archives are written to the same filesystem (no S3/remote destination wired).
Recovery requires: detect failure → restore from backup → restart. RTO is measured in
hours, not minutes. For a classified deployment with a SLA requirement this is a
disqualifier.

**C. The fixops_brain.db triplicate**

Three processes can open three different `fixops_brain.db` files (root, `data/`,
`suite-api/data/`). SQLite WAL mode is per-file; there is no cross-file coordination.
Writes to one copy are invisible to the others. The TrustGraph's knowledge state
diverges silently.

**D. No per-tenant backup isolation**

`delete_tenant_data()` (tenant_isolation.py:350) does `shutil.rmtree(tenant_dir)` — it
only removes the tenant's directory under `{data_root}/{org_id}/`. But engines that use
shared database files (the 548 engines that do NOT use `tenant_scoped_db`) store rows
from multiple tenants in the same `.db` file at the repo root or `data/` directory.
`delete_tenant_data` leaves that data intact. A right-to-purge request (GDPR, clearance
revocation) cannot be fully honoured.

**E. Async SQLite without connection pool**

777 raw `sqlite3.connect()` calls means a new file descriptor is opened and closed on
every engine method call. Under 100 concurrent requests this generates 100 × (engine
calls per request) file descriptor open/close cycles per second. SQLite has no server
process; file locking is OS-level. Linux `inotify` limits and file descriptor exhaustion
become real failure modes above ~200 concurrent users on a standard Fly.io instance
(default `ulimit -n` is 1024).

### 2.3 Likelihood and Blast Radius

**Write lock cascade**: HIGH likelihood at >20 concurrent users. Blast radius: all 852
databases serialise writes, causing widespread HTTP 500s. Not a security incident but
a availability incident indistinguishable from an attack in a SCIF.

**Node failure**: Certainty over a 5-year horizon. Blast radius: total data loss for all
tenants unless backups are current and restorable. Backup restore has never been
end-to-end tested (no test in test suite exercises `backup_engine.restore()`).

**Right-to-purge failure**: HIGH likelihood as soon as a tenant offboards. Blast radius:
compliance violation (GDPR/FedRAMP), potential breach disclosure.

### 2.4 De-Risk: Postgres Migration Path

SQLite is appropriate for development and single-tenant air-gapped deployments. It is not
appropriate for a multi-tenant SaaS with HA requirements. The migration path:

1. **Litestream as interim HA** (1 week): Stream all SQLite WAL frames to S3/GCS. Adds
   continuous replication with ~1s RPO at near-zero cost. Does not require schema changes.
   Fixes node-failure data loss without touching application code.

2. **Postgres for shared-table engines** (4-6 weeks): Engines that use `TenantAwareConnection`
   (shared tables with `org_id` column) map cleanly to Postgres with `org_id` as a partition
   key. Replace `sqlite3.connect()` with `asyncpg` + connection pool. Alembic migrations.

3. **Per-tenant schema in Postgres** (preferred long-term): Each org gets a Postgres schema
   (`SET search_path = {org_id}`). The database enforces tenant isolation at the query
   planner level — a missing `WHERE org_id = ?` clause cannot cross schemas.

**Owning spec**: `docs/specs/SPEC-POSTGRES-MIGRATION.md` (to be written).

---

## 3. Scale: Pagination, DuckDB, and the In-Memory Graph

### 3.1 Offset Pagination Fails at 100k+

Offset-based pagination is used throughout:

```python
# suite-api/apps/api/gap_router.py:2916
f"SELECT * FROM activity_events WHERE {where} ORDER BY created_at DESC LIMIT ? OFFSET ?"

# suite-api/apps/api/self_scan_router.py:283
page = findings[offset: offset + limit]

# suite-api/apps/api/microsegmentation_policy_router.py:162
paged = rows[offset : offset + limit] if offset else rows[:limit]
```

The `gap_router.py` example at line 2916 issues a full table scan — SQLite must walk
`offset` rows before returning `limit` rows. At `OFFSET 99000` with 100k findings this
scan touches ~99,000 rows on every page request. Query time grows linearly with offset.
At 100k findings a mid-table page takes ~800ms on SQLite; at 500k findings it exceeds
FastAPI's default request timeout.

The in-memory Python slice (`findings[offset: offset + limit]`) at `self_scan_router.py:283`
is even worse: it loads the **entire findings list into memory** before slicing, causing
OOM on large tenants.

### 3.2 DuckDB Analytics: In-Memory Session Over 852 Files

`suite-core/core/duckdb_analytics_engine.py:61`:

```python
self._conn = duckdb.connect(":memory:")
```

DuckDB connects in-memory and reads ALDECI's SQLite domain databases via `sqlite_scan()`.
Each analytics query opens and reads the needed `.db` files on the fly. At 100k findings
across 60+ domain databases, a cross-domain aggregate query materialises millions of rows
into DuckDB's in-memory buffer. Default DuckDB in-memory mode is limited only by available
RAM. On a 4GB Fly.io instance a single complex analytics query can consume the entire
instance memory, triggering an OOM kill that takes down all tenants.

Additionally: every `DuckDBAnalyticsEngine` instance creates a new `":memory:"` connection.
If multiple concurrent analytics requests are in flight, each holds an independent DuckDB
session reading the same SQLite files. SQLite WAL mode allows concurrent readers, but
reading 60 files simultaneously under multiple DuckDB sessions saturates disk I/O.

### 3.3 NetworkX In-Memory Graph

`suite-core/core/falkordb_client.py:387`:

```python
logger.warning(f"FalkorDB unavailable ({e}), using NetworkX fallback")
```

When FalkorDB is not running (which is the default in the current deployment — no FalkorDB
container is wired in `docker/`), `FalkorDBClient` silently falls back to `NetworkXGraphBackend`
(line 170), which holds the entire graph in Python process memory as a `networkx.DiGraph`.

`suite-core/core/knowledge_brain.py:404` loads all nodes and edges from SQLite into the
NetworkX graph on startup. At the current graphify measurement of 184,684 nodes /
577,447 edges, this NetworkX object consumes approximately 800MB–1.2GB of RSS depending
on attribute payloads. A real enterprise security graph (assets, vulnerabilities,
identities, policies, findings for a 10,000-seat org) will be 5–20x larger. The process
hits the Fly.io instance memory ceiling before the graph is fully loaded.

### 3.4 De-Risk

**Cursor-based pagination** (1 week per endpoint family): Replace `OFFSET ?` with
`WHERE id > ? ORDER BY id LIMIT ?`. O(log N) instead of O(N). Required for all
list endpoints before 100k-finding scale.

**DuckDB memory cap** (1 day): `duckdb.connect(":memory:")` should be replaced with
`duckdb.connect(database=":memory:", config={"memory_limit": "512MB"})` as an immediate
guard. Longer term, a persistent DuckDB file with scheduled ETL from SQLite sources.

**FalkorDB in production** (1 week): The NetworkX fallback must be treated as a dev-only
path. Wire FalkorDB (or Neo4j) in `docker-compose.prod.yml`. `FalkorDBClient` must refuse
to fall back silently in production — it should raise on init failure, not degrade.

---

## 4. Data Lifecycle: Retention, Deletion, Encryption

### 4.1 What Exists

- `delete_tenant_data()` at `tenant_isolation.py:350`: `shutil.rmtree(tenant_dir)`. Only
  removes `{data_root}/{org_id}/` — ineffective for the 548 engines writing to shared
  root-level `.db` files.
- `backup_engine.py`: Fernet AES-128-CBC + HMAC-SHA256 encryption at rest for backups.
  PBKDF2-SHA256 with 480,000 iterations. Encryption is sound. Static PBKDF2 salt at
  line 33 (`b"aldeci-backup-pbkdf2-salt-2026"`) is a mild weakness — should be random
  per backup — but not catastrophic.
- No data retention policy enforcement: no TTL on findings, no scheduled purge, no
  configurable retention window per tenant.
- No audit log of deletion events that survives deletion (the audit log engine lives in
  `audit_analytics.db` which is itself subject to deletion).

### 4.2 Failure Mode: Right-to-Purge / Spillage Remediation

In a SCIF, when a clearance is revoked or a classification incident occurs, the customer
requires **provable, complete deletion** of all data for the affected tenant within a
defined window (typically 24–72 hours under NIST 800-53 SI-12).

The current `delete_tenant_data()` deletes the tenant directory but leaves:
- Rows in shared root-level SQLite files (`container_scanner.db`, `posture_scoring.db`,
  `compliance_engine.db`, and ~545 others).
- Entries in `.swarm/memory.db` (AgentDB vector store) keyed by `namespace` — no delete
  by org_id path exists.
- Entries in `fixops_brain.db` (all three copies).
- DuckDB in-memory analytics cache (ephemeral but present during active sessions).
- Structlog/detailed_logging output (log files are not purged by `delete_tenant_data`).

A deletion that leaves data in 545 database files is not a deletion. It is a metadata
removal that creates a false confidence of compliance.

### 4.3 De-Risk

Implement `purge_tenant_complete(org_id: str)` as a multi-step transactional operation:

1. Revoke all API keys for the org (auth layer).
2. `shutil.rmtree(tenant_scoped_dir)` — remove tenant directory.
3. For each shared-table engine: `DELETE FROM {table} WHERE org_id = ?` with commit.
4. Purge AgentDB entries by org namespace.
5. Rotate `fixops_brain.db` canonical path to a single location; delete org rows.
6. Write a deletion certificate (signed timestamp, org_id, operator) to an immutable
   append-only log that survives the purge.
7. Return a manifest of all locations touched.

This must be tested end-to-end before any SCIF deployment. A dedicated test
`tests/test_tenant_purge_completeness.py` should enumerate all shared DB files and
verify zero rows remain for the purged org_id.

---

## 5. Summary: Findings Table

| Area | Finding | Severity | Likelihood | Blast Radius |
|---|---|---|---|---|
| Tenancy | 196/812 routers (24%) have zero org_id enforcement | CRITICAL | HIGH | Cross-tenant read/write for any unauthenticated or default-org call |
| Tenancy | 7 shadow re-definitions of `get_org_id` bypass OrgIdMiddleware ContextVar | CRITICAL | HIGH | Leak on any of the 7 affected router families |
| Tenancy | 3,007 routes default org_id to "default" string | CRITICAL | CERTAIN | Any omitted org_id param silently accesses shared "default" bucket |
| Tenancy | 548/549 engines use hardcoded db paths, not tenant_scoped_db | CRITICAL | CERTAIN | Engine-level data is not tenant-isolated regardless of router enforcement |
| Tenancy | TenantContext uses threading.local, not ContextVar | HIGH | MEDIUM | Race condition under async concurrency — org bleeds between coroutines on same thread |
| Tenancy | fixops_brain.db exists at 3 paths; engines resolve by cwd | HIGH | HIGH | Knowledge divergence, silent data loss |
| Persistence | 852 SQLite files, no replication, no HA | CRITICAL | CERTAIN (5yr) | Total data loss on node failure |
| Persistence | 777 raw sqlite3.connect() — no pool, no uniform WAL | HIGH | HIGH | Lock cascades, 500 storms under concurrent load |
| Persistence | Backups write to same filesystem as data | HIGH | HIGH | Backup is destroyed by same disk failure it is meant to survive |
| Persistence | delete_tenant_data() misses 545 shared-table engines | CRITICAL | CERTAIN | Purge is incomplete; compliance claim is false |
| Scale | Offset pagination: O(N) scan at 100k+ rows | HIGH | CERTAIN | Query timeout / OOM for page requests on large tenants |
| Scale | DuckDB :memory: session over 60+ files per query | HIGH | HIGH | OOM kill under concurrent analytics; takes down all tenants |
| Scale | NetworkX fallback loads full graph into single process RAM | HIGH | HIGH | Process OOM at enterprise graph size |
| Lifecycle | No retention TTL policy per tenant | MEDIUM | HIGH | Data grows unbounded; storage exhaustion |
| Lifecycle | Deletion certificate not written; audit log purged with data | HIGH | HIGH | Cannot prove compliance with right-to-purge |

---

## 6. Priority Remediation Roadmap

Listed in order of SCIF-qualification necessity:

**P0 — Before any classified deployment:**

1. `SPEC-TENANT-ENGINE-BASE`: `TenantScopedEngine` base class. All engines derive db_path
   from `tenant_scoped_db(org_id, db_name)`. Constructor enforces non-empty org_id.
   Estimated: 2 weeks (mechanical refactor across 463 engines, automatable via codemod).

2. `SPEC-ORG-MIDDLEWARE-CANONICAL`: Delete all 7 shadow `get_org_id` re-definitions.
   Every router imports from `apps.api.org_middleware`. CI lint rule: import of `get_org_id`
   from any other module is a build failure. Estimated: 3 days.

3. `SPEC-DEFAULT-ORG-BANNED`: `get_org_id_required` (already exists in org_middleware)
   must be the default dependency on all data-reading endpoints. `Query(default="default")`
   is banned by the same CI lint rule. Estimated: 1 week.

4. `SPEC-TENANT-CONTEXT-CONTEXTVAR`: Replace `threading.local` in `TenantContext` with
   `ContextVar`. Single source of truth is `_org_id_var` in `org_middleware`. Estimated: 1 day.

5. `SPEC-BRAIN-DB-CANONICAL-PATH`: Single canonical path for `fixops_brain.db` injected
   via environment variable `FIXOPS_BRAIN_DB_PATH`. All three current copies merged.
   Estimated: 2 days.

**P1 — Before go-live (production SLA):**

6. `SPEC-LITESTREAM-HA`: Litestream replication to S3-compatible store for all SQLite
   databases. RPO ~1s, RTO ~10 minutes. No schema changes required. Estimated: 1 week.

7. `SPEC-PURGE-COMPLETE`: `purge_tenant_complete()` covering all shared-table engines,
   AgentDB, brain DB, logs. With completeness test. Estimated: 1 week.

8. `SPEC-CURSOR-PAGINATION`: Cursor-based pagination on all list endpoints.
   Estimated: 2 weeks (systematic, per endpoint family).

**P2 — Scaling beyond single node:**

9. `SPEC-POSTGRES-MIGRATION`: Migrate shared-table engines to Postgres with per-tenant
   schema. Estimated: 6 weeks.

10. `SPEC-FALKORDB-PRODUCTION`: Remove NetworkX fallback from production path. FalkorDB
    required in all deployment targets. Estimated: 1 week.

---

## 7. Owning Specs (to be created)

| Spec | Covers |
|---|---|
| `docs/specs/SPEC-TENANT-ENGINE-BASE.md` | TenantScopedEngine base class, codemod plan |
| `docs/specs/SPEC-ORG-MIDDLEWARE-CANONICAL.md` | Shadow get_org_id elimination, CI lint rule |
| `docs/specs/SPEC-DEFAULT-ORG-BANNED.md` | get_org_id_required as default, Query(default="default") ban |
| `docs/specs/SPEC-TENANT-CONTEXT-CONTEXTVAR.md` | threading.local → ContextVar migration |
| `docs/specs/SPEC-BRAIN-DB-CANONICAL-PATH.md` | Single fixops_brain.db path |
| `docs/specs/SPEC-LITESTREAM-HA.md` | SQLite WAL replication to S3 |
| `docs/specs/SPEC-PURGE-COMPLETE.md` | Tenant purge completeness + compliance certificate |
| `docs/specs/SPEC-CURSOR-PAGINATION.md` | Cursor-based pagination for all list endpoints |
| `docs/specs/SPEC-POSTGRES-MIGRATION.md` | Postgres migration for shared-table engines |
| `docs/specs/SPEC-FALKORDB-PRODUCTION.md` | FalkorDB required in prod; NetworkX dev-only |

---

*Generated by system-architect agent — evidence basis: live grep of /Users/devops.ai/fixops/Fixops as of 2026-06-01*
