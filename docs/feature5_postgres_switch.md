# FEATURE-5 — PostgreSQL Switch (DBAdapter)

**Status:** Phase 1 shipped 2026-05-02 · 5 priority engines wired · backwards-compatible

## TL;DR

ALDECI engines historically used per-engine SQLite files. FEATURE-5 introduces
`core.db_adapter.DBAdapter` so production deployments can flip a single
environment variable to scale onto PostgreSQL without code changes.

```bash
# Production (PostgreSQL)
export DATABASE_URL=postgresql://aldeci:password@db.internal:5432/aldeci

# Development / air-gapped (default — zero config)
unset DATABASE_URL   # → engines use SQLite under data/*.db
```

## How it works

`DBAdapter` (`suite-core/core/db_adapter.py`) is a thin abstraction over
`sqlite3` and `psycopg2`. Engines obtain an adapter via:

```python
from core.db_adapter import get_adapter
self._db = get_adapter(self.db_path)            # sqlite_path is the fallback
with self._db.connect() as conn:                # ctx-managed: commit/rollback/close
    conn.execute(self._db.adapt_sql(            # rewrites ? → %s on postgres
        "SELECT * FROM t WHERE id = ?"), (x,))
```

Two connection modes are exposed:

| Mode | API | Used by |
|------|-----|---------|
| Per-call ctx-managed | `connect()` | `cspm`, `application_security_engine`, `ir_playbook_engine` |
| Long-lived persistent | `persistent_connect()` | `ctem_engine`, `asset_inventory` |

## Engines covered (Phase 1 — 5 priority engines)

- `suite-core/core/ctem_engine.py`
- `suite-core/core/cspm.py`
- `suite-core/core/asset_inventory.py`
- `suite-core/core/application_security_engine.py`
- `suite-core/core/ir_playbook_engine.py`

The remaining ~95 SQLite-backed engines still use raw `sqlite3.connect(...)`.
Migration is a sprintable mechanical refactor (~10 lines per engine, identical
to the patterns above).

## Backwards compatibility

- **Empty / missing `DATABASE_URL`** → SQLite, exactly as before. Zero behavior
  change for dev environments, tests, and air-gapped deployments.
- **`DATABASE_URL` set but `psycopg2` not installed** → `DBAdapter` logs a
  `structlog.warning` and falls back to SQLite. Test environments that don't
  install `psycopg2-binary` continue to pass.
- **Placeholders** — engines write SQL with `?` (sqlite style); the adapter
  rewrites to `%s` only when in postgres mode. Engines do not need to know
  which backend they're talking to.

## Schema migration

Schemas are created on first access via each engine's existing
`_init_db()` / `_init_tables()` / `_ensure_schema()` method. The DDL these
methods emit (`CREATE TABLE IF NOT EXISTS ...`, `INTEGER PRIMARY KEY`,
`TEXT`, `REAL`) is dialect-compatible with both SQLite and PostgreSQL — no
parallel schema files are required for Phase 1.

Phase 2 work (out of scope here) will introduce real Alembic migrations once
production loads exceed the 5-engine slice.

## Dependency

```
psycopg2-binary>=2.9,<3.0   # added to requirements.txt
```

Optional at runtime — see "Backwards compatibility" above.

## Verification

```bash
python -m pytest tests/test_feature5_db_adapter.py -x --tb=short -q
# 6 passed
```

Beast Mode regression suite (phase4 / phase7 / phase9 / trustgraph) confirmed
green after the refactor.
