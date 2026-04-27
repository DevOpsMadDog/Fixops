"""
Persistent dictionary backends — SQLite (default) and PostgreSQL.

Drop-in replacement for ``dict`` that survives process restarts.
All values are JSON-serialised.  An in-memory cache keeps read
performance identical to a plain dict.

Usage (SQLite, default)::

    from core.persistent_store import PersistentDict, get_persistent_store

    _jobs = PersistentDict("bulk_jobs")
    _jobs["abc"] = {"status": "pending"}   # auto-persisted
    _jobs["abc"]["status"] = "running"     # in-place mutation – NOT auto-persisted
    _jobs.persist("abc")                   # explicit flush after mutation

Usage (PostgreSQL, via env vars)::

    # Set FIXOPS_DB_TYPE=postgres and FIXOPS_DB_DSN=postgresql://user:pass@host/db
    _jobs = get_persistent_store("bulk_jobs")   # returns PostgresPersistentDict

Usage (factory, always preferred)::

    from core.persistent_store import get_persistent_store

    _jobs = get_persistent_store("bulk_jobs")   # auto-selects backend
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, Iterator, Optional, Union

# ---------------------------------------------------------------------------
# TrustGraph event-bus wiring (auto-added by hub-wiring wave)
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload):  # type: ignore[no-untyped-def]
    """Emit an event to the TrustGraph event bus. Never raises.

    Hub-level emit so this engine module participates in second-brain coverage.
    Downstream callers are AQUA via blast-radius (depth ≤ 2).
    """
    if _get_tg_bus is None:
        return
    try:
        bus = _get_tg_bus()
        if bus is None:
            return
        emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
        if emit is None:
            return
        result = emit(event_type, payload)
        try:
            import asyncio as _aio
            import inspect as _insp
            if _insp.iscoroutine(result):
                try:
                    loop = _aio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    result.close()
        except Exception:  # pragma: no cover
            pass
    except Exception:  # pragma: no cover
        pass


# Module-load heartbeat — fires once per process so this file is observable
# in the TrustGraph second-brain, even if no public method is called yet.
try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass

_DEFAULT_DB = "data/state.db"
_logger = logging.getLogger(__name__)

# Only allow alphanumeric + underscore table names (defense-in-depth)
_SAFE_TABLE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


# ---------------------------------------------------------------------------
# SQLite backend (original implementation)
# ---------------------------------------------------------------------------

class PersistentDict:
    """Dict-like object backed by a single SQLite table."""

    def __init__(self, table: str, db_path: str = _DEFAULT_DB) -> None:
        if not _SAFE_TABLE_RE.match(table):
            raise ValueError(
                f"Invalid table name {table!r}: must match [A-Za-z_][A-Za-z0-9_]{{0,127}}"
            )
        self._table = table
        self._db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_table()
        self._cache: Dict[str, Any] = {}
        self._load_all()

    # -- SQLite helpers -------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self._db_path)
            self._local.conn = conn
        return conn

    def close(self) -> None:
        """Close the current thread's database connection."""
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
                pass
            self._local.conn = None

    def __del__(self) -> None:
        self.close()

    def _init_table(self) -> None:
        with self._conn() as conn:
            conn.execute(
                f"CREATE TABLE IF NOT EXISTS [{self._table}] "  # nosec B608 — table validated by _SAFE_TABLE_RE in __init__
                "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )

    def _load_all(self) -> None:
        with self._conn() as conn:
            for key, raw in conn.execute(f"SELECT key, value FROM [{self._table}]"):  # nosec B608 — table validated by _SAFE_TABLE_RE
                self._cache[key] = json.loads(raw)

    def _write(self, key: str, value: Any) -> None:
        with self._conn() as conn:
            conn.execute(
                f"INSERT OR REPLACE INTO [{self._table}] (key, value) VALUES (?, ?)",  # nosec B608 — table validated by _SAFE_TABLE_RE
                (key, json.dumps(value, default=str)),
            )

    def _delete(self, key: str) -> None:
        with self._conn() as conn:
            conn.execute(f"DELETE FROM [{self._table}] WHERE key = ?", (key,))  # nosec B608 — table validated by _SAFE_TABLE_RE

    # -- dict interface -------------------------------------------------------

    def __getitem__(self, key: str) -> Any:
        return self._cache[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self._cache[key] = value
        self._write(key, value)

    def __delitem__(self, key: str) -> None:
        del self._cache[key]
        self._delete(key)

    def __contains__(self, key: object) -> bool:
        return key in self._cache

    def __len__(self) -> int:
        return len(self._cache)

    def __iter__(self) -> Iterator[str]:
        return iter(self._cache)

    def __bool__(self) -> bool:
        return bool(self._cache)

    def get(self, key: str, default: Any = None) -> Any:
        return self._cache.get(key, default)

    def pop(self, key: str, *args: Any) -> Any:
        result = self._cache.pop(key, *args)
        self._delete(key)
        return result

    def setdefault(self, key: str, default: Any = None) -> Any:
        if key not in self._cache:
            self[key] = default
        return self._cache[key]

    def keys(self):  # noqa: ANN201
        return self._cache.keys()

    def values(self):  # noqa: ANN201
        return self._cache.values()

    def items(self):  # noqa: ANN201
        return self._cache.items()

    def clear(self) -> None:
        """Remove all entries from the dict and the backing store."""
        self._cache.clear()
        with self._conn() as conn:
            conn.execute(f"DELETE FROM [{self._table}]")  # nosec B608 — table validated by _SAFE_TABLE_RE

    def update(self, mapping: Any = (), **kwargs: Any) -> None:
        """Bulk update from a mapping or keyword arguments."""
        if hasattr(mapping, "items"):
            mapping = mapping.items()
        for key, value in mapping:
            self[key] = value
        for key, value in kwargs.items():
            self[key] = value

    # -- mutation helper ------------------------------------------------------

    def persist(self, key: str) -> None:
        """Flush a key to disk after in-place mutation of its value."""
        if key in self._cache:
            self._write(key, self._cache[key])

    def persist_all(self) -> None:
        """Flush every cached key to disk."""
        with self._conn() as conn:
            for key, value in self._cache.items():
                conn.execute(
                    f"INSERT OR REPLACE INTO [{self._table}] (key, value) VALUES (?, ?)",  # nosec B608 — table validated by _SAFE_TABLE_RE
                    (key, json.dumps(value, default=str)),
                )


# ---------------------------------------------------------------------------
# PostgreSQL backend
# ---------------------------------------------------------------------------

class PostgresPersistentDict:
    """
    Dict-like object backed by a PostgreSQL table.

    Identical public API to PersistentDict — fully interchangeable as a
    drop-in replacement.  Uses psycopg2 with a ThreadedConnectionPool so
    multiple FastAPI worker threads share connections efficiently.

    Schema (created automatically on init)::

        CREATE TABLE IF NOT EXISTS kv_{table} (
            key  TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

    The ``kv_`` prefix isolates these simple key-value tables from the
    domain tables managed by Alembic migrations.

    Args:
        table: Logical table name.  Must match [A-Za-z_][A-Za-z0-9_]{0,127}.
        dsn:   PostgreSQL DSN, e.g. ``postgresql://user:pass@host:5432/db``.
               Defaults to the ``FIXOPS_DB_DSN`` environment variable.
        minconn: Minimum connections to keep in pool (default 1).
        maxconn: Maximum connections in pool (default 10).
    """

    # Pool instances are shared per DSN to avoid spawning multiple pools for
    # the same database when multiple PostgresPersistentDict objects exist.
    _pool_registry: Dict[str, Any] = {}
    _pool_lock = threading.Lock()

    def __init__(
        self,
        table: str,
        dsn: Optional[str] = None,
        minconn: int = 1,
        maxconn: int = 10,
    ) -> None:
        if not _SAFE_TABLE_RE.match(table):
            raise ValueError(
                f"Invalid table name {table!r}: must match [A-Za-z_][A-Za-z0-9_]{{0,127}}"
            )

        self._table = f"kv_{table}"  # prefix to avoid collision with Alembic tables
        self._dsn = dsn or os.environ.get("FIXOPS_DB_DSN", "")
        if not self._dsn:
            raise ValueError(
                "PostgresPersistentDict requires a DSN. "
                "Pass dsn= or set FIXOPS_DB_DSN environment variable."
            )

        self._pool = self._get_or_create_pool(self._dsn, minconn, maxconn)
        self._cache: Dict[str, Any] = {}
        self._init_table()
        self._load_all()

    # -- Pool management ------------------------------------------------------

    @classmethod
    def _get_or_create_pool(cls, dsn: str, minconn: int, maxconn: int) -> Any:
        """Return an existing pool for this DSN or create a new one."""
        try:
            import psycopg2
            import psycopg2.pool
        except ImportError as exc:
            raise ImportError(
                "psycopg2 is required for PostgresPersistentDict. "
                "Install it with: pip install psycopg2-binary"
            ) from exc

        with cls._pool_lock:
            if dsn not in cls._pool_registry:
                pool = psycopg2.pool.ThreadedConnectionPool(
                    minconn=minconn,
                    maxconn=maxconn,
                    dsn=dsn,
                )
                cls._pool_registry[dsn] = pool
                _logger.info(
                    "Created PostgreSQL connection pool for persistent store "
                    "(min=%d max=%d)", minconn, maxconn
                )
            return cls._pool_registry[dsn]

    def _acquire(self):
        """Acquire a connection from the pool (context manager)."""
        return _PooledConnectionContext(self._pool)

    def close(self) -> None:
        """Return connections to pool. Pool itself remains alive (shared)."""
        # Individual connections are returned per-operation; nothing to close here.
        pass

    def __del__(self) -> None:
        self.close()

    # -- PostgreSQL helpers ---------------------------------------------------

    def _init_table(self) -> None:
        with self._acquire() as conn:
            with conn.cursor() as cur:
                cur.execute(  # nosec B608 — table validated by _SAFE_TABLE_RE in __init__
                    f"""
                    CREATE TABLE IF NOT EXISTS {self._table} (
                        key   TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    )
                    """
                )
            conn.commit()

    def _load_all(self) -> None:
        with self._acquire() as conn:
            with conn.cursor() as cur:
                cur.execute(f"SELECT key, value FROM {self._table}")  # nosec B608 — table validated by _SAFE_TABLE_RE in __init__
                for key, raw in cur.fetchall():
                    self._cache[key] = json.loads(raw)

    def _write(self, key: str, value: Any) -> None:
        serialised = json.dumps(value, default=str)
        with self._acquire() as conn:
            with conn.cursor() as cur:
                cur.execute(  # nosec B608 — table validated by _SAFE_TABLE_RE in __init__
                    f"""INSERT INTO {self._table} (key, value)VALUES (%s, %s)
                    ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
                    """,  # nosec B608
                    (key, serialised),
                )
            conn.commit()

    def _delete(self, key: str) -> None:
        with self._acquire() as conn:
            with conn.cursor() as cur:
                cur.execute(  # nosec B608 — table validated by _SAFE_TABLE_RE in __init__
                    f"DELETE FROM {self._table} WHERE key = %s", (key,)  # nosec B608
                )
            conn.commit()

    # -- dict interface -------------------------------------------------------

    def __getitem__(self, key: str) -> Any:
        return self._cache[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self._cache[key] = value
        self._write(key, value)

    def __delitem__(self, key: str) -> None:
        del self._cache[key]
        self._delete(key)

    def __contains__(self, key: object) -> bool:
        return key in self._cache

    def __len__(self) -> int:
        return len(self._cache)

    def __iter__(self) -> Iterator[str]:
        return iter(self._cache)

    def __bool__(self) -> bool:
        return bool(self._cache)

    def get(self, key: str, default: Any = None) -> Any:
        return self._cache.get(key, default)

    def pop(self, key: str, *args: Any) -> Any:
        result = self._cache.pop(key, *args)
        self._delete(key)
        return result

    def setdefault(self, key: str, default: Any = None) -> Any:
        if key not in self._cache:
            self[key] = default
        return self._cache[key]

    def keys(self):  # noqa: ANN201
        return self._cache.keys()

    def values(self):  # noqa: ANN201
        return self._cache.values()

    def items(self):  # noqa: ANN201
        return self._cache.items()

    def clear(self) -> None:
        """Remove all entries from the dict and the backing table."""
        self._cache.clear()
        with self._acquire() as conn:
            with conn.cursor() as cur:
                cur.execute(f"DELETE FROM {self._table}")  # nosec B608 — table validated by _SAFE_TABLE_RE in __init__
            conn.commit()

    def update(self, mapping: Any = (), **kwargs: Any) -> None:
        """Bulk update from a mapping or keyword arguments."""
        if hasattr(mapping, "items"):
            mapping = mapping.items()
        for key, value in mapping:
            self[key] = value
        for key, value in kwargs.items():
            self[key] = value

    # -- mutation helper ------------------------------------------------------

    def persist(self, key: str) -> None:
        """Flush a key to the database after in-place mutation of its value."""
        if key in self._cache:
            self._write(key, self._cache[key])

    def persist_all(self) -> None:
        """Flush every cached key to the database in a single transaction."""
        if not self._cache:
            return
        serialised = [
            (key, json.dumps(value, default=str))
            for key, value in self._cache.items()
        ]
        with self._acquire() as conn:
            with conn.cursor() as cur:
                for key, value in serialised:
                    cur.execute(
                        f"""INSERT INTO {self._table} (key, value)VALUES (%s, %s)
                        ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
                        """,  # nosec B608
                        (key, value),
                    )
            conn.commit()


# ---------------------------------------------------------------------------
# Context manager wrapper for pooled connections
# ---------------------------------------------------------------------------

class _PooledConnectionContext:
    """Context manager that acquires a connection from the pool and returns it."""

    def __init__(self, pool: Any) -> None:
        self._pool = pool
        self._conn: Any = None

    def __enter__(self):
        self._conn = self._pool.getconn()
        return self._conn

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._conn is not None:
            if exc_type is not None:
                try:
                    self._conn.rollback()
                except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
                    pass
            self._pool.putconn(self._conn)
            self._conn = None
        return False  # do not suppress exceptions


# ---------------------------------------------------------------------------
# Factory function — drop-in replacement selector
# ---------------------------------------------------------------------------

def get_persistent_store(
    table: str,
    dsn: Optional[str] = None,
    db_path: str = _DEFAULT_DB,
) -> Union[PersistentDict, PostgresPersistentDict]:
    """
    Return the appropriate persistent store backend based on environment config.

    Selection logic:
    - If ``FIXOPS_DB_TYPE=postgres`` AND (``dsn`` arg OR ``FIXOPS_DB_DSN`` env var)
      is set → return ``PostgresPersistentDict``
    - Otherwise → return ``PersistentDict`` (SQLite)

    This is the preferred constructor for all production code.  It allows
    switching from SQLite to PostgreSQL purely via environment variables,
    with no code changes required in callers.

    Args:
        table:   Logical table/namespace name.
        dsn:     Optional PostgreSQL DSN.  Falls back to ``FIXOPS_DB_DSN``.
        db_path: SQLite database file path (ignored for PostgreSQL).

    Returns:
        A ``PersistentDict`` or ``PostgresPersistentDict`` instance.

    Example::

        # In application code — backend is transparent
        _state = get_persistent_store("pipeline_runs")
        _state["run-123"] = {"status": "running"}
    """
    db_type = os.environ.get("FIXOPS_DB_TYPE", "sqlite").lower().strip()
    effective_dsn = dsn or os.environ.get("FIXOPS_DB_DSN", "").strip()

    if db_type == "postgres" and effective_dsn:
        _logger.info(
            "get_persistent_store(%r): using PostgreSQL backend", table
        )
        return PostgresPersistentDict(table=table, dsn=effective_dsn)

    if db_type == "postgres" and not effective_dsn:
        _logger.warning(
            "get_persistent_store(%r): FIXOPS_DB_TYPE=postgres but FIXOPS_DB_DSN "
            "is not set — falling back to SQLite", table
        )

    return PersistentDict(table=table, db_path=db_path)


__all__ = [
    "PersistentDict",
    "PostgresPersistentDict",
    "get_persistent_store",
]
