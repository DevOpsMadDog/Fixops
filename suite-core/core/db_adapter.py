"""DBAdapter — thin abstraction over sqlite3 + psycopg2.

FEATURE-5 (founder spec): Replace SQLite with PostgreSQL for production deployments.

Design principles:
- **Backwards compatible by default**: empty/missing DATABASE_URL → sqlite3 path unchanged.
- **Zero-config dev mode**: every existing engine continues to work without code changes
  if DATABASE_URL is unset.
- **Graceful degradation**: if DATABASE_URL is set but psycopg2 is unimportable,
  emit a structlog warning and fall back to sqlite (so test environments without
  psycopg2-binary installed still pass).
- **Placeholder rewriter**: SQL written with `?` placeholders (sqlite style) gets
  auto-rewritten to `%s` when running on postgres. Engines do NOT need to rewrite
  their queries.
- **Context-managed transactions**: `with adapter.connect() as conn:` commits on
  success, rolls back on exception, always closes.

Scope (Phase 1):
- Provides `.connect()` / `.adapt_sql()` for engines that use per-call connections
  (cspm, application_security, ir_playbook).
- For engines using long-lived persistent connections (ctem, asset_inventory),
  the adapter exposes `.persistent_connect()` which returns a single shared connection
  — sqlite mode keeps existing semantics; postgres mode uses one persistent psycopg2
  connection with autocommit=False (caller must `.commit()`).

Out of scope (Phase 2):
- Schema migrations between sqlite and postgres dialects.
- Async (asyncpg) — runtime is still sync today.
- Connection pooling — single connection per call is fine for the 5 priority engines.
"""

from __future__ import annotations

import contextlib
import os
import sqlite3
import threading
from pathlib import Path
from typing import Any, Iterator, Optional

import structlog

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Backend detection
# ---------------------------------------------------------------------------


def _database_url() -> str:
    return os.environ.get("DATABASE_URL", "").strip()


def is_postgres_url(url: Optional[str] = None) -> bool:
    """Return True if DATABASE_URL points at a postgres backend."""
    target = url if url is not None else _database_url()
    return target.startswith(("postgres://", "postgresql://", "postgresql+psycopg2://"))


def is_postgres_async_url(url: Optional[str] = None) -> bool:
    """Return True if DATABASE_URL points at an async postgres backend (asyncpg)."""
    target = url if url is not None else _database_url()
    return target.startswith(("postgresql+asyncpg://",))


def _normalize_dsn(url: str) -> str:
    """Strip SQLAlchemy driver prefix (`postgresql+psycopg2://`) for psycopg2."""
    if url.startswith("postgresql+psycopg2://"):
        return "postgresql://" + url[len("postgresql+psycopg2://"):]
    return url


# ---------------------------------------------------------------------------
# DBAdapter
# ---------------------------------------------------------------------------


class DBAdapter:
    """Thin abstraction over sqlite3 + psycopg2.

    Engines instantiate this with their fallback sqlite path and use:

        self._db = get_adapter(self.db_path)
        with self._db.connect() as conn:
            conn.execute(self._db.adapt_sql("SELECT * FROM t WHERE id = ?"), (x,))

    For persistent-connection engines (ctem, asset_inventory):

        self._db = get_adapter(self.db_path)
        self._conn = self._db.persistent_connect()
        # use self._conn.execute(...) as before
    """

    def __init__(self, sqlite_path: str) -> None:
        self.sqlite_path = sqlite_path
        self.dsn = _normalize_dsn(_database_url())
        self.is_postgres = is_postgres_url()
        self._psycopg2: Any = None
        self._persistent_conn: Any = None
        self._persistent_lock = threading.Lock()

        if self.is_postgres:
            try:
                import psycopg2  # noqa: WPS433

                self._psycopg2 = psycopg2
                logger.info(
                    "DBAdapter: using PostgreSQL backend",
                    sqlite_fallback=sqlite_path,
                )
            except ImportError:
                logger.warning(
                    "DATABASE_URL is set but psycopg2 is not installed — "
                    "falling back to sqlite. Install psycopg2-binary to enable postgres.",
                    sqlite_fallback=sqlite_path,
                )
                self.is_postgres = False

        # Ensure the sqlite parent directory exists when we're on the sqlite path
        if not self.is_postgres:
            parent = Path(self.sqlite_path).parent
            if str(parent) and parent != Path(""):
                parent.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Per-call connections (for cspm, application_security, ir_playbook)
    # ------------------------------------------------------------------

    @contextlib.contextmanager
    def connect(self) -> Iterator[Any]:
        """Context-managed per-call connection.

        - sqlite: returns sqlite3.Connection with row_factory=sqlite3.Row,
          check_same_thread=False, timeout=10.
        - postgres: returns psycopg2.connection.

        Commits on success, rolls back on exception, always closes.
        """
        if self.is_postgres:
            conn = self._psycopg2.connect(self.dsn)
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()
        else:
            conn = sqlite3.connect(self.sqlite_path, check_same_thread=False, timeout=10)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    # ------------------------------------------------------------------
    # Persistent shared connection (for ctem, asset_inventory)
    # ------------------------------------------------------------------

    def persistent_connect(self) -> Any:
        """Return a long-lived shared connection.

        - sqlite: returns sqlite3.Connection with WAL/synchronous PRAGMAs set,
          row_factory=Row, check_same_thread=False.
        - postgres: returns psycopg2.connection (no autocommit — caller commits).

        Caller is responsible for `.commit()` and `.close()` (typically at process
        shutdown). Re-using the same connection across calls within the engine.
        """
        with self._persistent_lock:
            if self._persistent_conn is not None:
                return self._persistent_conn

            if self.is_postgres:
                conn = self._psycopg2.connect(self.dsn)
            else:
                conn = sqlite3.connect(self.sqlite_path, check_same_thread=False)
                conn.row_factory = sqlite3.Row
                # Match the WAL/synchronous=NORMAL tuning the persistent engines
                # were using before the adapter was introduced.
                try:
                    conn.execute("PRAGMA journal_mode=WAL")
                    conn.execute("PRAGMA synchronous=NORMAL")
                except sqlite3.DatabaseError:
                    # In-memory DBs or some test fixtures may reject PRAGMAs;
                    # they are non-critical for correctness, only for performance.
                    pass

            self._persistent_conn = conn
            return conn

    # ------------------------------------------------------------------
    # SQL placeholder rewriter
    # ------------------------------------------------------------------

    def adapt_sql(self, sql: str) -> str:
        """Rewrite `?` placeholders to `%s` for postgres.

        Engines write their parameterized queries with sqlite-style `?`
        placeholders. When running on postgres we replace `?` with `%s` (the
        psycopg2 parameter style).

        Caveat: this is a string replace, so if a literal `?` appears inside a
        quoted string in your SQL it WILL be rewritten too. None of the 5
        priority engines use literal `?` in string literals (audited 2026-05-02).
        For future engines that need it, escape via `??` and post-process, or
        use named parameters with `:name` syntax (psycopg2 supports both).
        """
        if self.is_postgres:
            return sql.replace("?", "%s")
        return sql

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def backend_name(self) -> str:
        """Return 'postgres' or 'sqlite' for logging/diagnostics."""
        return "postgres" if self.is_postgres else "sqlite"


# ---------------------------------------------------------------------------
# Module-level factory
# ---------------------------------------------------------------------------


def get_adapter(sqlite_path: str) -> DBAdapter:
    """Construct a DBAdapter. Always returns a fresh instance — engines own
    their own adapter so each engine can have its own sqlite fallback path."""
    return DBAdapter(sqlite_path)


__all__ = [
    "DBAdapter",
    "get_adapter",
    "is_postgres_url",
    "is_postgres_async_url",
]
