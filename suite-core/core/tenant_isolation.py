"""Tenant isolation utilities for ALDECI multi-tenancy.

Provides org-scoped SQLite paths, thread-local tenant context, access
validation, and administrative helpers for managing tenant data directories.

Usage::

    from core.tenant_isolation import (
        TenantContext, set_tenant, get_tenant, clear_tenant,
        tenant_scoped_db, TenantAwareConnection,
        ensure_tenant_directory, validate_tenant_access,
        list_tenants, delete_tenant_data, get_tenant_stats,
    )

    # Set the current tenant for this thread/task
    set_tenant("acme-corp")

    # Get org-scoped DB path
    db_path = tenant_scoped_db("findings", "acme-corp")
    # → "data/acme-corp/findings.db"
"""

from __future__ import annotations

import logging
import shutil
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.exceptions import TenantIsolationError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data root — can be overridden via ALDECI_DATA_ROOT env var
# ---------------------------------------------------------------------------

import os as _os

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


_DATA_ROOT = Path(_os.getenv("ALDECI_DATA_ROOT", "data"))


def _data_root() -> Path:
    """Return the current data root path (respects ALDECI_DATA_ROOT env var)."""
    return Path(_os.getenv("ALDECI_DATA_ROOT", "data"))


# ---------------------------------------------------------------------------
# TenantContext — thread-local storage for current org_id
# ---------------------------------------------------------------------------

class TenantContext:
    """Thread-local storage for the current request's org_id.

    Uses ``threading.local()`` so that each thread (including async worker
    threads) sees its own isolated tenant context.  For asyncio code running
    on a single thread, callers must explicitly set/clear the context.

    Example::

        TenantContext.set("acme-corp")
        assert TenantContext.get() == "acme-corp"
        TenantContext.clear()
        assert TenantContext.get() is None
    """

    _local: threading.local = threading.local()

    @classmethod
    def set(cls, org_id: str) -> None:
        """Set the current tenant org_id for this thread."""
        cls._local.org_id = org_id

    @classmethod
    def get(cls) -> Optional[str]:
        """Return the current tenant org_id or None if not set."""
        return getattr(cls._local, "org_id", None)

    @classmethod
    def clear(cls) -> None:
        """Clear the current tenant org_id for this thread."""
        cls._local.org_id = None


# ---------------------------------------------------------------------------
# Convenience module-level functions
# ---------------------------------------------------------------------------

def set_tenant(org_id: str) -> None:
    """Set the current tenant org_id for this thread.

    Args:
        org_id: Organisation identifier string.
    """
    if not org_id or not org_id.strip():
        raise ValueError("org_id must be a non-empty string")
    TenantContext.set(org_id.strip())
    logger.debug("Tenant context set: org_id=%s", org_id)


def get_tenant() -> Optional[str]:
    """Return the current tenant org_id or None if not set."""
    return TenantContext.get()


def clear_tenant() -> None:
    """Clear the current tenant context for this thread."""
    TenantContext.clear()
    logger.debug("Tenant context cleared")


# ---------------------------------------------------------------------------
# Org-scoped database path helper
# ---------------------------------------------------------------------------

def tenant_scoped_db(db_name: str, org_id: str) -> Path:
    """Return the org-scoped SQLite file path for a given database name.

    Path format: ``{data_root}/{org_id}/{db_name}.db``

    The parent directory is NOT created here — call
    ``ensure_tenant_directory(org_id)`` first if the directory may not exist.

    Args:
        db_name: Logical database name, e.g. ``"findings"``.
        org_id:  Organisation identifier string.

    Returns:
        ``pathlib.Path`` to the tenant-scoped SQLite file.

    Raises:
        ValueError: If db_name or org_id is empty.
    """
    if not db_name or not db_name.strip():
        raise ValueError("db_name must be a non-empty string")
    if not org_id or not org_id.strip():
        raise ValueError("org_id must be a non-empty string")

    return _data_root() / org_id.strip() / f"{db_name.strip()}.db"


# ---------------------------------------------------------------------------
# Directory management
# ---------------------------------------------------------------------------

def ensure_tenant_directory(org_id: str) -> Path:
    """Create the org data directory if it does not exist.

    Args:
        org_id: Organisation identifier string.

    Returns:
        ``pathlib.Path`` to the created (or existing) directory.

    Raises:
        ValueError: If org_id is empty.
    """
    if not org_id or not org_id.strip():
        raise ValueError("org_id must be a non-empty string")

    tenant_dir = _data_root() / org_id.strip()
    tenant_dir.mkdir(parents=True, exist_ok=True)
    logger.debug("Tenant directory ensured: %s", tenant_dir)
    return tenant_dir


# ---------------------------------------------------------------------------
# Access validation
# ---------------------------------------------------------------------------

def validate_tenant_access(request_org: str, resource_org: str) -> None:
    """Raise TenantIsolationError if request_org does not match resource_org.

    Args:
        request_org:  The org_id of the current authenticated request.
        resource_org: The org_id stored on the resource being accessed.

    Raises:
        TenantIsolationError: If the org IDs do not match.
        ValueError:           If either org_id is empty.
    """
    if not request_org or not request_org.strip():
        raise ValueError("request_org must be a non-empty string")
    if not resource_org or not resource_org.strip():
        raise ValueError("resource_org must be a non-empty string")

    if request_org.strip() != resource_org.strip():
        logger.warning(
            "Tenant isolation violation: request_org=%s resource_org=%s",
            request_org,
            resource_org,
        )
        raise TenantIsolationError(
            f"Access denied: request org '{request_org}' cannot access "
            f"resource belonging to org '{resource_org}'"
        )


# ---------------------------------------------------------------------------
# TenantAwareConnection — SQLite wrapper that auto-scopes queries
# ---------------------------------------------------------------------------

class TenantAwareConnection:
    """Thin SQLite connection wrapper that injects org_id WHERE clauses.

    Every ``execute()`` call that targets a ``SELECT``, ``UPDATE``, or
    ``DELETE`` statement will have ``AND org_id = ?`` appended to the WHERE
    clause (or a WHERE clause added if none exists) when no explicit
    ``org_id`` binding is present.

    Use this class for databases that store a shared table with an ``org_id``
    column rather than per-tenant database files.

    Example::

        conn = TenantAwareConnection("findings.db", org_id="acme-corp")
        rows = conn.execute("SELECT * FROM findings WHERE severity = ?", ("HIGH",))
        # Runs: SELECT * FROM findings WHERE severity = ? AND org_id = ?
        #       with params ("HIGH", "acme-corp")
    """

    def __init__(self, db_path: str | Path, org_id: str) -> None:
        if not org_id or not org_id.strip():
            raise ValueError("org_id must be a non-empty string")
        self._org_id = org_id.strip()
        self._conn = sqlite3.connect(str(db_path))
        self._conn.row_factory = sqlite3.Row

    # ------------------------------------------------------------------
    # Core execute with automatic org_id injection
    # ------------------------------------------------------------------

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        """Execute SQL, automatically appending org_id scoping.

        For SELECT / UPDATE / DELETE queries the org_id is injected.
        For INSERT and other DDL/DML statements it is passed through unchanged.

        Args:
            sql:    SQL query string.
            params: Positional parameters for the query.

        Returns:
            ``sqlite3.Cursor`` from the underlying connection.
        """
        upper = sql.strip().upper()
        if upper.startswith(("SELECT", "UPDATE", "DELETE")):
            sql, params = self._inject_org_id(sql, params)
        return self._conn.execute(sql, params)

    def _inject_org_id(self, sql: str, params: tuple) -> tuple[str, tuple]:
        """Append ``AND org_id = ?`` to existing WHERE or add a WHERE clause."""
        upper = sql.upper()
        if "WHERE" in upper:
            sql = sql.rstrip().rstrip(";") + " AND org_id = ?"
        else:
            # Find the end of the table reference (before ORDER/GROUP/LIMIT)
            for keyword in ("ORDER BY", "GROUP BY", "LIMIT", "HAVING"):
                idx = upper.find(keyword)
                if idx != -1:
                    sql = sql[:idx] + " WHERE org_id = ? " + sql[idx:]
                    return sql, params + (self._org_id,)
            sql = sql.rstrip().rstrip(";") + " WHERE org_id = ?"
        return sql, params + (self._org_id,)

    def commit(self) -> None:
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "TenantAwareConnection":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if exc_type is None:
            self.commit()
        self.close()


# ---------------------------------------------------------------------------
# Tenant administration helpers
# ---------------------------------------------------------------------------

def list_tenants() -> List[str]:
    """Return a sorted list of all org_id directories under the data root.

    Returns:
        List of org_id strings (directory names), sorted alphabetically.
        Returns an empty list if the data root does not exist.
    """
    root = _data_root()
    if not root.exists():
        return []
    return sorted(
        p.name for p in root.iterdir() if p.is_dir()
    )


def delete_tenant_data(org_id: str) -> None:
    """Remove all data for the given org (admin only — irreversible).

    Args:
        org_id: Organisation identifier whose data directory will be deleted.

    Raises:
        ValueError:  If org_id is empty.
        FileNotFoundError: If the tenant directory does not exist.
    """
    if not org_id or not org_id.strip():
        raise ValueError("org_id must be a non-empty string")

    tenant_dir = _data_root() / org_id.strip()
    if not tenant_dir.exists():
        raise FileNotFoundError(f"Tenant directory not found: {tenant_dir}")

    shutil.rmtree(tenant_dir)
    logger.warning("Tenant data deleted: org_id=%s path=%s", org_id, tenant_dir)


def get_tenant_stats(org_id: str) -> Dict[str, Any]:
    """Return statistics for the given org's data directory.

    Collects:
    - ``org_id``: the organisation identifier
    - ``data_dir``: absolute path to the tenant's data directory
    - ``exists``: whether the directory exists
    - ``databases``: dict mapping db filename → size in bytes
    - ``total_size_bytes``: total size of all files in the directory
    - ``database_count``: number of ``.db`` files

    Args:
        org_id: Organisation identifier.

    Returns:
        Dict with tenant statistics.

    Raises:
        ValueError: If org_id is empty.
    """
    if not org_id or not org_id.strip():
        raise ValueError("org_id must be a non-empty string")

    org_id = org_id.strip()
    tenant_dir = _data_root() / org_id

    stats: Dict[str, Any] = {
        "org_id": org_id,
        "data_dir": str(tenant_dir.resolve()),
        "exists": tenant_dir.exists(),
        "databases": {},
        "total_size_bytes": 0,
        "database_count": 0,
    }

    if not tenant_dir.exists():
        return stats

    total = 0
    db_files: Dict[str, int] = {}
    for f in tenant_dir.iterdir():
        if f.is_file():
            size = f.stat().st_size
            total += size
            if f.suffix == ".db":
                db_files[f.name] = size

    stats["databases"] = db_files
    stats["total_size_bytes"] = total
    stats["database_count"] = len(db_files)
    return stats


__all__ = [
    "TenantContext",
    "set_tenant",
    "get_tenant",
    "clear_tenant",
    "tenant_scoped_db",
    "TenantAwareConnection",
    "ensure_tenant_directory",
    "validate_tenant_access",
    "list_tenants",
    "delete_tenant_data",
    "get_tenant_stats",
]
