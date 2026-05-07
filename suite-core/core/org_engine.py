"""Org Management Engine — ALDECI multi-tenancy.

Provides organisation listing, creation, and summary across all engine
SQLite databases.  Each engine stores data keyed by ``org_id``; this engine
discovers all known tenants by scanning those databases for distinct
``org_id`` values.

Patterns:
    - WAL mode + RLock for thread safety
    - Single SQLite registry at data/orgs.db
    - Separate scan of engine DBs to collect known org_ids
    - org_id isolation enforced throughout
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# TrustGraph second-brain wiring
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload: dict) -> None:
    """Emit to TrustGraph event bus. Never raises."""
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


try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass

import glob
import logging
import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

_logger = logging.getLogger(__name__)

# Default location for the org registry DB
_DEFAULT_DB = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..",
    "..",
    "data",
    "orgs.db",
)

# Root of all engine databases (suite-core/core/)
_ENGINE_DB_GLOB = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "*.db",
)

# Also scan suite-api data dir
_API_DATA_GLOB = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..",
    "..",
    "data",
    "*.db",
)


class OrgEngine:
    """Registry for organisations with cross-DB discovery.

    Args:
        db_path: Path to the org registry SQLite file.  Defaults to
            ``data/orgs.db`` two levels above this file.
        engine_db_globs: Additional glob patterns to scan for engine DBs
            when discovering org_ids.  Defaults to the core/ directory and
            the data/ directory.
    """

    def __init__(
        self,
        db_path: Optional[str] = None,
        engine_db_globs: Optional[List[str]] = None,
    ) -> None:
        self._db_path = db_path or _DEFAULT_DB
        self._engine_db_globs: List[str] = engine_db_globs if engine_db_globs is not None else [
            _ENGINE_DB_GLOB,
            _API_DATA_GLOB,
        ]
        self._lock = threading.RLock()
        os.makedirs(os.path.dirname(os.path.abspath(self._db_path)), exist_ok=True)
        self._init_db()

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS orgs (
                        org_id      TEXT PRIMARY KEY,
                        name        TEXT NOT NULL,
                        description TEXT DEFAULT '',
                        created_at  TEXT NOT NULL,
                        is_active   INTEGER NOT NULL DEFAULT 1
                    )
                """)
                conn.commit()
                # Ensure the built-in "default" org always exists
                conn.execute("""
                    INSERT OR IGNORE INTO orgs (org_id, name, description, created_at, is_active)
                    VALUES ('default', 'Default Organization', 'Built-in default tenant', ?, 1)
                """, (datetime.now(timezone.utc).isoformat(),))
                conn.commit()
            finally:
                conn.close()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def list_orgs(self, include_discovered: bool = True) -> List[Dict[str, Any]]:
        """Return all known organisations.

        Args:
            include_discovered: When True (default), also returns org_ids
                discovered from engine databases that are not yet in the
                registry (marked as ``source: "discovered"``).

        Returns:
            List of org dicts sorted by org_id.
        """
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT org_id, name, description, created_at, is_active FROM orgs ORDER BY org_id"
                ).fetchall()
                registered: Dict[str, Dict[str, Any]] = {
                    r["org_id"]: {
                        "org_id": r["org_id"],
                        "name": r["name"],
                        "description": r["description"],
                        "created_at": r["created_at"],
                        "is_active": bool(r["is_active"]),
                        "source": "registry",
                    }
                    for r in rows
                }
            finally:
                conn.close()

        result = list(registered.values())

        if include_discovered:
            for discovered_id in self._discover_org_ids():
                if discovered_id not in registered:
                    result.append({
                        "org_id": discovered_id,
                        "name": discovered_id,
                        "description": "Discovered from engine databases",
                        "created_at": None,
                        "is_active": True,
                        "source": "discovered",
                    })

        result.sort(key=lambda x: x["org_id"])
        return result

    def create_org(self, org_id: str, name: str, description: str = "") -> Dict[str, Any]:
        """Create a new organisation in the registry.

        Args:
            org_id: Unique identifier (slug-style, e.g. ``acme-corp``).
            name: Human-readable display name.
            description: Optional description.

        Returns:
            The created org dict.

        Raises:
            ValueError: If org_id is empty or already exists.
        """
        if not org_id or not org_id.strip():
            raise ValueError("org_id must not be empty")
        org_id = org_id.strip()
        name = (name or org_id).strip()

        with self._lock:
            conn = self._connect()
            try:
                existing = conn.execute(
                    "SELECT org_id FROM orgs WHERE org_id = ?", (org_id,)
                ).fetchone()
                if existing:
                    raise ValueError(f"Organisation '{org_id}' already exists")

                created_at = datetime.now(timezone.utc).isoformat()
                conn.execute(
                    """
                    INSERT INTO orgs (org_id, name, description, created_at, is_active)
                    VALUES (?, ?, ?, ?, 1)
                    """,
                    (org_id, name, description, created_at),
                )
                conn.commit()
                _emit_event("org_engine.org_created", {
                    "org_id": org_id,
                    "name": name,
                    "created_at": created_at,
                })
                return {
                    "org_id": org_id,
                    "name": name,
                    "description": description,
                    "created_at": created_at,
                    "is_active": True,
                    "source": "registry",
                }
            finally:
                conn.close()

    def get_org(self, org_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single org from the registry (does not scan engine DBs).

        Returns:
            Org dict or None if not found.
        """
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT org_id, name, description, created_at, is_active FROM orgs WHERE org_id = ?",
                    (org_id,),
                ).fetchone()
            finally:
                conn.close()
        if row is None:
            return None
        return {
            "org_id": row["org_id"],
            "name": row["name"],
            "description": row["description"],
            "created_at": row["created_at"],
            "is_active": bool(row["is_active"]),
            "source": "registry",
        }

    def soft_delete_org(self, org_id: str) -> Dict[str, Any]:
        """Soft-delete an org: set deleted_at + status=DELETED.

        The org row is NOT removed; a hard purge job removes all data after
        30 days.  The built-in 'default' org may not be deleted.

        Args:
            org_id: Organisation to mark for deletion.

        Returns:
            Updated org dict with deleted_at timestamp.

        Raises:
            ValueError: If org_id is 'default' or not found.
        """
        if org_id == "default":
            raise ValueError("The built-in 'default' org cannot be deleted")

        with self._lock:
            conn = self._connect()
            try:
                # Ensure columns exist (idempotent migrations)
                existing_cols = [
                    c[1]
                    for c in conn.execute("PRAGMA table_info(orgs)").fetchall()
                ]
                if "deleted_at" not in existing_cols:
                    conn.execute("ALTER TABLE orgs ADD COLUMN deleted_at TEXT DEFAULT NULL")
                if "status" not in existing_cols:
                    conn.execute("ALTER TABLE orgs ADD COLUMN status TEXT DEFAULT 'ACTIVE'")
                conn.commit()

                row = conn.execute(
                    "SELECT org_id, name, description, created_at, is_active FROM orgs WHERE org_id = ?",
                    (org_id,),
                ).fetchone()
                if row is None:
                    raise ValueError(f"Organisation '{org_id}' not found")

                deleted_at = datetime.now(timezone.utc).isoformat()
                conn.execute(
                    "UPDATE orgs SET deleted_at = ?, status = 'DELETED', is_active = 0 WHERE org_id = ?",
                    (deleted_at, org_id),
                )
                conn.commit()
            finally:
                conn.close()

        _emit_event("org_engine.org_soft_deleted", {"org_id": org_id, "deleted_at": deleted_at})
        return {
            "org_id": org_id,
            "status": "DELETED",
            "deleted_at": deleted_at,
            "purge_after_days": 30,
        }

    def hard_purge_org(self, org_id: str, *, _force: bool = False) -> Dict[str, Any]:
        """Hard-purge all data for an org from the registry and engine tables.

        Only executes when the org has been soft-deleted for >= 30 days,
        unless ``_force=True`` (used by the purge job for exactly-30d orgs).

        Removes rows from:
          - orgs registry (this DB)
          - findings / incidents / audit_events / users tables in engine DBs
            (any table whose columns include org_id)

        Args:
            org_id: Organisation to purge.
            _force: Skip age check (caller guarantees 30d elapsed).

        Returns:
            Dict with purge statistics.

        Raises:
            ValueError: If org not soft-deleted or 30d window not elapsed.
        """
        from datetime import timedelta

        with self._lock:
            conn = self._connect()
            try:
                existing_cols = [
                    c[1]
                    for c in conn.execute("PRAGMA table_info(orgs)").fetchall()
                ]
                has_deleted_at = "deleted_at" in existing_cols
                has_status = "status" in existing_cols

                if not has_deleted_at or not has_status:
                    raise ValueError(f"Organisation '{org_id}' has not been soft-deleted")

                row = conn.execute(
                    "SELECT org_id, deleted_at, status FROM orgs WHERE org_id = ?",
                    (org_id,),
                ).fetchone()
                if row is None:
                    raise ValueError(f"Organisation '{org_id}' not found")
                if row["status"] != "DELETED" or row["deleted_at"] is None:
                    raise ValueError(f"Organisation '{org_id}' has not been soft-deleted")

                if not _force:
                    deleted_at_dt = datetime.fromisoformat(row["deleted_at"])
                    if deleted_at_dt.tzinfo is None:
                        deleted_at_dt = deleted_at_dt.replace(tzinfo=timezone.utc)
                    age = datetime.now(timezone.utc) - deleted_at_dt
                    if age < timedelta(days=30):
                        days_remaining = 30 - age.days
                        raise ValueError(
                            f"Organisation '{org_id}' cannot be purged yet — "
                            f"{days_remaining} day(s) remaining before 30-day window elapses"
                        )

                conn.execute("DELETE FROM orgs WHERE org_id = ?", (org_id,))
                conn.commit()
            finally:
                conn.close()

        # Purge from all engine DBs (findings / incidents / audit_events / users)
        _PURGE_TABLES = {"findings", "incidents", "audit_events", "users", "security_findings"}
        purged_tables: list[str] = []
        rows_deleted = 0

        for db_file in self._all_engine_db_files():
            try:
                conn2 = sqlite3.connect(db_file, check_same_thread=False, timeout=5)
                try:
                    tables = [
                        r[0]
                        for r in conn2.execute(
                            "SELECT name FROM sqlite_master WHERE type='table'"
                        ).fetchall()
                    ]
                    for table in tables:
                        if table not in _PURGE_TABLES:
                            continue
                        cols = [
                            c[1]
                            for c in conn2.execute(f"PRAGMA table_info({table})").fetchall()
                        ]
                        if "org_id" not in cols:
                            continue
                        n = conn2.execute(
                            f"DELETE FROM {table} WHERE org_id = ?", (org_id,)
                        ).rowcount
                        if n:
                            purged_tables.append(f"{os.path.basename(db_file)}:{table}")
                            rows_deleted += n
                    conn2.commit()
                finally:
                    conn2.close()
            except Exception:  # noqa: BLE001
                pass

        _emit_event("org_engine.org_hard_purged", {
            "org_id": org_id,
            "rows_deleted": rows_deleted,
            "tables": purged_tables,
        })
        return {
            "org_id": org_id,
            "status": "PURGED",
            "rows_deleted": rows_deleted,
            "tables_purged": purged_tables,
        }

    def get_org_summary(self, org_id: str) -> Dict[str, Any]:
        """Return a dashboard summary for an org.

        Counts how many engine databases contain data for this org_id.

        Args:
            org_id: Organisation to summarise.

        Returns:
            Dict with org metadata and engine coverage stats.
        """
        org = self.get_org(org_id)
        if org is None:
            # Could be a discovered org — synthesise minimal metadata
            org = {
                "org_id": org_id,
                "name": org_id,
                "description": "",
                "created_at": None,
                "is_active": True,
                "source": "discovered",
            }

        db_files = self._all_engine_db_files()
        engines_with_data: List[str] = []
        total_rows = 0

        for db_file in db_files:
            try:
                count, tables = self._count_rows_for_org(db_file, org_id)
                if count > 0:
                    engines_with_data.append(os.path.basename(db_file))
                    total_rows += count
            except Exception:  # noqa: BLE001
                pass  # skip unreadable DBs

        return {
            **org,
            "summary": {
                "engines_with_data": len(engines_with_data),
                "total_rows": total_rows,
                "engine_files": engines_with_data,
            },
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _all_engine_db_files(self) -> List[str]:
        """Return all SQLite DB file paths from configured glob patterns."""
        files: List[str] = []
        for pattern in self._engine_db_globs:
            files.extend(glob.glob(pattern))
        # Exclude the org registry itself
        own = os.path.abspath(self._db_path)
        return [f for f in files if os.path.abspath(f) != own]

    def _discover_org_ids(self) -> List[str]:
        """Scan all engine DBs and collect distinct org_id values."""
        discovered: set[str] = set()
        for db_file in self._all_engine_db_files():
            try:
                org_ids = self._scan_db_for_org_ids(db_file)
                discovered.update(org_ids)
            except Exception:  # noqa: BLE001
                pass
        # Filter out empty/None and the sentinel "default" (always in registry)
        return [o for o in discovered if o and o != "default"]

    def _scan_db_for_org_ids(self, db_path: str) -> List[str]:
        """Return all distinct org_id values from a single SQLite file."""
        results: List[str] = []
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=2)
            conn.row_factory = sqlite3.Row
            try:
                tables = [
                    r[0]
                    for r in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    ).fetchall()
                ]
                for table in tables:
                    # Check if table has an org_id column
                    try:
                        cols = [
                            c[1]
                            for c in conn.execute(
                                f"PRAGMA table_info({table})"
                            ).fetchall()
                        ]
                        if "org_id" not in cols:
                            continue
                        rows = conn.execute(
                            f"SELECT DISTINCT org_id FROM {table} WHERE org_id IS NOT NULL AND org_id != ''"
                        ).fetchall()
                        results.extend(r[0] for r in rows)
                    except sqlite3.OperationalError:
                        continue
            finally:
                conn.close()
        except (sqlite3.OperationalError, sqlite3.DatabaseError):
            pass
        return results

    def _count_rows_for_org(self, db_path: str, org_id: str):
        """Return (total_rows, tables_with_data) for an org in a single DB."""
        total = 0
        tables_with_data: List[str] = []
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=2)
        try:
            tables = [
                r[0]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            ]
            for table in tables:
                try:
                    cols = [
                        c[1]
                        for c in conn.execute(f"PRAGMA table_info({table})").fetchall()
                    ]
                    if "org_id" not in cols:
                        continue
                    count = conn.execute(
                        f"SELECT COUNT(*) FROM {table} WHERE org_id = ?", (org_id,)
                    ).fetchone()[0]
                    if count > 0:
                        tables_with_data.append(table)
                        total += count
                except sqlite3.OperationalError:
                    continue
        finally:
            conn.close()
        return total, tables_with_data
