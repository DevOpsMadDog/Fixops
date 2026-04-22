"""Configuration Management Database (CMDB) Engine — ALDECI.

Tracks configuration items (CIs), their relationships, and change history.
Provides a foundation for impact analysis, compliance, and asset risk scoring.

Compliance: ITIL v4, ISO 20000, CIS Controls v8 1.x/2.x
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "cmdb.db"
)

_VALID_CI_TYPES = {
    "server", "vm", "container", "database", "application",
    "network_device", "storage", "cloud_resource",
}

_VALID_CI_STATUSES = {"active", "decommissioned", "maintenance"}
_VALID_ENVIRONMENTS = {"prod", "staging", "dev", "dr"}
_VALID_CRITICALITIES = {"low", "medium", "high", "critical"}
_VALID_REL_TYPES = {"depends_on", "hosts", "connects_to", "backs_up", "manages"}
_VALID_CHANGE_TYPES = {"created", "updated", "decommissioned", "patched", "config_change", "incident"}


class CMDBEngine:
    """SQLite WAL-backed Configuration Management Database engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS ci_items (
                    ci_id        TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    name         TEXT NOT NULL,
                    ci_type      TEXT NOT NULL,
                    category     TEXT NOT NULL DEFAULT '',
                    owner        TEXT NOT NULL DEFAULT '',
                    status       TEXT NOT NULL DEFAULT 'active',
                    environment  TEXT NOT NULL DEFAULT 'prod',
                    location     TEXT NOT NULL DEFAULT '',
                    ip_address   TEXT NOT NULL DEFAULT '',
                    os           TEXT NOT NULL DEFAULT '',
                    version      TEXT NOT NULL DEFAULT '',
                    criticality  TEXT NOT NULL DEFAULT 'medium',
                    support_tier TEXT NOT NULL DEFAULT '',
                    tags         TEXT NOT NULL DEFAULT '[]',
                    created_at   DATETIME NOT NULL,
                    updated_at   DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ci_org
                    ON ci_items (org_id, ci_type, status, environment);

                CREATE TABLE IF NOT EXISTS ci_relationships (
                    rel_id      TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    src_ci_id   TEXT NOT NULL,
                    dst_ci_id   TEXT NOT NULL,
                    rel_type    TEXT NOT NULL,
                    created_at  DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ci_rel_org
                    ON ci_relationships (org_id, src_ci_id, dst_ci_id);

                CREATE TABLE IF NOT EXISTS ci_changes (
                    change_id    TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    ci_id        TEXT NOT NULL,
                    change_type  TEXT NOT NULL,
                    description  TEXT NOT NULL DEFAULT '',
                    changed_by   TEXT NOT NULL DEFAULT '',
                    change_date  DATETIME NOT NULL,
                    created_at   DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ci_changes_org
                    ON ci_changes (org_id, ci_id, change_date);

                CREATE TABLE IF NOT EXISTS ci_categories (
                    category_id TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    name        TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    created_at  DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ci_categories_org
                    ON ci_categories (org_id);

                -- GAP-059: shadow AI flags keyed to arbitrary asset references.
                -- Reused across cmdb CIs, cloud inventory ids, and identity ids.
                CREATE TABLE IF NOT EXISTS shadow_ai_flags (
                    id         TEXT PRIMARY KEY,
                    org_id     TEXT NOT NULL,
                    asset_ref  TEXT NOT NULL,
                    reason     TEXT NOT NULL DEFAULT '',
                    flagged_at DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_shadow_ai_flags_org
                    ON shadow_ai_flags (org_id, asset_ref);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        if "tags" in d:
            try:
                d["tags"] = json.loads(d["tags"] or "[]")
            except (json.JSONDecodeError, TypeError):
                d["tags"] = []
        return d

    # ------------------------------------------------------------------
    # CI CRUD
    # ------------------------------------------------------------------

    def add_ci(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a configuration item. Returns the full CI dict."""
        name = data.get("name", "")
        if not name:
            raise ValueError("name is required")

        ci_type = data.get("ci_type", "")
        if ci_type not in _VALID_CI_TYPES:
            raise ValueError(f"ci_type must be one of {sorted(_VALID_CI_TYPES)}")

        status = data.get("status", "active")
        if status not in _VALID_CI_STATUSES:
            raise ValueError(f"status must be one of {sorted(_VALID_CI_STATUSES)}")

        environment = data.get("environment", "prod")
        if environment not in _VALID_ENVIRONMENTS:
            raise ValueError(f"environment must be one of {sorted(_VALID_ENVIRONMENTS)}")

        criticality = data.get("criticality", "medium")
        if criticality not in _VALID_CRITICALITIES:
            raise ValueError(f"criticality must be one of {sorted(_VALID_CRITICALITIES)}")

        ci_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        tags = json.dumps(data.get("tags", []))

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO ci_items
                        (ci_id, org_id, name, ci_type, category, owner, status,
                         environment, location, ip_address, os, version,
                         criticality, support_tier, tags, created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        ci_id, org_id, name, ci_type,
                        data.get("category", ""),
                        data.get("owner", ""),
                        status, environment,
                        data.get("location", ""),
                        data.get("ip_address", ""),
                        data.get("os", ""),
                        data.get("version", ""),
                        criticality,
                        data.get("support_tier", ""),
                        tags, now, now,
                    ),
                )

        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ASSET_DISCOVERED", {"entity_type": "cmdb", "org_id": org_id, "source_engine": "cmdb"})
            except Exception:
                pass

        return {
            "ci_id": ci_id,
            "org_id": org_id,
            "name": name,
            "ci_type": ci_type,
            "category": data.get("category", ""),
            "owner": data.get("owner", ""),
            "status": status,
            "environment": environment,
            "location": data.get("location", ""),
            "ip_address": data.get("ip_address", ""),
            "os": data.get("os", ""),
            "version": data.get("version", ""),
            "criticality": criticality,
            "support_tier": data.get("support_tier", ""),
            "tags": data.get("tags", []),
            "created_at": now,
            "updated_at": now,
        }

    def list_cis(
        self,
        org_id: str,
        ci_type: Optional[str] = None,
        status: Optional[str] = None,
        environment: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List CIs for an org with optional filters."""
        query = "SELECT * FROM ci_items WHERE org_id=?"
        params: list = [org_id]

        if ci_type is not None:
            query += " AND ci_type=?"
            params.append(ci_type)
        if status is not None:
            query += " AND status=?"
            params.append(status)
        if environment is not None:
            query += " AND environment=?"
            params.append(environment)

        query += " ORDER BY criticality DESC, name ASC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_ci(self, org_id: str, ci_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single CI scoped to org."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM ci_items WHERE ci_id=? AND org_id=?",
                (ci_id, org_id),
            ).fetchone()
        return self._row_to_dict(row) if row else None

    def update_ci(self, org_id: str, ci_id: str, data: Dict[str, Any]) -> bool:
        """Update allowed fields on a CI. Returns True if updated."""
        allowed = {
            "name", "category", "owner", "status", "environment",
            "location", "ip_address", "os", "version",
            "criticality", "support_tier", "tags",
        }
        fields = {k: v for k, v in data.items() if k in allowed}
        if not fields:
            return False

        if "tags" in fields:
            fields["tags"] = json.dumps(fields["tags"])

        fields["updated_at"] = datetime.now(timezone.utc).isoformat()
        set_clause = ", ".join(f"{k}=?" for k in fields)
        values = list(fields.values()) + [ci_id, org_id]

        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    f"UPDATE ci_items SET {set_clause} WHERE ci_id=? AND org_id=?",  # nosec B608
                    values,
                )
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Relationships
    # ------------------------------------------------------------------

    def add_relationship(
        self,
        org_id: str,
        src_ci_id: str,
        dst_ci_id: str,
        rel_type: str,
    ) -> Dict[str, Any]:
        """Add a directional relationship between two CIs. Returns the relationship dict."""
        if rel_type not in _VALID_REL_TYPES:
            raise ValueError(f"rel_type must be one of {sorted(_VALID_REL_TYPES)}")

        rel_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO ci_relationships
                        (rel_id, org_id, src_ci_id, dst_ci_id, rel_type, created_at)
                    VALUES (?,?,?,?,?,?)
                    """,
                    (rel_id, org_id, src_ci_id, dst_ci_id, rel_type, now),
                )

        return {
            "rel_id": rel_id,
            "org_id": org_id,
            "src_ci_id": src_ci_id,
            "dst_ci_id": dst_ci_id,
            "rel_type": rel_type,
            "created_at": now,
        }

    def list_relationships(
        self,
        org_id: str,
        ci_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List relationships for an org. Optionally filter by CI (src or dst)."""
        if ci_id is not None:
            query = (
                "SELECT * FROM ci_relationships WHERE org_id=? "
                "AND (src_ci_id=? OR dst_ci_id=?) ORDER BY created_at DESC"
            )
            params = [org_id, ci_id, ci_id]
        else:
            query = "SELECT * FROM ci_relationships WHERE org_id=? ORDER BY created_at DESC"
            params = [org_id]

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Change records
    # ------------------------------------------------------------------

    def record_change(
        self,
        org_id: str,
        ci_id: str,
        change_type: str,
        description: str,
        changed_by: str,
        change_date: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Record a change event for a CI. Returns the change record dict."""
        change_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        effective_date = change_date or now

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO ci_changes
                        (change_id, org_id, ci_id, change_type, description,
                         changed_by, change_date, created_at)
                    VALUES (?,?,?,?,?,?,?,?)
                    """,
                    (
                        change_id, org_id, ci_id, change_type,
                        description, changed_by, effective_date, now,
                    ),
                )

        return {
            "change_id": change_id,
            "org_id": org_id,
            "ci_id": ci_id,
            "change_type": change_type,
            "description": description,
            "changed_by": changed_by,
            "change_date": effective_date,
            "created_at": now,
        }

    def list_changes(
        self,
        org_id: str,
        ci_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List change records for an org, optionally filtered by CI."""
        if ci_id is not None:
            query = (
                "SELECT * FROM ci_changes WHERE org_id=? AND ci_id=? "
                "ORDER BY change_date DESC"
            )
            params = [org_id, ci_id]
        else:
            query = "SELECT * FROM ci_changes WHERE org_id=? ORDER BY change_date DESC"
            params = [org_id]

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # GAP-059: Shadow-AI flagging
    # ------------------------------------------------------------------

    def flag_as_shadow_ai(
        self,
        org_id: str,
        asset_ref: str,
        reason: str = "",
    ) -> Dict[str, Any]:
        """Tag an asset as shadow AI.

        Writes to ``shadow_ai_flags``.  ``asset_ref`` is opaque — could be a
        ci_id, a cloud_resource_inventory id, or an identity id.  Returns the
        flag record.  Not idempotent; duplicate flags accumulate so that
        repeat detections retain a forensic trail.
        """
        if not org_id:
            raise ValueError("org_id is required")
        asset_ref = (asset_ref or "").strip()
        if not asset_ref:
            raise ValueError("asset_ref is required")
        flag_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    "INSERT INTO shadow_ai_flags "
                    "(id, org_id, asset_ref, reason, flagged_at) "
                    "VALUES (?,?,?,?,?)",
                    (flag_id, org_id, asset_ref, reason, now),
                )
        return {
            "id": flag_id,
            "org_id": org_id,
            "asset_ref": asset_ref,
            "reason": reason,
            "flagged_at": now,
        }

    def list_shadow_ai_flags(
        self,
        org_id: str,
        asset_ref: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List shadow-AI flags scoped to org and optional asset_ref."""
        if asset_ref is not None:
            query = (
                "SELECT * FROM shadow_ai_flags WHERE org_id=? AND asset_ref=? "
                "ORDER BY flagged_at DESC"
            )
            params: list = [org_id, asset_ref]
        else:
            query = (
                "SELECT * FROM shadow_ai_flags WHERE org_id=? "
                "ORDER BY flagged_at DESC"
            )
            params = [org_id]
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_cmdb_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate CMDB statistics for an org."""
        one_week_ago = (
            datetime.now(timezone.utc) - timedelta(days=7)
        ).isoformat()

        with self._conn() as conn:
            total_cis = conn.execute(
                "SELECT COUNT(*) FROM ci_items WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            # by_type
            type_rows = conn.execute(
                "SELECT ci_type, COUNT(*) as cnt FROM ci_items WHERE org_id=? GROUP BY ci_type",
                (org_id,),
            ).fetchall()
            by_type = {r["ci_type"]: r["cnt"] for r in type_rows}

            # by_environment
            env_rows = conn.execute(
                "SELECT environment, COUNT(*) as cnt FROM ci_items WHERE org_id=? GROUP BY environment",
                (org_id,),
            ).fetchall()
            by_environment = {r["environment"]: r["cnt"] for r in env_rows}

            # by_criticality
            crit_rows = conn.execute(
                "SELECT criticality, COUNT(*) as cnt FROM ci_items WHERE org_id=? GROUP BY criticality",
                (org_id,),
            ).fetchall()
            by_criticality = {r["criticality"]: r["cnt"] for r in crit_rows}

            # changes this week
            changes_this_week = conn.execute(
                "SELECT COUNT(*) FROM ci_changes WHERE org_id=? AND change_date>=?",
                (org_id, one_week_ago),
            ).fetchone()[0]

        return {
            "total_cis": total_cis,
            "by_type": by_type,
            "by_environment": by_environment,
            "by_criticality": by_criticality,
            "changes_this_week": changes_this_week,
        }
