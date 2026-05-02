"""Asset Group Engine — ALDECI.

Organizes assets into logical groups for policy and scan targeting.
Groups can be functional, compliance-scoped, geographic, cloud-based, etc.

Capabilities:
  - Group lifecycle (create/list/get)
  - Member management with INSERT OR IGNORE dedup + member_count tracking
  - Bulk member addition
  - Policy attachment with JSON config + toggle (enable/disable)
  - Reverse lookup: find all groups containing an asset
  - Per-org stats aggregation

Compliance: CIS, NIST SP 800-53, ISO 27001
"""

from __future__ import annotations

import contextlib
import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB_DIR = Path(__file__).resolve().parents[2] / ".fixops_data"

_VALID_GROUP_TYPES = {
    "functional", "compliance", "geographic", "cloud",
    "network", "security-zone", "business-unit", "custom",
}
_VALID_ASSET_TYPES = {
    "server", "workstation", "network-device", "cloud-instance",
    "container", "application", "database", "iot-device",
}
_VALID_CRITICALITIES = {"critical", "high", "medium", "low"}
_VALID_POLICY_TYPES = {"scan", "patch", "monitoring", "backup", "access", "compliance", "retention"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AssetGroupEngine:
    """SQLite WAL-backed Asset Group engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path:
            self._db_dir = Path(db_path).parent
            self._single_path: Optional[str] = db_path
        else:
            self._db_dir = _DEFAULT_DB_DIR
            self._single_path = None
        self._db_dir.mkdir(parents=True, exist_ok=True)
        self._locks: Dict[str, threading.RLock] = {}
        self._lock_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_lock(self, org_id: str) -> threading.RLock:
        with self._lock_lock:
            if org_id not in self._locks:
                self._locks[org_id] = threading.RLock()
            return self._locks[org_id]

    def _db_path(self, org_id: str) -> str:
        if self._single_path:
            return self._single_path
        return str(self._db_dir / f"{org_id}_asset_group.db")

    @contextlib.contextmanager
    def _conn(self, org_id: str):
        conn = sqlite3.connect(self._db_path(org_id), timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_db(self, org_id: str) -> None:
        with self._conn(org_id) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS asset_groups (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    group_name   TEXT NOT NULL,
                    group_type   TEXT NOT NULL DEFAULT 'functional',
                    description  TEXT NOT NULL DEFAULT '',
                    owner        TEXT NOT NULL DEFAULT '',
                    criticality  TEXT NOT NULL DEFAULT 'medium',
                    member_count INTEGER NOT NULL DEFAULT 0,
                    created_at   TEXT NOT NULL,
                    updated_at   TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_ag_org ON asset_groups (org_id, group_type);

                CREATE TABLE IF NOT EXISTS group_members (
                    id         TEXT PRIMARY KEY,
                    group_id   TEXT NOT NULL,
                    org_id     TEXT NOT NULL,
                    asset_id   TEXT NOT NULL,
                    asset_type TEXT NOT NULL DEFAULT 'server',
                    added_by   TEXT NOT NULL DEFAULT '',
                    added_at   TEXT NOT NULL,
                    UNIQUE(group_id, asset_id)
                );
                CREATE INDEX IF NOT EXISTS idx_gm_group ON group_members (group_id, org_id);
                CREATE INDEX IF NOT EXISTS idx_gm_asset ON group_members (asset_id, org_id);

                CREATE TABLE IF NOT EXISTS group_policies (
                    id          TEXT PRIMARY KEY,
                    group_id    TEXT NOT NULL,
                    org_id      TEXT NOT NULL,
                    policy_name TEXT NOT NULL,
                    policy_type TEXT NOT NULL DEFAULT 'scan',
                    enabled     INTEGER NOT NULL DEFAULT 1,
                    config      TEXT NOT NULL DEFAULT '{}',
                    created_at  TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_gp_group ON group_policies (group_id, org_id);
            """)

    def _ensure_db(self, org_id: str) -> None:
        self._init_db(org_id)

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        if "enabled" in d:
            d["enabled"] = bool(d["enabled"])
        if "config" in d and isinstance(d["config"], str):
            try:
                d["config"] = json.loads(d["config"])
            except (json.JSONDecodeError, TypeError):
                pass
        return d

    # ------------------------------------------------------------------
    # Groups
    # ------------------------------------------------------------------

    def create_group(
        self,
        org_id: str,
        group_name: str,
        group_type: str,
        description: str = "",
        owner: str = "",
        criticality: str = "medium",
    ) -> Dict[str, Any]:
        """Create a new asset group."""
        self._ensure_db(org_id)
        if group_type not in _VALID_GROUP_TYPES:
            raise ValueError(f"Invalid group_type '{group_type}'. Must be one of {_VALID_GROUP_TYPES}")
        if criticality not in _VALID_CRITICALITIES:
            raise ValueError(f"Invalid criticality '{criticality}'. Must be one of {_VALID_CRITICALITIES}")
        now = _now()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "group_name": group_name,
            "group_type": group_type,
            "description": description,
            "owner": owner,
            "criticality": criticality,
            "member_count": 0,
            "created_at": now,
            "updated_at": now,
        }
        with self._get_lock(org_id):
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO asset_groups
                       (id, org_id, group_name, group_type, description, owner, criticality,
                        member_count, created_at, updated_at)
                       VALUES (:id, :org_id, :group_name, :group_type, :description, :owner, :criticality,
                               :member_count, :created_at, :updated_at)""",
                    record,
                )
        return record

    def add_member(
        self,
        group_id: str,
        org_id: str,
        asset_id: str,
        asset_type: str,
        added_by: str = "",
    ) -> Dict[str, Any]:
        """Add an asset to a group. INSERT OR IGNORE prevents duplicates.
        member_count is only incremented when an actual insert occurs.
        """
        self._ensure_db(org_id)
        if asset_type not in _VALID_ASSET_TYPES:
            raise ValueError(f"Invalid asset_type '{asset_type}'. Must be one of {_VALID_ASSET_TYPES}")
        now = _now()
        member_id = str(uuid.uuid4())
        with self._get_lock(org_id):
            with self._conn(org_id) as conn:
                cursor = conn.execute(
                    """INSERT OR IGNORE INTO group_members
                       (id, group_id, org_id, asset_id, asset_type, added_by, added_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (member_id, group_id, org_id, asset_id, asset_type, added_by, now),
                )
                actually_inserted = cursor.rowcount > 0
                if actually_inserted:
                    conn.execute(
                        "UPDATE asset_groups SET member_count = member_count + 1, updated_at = ? WHERE id = ? AND org_id = ?",
                        (now, group_id, org_id),
                    )
                # Return actual member row (may have different id if already existed)
                row = conn.execute(
                    "SELECT * FROM group_members WHERE group_id = ? AND asset_id = ? AND org_id = ?",
                    (group_id, asset_id, org_id),
                ).fetchone()
        return self._row(row)

    def remove_member(self, group_id: str, org_id: str, asset_id: str) -> Dict[str, Any]:
        """Remove an asset from a group. member_count floored at 0."""
        self._ensure_db(org_id)
        now = _now()
        with self._get_lock(org_id):
            with self._conn(org_id) as conn:
                cursor = conn.execute(
                    "DELETE FROM group_members WHERE group_id = ? AND org_id = ? AND asset_id = ?",
                    (group_id, org_id, asset_id),
                )
                removed = cursor.rowcount > 0
                if removed:
                    conn.execute(
                        """UPDATE asset_groups
                           SET member_count = MAX(0, member_count - 1), updated_at = ?
                           WHERE id = ? AND org_id = ?""",
                        (now, group_id, org_id),
                    )
        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("ASSET_DISCOVERED", {"entity_type": "asset_group_engine", "org_id": org_id, "source_engine": "asset_group_engine"})
            except Exception:
                pass
        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("ASSET_DISCOVERED", {"entity_type": "asset_group_engine", "org_id": org_id, "source_engine": "asset_group_engine"})
            except Exception:
                pass
        return {"group_id": group_id, "asset_id": asset_id, "removed": removed}

    def add_policy(
        self,
        group_id: str,
        org_id: str,
        policy_name: str,
        policy_type: str,
        config: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Attach a policy to a group. config stored as JSON string."""
        self._ensure_db(org_id)
        if policy_type not in _VALID_POLICY_TYPES:
            raise ValueError(f"Invalid policy_type '{policy_type}'. Must be one of {_VALID_POLICY_TYPES}")
        now = _now()
        record = {
            "id": str(uuid.uuid4()),
            "group_id": group_id,
            "org_id": org_id,
            "policy_name": policy_name,
            "policy_type": policy_type,
            "enabled": 1,
            "config": json.dumps(config or {}),
            "created_at": now,
        }
        with self._get_lock(org_id):
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO group_policies
                       (id, group_id, org_id, policy_name, policy_type, enabled, config, created_at)
                       VALUES (:id, :group_id, :org_id, :policy_name, :policy_type, :enabled, :config, :created_at)""",
                    record,
                )
        record["enabled"] = True
        record["config"] = config or {}
        return record

    def toggle_policy(self, policy_id: str, group_id: str, org_id: str) -> Dict[str, Any]:
        """Flip policy enabled: 0→1 or 1→0."""
        self._ensure_db(org_id)
        with self._get_lock(org_id):
            with self._conn(org_id) as conn:
                cursor = conn.execute(
                    """UPDATE group_policies
                       SET enabled = 1 - enabled
                       WHERE id = ? AND group_id = ? AND org_id = ?""",
                    (policy_id, group_id, org_id),
                )
                if cursor.rowcount == 0:
                    raise ValueError(f"Policy '{policy_id}' not found in group '{group_id}'.")
                row = conn.execute(
                    "SELECT * FROM group_policies WHERE id = ?", (policy_id,)
                ).fetchone()
        return self._row(row)

    def get_group(self, group_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        """Get a group with all its members and policies."""
        self._ensure_db(org_id)
        with self._conn(org_id) as conn:
            row = conn.execute(
                "SELECT * FROM asset_groups WHERE id = ? AND org_id = ?",
                (group_id, org_id),
            ).fetchone()
            if not row:
                return None
            result = self._row(row)
            members = conn.execute(
                "SELECT * FROM group_members WHERE group_id = ? AND org_id = ? ORDER BY added_at DESC",
                (group_id, org_id),
            ).fetchall()
            policies = conn.execute(
                "SELECT * FROM group_policies WHERE group_id = ? AND org_id = ? ORDER BY created_at DESC",
                (group_id, org_id),
            ).fetchall()
            result["members"] = [self._row(m) for m in members]
            result["policies"] = [self._row(p) for p in policies]
        return result

    def list_groups(
        self,
        org_id: str,
        group_type: Optional[str] = None,
        criticality: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List groups with optional filters."""
        self._ensure_db(org_id)
        sql = "SELECT * FROM asset_groups WHERE org_id = ?"
        params: list = [org_id]
        if group_type:
            sql += " AND group_type = ?"
            params.append(group_type)
        if criticality:
            sql += " AND criticality = ?"
            params.append(criticality)
        sql += " ORDER BY created_at DESC"
        with self._conn(org_id) as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    def get_asset_groups(self, org_id: str, asset_id: str) -> List[Dict[str, Any]]:
        """Find all groups that contain a given asset_id."""
        self._ensure_db(org_id)
        with self._conn(org_id) as conn:
            group_ids = [
                r[0]
                for r in conn.execute(
                    "SELECT group_id FROM group_members WHERE asset_id = ? AND org_id = ?",
                    (asset_id, org_id),
                ).fetchall()
            ]
            if not group_ids:
                return []
            placeholders = ",".join("?" * len(group_ids))
            rows = conn.execute(
                f"SELECT * FROM asset_groups WHERE id IN ({placeholders}) AND org_id = ?",  # nosec B608
                group_ids + [org_id],
            ).fetchall()
        return [self._row(r) for r in rows]

    def bulk_add_members(
        self,
        group_id: str,
        org_id: str,
        asset_ids: List[str],
        asset_type: str,
        added_by: str = "",
    ) -> Dict[str, Any]:
        """Add multiple assets to a group. Returns count actually inserted."""
        count = 0
        for asset_id in asset_ids:
            try:
                self.add_member(group_id, org_id, asset_id, asset_type, added_by)
                # If member was newly inserted, added_at matches ~now
                count += 1
            except Exception:
                pass
        # Recalculate actual count from DB
        # We just track how many calls succeeded (not whether they were duplicates)
        # Re-run with proper tracking:
        # Reset and redo properly
        return {"group_id": group_id, "requested": len(asset_ids), "added": count}

    def bulk_add_members(  # noqa: F811
        self,
        group_id: str,
        org_id: str,
        asset_ids: List[str],
        asset_type: str,
        added_by: str = "",
    ) -> Dict[str, Any]:
        """Add multiple assets to a group. Returns count actually inserted (dedup-aware)."""
        self._ensure_db(org_id)
        if asset_type not in _VALID_ASSET_TYPES:
            raise ValueError(f"Invalid asset_type '{asset_type}'. Must be one of {_VALID_ASSET_TYPES}")
        now = _now()
        actually_inserted = 0
        with self._get_lock(org_id):
            with self._conn(org_id) as conn:
                for asset_id in asset_ids:
                    member_id = str(uuid.uuid4())
                    cursor = conn.execute(
                        """INSERT OR IGNORE INTO group_members
                           (id, group_id, org_id, asset_id, asset_type, added_by, added_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        (member_id, group_id, org_id, asset_id, asset_type, added_by, now),
                    )
                    if cursor.rowcount > 0:
                        actually_inserted += 1
                if actually_inserted > 0:
                    conn.execute(
                        "UPDATE asset_groups SET member_count = member_count + ?, updated_at = ? WHERE id = ? AND org_id = ?",
                        (actually_inserted, now, group_id, org_id),
                    )
        return {"group_id": group_id, "requested": len(asset_ids), "added": actually_inserted}

    def get_group_stats(self, org_id: str) -> Dict[str, Any]:
        """Aggregate group statistics for an org."""
        self._ensure_db(org_id)
        with self._conn(org_id) as conn:
            total_groups = conn.execute(
                "SELECT COUNT(*) FROM asset_groups WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            total_members = conn.execute(
                "SELECT COALESCE(SUM(member_count), 0) FROM asset_groups WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            by_criticality_rows = conn.execute(
                "SELECT criticality, COUNT(*) as cnt FROM asset_groups WHERE org_id = ? GROUP BY criticality",
                (org_id,),
            ).fetchall()
            by_type_rows = conn.execute(
                "SELECT group_type, COUNT(*) as cnt FROM asset_groups WHERE org_id = ? GROUP BY group_type",
                (org_id,),
            ).fetchall()
            largest_row = conn.execute(
                "SELECT * FROM asset_groups WHERE org_id = ? ORDER BY member_count DESC LIMIT 1",
                (org_id,),
            ).fetchone()
        return {
            "org_id": org_id,
            "total_groups": total_groups,
            "total_members": total_members,
            "by_criticality": {r["criticality"]: r["cnt"] for r in by_criticality_rows},
            "by_type": {r["group_type"]: r["cnt"] for r in by_type_rows},
            "largest_group": self._row(largest_row) if largest_row else None,
        }
