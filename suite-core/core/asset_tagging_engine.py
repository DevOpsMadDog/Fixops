"""Asset Tagging Engine — ALDECI.

Manages asset tagging lifecycle: tags, tagged assets, and tag assignments.

Capabilities:
  - Tag management: create, list, get with category validation
  - Asset registration: create, list, get with type/criticality validation
  - Tag assignments: assign tag to asset, bulk tag assets, list asset tags
  - Stats: totals, by_category, by_asset_type, most_used_tag, untagged_assets

Compliance: NIST SP 800-53 CM-8, CIS Control 1 (Asset Inventory)
"""

from __future__ import annotations

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

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "asset_tagging.db"
)

_VALID_TAG_CATEGORIES = {
    "environment",
    "criticality",
    "data_classification",
    "owner",
    "compliance",
    "technology",
    "location",
    "department",
}

_VALID_CRITICALITIES = {"mission_critical", "high", "medium", "low"}

_VALID_ASSET_TYPES = {
    "server",
    "workstation",
    "network",
    "application",
    "database",
    "cloud",
    "iot",
    "mobile",
    "container",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AssetTaggingEngine:
    """SQLite WAL-backed Asset Tagging engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/asset_tagging.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = db_path if db_path is not None else _DEFAULT_DB
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
                CREATE TABLE IF NOT EXISTS asset_tags (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    tag_key      TEXT NOT NULL,
                    tag_value    TEXT NOT NULL,
                    tag_category TEXT NOT NULL DEFAULT 'environment',
                    description  TEXT NOT NULL DEFAULT '',
                    usage_count  INTEGER NOT NULL DEFAULT 0,
                    created_at   DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_asset_tags_org
                    ON asset_tags (org_id, tag_category, created_at DESC);

                CREATE TABLE IF NOT EXISTS tagged_assets (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    asset_id     TEXT NOT NULL,
                    asset_name   TEXT NOT NULL,
                    asset_type   TEXT NOT NULL DEFAULT 'server',
                    criticality  TEXT NOT NULL DEFAULT 'medium',
                    tag_count    INTEGER NOT NULL DEFAULT 0,
                    owner        TEXT NOT NULL DEFAULT '',
                    environment  TEXT NOT NULL DEFAULT '',
                    created_at   DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_tagged_assets_org
                    ON tagged_assets (org_id, asset_type, criticality, environment, created_at DESC);

                CREATE UNIQUE INDEX IF NOT EXISTS idx_tagged_assets_asset_id
                    ON tagged_assets (org_id, asset_id);

                CREATE TABLE IF NOT EXISTS asset_tag_assignments (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    asset_id    TEXT NOT NULL,
                    tag_id      TEXT NOT NULL,
                    assigned_by TEXT NOT NULL DEFAULT 'system',
                    assigned_at DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_assignments_org
                    ON asset_tag_assignments (org_id, asset_id, tag_id);

                CREATE UNIQUE INDEX IF NOT EXISTS idx_assignments_unique
                    ON asset_tag_assignments (org_id, asset_id, tag_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Tags
    # ------------------------------------------------------------------

    def create_tag(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new asset tag."""
        tag_key = (data.get("tag_key") or "").strip()
        if not tag_key:
            raise ValueError("tag_key is required.")

        tag_value = (data.get("tag_value") or "").strip()
        if not tag_value:
            raise ValueError("tag_value is required.")

        tag_category = data.get("tag_category", "environment")
        if tag_category not in _VALID_TAG_CATEGORIES:
            raise ValueError(
                f"Invalid tag_category: {tag_category!r}. "
                f"Must be one of {sorted(_VALID_TAG_CATEGORIES)}"
            )

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "tag_key": tag_key,
            "tag_value": tag_value,
            "tag_category": tag_category,
            "description": data.get("description", ""),
            "usage_count": 0,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO asset_tags
                       (id, org_id, tag_key, tag_value, tag_category,
                        description, usage_count, created_at)
                       VALUES (:id, :org_id, :tag_key, :tag_value, :tag_category,
                               :description, :usage_count, :created_at)""",
                    record,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ASSET_DISCOVERED", {"entity_type": "asset_tagging", "org_id": org_id, "source_engine": "asset_tagging"})
            except Exception:
                pass

        return record

    def list_tags(
        self,
        org_id: str,
        tag_category: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List tags with optional category filter."""
        sql = "SELECT * FROM asset_tags WHERE org_id = ?"
        params: list = [org_id]
        if tag_category:
            sql += " AND tag_category = ?"
            params.append(tag_category)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_tag(self, org_id: str, tag_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single tag by ID. Returns None if not found or wrong org."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM asset_tags WHERE org_id = ? AND id = ?",
                (org_id, tag_id),
            ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Assets
    # ------------------------------------------------------------------

    def register_asset(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new asset for tagging."""
        asset_name = (data.get("asset_name") or "").strip()
        if not asset_name:
            raise ValueError("asset_name is required.")

        asset_type = data.get("asset_type", "server")
        if asset_type not in _VALID_ASSET_TYPES:
            raise ValueError(
                f"Invalid asset_type: {asset_type!r}. "
                f"Must be one of {sorted(_VALID_ASSET_TYPES)}"
            )

        criticality = data.get("criticality", "medium")
        if criticality not in _VALID_CRITICALITIES:
            raise ValueError(
                f"Invalid criticality: {criticality!r}. "
                f"Must be one of {sorted(_VALID_CRITICALITIES)}"
            )

        now = _now_iso()
        asset_id = data.get("asset_id") or str(uuid.uuid4())
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "asset_id": asset_id,
            "asset_name": asset_name,
            "asset_type": asset_type,
            "criticality": criticality,
            "tag_count": 0,
            "owner": data.get("owner", ""),
            "environment": data.get("environment", ""),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO tagged_assets
                       (id, org_id, asset_id, asset_name, asset_type, criticality,
                        tag_count, owner, environment, created_at)
                       VALUES (:id, :org_id, :asset_id, :asset_name, :asset_type,
                               :criticality, :tag_count, :owner, :environment, :created_at)""",
                    record,
                )
        return record

    def list_assets(
        self,
        org_id: str,
        asset_type: Optional[str] = None,
        criticality: Optional[str] = None,
        environment: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List assets with optional filters."""
        sql = "SELECT * FROM tagged_assets WHERE org_id = ?"
        params: list = [org_id]
        if asset_type:
            sql += " AND asset_type = ?"
            params.append(asset_type)
        if criticality:
            sql += " AND criticality = ?"
            params.append(criticality)
        if environment:
            sql += " AND environment = ?"
            params.append(environment)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_asset(self, org_id: str, asset_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single asset by asset_id. Returns None if not found or wrong org."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM tagged_assets WHERE org_id = ? AND asset_id = ?",
                (org_id, asset_id),
            ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Assignments
    # ------------------------------------------------------------------

    def assign_tag(
        self,
        org_id: str,
        asset_id: str,
        tag_id: str,
        assigned_by: str = "system",
    ) -> Dict[str, Any]:
        """Assign a tag to an asset. Increments usage_count and tag_count."""
        with self._lock:
            with self._conn() as conn:
                # Validate asset exists in org
                asset_row = conn.execute(
                    "SELECT id FROM tagged_assets WHERE org_id = ? AND asset_id = ?",
                    (org_id, asset_id),
                ).fetchone()
                if not asset_row:
                    raise KeyError(f"Asset '{asset_id}' not found in org '{org_id}'.")

                # Validate tag exists in org
                tag_row = conn.execute(
                    "SELECT id FROM asset_tags WHERE org_id = ? AND id = ?",
                    (org_id, tag_id),
                ).fetchone()
                if not tag_row:
                    raise KeyError(f"Tag '{tag_id}' not found in org '{org_id}'.")

                now = _now_iso()
                assignment_id = str(uuid.uuid4())

                # INSERT OR IGNORE to handle duplicates gracefully
                conn.execute(
                    """INSERT OR IGNORE INTO asset_tag_assignments
                       (id, org_id, asset_id, tag_id, assigned_by, assigned_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (assignment_id, org_id, asset_id, tag_id, assigned_by, now),
                )

                # Check if it was actually inserted (not a duplicate)
                inserted = conn.execute(
                    "SELECT id FROM asset_tag_assignments "
                    "WHERE org_id = ? AND asset_id = ? AND tag_id = ?",
                    (org_id, asset_id, tag_id),
                ).fetchone()
                actual_id = inserted["id"] if inserted else assignment_id

                # Only increment counters if this is a new assignment
                if actual_id == assignment_id:
                    conn.execute(
                        "UPDATE asset_tags SET usage_count = usage_count + 1 "
                        "WHERE org_id = ? AND id = ?",
                        (org_id, tag_id),
                    )
                    conn.execute(
                        "UPDATE tagged_assets SET tag_count = tag_count + 1 "
                        "WHERE org_id = ? AND asset_id = ?",
                        (org_id, asset_id),
                    )

                record: Dict[str, Any] = {
                    "id": actual_id,
                    "org_id": org_id,
                    "asset_id": asset_id,
                    "tag_id": tag_id,
                    "assigned_by": assigned_by,
                    "assigned_at": now,
                }
        return record

    def list_asset_tags(
        self, org_id: str, asset_id: str
    ) -> List[Dict[str, Any]]:
        """Return all tags assigned to an asset (join with tag data)."""
        sql = """
            SELECT
                a.id AS assignment_id,
                a.asset_id,
                a.tag_id,
                a.assigned_by,
                a.assigned_at,
                t.tag_key,
                t.tag_value,
                t.tag_category,
                t.description,
                t.usage_count
            FROM asset_tag_assignments a
            JOIN asset_tags t ON t.id = a.tag_id
            WHERE a.org_id = ? AND a.asset_id = ?
            ORDER BY a.assigned_at DESC
        """
        with self._conn() as conn:
            rows = conn.execute(sql, (org_id, asset_id)).fetchall()
        return [self._row(r) for r in rows]

    def bulk_tag_assets(
        self,
        org_id: str,
        asset_ids: List[str],
        tag_id: str,
        assigned_by: str = "system",
    ) -> List[Dict[str, Any]]:
        """Assign a tag to multiple assets. Returns list of assignment results."""
        results = []
        for asset_id in asset_ids:
            try:
                result = self.assign_tag(org_id, asset_id, tag_id, assigned_by=assigned_by)
                results.append({"asset_id": asset_id, "status": "ok", "assignment": result})
            except KeyError as exc:
                results.append({"asset_id": asset_id, "status": "error", "detail": str(exc)})
        return results

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_tag_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated tag statistics for an org."""
        with self._conn() as conn:
            total_tags = conn.execute(
                "SELECT COUNT(*) FROM asset_tags WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            total_assets = conn.execute(
                "SELECT COUNT(*) FROM tagged_assets WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            total_assignments = conn.execute(
                "SELECT COUNT(*) FROM asset_tag_assignments WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            by_category_rows = conn.execute(
                "SELECT tag_category, COUNT(*) AS cnt FROM asset_tags "
                "WHERE org_id = ? GROUP BY tag_category",
                (org_id,),
            ).fetchall()

            by_asset_type_rows = conn.execute(
                "SELECT asset_type, COUNT(*) AS cnt FROM tagged_assets "
                "WHERE org_id = ? GROUP BY asset_type",
                (org_id,),
            ).fetchall()

            most_used_row = conn.execute(
                "SELECT id, tag_key, tag_value, usage_count FROM asset_tags "
                "WHERE org_id = ? ORDER BY usage_count DESC LIMIT 1",
                (org_id,),
            ).fetchone()

            untagged_assets = conn.execute(
                "SELECT COUNT(*) FROM tagged_assets WHERE org_id = ? AND tag_count = 0",
                (org_id,),
            ).fetchone()[0]

        return {
            "total_tags": total_tags,
            "total_assets": total_assets,
            "total_assignments": total_assignments,
            "by_category": {r["tag_category"]: r["cnt"] for r in by_category_rows},
            "by_asset_type": {r["asset_type"]: r["cnt"] for r in by_asset_type_rows},
            "most_used_tag": self._row(most_used_row) if most_used_row else None,
            "untagged_assets": untagged_assets,
        }
