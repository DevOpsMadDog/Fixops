"""
AssetLifecycleEngine — ALDECI.

Tracks hardware, software, cloud, network, endpoint, server, and mobile assets
through their full lifecycle: planning → procurement → deployment → operation →
maintenance → decommission.

SQLite-backed, thread-safe, multi-tenant (per org_id).

Compliance: ISO 27001 A.8 (Asset Management), NIST SP 800-53 CM-8.
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "asset_lifecycle.db"
)

VALID_ASSET_TYPES = frozenset(
    {"hardware", "software", "cloud", "network", "endpoint", "server", "mobile"}
)

VALID_LIFECYCLE_PHASES = frozenset(
    {"planning", "procurement", "deployment", "operation", "maintenance", "decommission"}
)

VALID_CRITICALITIES = frozenset({"low", "medium", "high", "critical"})

VALID_MAINTENANCE_TYPES = frozenset({"patch", "inspection", "repair", "upgrade", "replacement"})


class AssetLifecycleEngine:
    """
    SQLite-backed asset lifecycle tracking engine.

    All public methods are thread-safe via RLock.

    Args:
        db_path: Path to SQLite database. Defaults to .fixops_data/asset_lifecycle.db.
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
        with self._get_conn() as conn:
            conn.executescript(
                """
                PRAGMA journal_mode=WAL;

                CREATE TABLE IF NOT EXISTS assets (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    name                TEXT NOT NULL,
                    asset_type          TEXT NOT NULL,
                    lifecycle_phase     TEXT NOT NULL DEFAULT 'deployment',
                    criticality         TEXT NOT NULL DEFAULT 'medium',
                    vendor              TEXT DEFAULT '',
                    model               TEXT DEFAULT '',
                    serial_number       TEXT DEFAULT '',
                    location            TEXT DEFAULT '',
                    lifecycle_history   TEXT DEFAULT '[]',
                    status              TEXT NOT NULL DEFAULT 'active',
                    acquisition_date    DATETIME NOT NULL,
                    decommissioned_at   DATETIME,
                    decommission_reason TEXT DEFAULT '',
                    updated_at          DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_assets_org
                    ON assets (org_id);

                CREATE INDEX IF NOT EXISTS idx_assets_org_type
                    ON assets (org_id, asset_type);

                CREATE INDEX IF NOT EXISTS idx_assets_org_phase
                    ON assets (org_id, lifecycle_phase);

                CREATE TABLE IF NOT EXISTS maintenance_records (
                    id                   TEXT PRIMARY KEY,
                    org_id               TEXT NOT NULL,
                    asset_id             TEXT NOT NULL,
                    maintenance_type     TEXT NOT NULL,
                    performed_by         TEXT NOT NULL,
                    cost                 REAL NOT NULL DEFAULT 0.0,
                    notes                TEXT DEFAULT '',
                    next_maintenance_date DATETIME,
                    performed_at         DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_maint_org_asset
                    ON maintenance_records (org_id, asset_id);
                """
            )

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _row_to_asset(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "org_id": row["org_id"],
            "name": row["name"],
            "asset_type": row["asset_type"],
            "lifecycle_phase": row["lifecycle_phase"],
            "criticality": row["criticality"],
            "vendor": row["vendor"],
            "model": row["model"],
            "serial_number": row["serial_number"],
            "location": row["location"],
            "lifecycle_history": json.loads(row["lifecycle_history"] or "[]"),
            "status": row["status"],
            "acquisition_date": row["acquisition_date"],
            "decommissioned_at": row["decommissioned_at"],
            "decommission_reason": row["decommission_reason"],
            "updated_at": row["updated_at"],
        }

    def _row_to_maintenance(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "org_id": row["org_id"],
            "asset_id": row["asset_id"],
            "maintenance_type": row["maintenance_type"],
            "performed_by": row["performed_by"],
            "cost": row["cost"],
            "notes": row["notes"],
            "next_maintenance_date": row["next_maintenance_date"],
            "performed_at": row["performed_at"],
        }

    # ------------------------------------------------------------------
    # Asset Management
    # ------------------------------------------------------------------

    def register_asset(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Register a new asset.

        data keys: name (required), asset_type (required), lifecycle_phase,
        criticality, vendor, model, serial_number, location, acquisition_date.
        Returns the created asset record.
        """
        name = data.get("name", "").strip()
        if not name:
            raise ValueError("name is required")

        asset_type = data.get("asset_type", "")
        if asset_type not in VALID_ASSET_TYPES:
            raise ValueError(
                f"asset_type must be one of {sorted(VALID_ASSET_TYPES)}, got '{asset_type}'"
            )

        lifecycle_phase = data.get("lifecycle_phase", "deployment")
        if lifecycle_phase not in VALID_LIFECYCLE_PHASES:
            raise ValueError(
                f"lifecycle_phase must be one of {sorted(VALID_LIFECYCLE_PHASES)}, got '{lifecycle_phase}'"
            )

        criticality = data.get("criticality", "medium")
        if criticality not in VALID_CRITICALITIES:
            raise ValueError(
                f"criticality must be one of {sorted(VALID_CRITICALITIES)}, got '{criticality}'"
            )

        now = datetime.now(timezone.utc).isoformat()
        asset_id = str(uuid.uuid4())
        acquisition_date = data.get("acquisition_date", now)

        record = {
            "id": asset_id,
            "org_id": org_id,
            "name": name,
            "asset_type": asset_type,
            "lifecycle_phase": lifecycle_phase,
            "criticality": criticality,
            "vendor": data.get("vendor", ""),
            "model": data.get("model", ""),
            "serial_number": data.get("serial_number", ""),
            "location": data.get("location", ""),
            "lifecycle_history": json.dumps([]),
            "status": "active",
            "acquisition_date": acquisition_date,
            "decommissioned_at": None,
            "decommission_reason": "",
            "updated_at": now,
        }

        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO assets
                        (id, org_id, name, asset_type, lifecycle_phase, criticality,
                         vendor, model, serial_number, location, lifecycle_history,
                         status, acquisition_date, decommissioned_at, decommission_reason,
                         updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record["id"], record["org_id"], record["name"],
                        record["asset_type"], record["lifecycle_phase"], record["criticality"],
                        record["vendor"], record["model"], record["serial_number"],
                        record["location"], record["lifecycle_history"], record["status"],
                        record["acquisition_date"], record["decommissioned_at"],
                        record["decommission_reason"], record["updated_at"],
                    ),
                )

        record["lifecycle_history"] = []
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ASSET_DISCOVERED", {"entity_type": "asset_lifecycle", "org_id": org_id, "source_engine": "asset_lifecycle"})
            except Exception:
                pass

        return record

    def list_assets(
        self,
        org_id: str,
        asset_type: Optional[str] = None,
        lifecycle_phase: Optional[str] = None,
        criticality: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List assets for an org with optional filters."""
        query = "SELECT * FROM assets WHERE org_id = ?"
        params: List[Any] = [org_id]

        if asset_type:
            query += " AND asset_type = ?"
            params.append(asset_type)
        if lifecycle_phase:
            query += " AND lifecycle_phase = ?"
            params.append(lifecycle_phase)
        if criticality:
            query += " AND criticality = ?"
            params.append(criticality)

        query += " ORDER BY updated_at DESC"

        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(query, params).fetchall()

        return [self._row_to_asset(r) for r in rows]

    def get_asset(self, org_id: str, asset_id: str) -> Dict[str, Any]:
        """
        Retrieve a single asset by ID.

        Returns the asset dict or empty dict if not found / wrong org.
        """
        with self._lock:
            with self._get_conn() as conn:
                row = conn.execute(
                    "SELECT * FROM assets WHERE org_id = ? AND id = ?",
                    (org_id, asset_id),
                ).fetchone()

        if not row:
            return {}
        return self._row_to_asset(row)

    def update_lifecycle_phase(
        self,
        org_id: str,
        asset_id: str,
        new_phase: str,
        notes: str = "",
    ) -> Dict[str, Any]:
        """
        Transition an asset to a new lifecycle phase.

        Appends to lifecycle_history and sets updated_at.
        Raises ValueError for invalid phase or missing asset.
        """
        if new_phase not in VALID_LIFECYCLE_PHASES:
            raise ValueError(
                f"lifecycle_phase must be one of {sorted(VALID_LIFECYCLE_PHASES)}, got '{new_phase}'"
            )

        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._get_conn() as conn:
                row = conn.execute(
                    "SELECT * FROM assets WHERE org_id = ? AND id = ?",
                    (org_id, asset_id),
                ).fetchone()

                if not row:
                    raise ValueError(f"Asset '{asset_id}' not found for org '{org_id}'")

                history = json.loads(row["lifecycle_history"] or "[]")
                history.append({"phase": new_phase, "timestamp": now, "notes": notes})

                conn.execute(
                    """
                    UPDATE assets
                    SET lifecycle_phase = ?, lifecycle_history = ?, updated_at = ?
                    WHERE org_id = ? AND id = ?
                    """,
                    (new_phase, json.dumps(history), now, org_id, asset_id),
                )

        return self.get_asset(org_id, asset_id)

    def record_maintenance(
        self, org_id: str, asset_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Record a maintenance event for an asset.

        data keys: maintenance_type (required), performed_by (required),
        cost (float, default=0), notes, next_maintenance_date.
        Returns the maintenance record.
        """
        maintenance_type = data.get("maintenance_type", "")
        if maintenance_type not in VALID_MAINTENANCE_TYPES:
            raise ValueError(
                f"maintenance_type must be one of {sorted(VALID_MAINTENANCE_TYPES)}, got '{maintenance_type}'"
            )

        performed_by = data.get("performed_by", "").strip()
        if not performed_by:
            raise ValueError("performed_by is required")

        # Verify asset belongs to org
        with self._lock:
            with self._get_conn() as conn:
                asset_row = conn.execute(
                    "SELECT id FROM assets WHERE org_id = ? AND id = ?",
                    (org_id, asset_id),
                ).fetchone()

                if not asset_row:
                    raise ValueError(f"Asset '{asset_id}' not found for org '{org_id}'")

        cost = float(data.get("cost", 0.0))
        notes = data.get("notes", "")
        next_maintenance_date = data.get("next_maintenance_date")
        now = datetime.now(timezone.utc).isoformat()
        record_id = str(uuid.uuid4())

        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO maintenance_records
                        (id, org_id, asset_id, maintenance_type, performed_by,
                         cost, notes, next_maintenance_date, performed_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record_id, org_id, asset_id, maintenance_type,
                        performed_by, cost, notes, next_maintenance_date, now,
                    ),
                )

        return {
            "id": record_id,
            "org_id": org_id,
            "asset_id": asset_id,
            "maintenance_type": maintenance_type,
            "performed_by": performed_by,
            "cost": cost,
            "notes": notes,
            "next_maintenance_date": next_maintenance_date,
            "performed_at": now,
        }

    def decommission_asset(
        self, org_id: str, asset_id: str, reason: str
    ) -> Dict[str, Any]:
        """
        Decommission an asset — sets lifecycle_phase=decommission and status=decommissioned.

        Raises ValueError if asset not found.
        """
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._get_conn() as conn:
                row = conn.execute(
                    "SELECT * FROM assets WHERE org_id = ? AND id = ?",
                    (org_id, asset_id),
                ).fetchone()

                if not row:
                    raise ValueError(f"Asset '{asset_id}' not found for org '{org_id}'")

                history = json.loads(row["lifecycle_history"] or "[]")
                history.append({"phase": "decommission", "timestamp": now, "notes": reason})

                conn.execute(
                    """
                    UPDATE assets
                    SET lifecycle_phase = 'decommission',
                        status = 'decommissioned',
                        decommissioned_at = ?,
                        decommission_reason = ?,
                        lifecycle_history = ?,
                        updated_at = ?
                    WHERE org_id = ? AND id = ?
                    """,
                    (now, reason, json.dumps(history), now, org_id, asset_id),
                )

        return self.get_asset(org_id, asset_id)

    def get_lifecycle_stats(self, org_id: str) -> Dict[str, Any]:
        """
        Return aggregated lifecycle statistics for the org.

        Includes total_assets, by_type, by_phase, by_criticality,
        decommissioned_count, and maintenance_due (assets due in next 30 days).
        """
        now_dt = datetime.now(timezone.utc)
        window_end = (now_dt + timedelta(days=30)).isoformat()

        with self._lock:
            with self._get_conn() as conn:
                all_rows = conn.execute(
                    "SELECT asset_type, lifecycle_phase, criticality, status FROM assets WHERE org_id = ?",
                    (org_id,),
                ).fetchall()

                maintenance_due_rows = conn.execute(
                    """
                    SELECT DISTINCT m.asset_id
                    FROM maintenance_records m
                    JOIN assets a ON a.id = m.asset_id AND a.org_id = m.org_id
                    WHERE m.org_id = ?
                      AND m.next_maintenance_date IS NOT NULL
                      AND m.next_maintenance_date <= ?
                      AND a.lifecycle_phase IN ('operation', 'maintenance')
                    """,
                    (org_id, window_end),
                ).fetchall()

        total = len(all_rows)
        by_type: Dict[str, int] = {}
        by_phase: Dict[str, int] = {}
        by_criticality: Dict[str, int] = {}
        decommissioned = 0

        for r in all_rows:
            by_type[r["asset_type"]] = by_type.get(r["asset_type"], 0) + 1
            by_phase[r["lifecycle_phase"]] = by_phase.get(r["lifecycle_phase"], 0) + 1
            by_criticality[r["criticality"]] = by_criticality.get(r["criticality"], 0) + 1
            if r["status"] == "decommissioned":
                decommissioned += 1

        return {
            "total_assets": total,
            "by_type": by_type,
            "by_phase": by_phase,
            "by_criticality": by_criticality,
            "decommissioned_count": decommissioned,
            "maintenance_due": len(maintenance_due_rows),
        }
