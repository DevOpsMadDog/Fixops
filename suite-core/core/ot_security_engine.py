"""Operational Technology (OT) / ICS/SCADA Security Engine — ALDECI.

Asset registration, anomaly detection, and lifecycle management for OT
environments including PLCs, HMIs, SCADA systems, RTUs, sensors, and
historians. Full org_id multi-tenant isolation.

Compliance: NIST SP 800-82, IEC 62443, NERC CIP
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "ot_security.db"
)

_VALID_ASSET_TYPES = {"plc", "hmi", "scada", "rtu", "sensor", "historian"}
_VALID_CRITICALITIES = {"low", "medium", "high", "critical"}
_VALID_SEVERITIES = {"low", "medium", "high", "critical"}
_VALID_ANOMALY_STATUSES = {"open", "investigating", "resolved"}


class OTSecurityEngine:
    """SQLite WAL-backed OT/ICS/SCADA security engine.

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
                CREATE TABLE IF NOT EXISTS ot_assets (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    name             TEXT NOT NULL DEFAULT '',
                    asset_type       TEXT NOT NULL DEFAULT '',
                    criticality      TEXT NOT NULL DEFAULT 'medium',
                    vendor           TEXT NOT NULL DEFAULT '',
                    firmware_version TEXT NOT NULL DEFAULT '',
                    ip_address       TEXT NOT NULL DEFAULT '',
                    zone             TEXT NOT NULL DEFAULT '',
                    status           TEXT NOT NULL DEFAULT 'active',
                    registered_at    TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ot_assets_org
                    ON ot_assets (org_id, asset_type, criticality);

                CREATE TABLE IF NOT EXISTS ot_anomalies (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    asset_id     TEXT NOT NULL,
                    anomaly_type TEXT NOT NULL DEFAULT '',
                    severity     TEXT NOT NULL DEFAULT 'medium',
                    description  TEXT NOT NULL DEFAULT '',
                    status       TEXT NOT NULL DEFAULT 'open',
                    detected_at  TEXT NOT NULL,
                    resolved_at  TEXT,
                    resolution   TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_ot_anomalies_org
                    ON ot_anomalies (org_id, status, severity);

                CREATE INDEX IF NOT EXISTS idx_ot_anomalies_asset
                    ON ot_anomalies (org_id, asset_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Asset Management
    # ------------------------------------------------------------------

    def register_asset(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new OT asset.

        Required keys: name, asset_type
        Optional keys: criticality, vendor, firmware_version, ip_address, zone
        """
        name = data.get("name", "").strip()
        if not name:
            raise ValueError("name is required")

        asset_type = data.get("asset_type", "").lower().strip()
        if asset_type not in _VALID_ASSET_TYPES:
            raise ValueError(f"asset_type must be one of {_VALID_ASSET_TYPES}")

        criticality = data.get("criticality", "medium").lower().strip()
        if criticality not in _VALID_CRITICALITIES:
            raise ValueError(f"criticality must be one of {_VALID_CRITICALITIES}")

        asset_id = str(uuid.uuid4())
        now = self._now()
        row = {
            "id": asset_id,
            "org_id": org_id,
            "name": name,
            "asset_type": asset_type,
            "criticality": criticality,
            "vendor": data.get("vendor", ""),
            "firmware_version": data.get("firmware_version", ""),
            "ip_address": data.get("ip_address", ""),
            "zone": data.get("zone", ""),
            "status": "active",
            "registered_at": now,
        }
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO ot_assets
                    (id, org_id, name, asset_type, criticality, vendor,
                     firmware_version, ip_address, zone, status, registered_at)
                VALUES
                    (:id, :org_id, :name, :asset_type, :criticality, :vendor,
                     :firmware_version, :ip_address, :zone, :status, :registered_at)
                """,
                row,
            )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "ot_security", "org_id": org_id, "source_engine": "ot_security"})
            except Exception:
                pass

        return dict(row)

    def list_assets(
        self,
        org_id: str,
        asset_type: Optional[str] = None,
        criticality: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List OT assets with optional asset_type and criticality filters."""
        query = "SELECT * FROM ot_assets WHERE org_id = ?"
        params: list = [org_id]
        if asset_type is not None:
            query += " AND asset_type = ?"
            params.append(asset_type.lower())
        if criticality is not None:
            query += " AND criticality = ?"
            params.append(criticality.lower())
        query += " ORDER BY registered_at DESC"
        with self._lock, self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_asset(self, org_id: str, asset_id: str) -> Dict[str, Any]:
        """Return a single OT asset by ID, scoped to org."""
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM ot_assets WHERE id = ? AND org_id = ?",
                (asset_id, org_id),
            ).fetchone()
        if not row:
            raise ValueError(f"Asset {asset_id} not found for org {org_id}")
        return self._row_to_dict(row)

    # ------------------------------------------------------------------
    # Anomaly Management
    # ------------------------------------------------------------------

    def record_anomaly(
        self,
        org_id: str,
        asset_id: str,
        anomaly_type: str,
        severity: str,
        description: str,
    ) -> Dict[str, Any]:
        """Record an anomaly against an OT asset.

        The asset must exist and belong to the same org.
        """
        severity = severity.lower().strip()
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {_VALID_SEVERITIES}")

        # Verify asset exists in org
        self.get_asset(org_id, asset_id)

        anomaly_id = str(uuid.uuid4())
        now = self._now()
        row = {
            "id": anomaly_id,
            "org_id": org_id,
            "asset_id": asset_id,
            "anomaly_type": anomaly_type,
            "severity": severity,
            "description": description,
            "status": "open",
            "detected_at": now,
            "resolved_at": None,
            "resolution": None,
        }
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO ot_anomalies
                    (id, org_id, asset_id, anomaly_type, severity, description,
                     status, detected_at, resolved_at, resolution)
                VALUES
                    (:id, :org_id, :asset_id, :anomaly_type, :severity, :description,
                     :status, :detected_at, :resolved_at, :resolution)
                """,
                row,
            )
        return dict(row)

    def list_anomalies(
        self,
        org_id: str,
        status: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List anomalies with optional status and severity filters."""
        query = "SELECT * FROM ot_anomalies WHERE org_id = ?"
        params: list = [org_id]
        if status is not None:
            query += " AND status = ?"
            params.append(status.lower())
        if severity is not None:
            query += " AND severity = ?"
            params.append(severity.lower())
        query += " ORDER BY detected_at DESC"
        with self._lock, self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def resolve_anomaly(
        self, org_id: str, anomaly_id: str, resolution: str
    ) -> Dict[str, Any]:
        """Resolve an anomaly — sets status=resolved and records resolution text."""
        now = self._now()
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                UPDATE ot_anomalies
                SET status = 'resolved',
                    resolved_at = ?,
                    resolution = ?
                WHERE id = ? AND org_id = ? AND status != 'resolved'
                """,
                (now, resolution, anomaly_id, org_id),
            )
            row = conn.execute(
                "SELECT * FROM ot_anomalies WHERE id = ? AND org_id = ?",
                (anomaly_id, org_id),
            ).fetchone()
        if not row:
            raise ValueError(f"Anomaly {anomaly_id} not found for org {org_id}")
        return self._row_to_dict(row)

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_ot_stats(self, org_id: str) -> Dict[str, Any]:
        """Return OT environment statistics."""
        with self._lock, self._conn() as conn:
            total_assets = conn.execute(
                "SELECT COUNT(*) FROM ot_assets WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            type_rows = conn.execute(
                "SELECT asset_type, COUNT(*) AS cnt FROM ot_assets WHERE org_id = ? GROUP BY asset_type",
                (org_id,),
            ).fetchall()

            crit_rows = conn.execute(
                "SELECT criticality, COUNT(*) AS cnt FROM ot_assets WHERE org_id = ? GROUP BY criticality",
                (org_id,),
            ).fetchall()

            open_anomalies = conn.execute(
                "SELECT COUNT(*) FROM ot_anomalies WHERE org_id = ? AND status != 'resolved'",
                (org_id,),
            ).fetchone()[0]

            critical_anomalies = conn.execute(
                "SELECT COUNT(*) FROM ot_anomalies WHERE org_id = ? AND severity = 'critical' AND status != 'resolved'",
                (org_id,),
            ).fetchone()[0]

        return {
            "org_id": org_id,
            "total_assets": total_assets,
            "by_type": {r["asset_type"]: r["cnt"] for r in type_rows},
            "by_criticality": {r["criticality"]: r["cnt"] for r in crit_rows},
            "open_anomalies": open_anomalies,
            "critical_anomalies": critical_anomalies,
        }
