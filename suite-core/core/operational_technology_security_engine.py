"""Operational Technology Security Engine — ALDECI.

Manages OT/ICS/SCADA assets, security incidents, and zone topology for
industrial control systems. Full org_id multi-tenant isolation.

Capabilities:
  - Asset registration (PLC, SCADA, HMI, RTU, Historian, DCS, IED, etc.)
  - Incident lifecycle (detected → investigating → contained → remediated)
  - Zone management (enterprise/DMZ/control/field/safety) with Purdue levels
  - Stats: totals, open incidents, by asset type, by zone, by incident type

Compliance: IEC 62443, NIST SP 800-82, NERC CIP, ISA/IEC 62443-2-1
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "operational_technology_security.db"
)

_VALID_ASSET_TYPES = {
    "plc",
    "scada",
    "hmi",
    "rtu",
    "historian",
    "dcs",
    "ied",
    "engineering_workstation",
    "safety_system",
    "sensor",
}
_VALID_ZONES = {"enterprise", "dmz", "control", "field", "safety"}
_VALID_PROTOCOLS = {
    "modbus",
    "dnp3",
    "profinet",
    "bacnet",
    "opc_ua",
    "iec_61850",
    "hart",
    "ethernet_ip",
    "s7",
    "other",
}
_VALID_ASSET_STATUSES = {"operational", "maintenance", "decommissioned", "compromised"}

_VALID_INCIDENT_TYPES = {
    "malware",
    "unauthorized_access",
    "configuration_change",
    "dos",
    "firmware_tampering",
    "network_intrusion",
    "physical_access",
    "data_manipulation",
    "safety_system_impact",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_IMPACT_LEVELS = {"none", "minor", "moderate", "major", "catastrophic"}
_VALID_INCIDENT_STATUSES = {"detected", "investigating", "contained", "remediated"}

_VALID_ZONE_TYPES = {"enterprise", "dmz", "control", "field", "safety"}
_VALID_SECURITY_LEVELS = {"sl1", "sl2", "sl3", "sl4"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class OperationalTechnologySecurityEngine:
    """SQLite WAL-backed OT Security engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/operational_technology_security.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = _DEFAULT_DB
        self._db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS ots_assets (
                    id                 TEXT PRIMARY KEY,
                    org_id             TEXT NOT NULL,
                    asset_name         TEXT NOT NULL DEFAULT '',
                    asset_type         TEXT NOT NULL DEFAULT '',
                    vendor             TEXT NOT NULL DEFAULT '',
                    model              TEXT NOT NULL DEFAULT '',
                    firmware_version   TEXT NOT NULL DEFAULT '',
                    zone               TEXT NOT NULL DEFAULT '',
                    protocol           TEXT NOT NULL DEFAULT 'other',
                    risk_score         REAL NOT NULL DEFAULT 50.0,
                    status             TEXT NOT NULL DEFAULT 'operational',
                    last_patched       TEXT,
                    created_at         TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ots_assets_org
                    ON ots_assets (org_id, asset_type, zone, status);

                CREATE TABLE IF NOT EXISTS ots_incidents (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    asset_id       TEXT NOT NULL,
                    incident_type  TEXT NOT NULL,
                    severity       TEXT NOT NULL DEFAULT 'medium',
                    impact_level   TEXT NOT NULL DEFAULT 'none',
                    status         TEXT NOT NULL DEFAULT 'detected',
                    detected_at    TEXT NOT NULL,
                    created_at     TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ots_incidents_org
                    ON ots_incidents (org_id, asset_id, severity, status);

                CREATE TABLE IF NOT EXISTS ots_zones (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    zone_name      TEXT NOT NULL DEFAULT '',
                    zone_type      TEXT NOT NULL DEFAULT '',
                    asset_count    INTEGER NOT NULL DEFAULT 0,
                    security_level TEXT NOT NULL DEFAULT 'sl1',
                    purdue_level   INTEGER NOT NULL DEFAULT 0,
                    conduit_count  INTEGER NOT NULL DEFAULT 0,
                    created_at     TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ots_zones_org
                    ON ots_zones (org_id, zone_type);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Assets
    # ------------------------------------------------------------------

    def register_asset(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new OT asset."""
        asset_type = data.get("asset_type", "")
        if asset_type not in _VALID_ASSET_TYPES:
            raise ValueError(
                f"Invalid asset_type: {asset_type}. "
                f"Must be one of {sorted(_VALID_ASSET_TYPES)}"
            )

        zone = data.get("zone", "")
        if zone not in _VALID_ZONES:
            raise ValueError(
                f"Invalid zone: {zone}. Must be one of {sorted(_VALID_ZONES)}"
            )

        protocol = data.get("protocol", "other")
        if protocol not in _VALID_PROTOCOLS:
            raise ValueError(
                f"Invalid protocol: {protocol}. "
                f"Must be one of {sorted(_VALID_PROTOCOLS)}"
            )

        risk_score = float(data.get("risk_score", 50.0))
        risk_score = max(0.0, min(100.0, risk_score))

        status = data.get("status", "operational")
        if status not in _VALID_ASSET_STATUSES:
            raise ValueError(
                f"Invalid status: {status}. "
                f"Must be one of {sorted(_VALID_ASSET_STATUSES)}"
            )

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "asset_name": data.get("asset_name", ""),
            "asset_type": asset_type,
            "vendor": data.get("vendor", ""),
            "model": data.get("model", ""),
            "firmware_version": data.get("firmware_version", ""),
            "zone": zone,
            "protocol": protocol,
            "risk_score": risk_score,
            "status": status,
            "last_patched": data.get("last_patched"),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO ots_assets
                       (id, org_id, asset_name, asset_type, vendor, model,
                        firmware_version, zone, protocol, risk_score, status,
                        last_patched, created_at)
                       VALUES
                       (:id, :org_id, :asset_name, :asset_type, :vendor, :model,
                        :firmware_version, :zone, :protocol, :risk_score, :status,
                        :last_patched, :created_at)""",
                    record,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "operational_technology_security", "org_id": org_id, "source_engine": "operational_technology_security"})
            except Exception:
                pass

        return record

    def list_assets(
        self,
        org_id: str,
        asset_type: Optional[str] = None,
        zone: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List OT assets with optional filters."""
        sql = "SELECT * FROM ots_assets WHERE org_id = ?"
        params: list = [org_id]
        if asset_type is not None:
            sql += " AND asset_type = ?"
            params.append(asset_type)
        if zone is not None:
            sql += " AND zone = ?"
            params.append(zone)
        if status is not None:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_asset(self, org_id: str, asset_id: str) -> Optional[Dict[str, Any]]:
        """Get a single OT asset by id, scoped to org. Returns None if not found."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM ots_assets WHERE id = ? AND org_id = ?",
                (asset_id, org_id),
            ).fetchone()
        return self._row(row) if row else None

    def update_asset_status(
        self, org_id: str, asset_id: str, status: str
    ) -> Dict[str, Any]:
        """Update asset status. Raises KeyError if not found."""
        if status not in _VALID_ASSET_STATUSES:
            raise ValueError(
                f"Invalid status: {status}. "
                f"Must be one of {sorted(_VALID_ASSET_STATUSES)}"
            )
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    "UPDATE ots_assets SET status = ? WHERE id = ? AND org_id = ?",
                    (status, asset_id, org_id),
                )
                if cur.rowcount == 0:
                    raise KeyError(
                        f"Asset {asset_id} not found in org {org_id}"
                    )
                row = conn.execute(
                    "SELECT * FROM ots_assets WHERE id = ? AND org_id = ?",
                    (asset_id, org_id),
                ).fetchone()
        return self._row(row)

    # ------------------------------------------------------------------
    # Incidents
    # ------------------------------------------------------------------

    def record_incident(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record an OT security incident."""
        incident_type = data.get("incident_type", "")
        if incident_type not in _VALID_INCIDENT_TYPES:
            raise ValueError(
                f"Invalid incident_type: {incident_type}. "
                f"Must be one of {sorted(_VALID_INCIDENT_TYPES)}"
            )

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity: {severity}. "
                f"Must be one of {sorted(_VALID_SEVERITIES)}"
            )

        impact_level = data.get("impact_level", "none")
        if impact_level not in _VALID_IMPACT_LEVELS:
            raise ValueError(
                f"Invalid impact_level: {impact_level}. "
                f"Must be one of {sorted(_VALID_IMPACT_LEVELS)}"
            )

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "asset_id": data.get("asset_id", ""),
            "incident_type": incident_type,
            "severity": severity,
            "impact_level": impact_level,
            "status": "detected",
            "detected_at": data.get("detected_at", now),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO ots_incidents
                       (id, org_id, asset_id, incident_type, severity, impact_level,
                        status, detected_at, created_at)
                       VALUES
                       (:id, :org_id, :asset_id, :incident_type, :severity, :impact_level,
                        :status, :detected_at, :created_at)""",
                    record,
                )
        return record

    def list_incidents(
        self,
        org_id: str,
        asset_id: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List incidents with optional filters."""
        sql = "SELECT * FROM ots_incidents WHERE org_id = ?"
        params: list = [org_id]
        if asset_id is not None:
            sql += " AND asset_id = ?"
            params.append(asset_id)
        if severity is not None:
            sql += " AND severity = ?"
            params.append(severity)
        if status is not None:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def update_incident_status(
        self, org_id: str, incident_id: str, status: str
    ) -> Dict[str, Any]:
        """Update incident status. Validates allowed values."""
        if status not in _VALID_INCIDENT_STATUSES:
            raise ValueError(
                f"Invalid status: {status}. "
                f"Must be one of {sorted(_VALID_INCIDENT_STATUSES)}"
            )
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    "UPDATE ots_incidents SET status = ? WHERE id = ? AND org_id = ?",
                    (status, incident_id, org_id),
                )
                if cur.rowcount == 0:
                    raise KeyError(
                        f"Incident {incident_id} not found in org {org_id}"
                    )
                row = conn.execute(
                    "SELECT * FROM ots_incidents WHERE id = ? AND org_id = ?",
                    (incident_id, org_id),
                ).fetchone()
        return self._row(row)

    # ------------------------------------------------------------------
    # Zones
    # ------------------------------------------------------------------

    def create_zone(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create an OT network zone."""
        zone_type = data.get("zone_type", "")
        if zone_type not in _VALID_ZONE_TYPES:
            raise ValueError(
                f"Invalid zone_type: {zone_type}. "
                f"Must be one of {sorted(_VALID_ZONE_TYPES)}"
            )

        security_level = data.get("security_level", "sl1")
        if security_level not in _VALID_SECURITY_LEVELS:
            raise ValueError(
                f"Invalid security_level: {security_level}. "
                f"Must be one of {sorted(_VALID_SECURITY_LEVELS)}"
            )

        purdue_level = int(data.get("purdue_level", 0))
        if purdue_level < 0 or purdue_level > 5:
            raise ValueError("purdue_level must be between 0 and 5")

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "zone_name": data.get("zone_name", ""),
            "zone_type": zone_type,
            "asset_count": int(data.get("asset_count", 0)),
            "security_level": security_level,
            "purdue_level": purdue_level,
            "conduit_count": int(data.get("conduit_count", 0)),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO ots_zones
                       (id, org_id, zone_name, zone_type, asset_count, security_level,
                        purdue_level, conduit_count, created_at)
                       VALUES
                       (:id, :org_id, :zone_name, :zone_type, :asset_count, :security_level,
                        :purdue_level, :conduit_count, :created_at)""",
                    record,
                )
        return record

    def list_zones(
        self, org_id: str, zone_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List zones with optional zone_type filter."""
        sql = "SELECT * FROM ots_zones WHERE org_id = ?"
        params: list = [org_id]
        if zone_type is not None:
            sql += " AND zone_type = ?"
            params.append(zone_type)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_ot_stats(self, org_id: str) -> Dict[str, Any]:
        """Aggregated OT security statistics for an org."""
        with self._conn() as conn:
            total_assets = conn.execute(
                "SELECT COUNT(*) FROM ots_assets WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            operational_assets = conn.execute(
                "SELECT COUNT(*) FROM ots_assets WHERE org_id = ? AND status = 'operational'",
                (org_id,),
            ).fetchone()[0]

            compromised_assets = conn.execute(
                "SELECT COUNT(*) FROM ots_assets WHERE org_id = ? AND status = 'compromised'",
                (org_id,),
            ).fetchone()[0]

            total_incidents = conn.execute(
                "SELECT COUNT(*) FROM ots_incidents WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            open_incidents = conn.execute(
                """SELECT COUNT(*) FROM ots_incidents
                   WHERE org_id = ? AND status IN ('detected', 'investigating')""",
                (org_id,),
            ).fetchone()[0]

            critical_incidents = conn.execute(
                "SELECT COUNT(*) FROM ots_incidents WHERE org_id = ? AND severity = 'critical'",
                (org_id,),
            ).fetchone()[0]

            total_zones = conn.execute(
                "SELECT COUNT(*) FROM ots_zones WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            type_rows = conn.execute(
                """SELECT asset_type, COUNT(*) as cnt
                   FROM ots_assets WHERE org_id = ?
                   GROUP BY asset_type""",
                (org_id,),
            ).fetchall()
            by_asset_type = {r["asset_type"]: r["cnt"] for r in type_rows}

            zone_rows = conn.execute(
                """SELECT zone, COUNT(*) as cnt
                   FROM ots_assets WHERE org_id = ?
                   GROUP BY zone""",
                (org_id,),
            ).fetchall()
            by_zone = {r["zone"]: r["cnt"] for r in zone_rows}

            incident_type_rows = conn.execute(
                """SELECT incident_type, COUNT(*) as cnt
                   FROM ots_incidents WHERE org_id = ?
                   GROUP BY incident_type""",
                (org_id,),
            ).fetchall()
            by_incident_type = {r["incident_type"]: r["cnt"] for r in incident_type_rows}

        return {
            "total_assets": total_assets,
            "operational_assets": operational_assets,
            "compromised_assets": compromised_assets,
            "total_incidents": total_incidents,
            "open_incidents": open_incidents,
            "critical_incidents": critical_incidents,
            "total_zones": total_zones,
            "by_asset_type": by_asset_type,
            "by_zone": by_zone,
            "by_incident_type": by_incident_type,
        }
