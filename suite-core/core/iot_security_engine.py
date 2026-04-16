"""IoT Security Engine — ALDECI.

Manages IoT device security posture including device inventory, anomaly
detection, and policy enforcement.

Capabilities:
  - IoT device registration across categories (sensor, camera, gateway, etc.)
  - Protocol-aware risk tracking (mqtt, coap, modbus, zigbee, etc.)
  - Anomaly recording with severity classification
  - Policy lifecycle management (network_isolation, auth_enforcement, etc.)
  - Multi-tenant org_id isolation
  - Stats aggregation (by_category, by_protocol)

Compliance: NIST IR 8259 (IoT Security), IEC 62443, CIS Controls v8 (Control 1)
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "iot_security.db"
)

_VALID_CATEGORIES = {
    "sensor", "actuator", "gateway", "camera", "wearable",
    "smart_home", "industrial", "medical", "vehicle", "other"
}
_VALID_PROTOCOLS = {
    "mqtt", "coap", "http", "modbus", "bacnet",
    "zigbee", "zwave", "bluetooth", "wifi", "cellular"
}
_VALID_DEVICE_STATUSES = {"online", "offline", "quarantined", "decommissioned"}
_VALID_ANOMALY_TYPES = {
    "unusual_traffic", "port_scan", "data_exfil", "command_injection",
    "firmware_tampering", "auth_failure", "dos_attempt", "lateral_movement"
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_ANOMALY_STATUSES = {"open", "investigating", "resolved", "false_positive"}
_VALID_POLICY_TYPES = {
    "network_isolation", "traffic_filtering", "auth_enforcement",
    "update_requirement", "monitoring"
}
_VALID_ENFORCEMENTS = {"mandatory", "recommended"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class IoTSecurityEngine:
    """SQLite WAL-backed IoT security engine.

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
                CREATE TABLE IF NOT EXISTS iot_devices (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    device_name      TEXT NOT NULL DEFAULT '',
                    device_category  TEXT NOT NULL DEFAULT 'other',
                    protocol         TEXT NOT NULL DEFAULT 'mqtt',
                    ip_address       TEXT NOT NULL DEFAULT '',
                    mac_address      TEXT NOT NULL DEFAULT '',
                    firmware_version TEXT NOT NULL DEFAULT '',
                    last_seen        DATETIME,
                    risk_score       REAL NOT NULL DEFAULT 50.0,
                    status           TEXT NOT NULL DEFAULT 'online',
                    created_at       DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_iotdev_org
                    ON iot_devices (org_id);

                CREATE INDEX IF NOT EXISTS idx_iotdev_org_category
                    ON iot_devices (org_id, device_category);

                CREATE INDEX IF NOT EXISTS idx_iotdev_org_status
                    ON iot_devices (org_id, status);

                CREATE TABLE IF NOT EXISTS iot_anomalies (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    device_id    TEXT NOT NULL,
                    anomaly_type TEXT NOT NULL DEFAULT 'unusual_traffic',
                    severity     TEXT NOT NULL DEFAULT 'medium',
                    description  TEXT NOT NULL DEFAULT '',
                    detected_at  DATETIME,
                    status       TEXT NOT NULL DEFAULT 'open',
                    created_at   DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_iotanomaly_org_device
                    ON iot_anomalies (org_id, device_id);

                CREATE INDEX IF NOT EXISTS idx_iotanomaly_org_severity
                    ON iot_anomalies (org_id, severity);

                CREATE TABLE IF NOT EXISTS iot_policies (
                    id                   TEXT PRIMARY KEY,
                    org_id               TEXT NOT NULL,
                    policy_name          TEXT NOT NULL DEFAULT '',
                    policy_type          TEXT NOT NULL DEFAULT 'monitoring',
                    applies_to_category  TEXT NOT NULL DEFAULT 'all',
                    enforcement          TEXT NOT NULL DEFAULT 'recommended',
                    enabled              INTEGER NOT NULL DEFAULT 1,
                    created_at           DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_iotpol_org
                    ON iot_policies (org_id);
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
    # Devices
    # ------------------------------------------------------------------

    def register_device(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new IoT device. Returns the created record."""
        category = data.get("device_category", "other")
        if category not in _VALID_CATEGORIES:
            raise ValueError(
                f"Invalid device_category: {category}. Must be one of {sorted(_VALID_CATEGORIES)}"
            )

        protocol = data.get("protocol", "mqtt")
        if protocol not in _VALID_PROTOCOLS:
            raise ValueError(
                f"Invalid protocol: {protocol}. Must be one of {sorted(_VALID_PROTOCOLS)}"
            )

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "device_name": data.get("device_name", ""),
            "device_category": category,
            "protocol": protocol,
            "ip_address": data.get("ip_address", ""),
            "mac_address": data.get("mac_address", ""),
            "firmware_version": data.get("firmware_version", ""),
            "last_seen": data.get("last_seen"),
            "risk_score": float(data.get("risk_score", 50.0)),
            "status": data.get("status", "online"),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO iot_devices
                       (id, org_id, device_name, device_category, protocol,
                        ip_address, mac_address, firmware_version, last_seen,
                        risk_score, status, created_at)
                       VALUES (:id, :org_id, :device_name, :device_category, :protocol,
                               :ip_address, :mac_address, :firmware_version, :last_seen,
                               :risk_score, :status, :created_at)""",
                    record,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ASSET_DISCOVERED", {"entity_type": "iot_security", "org_id": org_id, "source_engine": "iot_security"})
            except Exception:
                pass

        return record

    def list_devices(
        self,
        org_id: str,
        device_category: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List devices for an org, with optional filters."""
        sql = "SELECT * FROM iot_devices WHERE org_id = ?"
        params: List[Any] = [org_id]
        if device_category:
            sql += " AND device_category = ?"
            params.append(device_category)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_device(self, org_id: str, device_id: str) -> Optional[Dict[str, Any]]:
        """Get a single device by ID with org isolation."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM iot_devices WHERE id = ? AND org_id = ?",
                (device_id, org_id),
            ).fetchone()
        return self._row(row) if row else None

    def update_device_status(
        self, org_id: str, device_id: str, status: str
    ) -> Optional[Dict[str, Any]]:
        """Update device status. Returns updated record or None if not found."""
        if status not in _VALID_DEVICE_STATUSES:
            raise ValueError(
                f"Invalid status: {status}. Must be one of {sorted(_VALID_DEVICE_STATUSES)}"
            )
        with self._lock:
            with self._conn() as conn:
                result = conn.execute(
                    "UPDATE iot_devices SET status = ? WHERE id = ? AND org_id = ?",
                    (status, device_id, org_id),
                )
                if result.rowcount == 0:
                    return None
        return self.get_device(org_id, device_id)

    # ------------------------------------------------------------------
    # Anomalies
    # ------------------------------------------------------------------

    def record_anomaly(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record an IoT anomaly. Returns the created record."""
        anomaly_type = data.get("anomaly_type", "unusual_traffic")
        if anomaly_type not in _VALID_ANOMALY_TYPES:
            raise ValueError(
                f"Invalid anomaly_type: {anomaly_type}. Must be one of {sorted(_VALID_ANOMALY_TYPES)}"
            )

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity: {severity}. Must be one of {sorted(_VALID_SEVERITIES)}"
            )

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "device_id": data.get("device_id", ""),
            "anomaly_type": anomaly_type,
            "severity": severity,
            "description": data.get("description", ""),
            "detected_at": data.get("detected_at", now),
            "status": "open",
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO iot_anomalies
                       (id, org_id, device_id, anomaly_type, severity, description,
                        detected_at, status, created_at)
                       VALUES (:id, :org_id, :device_id, :anomaly_type, :severity,
                               :description, :detected_at, :status, :created_at)""",
                    record,
                )
        return record

    def list_anomalies(
        self,
        org_id: str,
        device_id: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List anomalies for an org, with optional filters."""
        sql = "SELECT * FROM iot_anomalies WHERE org_id = ?"
        params: List[Any] = [org_id]
        if device_id:
            sql += " AND device_id = ?"
            params.append(device_id)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def resolve_anomaly(
        self, org_id: str, anomaly_id: str, resolution_status: str
    ) -> Optional[Dict[str, Any]]:
        """Update anomaly resolution status. Returns updated record or None."""
        if resolution_status not in _VALID_ANOMALY_STATUSES:
            raise ValueError(
                f"Invalid resolution_status: {resolution_status}. "
                f"Must be one of {sorted(_VALID_ANOMALY_STATUSES)}"
            )
        with self._lock:
            with self._conn() as conn:
                result = conn.execute(
                    "UPDATE iot_anomalies SET status = ? WHERE id = ? AND org_id = ?",
                    (resolution_status, anomaly_id, org_id),
                )
                if result.rowcount == 0:
                    return None
                row = conn.execute(
                    "SELECT * FROM iot_anomalies WHERE id = ?", (anomaly_id,)
                ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Policies
    # ------------------------------------------------------------------

    def create_policy(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create an IoT security policy. Returns the created record."""
        policy_type = data.get("policy_type", "monitoring")
        if policy_type not in _VALID_POLICY_TYPES:
            raise ValueError(
                f"Invalid policy_type: {policy_type}. Must be one of {sorted(_VALID_POLICY_TYPES)}"
            )

        enforcement = data.get("enforcement", "recommended")
        if enforcement not in _VALID_ENFORCEMENTS:
            raise ValueError(
                f"Invalid enforcement: {enforcement}. Must be one of {sorted(_VALID_ENFORCEMENTS)}"
            )

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "policy_name": data.get("policy_name", ""),
            "policy_type": policy_type,
            "applies_to_category": data.get("applies_to_category", "all"),
            "enforcement": enforcement,
            "enabled": int(bool(data.get("enabled", True))),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO iot_policies
                       (id, org_id, policy_name, policy_type, applies_to_category,
                        enforcement, enabled, created_at)
                       VALUES (:id, :org_id, :policy_name, :policy_type,
                               :applies_to_category, :enforcement, :enabled, :created_at)""",
                    record,
                )
        return record

    def list_policies(
        self,
        org_id: str,
        enabled: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        """List policies for an org, optionally filtered by enabled flag."""
        sql = "SELECT * FROM iot_policies WHERE org_id = ?"
        params: List[Any] = [org_id]
        if enabled is not None:
            sql += " AND enabled = ?"
            params.append(int(enabled))
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_iot_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated IoT security statistics for the org."""
        with self._conn() as conn:
            total_devices = conn.execute(
                "SELECT COUNT(*) FROM iot_devices WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            online_devices = conn.execute(
                "SELECT COUNT(*) FROM iot_devices WHERE org_id = ? AND status = 'online'",
                (org_id,),
            ).fetchone()[0]

            quarantined_devices = conn.execute(
                "SELECT COUNT(*) FROM iot_devices WHERE org_id = ? AND status = 'quarantined'",
                (org_id,),
            ).fetchone()[0]

            total_anomalies = conn.execute(
                "SELECT COUNT(*) FROM iot_anomalies WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            open_anomalies = conn.execute(
                "SELECT COUNT(*) FROM iot_anomalies WHERE org_id = ? AND status = 'open'",
                (org_id,),
            ).fetchone()[0]

            critical_anomalies = conn.execute(
                "SELECT COUNT(*) FROM iot_anomalies WHERE org_id = ? AND severity = 'critical'",
                (org_id,),
            ).fetchone()[0]

            by_category_rows = conn.execute(
                "SELECT device_category, COUNT(*) as cnt FROM iot_devices WHERE org_id = ? GROUP BY device_category",
                (org_id,),
            ).fetchall()
            by_category = {r["device_category"]: r["cnt"] for r in by_category_rows}

            by_protocol_rows = conn.execute(
                "SELECT protocol, COUNT(*) as cnt FROM iot_devices WHERE org_id = ? GROUP BY protocol",
                (org_id,),
            ).fetchall()
            by_protocol = {r["protocol"]: r["cnt"] for r in by_protocol_rows}

            avg_risk_row = conn.execute(
                "SELECT AVG(risk_score) FROM iot_devices WHERE org_id = ?", (org_id,)
            ).fetchone()
            avg_risk_score = float(avg_risk_row[0]) if avg_risk_row[0] is not None else 0.0

        return {
            "total_devices": total_devices,
            "online_devices": online_devices,
            "quarantined_devices": quarantined_devices,
            "total_anomalies": total_anomalies,
            "open_anomalies": open_anomalies,
            "critical_anomalies": critical_anomalies,
            "by_category": by_category,
            "by_protocol": by_protocol,
            "avg_risk_score": round(avg_risk_score, 2),
        }
