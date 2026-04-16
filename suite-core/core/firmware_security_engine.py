"""Firmware Security Engine — ALDECI.

Manages firmware security posture for network devices, IoT, OT, and embedded
systems. Tracks devices, vulnerabilities, and scan results per org.

Capabilities:
  - Device registration with firmware version tracking
  - CVE-linked vulnerability recording per device
  - Firmware scan lifecycle (static/dynamic/network/binary)
  - Risk scoring and level assignment
  - Multi-tenant org_id isolation
  - Stats aggregation (by device_type, risk_level)

Compliance: NIST SP 800-82 (ICS/SCADA), IEC 62443, CIS Controls v8 (Control 2)
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "firmware_security.db"
)

_VALID_DEVICE_TYPES = {
    "router", "switch", "camera", "iot_hub", "plc", "embedded", "industrial", "medical"
}
_VALID_RISK_LEVELS = {"critical", "high", "medium", "low"}
_VALID_STATUSES = {"active", "inactive", "decommissioned"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_VULN_STATUSES = {"open", "patched", "mitigated", "accepted"}
_VALID_SCAN_TYPES = {"static", "dynamic", "network", "binary"}
_VALID_SCAN_STATUSES = {"queued", "running", "completed", "failed"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class FirmwareSecurityEngine:
    """SQLite WAL-backed firmware security engine.

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
                CREATE TABLE IF NOT EXISTS fw_devices (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    device_name      TEXT NOT NULL DEFAULT '',
                    device_type      TEXT NOT NULL DEFAULT 'embedded',
                    manufacturer     TEXT NOT NULL DEFAULT '',
                    model            TEXT NOT NULL DEFAULT '',
                    firmware_version TEXT NOT NULL DEFAULT '',
                    last_scanned     DATETIME,
                    risk_score       REAL NOT NULL DEFAULT 50.0,
                    risk_level       TEXT NOT NULL DEFAULT 'medium',
                    status           TEXT NOT NULL DEFAULT 'active',
                    created_at       DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_fwdev_org
                    ON fw_devices (org_id);

                CREATE INDEX IF NOT EXISTS idx_fwdev_org_type
                    ON fw_devices (org_id, device_type);

                CREATE INDEX IF NOT EXISTS idx_fwdev_org_risk
                    ON fw_devices (org_id, risk_level);

                CREATE TABLE IF NOT EXISTS fw_vulnerabilities (
                    id                 TEXT PRIMARY KEY,
                    org_id             TEXT NOT NULL,
                    device_id          TEXT NOT NULL,
                    cve_id             TEXT NOT NULL DEFAULT '',
                    title              TEXT NOT NULL DEFAULT '',
                    severity           TEXT NOT NULL DEFAULT 'medium',
                    cvss_score         REAL NOT NULL DEFAULT 0.0,
                    affected_component TEXT NOT NULL DEFAULT '',
                    patch_available    INTEGER NOT NULL DEFAULT 0,
                    patch_version      TEXT NOT NULL DEFAULT '',
                    status             TEXT NOT NULL DEFAULT 'open',
                    discovered_at      DATETIME,
                    created_at         DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_fwvuln_org_device
                    ON fw_vulnerabilities (org_id, device_id);

                CREATE INDEX IF NOT EXISTS idx_fwvuln_org_severity
                    ON fw_vulnerabilities (org_id, severity);

                CREATE TABLE IF NOT EXISTS fw_scans (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    device_id       TEXT NOT NULL,
                    scan_type       TEXT NOT NULL DEFAULT 'static',
                    scan_status     TEXT NOT NULL DEFAULT 'queued',
                    findings_count  INTEGER NOT NULL DEFAULT 0,
                    critical_count  INTEGER NOT NULL DEFAULT 0,
                    high_count      INTEGER NOT NULL DEFAULT 0,
                    started_at      DATETIME,
                    completed_at    DATETIME,
                    created_at      DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_fwscan_org_device
                    ON fw_scans (org_id, device_id);
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
        """Register a new firmware device. Returns the created record."""
        device_type = data.get("device_type", "embedded")
        if device_type not in _VALID_DEVICE_TYPES:
            raise ValueError(
                f"Invalid device_type: {device_type}. Must be one of {sorted(_VALID_DEVICE_TYPES)}"
            )

        risk_score = float(data.get("risk_score", 50.0))
        risk_level = data.get("risk_level", "medium")
        if risk_level not in _VALID_RISK_LEVELS:
            raise ValueError(
                f"Invalid risk_level: {risk_level}. Must be one of {sorted(_VALID_RISK_LEVELS)}"
            )

        status = data.get("status", "active")
        if status not in _VALID_STATUSES:
            raise ValueError(
                f"Invalid status: {status}. Must be one of {sorted(_VALID_STATUSES)}"
            )

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "device_name": data.get("device_name", ""),
            "device_type": device_type,
            "manufacturer": data.get("manufacturer", ""),
            "model": data.get("model", ""),
            "firmware_version": data.get("firmware_version", ""),
            "last_scanned": data.get("last_scanned"),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "status": status,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO fw_devices
                       (id, org_id, device_name, device_type, manufacturer, model,
                        firmware_version, last_scanned, risk_score, risk_level,
                        status, created_at)
                       VALUES (:id, :org_id, :device_name, :device_type, :manufacturer,
                               :model, :firmware_version, :last_scanned, :risk_score,
                               :risk_level, :status, :created_at)""",
                    record,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ASSET_DISCOVERED", {"entity_type": "firmware_security", "org_id": org_id, "source_engine": "firmware_security"})
            except Exception:
                pass

        return record

    def list_devices(
        self,
        org_id: str,
        device_type: Optional[str] = None,
        risk_level: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List devices for an org, with optional filters."""
        sql = "SELECT * FROM fw_devices WHERE org_id = ?"
        params: List[Any] = [org_id]
        if device_type:
            sql += " AND device_type = ?"
            params.append(device_type)
        if risk_level:
            sql += " AND risk_level = ?"
            params.append(risk_level)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_device(self, org_id: str, device_id: str) -> Optional[Dict[str, Any]]:
        """Get a single device by ID with org isolation."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM fw_devices WHERE id = ? AND org_id = ?",
                (device_id, org_id),
            ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Vulnerabilities
    # ------------------------------------------------------------------

    def record_vulnerability(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a firmware vulnerability. Returns the created record."""
        device_id = data.get("device_id", "")
        if not device_id:
            raise ValueError("device_id is required")

        cve_id = data.get("cve_id", "")
        if not cve_id:
            raise ValueError("cve_id is required")

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity: {severity}. Must be one of {sorted(_VALID_SEVERITIES)}"
            )

        status = data.get("status", "open")
        if status not in _VALID_VULN_STATUSES:
            raise ValueError(
                f"Invalid status: {status}. Must be one of {sorted(_VALID_VULN_STATUSES)}"
            )

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "device_id": device_id,
            "cve_id": cve_id,
            "title": data.get("title", ""),
            "severity": severity,
            "cvss_score": float(data.get("cvss_score", 0.0)),
            "affected_component": data.get("affected_component", ""),
            "patch_available": int(bool(data.get("patch_available", False))),
            "patch_version": data.get("patch_version", ""),
            "status": status,
            "discovered_at": data.get("discovered_at"),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO fw_vulnerabilities
                       (id, org_id, device_id, cve_id, title, severity, cvss_score,
                        affected_component, patch_available, patch_version, status,
                        discovered_at, created_at)
                       VALUES (:id, :org_id, :device_id, :cve_id, :title, :severity,
                               :cvss_score, :affected_component, :patch_available,
                               :patch_version, :status, :discovered_at, :created_at)""",
                    record,
                )
        return record

    def list_vulnerabilities(
        self,
        org_id: str,
        device_id: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List vulnerabilities for an org, with optional filters."""
        sql = "SELECT * FROM fw_vulnerabilities WHERE org_id = ?"
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

    # ------------------------------------------------------------------
    # Scans
    # ------------------------------------------------------------------

    def create_scan(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a firmware scan job. Returns the created record."""
        scan_type = data.get("scan_type", "static")
        if scan_type not in _VALID_SCAN_TYPES:
            raise ValueError(
                f"Invalid scan_type: {scan_type}. Must be one of {sorted(_VALID_SCAN_TYPES)}"
            )

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "device_id": data.get("device_id", ""),
            "scan_type": scan_type,
            "scan_status": "queued",
            "findings_count": 0,
            "critical_count": 0,
            "high_count": 0,
            "started_at": data.get("started_at"),
            "completed_at": None,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO fw_scans
                       (id, org_id, device_id, scan_type, scan_status, findings_count,
                        critical_count, high_count, started_at, completed_at, created_at)
                       VALUES (:id, :org_id, :device_id, :scan_type, :scan_status,
                               :findings_count, :critical_count, :high_count,
                               :started_at, :completed_at, :created_at)""",
                    record,
                )
        return record

    def complete_scan(
        self,
        org_id: str,
        scan_id: str,
        findings_count: int,
        critical_count: int,
        high_count: int,
    ) -> Optional[Dict[str, Any]]:
        """Mark scan completed and update device.last_scanned. Returns updated scan or None."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM fw_scans WHERE id = ? AND org_id = ?",
                    (scan_id, org_id),
                ).fetchone()
                if not row:
                    return None
                scan = self._row(row)
                conn.execute(
                    """UPDATE fw_scans
                       SET scan_status = 'completed', findings_count = ?,
                           critical_count = ?, high_count = ?, completed_at = ?
                       WHERE id = ? AND org_id = ?""",
                    (findings_count, critical_count, high_count, now, scan_id, org_id),
                )
                # Update device.last_scanned if device_id present
                device_id = scan.get("device_id", "")
                if device_id:
                    conn.execute(
                        "UPDATE fw_devices SET last_scanned = ? WHERE id = ? AND org_id = ?",
                        (now, device_id, org_id),
                    )
        # Return updated record
        with self._conn() as conn:
            updated = conn.execute(
                "SELECT * FROM fw_scans WHERE id = ?", (scan_id,)
            ).fetchone()
        return self._row(updated) if updated else None

    def list_scans(
        self,
        org_id: str,
        device_id: Optional[str] = None,
        scan_status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List scans for an org, with optional filters."""
        sql = "SELECT * FROM fw_scans WHERE org_id = ?"
        params: List[Any] = [org_id]
        if device_id:
            sql += " AND device_id = ?"
            params.append(device_id)
        if scan_status:
            sql += " AND scan_status = ?"
            params.append(scan_status)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_firmware_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated firmware security statistics for the org."""
        with self._conn() as conn:
            total_devices = conn.execute(
                "SELECT COUNT(*) FROM fw_devices WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            active_devices = conn.execute(
                "SELECT COUNT(*) FROM fw_devices WHERE org_id = ? AND status = 'active'",
                (org_id,),
            ).fetchone()[0]

            total_vulns = conn.execute(
                "SELECT COUNT(*) FROM fw_vulnerabilities WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            unpatched_vulns = conn.execute(
                "SELECT COUNT(*) FROM fw_vulnerabilities WHERE org_id = ? AND patch_available = 0 AND status = 'open'",
                (org_id,),
            ).fetchone()[0]

            critical_vulns = conn.execute(
                "SELECT COUNT(*) FROM fw_vulnerabilities WHERE org_id = ? AND severity = 'critical'",
                (org_id,),
            ).fetchone()[0]

            avg_risk_row = conn.execute(
                "SELECT AVG(risk_score) FROM fw_devices WHERE org_id = ?", (org_id,)
            ).fetchone()
            avg_risk_score = float(avg_risk_row[0]) if avg_risk_row[0] is not None else 0.0

            by_type_rows = conn.execute(
                "SELECT device_type, COUNT(*) as cnt FROM fw_devices WHERE org_id = ? GROUP BY device_type",
                (org_id,),
            ).fetchall()
            by_device_type = {r["device_type"]: r["cnt"] for r in by_type_rows}

            by_risk_rows = conn.execute(
                "SELECT risk_level, COUNT(*) as cnt FROM fw_devices WHERE org_id = ? GROUP BY risk_level",
                (org_id,),
            ).fetchall()
            by_risk_level = {r["risk_level"]: r["cnt"] for r in by_risk_rows}

        return {
            "total_devices": total_devices,
            "active_devices": active_devices,
            "total_vulns": total_vulns,
            "unpatched_vulns": unpatched_vulns,
            "critical_vulns": critical_vulns,
            "avg_risk_score": round(avg_risk_score, 2),
            "by_device_type": by_device_type,
            "by_risk_level": by_risk_level,
        }
