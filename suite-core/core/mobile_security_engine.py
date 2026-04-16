"""Mobile Security Engine — ALDECI.

Track mobile device inventory, MDM policy compliance, and mobile threat detection.

Compliance: CIS Controls v8 4.1, NIST SP 800-124r2, OWASP Mobile Top 10
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "mobile_security.db"
)

_VALID_PLATFORMS = {"ios", "android", "windows_phone"}
_VALID_ENROLLMENT = {"enrolled", "pending", "unenrolled"}
_VALID_COMPLIANCE = {"compliant", "non_compliant", "unknown"}
_VALID_THREAT_TYPES = {
    "malware", "jailbreak", "rooted", "outdated_os",
    "unauthorized_app", "network_attack",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_VALID_THREAT_STATUSES = {"active", "remediated", "false_positive"}


class MobileSecurityEngine:
    """SQLite WAL-backed mobile device security and MDM policy engine.

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
                CREATE TABLE IF NOT EXISTS mobile_devices (
                    device_id           TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    device_name         TEXT NOT NULL,
                    platform            TEXT NOT NULL DEFAULT 'unknown',
                    os_version          TEXT NOT NULL DEFAULT '',
                    enrollment_status   TEXT NOT NULL DEFAULT 'pending',
                    compliance_status   TEXT NOT NULL DEFAULT 'unknown',
                    risk_score          INTEGER NOT NULL DEFAULT 0,
                    jailbroken          INTEGER NOT NULL DEFAULT 0,
                    last_checkin        DATETIME NOT NULL,
                    created_at          DATETIME NOT NULL,
                    updated_at          DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_md_org
                    ON mobile_devices (org_id, platform);

                CREATE INDEX IF NOT EXISTS idx_md_compliance
                    ON mobile_devices (org_id, compliance_status);

                CREATE TABLE IF NOT EXISTS mobile_threats (
                    threat_id     TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    device_id     TEXT NOT NULL,
                    threat_type   TEXT NOT NULL,
                    severity      TEXT NOT NULL DEFAULT 'medium',
                    description   TEXT NOT NULL DEFAULT '',
                    status        TEXT NOT NULL DEFAULT 'active',
                    created_at    DATETIME NOT NULL,
                    updated_at    DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_mt_org
                    ON mobile_threats (org_id, status);

                CREATE INDEX IF NOT EXISTS idx_mt_severity
                    ON mobile_threats (org_id, severity);

                CREATE TABLE IF NOT EXISTS mdm_policies (
                    policy_id            TEXT PRIMARY KEY,
                    org_id               TEXT NOT NULL,
                    name                 TEXT NOT NULL,
                    require_encryption   INTEGER NOT NULL DEFAULT 1,
                    require_pin          INTEGER NOT NULL DEFAULT 1,
                    min_os_version       TEXT NOT NULL DEFAULT '',
                    allow_jailbroken     INTEGER NOT NULL DEFAULT 0,
                    remote_wipe_enabled  INTEGER NOT NULL DEFAULT 0,
                    created_at           DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_mdmp_org
                    ON mdm_policies (org_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _device_row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        d["jailbroken"] = bool(d["jailbroken"])
        return d

    @staticmethod
    def _policy_row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        for field in ("require_encryption", "require_pin", "allow_jailbroken", "remote_wipe_enabled"):
            if field in d:
                d[field] = bool(d[field])
        return d

    # ------------------------------------------------------------------
    # Devices
    # ------------------------------------------------------------------

    def register_device(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a mobile device. Returns the created device dict."""
        device_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        platform = data.get("platform", "android")
        if platform not in _VALID_PLATFORMS:
            platform = "android"

        enrollment_status = data.get("enrollment_status", "pending")
        if enrollment_status not in _VALID_ENROLLMENT:
            enrollment_status = "pending"

        compliance_status = data.get("compliance_status", "unknown")
        if compliance_status not in _VALID_COMPLIANCE:
            compliance_status = "unknown"

        risk_score = max(0, min(100, int(data.get("risk_score", 0))))
        jailbroken = 1 if data.get("jailbroken") else 0
        last_checkin = data.get("last_checkin", now)

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO mobile_devices
                        (device_id, org_id, device_name, platform, os_version,
                         enrollment_status, compliance_status, risk_score,
                         jailbroken, last_checkin, created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        device_id, org_id,
                        data.get("device_name", "Unknown Device"),
                        platform,
                        data.get("os_version", ""),
                        enrollment_status,
                        compliance_status,
                        risk_score,
                        jailbroken,
                        last_checkin,
                        now, now,
                    ),
                )

        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ASSET_DISCOVERED", {"entity_type": "mobile_security", "org_id": org_id, "source_engine": "mobile_security"})
            except Exception:
                pass

        return {
            "device_id": device_id,
            "org_id": org_id,
            "device_name": data.get("device_name", "Unknown Device"),
            "platform": platform,
            "os_version": data.get("os_version", ""),
            "enrollment_status": enrollment_status,
            "compliance_status": compliance_status,
            "risk_score": risk_score,
            "jailbroken": bool(jailbroken),
            "last_checkin": last_checkin,
            "created_at": now,
            "updated_at": now,
        }

    def list_devices(
        self,
        org_id: str,
        platform: Optional[str] = None,
        compliance_status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List devices for an org, optionally filtered by platform and/or compliance_status."""
        params: list = [org_id]
        query = "SELECT * FROM mobile_devices WHERE org_id=?"

        if platform:
            query += " AND platform=?"
            params.append(platform)

        if compliance_status:
            query += " AND compliance_status=?"
            params.append(compliance_status)

        query += " ORDER BY created_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()

        return [self._device_row_to_dict(r) for r in rows]

    def update_device_compliance(
        self, org_id: str, device_id: str, data: Dict[str, Any]
    ) -> bool:
        """Update compliance-related fields on a device. Returns True if updated."""
        allowed = {"compliance_status", "risk_score", "jailbroken", "os_version",
                   "enrollment_status", "last_checkin"}
        fields: Dict[str, Any] = {k: v for k, v in data.items() if k in allowed}
        if not fields:
            return False

        if "jailbroken" in fields:
            fields["jailbroken"] = 1 if fields["jailbroken"] else 0
        if "risk_score" in fields:
            fields["risk_score"] = max(0, min(100, int(fields["risk_score"])))

        fields["updated_at"] = datetime.now(timezone.utc).isoformat()
        set_clause = ", ".join(f"{k}=?" for k in fields)
        values = list(fields.values()) + [device_id, org_id]

        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    f"UPDATE mobile_devices SET {set_clause} WHERE device_id=? AND org_id=?",  # nosec B608
                    values,
                )
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Threats
    # ------------------------------------------------------------------

    def create_threat(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a mobile threat. Returns the created threat dict."""
        threat_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        threat_type = data.get("threat_type", "malware")
        if threat_type not in _VALID_THREAT_TYPES:
            threat_type = "malware"

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            severity = "medium"

        status = data.get("status", "active")
        if status not in _VALID_THREAT_STATUSES:
            status = "active"

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO mobile_threats
                        (threat_id, org_id, device_id, threat_type, severity,
                         description, status, created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        threat_id, org_id,
                        data.get("device_id", ""),
                        threat_type, severity,
                        data.get("description", ""),
                        status, now, now,
                    ),
                )

        return {
            "threat_id": threat_id,
            "org_id": org_id,
            "device_id": data.get("device_id", ""),
            "threat_type": threat_type,
            "severity": severity,
            "description": data.get("description", ""),
            "status": status,
            "created_at": now,
            "updated_at": now,
        }

    def list_threats(
        self, org_id: str, severity: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List threats for an org, optionally filtered by severity."""
        params: list = [org_id]
        query = "SELECT * FROM mobile_threats WHERE org_id=?"

        if severity:
            query += " AND severity=?"
            params.append(severity)

        query += " ORDER BY created_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()

        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # MDM Policies
    # ------------------------------------------------------------------

    def create_mdm_policy(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create an MDM policy. Returns the created policy dict."""
        policy_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        row = {
            "policy_id": policy_id,
            "org_id": org_id,
            "name": data.get("name", "Default MDM Policy"),
            "require_encryption": 1 if data.get("require_encryption", True) else 0,
            "require_pin": 1 if data.get("require_pin", True) else 0,
            "min_os_version": data.get("min_os_version", ""),
            "allow_jailbroken": 1 if data.get("allow_jailbroken", False) else 0,
            "remote_wipe_enabled": 1 if data.get("remote_wipe_enabled", False) else 0,
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO mdm_policies
                        (policy_id, org_id, name, require_encryption, require_pin,
                         min_os_version, allow_jailbroken, remote_wipe_enabled, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        row["policy_id"], row["org_id"], row["name"],
                        row["require_encryption"], row["require_pin"],
                        row["min_os_version"], row["allow_jailbroken"],
                        row["remote_wipe_enabled"], row["created_at"],
                    ),
                )

        # Return with bool coercion
        row["require_encryption"] = bool(row["require_encryption"])
        row["require_pin"] = bool(row["require_pin"])
        row["allow_jailbroken"] = bool(row["allow_jailbroken"])
        row["remote_wipe_enabled"] = bool(row["remote_wipe_enabled"])
        return row

    def list_mdm_policies(self, org_id: str) -> List[Dict[str, Any]]:
        """Return all MDM policies for the given org."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM mdm_policies WHERE org_id=? ORDER BY created_at ASC",
                (org_id,),
            ).fetchall()
        return [self._policy_row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_mobile_stats(self, org_id: str) -> Dict[str, Any]:
        """Return summary statistics for the org's mobile device posture."""
        with self._conn() as conn:
            total_devices = conn.execute(
                "SELECT COUNT(*) FROM mobile_devices WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            enrolled = conn.execute(
                "SELECT COUNT(*) FROM mobile_devices WHERE org_id=? AND enrollment_status='enrolled'",
                (org_id,),
            ).fetchone()[0]

            compliant = conn.execute(
                "SELECT COUNT(*) FROM mobile_devices WHERE org_id=? AND compliance_status='compliant'",
                (org_id,),
            ).fetchone()[0]

            non_compliant = conn.execute(
                "SELECT COUNT(*) FROM mobile_devices WHERE org_id=? AND compliance_status='non_compliant'",
                (org_id,),
            ).fetchone()[0]

            jailbroken_count = conn.execute(
                "SELECT COUNT(*) FROM mobile_devices WHERE org_id=? AND jailbroken=1",
                (org_id,),
            ).fetchone()[0]

            active_threats = conn.execute(
                "SELECT COUNT(*) FROM mobile_threats WHERE org_id=? AND status='active'",
                (org_id,),
            ).fetchone()[0]

            platform_rows = conn.execute(
                """
                SELECT platform, COUNT(*) as cnt
                FROM mobile_devices WHERE org_id=?
                GROUP BY platform
                """,
                (org_id,),
            ).fetchall()

        by_platform = {r["platform"]: r["cnt"] for r in platform_rows}

        return {
            "total_devices": total_devices,
            "enrolled": enrolled,
            "compliant": compliant,
            "non_compliant": non_compliant,
            "jailbroken_count": jailbroken_count,
            "active_threats": active_threats,
            "by_platform": by_platform,
        }
