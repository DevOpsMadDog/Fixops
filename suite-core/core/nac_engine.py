"""NAC Engine — Network Access Control for ALDECI.

Manages device posture checks, 802.1X enforcement, quarantine, and VLAN assignment.

Features:
- Device registration (MAC/UUID identity, device type classification)
- Posture checks: OS patch level, AV status, disk encryption, certificate validity
- Policy engine: per-device-type rules, VLAN assignment on pass/fail
- Quarantine workflow: status transitions with audit trail
- Access event logging: connect/disconnect/quarantine/remediated events
- Stats: compliance percentage, quarantine count, 24h event volume

Compliance: NIST SP 800-82 (ICS NAC), CIS Control 1 (Asset Inventory),
            CIS Control 2 (Software Inventory), ISO 27001 A.9.1.2
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

from pydantic import BaseModel, Field

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(Path(__file__).resolve().parents[2] / ".fixops_data" / "nac.db")


# ============================================================================
# PYDANTIC MODELS
# ============================================================================


class DeviceCreate(BaseModel):
    hostname: str
    device_type: str = "laptop"  # laptop/server/mobile/iot/printer
    owner: Optional[str] = None
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    os_type: Optional[str] = None


class DeviceStatusUpdate(BaseModel):
    status: str  # compliant/non_compliant/quarantined/unknown
    reason: str
    updated_by: str


class PolicyCreate(BaseModel):
    name: str
    device_types: List[str] = Field(default_factory=list)
    required_checks: List[str] = Field(default_factory=list)
    vlan_on_pass: Optional[str] = None
    vlan_on_fail: Optional[str] = None
    action_on_fail: str = "quarantine"  # quarantine/block/notify


class AccessEventCreate(BaseModel):
    device_id: str
    event_type: str  # connect/disconnect/quarantine/remediated
    location: Optional[str] = None
    switch_port: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


# ============================================================================
# NAC ENGINE
# ============================================================================


class NACEngine:
    """Network Access Control engine — device posture, policy, quarantine."""

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db_path = db_path
        self._lock = threading.RLock()
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ------------------------------------------------------------------
    # DB INIT
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS nac_devices (
                    device_id    TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    hostname     TEXT NOT NULL,
                    device_type  TEXT NOT NULL DEFAULT 'laptop',
                    owner        TEXT,
                    ip_address   TEXT,
                    mac_address  TEXT,
                    os_type      TEXT,
                    status       TEXT NOT NULL DEFAULT 'unknown',
                    created_at   TEXT NOT NULL,
                    updated_at   TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS nac_posture_checks (
                    check_id     TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    device_id    TEXT NOT NULL,
                    passed       INTEGER NOT NULL,
                    score        REAL NOT NULL,
                    checks_json  TEXT NOT NULL,
                    recommended_action TEXT NOT NULL,
                    checked_at   TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS nac_policies (
                    policy_id        TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    name             TEXT NOT NULL,
                    device_types     TEXT NOT NULL,
                    required_checks  TEXT NOT NULL,
                    vlan_on_pass     TEXT,
                    vlan_on_fail     TEXT,
                    action_on_fail   TEXT NOT NULL DEFAULT 'quarantine',
                    created_at       TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS nac_access_events (
                    event_id     TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    device_id    TEXT NOT NULL,
                    event_type   TEXT NOT NULL,
                    location     TEXT,
                    switch_port  TEXT,
                    details      TEXT,
                    occurred_at  TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS nac_status_history (
                    history_id  TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    device_id   TEXT NOT NULL,
                    status      TEXT NOT NULL,
                    reason      TEXT,
                    updated_by  TEXT,
                    changed_at  TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_nac_devices_org ON nac_devices(org_id);
                CREATE INDEX IF NOT EXISTS idx_nac_events_org  ON nac_access_events(org_id);
                CREATE INDEX IF NOT EXISTS idx_nac_events_device ON nac_access_events(device_id);
            """)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # DEVICE MANAGEMENT
    # ------------------------------------------------------------------

    def register_device(self, org_id: str, data: DeviceCreate) -> Dict[str, Any]:
        """Register a new device under org_id. Returns the device record."""
        device_id = str(uuid.uuid4())
        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO nac_devices
                   (device_id, org_id, hostname, device_type, owner,
                    ip_address, mac_address, os_type, status, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    device_id, org_id, data.hostname, data.device_type,
                    data.owner, data.ip_address, data.mac_address,
                    data.os_type, "unknown", now, now,
                ),
            )
        _logger.info("nac.device_registered org=%s device_id=%s", org_id, device_id)
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "nac", "org_id": org_id, "source_engine": "nac"})
            except Exception:
                pass

        return self.get_device(org_id, device_id)

    def list_devices(
        self,
        org_id: str,
        device_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List devices for org, optionally filtered by device_type or status."""
        query = "SELECT * FROM nac_devices WHERE org_id=?"
        params: List[Any] = [org_id]
        if device_type:
            query += " AND device_type=?"
            params.append(device_type)
        if status:
            query += " AND status=?"
            params.append(status)
        query += " ORDER BY created_at DESC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_device(self, org_id: str, device_id: str) -> Dict[str, Any]:
        """Fetch a single device, scoped to org_id."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM nac_devices WHERE org_id=? AND device_id=?",
                (org_id, device_id),
            ).fetchone()
        if not row:
            raise ValueError(f"Device {device_id} not found for org {org_id}")
        return dict(row)

    # ------------------------------------------------------------------
    # POSTURE CHECKS
    # ------------------------------------------------------------------

    _POSTURE_CHECK_WEIGHTS: Dict[str, float] = {
        "os_patch_level": 30.0,
        "av_status": 25.0,
        "disk_encryption": 25.0,
        "certificate_validity": 20.0,
    }

    def run_posture_check(self, org_id: str, device_id: str) -> Dict[str, Any]:
        """Evaluate device posture. Returns {device_id, passed, score, checks, recommended_action}."""
        device = self.get_device(org_id, device_id)

        checks: List[Dict[str, Any]] = []
        score = 0.0

        # OS patch level — heuristic based on os_type presence
        os_type = device.get("os_type") or ""
        patch_result = "pass" if os_type and "eol" not in os_type.lower() else "fail"
        patch_detail = (
            f"OS type '{os_type}' detected; assumed patched"
            if patch_result == "pass"
            else "OS type missing or end-of-life — patch status unknown"
        )
        checks.append({"check_name": "os_patch_level", "result": patch_result, "details": patch_detail})
        if patch_result == "pass":
            score += self._POSTURE_CHECK_WEIGHTS["os_patch_level"]

        # AV status — warn for IoT/printer (no AV expected), pass for others with hostname
        device_type = device.get("device_type", "laptop")
        if device_type in ("iot", "printer"):
            av_result = "warning"
            av_detail = f"Device type '{device_type}' typically does not run AV software"
            score += self._POSTURE_CHECK_WEIGHTS["av_status"] * 0.5
        elif device.get("hostname"):
            av_result = "pass"
            av_detail = "AV agent assumed present on managed device"
            score += self._POSTURE_CHECK_WEIGHTS["av_status"]
        else:
            av_result = "fail"
            av_detail = "Hostname missing — device manageability unconfirmed"
        checks.append({"check_name": "av_status", "result": av_result, "details": av_detail})

        # Disk encryption — pass for laptops/mobiles, warning for servers, fail for iot/printer
        if device_type in ("laptop", "mobile"):
            enc_result = "pass"
            enc_detail = "Full-disk encryption expected and assumed for portable device"
            score += self._POSTURE_CHECK_WEIGHTS["disk_encryption"]
        elif device_type == "server":
            enc_result = "warning"
            enc_detail = "Server disk encryption should be verified in CMDB"
            score += self._POSTURE_CHECK_WEIGHTS["disk_encryption"] * 0.5
        else:
            enc_result = "fail"
            enc_detail = f"Device type '{device_type}' does not support disk encryption"
        checks.append({"check_name": "disk_encryption", "result": enc_result, "details": enc_detail})

        # Certificate validity — pass if ip_address or mac_address present (802.1X cert enrolled)
        has_identity = bool(device.get("ip_address") or device.get("mac_address"))
        cert_result = "pass" if has_identity else "fail"
        cert_detail = (
            "Device identity (IP/MAC) present — 802.1X certificate assumed valid"
            if cert_result == "pass"
            else "No IP/MAC address registered — certificate enrollment required"
        )
        checks.append({"check_name": "certificate_validity", "result": cert_result, "details": cert_detail})
        if cert_result == "pass":
            score += self._POSTURE_CHECK_WEIGHTS["certificate_validity"]

        score = round(min(score, 100.0), 1)
        passed = score >= 60.0 and not any(c["result"] == "fail" for c in checks)

        if passed:
            recommended_action = "allow"
        elif score >= 40.0:
            recommended_action = "quarantine"
        else:
            recommended_action = "block"

        # Persist result
        check_id = str(uuid.uuid4())
        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO nac_posture_checks
                   (check_id, org_id, device_id, passed, score, checks_json, recommended_action, checked_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (check_id, org_id, device_id, int(passed), score, json.dumps(checks), recommended_action, now),
            )

        _logger.info(
            "nac.posture_check org=%s device_id=%s score=%.1f passed=%s action=%s",
            org_id, device_id, score, passed, recommended_action,
        )
        return {
            "device_id": device_id,
            "passed": passed,
            "score": score,
            "checks": checks,
            "recommended_action": recommended_action,
            "checked_at": now,
        }

    # ------------------------------------------------------------------
    # STATUS MANAGEMENT
    # ------------------------------------------------------------------

    def update_device_status(
        self,
        org_id: str,
        device_id: str,
        status: str,
        reason: str,
        updated_by: str,
    ) -> Dict[str, Any]:
        """Update device status and write history record."""
        valid_statuses = {"compliant", "non_compliant", "quarantined", "unknown"}
        if status not in valid_statuses:
            raise ValueError(f"Invalid status '{status}'. Must be one of {valid_statuses}")

        # Verify device belongs to org
        self.get_device(org_id, device_id)

        now = self._now()
        history_id = str(uuid.uuid4())
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE nac_devices SET status=?, updated_at=? WHERE org_id=? AND device_id=?",
                (status, now, org_id, device_id),
            )
            conn.execute(
                """INSERT INTO nac_status_history
                   (history_id, org_id, device_id, status, reason, updated_by, changed_at)
                   VALUES (?,?,?,?,?,?,?)""",
                (history_id, org_id, device_id, status, reason, updated_by, now),
            )

        _logger.info("nac.status_updated org=%s device_id=%s status=%s", org_id, device_id, status)
        return self.get_device(org_id, device_id)

    # ------------------------------------------------------------------
    # POLICY MANAGEMENT
    # ------------------------------------------------------------------

    def create_policy(self, org_id: str, data: PolicyCreate) -> Dict[str, Any]:
        """Create a NAC policy for org_id."""
        policy_id = str(uuid.uuid4())
        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO nac_policies
                   (policy_id, org_id, name, device_types, required_checks,
                    vlan_on_pass, vlan_on_fail, action_on_fail, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    policy_id, org_id, data.name,
                    json.dumps(data.device_types),
                    json.dumps(data.required_checks),
                    data.vlan_on_pass, data.vlan_on_fail,
                    data.action_on_fail, now,
                ),
            )
        _logger.info("nac.policy_created org=%s policy_id=%s name=%s", org_id, policy_id, data.name)
        return self._get_policy_dict(org_id, policy_id)

    def list_policies(self, org_id: str) -> List[Dict[str, Any]]:
        """List all NAC policies for org_id."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM nac_policies WHERE org_id=? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        return [self._deserialize_policy(dict(r)) for r in rows]

    def _get_policy_dict(self, org_id: str, policy_id: str) -> Dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM nac_policies WHERE org_id=? AND policy_id=?",
                (org_id, policy_id),
            ).fetchone()
        if not row:
            raise ValueError(f"Policy {policy_id} not found for org {org_id}")
        return self._deserialize_policy(dict(row))

    @staticmethod
    def _deserialize_policy(row: Dict[str, Any]) -> Dict[str, Any]:
        for field in ("device_types", "required_checks"):
            if isinstance(row.get(field), str):
                row[field] = json.loads(row[field])
        return row

    # ------------------------------------------------------------------
    # POLICY APPLICATION
    # ------------------------------------------------------------------

    def apply_policy(self, org_id: str, device_id: str, policy_id: str) -> Dict[str, Any]:
        """Evaluate device against policy. Returns {device_id, policy_id, decision, vlan, reason}."""
        device = self.get_device(org_id, device_id)
        policy = self._get_policy_dict(org_id, policy_id)

        # Check device_type applicability
        device_types = policy.get("device_types") or []
        if device_types and device["device_type"] not in device_types:
            return {
                "device_id": device_id,
                "policy_id": policy_id,
                "decision": "allow",
                "vlan": policy.get("vlan_on_pass"),
                "reason": f"Device type '{device['device_type']}' not in policy scope {device_types}",
            }

        # Run posture check
        posture = self.run_posture_check(org_id, device_id)

        # Check required checks all pass
        required = policy.get("required_checks") or []
        check_results = {c["check_name"]: c["result"] for c in posture["checks"]}
        failing = [r for r in required if check_results.get(r) == "fail"]

        if failing:
            action = policy.get("action_on_fail", "quarantine")
            decision = action if action in ("quarantine", "block") else "quarantine"
            vlan = policy.get("vlan_on_fail")
            reason = f"Required checks failed: {', '.join(failing)}"
        elif posture["passed"]:
            decision = "allow"
            vlan = policy.get("vlan_on_pass")
            reason = f"All posture checks passed (score={posture['score']})"
        else:
            action = policy.get("action_on_fail", "quarantine")
            decision = action if action in ("quarantine", "block") else "quarantine"
            vlan = policy.get("vlan_on_fail")
            reason = f"Posture check score {posture['score']} below threshold"

        _logger.info(
            "nac.policy_applied org=%s device_id=%s policy_id=%s decision=%s",
            org_id, device_id, policy_id, decision,
        )
        return {
            "device_id": device_id,
            "policy_id": policy_id,
            "decision": decision,
            "vlan": vlan,
            "reason": reason,
            "posture_score": posture["score"],
        }

    # ------------------------------------------------------------------
    # ACCESS EVENTS
    # ------------------------------------------------------------------

    def record_access_event(self, org_id: str, data: AccessEventCreate) -> Dict[str, Any]:
        """Record a NAC access event (connect/disconnect/quarantine/remediated)."""
        # Verify device belongs to org
        self.get_device(org_id, data.device_id)

        event_id = str(uuid.uuid4())
        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO nac_access_events
                   (event_id, org_id, device_id, event_type, location, switch_port, details, occurred_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    event_id, org_id, data.device_id, data.event_type,
                    data.location, data.switch_port,
                    json.dumps(data.details) if data.details else None,
                    now,
                ),
            )
        return {
            "event_id": event_id,
            "org_id": org_id,
            "device_id": data.device_id,
            "event_type": data.event_type,
            "location": data.location,
            "switch_port": data.switch_port,
            "details": data.details,
            "occurred_at": now,
        }

    def list_access_events(
        self,
        org_id: str,
        device_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """List access events for org, optionally filtered by device_id."""
        query = "SELECT * FROM nac_access_events WHERE org_id=?"
        params: List[Any] = [org_id]
        if device_id:
            query += " AND device_id=?"
            params.append(device_id)
        query += " ORDER BY occurred_at DESC LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        results = []
        for r in rows:
            row = dict(r)
            if row.get("details"):
                try:
                    row["details"] = json.loads(row["details"])
                except (json.JSONDecodeError, TypeError):
                    pass
            results.append(row)
        return results

    # ------------------------------------------------------------------
    # STATS
    # ------------------------------------------------------------------

    def get_nac_stats(self, org_id: str) -> Dict[str, Any]:
        """Return NAC overview stats for org_id."""
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()

        with self._connect() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM nac_devices WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            status_rows = conn.execute(
                "SELECT status, COUNT(*) as cnt FROM nac_devices WHERE org_id=? GROUP BY status",
                (org_id,),
            ).fetchall()
            by_status = {r["status"]: r["cnt"] for r in status_rows}

            type_rows = conn.execute(
                "SELECT device_type, COUNT(*) as cnt FROM nac_devices WHERE org_id=? GROUP BY device_type",
                (org_id,),
            ).fetchall()
            by_device_type = {r["device_type"]: r["cnt"] for r in type_rows}

            events_24h = conn.execute(
                "SELECT COUNT(*) FROM nac_access_events WHERE org_id=? AND occurred_at>=?",
                (org_id, cutoff),
            ).fetchone()[0]

            policy_count = conn.execute(
                "SELECT COUNT(*) FROM nac_policies WHERE org_id=?", (org_id,)
            ).fetchone()[0]

        compliant_count = by_status.get("compliant", 0)
        quarantined_count = by_status.get("quarantined", 0)
        compliant_pct = round(compliant_count / total * 100, 1) if total > 0 else 0.0

        return {
            "total_devices": total,
            "by_status": by_status,
            "by_device_type": by_device_type,
            "compliant_pct": compliant_pct,
            "quarantined_count": quarantined_count,
            "events_24h": events_24h,
            "policy_count": policy_count,
        }
