"""Mobile Device Management (MDM) Engine — ALDECI.

Device enrollment, compliance tracking, and remote wipe for iOS, Android,
Windows, and macOS endpoints. Full org_id multi-tenant isolation.

Compliance: NIST CSF PR.AC, ISO/IEC 27001 A.6.2, CIS Control 1
"""

from __future__ import annotations

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

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "mobile_device_management.db"
)

_VALID_PLATFORMS = {"ios", "android", "windows", "macos"}
_VALID_STATUSES = {"enrolled", "compliant", "warning", "non_compliant", "wiped"}


class MobileDeviceManagementEngine:
    """SQLite WAL-backed MDM engine.

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
                CREATE TABLE IF NOT EXISTS devices (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    name             TEXT NOT NULL DEFAULT '',
                    platform         TEXT NOT NULL DEFAULT '',
                    serial_number    TEXT NOT NULL DEFAULT '',
                    os_version       TEXT NOT NULL DEFAULT '',
                    status           TEXT NOT NULL DEFAULT 'enrolled',
                    compliance_score INTEGER NOT NULL DEFAULT 100,
                    issues           TEXT NOT NULL DEFAULT '[]',
                    enrolled_at      TEXT NOT NULL,
                    last_seen        TEXT NOT NULL,
                    wiped_at         TEXT,
                    wipe_reason      TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_devices_org
                    ON devices (org_id, platform, status);
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
        d = dict(row)
        if "issues" in d and isinstance(d["issues"], str):
            try:
                d["issues"] = json.loads(d["issues"])
            except (json.JSONDecodeError, TypeError):
                d["issues"] = []
        return d

    @staticmethod
    def _derive_status(score: int) -> str:
        if score >= 80:
            return "compliant"
        if score >= 50:
            return "warning"
        return "non_compliant"

    # ------------------------------------------------------------------
    # Device Management
    # ------------------------------------------------------------------

    def enroll_device(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Enroll a new device.

        Required keys: name, platform
        Optional keys: serial_number, os_version
        """
        name = data.get("name", "").strip()
        if not name:
            raise ValueError("name is required")

        platform = data.get("platform", "").lower().strip()
        if platform not in _VALID_PLATFORMS:
            raise ValueError(f"platform must be one of {_VALID_PLATFORMS}")

        device_id = str(uuid.uuid4())
        now = self._now()
        row = {
            "id": device_id,
            "org_id": org_id,
            "name": name,
            "platform": platform,
            "serial_number": data.get("serial_number", ""),
            "os_version": data.get("os_version", ""),
            "status": "enrolled",
            "compliance_score": 100,
            "issues": json.dumps([]),
            "enrolled_at": now,
            "last_seen": now,
            "wiped_at": None,
            "wipe_reason": None,
        }
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO devices
                    (id, org_id, name, platform, serial_number, os_version,
                     status, compliance_score, issues, enrolled_at, last_seen,
                     wiped_at, wipe_reason)
                VALUES
                    (:id, :org_id, :name, :platform, :serial_number, :os_version,
                     :status, :compliance_score, :issues, :enrolled_at, :last_seen,
                     :wiped_at, :wipe_reason)
                """,
                row,
            )
        result = dict(row)
        result["issues"] = []
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ASSET_DISCOVERED", {"entity_type": "mobile_device_management", "org_id": org_id, "source_engine": "mobile_device_management"})
            except Exception:
                pass

        return result

    def list_devices(
        self,
        org_id: str,
        platform: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List devices for an org with optional platform/status filters."""
        query = "SELECT * FROM devices WHERE org_id = ?"
        params: list = [org_id]
        if platform is not None:
            query += " AND platform = ?"
            params.append(platform.lower())
        if status is not None:
            query += " AND status = ?"
            params.append(status.lower())
        query += " ORDER BY enrolled_at DESC"
        with self._lock, self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_device(self, org_id: str, device_id: str) -> Dict[str, Any]:
        """Return a single device by ID, scoped to org."""
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM devices WHERE id = ? AND org_id = ?",
                (device_id, org_id),
            ).fetchone()
        if not row:
            raise ValueError(f"Device {device_id} not found for org {org_id}")
        return self._row_to_dict(row)

    def update_compliance(
        self,
        org_id: str,
        device_id: str,
        compliance_score: int,
        issues: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Update compliance score and derive new status.

        Score is clamped to [0, 100].
        Status: >=80 → compliant, 50-79 → warning, <50 → non_compliant.
        """
        score = max(0, min(100, compliance_score))
        new_status = self._derive_status(score)
        now = self._now()
        issues_list = issues if issues is not None else []

        with self._lock, self._conn() as conn:
            conn.execute(
                """
                UPDATE devices
                SET compliance_score = ?,
                    status = ?,
                    issues = ?,
                    last_seen = ?
                WHERE id = ? AND org_id = ? AND status != 'wiped'
                """,
                (score, new_status, json.dumps(issues_list), now, device_id, org_id),
            )
            row = conn.execute(
                "SELECT * FROM devices WHERE id = ? AND org_id = ?",
                (device_id, org_id),
            ).fetchone()
        if not row:
            raise ValueError(f"Device {device_id} not found for org {org_id}")
        return self._row_to_dict(row)

    def wipe_device(
        self, org_id: str, device_id: str, reason: str
    ) -> Dict[str, Any]:
        """Initiate a remote wipe — sets status=wiped."""
        now = self._now()
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                UPDATE devices
                SET status = 'wiped',
                    wipe_reason = ?,
                    wiped_at = ?,
                    last_seen = ?
                WHERE id = ? AND org_id = ?
                """,
                (reason, now, now, device_id, org_id),
            )
            row = conn.execute(
                "SELECT * FROM devices WHERE id = ? AND org_id = ?",
                (device_id, org_id),
            ).fetchone()
        if not row:
            raise ValueError(f"Device {device_id} not found for org {org_id}")
        return self._row_to_dict(row)

    # ------------------------------------------------------------------
    # Summary / Stats
    # ------------------------------------------------------------------

    def get_compliance_summary(self, org_id: str) -> Dict[str, Any]:
        """Return compliance summary: total, by_platform, by_status, avg_score."""
        with self._lock, self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM devices WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            platform_rows = conn.execute(
                "SELECT platform, COUNT(*) AS cnt FROM devices WHERE org_id = ? GROUP BY platform",
                (org_id,),
            ).fetchall()

            status_rows = conn.execute(
                "SELECT status, COUNT(*) AS cnt FROM devices WHERE org_id = ? GROUP BY status",
                (org_id,),
            ).fetchall()

            avg_row = conn.execute(
                "SELECT AVG(compliance_score) FROM devices WHERE org_id = ? AND status != 'wiped'",
                (org_id,),
            ).fetchone()

        avg_score = round(avg_row[0], 2) if avg_row[0] is not None else 0.0

        return {
            "org_id": org_id,
            "total": total,
            "by_platform": {r["platform"]: r["cnt"] for r in platform_rows},
            "by_status": {r["status"]: r["cnt"] for r in status_rows},
            "avg_compliance_score": avg_score,
        }
