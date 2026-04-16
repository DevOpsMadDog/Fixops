"""Access Request Management Engine — ALDECI.

Manages the full lifecycle of access requests: creation, review, approval,
rejection, and revocation.

Features:
- Request lifecycle (pending → under_review → approved/rejected/expired/revoked)
- Approval with expiry computation (created_at + duration_days)
- Rejection with reason audit trail
- Revocation with reason
- Stats: rejection_rate, avg_approval_time_hours, by_resource_type, by_access_type

Compliance: NIST SP 800-53 AC-2 (Account Management), ISO 27001 A.9.2,
            CIS Control 6 (Access Control Management)
"""

from __future__ import annotations

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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "access_request_management.db"
)

_VALID_ACCESS_TYPES = {"read", "write", "admin", "execute", "delete", "full_control"}
_VALID_REQUEST_STATUSES = {"pending", "under_review", "approved", "rejected", "expired", "revoked"}
_VALID_RESOURCE_TYPES = {"database", "application", "server", "network", "cloud_resource", "file_share", "api"}
_VALID_PRIORITIES = {"urgent", "high", "normal", "low"}


class AccessRequestManagementEngine:
    """Engine for managing privileged access requests."""

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # DB INIT
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS arm_requests (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    requester     TEXT NOT NULL DEFAULT '',
                    resource_id   TEXT NOT NULL DEFAULT '',
                    resource_name TEXT NOT NULL DEFAULT '',
                    resource_type TEXT NOT NULL DEFAULT 'application',
                    access_type   TEXT NOT NULL DEFAULT 'read',
                    justification TEXT NOT NULL DEFAULT '',
                    priority      TEXT NOT NULL DEFAULT 'normal',
                    duration_days INTEGER NOT NULL DEFAULT 30,
                    status        TEXT NOT NULL DEFAULT 'pending',
                    approver      TEXT NOT NULL DEFAULT '',
                    notes         TEXT NOT NULL DEFAULT '',
                    approved_at   DATETIME,
                    expires_at    DATETIME,
                    created_at    DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_arm_org     ON arm_requests(org_id);
                CREATE INDEX IF NOT EXISTS idx_arm_status  ON arm_requests(org_id, status);
                CREATE INDEX IF NOT EXISTS idx_arm_type    ON arm_requests(org_id, access_type);
            """)

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # PUBLIC API
    # ------------------------------------------------------------------

    def create_request(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new access request. Returns the created record."""
        requester = data.get("requester", "").strip()
        if not requester:
            raise ValueError("requester is required")

        access_type = data.get("access_type", "read")
        if access_type not in _VALID_ACCESS_TYPES:
            raise ValueError(
                f"Invalid access_type '{access_type}'. Must be one of {sorted(_VALID_ACCESS_TYPES)}"
            )

        resource_type = data.get("resource_type", "application")
        if resource_type not in _VALID_RESOURCE_TYPES:
            raise ValueError(
                f"Invalid resource_type '{resource_type}'. Must be one of {sorted(_VALID_RESOURCE_TYPES)}"
            )

        priority = data.get("priority", "normal")
        if priority not in _VALID_PRIORITIES:
            raise ValueError(
                f"Invalid priority '{priority}'. Must be one of {sorted(_VALID_PRIORITIES)}"
            )

        request_id = str(uuid.uuid4())
        now = self._now()
        duration_days = int(data.get("duration_days", 30))

        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO arm_requests
                   (id, org_id, requester, resource_id, resource_name, resource_type,
                    access_type, justification, priority, duration_days, status,
                    approver, notes, approved_at, expires_at, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,'pending','','',NULL,NULL,?)""",
                (
                    request_id, org_id, requester,
                    data.get("resource_id", ""),
                    data.get("resource_name", ""),
                    resource_type, access_type,
                    data.get("justification", ""),
                    priority, duration_days, now,
                ),
            )
        _logger.info(
            "arm.request_created org=%s request_id=%s requester=%s",
            org_id, request_id, requester,
        )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("IDENTITY_UPDATED", {"entity_type": "access_request_management", "org_id": org_id, "source_engine": "access_request_management"})
            except Exception:
                pass

        return self.get_request(org_id, request_id)

    def list_requests(
        self,
        org_id: str,
        access_type: Optional[str] = None,
        status: Optional[str] = None,
        resource_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List access requests for org, optionally filtered."""
        query = "SELECT * FROM arm_requests WHERE org_id=?"
        params: List[Any] = [org_id]
        if access_type:
            query += " AND access_type=?"
            params.append(access_type)
        if status:
            query += " AND status=?"
            params.append(status)
        if resource_type:
            query += " AND resource_type=?"
            params.append(resource_type)
        query += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def get_request(self, org_id: str, request_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single request scoped to org_id. Returns None if not found."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM arm_requests WHERE org_id=? AND id=?",
                (org_id, request_id),
            ).fetchone()
        return self._row(row) if row else None

    def approve_request(
        self,
        org_id: str,
        request_id: str,
        approver: str,
        notes: str = "",
    ) -> Dict[str, Any]:
        """Approve an access request. Sets approved_at and computes expires_at."""
        req = self.get_request(org_id, request_id)
        if req is None:
            raise ValueError(f"Request '{request_id}' not found for org '{org_id}'")

        now_dt = datetime.now(timezone.utc)
        approved_at = now_dt.isoformat()
        duration_days = req.get("duration_days") or 30
        expires_at = (now_dt + timedelta(days=duration_days)).isoformat()

        with self._lock, self._conn() as conn:
            conn.execute(
                """UPDATE arm_requests
                   SET status='approved', approver=?, notes=?,
                       approved_at=?, expires_at=?
                   WHERE org_id=? AND id=?""",
                (approver, notes, approved_at, expires_at, org_id, request_id),
            )
        _logger.info(
            "arm.request_approved org=%s request_id=%s approver=%s",
            org_id, request_id, approver,
        )
        return self.get_request(org_id, request_id)

    def reject_request(
        self,
        org_id: str,
        request_id: str,
        approver: str,
        reason: str,
    ) -> Dict[str, Any]:
        """Reject an access request. Records approver and rejection reason."""
        req = self.get_request(org_id, request_id)
        if req is None:
            raise ValueError(f"Request '{request_id}' not found for org '{org_id}'")

        with self._lock, self._conn() as conn:
            conn.execute(
                """UPDATE arm_requests
                   SET status='rejected', approver=?, notes=?
                   WHERE org_id=? AND id=?""",
                (approver, reason, org_id, request_id),
            )
        _logger.info(
            "arm.request_rejected org=%s request_id=%s approver=%s",
            org_id, request_id, approver,
        )
        return self.get_request(org_id, request_id)

    def revoke_access(
        self,
        org_id: str,
        request_id: str,
        reason: str,
    ) -> Dict[str, Any]:
        """Revoke a previously approved access request."""
        req = self.get_request(org_id, request_id)
        if req is None:
            raise ValueError(f"Request '{request_id}' not found for org '{org_id}'")

        with self._lock, self._conn() as conn:
            conn.execute(
                """UPDATE arm_requests
                   SET status='revoked', notes=?
                   WHERE org_id=? AND id=?""",
                (reason, org_id, request_id),
            )
        _logger.info(
            "arm.access_revoked org=%s request_id=%s", org_id, request_id
        )
        return self.get_request(org_id, request_id)

    def get_access_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate stats for access requests in org."""
        with self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM arm_requests WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            pending_count = conn.execute(
                "SELECT COUNT(*) FROM arm_requests WHERE org_id=? AND status='pending'",
                (org_id,),
            ).fetchone()[0]

            approved_count = conn.execute(
                "SELECT COUNT(*) FROM arm_requests WHERE org_id=? AND status='approved'",
                (org_id,),
            ).fetchone()[0]

            rejected_count = conn.execute(
                "SELECT COUNT(*) FROM arm_requests WHERE org_id=? AND status='rejected'",
                (org_id,),
            ).fetchone()[0]

            # avg approval time in hours (from created_at to approved_at)
            avg_row = conn.execute(
                """SELECT AVG(
                       (julianday(approved_at) - julianday(created_at)) * 24
                   ) FROM arm_requests
                   WHERE org_id=? AND status='approved'
                     AND approved_at IS NOT NULL AND created_at IS NOT NULL""",
                (org_id,),
            ).fetchone()[0]

            by_resource = conn.execute(
                """SELECT resource_type, COUNT(*) AS cnt
                   FROM arm_requests WHERE org_id=?
                   GROUP BY resource_type""",
                (org_id,),
            ).fetchall()

            by_access = conn.execute(
                """SELECT access_type, COUNT(*) AS cnt
                   FROM arm_requests WHERE org_id=?
                   GROUP BY access_type""",
                (org_id,),
            ).fetchall()

        rejection_rate = round((rejected_count / total * 100) if total > 0 else 0.0, 2)

        return {
            "total_requests": total,
            "pending_count": pending_count,
            "approved_count": approved_count,
            "rejection_rate": rejection_rate,
            "avg_approval_time_hours": round(avg_row, 2) if avg_row is not None else 0.0,
            "by_resource_type": {r["resource_type"]: r["cnt"] for r in by_resource},
            "by_access_type": {r["access_type"]: r["cnt"] for r in by_access},
        }
