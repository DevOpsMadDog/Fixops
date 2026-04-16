"""
VulnExceptionEngine — ALDECI.

Manages vulnerability exceptions: false positives, accepted risks,
compensating controls, deferred fixes, and not-applicable findings.

SQLite-backed, thread-safe, multi-tenant (per org_id).

Compliance: NIST SP 800-53 RA-5, PCI-DSS 6.3.3 (risk acceptance).
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "vuln_exceptions.db"
)

VALID_EXCEPTION_TYPES = frozenset(
    {
        "false_positive",
        "accepted_risk",
        "compensating_control",
        "deferred",
        "not_applicable",
    }
)

VALID_STATUSES = frozenset({"pending", "approved", "rejected", "expired"})


class VulnExceptionEngine:
    """
    SQLite-backed vulnerability exception management engine.

    All public methods are thread-safe via RLock.

    Args:
        db_path: Path to SQLite database. Defaults to .fixops_data/vuln_exceptions.db.
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

                CREATE TABLE IF NOT EXISTS vuln_exceptions (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    cve_id           TEXT NOT NULL,
                    asset_id         TEXT NOT NULL,
                    reason           TEXT NOT NULL,
                    exception_type   TEXT NOT NULL,
                    requested_by     TEXT NOT NULL DEFAULT '',
                    status           TEXT NOT NULL DEFAULT 'pending',
                    expiry_date      DATETIME,
                    approved_by      TEXT DEFAULT '',
                    approved_at      DATETIME,
                    approval_notes   TEXT DEFAULT '',
                    rejected_by      TEXT DEFAULT '',
                    rejected_at      DATETIME,
                    rejection_reason TEXT DEFAULT '',
                    created_at       DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_vexc_org
                    ON vuln_exceptions (org_id);

                CREATE INDEX IF NOT EXISTS idx_vexc_org_status
                    ON vuln_exceptions (org_id, status);

                CREATE INDEX IF NOT EXISTS idx_vexc_org_type
                    ON vuln_exceptions (org_id, exception_type);
                """
            )

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _row_to_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "org_id": row["org_id"],
            "cve_id": row["cve_id"],
            "asset_id": row["asset_id"],
            "reason": row["reason"],
            "exception_type": row["exception_type"],
            "requested_by": row["requested_by"],
            "status": row["status"],
            "expiry_date": row["expiry_date"],
            "approved_by": row["approved_by"],
            "approved_at": row["approved_at"],
            "approval_notes": row["approval_notes"],
            "rejected_by": row["rejected_by"],
            "rejected_at": row["rejected_at"],
            "rejection_reason": row["rejection_reason"],
            "created_at": row["created_at"],
        }

    # ------------------------------------------------------------------
    # Exception Management
    # ------------------------------------------------------------------

    def create_exception(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a new vulnerability exception request.

        data keys: cve_id (required), asset_id (required), reason (required),
        exception_type (required), requested_by, expiry_date.
        Returns the created exception record with status=pending.
        """
        cve_id = data.get("cve_id", "").strip()
        if not cve_id:
            raise ValueError("cve_id is required")

        asset_id = data.get("asset_id", "").strip()
        if not asset_id:
            raise ValueError("asset_id is required")

        reason = data.get("reason", "").strip()
        if not reason:
            raise ValueError("reason is required")

        exception_type = data.get("exception_type", "")
        if exception_type not in VALID_EXCEPTION_TYPES:
            raise ValueError(
                f"exception_type must be one of {sorted(VALID_EXCEPTION_TYPES)}, got '{exception_type}'"
            )

        now = datetime.now(timezone.utc).isoformat()
        exc_id = str(uuid.uuid4())
        requested_by = data.get("requested_by", "")
        expiry_date = data.get("expiry_date")

        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO vuln_exceptions
                        (id, org_id, cve_id, asset_id, reason, exception_type,
                         requested_by, status, expiry_date, approved_by, approved_at,
                         approval_notes, rejected_by, rejected_at, rejection_reason,
                         created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, '', NULL, '', '', NULL, '', ?)
                    """,
                    (
                        exc_id, org_id, cve_id, asset_id, reason, exception_type,
                        requested_by, expiry_date, now,
                    ),
                )

        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("FINDING_CREATED", {"entity_type": "vuln_exception", "org_id": org_id, "source_engine": "vuln_exception"})
            except Exception:
                pass

        return {
            "id": exc_id,
            "org_id": org_id,
            "cve_id": cve_id,
            "asset_id": asset_id,
            "reason": reason,
            "exception_type": exception_type,
            "requested_by": requested_by,
            "status": "pending",
            "expiry_date": expiry_date,
            "approved_by": "",
            "approved_at": None,
            "approval_notes": "",
            "rejected_by": "",
            "rejected_at": None,
            "rejection_reason": "",
            "created_at": now,
        }

    def list_exceptions(
        self,
        org_id: str,
        exception_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List exceptions for an org with optional filters."""
        query = "SELECT * FROM vuln_exceptions WHERE org_id = ?"
        params: List[Any] = [org_id]

        if exception_type:
            query += " AND exception_type = ?"
            params.append(exception_type)
        if status:
            query += " AND status = ?"
            params.append(status)

        query += " ORDER BY created_at DESC"

        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(query, params).fetchall()

        return [self._row_to_dict(r) for r in rows]

    def get_exception(self, org_id: str, exception_id: str) -> Dict[str, Any]:
        """
        Retrieve a single exception by ID.

        Returns the exception dict or empty dict if not found / wrong org.
        """
        with self._lock:
            with self._get_conn() as conn:
                row = conn.execute(
                    "SELECT * FROM vuln_exceptions WHERE org_id = ? AND id = ?",
                    (org_id, exception_id),
                ).fetchone()

        if not row:
            return {}
        return self._row_to_dict(row)

    def approve_exception(
        self,
        org_id: str,
        exception_id: str,
        approved_by: str,
        notes: str = "",
    ) -> Dict[str, Any]:
        """
        Approve a pending exception.

        Sets status=approved, records approver and timestamp.
        Raises ValueError if not found.
        """
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._get_conn() as conn:
                row = conn.execute(
                    "SELECT id FROM vuln_exceptions WHERE org_id = ? AND id = ?",
                    (org_id, exception_id),
                ).fetchone()

                if not row:
                    raise ValueError(
                        f"Exception '{exception_id}' not found for org '{org_id}'"
                    )

                conn.execute(
                    """
                    UPDATE vuln_exceptions
                    SET status = 'approved', approved_by = ?, approved_at = ?,
                        approval_notes = ?
                    WHERE org_id = ? AND id = ?
                    """,
                    (approved_by, now, notes, org_id, exception_id),
                )

        return self.get_exception(org_id, exception_id)

    def reject_exception(
        self,
        org_id: str,
        exception_id: str,
        rejected_by: str,
        reason: str,
    ) -> Dict[str, Any]:
        """
        Reject a pending exception.

        Sets status=rejected, records rejector and reason.
        Raises ValueError if not found.
        """
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._get_conn() as conn:
                row = conn.execute(
                    "SELECT id FROM vuln_exceptions WHERE org_id = ? AND id = ?",
                    (org_id, exception_id),
                ).fetchone()

                if not row:
                    raise ValueError(
                        f"Exception '{exception_id}' not found for org '{org_id}'"
                    )

                conn.execute(
                    """
                    UPDATE vuln_exceptions
                    SET status = 'rejected', rejected_by = ?, rejected_at = ?,
                        rejection_reason = ?
                    WHERE org_id = ? AND id = ?
                    """,
                    (rejected_by, now, reason, org_id, exception_id),
                )

        return self.get_exception(org_id, exception_id)

    def expire_exceptions(self, org_id: str) -> Dict[str, Any]:
        """
        Expire approved exceptions whose expiry_date has passed.

        Returns dict with expired_count.
        """
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._get_conn() as conn:
                result = conn.execute(
                    """
                    UPDATE vuln_exceptions
                    SET status = 'expired'
                    WHERE org_id = ?
                      AND status = 'approved'
                      AND expiry_date IS NOT NULL
                      AND expiry_date < ?
                    """,
                    (org_id, now),
                )
                count = result.rowcount

        return {"expired_count": count}

    def get_exception_stats(self, org_id: str) -> Dict[str, Any]:
        """
        Return aggregated exception statistics for the org.

        Includes total_exceptions, by_type, by_status, pending_count,
        approved_count, expired_count, and acceptance_rate.
        """
        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(
                    "SELECT exception_type, status FROM vuln_exceptions WHERE org_id = ?",
                    (org_id,),
                ).fetchall()

        total = len(rows)
        by_type: Dict[str, int] = {}
        by_status: Dict[str, int] = {}

        for r in rows:
            by_type[r["exception_type"]] = by_type.get(r["exception_type"], 0) + 1
            by_status[r["status"]] = by_status.get(r["status"], 0) + 1

        pending_count = by_status.get("pending", 0)
        approved_count = by_status.get("approved", 0)
        rejected_count = by_status.get("rejected", 0)
        expired_count = by_status.get("expired", 0)

        decided = approved_count + rejected_count
        acceptance_rate = (approved_count / decided * 100.0) if decided > 0 else 0.0

        return {
            "total_exceptions": total,
            "by_type": by_type,
            "by_status": by_status,
            "pending_count": pending_count,
            "approved_count": approved_count,
            "expired_count": expired_count,
            "acceptance_rate": round(acceptance_rate, 2),
        }
