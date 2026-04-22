"""SecurityExceptionWorkflowEngine — ALDECI.

Manages formal security policy exception requests, reviews, approvals,
renewals, and expiry tracking.

Multi-tenant via org_id. SQLite WAL + threading.RLock for concurrency safety.
Compliance: NIST SP 800-53 CA-5, ISO 27001 A.18.2, SOC 2 CC9.1.
"""

from __future__ import annotations

import contextlib
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


logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "security_exception_workflow.db"
)

EXCEPTION_TYPES = frozenset({
    "policy-waiver", "risk-acceptance", "compensating-control",
    "temporary-deviation", "architectural", "vendor", "regulatory",
})
STATUSES = frozenset({"pending", "approved", "rejected", "needs-info", "revoked", "expired"})
PRIORITIES = frozenset({"critical", "high", "medium", "low"})
DECISIONS = frozenset({"approved", "rejected", "needs-info"})
RISK_RATINGS = frozenset({"critical", "high", "medium", "low", "acceptable"})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class SecurityExceptionWorkflowEngine:
    """SQLite WAL-backed security exception workflow engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _conn(self):
        @contextlib.contextmanager
        def _ctx():
            conn = sqlite3.connect(self._db_path)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            try:
                yield conn
                conn.commit()
            finally:
                conn.close()
        return _ctx()

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS exception_requests (
                    id                      TEXT PRIMARY KEY,
                    org_id                  TEXT NOT NULL,
                    policy_name             TEXT NOT NULL,
                    exception_type          TEXT NOT NULL DEFAULT 'policy-waiver',
                    requestor               TEXT NOT NULL DEFAULT '',
                    business_justification  TEXT NOT NULL DEFAULT '',
                    risk_description        TEXT NOT NULL DEFAULT '',
                    compensating_controls   TEXT NOT NULL DEFAULT '',
                    status                  TEXT NOT NULL DEFAULT 'pending',
                    priority                TEXT NOT NULL DEFAULT 'medium',
                    expires_at              TEXT,
                    approved_until          TEXT,
                    created_at              TEXT NOT NULL,
                    reviewed_at             TEXT
                );

                CREATE TABLE IF NOT EXISTS exception_reviews (
                    id          TEXT PRIMARY KEY,
                    request_id  TEXT NOT NULL,
                    org_id      TEXT NOT NULL,
                    reviewer    TEXT NOT NULL DEFAULT '',
                    decision    TEXT NOT NULL,
                    conditions  TEXT NOT NULL DEFAULT '',
                    risk_rating TEXT NOT NULL DEFAULT 'medium',
                    comments    TEXT NOT NULL DEFAULT '',
                    reviewed_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS exception_renewals (
                    id          TEXT PRIMARY KEY,
                    request_id  TEXT NOT NULL,
                    org_id      TEXT NOT NULL,
                    renewed_by  TEXT NOT NULL DEFAULT '',
                    new_expiry  TEXT NOT NULL,
                    reason      TEXT NOT NULL DEFAULT '',
                    renewed_at  TEXT NOT NULL
                );
            """)

    @staticmethod
    def _row_to_dict(row) -> Dict[str, Any]:
        return dict(row) if row else {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_request(
        self,
        org_id: str,
        policy_name: str,
        exception_type: str = "policy-waiver",
        requestor: str = "",
        business_justification: str = "",
        risk_description: str = "",
        compensating_controls: str = "",
        priority: str = "medium",
        expires_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a new exception request with status=pending."""
        rid = str(uuid.uuid4())
        now = _now()
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO exception_requests
                   (id, org_id, policy_name, exception_type, requestor,
                    business_justification, risk_description, compensating_controls,
                    status, priority, expires_at, approved_until, created_at, reviewed_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,NULL,?,NULL)""",
                (rid, org_id, policy_name, exception_type, requestor,
                 business_justification, risk_description, compensating_controls,
                 "pending", priority, expires_at, now),
            )
            row = conn.execute(
                "SELECT * FROM exception_requests WHERE id=?", (rid,)
            ).fetchone()
        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("CONTROL_ASSESSED", {"entity_type": "security_exception_workflow_engine", "org_id": org_id, "source_engine": "security_exception_workflow_engine"})
            except Exception:
                pass
        return self._row_to_dict(row)

    def review_request(
        self,
        request_id: str,
        org_id: str,
        reviewer: str,
        decision: str,
        conditions: str = "",
        risk_rating: str = "medium",
        comments: str = "",
    ) -> Dict[str, Any]:
        """Review an exception request. Updates request status based on decision."""
        review_id = str(uuid.uuid4())
        now = _now()

        if decision not in DECISIONS:
            raise ValueError(f"Invalid decision: {decision}. Must be one of {DECISIONS}")

        # Determine new status and approved_until
        if decision == "approved":
            new_status = "approved"
        elif decision == "rejected":
            new_status = "rejected"
        else:  # needs-info
            new_status = "needs-info"

        with self._lock, self._conn() as conn:
            # Get the request to find expires_at
            req_row = conn.execute(
                "SELECT * FROM exception_requests WHERE id=? AND org_id=?",
                (request_id, org_id),
            ).fetchone()
            if not req_row:
                raise KeyError(f"Request {request_id} not found for org {org_id}")

            expires_at = req_row["expires_at"]
            approved_until = expires_at if decision == "approved" else None

            # Insert review
            conn.execute(
                """INSERT INTO exception_reviews
                   (id, request_id, org_id, reviewer, decision, conditions,
                    risk_rating, comments, reviewed_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (review_id, request_id, org_id, reviewer, decision,
                 conditions, risk_rating, comments, now),
            )

            # Update request
            if decision == "approved":
                conn.execute(
                    """UPDATE exception_requests
                       SET status=?, reviewed_at=?, approved_until=?
                       WHERE id=? AND org_id=?""",
                    (new_status, now, approved_until, request_id, org_id),
                )
            else:
                conn.execute(
                    """UPDATE exception_requests
                       SET status=?, reviewed_at=?
                       WHERE id=? AND org_id=?""",
                    (new_status, now, request_id, org_id),
                )

            row = conn.execute(
                "SELECT * FROM exception_reviews WHERE id=?", (review_id,)
            ).fetchone()
        return self._row_to_dict(row)

    def renew_exception(
        self,
        request_id: str,
        org_id: str,
        renewed_by: str,
        new_expiry: str,
        reason: str = "",
    ) -> Dict[str, Any]:
        """Renew an exception, extending its expiry and approved_until."""
        renewal_id = str(uuid.uuid4())
        now = _now()
        with self._lock, self._conn() as conn:
            req_row = conn.execute(
                "SELECT id FROM exception_requests WHERE id=? AND org_id=?",
                (request_id, org_id),
            ).fetchone()
            if not req_row:
                raise KeyError(f"Request {request_id} not found for org {org_id}")

            conn.execute(
                """INSERT INTO exception_renewals
                   (id, request_id, org_id, renewed_by, new_expiry, reason, renewed_at)
                   VALUES (?,?,?,?,?,?,?)""",
                (renewal_id, request_id, org_id, renewed_by, new_expiry, reason, now),
            )
            # Update request expiry
            conn.execute(
                """UPDATE exception_requests
                   SET expires_at=?, approved_until=?
                   WHERE id=? AND org_id=?""",
                (new_expiry, new_expiry, request_id, org_id),
            )
            row = conn.execute(
                "SELECT * FROM exception_renewals WHERE id=?", (renewal_id,)
            ).fetchone()
        return self._row_to_dict(row)

    def record_auto_waiver(
        self,
        org_id: str,
        finding_id: str,
        rule_key: str,
        approvers: List[str],
        expires_at: str,
    ) -> Dict[str, Any]:
        """Record an auto-waiver referencing a rule; creates a pending-approval exception.

        The business_justification field encodes the rule linkage as JSON.
        """
        rid = str(uuid.uuid4())
        now = _now()
        payload = {
            "auto_waiver": True,
            "rule_key": rule_key,
            "finding_id": finding_id,
            "approvers": list(approvers or []),
        }
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO exception_requests
                   (id, org_id, policy_name, exception_type, requestor,
                    business_justification, risk_description, compensating_controls,
                    status, priority, expires_at, approved_until, created_at, reviewed_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,NULL,?,NULL)""",
                (
                    rid, org_id, f"auto-waiver:{rule_key}",
                    "policy-waiver", "auto-waiver",
                    json.dumps(payload),
                    f"auto-waiver for finding {finding_id} via rule {rule_key}",
                    "",
                    "pending", "medium", expires_at, now,
                ),
            )
            row = conn.execute(
                "SELECT * FROM exception_requests WHERE id=?", (rid,)
            ).fetchone()
        return self._row_to_dict(row)

    def revoke_exception(self, request_id: str, org_id: str) -> Dict[str, Any]:
        """Revoke an approved exception."""
        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE exception_requests SET status='revoked' WHERE id=? AND org_id=?",
                (request_id, org_id),
            )
            row = conn.execute(
                "SELECT * FROM exception_requests WHERE id=? AND org_id=?",
                (request_id, org_id),
            ).fetchone()
        return self._row_to_dict(row)

    def get_request(self, request_id: str, org_id: str) -> Dict[str, Any]:
        """Get request with its reviews and renewals."""
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM exception_requests WHERE id=? AND org_id=?",
                (request_id, org_id),
            ).fetchone()
            if not row:
                return {}
            result = self._row_to_dict(row)

            reviews = conn.execute(
                "SELECT * FROM exception_reviews WHERE request_id=? AND org_id=? ORDER BY reviewed_at",
                (request_id, org_id),
            ).fetchall()
            result["reviews"] = [self._row_to_dict(r) for r in reviews]

            renewals = conn.execute(
                "SELECT * FROM exception_renewals WHERE request_id=? AND org_id=? ORDER BY renewed_at",
                (request_id, org_id),
            ).fetchall()
            result["renewals"] = [self._row_to_dict(r) for r in renewals]
        return result

    def list_requests(
        self,
        org_id: str,
        status: Optional[str] = None,
        exception_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List exception requests with optional filters."""
        query = "SELECT * FROM exception_requests WHERE org_id=?"
        params: List[Any] = [org_id]
        if status:
            query += " AND status=?"
            params.append(status)
        if exception_type:
            query += " AND exception_type=?"
            params.append(exception_type)
        query += " ORDER BY created_at DESC"

        with self._lock, self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_expiring_exceptions(self, org_id: str, days_ahead: int) -> List[Dict[str, Any]]:
        """Get approved exceptions expiring within days_ahead from now."""
        now_str = _now()
        cutoff = (datetime.now(timezone.utc) + timedelta(days=days_ahead)).isoformat()
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM exception_requests
                   WHERE org_id=? AND status='approved'
                     AND approved_until IS NOT NULL
                     AND approved_until > ?
                     AND approved_until <= ?
                   ORDER BY approved_until""",
                (org_id, now_str, cutoff),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_expired_exceptions(self, org_id: str) -> List[Dict[str, Any]]:
        """Get approved exceptions where approved_until has passed."""
        now_str = _now()
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM exception_requests
                   WHERE org_id=? AND status='approved'
                     AND approved_until IS NOT NULL
                     AND approved_until < ?
                   ORDER BY approved_until""",
                (org_id, now_str),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_exception_summary(self, org_id: str) -> Dict[str, Any]:
        """Summary: counts by status/type, expiring_soon (30d), overdue renewals."""
        now_str = _now()
        cutoff_30 = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()

        with self._lock, self._conn() as conn:
            # Counts by status
            status_rows = conn.execute(
                "SELECT status, COUNT(*) as cnt FROM exception_requests WHERE org_id=? GROUP BY status",
                (org_id,),
            ).fetchall()
            by_status = {r["status"]: r["cnt"] for r in status_rows}

            # Counts by type
            type_rows = conn.execute(
                "SELECT exception_type, COUNT(*) as cnt FROM exception_requests WHERE org_id=? GROUP BY exception_type",
                (org_id,),
            ).fetchall()
            by_type = {r["exception_type"]: r["cnt"] for r in type_rows}

            # Expiring soon (within 30 days, currently approved)
            expiring_soon = conn.execute(
                """SELECT COUNT(*) as cnt FROM exception_requests
                   WHERE org_id=? AND status='approved'
                     AND approved_until IS NOT NULL
                     AND approved_until > ?
                     AND approved_until <= ?""",
                (org_id, now_str, cutoff_30),
            ).fetchone()["cnt"]

            # Overdue renewals (approved_until < now but still status=approved)
            overdue = conn.execute(
                """SELECT COUNT(*) as cnt FROM exception_requests
                   WHERE org_id=? AND status='approved'
                     AND approved_until IS NOT NULL
                     AND approved_until < ?""",
                (org_id, now_str),
            ).fetchone()["cnt"]

            total = conn.execute(
                "SELECT COUNT(*) as cnt FROM exception_requests WHERE org_id=?",
                (org_id,),
            ).fetchone()["cnt"]

        return {
            "org_id": org_id,
            "total": total,
            "by_status": by_status,
            "by_type": by_type,
            "expiring_soon": expiring_soon,
            "overdue_renewals": overdue,
        }
