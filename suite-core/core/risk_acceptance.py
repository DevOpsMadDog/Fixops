"""
Risk Acceptance Workflow for ALDECI.

Provides a formal risk acceptance process with:
- Justification and business reason capture
- Expiration and review date tracking
- Approval chain (request → approve/reject → revoke)
- Full audit trail via AcceptanceReview records
- SQLite persistence

Compliance: SOC2 CC3.2, ISO27001 A.8.2, NIST RMF
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class AcceptanceStatus(str, Enum):
    """Lifecycle states for a risk acceptance record."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    REVOKED = "revoked"


class ReviewPriority(str, Enum):
    """Priority classification for the review queue."""

    ROUTINE = "routine"
    ELEVATED = "elevated"
    URGENT = "urgent"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class RiskAcceptance(BaseModel):
    """A formal risk acceptance record."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    finding_id: str
    org_id: str
    justification: str
    business_reason: str
    compensating_controls: str = ""
    requested_by: str
    requested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    expires_at: datetime
    review_date: datetime
    status: AcceptanceStatus = AcceptanceStatus.PENDING
    priority: ReviewPriority = ReviewPriority.ROUTINE
    conditions: List[str] = Field(default_factory=list)
    risk_score_at_acceptance: float = 0.0

    model_config = {"use_enum_values": True}


class AcceptanceReview(BaseModel):
    """A single review action against a RiskAcceptance."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    acceptance_id: str
    reviewer: str
    decision: str  # "approved", "rejected", "revoked"
    comment: str = ""
    reviewed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# SQLite schema
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS risk_acceptances (
    id                      TEXT PRIMARY KEY,
    finding_id              TEXT NOT NULL,
    org_id                  TEXT NOT NULL,
    justification           TEXT NOT NULL,
    business_reason         TEXT NOT NULL,
    compensating_controls   TEXT NOT NULL DEFAULT '',
    requested_by            TEXT NOT NULL,
    requested_at            TEXT NOT NULL,
    approved_by             TEXT,
    approved_at             TEXT,
    expires_at              TEXT NOT NULL,
    review_date             TEXT NOT NULL,
    status                  TEXT NOT NULL DEFAULT 'pending',
    priority                TEXT NOT NULL DEFAULT 'routine',
    conditions              TEXT NOT NULL DEFAULT '[]',
    risk_score_at_acceptance REAL NOT NULL DEFAULT 0.0
);
CREATE INDEX IF NOT EXISTS idx_ra_org_status  ON risk_acceptances (org_id, status);
CREATE INDEX IF NOT EXISTS idx_ra_finding     ON risk_acceptances (finding_id);
CREATE INDEX IF NOT EXISTS idx_ra_expires     ON risk_acceptances (expires_at);

CREATE TABLE IF NOT EXISTS acceptance_reviews (
    id              TEXT PRIMARY KEY,
    acceptance_id   TEXT NOT NULL,
    reviewer        TEXT NOT NULL,
    decision        TEXT NOT NULL,
    comment         TEXT NOT NULL DEFAULT '',
    reviewed_at     TEXT NOT NULL,
    FOREIGN KEY (acceptance_id) REFERENCES risk_acceptances(id)
);
CREATE INDEX IF NOT EXISTS idx_arv_acceptance ON acceptance_reviews (acceptance_id);
"""


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class RiskAcceptanceManager:
    """SQLite-backed manager for the risk acceptance workflow.

    Args:
        db_path: Path to the SQLite database file, or ``:memory:`` for tests.
    """

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self._db_path = db_path if isinstance(db_path, Path) else Path(str(db_path))
        self._lock = threading.RLock()
        self._mem_conn: Optional[sqlite3.Connection] = None
        self._init_db()

    # ------------------------------------------------------------------
    # Internal DB helpers
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        if str(self._db_path) == ":memory:":
            if self._mem_conn is None:
                self._mem_conn = sqlite3.connect(":memory:", check_same_thread=False)
                self._mem_conn.row_factory = sqlite3.Row
            return self._mem_conn
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock:
            conn = self._connect()
            conn.executescript(_SCHEMA)
            conn.commit()

    @staticmethod
    def _row_to_acceptance(row: sqlite3.Row) -> RiskAcceptance:
        d = dict(row)
        d["conditions"] = json.loads(d.get("conditions") or "[]")
        return RiskAcceptance(**d)

    @staticmethod
    def _row_to_review(row: sqlite3.Row) -> AcceptanceReview:
        return AcceptanceReview(**dict(row))

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def request_acceptance(
        self,
        finding_id: str,
        justification: str,
        business_reason: str,
        compensating_controls: str,
        requested_by: str,
        expires_at: datetime,
        org_id: str,
        priority: ReviewPriority = ReviewPriority.ROUTINE,
        conditions: Optional[List[str]] = None,
        risk_score_at_acceptance: float = 0.0,
    ) -> RiskAcceptance:
        """Submit a new risk acceptance request.

        The record starts in PENDING status and is placed in the review queue.
        """
        review_date = expires_at - timedelta(days=30)
        if review_date < datetime.now(timezone.utc):
            review_date = expires_at - timedelta(days=7)

        acceptance = RiskAcceptance(
            finding_id=finding_id,
            org_id=org_id,
            justification=justification,
            business_reason=business_reason,
            compensating_controls=compensating_controls,
            requested_by=requested_by,
            expires_at=expires_at,
            review_date=review_date,
            priority=priority,
            conditions=conditions or [],
            risk_score_at_acceptance=risk_score_at_acceptance,
        )

        with self._lock:
            conn = self._connect()
            conn.execute(
                """
                INSERT INTO risk_acceptances
                    (id, finding_id, org_id, justification, business_reason,
                     compensating_controls, requested_by, requested_at,
                     approved_by, approved_at, expires_at, review_date,
                     status, priority, conditions, risk_score_at_acceptance)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    acceptance.id,
                    acceptance.finding_id,
                    acceptance.org_id,
                    acceptance.justification,
                    acceptance.business_reason,
                    acceptance.compensating_controls,
                    acceptance.requested_by,
                    acceptance.requested_at.isoformat(),
                    acceptance.approved_by,
                    acceptance.approved_at.isoformat() if acceptance.approved_at else None,
                    acceptance.expires_at.isoformat(),
                    acceptance.review_date.isoformat(),
                    acceptance.status,
                    acceptance.priority,
                    json.dumps(acceptance.conditions),
                    acceptance.risk_score_at_acceptance,
                ),
            )
            conn.commit()

        _logger.info(
            "risk_acceptance: requested %s for finding %s by %s",
            acceptance.id, finding_id, requested_by,
        )
        return acceptance

    def approve(
        self,
        acceptance_id: str,
        approver: str,
        comment: str = "",
        approver_role: str = "admin",
    ) -> RiskAcceptance:
        """Approve a pending risk acceptance.

        Only ADMIN or SECURITY_ANALYST roles may approve.

        Raises:
            ValueError: if acceptance not found, not pending, or role insufficient.
        """
        allowed_roles = {"admin", "security_analyst", "super_admin"}
        if approver_role.lower() not in allowed_roles:
            raise ValueError(
                f"Role '{approver_role}' is not permitted to approve risk acceptances. "
                f"Required: {allowed_roles}"
            )

        acceptance = self.get_acceptance(acceptance_id)
        if acceptance is None:
            raise ValueError(f"Risk acceptance '{acceptance_id}' not found")
        if acceptance.status != AcceptanceStatus.PENDING:
            raise ValueError(
                f"Cannot approve acceptance in status '{acceptance.status}'. Must be 'pending'."
            )

        now_iso = self._now_iso()
        with self._lock:
            conn = self._connect()
            conn.execute(
                "UPDATE risk_acceptances SET status=?, approved_by=?, approved_at=? WHERE id=?",
                (AcceptanceStatus.APPROVED, approver, now_iso, acceptance_id),
            )
            conn.commit()

        self._add_review(acceptance_id, approver, "approved", comment)
        _logger.info("risk_acceptance: %s approved by %s", acceptance_id, approver)
        return self.get_acceptance(acceptance_id)  # type: ignore[return-value]

    def reject(
        self,
        acceptance_id: str,
        reviewer: str,
        reason: str = "",
    ) -> RiskAcceptance:
        """Reject a pending risk acceptance request.

        Raises:
            ValueError: if acceptance not found or not in a rejectable state.
        """
        acceptance = self.get_acceptance(acceptance_id)
        if acceptance is None:
            raise ValueError(f"Risk acceptance '{acceptance_id}' not found")
        if acceptance.status != AcceptanceStatus.PENDING:
            raise ValueError(
                f"Cannot reject acceptance in status '{acceptance.status}'. Must be 'pending'."
            )

        with self._lock:
            conn = self._connect()
            conn.execute(
                "UPDATE risk_acceptances SET status=? WHERE id=?",
                (AcceptanceStatus.REJECTED, acceptance_id),
            )
            conn.commit()

        self._add_review(acceptance_id, reviewer, "rejected", reason)
        _logger.info("risk_acceptance: %s rejected by %s", acceptance_id, reviewer)
        return self.get_acceptance(acceptance_id)  # type: ignore[return-value]

    def revoke(
        self,
        acceptance_id: str,
        revoker: str,
        reason: str = "",
    ) -> RiskAcceptance:
        """Revoke a previously approved risk acceptance.

        Raises:
            ValueError: if acceptance not found or not currently approved.
        """
        acceptance = self.get_acceptance(acceptance_id)
        if acceptance is None:
            raise ValueError(f"Risk acceptance '{acceptance_id}' not found")
        if acceptance.status != AcceptanceStatus.APPROVED:
            raise ValueError(
                f"Cannot revoke acceptance in status '{acceptance.status}'. Must be 'approved'."
            )

        with self._lock:
            conn = self._connect()
            conn.execute(
                "UPDATE risk_acceptances SET status=? WHERE id=?",
                (AcceptanceStatus.REVOKED, acceptance_id),
            )
            conn.commit()

        self._add_review(acceptance_id, revoker, "revoked", reason)
        _logger.info("risk_acceptance: %s revoked by %s", acceptance_id, revoker)
        return self.get_acceptance(acceptance_id)  # type: ignore[return-value]

    def get_acceptance(self, acceptance_id: str) -> Optional[RiskAcceptance]:
        """Retrieve a risk acceptance by ID."""
        with self._lock:
            conn = self._connect()
            row = conn.execute(
                "SELECT * FROM risk_acceptances WHERE id=?", (acceptance_id,)
            ).fetchone()
        if row is None:
            return None
        return self._row_to_acceptance(row)

    def list_acceptances(
        self,
        org_id: str,
        status_filter: Optional[AcceptanceStatus] = None,
    ) -> List[RiskAcceptance]:
        """List all risk acceptances for an org, optionally filtered by status."""
        with self._lock:
            conn = self._connect()
            if status_filter is not None:
                status_val = status_filter.value if hasattr(status_filter, "value") else str(status_filter)
                rows = conn.execute(
                    "SELECT * FROM risk_acceptances WHERE org_id=? AND status=? ORDER BY requested_at DESC",
                    (org_id, status_val),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM risk_acceptances WHERE org_id=? ORDER BY requested_at DESC",
                    (org_id,),
                ).fetchall()
        return [self._row_to_acceptance(r) for r in rows]

    def get_pending_reviews(self, org_id: str) -> List[RiskAcceptance]:
        """Return all acceptances awaiting approval for an org."""
        return self.list_acceptances(org_id, status_filter=AcceptanceStatus.PENDING)

    def get_expiring_soon(self, org_id: str, days: int = 30) -> List[RiskAcceptance]:
        """Return approved acceptances expiring within *days* days."""
        now = datetime.now(timezone.utc)
        cutoff = (now + timedelta(days=days)).isoformat()
        now_iso = now.isoformat()
        with self._lock:
            conn = self._connect()
            rows = conn.execute(
                """
                SELECT * FROM risk_acceptances
                WHERE org_id=? AND status=? AND expires_at > ? AND expires_at <= ?
                ORDER BY expires_at ASC
                """,
                (org_id, AcceptanceStatus.APPROVED.value, now_iso, cutoff),
            ).fetchall()
        return [self._row_to_acceptance(r) for r in rows]

    def expire_overdue(self, org_id: str) -> int:
        """Mark all overdue APPROVED acceptances as EXPIRED.

        Returns:
            Number of acceptances transitioned to EXPIRED.
        """
        now_iso = self._now_iso()
        with self._lock:
            conn = self._connect()
            cursor = conn.execute(
                """
                UPDATE risk_acceptances
                SET status=?
                WHERE org_id=? AND status=? AND expires_at <= ?
                """,
                (AcceptanceStatus.EXPIRED.value, org_id, AcceptanceStatus.APPROVED.value, now_iso),
            )
            conn.commit()
            count = cursor.rowcount

        if count:
            _logger.info("risk_acceptance: expired %d acceptances for org %s", count, org_id)
        return count

    def get_acceptance_for_finding(self, finding_id: str) -> Optional[RiskAcceptance]:
        """Return the most recent acceptance for a given finding_id (any status)."""
        with self._lock:
            conn = self._connect()
            row = conn.execute(
                """
                SELECT * FROM risk_acceptances
                WHERE finding_id=?
                ORDER BY requested_at DESC
                LIMIT 1
                """,
                (finding_id,),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_acceptance(row)

    def get_review_history(self, acceptance_id: str) -> List[AcceptanceReview]:
        """Return all review actions taken against an acceptance, oldest first."""
        with self._lock:
            conn = self._connect()
            rows = conn.execute(
                "SELECT * FROM acceptance_reviews WHERE acceptance_id=? ORDER BY reviewed_at ASC",
                (acceptance_id,),
            ).fetchall()
        return [self._row_to_review(r) for r in rows]

    def get_acceptance_stats(self, org_id: str) -> Dict[str, Any]:
        """Compute summary statistics for an org's risk acceptances.

        Returns:
            Dict with keys: total, pending, approved, rejected, expired, revoked,
            avg_duration_days (average days between request and approval/rejection).
        """
        acceptances = self.list_acceptances(org_id)
        stats: Dict[str, Any] = {
            "total": len(acceptances),
            "pending": 0,
            "approved": 0,
            "rejected": 0,
            "expired": 0,
            "revoked": 0,
            "avg_duration_days": None,
        }

        durations: List[float] = []
        for acc in acceptances:
            status_key = acc.status if isinstance(acc.status, str) else acc.status.value
            if status_key in stats:
                stats[status_key] += 1

            # Duration: days from request to decision
            if acc.approved_at is not None:
                approved_at = acc.approved_at
                requested_at = acc.requested_at
                if approved_at.tzinfo is None:
                    approved_at = approved_at.replace(tzinfo=timezone.utc)
                if requested_at.tzinfo is None:
                    requested_at = requested_at.replace(tzinfo=timezone.utc)
                delta = (approved_at - requested_at).total_seconds() / 86400
                durations.append(delta)

        if durations:
            stats["avg_duration_days"] = round(sum(durations) / len(durations), 2)

        return stats

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _add_review(
        self,
        acceptance_id: str,
        reviewer: str,
        decision: str,
        comment: str,
    ) -> AcceptanceReview:
        """Persist an AcceptanceReview record."""
        review = AcceptanceReview(
            acceptance_id=acceptance_id,
            reviewer=reviewer,
            decision=decision,
            comment=comment,
        )
        with self._lock:
            conn = self._connect()
            conn.execute(
                """
                INSERT INTO acceptance_reviews
                    (id, acceptance_id, reviewer, decision, comment, reviewed_at)
                VALUES (?,?,?,?,?,?)
                """,
                (
                    review.id,
                    review.acceptance_id,
                    review.reviewer,
                    review.decision,
                    review.comment,
                    review.reviewed_at.isoformat(),
                ),
            )
            conn.commit()
        return review


__all__ = [
    "AcceptanceStatus",
    "ReviewPriority",
    "RiskAcceptance",
    "AcceptanceReview",
    "RiskAcceptanceManager",
]
