"""
Privileged Access Management (PAM) — time-bound elevation, break-glass, and audit trail.

Provides full PAM lifecycle: request elevation, approve/deny, check current privilege,
revoke, auto-expire, emergency break-glass, and audit reporting.

Thread-safe via per-thread SQLite connections (WAL mode).

Usage::

    mgr = PAMManager()
    req = mgr.request_access("alice@acme.com", PrivilegeLevel.ADMIN,
                              "Incident response", duration_minutes=60)
    mgr.approve_request(req.id, "security@acme.com")
    level = mgr.check_privilege("alice@acme.com")

Environment:
    FIXOPS_DATA_DIR   directory for the SQLite DB (default: ``.fixops_data``)
"""

from __future__ import annotations

import logging
import os
import secrets
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel

_logger = logging.getLogger(__name__)

_DB_ENV = "FIXOPS_DATA_DIR"
_DEFAULT_DB_DIR = ".fixops_data"

# Break-glass sessions are always 4 hours max
_BREAK_GLASS_DURATION_MINUTES = 240


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class PrivilegeLevel(str, Enum):
    STANDARD = "standard"
    ELEVATED = "elevated"
    ADMIN = "admin"
    SUPERADMIN = "superadmin"
    EMERGENCY = "emergency"


class RequestStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    REVOKED = "revoked"


# ---------------------------------------------------------------------------
# Pydantic model
# ---------------------------------------------------------------------------


class AccessRequest(BaseModel):
    """A privilege elevation request."""

    id: str
    user_email: str
    requested_level: PrivilegeLevel
    justification: str
    duration_minutes: int
    status: RequestStatus
    approved_by: Optional[str] = None
    denial_reason: Optional[str] = None
    created_at: datetime
    expires_at: Optional[datetime] = None
    org_id: str
    is_break_glass: bool = False
    post_review_required: bool = False

    model_config = {"arbitrary_types_allowed": True}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_dt(val: Optional[str]) -> Optional[datetime]:
    if not val:
        return None
    return datetime.fromisoformat(val)


def _new_id(prefix: str) -> str:
    return prefix + secrets.token_hex(8)


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class PAMManager:
    """
    SQLite-backed Privileged Access Management engine.

    Thread-safe: each thread keeps its own connection via ``threading.local``.
    Singleton pattern: calling ``PAMManager()`` without arguments returns the
    same instance; pass an explicit ``db_path`` to create a separate instance
    (useful for testing).
    """

    _instance: Optional["PAMManager"] = None
    _class_lock: threading.Lock = threading.Lock()

    def __new__(cls, db_path: Optional[str] = None) -> "PAMManager":
        with cls._class_lock:
            if db_path is not None:
                inst = object.__new__(cls)
                inst._init(db_path)
                return inst
            if cls._instance is None:
                inst = object.__new__(cls)
                default_path = os.path.join(
                    os.getenv(_DB_ENV, _DEFAULT_DB_DIR), "pam.db"
                )
                inst._init(default_path)
                cls._instance = inst
            return cls._instance  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    def _init(self, db_path: str) -> None:
        self._db_path = db_path
        from pathlib import Path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self._db_path)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return conn

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS access_requests (
                    id                  TEXT PRIMARY KEY,
                    user_email          TEXT NOT NULL,
                    requested_level     TEXT NOT NULL,
                    justification       TEXT NOT NULL,
                    duration_minutes    INTEGER NOT NULL,
                    status              TEXT NOT NULL DEFAULT 'pending',
                    approved_by         TEXT,
                    denial_reason       TEXT,
                    created_at          TEXT NOT NULL,
                    expires_at          TEXT,
                    org_id              TEXT NOT NULL,
                    is_break_glass      INTEGER NOT NULL DEFAULT 0,
                    post_review_required INTEGER NOT NULL DEFAULT 0
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_pam_org ON access_requests(org_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_pam_user ON access_requests(user_email)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_pam_status ON access_requests(status)"
            )

    # ------------------------------------------------------------------
    # Row converter
    # ------------------------------------------------------------------

    def _row_to_request(self, row: Dict[str, Any]) -> AccessRequest:
        return AccessRequest(
            id=row["id"],
            user_email=row["user_email"],
            requested_level=PrivilegeLevel(row["requested_level"]),
            justification=row["justification"],
            duration_minutes=int(row["duration_minutes"]),
            status=RequestStatus(row["status"]),
            approved_by=row.get("approved_by"),
            denial_reason=row.get("denial_reason"),
            created_at=_parse_dt(row["created_at"]) or _now(),
            expires_at=_parse_dt(row.get("expires_at")),
            org_id=row["org_id"],
            is_break_glass=bool(row.get("is_break_glass", False)),
            post_review_required=bool(row.get("post_review_required", False)),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def request_access(
        self,
        user_email: str,
        requested_level: PrivilegeLevel,
        justification: str,
        duration_minutes: int,
        org_id: str = "default",
    ) -> AccessRequest:
        """Create a privilege elevation request (status: pending).

        Returns the created ``AccessRequest``.
        """
        if duration_minutes <= 0:
            raise ValueError("duration_minutes must be positive")
        if not justification.strip():
            raise ValueError("justification is required")

        req_id = _new_id("pam_")
        now = _now()

        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO access_requests
                    (id, user_email, requested_level, justification,
                     duration_minutes, status, created_at, org_id)
                VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)
                """,
                (
                    req_id,
                    user_email,
                    requested_level.value,
                    justification.strip(),
                    duration_minutes,
                    now.isoformat(),
                    org_id,
                ),
            )

        _logger.info(
            "PAM request %s: user=%s level=%s org=%s",
            req_id, user_email, requested_level.value, org_id,
        )
        return self._get_request_by_id(req_id)  # type: ignore[return-value]

    def approve_request(
        self,
        request_id: str,
        approver: str,
    ) -> AccessRequest:
        """Approve a pending elevation request with time-bound access.

        Sets ``expires_at = now + duration_minutes`` and status to ``approved``.

        Raises:
            ValueError: if request not found or not in pending state.
        """
        req = self._get_request_by_id(request_id)
        if req is None:
            raise ValueError(f"Request not found: {request_id}")
        if req.status != RequestStatus.PENDING:
            raise ValueError(
                f"Request {request_id} is {req.status.value}, not pending"
            )

        now = _now()
        expires_at = now + timedelta(minutes=req.duration_minutes)

        with self._conn() as conn:
            conn.execute(
                """
                UPDATE access_requests
                SET status = 'approved', approved_by = ?, expires_at = ?
                WHERE id = ?
                """,
                (approver, expires_at.isoformat(), request_id),
            )

        _logger.info(
            "PAM approved %s by %s, expires %s", request_id, approver, expires_at.isoformat()
        )
        return self._get_request_by_id(request_id)  # type: ignore[return-value]

    def deny_request(
        self,
        request_id: str,
        reviewer: str,
        reason: str,
    ) -> AccessRequest:
        """Deny a pending elevation request.

        Raises:
            ValueError: if request not found or not in pending state.
        """
        req = self._get_request_by_id(request_id)
        if req is None:
            raise ValueError(f"Request not found: {request_id}")
        if req.status != RequestStatus.PENDING:
            raise ValueError(
                f"Request {request_id} is {req.status.value}, not pending"
            )

        with self._conn() as conn:
            conn.execute(
                """
                UPDATE access_requests
                SET status = 'denied', approved_by = ?, denial_reason = ?
                WHERE id = ?
                """,
                (reviewer, reason, request_id),
            )

        _logger.info("PAM denied %s by %s: %s", request_id, reviewer, reason)
        return self._get_request_by_id(request_id)  # type: ignore[return-value]

    def check_privilege(
        self,
        user_email: str,
        org_id: str = "default",
    ) -> PrivilegeLevel:
        """Return the current effective privilege level for a user.

        Checks for an active (approved + not expired) elevation. Returns the
        highest active level if multiple approvals exist, otherwise STANDARD.
        """
        now = _now()
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT requested_level FROM access_requests
                WHERE user_email = ? AND org_id = ?
                  AND status = 'approved'
                  AND expires_at > ?
                """,
                (user_email, org_id, now.isoformat()),
            ).fetchall()

        if not rows:
            return PrivilegeLevel.STANDARD

        # Return highest level found
        _order = [
            PrivilegeLevel.STANDARD,
            PrivilegeLevel.ELEVATED,
            PrivilegeLevel.ADMIN,
            PrivilegeLevel.SUPERADMIN,
            PrivilegeLevel.EMERGENCY,
        ]
        levels = [PrivilegeLevel(r["requested_level"]) for r in rows]
        return max(levels, key=lambda l: _order.index(l))

    def revoke_access(self, request_id: str) -> AccessRequest:
        """Immediately revoke an approved elevation.

        Raises:
            ValueError: if request not found or not currently approved.
        """
        req = self._get_request_by_id(request_id)
        if req is None:
            raise ValueError(f"Request not found: {request_id}")
        if req.status != RequestStatus.APPROVED:
            raise ValueError(
                f"Request {request_id} is {req.status.value}, cannot revoke"
            )

        with self._conn() as conn:
            conn.execute(
                "UPDATE access_requests SET status = 'revoked' WHERE id = ?",
                (request_id,),
            )

        _logger.info("PAM revoked %s", request_id)
        return self._get_request_by_id(request_id)  # type: ignore[return-value]

    def expire_access(self, org_id: str = "default") -> int:
        """Auto-expire approved elevations whose ``expires_at`` has passed.

        Returns count of requests transitioned to ``expired``.
        """
        now = _now()
        with self._conn() as conn:
            result = conn.execute(
                """
                UPDATE access_requests
                SET status = 'expired'
                WHERE org_id = ? AND status = 'approved' AND expires_at <= ?
                """,
                (org_id, now.isoformat()),
            )
        count = result.rowcount
        if count:
            _logger.info("PAM expired %d elevations for org=%s", count, org_id)
        return count

    def get_active_elevations(self, org_id: str = "default") -> List[AccessRequest]:
        """Return all currently active (approved + not expired) elevations."""
        now = _now()
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM access_requests
                WHERE org_id = ? AND status = 'approved' AND expires_at > ?
                ORDER BY expires_at ASC
                """,
                (org_id, now.isoformat()),
            ).fetchall()
        return [self._row_to_request(dict(r)) for r in rows]

    def get_request_history(
        self,
        org_id: str = "default",
        limit: int = 100,
        offset: int = 0,
    ) -> List[AccessRequest]:
        """Return full audit trail for an org, newest first."""
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM access_requests
                WHERE org_id = ?
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                (org_id, limit, offset),
            ).fetchall()
        return [self._row_to_request(dict(r)) for r in rows]

    def get_pam_stats(self, org_id: str = "default") -> Dict[str, Any]:
        """Return summary statistics for an org's PAM activity.

        Includes: counts by status, average duration, top requesters,
        break-glass count, pending post-review count.
        """
        with self._conn() as conn:
            # Status counts
            status_rows = conn.execute(
                """
                SELECT status, COUNT(*) as cnt
                FROM access_requests WHERE org_id = ?
                GROUP BY status
                """,
                (org_id,),
            ).fetchall()
            by_status = {r["status"]: r["cnt"] for r in status_rows}

            # Average duration of approved requests
            avg_row = conn.execute(
                """
                SELECT AVG(duration_minutes) as avg_dur
                FROM access_requests WHERE org_id = ? AND status = 'approved'
                """,
                (org_id,),
            ).fetchone()
            avg_duration = round(avg_row["avg_dur"], 1) if avg_row["avg_dur"] else 0.0

            # Top 5 requesters
            top_rows = conn.execute(
                """
                SELECT user_email, COUNT(*) as cnt
                FROM access_requests WHERE org_id = ?
                GROUP BY user_email ORDER BY cnt DESC LIMIT 5
                """,
                (org_id,),
            ).fetchall()
            top_requesters = [{"user_email": r["user_email"], "count": r["cnt"]} for r in top_rows]

            # Break-glass count
            bg_row = conn.execute(
                "SELECT COUNT(*) as cnt FROM access_requests WHERE org_id = ? AND is_break_glass = 1",
                (org_id,),
            ).fetchone()
            break_glass_count = bg_row["cnt"] if bg_row else 0

            # Post-review pending
            pr_row = conn.execute(
                """
                SELECT COUNT(*) as cnt FROM access_requests
                WHERE org_id = ? AND post_review_required = 1 AND status IN ('approved','expired')
                """,
                (org_id,),
            ).fetchone()
            post_review_pending = pr_row["cnt"] if pr_row else 0

            # Total
            total_row = conn.execute(
                "SELECT COUNT(*) as cnt FROM access_requests WHERE org_id = ?",
                (org_id,),
            ).fetchone()
            total = total_row["cnt"] if total_row else 0

        return {
            "org_id": org_id,
            "total_requests": total,
            "by_status": by_status,
            "avg_approved_duration_minutes": avg_duration,
            "top_requesters": top_requesters,
            "break_glass_count": break_glass_count,
            "post_review_pending": post_review_pending,
        }

    def break_glass(
        self,
        user_email: str,
        justification: str,
        org_id: str = "default",
    ) -> AccessRequest:
        """Emergency break-glass procedure.

        Auto-approves an EMERGENCY elevation immediately (no human approval step).
        Caps duration at ``_BREAK_GLASS_DURATION_MINUTES`` (4 hours).
        Flags ``is_break_glass=True`` and ``post_review_required=True`` for mandatory
        post-incident review.

        Returns the already-approved ``AccessRequest``.
        """
        if not justification.strip():
            raise ValueError("Break-glass justification is required")

        req_id = _new_id("bg_")
        now = _now()
        expires_at = now + timedelta(minutes=_BREAK_GLASS_DURATION_MINUTES)

        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO access_requests
                    (id, user_email, requested_level, justification,
                     duration_minutes, status, approved_by, created_at,
                     expires_at, org_id, is_break_glass, post_review_required)
                VALUES (?, ?, 'emergency', ?, ?, 'approved', 'system:break-glass',
                        ?, ?, ?, 1, 1)
                """,
                (
                    req_id,
                    user_email,
                    justification.strip(),
                    _BREAK_GLASS_DURATION_MINUTES,
                    now.isoformat(),
                    expires_at.isoformat(),
                    org_id,
                ),
            )

        _logger.warning(
            "BREAK-GLASS activated by %s for org=%s, expires %s. MANDATORY POST-REVIEW REQUIRED.",
            user_email, org_id, expires_at.isoformat(),
        )
        return self._get_request_by_id(req_id)  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_request_by_id(self, request_id: str) -> Optional[AccessRequest]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM access_requests WHERE id = ?", (request_id,)
            ).fetchone()
        if not row:
            return None
        return self._row_to_request(dict(row))


# ---------------------------------------------------------------------------
# Module-level singleton factory
# ---------------------------------------------------------------------------


def get_pam_manager(db_path: Optional[str] = None) -> PAMManager:
    """Return the singleton ``PAMManager`` (or a new instance for a custom path)."""
    return PAMManager(db_path=db_path)
