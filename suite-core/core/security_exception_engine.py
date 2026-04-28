"""Security Exception Manager — ALDECI.

Manages security exceptions (vulnerability, policy, compliance, configuration,
access). Supports request → review → approve/reject/revoke lifecycle with
expiry tracking and notification logging.

Multi-tenant via org_id. SQLite WAL + threading.RLock for concurrency safety.
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "security_exceptions.db"
)


class SecurityExceptionEngine:
    """SQLite WAL-backed security exception manager.

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
                CREATE TABLE IF NOT EXISTS exceptions (
                    exception_id            TEXT PRIMARY KEY,
                    org_id                  TEXT NOT NULL,
                    title                   TEXT NOT NULL,
                    description             TEXT NOT NULL DEFAULT '',
                    exception_type          TEXT NOT NULL DEFAULT 'vulnerability',
                    risk_level              TEXT NOT NULL DEFAULT 'medium',
                    status                  TEXT NOT NULL DEFAULT 'pending',
                    requestor               TEXT NOT NULL DEFAULT '',
                    approver                TEXT NOT NULL DEFAULT '',
                    business_justification  TEXT NOT NULL DEFAULT '',
                    compensating_controls   TEXT NOT NULL DEFAULT '',
                    requested_at            DATETIME NOT NULL,
                    approved_at             DATETIME,
                    expires_at              DATETIME,
                    reviewed_at             DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_exc_org
                    ON exceptions (org_id);

                CREATE INDEX IF NOT EXISTS idx_exc_org_status
                    ON exceptions (org_id, status);

                CREATE TABLE IF NOT EXISTS exception_assets (
                    asset_id        TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    exception_id    TEXT NOT NULL REFERENCES exceptions(exception_id),
                    asset_name      TEXT NOT NULL,
                    asset_type      TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_ea_org_exc
                    ON exception_assets (org_id, exception_id);

                CREATE TABLE IF NOT EXISTS exception_reviews (
                    review_id       TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    exception_id    TEXT NOT NULL REFERENCES exceptions(exception_id),
                    reviewer        TEXT NOT NULL,
                    action          TEXT NOT NULL DEFAULT 'request_info',
                    notes           TEXT NOT NULL DEFAULT '',
                    new_expiry      TEXT NOT NULL DEFAULT '',
                    reviewed_at     DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_er_org_exc
                    ON exception_reviews (org_id, exception_id);

                CREATE TABLE IF NOT EXISTS exception_notifications (
                    notif_id            TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    exception_id        TEXT NOT NULL REFERENCES exceptions(exception_id),
                    notification_type   TEXT NOT NULL DEFAULT 'created',
                    message             TEXT NOT NULL DEFAULT '',
                    sent_at             DATETIME NOT NULL,
                    recipient           TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_en_org_exc
                    ON exception_notifications (org_id, exception_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    def _send_notification(
        self,
        conn: sqlite3.Connection,
        org_id: str,
        exception_id: str,
        notification_type: str,
        message: str,
        recipient: str = "",
    ) -> None:
        """Log a notification record (integration point for email/Slack)."""
        notif_id = str(uuid.uuid4())
        now = self._now()
        conn.execute(
            """
            INSERT INTO exception_notifications
                (notif_id, org_id, exception_id, notification_type, message, sent_at, recipient)
            VALUES (?,?,?,?,?,?,?)
            """,
            (notif_id, org_id, exception_id, notification_type, message, now, recipient),
        )
        _logger.info(
            "exception_notification org_id=%s exception_id=%s type=%s recipient=%s",
            org_id, exception_id, notification_type, recipient,
        )

    # ------------------------------------------------------------------
    # Exception CRUD
    # ------------------------------------------------------------------

    def request_exception(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new exception request with status=pending. Logs creation notification."""
        exception_id = str(uuid.uuid4())
        now = self._now()
        requestor = data.get("requestor", "")

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO exceptions
                        (exception_id, org_id, title, description, exception_type,
                         risk_level, status, requestor, approver, business_justification,
                         compensating_controls, requested_at, expires_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        exception_id, org_id,
                        data.get("title", "Untitled Exception"),
                        data.get("description", ""),
                        data.get("exception_type", "vulnerability"),
                        data.get("risk_level", "medium"),
                        "pending",
                        requestor,
                        data.get("approver", ""),
                        data.get("business_justification", ""),
                        data.get("compensating_controls", ""),
                        now,
                        data.get("expires_at"),
                    ),
                )
                self._send_notification(
                    conn, org_id, exception_id, "created",
                    f"New security exception requested: {data.get('title', 'Untitled Exception')}",
                    recipient=data.get("approver", ""),
                )

        return {
            "exception_id": exception_id,
            "org_id": org_id,
            "title": data.get("title", "Untitled Exception"),
            "description": data.get("description", ""),
            "exception_type": data.get("exception_type", "vulnerability"),
            "risk_level": data.get("risk_level", "medium"),
            "status": "pending",
            "requestor": requestor,
            "approver": data.get("approver", ""),
            "business_justification": data.get("business_justification", ""),
            "compensating_controls": data.get("compensating_controls", ""),
            "requested_at": now,
            "approved_at": None,
            "expires_at": data.get("expires_at"),
            "reviewed_at": None,
        }

    def list_exceptions(
        self,
        org_id: str,
        status: Optional[str] = None,
        risk_level: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List exceptions for an org with optional filters."""
        query = "SELECT * FROM exceptions WHERE org_id=?"
        params: list = [org_id]
        if status:
            query += " AND status=?"
            params.append(status)
        if risk_level:
            query += " AND risk_level=?"
            params.append(risk_level)
        query += " ORDER BY requested_at DESC"

        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def get_exception(self, org_id: str, exception_id: str) -> Optional[Dict[str, Any]]:
        """Get a single exception by ID."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM exceptions WHERE org_id=? AND exception_id=?",
                    (org_id, exception_id),
                ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Review lifecycle
    # ------------------------------------------------------------------

    def review_exception(
        self,
        org_id: str,
        exception_id: str,
        action: str,
        reviewer: str,
        notes: str = "",
        new_expiry: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Review an exception. Actions: approve, reject, request_info, extend.

        - approve  → status=approved, sets approved_at
        - reject   → status=rejected
        - extend   → updates expires_at
        - request_info → no status change
        Returns updated exception dict.
        """
        review_id = str(uuid.uuid4())
        now = self._now()

        with self._lock:
            with self._conn() as conn:
                # Log the review
                conn.execute(
                    """
                    INSERT INTO exception_reviews
                        (review_id, org_id, exception_id, reviewer, action, notes, new_expiry, reviewed_at)
                    VALUES (?,?,?,?,?,?,?,?)
                    """,
                    (
                        review_id, org_id, exception_id,
                        reviewer, action, notes,
                        new_expiry or "", now,
                    ),
                )

                # Update exception based on action
                if action == "approve":
                    conn.execute(
                        """
                        UPDATE exceptions
                        SET status='approved', approver=?, approved_at=?, reviewed_at=?
                        WHERE org_id=? AND exception_id=?
                        """,
                        (reviewer, now, now, org_id, exception_id),
                    )
                    notif_type = "approved"
                    notif_msg = f"Security exception approved by {reviewer}"
                elif action == "reject":
                    conn.execute(
                        """
                        UPDATE exceptions
                        SET status='rejected', reviewed_at=?
                        WHERE org_id=? AND exception_id=?
                        """,
                        (now, org_id, exception_id),
                    )
                    notif_type = "rejected"
                    notif_msg = f"Security exception rejected by {reviewer}"
                elif action == "extend" and new_expiry:
                    conn.execute(
                        """
                        UPDATE exceptions
                        SET expires_at=?, reviewed_at=?
                        WHERE org_id=? AND exception_id=?
                        """,
                        (new_expiry, now, org_id, exception_id),
                    )
                    notif_type = "approved"
                    notif_msg = f"Security exception extended to {new_expiry} by {reviewer}"
                else:
                    conn.execute(
                        "UPDATE exceptions SET reviewed_at=? WHERE org_id=? AND exception_id=?",
                        (now, org_id, exception_id),
                    )
                    notif_type = "created"
                    notif_msg = f"Additional information requested by {reviewer}"

                self._send_notification(
                    conn, org_id, exception_id, notif_type, notif_msg,
                )

                row = conn.execute(
                    "SELECT * FROM exceptions WHERE org_id=? AND exception_id=?",
                    (org_id, exception_id),
                ).fetchone()

        return self._row(row) if row else {}

    # ------------------------------------------------------------------
    # Assets
    # ------------------------------------------------------------------

    def add_asset(self, org_id: str, exception_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add an asset to an exception."""
        asset_id = str(uuid.uuid4())
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO exception_assets
                        (asset_id, org_id, exception_id, asset_name, asset_type)
                    VALUES (?,?,?,?,?)
                    """,
                    (
                        asset_id, org_id, exception_id,
                        data.get("asset_name", ""),
                        data.get("asset_type", ""),
                    ),
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "security_exception", "org_id": org_id, "source_engine": "security_exception"})
            except Exception:
                pass

        return {
            "asset_id": asset_id,
            "org_id": org_id,
            "exception_id": exception_id,
            "asset_name": data.get("asset_name", ""),
            "asset_type": data.get("asset_type", ""),
        }

    def list_assets(self, org_id: str, exception_id: str) -> List[Dict[str, Any]]:
        """List assets attached to an exception."""
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM exception_assets WHERE org_id=? AND exception_id=?",
                    (org_id, exception_id),
                ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Expiry tracking
    # ------------------------------------------------------------------

    def check_expiring(self, org_id: str, days_ahead: int = 7) -> List[Dict[str, Any]]:
        """Return approved exceptions expiring within days_ahead days."""
        now = datetime.now(timezone.utc)
        cutoff = (now + timedelta(days=days_ahead)).isoformat()
        now_str = now.isoformat()

        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    """
                    SELECT * FROM exceptions
                    WHERE org_id=? AND status='approved'
                      AND expires_at IS NOT NULL
                      AND expires_at > ?
                      AND expires_at <= ?
                    ORDER BY expires_at ASC
                    """,
                    (org_id, now_str, cutoff),
                ).fetchall()
        return [self._row(r) for r in rows]

    def revoke_exception(
        self,
        org_id: str,
        exception_id: str,
        revoker: str,
        reason: str = "",
    ) -> bool:
        """Revoke an approved exception. Logs a review record. Returns True on success."""
        review_id = str(uuid.uuid4())
        now = self._now()

        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    """
                    UPDATE exceptions
                    SET status='revoked', reviewed_at=?
                    WHERE org_id=? AND exception_id=?
                    """,
                    (now, org_id, exception_id),
                )
                if cur.rowcount == 0:
                    return False
                conn.execute(
                    """
                    INSERT INTO exception_reviews
                        (review_id, org_id, exception_id, reviewer, action, notes, new_expiry, reviewed_at)
                    VALUES (?,?,?,?,?,?,?,?)
                    """,
                    (review_id, org_id, exception_id, revoker, "reject", reason, "", now),
                )
                self._send_notification(
                    conn, org_id, exception_id, "rejected",
                    f"Exception revoked by {revoker}: {reason}",
                )
        return True

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_exception_stats(self, org_id: str) -> Dict[str, Any]:
        """Aggregate stats for the org."""
        now = datetime.now(timezone.utc)
        cutoff_7 = (now + timedelta(days=7)).isoformat()
        now_str = now.isoformat()

        with self._lock:
            with self._conn() as conn:
                total = conn.execute(
                    "SELECT COUNT(*) FROM exceptions WHERE org_id=?", (org_id,)
                ).fetchone()[0]

                pending = conn.execute(
                    "SELECT COUNT(*) FROM exceptions WHERE org_id=? AND status='pending'",
                    (org_id,),
                ).fetchone()[0]

                approved = conn.execute(
                    "SELECT COUNT(*) FROM exceptions WHERE org_id=? AND status='approved'",
                    (org_id,),
                ).fetchone()[0]

                expired = conn.execute(
                    "SELECT COUNT(*) FROM exceptions WHERE org_id=? AND status='expired'",
                    (org_id,),
                ).fetchone()[0]

                type_rows = conn.execute(
                    """
                    SELECT exception_type, COUNT(*) as cnt
                    FROM exceptions WHERE org_id=?
                    GROUP BY exception_type
                    """,
                    (org_id,),
                ).fetchall()

                risk_rows = conn.execute(
                    """
                    SELECT risk_level, COUNT(*) as cnt
                    FROM exceptions WHERE org_id=?
                    GROUP BY risk_level
                    """,
                    (org_id,),
                ).fetchall()

                expiring_soon = conn.execute(
                    """
                    SELECT COUNT(*) FROM exceptions
                    WHERE org_id=? AND status='approved'
                      AND expires_at IS NOT NULL
                      AND expires_at > ?
                      AND expires_at <= ?
                    """,
                    (org_id, now_str, cutoff_7),
                ).fetchone()[0]

                # Average days from requested_at to approved_at for approved exceptions
                avg_row = conn.execute(
                    """
                    SELECT AVG(
                        CAST((julianday(approved_at) - julianday(requested_at)) AS REAL)
                    )
                    FROM exceptions
                    WHERE org_id=? AND status='approved' AND approved_at IS NOT NULL
                    """,
                    (org_id,),
                ).fetchone()[0]

        return {
            "total_exceptions": total,
            "pending": pending,
            "approved": approved,
            "expired": expired,
            "by_type": {r[0]: r[1] for r in type_rows},
            "by_risk": {r[0]: r[1] for r in risk_rows},
            "expiring_soon": expiring_soon,
            "avg_approval_days": round(avg_row, 2) if avg_row is not None else 0.0,
        }
