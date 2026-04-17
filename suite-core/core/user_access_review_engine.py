"""User Access Review Engine — ALDECI. SQLite WAL + RLock + org_id isolation.

Manages periodic access certification campaigns:
  - Access reviews with item-level certify/revoke/modify/defer decisions
  - Auto-complete review when all items are decided
  - Campaign scheduling with completion rate tracking
  - Overdue detection

Compliance: SOX, SOC2 CC6.2/CC6.3, ISO 27001 A.9.2.5, NIST AC-5/AC-6
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "user_access_review.db"
)

_VALID_REVIEW_TYPES = {
    "quarterly", "annual", "triggered", "ad-hoc", "role-based", "system-based",
}
_VALID_DECISIONS = {"certify", "revoke", "modify", "defer"}
_VALID_FREQUENCIES = {"monthly", "quarterly", "semi-annual", "annual"}
_VALID_STATUSES = {"pending", "in-progress", "completed", "cancelled"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class UserAccessReviewEngine:
    """SQLite WAL-backed User Access Review engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/user_access_review.db
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
                CREATE TABLE IF NOT EXISTS access_reviews (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    review_name  TEXT NOT NULL DEFAULT '',
                    review_type  TEXT NOT NULL DEFAULT 'quarterly',
                    status       TEXT NOT NULL DEFAULT 'pending',
                    reviewer_id  TEXT NOT NULL DEFAULT '',
                    created_at   TEXT NOT NULL,
                    completed_at TEXT,
                    due_date     TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_ar_org
                    ON access_reviews (org_id, status);

                CREATE TABLE IF NOT EXISTS review_items (
                    id              TEXT PRIMARY KEY,
                    review_id       TEXT NOT NULL,
                    org_id          TEXT NOT NULL,
                    user_id         TEXT NOT NULL DEFAULT '',
                    resource_id     TEXT NOT NULL DEFAULT '',
                    resource_type   TEXT NOT NULL DEFAULT '',
                    access_level    TEXT NOT NULL DEFAULT '',
                    decision        TEXT,
                    decision_reason TEXT NOT NULL DEFAULT '',
                    decided_at      TEXT,
                    decided_by      TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_ri_review
                    ON review_items (review_id, org_id);

                CREATE TABLE IF NOT EXISTS review_campaigns (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    campaign_name   TEXT NOT NULL DEFAULT '',
                    frequency       TEXT NOT NULL DEFAULT 'quarterly',
                    scope           TEXT NOT NULL DEFAULT '',
                    completion_rate REAL NOT NULL DEFAULT 0.0,
                    overdue_count   INTEGER NOT NULL DEFAULT 0,
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_rc_org
                    ON review_campaigns (org_id);
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
    # Reviews
    # ------------------------------------------------------------------

    def create_review(
        self,
        org_id: str,
        review_name: str,
        review_type: str = "quarterly",
        reviewer_id: str = "",
        due_date: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a new access review."""
        review_type = review_type or "quarterly"
        if review_type not in _VALID_REVIEW_TYPES:
            raise ValueError(
                f"Invalid review_type '{review_type}'. "
                f"Must be one of {sorted(_VALID_REVIEW_TYPES)}"
            )
        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "review_name": review_name or "",
            "review_type": review_type,
            "status": "pending",
            "reviewer_id": reviewer_id or "",
            "created_at": now,
            "completed_at": None,
            "due_date": due_date,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO access_reviews
                       (id, org_id, review_name, review_type, status, reviewer_id,
                        created_at, completed_at, due_date)
                       VALUES (:id, :org_id, :review_name, :review_type, :status,
                               :reviewer_id, :created_at, :completed_at, :due_date)""",
                    record,
                )
        return record

    def add_review_item(
        self,
        review_id: str,
        org_id: str,
        user_id: str,
        resource_id: str,
        resource_type: str = "",
        access_level: str = "",
    ) -> Dict[str, Any]:
        """Add an item to an existing review."""
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "review_id": review_id,
            "org_id": org_id,
            "user_id": user_id or "",
            "resource_id": resource_id or "",
            "resource_type": resource_type or "",
            "access_level": access_level or "",
            "decision": None,
            "decision_reason": "",
            "decided_at": None,
            "decided_by": "",
        }
        with self._lock:
            with self._conn() as conn:
                # Move review to in-progress when first item added
                conn.execute(
                    "UPDATE access_reviews SET status='in-progress' "
                    "WHERE id=? AND org_id=? AND status='pending'",
                    (review_id, org_id),
                )
                conn.execute(
                    """INSERT INTO review_items
                       (id, review_id, org_id, user_id, resource_id, resource_type,
                        access_level, decision, decision_reason, decided_at, decided_by)
                       VALUES (:id, :review_id, :org_id, :user_id, :resource_id,
                               :resource_type, :access_level, :decision,
                               :decision_reason, :decided_at, :decided_by)""",
                    record,
                )
        return record

    def make_decision(
        self,
        review_id: str,
        item_id: str,
        org_id: str,
        decision: str,
        decision_reason: str = "",
        decided_by: str = "",
    ) -> Dict[str, Any]:
        """Record a decision on a review item; auto-completes review if all decided."""
        if decision not in _VALID_DECISIONS:
            raise ValueError(
                f"Invalid decision '{decision}'. "
                f"Must be one of {sorted(_VALID_DECISIONS)}"
            )
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """UPDATE review_items
                       SET decision=?, decision_reason=?, decided_at=?, decided_by=?
                       WHERE id=? AND review_id=? AND org_id=?""",
                    (decision, decision_reason or "", now, decided_by or "",
                     item_id, review_id, org_id),
                )
                # Check if all items are decided
                row = conn.execute(
                    "SELECT COUNT(*) as total, "
                    "SUM(CASE WHEN decision IS NULL THEN 1 ELSE 0 END) as undecided "
                    "FROM review_items WHERE review_id=? AND org_id=?",
                    (review_id, org_id),
                ).fetchone()
                if row and row["total"] > 0 and row["undecided"] == 0:
                    conn.execute(
                        "UPDATE access_reviews SET status='completed', completed_at=? "
                        "WHERE id=? AND org_id=?",
                        (now, review_id, org_id),
                    )
                # Fetch updated item
                item_row = conn.execute(
                    "SELECT * FROM review_items WHERE id=? AND review_id=? AND org_id=?",
                    (item_id, review_id, org_id),
                ).fetchone()
        if item_row is None:
            raise ValueError(f"Item {item_id} not found in review {review_id}")
        return self._row(item_row)

    def get_review(self, review_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        """Get a review with all its items."""
        with self._lock:
            with self._conn() as conn:
                review_row = conn.execute(
                    "SELECT * FROM access_reviews WHERE id=? AND org_id=?",
                    (review_id, org_id),
                ).fetchone()
                if review_row is None:
                    return None
                review = self._row(review_row)
                items = conn.execute(
                    "SELECT * FROM review_items WHERE review_id=? AND org_id=? "
                    "ORDER BY rowid",
                    (review_id, org_id),
                ).fetchall()
                review["items"] = [self._row(r) for r in items]
        return review

    def list_reviews(
        self, org_id: str, status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List reviews, optionally filtered by status."""
        with self._lock:
            with self._conn() as conn:
                if status:
                    rows = conn.execute(
                        "SELECT * FROM access_reviews WHERE org_id=? AND status=? "
                        "ORDER BY created_at DESC",
                        (org_id, status),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM access_reviews WHERE org_id=? "
                        "ORDER BY created_at DESC",
                        (org_id,),
                    ).fetchall()
        return [self._row(r) for r in rows]

    def get_overdue_reviews(self, org_id: str) -> List[Dict[str, Any]]:
        """Return reviews past due_date that are not completed."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM access_reviews "
                    "WHERE org_id=? AND status NOT IN ('completed','cancelled') "
                    "AND due_date IS NOT NULL AND due_date < ? "
                    "ORDER BY due_date ASC",
                    (org_id, now),
                ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Campaigns
    # ------------------------------------------------------------------

    def create_campaign(
        self,
        org_id: str,
        campaign_name: str,
        frequency: str = "quarterly",
        scope: str = "",
    ) -> Dict[str, Any]:
        """Create a review campaign."""
        frequency = frequency or "quarterly"
        if frequency not in _VALID_FREQUENCIES:
            raise ValueError(
                f"Invalid frequency '{frequency}'. "
                f"Must be one of {sorted(_VALID_FREQUENCIES)}"
            )
        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "campaign_name": campaign_name or "",
            "frequency": frequency,
            "scope": scope or "",
            "completion_rate": 0.0,
            "overdue_count": 0,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO review_campaigns
                       (id, org_id, campaign_name, frequency, scope,
                        completion_rate, overdue_count, created_at)
                       VALUES (:id, :org_id, :campaign_name, :frequency, :scope,
                               :completion_rate, :overdue_count, :created_at)""",
                    record,
                )
        return record

    def get_campaign_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated campaign stats: avg completion_rate, total overdue_count."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT COUNT(*) as total_campaigns, "
                    "AVG(completion_rate) as avg_completion_rate, "
                    "SUM(overdue_count) as total_overdue "
                    "FROM review_campaigns WHERE org_id=?",
                    (org_id,),
                ).fetchone()
        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("IDENTITY_UPDATED", {"entity_type": "user_access_review_engine", "org_id": org_id, "source_engine": "user_access_review_engine"})
            except Exception:
                pass
        return {
            "org_id": org_id,
            "total_campaigns": row["total_campaigns"] if row else 0,
            "avg_completion_rate": round(row["avg_completion_rate"] or 0.0, 2) if row else 0.0,
            "total_overdue": row["total_overdue"] or 0 if row else 0,
        }

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def get_review_summary(self, org_id: str) -> Dict[str, Any]:
        """Return total/pending/completed/overdue counts for org."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                total = conn.execute(
                    "SELECT COUNT(*) FROM access_reviews WHERE org_id=?",
                    (org_id,),
                ).fetchone()[0]
                pending = conn.execute(
                    "SELECT COUNT(*) FROM access_reviews "
                    "WHERE org_id=? AND status IN ('pending','in-progress')",
                    (org_id,),
                ).fetchone()[0]
                completed = conn.execute(
                    "SELECT COUNT(*) FROM access_reviews "
                    "WHERE org_id=? AND status='completed'",
                    (org_id,),
                ).fetchone()[0]
                overdue = conn.execute(
                    "SELECT COUNT(*) FROM access_reviews "
                    "WHERE org_id=? AND status NOT IN ('completed','cancelled') "
                    "AND due_date IS NOT NULL AND due_date < ?",
                    (org_id, now),
                ).fetchone()[0]
        return {
            "org_id": org_id,
            "total": total,
            "pending": pending,
            "completed": completed,
            "overdue": overdue,
        }
