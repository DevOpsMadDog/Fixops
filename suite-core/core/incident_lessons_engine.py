"""Incident Lessons Engine — ALDECI.

Captures and tracks lessons learned from security incidents — post-incident
analysis, action items, and implementation tracking.

Capabilities:
  - Lessons learned lifecycle (open/in-progress/reviewed/implemented/closed)
  - Action item tracking with due dates and completion
  - Lesson reviews with acceptance outcomes
  - Auto-promote lesson to "implemented" when all actions complete
  - Overdue action detection
  - Implementation rate and summary stats

Compliance: ISO 27001 A.5.27 (lessons learned), NIST SP 800-61 Rev 2 (post-incident)
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

_DEFAULT_DB_DIR = str(Path(__file__).resolve().parents[2] / ".fixops_data")

_VALID_LESSON_TYPES = {
    "process", "technology", "communication", "training",
    "detection", "response", "recovery", "prevention",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_STATUSES = {"open", "in-progress", "reviewed", "implemented", "closed"}
_VALID_PRIORITIES = {"critical", "high", "medium", "low"}
_VALID_OUTCOMES = {"accepted", "rejected", "modified"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class IncidentLessonsEngine:
    """SQLite WAL-backed Incident Lessons Learned engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/incident_lessons.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(Path(_DEFAULT_DB_DIR) / "incident_lessons.db")
        self._db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS lessons_learned (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    incident_id    TEXT NOT NULL,
                    title          TEXT NOT NULL,
                    description    TEXT NOT NULL DEFAULT '',
                    lesson_type    TEXT NOT NULL,
                    severity       TEXT NOT NULL,
                    status         TEXT NOT NULL DEFAULT 'open',
                    identified_by  TEXT NOT NULL DEFAULT '',
                    created_at     TEXT NOT NULL,
                    reviewed_at    TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_ll_org
                    ON lessons_learned (org_id, status, lesson_type, created_at DESC);

                CREATE TABLE IF NOT EXISTS action_items (
                    id            TEXT PRIMARY KEY,
                    lesson_id     TEXT NOT NULL,
                    org_id        TEXT NOT NULL,
                    action        TEXT NOT NULL,
                    owner         TEXT NOT NULL DEFAULT '',
                    due_date      TEXT NOT NULL,
                    status        TEXT NOT NULL DEFAULT 'open',
                    priority      TEXT NOT NULL DEFAULT 'medium',
                    completed_at  TEXT,
                    created_at    TEXT NOT NULL,
                    FOREIGN KEY (lesson_id) REFERENCES lessons_learned(id)
                );

                CREATE INDEX IF NOT EXISTS idx_ai_lesson
                    ON action_items (lesson_id, org_id, status);

                CREATE TABLE IF NOT EXISTS lesson_reviews (
                    id          TEXT PRIMARY KEY,
                    lesson_id   TEXT NOT NULL,
                    org_id      TEXT NOT NULL,
                    reviewer    TEXT NOT NULL,
                    outcome     TEXT NOT NULL,
                    notes       TEXT NOT NULL DEFAULT '',
                    reviewed_at TEXT NOT NULL,
                    FOREIGN KEY (lesson_id) REFERENCES lessons_learned(id)
                );

                CREATE INDEX IF NOT EXISTS idx_lr_lesson
                    ON lesson_reviews (lesson_id, org_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Lessons
    # ------------------------------------------------------------------

    def create_lesson(
        self,
        org_id: str,
        incident_id: str,
        title: str,
        description: str,
        lesson_type: str,
        severity: str,
        identified_by: str = "",
    ) -> Dict[str, Any]:
        """Create a new lessons-learned entry."""
        if not incident_id.strip():
            raise ValueError("incident_id is required.")
        if not title.strip():
            raise ValueError("title is required.")
        if lesson_type not in _VALID_LESSON_TYPES:
            raise ValueError(
                f"Invalid lesson_type: {lesson_type!r}. "
                f"Must be one of {sorted(_VALID_LESSON_TYPES)}"
            )
        if severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity: {severity!r}. "
                f"Must be one of {sorted(_VALID_SEVERITIES)}"
            )
        now = _now()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "incident_id": incident_id.strip(),
            "title": title.strip(),
            "description": description or "",
            "lesson_type": lesson_type,
            "severity": severity,
            "status": "open",
            "identified_by": identified_by or "",
            "created_at": now,
            "reviewed_at": None,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO lessons_learned
                       (id, org_id, incident_id, title, description, lesson_type,
                        severity, status, identified_by, created_at, reviewed_at)
                       VALUES (:id, :org_id, :incident_id, :title, :description,
                               :lesson_type, :severity, :status, :identified_by,
                               :created_at, :reviewed_at)""",
                    record,
                )
        return record

    def get_lesson(self, lesson_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        """Get a lesson with its action_items and reviews."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM lessons_learned WHERE id=? AND org_id=?",
                (lesson_id, org_id),
            ).fetchone()
            if not row:
                return None
            lesson = self._row(row)
            action_rows = conn.execute(
                "SELECT * FROM action_items WHERE lesson_id=? AND org_id=? ORDER BY created_at",
                (lesson_id, org_id),
            ).fetchall()
            review_rows = conn.execute(
                "SELECT * FROM lesson_reviews WHERE lesson_id=? AND org_id=? ORDER BY reviewed_at",
                (lesson_id, org_id),
            ).fetchall()
        lesson["action_items"] = [self._row(r) for r in action_rows]
        lesson["reviews"] = [self._row(r) for r in review_rows]
        return lesson

    def list_lessons(
        self,
        org_id: str,
        status: Optional[str] = None,
        lesson_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List lessons with optional filters."""
        query = "SELECT * FROM lessons_learned WHERE org_id=?"
        params: List[Any] = [org_id]
        if status:
            query += " AND status=?"
            params.append(status)
        if lesson_type:
            query += " AND lesson_type=?"
            params.append(lesson_type)
        query += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Action Items
    # ------------------------------------------------------------------

    def add_action_item(
        self,
        lesson_id: str,
        org_id: str,
        action: str,
        owner: str,
        due_date: str,
        priority: str = "medium",
    ) -> Dict[str, Any]:
        """Add an action item to a lesson."""
        if not action.strip():
            raise ValueError("action is required.")
        if not due_date.strip():
            raise ValueError("due_date is required.")
        if priority not in _VALID_PRIORITIES:
            raise ValueError(
                f"Invalid priority: {priority!r}. "
                f"Must be one of {sorted(_VALID_PRIORITIES)}"
            )
        # Verify lesson exists for this org
        with self._conn() as conn:
            row = conn.execute(
                "SELECT id FROM lessons_learned WHERE id=? AND org_id=?",
                (lesson_id, org_id),
            ).fetchone()
        if not row:
            raise KeyError(f"Lesson {lesson_id!r} not found.")

        now = _now()
        record = {
            "id": str(uuid.uuid4()),
            "lesson_id": lesson_id,
            "org_id": org_id,
            "action": action.strip(),
            "owner": owner or "",
            "due_date": due_date.strip(),
            "status": "open",
            "priority": priority,
            "completed_at": None,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO action_items
                       (id, lesson_id, org_id, action, owner, due_date, status,
                        priority, completed_at, created_at)
                       VALUES (:id, :lesson_id, :org_id, :action, :owner, :due_date,
                               :status, :priority, :completed_at, :created_at)""",
                    record,
                )
            # If lesson is "open", advance to "in-progress"
            with self._conn() as conn:
                conn.execute(
                    """UPDATE lessons_learned SET status='in-progress'
                       WHERE id=? AND org_id=? AND status='open'""",
                    (lesson_id, org_id),
                )
        return record

    def complete_action(
        self, lesson_id: str, action_id: str, org_id: str
    ) -> Dict[str, Any]:
        """Mark an action item as completed. Auto-implements lesson when all done."""
        now = _now()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM action_items WHERE id=? AND lesson_id=? AND org_id=?",
                    (action_id, lesson_id, org_id),
                ).fetchone()
                if not row:
                    raise KeyError(f"Action item {action_id!r} not found.")
                conn.execute(
                    """UPDATE action_items SET status='completed', completed_at=?
                       WHERE id=? AND lesson_id=? AND org_id=?""",
                    (now, action_id, lesson_id, org_id),
                )
                # Check if all actions are completed
                pending = conn.execute(
                    """SELECT COUNT(*) FROM action_items
                       WHERE lesson_id=? AND org_id=? AND status != 'completed'""",
                    (lesson_id, org_id),
                ).fetchone()[0]
                if pending == 0:
                    conn.execute(
                        """UPDATE lessons_learned SET status='implemented'
                           WHERE id=? AND org_id=? AND status NOT IN ('closed', 'implemented')""",
                        (lesson_id, org_id),
                    )
                updated = conn.execute(
                    "SELECT * FROM action_items WHERE id=?", (action_id,)
                ).fetchone()
        return self._row(updated)

    # ------------------------------------------------------------------
    # Reviews
    # ------------------------------------------------------------------

    def review_lesson(
        self,
        lesson_id: str,
        org_id: str,
        reviewer: str,
        outcome: str,
        notes: str = "",
    ) -> Dict[str, Any]:
        """Create a review record and mark lesson as reviewed."""
        if not reviewer.strip():
            raise ValueError("reviewer is required.")
        if outcome not in _VALID_OUTCOMES:
            raise ValueError(
                f"Invalid outcome: {outcome!r}. "
                f"Must be one of {sorted(_VALID_OUTCOMES)}"
            )
        # Verify lesson
        with self._conn() as conn:
            row = conn.execute(
                "SELECT id FROM lessons_learned WHERE id=? AND org_id=?",
                (lesson_id, org_id),
            ).fetchone()
        if not row:
            raise KeyError(f"Lesson {lesson_id!r} not found.")

        now = _now()
        review = {
            "id": str(uuid.uuid4()),
            "lesson_id": lesson_id,
            "org_id": org_id,
            "reviewer": reviewer.strip(),
            "outcome": outcome,
            "notes": notes or "",
            "reviewed_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO lesson_reviews
                       (id, lesson_id, org_id, reviewer, outcome, notes, reviewed_at)
                       VALUES (:id, :lesson_id, :org_id, :reviewer, :outcome, :notes, :reviewed_at)""",
                    review,
                )
                conn.execute(
                    """UPDATE lessons_learned SET reviewed_at=?, status='reviewed'
                       WHERE id=? AND org_id=? AND status NOT IN ('implemented', 'closed')""",
                    (now, lesson_id, org_id),
                )
        return review

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_overdue_actions(self, org_id: str) -> List[Dict[str, Any]]:
        """Return action items past their due_date and not yet completed."""
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM action_items
                   WHERE org_id=? AND status != 'completed' AND due_date < ?
                   ORDER BY due_date ASC""",
                (org_id, today),
            ).fetchall()
        return [self._row(r) for r in rows]

    def get_implementation_rate(self, org_id: str) -> Dict[str, Any]:
        """Return % of lessons where all action items are completed (implemented)."""
        with self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM lessons_learned WHERE org_id=?", (org_id,)
            ).fetchone()[0]
            implemented = conn.execute(
                """SELECT COUNT(*) FROM lessons_learned
                   WHERE org_id=? AND status IN ('implemented', 'closed')""",
                (org_id,),
            ).fetchone()[0]
        rate = (implemented / total * 100) if total > 0 else 0.0
        return {
            "total_lessons": total,
            "implemented_lessons": implemented,
            "implementation_rate_pct": round(rate, 2),
        }

    def get_lessons_summary(self, org_id: str) -> Dict[str, Any]:
        """Return counts by status and lesson_type."""
        with self._conn() as conn:
            by_status_rows = conn.execute(
                """SELECT status, COUNT(*) as cnt FROM lessons_learned
                   WHERE org_id=? GROUP BY status""",
                (org_id,),
            ).fetchall()
            by_type_rows = conn.execute(
                """SELECT lesson_type, COUNT(*) as cnt FROM lessons_learned
                   WHERE org_id=? GROUP BY lesson_type""",
                (org_id,),
            ).fetchall()
            total_actions = conn.execute(
                "SELECT COUNT(*) FROM action_items WHERE org_id=?", (org_id,)
            ).fetchone()[0]
            open_actions = conn.execute(
                "SELECT COUNT(*) FROM action_items WHERE org_id=? AND status='open'",
                (org_id,),
            ).fetchone()[0]
        return {
            "by_status": {r["status"]: r["cnt"] for r in by_status_rows},
            "by_lesson_type": {r["lesson_type"]: r["cnt"] for r in by_type_rows},
            "total_action_items": total_actions,
            "open_action_items": open_actions,
        }
