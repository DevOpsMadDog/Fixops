"""Compliance Calendar Engine — ALDECI.

Compliance calendar tracking deadlines, audits, renewals, and regulatory
filings. Supports recurrence, reminders, views, and calendar summaries.

Compliance: NIST CSF ID.GV-1, ISO/IEC 27001 A.18.1, SOC 2 CC3.1
"""

from __future__ import annotations

import contextlib
import logging
import sqlite3
import threading
import uuid
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "compliance_calendar.db"
)

_VALID_EVENT_TYPES = {
    "audit", "certification", "filing", "renewal",
    "review", "training", "assessment", "deadline",
}
_VALID_FRAMEWORKS = {
    "SOC2", "ISO27001", "PCI-DSS", "HIPAA",
    "GDPR", "NIST", "CIS", "FedRAMP",
}
_VALID_RECURRENCES = {"none", "weekly", "monthly", "quarterly", "annual"}
_VALID_PRIORITIES = {"critical", "high", "medium", "low"}
_VALID_STATUSES = {"upcoming", "completed", "cancelled", "overdue"}

_RECURRENCE_DAYS = {
    "weekly": 7,
    "monthly": 30,
    "quarterly": 90,
    "annual": 365,
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _today() -> str:
    return date.today().isoformat()


def _add_days_to_date(date_str: str, days: int) -> str:
    """Add days to a YYYY-MM-DD date string and return new date string."""
    d = date.fromisoformat(date_str)
    return (d + timedelta(days=days)).isoformat()


class ComplianceCalendarEngine:
    """SQLite WAL-backed Compliance Calendar engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
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
                CREATE TABLE IF NOT EXISTS calendar_events (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    event_name    TEXT NOT NULL,
                    event_type    TEXT NOT NULL DEFAULT 'deadline',
                    framework     TEXT NOT NULL DEFAULT 'NIST',
                    due_date      TEXT NOT NULL,
                    recurrence    TEXT NOT NULL DEFAULT 'none',
                    owner         TEXT NOT NULL DEFAULT '',
                    status        TEXT NOT NULL DEFAULT 'upcoming',
                    priority      TEXT NOT NULL DEFAULT 'medium',
                    reminder_days INTEGER NOT NULL DEFAULT 7,
                    notes         TEXT NOT NULL DEFAULT '',
                    created_at    TEXT,
                    completed_at  TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_cc_events_org_due
                    ON calendar_events (org_id, due_date, status);

                CREATE TABLE IF NOT EXISTS event_reminders (
                    id            TEXT PRIMARY KEY,
                    event_id      TEXT NOT NULL,
                    org_id        TEXT NOT NULL,
                    reminder_date TEXT NOT NULL,
                    sent          INTEGER NOT NULL DEFAULT 0,
                    sent_at       TEXT,
                    created_at    TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_cc_reminders_org_date
                    ON event_reminders (org_id, reminder_date, sent);

                CREATE TABLE IF NOT EXISTS calendar_views (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    view_name   TEXT NOT NULL,
                    frameworks  TEXT NOT NULL DEFAULT '',
                    event_types TEXT NOT NULL DEFAULT '',
                    created_at  TEXT
                );
                """
            )

    @contextlib.contextmanager
    def _conn(self):
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    def create_event(
        self,
        org_id: str,
        event_name: str,
        event_type: str,
        framework: str,
        due_date: str,
        recurrence: str = "none",
        owner: str = "",
        priority: str = "medium",
        reminder_days: int = 7,
        notes: str = "",
    ) -> Dict[str, Any]:
        """Create a new compliance calendar event with auto-reminder."""
        if event_type not in _VALID_EVENT_TYPES:
            raise ValueError(
                f"Invalid event_type '{event_type}'. Valid: {sorted(_VALID_EVENT_TYPES)}"
            )
        if framework not in _VALID_FRAMEWORKS:
            raise ValueError(
                f"Invalid framework '{framework}'. Valid: {sorted(_VALID_FRAMEWORKS)}"
            )
        if recurrence not in _VALID_RECURRENCES:
            raise ValueError(
                f"Invalid recurrence '{recurrence}'. Valid: {sorted(_VALID_RECURRENCES)}"
            )
        if priority not in _VALID_PRIORITIES:
            raise ValueError(
                f"Invalid priority '{priority}'. Valid: {sorted(_VALID_PRIORITIES)}"
            )

        event_id = str(uuid.uuid4())
        now = _now()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO calendar_events
                        (id, org_id, event_name, event_type, framework, due_date,
                         recurrence, owner, status, priority, reminder_days,
                         notes, created_at, completed_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        event_id, org_id, event_name, event_type, framework,
                        due_date, recurrence, owner, "upcoming", priority,
                        reminder_days, notes, now, None,
                    ),
                )
                # Auto-create reminder
                reminder_date = _add_days_to_date(due_date, -reminder_days)
                reminder_id = str(uuid.uuid4())
                conn.execute(
                    """
                    INSERT INTO event_reminders
                        (id, event_id, org_id, reminder_date, sent, sent_at, created_at)
                    VALUES (?,?,?,?,?,?,?)
                    """,
                    (reminder_id, event_id, org_id, reminder_date, 0, None, now),
                )

        return self.get_event(event_id)  # type: ignore[return-value]

    def get_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM calendar_events WHERE id = ?", (event_id,)
            ).fetchone()
        return self._row(row) if row else None

    def complete_event(self, event_id: str, org_id: str) -> Dict[str, Any]:
        """Mark event as completed. If recurring, create the next occurrence."""
        event = self.get_event(event_id)
        if event is None:
            raise KeyError(f"Event '{event_id}' not found")
        if event["org_id"] != org_id:
            raise PermissionError(f"Event '{event_id}' does not belong to org '{org_id}'")

        now = _now()
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    UPDATE calendar_events
                    SET status = 'completed', completed_at = ?
                    WHERE id = ? AND org_id = ?
                    """,
                    (now, event_id, org_id),
                )

        # If recurring, create next event
        recurrence = event["recurrence"]
        if recurrence != "none" and recurrence in _RECURRENCE_DAYS:
            delta = _RECURRENCE_DAYS[recurrence]
            next_due = _add_days_to_date(event["due_date"], delta)
            self.create_event(
                org_id=org_id,
                event_name=event["event_name"],
                event_type=event["event_type"],
                framework=event["framework"],
                due_date=next_due,
                recurrence=recurrence,
                owner=event["owner"],
                priority=event["priority"],
                reminder_days=event["reminder_days"],
                notes=event["notes"],
            )

        return self.get_event(event_id)  # type: ignore[return-value]

    def get_upcoming_events(self, org_id: str, days_ahead: int = 30) -> List[Dict[str, Any]]:
        """Events due within the next `days_ahead` days with status=upcoming."""
        today = _today()
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM calendar_events
                WHERE org_id = ?
                  AND status = 'upcoming'
                  AND due_date >= ?
                  AND due_date <= date(?, ? || ' days')
                ORDER BY due_date ASC
                """,
                (org_id, today, today, f"+{days_ahead}"),
            ).fetchall()
        return [self._row(r) for r in rows]

    def get_overdue_events(self, org_id: str) -> List[Dict[str, Any]]:
        """Events past their due_date with status=upcoming."""
        today = _today()
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM calendar_events
                WHERE org_id = ?
                  AND status = 'upcoming'
                  AND due_date < ?
                ORDER BY due_date ASC
                """,
                (org_id, today),
            ).fetchall()
        return [self._row(r) for r in rows]

    def get_events_by_framework(self, org_id: str, framework: str) -> List[Dict[str, Any]]:
        """List all events for a given framework."""
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM calendar_events
                WHERE org_id = ? AND framework = ?
                ORDER BY due_date ASC
                """,
                (org_id, framework),
            ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Reminders
    # ------------------------------------------------------------------

    def mark_reminder_sent(self, reminder_id: str, org_id: str) -> Dict[str, Any]:
        """Mark a reminder as sent."""
        now = _now()
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    UPDATE event_reminders
                    SET sent = 1, sent_at = ?
                    WHERE id = ? AND org_id = ?
                    """,
                    (now, reminder_id, org_id),
                )
                row = conn.execute(
                    "SELECT * FROM event_reminders WHERE id = ?", (reminder_id,)
                ).fetchone()
        if not row:
            raise KeyError(f"Reminder '{reminder_id}' not found")
        return self._row(row)

    def get_due_reminders(self, org_id: str) -> List[Dict[str, Any]]:
        """Reminders where reminder_date <= today and not yet sent."""
        today = _today()
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM event_reminders
                WHERE org_id = ?
                  AND reminder_date <= ?
                  AND sent = 0
                ORDER BY reminder_date ASC
                """,
                (org_id, today),
            ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Views
    # ------------------------------------------------------------------

    def create_view(
        self,
        org_id: str,
        view_name: str,
        frameworks: List[str],
        event_types: List[str],
    ) -> Dict[str, Any]:
        """Create a calendar view with framework/event_type filters."""
        view_id = str(uuid.uuid4())
        now = _now()
        frameworks_str = ",".join(frameworks)
        event_types_str = ",".join(event_types)

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO calendar_views
                        (id, org_id, view_name, frameworks, event_types, created_at)
                    VALUES (?,?,?,?,?,?)
                    """,
                    (view_id, org_id, view_name, frameworks_str, event_types_str, now),
                )
                row = conn.execute(
                    "SELECT * FROM calendar_views WHERE id = ?", (view_id,)
                ).fetchone()
        return self._row(row)

    def get_view(self, view_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM calendar_views WHERE id = ?", (view_id,)
            ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def get_calendar_summary(self, org_id: str) -> Dict[str, Any]:
        """Return upcoming_count, overdue_count, completed_this_month,
        by_framework counts, by_type counts."""
        today = _today()
        # Current month prefix e.g. "2026-04"
        month_prefix = today[:7]

        with self._conn() as conn:
            upcoming_count = conn.execute(
                """
                SELECT COUNT(*) FROM calendar_events
                WHERE org_id = ? AND status = 'upcoming' AND due_date >= ?
                """,
                (org_id, today),
            ).fetchone()[0]

            overdue_count = conn.execute(
                """
                SELECT COUNT(*) FROM calendar_events
                WHERE org_id = ? AND status = 'upcoming' AND due_date < ?
                """,
                (org_id, today),
            ).fetchone()[0]

            completed_this_month = conn.execute(
                """
                SELECT COUNT(*) FROM calendar_events
                WHERE org_id = ? AND status = 'completed'
                  AND completed_at LIKE ?
                """,
                (org_id, f"{month_prefix}%"),
            ).fetchone()[0]

            fw_rows = conn.execute(
                """
                SELECT framework, COUNT(*) as cnt
                FROM calendar_events WHERE org_id = ?
                GROUP BY framework
                """,
                (org_id,),
            ).fetchall()
            by_framework = {r["framework"]: r["cnt"] for r in fw_rows}

            type_rows = conn.execute(
                """
                SELECT event_type, COUNT(*) as cnt
                FROM calendar_events WHERE org_id = ?
                GROUP BY event_type
                """,
                (org_id,),
            ).fetchall()
            by_type = {r["event_type"]: r["cnt"] for r in type_rows}

        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("CONTROL_ASSESSED", {"entity_type": "compliance_calendar_engine", "org_id": org_id, "source_engine": "compliance_calendar_engine"})
            except Exception:
                pass
        return {
            "upcoming_count": upcoming_count,
            "overdue_count": overdue_count,
            "completed_this_month": completed_this_month,
            "by_framework": by_framework,
            "by_type": by_type,
        }
