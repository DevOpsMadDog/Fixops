"""
Compliance calendar — track compliance deadlines, events, and activities.

Supports all 7 ALDECI frameworks: SOC2, PCI-DSS, HIPAA, ISO27001, NIST-CSF, CIS, GDPR.
SQLite-backed with recurring event generation and overdue detection.
"""
from __future__ import annotations

import sqlite3
import uuid
from datetime import date, datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class EventType(str, Enum):
    AUDIT = "audit"
    ASSESSMENT = "assessment"
    CERTIFICATION_RENEWAL = "certification_renewal"
    EVIDENCE_DUE = "evidence_due"
    TRAINING_DUE = "training_due"
    POLICY_REVIEW = "policy_review"
    PEN_TEST = "pen_test"
    RISK_REVIEW = "risk_review"
    BOARD_REPORT = "board_report"


class EventStatus(str, Enum):
    UPCOMING = "upcoming"
    OVERDUE = "overdue"
    COMPLETED = "completed"


# ---------------------------------------------------------------------------
# Pydantic model
# ---------------------------------------------------------------------------


class CalendarEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    event_type: EventType
    framework: str
    due_date: date
    assignee: Optional[str] = None
    status: EventStatus = EventStatus.UPCOMING
    reminder_days: int = 7
    recurring: bool = False
    recurrence_interval_days: Optional[int] = None
    org_id: str = "default"

    model_config = {"use_enum_values": True}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "event_type": self.event_type,
            "framework": self.framework,
            "due_date": self.due_date.isoformat() if isinstance(self.due_date, date) else self.due_date,
            "assignee": self.assignee,
            "status": self.status,
            "reminder_days": self.reminder_days,
            "recurring": self.recurring,
            "recurrence_interval_days": self.recurrence_interval_days,
            "org_id": self.org_id,
        }


# ---------------------------------------------------------------------------
# Framework recurring event templates
# ---------------------------------------------------------------------------

# Each entry: (title, event_type, recurrence_interval_days, reminder_days)
_FRAMEWORK_EVENTS: Dict[str, List[tuple]] = {
    "SOC2": [
        ("SOC2 Annual Audit", EventType.AUDIT, 365, 30),
        ("SOC2 Evidence Collection", EventType.EVIDENCE_DUE, 90, 14),
        ("SOC2 Security Training", EventType.TRAINING_DUE, 365, 30),
        ("SOC2 Policy Review", EventType.POLICY_REVIEW, 180, 14),
        ("SOC2 Risk Assessment", EventType.RISK_REVIEW, 365, 30),
        ("SOC2 Penetration Test", EventType.PEN_TEST, 365, 30),
    ],
    "PCI-DSS": [
        ("PCI-DSS Annual Assessment", EventType.ASSESSMENT, 365, 60),
        ("PCI-DSS Quarterly Scan", EventType.EVIDENCE_DUE, 90, 14),
        ("PCI-DSS Penetration Test", EventType.PEN_TEST, 365, 45),
        ("PCI-DSS Security Awareness Training", EventType.TRAINING_DUE, 365, 30),
        ("PCI-DSS Policy Review", EventType.POLICY_REVIEW, 365, 30),
        ("PCI-DSS Board Report", EventType.BOARD_REPORT, 90, 7),
    ],
    "HIPAA": [
        ("HIPAA Risk Assessment", EventType.RISK_REVIEW, 365, 45),
        ("HIPAA Security Training", EventType.TRAINING_DUE, 365, 30),
        ("HIPAA Policy Review", EventType.POLICY_REVIEW, 365, 30),
        ("HIPAA Audit Log Review", EventType.AUDIT, 90, 7),
        ("HIPAA Business Associate Review", EventType.ASSESSMENT, 365, 30),
        ("HIPAA Breach Assessment", EventType.EVIDENCE_DUE, 180, 14),
    ],
    "ISO27001": [
        ("ISO27001 Internal Audit", EventType.AUDIT, 365, 45),
        ("ISO27001 Management Review", EventType.BOARD_REPORT, 365, 30),
        ("ISO27001 Certification Renewal", EventType.CERTIFICATION_RENEWAL, 1095, 90),
        ("ISO27001 Risk Assessment", EventType.RISK_REVIEW, 365, 45),
        ("ISO27001 Security Awareness Training", EventType.TRAINING_DUE, 365, 30),
        ("ISO27001 Policy Review", EventType.POLICY_REVIEW, 365, 30),
    ],
    "NIST-CSF": [
        ("NIST-CSF Risk Assessment", EventType.RISK_REVIEW, 365, 45),
        ("NIST-CSF Security Assessment", EventType.ASSESSMENT, 365, 45),
        ("NIST-CSF Penetration Test", EventType.PEN_TEST, 365, 30),
        ("NIST-CSF Training", EventType.TRAINING_DUE, 365, 30),
        ("NIST-CSF Policy Review", EventType.POLICY_REVIEW, 180, 14),
        ("NIST-CSF Executive Briefing", EventType.BOARD_REPORT, 180, 14),
    ],
    "CIS": [
        ("CIS Controls Assessment", EventType.ASSESSMENT, 365, 30),
        ("CIS Benchmark Scan", EventType.EVIDENCE_DUE, 90, 7),
        ("CIS Security Training", EventType.TRAINING_DUE, 365, 30),
        ("CIS Policy Review", EventType.POLICY_REVIEW, 365, 30),
        ("CIS Penetration Test", EventType.PEN_TEST, 365, 30),
        ("CIS Risk Review", EventType.RISK_REVIEW, 180, 14),
    ],
    "GDPR": [
        ("GDPR Data Protection Impact Assessment", EventType.ASSESSMENT, 365, 45),
        ("GDPR Privacy Training", EventType.TRAINING_DUE, 365, 30),
        ("GDPR Policy Review", EventType.POLICY_REVIEW, 365, 30),
        ("GDPR Data Audit", EventType.AUDIT, 365, 30),
        ("GDPR Board Report", EventType.BOARD_REPORT, 180, 14),
        ("GDPR Vendor Risk Review", EventType.RISK_REVIEW, 365, 30),
    ],
}


# ---------------------------------------------------------------------------
# ComplianceCalendar
# ---------------------------------------------------------------------------


class ComplianceCalendar:
    """SQLite-backed compliance calendar."""

    def __init__(self, db_path: str = "data/compliance_calendar.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_tables(self) -> None:
        conn = self._get_connection()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS calendar_events (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    framework TEXT NOT NULL,
                    due_date TEXT NOT NULL,
                    assignee TEXT,
                    status TEXT NOT NULL DEFAULT 'upcoming',
                    reminder_days INTEGER NOT NULL DEFAULT 7,
                    recurring INTEGER NOT NULL DEFAULT 0,
                    recurrence_interval_days INTEGER,
                    org_id TEXT NOT NULL DEFAULT 'default'
                );

                CREATE INDEX IF NOT EXISTS idx_cal_org_id ON calendar_events(org_id);
                CREATE INDEX IF NOT EXISTS idx_cal_due_date ON calendar_events(due_date);
                CREATE INDEX IF NOT EXISTS idx_cal_status ON calendar_events(status);
                CREATE INDEX IF NOT EXISTS idx_cal_framework ON calendar_events(framework);
                """
            )
            conn.commit()
        finally:
            conn.close()

    def _row_to_event(self, row: sqlite3.Row) -> CalendarEvent:
        return CalendarEvent(
            id=row["id"],
            title=row["title"],
            event_type=row["event_type"],
            framework=row["framework"],
            due_date=date.fromisoformat(row["due_date"]),
            assignee=row["assignee"],
            status=row["status"],
            reminder_days=row["reminder_days"],
            recurring=bool(row["recurring"]),
            recurrence_interval_days=row["recurrence_interval_days"],
            org_id=row["org_id"],
        )

    def _today(self) -> date:
        return datetime.now(timezone.utc).date()

    def _refresh_statuses(self, org_id: str) -> None:
        """Mark upcoming events as overdue if past due_date."""
        today = self._today().isoformat()
        conn = self._get_connection()
        try:
            conn.execute(
                """
                UPDATE calendar_events
                SET status = 'overdue'
                WHERE org_id = ? AND status = 'upcoming' AND due_date < ?
                """,
                (org_id, today),
            )
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_event(self, event: CalendarEvent) -> CalendarEvent:
        """Create a compliance event."""
        conn = self._get_connection()
        try:
            conn.execute(
                """
                INSERT INTO calendar_events
                    (id, title, event_type, framework, due_date, assignee,
                     status, reminder_days, recurring, recurrence_interval_days, org_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.id,
                    event.title,
                    event.event_type,
                    event.framework,
                    event.due_date.isoformat() if isinstance(event.due_date, date) else event.due_date,
                    event.assignee,
                    event.status,
                    event.reminder_days,
                    1 if event.recurring else 0,
                    event.recurrence_interval_days,
                    event.org_id,
                ),
            )
            conn.commit()
        finally:
            conn.close()
        return event

    def list_events(self, org_id: str, month: int, year: int) -> List[CalendarEvent]:
        """Return all events for org in the given month/year."""
        self._refresh_statuses(org_id)
        # Build date range for the month
        start = date(year, month, 1)
        if month == 12:
            end = date(year + 1, 1, 1)
        else:
            end = date(year, month + 1, 1)

        conn = self._get_connection()
        try:
            rows = conn.execute(
                """
                SELECT * FROM calendar_events
                WHERE org_id = ?
                  AND due_date >= ?
                  AND due_date < ?
                ORDER BY due_date ASC
                """,
                (org_id, start.isoformat(), end.isoformat()),
            ).fetchall()
            return [self._row_to_event(r) for r in rows]
        finally:
            conn.close()

    def get_upcoming(self, org_id: str, days: int = 30) -> List[CalendarEvent]:
        """Return events due within the next N days."""
        self._refresh_statuses(org_id)
        today = self._today()
        cutoff = today + timedelta(days=days)
        conn = self._get_connection()
        try:
            rows = conn.execute(
                """
                SELECT * FROM calendar_events
                WHERE org_id = ?
                  AND status = 'upcoming'
                  AND due_date >= ?
                  AND due_date <= ?
                ORDER BY due_date ASC
                """,
                (org_id, today.isoformat(), cutoff.isoformat()),
            ).fetchall()
            return [self._row_to_event(r) for r in rows]
        finally:
            conn.close()

    def get_overdue(self, org_id: str) -> List[CalendarEvent]:
        """Return all past-due events."""
        self._refresh_statuses(org_id)
        conn = self._get_connection()
        try:
            rows = conn.execute(
                """
                SELECT * FROM calendar_events
                WHERE org_id = ? AND status = 'overdue'
                ORDER BY due_date ASC
                """,
                (org_id,),
            ).fetchall()
            return [self._row_to_event(r) for r in rows]
        finally:
            conn.close()

    def complete_event(self, event_id: str) -> Optional[CalendarEvent]:
        """Mark an event as completed; if recurring, spawn the next occurrence."""
        conn = self._get_connection()
        try:
            conn.execute(
                "UPDATE calendar_events SET status = 'completed' WHERE id = ?",
                (event_id,),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM calendar_events WHERE id = ?", (event_id,)
            ).fetchone()
            if not row:
                return None
            event = self._row_to_event(row)
        finally:
            conn.close()

        # Spawn next recurrence
        if event.recurring and event.recurrence_interval_days:
            next_due = event.due_date + timedelta(days=event.recurrence_interval_days)
            next_event = CalendarEvent(
                title=event.title,
                event_type=event.event_type,
                framework=event.framework,
                due_date=next_due,
                assignee=event.assignee,
                status=EventStatus.UPCOMING,
                reminder_days=event.reminder_days,
                recurring=event.recurring,
                recurrence_interval_days=event.recurrence_interval_days,
                org_id=event.org_id,
            )
            self.add_event(next_event)

        return event

    def get_calendar_view(self, org_id: str, year: int, month: int) -> Dict[str, Any]:
        """Full month calendar view grouped by day."""
        events = self.list_events(org_id, month, year)
        # Build a dict: day -> [events]
        by_day: Dict[str, List[Dict[str, Any]]] = {}
        for ev in events:
            day_key = ev.due_date.isoformat() if isinstance(ev.due_date, date) else ev.due_date
            by_day.setdefault(day_key, []).append(ev.to_dict())

        return {
            "org_id": org_id,
            "year": year,
            "month": month,
            "total_events": len(events),
            "days": by_day,
        }

    def auto_generate_events(self, org_id: str, framework: str) -> List[CalendarEvent]:
        """Create recurring events based on framework requirements."""
        templates = _FRAMEWORK_EVENTS.get(framework.upper(), _FRAMEWORK_EVENTS.get(framework, []))
        if not templates:
            return []

        today = self._today()
        created: List[CalendarEvent] = []
        for title, event_type, interval_days, reminder_days in templates:
            due = today + timedelta(days=interval_days)
            event = CalendarEvent(
                title=title,
                event_type=event_type,
                framework=framework,
                due_date=due,
                status=EventStatus.UPCOMING,
                reminder_days=reminder_days,
                recurring=True,
                recurrence_interval_days=interval_days,
                org_id=org_id,
            )
            self.add_event(event)
            created.append(event)
        return created

    def get_calendar_stats(self, org_id: str) -> Dict[str, Any]:
        """Return upcoming, overdue, and completed counts."""
        self._refresh_statuses(org_id)
        conn = self._get_connection()
        try:
            rows = conn.execute(
                """
                SELECT status, COUNT(*) as cnt
                FROM calendar_events
                WHERE org_id = ?
                GROUP BY status
                """,
                (org_id,),
            ).fetchall()
        finally:
            conn.close()

        counts: Dict[str, int] = {"upcoming": 0, "overdue": 0, "completed": 0}
        for row in rows:
            if row["status"] in counts:
                counts[row["status"]] = row["cnt"]

        # Next upcoming event
        upcoming_events = self.get_upcoming(org_id, days=365)
        next_event: Optional[Dict[str, Any]] = None
        if upcoming_events:
            next_event = upcoming_events[0].to_dict()

        return {
            "org_id": org_id,
            "upcoming": counts["upcoming"],
            "overdue": counts["overdue"],
            "completed": counts["completed"],
            "total": sum(counts.values()),
            "next_event": next_event,
        }
