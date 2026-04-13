"""
Tests for compliance_calendar — 30+ tests covering all methods and edge cases.
"""
from __future__ import annotations

import os
import sys
import tempfile
from datetime import date, timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))
sys.path.insert(0, os.path.join(ROOT, "suite-api"))

import pytest

from core.compliance_calendar import (
    CalendarEvent,
    ComplianceCalendar,
    EventStatus,
    EventType,
    _FRAMEWORK_EVENTS,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_calendar(tmp_path):
    """Return a ComplianceCalendar backed by a temp SQLite file."""
    db_file = str(tmp_path / "test_cal.db")
    return ComplianceCalendar(db_path=db_file)


def _event(
    title: str = "Test Event",
    event_type: EventType = EventType.AUDIT,
    framework: str = "SOC2",
    due_date: date = None,
    org_id: str = "org-1",
    recurring: bool = False,
    recurrence_interval_days: int = None,
    status: EventStatus = EventStatus.UPCOMING,
    reminder_days: int = 7,
) -> CalendarEvent:
    return CalendarEvent(
        title=title,
        event_type=event_type,
        framework=framework,
        due_date=due_date or (date.today() + timedelta(days=10)),
        org_id=org_id,
        recurring=recurring,
        recurrence_interval_days=recurrence_interval_days,
        status=status,
        reminder_days=reminder_days,
    )


# ---------------------------------------------------------------------------
# EventType enum
# ---------------------------------------------------------------------------


class TestEventTypeEnum:
    def test_all_values_exist(self):
        expected = {
            "audit", "assessment", "certification_renewal", "evidence_due",
            "training_due", "policy_review", "pen_test", "risk_review", "board_report",
        }
        actual = {e.value for e in EventType}
        assert expected == actual

    def test_string_comparison(self):
        assert EventType.AUDIT == "audit"
        assert EventType.PEN_TEST == "pen_test"
        assert EventType.BOARD_REPORT == "board_report"
        assert EventType.CERTIFICATION_RENEWAL == "certification_renewal"

    def test_nine_event_types(self):
        assert len(EventType) == 9


# ---------------------------------------------------------------------------
# EventStatus enum
# ---------------------------------------------------------------------------


class TestEventStatusEnum:
    def test_three_statuses(self):
        assert len(EventStatus) == 3

    def test_values(self):
        assert EventStatus.UPCOMING == "upcoming"
        assert EventStatus.OVERDUE == "overdue"
        assert EventStatus.COMPLETED == "completed"


# ---------------------------------------------------------------------------
# CalendarEvent model
# ---------------------------------------------------------------------------


class TestCalendarEventModel:
    def test_default_id_generated(self):
        ev = _event()
        assert ev.id
        assert len(ev.id) == 36  # UUID4

    def test_to_dict_keys(self):
        ev = _event()
        d = ev.to_dict()
        for key in ("id", "title", "event_type", "framework", "due_date",
                    "assignee", "status", "reminder_days", "recurring",
                    "recurrence_interval_days", "org_id"):
            assert key in d

    def test_to_dict_due_date_is_isoformat(self):
        ev = _event(due_date=date(2026, 6, 15))
        assert ev.to_dict()["due_date"] == "2026-06-15"

    def test_default_status_upcoming(self):
        ev = _event()
        assert ev.status == EventStatus.UPCOMING

    def test_recurring_defaults(self):
        ev = _event()
        assert ev.recurring is False
        assert ev.recurrence_interval_days is None

    def test_org_id_default(self):
        ev = CalendarEvent(
            title="X", event_type=EventType.AUDIT, framework="SOC2",
            due_date=date.today()
        )
        assert ev.org_id == "default"


# ---------------------------------------------------------------------------
# ComplianceCalendar — add_event / list_events
# ---------------------------------------------------------------------------


class TestAddAndListEvents:
    def test_add_event_returns_event(self, tmp_calendar):
        ev = _event()
        result = tmp_calendar.add_event(ev)
        assert result.id == ev.id

    def test_list_events_correct_month(self, tmp_calendar):
        ev = _event(due_date=date(2026, 6, 15))
        tmp_calendar.add_event(ev)
        results = tmp_calendar.list_events("org-1", month=6, year=2026)
        assert len(results) == 1
        assert results[0].id == ev.id

    def test_list_events_excludes_other_months(self, tmp_calendar):
        tmp_calendar.add_event(_event(due_date=date(2026, 5, 10)))
        results = tmp_calendar.list_events("org-1", month=6, year=2026)
        assert len(results) == 0

    def test_list_events_excludes_other_orgs(self, tmp_calendar):
        tmp_calendar.add_event(_event(due_date=date(2026, 6, 1), org_id="org-A"))
        results = tmp_calendar.list_events("org-B", month=6, year=2026)
        assert len(results) == 0

    def test_list_events_sorted_by_due_date(self, tmp_calendar):
        tmp_calendar.add_event(_event(due_date=date(2026, 6, 20)))
        tmp_calendar.add_event(_event(due_date=date(2026, 6, 5)))
        tmp_calendar.add_event(_event(due_date=date(2026, 6, 12)))
        results = tmp_calendar.list_events("org-1", month=6, year=2026)
        dates = [r.due_date for r in results]
        assert dates == sorted(dates)

    def test_list_events_december_boundary(self, tmp_calendar):
        # Dec 31 should be in December results, Jan 1 should not
        tmp_calendar.add_event(_event(due_date=date(2026, 12, 31), org_id="org-dec"))
        tmp_calendar.add_event(_event(due_date=date(2027, 1, 1), org_id="org-dec"))
        results = tmp_calendar.list_events("org-dec", month=12, year=2026)
        assert len(results) == 1
        assert results[0].due_date == date(2026, 12, 31)


# ---------------------------------------------------------------------------
# get_upcoming
# ---------------------------------------------------------------------------


class TestGetUpcoming:
    def test_returns_events_within_window(self, tmp_calendar):
        ev = _event(due_date=date.today() + timedelta(days=5))
        tmp_calendar.add_event(ev)
        results = tmp_calendar.get_upcoming("org-1", days=10)
        assert any(r.id == ev.id for r in results)

    def test_excludes_events_beyond_window(self, tmp_calendar):
        ev = _event(due_date=date.today() + timedelta(days=60))
        tmp_calendar.add_event(ev)
        results = tmp_calendar.get_upcoming("org-1", days=30)
        assert not any(r.id == ev.id for r in results)

    def test_excludes_past_due(self, tmp_calendar):
        # Past-due events should not appear in upcoming
        ev = _event(due_date=date.today() - timedelta(days=5))
        tmp_calendar.add_event(ev)
        results = tmp_calendar.get_upcoming("org-1", days=30)
        assert not any(r.id == ev.id for r in results)

    def test_org_isolation(self, tmp_calendar):
        tmp_calendar.add_event(_event(due_date=date.today() + timedelta(days=3), org_id="org-X"))
        results = tmp_calendar.get_upcoming("org-Y", days=30)
        assert len(results) == 0


# ---------------------------------------------------------------------------
# get_overdue
# ---------------------------------------------------------------------------


class TestGetOverdue:
    def test_past_due_event_appears(self, tmp_calendar):
        ev = _event(due_date=date.today() - timedelta(days=2))
        tmp_calendar.add_event(ev)
        results = tmp_calendar.get_overdue("org-1")
        assert any(r.id == ev.id for r in results)

    def test_future_event_not_overdue(self, tmp_calendar):
        ev = _event(due_date=date.today() + timedelta(days=5))
        tmp_calendar.add_event(ev)
        results = tmp_calendar.get_overdue("org-1")
        assert not any(r.id == ev.id for r in results)

    def test_completed_not_overdue(self, tmp_calendar):
        ev = _event(due_date=date.today() - timedelta(days=2))
        tmp_calendar.add_event(ev)
        tmp_calendar.complete_event(ev.id)
        results = tmp_calendar.get_overdue("org-1")
        assert not any(r.id == ev.id for r in results)


# ---------------------------------------------------------------------------
# complete_event
# ---------------------------------------------------------------------------


class TestCompleteEvent:
    def test_marks_completed(self, tmp_calendar):
        ev = _event()
        tmp_calendar.add_event(ev)
        result = tmp_calendar.complete_event(ev.id)
        assert result is not None
        assert result.status == EventStatus.COMPLETED

    def test_returns_none_for_missing_id(self, tmp_calendar):
        result = tmp_calendar.complete_event("nonexistent-id")
        assert result is None

    def test_recurring_spawns_next_occurrence(self, tmp_calendar):
        ev = _event(
            due_date=date(2026, 6, 1),
            recurring=True,
            recurrence_interval_days=90,
        )
        tmp_calendar.add_event(ev)
        tmp_calendar.complete_event(ev.id)
        # Next occurrence should be 90 days later
        next_due = date(2026, 6, 1) + timedelta(days=90)
        events = tmp_calendar.list_events("org-1", month=next_due.month, year=next_due.year)
        assert any(e.due_date == next_due for e in events)

    def test_non_recurring_does_not_spawn(self, tmp_calendar):
        ev = _event(due_date=date(2026, 6, 1), recurring=False)
        tmp_calendar.add_event(ev)
        before_count = len(tmp_calendar.list_events("org-1", month=9, year=2026))
        tmp_calendar.complete_event(ev.id)
        after_count = len(tmp_calendar.list_events("org-1", month=9, year=2026))
        assert before_count == after_count


# ---------------------------------------------------------------------------
# get_calendar_view
# ---------------------------------------------------------------------------


class TestGetCalendarView:
    def test_returns_correct_structure(self, tmp_calendar):
        view = tmp_calendar.get_calendar_view("org-1", year=2026, month=6)
        assert "org_id" in view
        assert "year" in view
        assert "month" in view
        assert "total_events" in view
        assert "days" in view

    def test_groups_by_day(self, tmp_calendar):
        tmp_calendar.add_event(_event(due_date=date(2026, 6, 10)))
        tmp_calendar.add_event(_event(due_date=date(2026, 6, 10)))
        tmp_calendar.add_event(_event(due_date=date(2026, 6, 20)))
        view = tmp_calendar.get_calendar_view("org-1", year=2026, month=6)
        assert len(view["days"]["2026-06-10"]) == 2
        assert len(view["days"]["2026-06-20"]) == 1
        assert view["total_events"] == 3


# ---------------------------------------------------------------------------
# auto_generate_events
# ---------------------------------------------------------------------------


class TestAutoGenerateEvents:
    def test_generates_soc2_events(self, tmp_calendar):
        events = tmp_calendar.auto_generate_events("org-1", "SOC2")
        assert len(events) == len(_FRAMEWORK_EVENTS["SOC2"])
        assert all(e.framework == "SOC2" for e in events)
        assert all(e.recurring is True for e in events)

    def test_generates_gdpr_events(self, tmp_calendar):
        events = tmp_calendar.auto_generate_events("org-2", "GDPR")
        assert len(events) == len(_FRAMEWORK_EVENTS["GDPR"])
        assert all(e.org_id == "org-2" for e in events)

    def test_all_7_frameworks_have_templates(self):
        for fw in ("SOC2", "PCI-DSS", "HIPAA", "ISO27001", "NIST-CSF", "CIS", "GDPR"):
            assert fw in _FRAMEWORK_EVENTS
            assert len(_FRAMEWORK_EVENTS[fw]) >= 4

    def test_unknown_framework_returns_empty(self, tmp_calendar):
        events = tmp_calendar.auto_generate_events("org-1", "UNKNOWN-FW")
        assert events == []

    def test_events_have_future_due_dates(self, tmp_calendar):
        events = tmp_calendar.auto_generate_events("org-1", "HIPAA")
        today = date.today()
        assert all(e.due_date > today for e in events)

    def test_events_persisted_to_db(self, tmp_calendar):
        events = tmp_calendar.auto_generate_events("org-3", "CIS")
        # Verify they appear in stats
        stats = tmp_calendar.get_calendar_stats("org-3")
        assert stats["upcoming"] >= len(events)


# ---------------------------------------------------------------------------
# get_calendar_stats
# ---------------------------------------------------------------------------


class TestGetCalendarStats:
    def test_empty_org_returns_zeros(self, tmp_calendar):
        stats = tmp_calendar.get_calendar_stats("org-empty")
        assert stats["upcoming"] == 0
        assert stats["overdue"] == 0
        assert stats["completed"] == 0
        assert stats["total"] == 0

    def test_counts_are_accurate(self, tmp_calendar):
        org = "org-stats"
        # 2 upcoming
        tmp_calendar.add_event(_event(due_date=date.today() + timedelta(days=5), org_id=org))
        tmp_calendar.add_event(_event(due_date=date.today() + timedelta(days=10), org_id=org))
        # 1 overdue (past due)
        tmp_calendar.add_event(_event(due_date=date.today() - timedelta(days=3), org_id=org))
        stats = tmp_calendar.get_calendar_stats(org)
        assert stats["overdue"] == 1
        assert stats["upcoming"] == 2
        assert stats["total"] == 3

    def test_next_event_is_nearest(self, tmp_calendar):
        org = "org-next"
        near = _event(due_date=date.today() + timedelta(days=3), org_id=org, title="Near")
        far = _event(due_date=date.today() + timedelta(days=30), org_id=org, title="Far")
        tmp_calendar.add_event(far)
        tmp_calendar.add_event(near)
        stats = tmp_calendar.get_calendar_stats(org)
        assert stats["next_event"]["title"] == "Near"

    def test_completed_counted_correctly(self, tmp_calendar):
        org = "org-comp"
        ev = _event(due_date=date.today() + timedelta(days=5), org_id=org)
        tmp_calendar.add_event(ev)
        tmp_calendar.complete_event(ev.id)
        stats = tmp_calendar.get_calendar_stats(org)
        assert stats["completed"] == 1
