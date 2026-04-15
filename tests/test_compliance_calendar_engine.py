"""Tests for ComplianceCalendarEngine.

Covers event creation, completion, recurrence, reminders, overdue detection,
views, framework filtering, and calendar summary.

Total: 35+ tests.
"""

from __future__ import annotations

import os
import sys
import pytest
from datetime import date, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'suite-core'))

from core.compliance_calendar_engine import ComplianceCalendarEngine


def _future(days: int) -> str:
    return (date.today() + timedelta(days=days)).isoformat()


def _past(days: int) -> str:
    return (date.today() - timedelta(days=days)).isoformat()


@pytest.fixture
def engine(tmp_path):
    return ComplianceCalendarEngine(db_path=str(tmp_path / "test.db"))


# ===========================================================================
# 1. Initialization
# ===========================================================================

def test_init_creates_db(tmp_path):
    db = str(tmp_path / "cc.db")
    ComplianceCalendarEngine(db_path=db)
    assert os.path.exists(db)


def test_init_idempotent(tmp_path):
    db = str(tmp_path / "cc.db")
    ComplianceCalendarEngine(db_path=db)
    ComplianceCalendarEngine(db_path=db)


# ===========================================================================
# 2. create_event
# ===========================================================================

def test_create_event_returns_dict(engine):
    e = engine.create_event("org1", "SOC2 Audit", "audit", "SOC2", _future(30))
    assert isinstance(e, dict)
    assert e["event_name"] == "SOC2 Audit"
    assert e["status"] == "upcoming"


def test_create_event_status_upcoming(engine):
    e = engine.create_event("org1", "E1", "deadline", "NIST", _future(10))
    assert e["status"] == "upcoming"


def test_create_event_invalid_event_type(engine):
    with pytest.raises(ValueError, match="event_type"):
        engine.create_event("org1", "E1", "invalid_type", "SOC2", _future(10))


def test_create_event_invalid_framework(engine):
    with pytest.raises(ValueError, match="framework"):
        engine.create_event("org1", "E1", "audit", "UNKNOWN_FW", _future(10))


def test_create_event_invalid_recurrence(engine):
    with pytest.raises(ValueError, match="recurrence"):
        engine.create_event("org1", "E1", "audit", "SOC2", _future(10), recurrence="biweekly")


def test_create_event_invalid_priority(engine):
    with pytest.raises(ValueError, match="priority"):
        engine.create_event("org1", "E1", "audit", "SOC2", _future(10), priority="urgent")


def test_create_event_creates_reminder(engine):
    e = engine.create_event("org1", "E1", "audit", "SOC2", _future(30), reminder_days=7)
    with engine._conn() as conn:
        count = conn.execute(
            "SELECT COUNT(*) FROM event_reminders WHERE event_id = ?", (e["id"],)
        ).fetchone()[0]
    assert count == 1


def test_create_event_reminder_date_is_due_minus_days(engine):
    due = _future(30)
    e = engine.create_event("org1", "E1", "audit", "SOC2", due, reminder_days=7)
    expected_reminder = (date.today() + timedelta(days=30 - 7)).isoformat()
    with engine._conn() as conn:
        row = conn.execute(
            "SELECT reminder_date FROM event_reminders WHERE event_id = ?", (e["id"],)
        ).fetchone()
    assert row["reminder_date"] == expected_reminder


def test_create_event_all_frameworks(engine):
    frameworks = ["SOC2", "ISO27001", "PCI-DSS", "HIPAA", "GDPR", "NIST", "CIS", "FedRAMP"]
    for fw in frameworks:
        e = engine.create_event("org1", f"Event {fw}", "audit", fw, _future(30))
        assert e["framework"] == fw


def test_create_event_all_event_types(engine):
    types = ["audit", "certification", "filing", "renewal", "review", "training", "assessment", "deadline"]
    for et in types:
        e = engine.create_event("org1", f"Event {et}", et, "SOC2", _future(30))
        assert e["event_type"] == et


def test_create_event_org_isolation(engine):
    engine.create_event("org1", "E1", "audit", "SOC2", _future(10))
    engine.create_event("org2", "E2", "audit", "SOC2", _future(10))
    upcoming_org1 = engine.get_upcoming_events("org1")
    upcoming_org2 = engine.get_upcoming_events("org2")
    assert all(e["org_id"] == "org1" for e in upcoming_org1)
    assert all(e["org_id"] == "org2" for e in upcoming_org2)


# ===========================================================================
# 3. complete_event
# ===========================================================================

def test_complete_event_sets_status(engine):
    e = engine.create_event("org1", "E1", "audit", "SOC2", _future(10))
    completed = engine.complete_event(e["id"], "org1")
    assert completed["status"] == "completed"
    assert completed["completed_at"] is not None


def test_complete_event_not_found_raises(engine):
    with pytest.raises(KeyError):
        engine.complete_event("nonexistent-id", "org1")


def test_complete_event_wrong_org_raises(engine):
    e = engine.create_event("org1", "E1", "audit", "SOC2", _future(10))
    with pytest.raises(PermissionError):
        engine.complete_event(e["id"], "org2")


def test_complete_event_monthly_recurrence_creates_next(engine):
    due = _future(5)
    e = engine.create_event("org1", "Monthly Review", "review", "NIST", due, recurrence="monthly")
    engine.complete_event(e["id"], "org1")
    # Should have created a new upcoming event
    upcoming = engine.get_upcoming_events("org1", days_ahead=400)
    assert len(upcoming) >= 1
    assert upcoming[0]["recurrence"] == "monthly"


def test_complete_event_annual_recurrence_creates_next(engine):
    due = _future(5)
    e = engine.create_event("org1", "Annual Cert", "certification", "ISO27001", due, recurrence="annual")
    engine.complete_event(e["id"], "org1")
    upcoming = engine.get_upcoming_events("org1", days_ahead=400)
    # Next event due ~365 days from original due
    assert len(upcoming) >= 1


def test_complete_event_no_recurrence_no_next(engine):
    e = engine.create_event("org1", "One-off", "deadline", "GDPR", _future(5), recurrence="none")
    engine.complete_event(e["id"], "org1")
    upcoming = engine.get_upcoming_events("org1")
    assert len(upcoming) == 0


# ===========================================================================
# 4. get_upcoming_events
# ===========================================================================

def test_get_upcoming_events_within_window(engine):
    engine.create_event("org1", "Near", "audit", "SOC2", _future(5))
    engine.create_event("org1", "Far", "audit", "SOC2", _future(60))
    upcoming = engine.get_upcoming_events("org1", days_ahead=30)
    names = [e["event_name"] for e in upcoming]
    assert "Near" in names
    assert "Far" not in names


def test_get_upcoming_events_excludes_completed(engine):
    e = engine.create_event("org1", "Done", "audit", "SOC2", _future(5))
    engine.complete_event(e["id"], "org1")
    upcoming = engine.get_upcoming_events("org1")
    assert all(ev["event_name"] != "Done" for ev in upcoming)


# ===========================================================================
# 5. get_overdue_events
# ===========================================================================

def test_get_overdue_events_past_due(engine):
    engine.create_event("org1", "Overdue1", "filing", "PCI-DSS", _past(5))
    overdue = engine.get_overdue_events("org1")
    assert any(e["event_name"] == "Overdue1" for e in overdue)


def test_get_overdue_events_excludes_future(engine):
    engine.create_event("org1", "Future", "audit", "SOC2", _future(10))
    overdue = engine.get_overdue_events("org1")
    assert all(e["event_name"] != "Future" for e in overdue)


def test_get_overdue_events_excludes_completed(engine):
    e = engine.create_event("org1", "WasDone", "audit", "SOC2", _past(3))
    engine.complete_event(e["id"], "org1")
    overdue = engine.get_overdue_events("org1")
    assert all(ev["event_name"] != "WasDone" for ev in overdue)


# ===========================================================================
# 6. Reminders
# ===========================================================================

def test_mark_reminder_sent(engine):
    e = engine.create_event("org1", "E1", "audit", "SOC2", _future(10), reminder_days=5)
    with engine._conn() as conn:
        rem = conn.execute(
            "SELECT id FROM event_reminders WHERE event_id = ?", (e["id"],)
        ).fetchone()
    result = engine.mark_reminder_sent(rem["id"], "org1")
    assert result["sent"] == 1
    assert result["sent_at"] is not None


def test_mark_reminder_sent_not_found(engine):
    with pytest.raises(KeyError):
        engine.mark_reminder_sent("nonexistent-id", "org1")


def test_get_due_reminders_returns_past_due(engine):
    # Create event with reminder_days=0 so reminder_date = due_date (future)
    # But create one with reminder_days > days_ahead to get a past reminder_date
    engine.create_event("org1", "E1", "audit", "SOC2", _future(3), reminder_days=10)
    # reminder_date = today + 3 - 10 = today - 7 → past → due
    due_reminders = engine.get_due_reminders("org1")
    assert len(due_reminders) >= 1


def test_get_due_reminders_excludes_sent(engine):
    e = engine.create_event("org1", "E1", "audit", "SOC2", _future(3), reminder_days=10)
    with engine._conn() as conn:
        rem = conn.execute(
            "SELECT id FROM event_reminders WHERE event_id = ?", (e["id"],)
        ).fetchone()
    engine.mark_reminder_sent(rem["id"], "org1")
    due = engine.get_due_reminders("org1")
    assert all(r["id"] != rem["id"] for r in due)


# ===========================================================================
# 7. Views
# ===========================================================================

def test_create_view_returns_dict(engine):
    v = engine.create_view("org1", "SOC2 View", ["SOC2"], ["audit", "certification"])
    assert v["view_name"] == "SOC2 View"
    assert "SOC2" in v["frameworks"]
    assert "audit" in v["event_types"]


def test_create_view_frameworks_comma_separated(engine):
    v = engine.create_view("org1", "Multi-FW", ["SOC2", "GDPR"], ["filing"])
    assert "SOC2" in v["frameworks"]
    assert "GDPR" in v["frameworks"]


# ===========================================================================
# 8. get_events_by_framework
# ===========================================================================

def test_get_events_by_framework(engine):
    engine.create_event("org1", "SOC2 Audit", "audit", "SOC2", _future(10))
    engine.create_event("org1", "GDPR Review", "review", "GDPR", _future(20))
    soc2_events = engine.get_events_by_framework("org1", "SOC2")
    assert all(e["framework"] == "SOC2" for e in soc2_events)
    assert len(soc2_events) == 1


# ===========================================================================
# 9. get_calendar_summary
# ===========================================================================

def test_get_calendar_summary_counts(engine):
    engine.create_event("org1", "Up1", "audit", "SOC2", _future(5))
    engine.create_event("org1", "Up2", "filing", "NIST", _future(15))
    engine.create_event("org1", "Overdue1", "renewal", "GDPR", _past(3))
    summary = engine.get_calendar_summary("org1")
    assert summary["upcoming_count"] == 2
    assert summary["overdue_count"] == 1


def test_get_calendar_summary_by_framework(engine):
    engine.create_event("org1", "E1", "audit", "SOC2", _future(5))
    engine.create_event("org1", "E2", "audit", "SOC2", _future(10))
    engine.create_event("org1", "E3", "audit", "GDPR", _future(10))
    summary = engine.get_calendar_summary("org1")
    assert summary["by_framework"].get("SOC2", 0) == 2
    assert summary["by_framework"].get("GDPR", 0) == 1


def test_get_calendar_summary_by_type(engine):
    engine.create_event("org1", "A1", "audit", "SOC2", _future(5))
    engine.create_event("org1", "F1", "filing", "NIST", _future(10))
    engine.create_event("org1", "F2", "filing", "GDPR", _future(15))
    summary = engine.get_calendar_summary("org1")
    assert summary["by_type"].get("audit", 0) == 1
    assert summary["by_type"].get("filing", 0) == 2


def test_get_calendar_summary_completed_this_month(engine):
    e = engine.create_event("org1", "Done", "audit", "SOC2", _future(2))
    engine.complete_event(e["id"], "org1")
    summary = engine.get_calendar_summary("org1")
    assert summary["completed_this_month"] >= 1


def test_get_calendar_summary_org_isolation(engine):
    engine.create_event("org1", "E1", "audit", "SOC2", _future(5))
    engine.create_event("org2", "E2", "audit", "SOC2", _future(5))
    engine.create_event("org2", "E3", "audit", "GDPR", _past(3))
    s1 = engine.get_calendar_summary("org1")
    s2 = engine.get_calendar_summary("org2")
    assert s1["upcoming_count"] == 1
    assert s2["upcoming_count"] == 1
    assert s2["overdue_count"] == 1
