"""Tests for ReportScheduler — scheduled report delivery engine.

25+ tests covering schedule CRUD, delivery, logging, and scheduling math.
All tests use a temporary SQLite DB; no real HTTP calls are made.
"""
import sys
import os
import tempfile
import pytest
from datetime import datetime, timezone, timedelta
from pathlib import Path

sys.path.insert(0, "suite-core")

from core.report_scheduler import (
    DELIVERY_CHANNELS,
    REPORT_TYPES,
    SCHEDULE_TYPES,
    ReportScheduler,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def scheduler(tmp_path):
    """Scheduler backed by a fresh temporary SQLite database."""
    db_path = str(tmp_path / "test_report_scheduler.db")
    return ReportScheduler(db_path=db_path)


def _make_schedule(scheduler, **overrides):
    """Helper to create a valid schedule with sensible defaults."""
    defaults = dict(
        name="Daily Posture",
        report_type="posture_summary",
        schedule_type="daily",
        channel="webhook",
        destination="https://example.com/hook",
        org_id="test-org",
    )
    defaults.update(overrides)
    return scheduler.create_schedule(**defaults)


# ---------------------------------------------------------------------------
# create_schedule
# ---------------------------------------------------------------------------


def test_create_schedule_returns_dict_with_schedule_id(scheduler):
    result = _make_schedule(scheduler)
    assert isinstance(result, dict)
    assert "schedule_id" in result
    assert result["schedule_id"]


def test_create_schedule_invalid_report_type_raises(scheduler):
    with pytest.raises(ValueError, match="report_type"):
        scheduler.create_schedule(
            name="Bad",
            report_type="not_a_type",
            schedule_type="daily",
            channel="webhook",
            destination="https://example.com/hook",
        )


def test_create_schedule_invalid_schedule_type_raises(scheduler):
    with pytest.raises(ValueError, match="schedule_type"):
        scheduler.create_schedule(
            name="Bad",
            report_type="posture_summary",
            schedule_type="minutely",
            channel="webhook",
            destination="https://example.com/hook",
        )


def test_create_schedule_invalid_channel_raises(scheduler):
    with pytest.raises(ValueError, match="channel"):
        scheduler.create_schedule(
            name="Bad",
            report_type="posture_summary",
            schedule_type="daily",
            channel="carrier_pigeon",
            destination="roof",
        )


def test_create_schedule_fields_stored_correctly(scheduler):
    result = _make_schedule(
        scheduler,
        name="Weekly Vuln",
        report_type="vulnerability_summary",
        schedule_type="weekly",
        channel="slack",
        destination="https://hooks.slack.com/abc",
        org_id="sec-team",
    )
    assert result["name"] == "Weekly Vuln"
    assert result["report_type"] == "vulnerability_summary"
    assert result["schedule_type"] == "weekly"
    assert result["channel"] == "slack"
    assert result["org_id"] == "sec-team"


def test_create_schedule_with_config(scheduler):
    result = _make_schedule(scheduler, config={"format": "pdf", "filters": {"severity": "high"}})
    assert result["config"]["format"] == "pdf"
    assert result["config"]["filters"]["severity"] == "high"


def test_create_schedule_next_run_at_is_string(scheduler):
    result = _make_schedule(scheduler)
    assert isinstance(result["next_run_at"], str)
    # Should parse as ISO datetime
    dt = datetime.fromisoformat(result["next_run_at"])
    assert dt > datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# get_schedule
# ---------------------------------------------------------------------------


def test_get_schedule_returns_created_schedule(scheduler):
    created = _make_schedule(scheduler)
    fetched = scheduler.get_schedule(created["schedule_id"])
    assert fetched is not None
    assert fetched["schedule_id"] == created["schedule_id"]
    assert fetched["name"] == created["name"]


def test_get_schedule_unknown_id_returns_none(scheduler):
    result = scheduler.get_schedule("00000000-0000-0000-0000-000000000000")
    assert result is None


# ---------------------------------------------------------------------------
# update_schedule
# ---------------------------------------------------------------------------


def test_update_schedule_changes_field(scheduler):
    created = _make_schedule(scheduler, name="Original Name")
    updated = scheduler.update_schedule(created["schedule_id"], name="Updated Name")
    assert updated["name"] == "Updated Name"
    assert updated["schedule_id"] == created["schedule_id"]


def test_update_schedule_unknown_id_raises(scheduler):
    with pytest.raises(ValueError):
        scheduler.update_schedule("does-not-exist", name="Whatever")


def test_update_schedule_invalid_report_type_raises(scheduler):
    created = _make_schedule(scheduler)
    with pytest.raises(ValueError):
        scheduler.update_schedule(created["schedule_id"], report_type="bogus")


def test_update_schedule_active_flag(scheduler):
    created = _make_schedule(scheduler)
    updated = scheduler.update_schedule(created["schedule_id"], active=False)
    assert updated["active"] is False


# ---------------------------------------------------------------------------
# delete_schedule
# ---------------------------------------------------------------------------


def test_delete_schedule_returns_true_for_known(scheduler):
    created = _make_schedule(scheduler)
    result = scheduler.delete_schedule(created["schedule_id"])
    assert result is True


def test_delete_schedule_returns_false_for_unknown(scheduler):
    result = scheduler.delete_schedule("00000000-0000-0000-0000-000000000000")
    assert result is False


def test_delete_schedule_removes_from_list(scheduler):
    created = _make_schedule(scheduler)
    scheduler.delete_schedule(created["schedule_id"])
    assert scheduler.get_schedule(created["schedule_id"]) is None


# ---------------------------------------------------------------------------
# list_schedules
# ---------------------------------------------------------------------------


def test_list_schedules_returns_list(scheduler):
    _make_schedule(scheduler)
    result = scheduler.list_schedules(org_id="test-org")
    assert isinstance(result, list)
    assert len(result) >= 1


def test_list_schedules_active_only_filters_inactive(scheduler):
    created = _make_schedule(scheduler)
    scheduler.update_schedule(created["schedule_id"], active=False)
    active_list = scheduler.list_schedules(org_id="test-org", active_only=True)
    ids = [s["schedule_id"] for s in active_list]
    assert created["schedule_id"] not in ids


def test_list_schedules_active_only_false_includes_inactive(scheduler):
    created = _make_schedule(scheduler)
    scheduler.update_schedule(created["schedule_id"], active=False)
    all_list = scheduler.list_schedules(org_id="test-org", active_only=False)
    ids = [s["schedule_id"] for s in all_list]
    assert created["schedule_id"] in ids


# ---------------------------------------------------------------------------
# Multiple orgs isolation
# ---------------------------------------------------------------------------


def test_multiple_orgs_isolated_in_list(scheduler):
    _make_schedule(scheduler, org_id="org-a")
    _make_schedule(scheduler, org_id="org-b")
    org_a = scheduler.list_schedules(org_id="org-a")
    org_b = scheduler.list_schedules(org_id="org-b")
    a_ids = {s["org_id"] for s in org_a}
    b_ids = {s["org_id"] for s in org_b}
    assert a_ids == {"org-a"}
    assert b_ids == {"org-b"}


# ---------------------------------------------------------------------------
# calculate_next_run
# ---------------------------------------------------------------------------


def test_calculate_next_run_daily(scheduler):
    base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    nxt = scheduler.calculate_next_run("daily", from_time=base)
    assert nxt == base + timedelta(days=1)


def test_calculate_next_run_weekly(scheduler):
    base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    nxt = scheduler.calculate_next_run("weekly", from_time=base)
    assert nxt == base + timedelta(weeks=1)


def test_calculate_next_run_hourly(scheduler):
    base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    nxt = scheduler.calculate_next_run("hourly", from_time=base)
    assert nxt == base + timedelta(hours=1)


def test_calculate_next_run_monthly(scheduler):
    base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    nxt = scheduler.calculate_next_run("monthly", from_time=base)
    assert nxt == base + timedelta(days=30)


# ---------------------------------------------------------------------------
# deliver_report
# ---------------------------------------------------------------------------


def test_deliver_report_returns_dict_with_status(scheduler):
    created = _make_schedule(scheduler)
    result = scheduler.deliver_report(created["schedule_id"])
    assert isinstance(result, dict)
    assert "status" in result


def test_deliver_report_status_is_sent_or_failed(scheduler):
    created = _make_schedule(scheduler)
    result = scheduler.deliver_report(created["schedule_id"])
    assert result["status"] in ("sent", "failed")


def test_deliver_report_payload_size_bytes_non_negative(scheduler):
    created = _make_schedule(scheduler)
    result = scheduler.deliver_report(created["schedule_id"])
    assert isinstance(result["payload_size_bytes"], int)
    assert result["payload_size_bytes"] >= 0


def test_deliver_report_unknown_schedule_raises(scheduler):
    with pytest.raises(ValueError):
        scheduler.deliver_report("no-such-id")


def test_deliver_report_email_channel_is_sent(scheduler):
    created = _make_schedule(
        scheduler, channel="email_smtp", destination="security@example.com"
    )
    result = scheduler.deliver_report(created["schedule_id"])
    assert result["status"] == "sent"


def test_deliver_report_s3_channel_is_sent(scheduler):
    created = _make_schedule(
        scheduler, channel="s3_bucket", destination="s3://my-bucket/reports/"
    )
    result = scheduler.deliver_report(created["schedule_id"])
    assert result["status"] == "sent"


def test_deliver_report_slack_channel_result_has_schedule_id(scheduler):
    created = _make_schedule(
        scheduler, channel="slack", destination="https://hooks.slack.com/services/abc"
    )
    result = scheduler.deliver_report(created["schedule_id"])
    assert result["schedule_id"] == created["schedule_id"]


# ---------------------------------------------------------------------------
# get_delivery_log
# ---------------------------------------------------------------------------


def test_get_delivery_log_returns_list_after_deliver(scheduler):
    created = _make_schedule(scheduler)
    scheduler.deliver_report(created["schedule_id"])
    log = scheduler.get_delivery_log(schedule_id=created["schedule_id"])
    assert isinstance(log, list)
    assert len(log) >= 1


def test_get_delivery_log_entry_has_expected_keys(scheduler):
    created = _make_schedule(scheduler)
    scheduler.deliver_report(created["schedule_id"])
    log = scheduler.get_delivery_log(schedule_id=created["schedule_id"])
    entry = log[0]
    assert "schedule_id" in entry
    assert "delivered_at" in entry
    assert "status" in entry
    assert "payload_size_bytes" in entry


def test_get_delivery_log_no_filter_returns_all(scheduler):
    s1 = _make_schedule(scheduler, name="S1", org_id="org-log-1")
    s2 = _make_schedule(scheduler, name="S2", org_id="org-log-2")
    scheduler.deliver_report(s1["schedule_id"])
    scheduler.deliver_report(s2["schedule_id"])
    log = scheduler.get_delivery_log()
    schedule_ids = {e["schedule_id"] for e in log}
    assert s1["schedule_id"] in schedule_ids
    assert s2["schedule_id"] in schedule_ids


# ---------------------------------------------------------------------------
# run_due_schedules
# ---------------------------------------------------------------------------


def test_run_due_schedules_no_due_returns_empty(scheduler):
    # Create a schedule — next_run_at defaults to future
    _make_schedule(scheduler, org_id="run-due-org")
    result = scheduler.run_due_schedules(org_id="run-due-org")
    assert result == []


def test_run_due_schedules_executes_overdue_schedule(scheduler, tmp_path):
    """Force next_run_at into the past, then run_due_schedules should fire it."""
    db_path = str(tmp_path / "due_test.db")
    sched = ReportScheduler(db_path=db_path)
    created = _make_schedule(sched, org_id="due-org")

    # Manually back-date next_run_at so it's overdue
    import sqlite3
    conn = sqlite3.connect(db_path)
    past = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    conn.execute(
        "UPDATE schedules SET next_run_at = ? WHERE schedule_id = ?",
        (past, created["schedule_id"]),
    )
    conn.commit()
    conn.close()

    results = sched.run_due_schedules(org_id="due-org")
    assert len(results) == 1
    assert results[0]["schedule_id"] == created["schedule_id"]
    assert results[0]["status"] in ("sent", "failed")
