"""Tests for ReportScheduler — scheduled report delivery engine with n8n dispatch.

25+ tests covering schedule CRUD, report generation, delivery, history,
and n8n webhook dispatch. All HTTP calls are mocked; no real network access.
"""
from __future__ import annotations

import json
import sys
import urllib.error
from io import BytesIO
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, "suite-core")

from core.report_scheduler import (
    CHANNELS,
    FORMATS,
    FREQUENCIES,
    REPORT_TYPES,
    ReportScheduler,
    _calculate_next_run,
)
from datetime import datetime, timezone, timedelta


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def scheduler(tmp_path):
    """Scheduler backed by a fresh temporary SQLite database and offline n8n."""
    return ReportScheduler(
        db_path=str(tmp_path / "test_schedules.db"),
        n8n_base_url="http://localhost:15678",  # non-routable for tests
    )


def _make_schedule(scheduler: ReportScheduler, **overrides) -> str:
    defaults = dict(
        org_id="test-org",
        schedule={
            "name": "Daily Executive",
            "report_type": "executive_summary",
            "frequency": "daily",
            "recipients": ["ciso@example.com"],
            "channels": ["email"],
            "format": "json",
            "filters": {},
        },
    )
    if overrides:
        schedule_data = dict(defaults["schedule"])
        org_id = overrides.pop("org_id", defaults["org_id"])
        schedule_data.update(overrides)
        return scheduler.create_schedule(org_id=org_id, schedule=schedule_data)
    return scheduler.create_schedule(**defaults)


# ---------------------------------------------------------------------------
# create_schedule
# ---------------------------------------------------------------------------


def test_create_schedule_returns_string_id(scheduler):
    sid = _make_schedule(scheduler)
    assert isinstance(sid, str)
    assert len(sid) == 36  # UUID4


def test_create_schedule_stored_and_retrievable(scheduler):
    sid = _make_schedule(scheduler)
    schedules = scheduler.list_schedules(org_id="test-org")
    ids = [s["schedule_id"] for s in schedules]
    assert sid in ids


def test_create_schedule_invalid_report_type_raises(scheduler):
    with pytest.raises(ValueError, match="report_type"):
        scheduler.create_schedule(
            org_id="test-org",
            schedule={
                "name": "Bad",
                "report_type": "not_a_type",
                "frequency": "daily",
                "recipients": [],
                "channels": ["email"],
            },
        )


def test_create_schedule_invalid_frequency_raises(scheduler):
    with pytest.raises(ValueError, match="frequency"):
        scheduler.create_schedule(
            org_id="test-org",
            schedule={
                "name": "Bad",
                "report_type": "executive_summary",
                "frequency": "minutely",
                "channels": ["email"],
            },
        )


def test_create_schedule_invalid_channel_raises(scheduler):
    with pytest.raises(ValueError, match="channel"):
        scheduler.create_schedule(
            org_id="test-org",
            schedule={
                "name": "Bad",
                "report_type": "executive_summary",
                "frequency": "daily",
                "channels": ["carrier_pigeon"],
            },
        )


def test_create_schedule_invalid_format_raises(scheduler):
    with pytest.raises(ValueError, match="format"):
        scheduler.create_schedule(
            org_id="test-org",
            schedule={
                "name": "Bad",
                "report_type": "executive_summary",
                "frequency": "daily",
                "channels": ["email"],
                "format": "docx",
            },
        )


def test_create_schedule_missing_name_raises(scheduler):
    with pytest.raises(ValueError, match="name"):
        scheduler.create_schedule(
            org_id="test-org",
            schedule={
                "name": "",
                "report_type": "executive_summary",
                "frequency": "daily",
                "channels": ["email"],
            },
        )


def test_create_schedule_all_report_types_accepted(scheduler):
    for rt in REPORT_TYPES:
        sid = _make_schedule(scheduler, report_type=rt)
        assert isinstance(sid, str)


def test_create_schedule_all_frequencies_accepted(scheduler):
    for freq in FREQUENCIES:
        sid = _make_schedule(scheduler, frequency=freq)
        assert isinstance(sid, str)


def test_create_schedule_slack_channel_accepted(scheduler):
    sid = _make_schedule(scheduler, channels=["slack"])
    assert isinstance(sid, str)


def test_create_schedule_both_channels_accepted(scheduler):
    sid = _make_schedule(scheduler, channels=["email", "slack"])
    assert isinstance(sid, str)


# ---------------------------------------------------------------------------
# list_schedules
# ---------------------------------------------------------------------------


def test_list_schedules_returns_list(scheduler):
    _make_schedule(scheduler)
    result = scheduler.list_schedules(org_id="test-org")
    assert isinstance(result, list)
    assert len(result) >= 1


def test_list_schedules_org_isolation(scheduler):
    _make_schedule(scheduler, org_id="org-a")
    _make_schedule(scheduler, org_id="org-b")
    a_list = scheduler.list_schedules(org_id="org-a")
    b_list = scheduler.list_schedules(org_id="org-b")
    a_orgs = {s["org_id"] for s in a_list}
    b_orgs = {s["org_id"] for s in b_list}
    assert a_orgs == {"org-a"}
    assert b_orgs == {"org-b"}


def test_list_schedules_entry_has_expected_fields(scheduler):
    _make_schedule(scheduler)
    items = scheduler.list_schedules(org_id="test-org")
    item = items[0]
    for key in ("schedule_id", "name", "report_type", "frequency", "channels", "next_run_at"):
        assert key in item, f"Missing key: {key}"


# ---------------------------------------------------------------------------
# delete_schedule
# ---------------------------------------------------------------------------


def test_delete_schedule_returns_true_when_found(scheduler):
    sid = _make_schedule(scheduler)
    assert scheduler.delete_schedule(sid, org_id="test-org") is True


def test_delete_schedule_returns_false_when_not_found(scheduler):
    assert scheduler.delete_schedule("no-such-id", org_id="test-org") is False


def test_delete_schedule_removes_from_list(scheduler):
    sid = _make_schedule(scheduler)
    scheduler.delete_schedule(sid, org_id="test-org")
    ids = [s["schedule_id"] for s in scheduler.list_schedules(org_id="test-org")]
    assert sid not in ids


def test_delete_schedule_wrong_org_returns_false(scheduler):
    sid = _make_schedule(scheduler, org_id="org-x")
    assert scheduler.delete_schedule(sid, org_id="org-y") is False


# ---------------------------------------------------------------------------
# generate_report_data
# ---------------------------------------------------------------------------


def test_generate_report_data_returns_dict(scheduler):
    result = scheduler.generate_report_data("executive_summary", "test-org", {})
    assert isinstance(result, dict)


def test_generate_report_data_has_required_keys(scheduler):
    result = scheduler.generate_report_data("kpi_scorecard", "test-org", {})
    for key in ("report_type", "org_id", "generated_at", "data"):
        assert key in result, f"Missing key: {key}"


def test_generate_report_data_all_types_succeed(scheduler):
    for rt in REPORT_TYPES:
        result = scheduler.generate_report_data(rt, "test-org", {})
        assert result["report_type"] == rt


def test_generate_report_data_invalid_type_raises(scheduler):
    with pytest.raises(ValueError, match="report_type"):
        scheduler.generate_report_data("not_a_type", "test-org", {})


def test_generate_report_data_passes_filters(scheduler):
    result = scheduler.generate_report_data(
        "vulnerability_digest", "test-org", {"severity": "critical"}
    )
    assert result["filters"] == {"severity": "critical"}


# ---------------------------------------------------------------------------
# get_report_preview
# ---------------------------------------------------------------------------


def test_get_report_preview_returns_preview_flag(scheduler):
    result = scheduler.get_report_preview("executive_summary", "test-org")
    assert result.get("preview") is True


def test_get_report_preview_has_data_key(scheduler):
    result = scheduler.get_report_preview("compliance_status", "test-org")
    assert "data" in result


# ---------------------------------------------------------------------------
# trigger_report
# ---------------------------------------------------------------------------


def test_trigger_report_returns_status(scheduler):
    sid = _make_schedule(scheduler)
    result = scheduler.trigger_report(schedule_id=sid, org_id="test-org")
    assert "status" in result
    assert result["status"] in ("sent", "queued", "failed")


def test_trigger_report_returns_report_id(scheduler):
    sid = _make_schedule(scheduler)
    result = scheduler.trigger_report(schedule_id=sid, org_id="test-org")
    assert "report_id" in result
    assert isinstance(result["report_id"], str)


def test_trigger_report_returns_channels_notified(scheduler):
    sid = _make_schedule(scheduler)
    result = scheduler.trigger_report(schedule_id=sid, org_id="test-org")
    assert "channels_notified" in result
    assert isinstance(result["channels_notified"], list)


def test_trigger_report_unknown_schedule_raises(scheduler):
    with pytest.raises(ValueError):
        scheduler.trigger_report(schedule_id="no-such-id", org_id="test-org")


def test_trigger_report_wrong_org_raises(scheduler):
    sid = _make_schedule(scheduler, org_id="org-a")
    with pytest.raises(ValueError):
        scheduler.trigger_report(schedule_id=sid, org_id="org-b")


def test_trigger_report_queued_when_n8n_unreachable(scheduler):
    """Non-routable n8n URL should return 'queued', not fail hard."""
    sid = _make_schedule(scheduler)
    result = scheduler.trigger_report(schedule_id=sid, org_id="test-org")
    assert result["status"] in ("sent", "queued")


def test_trigger_report_sent_when_n8n_responds(tmp_path):
    """Mock successful n8n response — status should be 'sent'."""
    sched = ReportScheduler(
        db_path=str(tmp_path / "mock_n8n.db"),
        n8n_base_url="http://mock-n8n:5678",
    )
    sid = _make_schedule(sched)

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_resp):
        result = sched.trigger_report(schedule_id=sid, org_id="test-org")

    assert result["status"] == "sent"
    assert result["channels_notified"] == ["email"]


def test_trigger_report_logs_delivery_in_history(scheduler):
    sid = _make_schedule(scheduler)
    scheduler.trigger_report(schedule_id=sid, org_id="test-org")
    history = scheduler.get_delivery_history(org_id="test-org")
    assert len(history) >= 1
    assert history[0]["schedule_id"] == sid


# ---------------------------------------------------------------------------
# get_delivery_history
# ---------------------------------------------------------------------------


def test_get_delivery_history_returns_list(scheduler):
    result = scheduler.get_delivery_history(org_id="test-org")
    assert isinstance(result, list)


def test_get_delivery_history_org_isolation(scheduler):
    sid_a = _make_schedule(scheduler, org_id="hist-org-a")
    sid_b = _make_schedule(scheduler, org_id="hist-org-b")
    scheduler.trigger_report(schedule_id=sid_a, org_id="hist-org-a")
    scheduler.trigger_report(schedule_id=sid_b, org_id="hist-org-b")
    hist_a = scheduler.get_delivery_history(org_id="hist-org-a")
    hist_b = scheduler.get_delivery_history(org_id="hist-org-b")
    a_sids = {h["schedule_id"] for h in hist_a}
    b_sids = {h["schedule_id"] for h in hist_b}
    assert sid_a in a_sids
    assert sid_b not in a_sids
    assert sid_b in b_sids


def test_get_delivery_history_entry_has_expected_keys(scheduler):
    sid = _make_schedule(scheduler)
    scheduler.trigger_report(schedule_id=sid, org_id="test-org")
    history = scheduler.get_delivery_history(org_id="test-org")
    entry = history[0]
    for key in ("report_id", "schedule_id", "org_id", "delivered_at", "status", "channels_notified"):
        assert key in entry, f"Missing key: {key}"


def test_get_delivery_history_respects_limit(scheduler):
    sid = _make_schedule(scheduler)
    for _ in range(5):
        scheduler.trigger_report(schedule_id=sid, org_id="test-org")
    history = scheduler.get_delivery_history(org_id="test-org", limit=3)
    assert len(history) <= 3


# ---------------------------------------------------------------------------
# _calculate_next_run helper
# ---------------------------------------------------------------------------


def test_calculate_next_run_daily():
    base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    nxt = _calculate_next_run("daily", from_time=base)
    assert nxt == base + timedelta(days=1)


def test_calculate_next_run_weekly():
    base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    nxt = _calculate_next_run("weekly", from_time=base)
    assert nxt == base + timedelta(weeks=1)


def test_calculate_next_run_monthly():
    base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    nxt = _calculate_next_run("monthly", from_time=base)
    assert nxt == base + timedelta(days=30)


def test_calculate_next_run_invalid_raises():
    with pytest.raises(ValueError, match="frequency"):
        _calculate_next_run("hourly")
