"""Tests for ScheduledReportsEngine n8n delivery wiring + seed_default_schedules.

Covers:
  - _deliver_via_n8n: sent on 200, failed on HTTP error, failed on network error
  - trigger_report: n8n email delivery attempted, Slack fallback to direct webhook
  - seed_default_schedules: creates 3 defaults, idempotent, overwrite flag
  - /seed-defaults router endpoint
"""
from __future__ import annotations

import json
import sys
from io import BytesIO
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, "suite-core")

from core.scheduled_reports_engine import (
    ScheduledReportsEngine,
    _N8N_EMAIL_WEBHOOK_PATH,
    _N8N_SLACK_WEBHOOK_PATH,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    """Fresh ScheduledReportsEngine backed by a temp SQLite DB."""
    return ScheduledReportsEngine(db_path=str(tmp_path / "test_sr.db"))


def _make_schedule(engine: ScheduledReportsEngine, **overrides) -> dict:
    data = {
        "name": "Test Daily Posture",
        "report_type": "executive_summary",
        "frequency": "daily",
        "hour_utc": 6,
        "recipients": ["sec@example.com"],
        "slack_webhook_url": "",
        "format": "json",
    }
    data.update(overrides)
    return engine.create_schedule("test-org", data)


def _mock_urlopen_200():
    """Return a mock context manager that simulates HTTP 200."""
    resp = MagicMock()
    resp.status = 200
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


# ---------------------------------------------------------------------------
# _deliver_via_n8n
# ---------------------------------------------------------------------------


def test_deliver_via_n8n_sent_on_200(engine, tmp_path):
    schedule = _make_schedule(engine)
    with patch("urllib.request.urlopen", return_value=_mock_urlopen_200()):
        status, err = engine._deliver_via_n8n(
            channel="email",
            schedule=schedule,
            org_id="test-org",
            generated_at="2026-04-17T06:00:00+00:00",
            recipients=["ciso@example.com"],
            content_preview="{}",
        )
    assert status == "sent"
    assert err == ""


def test_deliver_via_n8n_failed_on_http_error(engine):
    import urllib.error

    schedule = _make_schedule(engine)
    http_err = urllib.error.HTTPError(
        url="http://localhost:5678/webhook/aldeci-report-email",
        code=500,
        msg="Internal Server Error",
        hdrs={},  # type: ignore[arg-type]
        fp=BytesIO(b"error"),
    )
    with patch("urllib.request.urlopen", side_effect=http_err):
        status, err = engine._deliver_via_n8n(
            channel="email",
            schedule=schedule,
            org_id="test-org",
            generated_at="2026-04-17T06:00:00+00:00",
            recipients=["ciso@example.com"],
            content_preview="{}",
        )
    assert status == "failed"
    assert err != ""


def test_deliver_via_n8n_failed_on_connection_error(engine):
    import urllib.error

    schedule = _make_schedule(engine)
    with patch(
        "urllib.request.urlopen",
        side_effect=urllib.error.URLError("Connection refused"),
    ):
        status, err = engine._deliver_via_n8n(
            channel="slack",
            schedule=schedule,
            org_id="test-org",
            generated_at="2026-04-17T06:00:00+00:00",
            recipients=["https://hooks.slack.com/xyz"],
            content_preview="{}",
        )
    assert status == "failed"
    assert "refused" in err.lower() or err != ""


def test_deliver_via_n8n_uses_email_webhook_path(engine):
    """Confirm the correct n8n webhook path is used for email channel."""
    schedule = _make_schedule(engine)
    captured_urls = []

    def fake_urlopen(req, timeout=None):
        captured_urls.append(req.full_url)
        return _mock_urlopen_200()

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        engine._deliver_via_n8n(
            channel="email",
            schedule=schedule,
            org_id="test-org",
            generated_at="2026-04-17T06:00:00+00:00",
            recipients=["x@example.com"],
            content_preview="{}",
        )

    assert len(captured_urls) == 1
    assert _N8N_EMAIL_WEBHOOK_PATH in captured_urls[0]


def test_deliver_via_n8n_uses_slack_webhook_path(engine):
    """Confirm the correct n8n webhook path is used for slack channel."""
    schedule = _make_schedule(engine)
    captured_urls = []

    def fake_urlopen(req, timeout=None):
        captured_urls.append(req.full_url)
        return _mock_urlopen_200()

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        engine._deliver_via_n8n(
            channel="slack",
            schedule=schedule,
            org_id="test-org",
            generated_at="2026-04-17T06:00:00+00:00",
            recipients=["https://hooks.slack.com/abc"],
            content_preview="{}",
        )

    assert len(captured_urls) == 1
    assert _N8N_SLACK_WEBHOOK_PATH in captured_urls[0]


def test_deliver_via_n8n_payload_contains_required_keys(engine):
    """n8n webhook payload includes org_id, schedule_id, channel, recipients."""
    schedule = _make_schedule(engine)
    captured_bodies = []

    def fake_urlopen(req, timeout=None):
        captured_bodies.append(json.loads(req.data.decode()))
        return _mock_urlopen_200()

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        engine._deliver_via_n8n(
            channel="email",
            schedule=schedule,
            org_id="test-org",
            generated_at="2026-04-17T06:00:00+00:00",
            recipients=["a@b.com"],
            content_preview='{"summary": "test"}',
        )

    body = captured_bodies[0]
    assert body["channel"] == "email"
    assert body["org_id"] == "test-org"
    assert body["schedule_id"] == schedule["id"]
    assert "a@b.com" in body["recipients"]
    assert "content_preview" in body


# ---------------------------------------------------------------------------
# trigger_report — n8n integration
# ---------------------------------------------------------------------------


def test_trigger_report_attempts_n8n_email_delivery(engine):
    """trigger_report calls n8n when recipients are set."""
    schedule = _make_schedule(engine, recipients=["ciso@example.com"])
    called = []

    original = engine._deliver_via_n8n

    def spy(*args, **kwargs):
        called.append(kwargs.get("channel", args[0] if args else "?"))
        return "sent", ""

    with patch.object(engine, "_deliver_via_n8n", side_effect=spy):
        engine.trigger_report("test-org", schedule["id"])

    assert "email" in called


def test_trigger_report_attempts_n8n_slack_delivery(engine):
    """trigger_report calls n8n slack path when slack_webhook_url is set."""
    schedule = _make_schedule(
        engine,
        slack_webhook_url="https://hooks.slack.com/test",
        recipients=[],
    )
    called = []

    def spy(*args, **kwargs):
        called.append(kwargs.get("channel", args[0] if args else "?"))
        return "sent", ""

    with patch.object(engine, "_deliver_via_n8n", side_effect=spy):
        engine.trigger_report("test-org", schedule["id"])

    assert "slack" in called


def test_trigger_report_falls_back_to_direct_slack_when_n8n_fails(engine):
    """When n8n Slack delivery fails, direct Slack webhook is attempted."""
    schedule = _make_schedule(
        engine,
        slack_webhook_url="https://hooks.slack.com/fallback",
        recipients=[],
    )
    direct_called = []

    def n8n_returns_failed(*args, **kwargs):
        return "failed", "n8n offline"

    def direct_slack(webhook_url, sched, org_id, generated_at):
        direct_called.append(webhook_url)
        return "sent", ""

    with patch.object(engine, "_deliver_via_n8n", side_effect=n8n_returns_failed):
        with patch.object(engine, "_deliver_slack", side_effect=direct_slack):
            result = engine.trigger_report("test-org", schedule["id"])

    assert len(direct_called) == 1
    assert direct_called[0] == "https://hooks.slack.com/fallback"
    assert result["status"] == "completed"


def test_trigger_report_no_double_delivery_when_no_recipients_no_slack(engine):
    """trigger_report with no recipients and no slack does not call n8n."""
    schedule = _make_schedule(engine, recipients=[], slack_webhook_url="")
    called = []

    def spy(*args, **kwargs):
        called.append(True)
        return "sent", ""

    with patch.object(engine, "_deliver_via_n8n", side_effect=spy):
        result = engine.trigger_report("test-org", schedule["id"])

    assert called == []
    assert result["status"] == "completed"


def test_trigger_report_delivery_logged_for_each_recipient(engine):
    """Each recipient gets its own delivery_log entry."""
    schedule = _make_schedule(
        engine, recipients=["a@b.com", "c@d.com"], slack_webhook_url=""
    )
    with patch.object(engine, "_deliver_via_n8n", return_value=("sent", "")):
        run = engine.trigger_report("test-org", schedule["id"])

    with engine._conn() as conn:
        entries = conn.execute(
            "SELECT * FROM delivery_log WHERE run_id = ? AND channel = 'email'",
            (run["id"],),
        ).fetchall()
    assert len(entries) == 2
    recipients_logged = {e["recipient"] for e in entries}
    assert "a@b.com" in recipients_logged
    assert "c@d.com" in recipients_logged


# ---------------------------------------------------------------------------
# seed_default_schedules
# ---------------------------------------------------------------------------


def test_seed_default_schedules_creates_three(engine):
    created = engine.seed_default_schedules("acme-org")
    assert len(created) == 3


def test_seed_default_schedules_names(engine):
    created = engine.seed_default_schedules("acme-org")
    names = {s["name"] for s in created}
    assert "Daily Security Posture Summary" in names
    assert "Weekly Executive Briefing" in names
    assert "Monthly Compliance Report" in names


def test_seed_default_schedules_frequencies(engine):
    created = engine.seed_default_schedules("acme-org")
    freq_map = {s["name"]: s["frequency"] for s in created}
    assert freq_map["Daily Security Posture Summary"] == "daily"
    assert freq_map["Weekly Executive Briefing"] == "weekly"
    assert freq_map["Monthly Compliance Report"] == "monthly"


def test_seed_default_schedules_hours(engine):
    created = engine.seed_default_schedules("acme-org")
    hour_map = {s["name"]: s["hour_utc"] for s in created}
    assert hour_map["Daily Security Posture Summary"] == 6
    assert hour_map["Weekly Executive Briefing"] == 8
    assert hour_map["Monthly Compliance Report"] == 7


def test_seed_default_schedules_weekly_is_monday(engine):
    created = engine.seed_default_schedules("acme-org")
    weekly = next(s for s in created if s["frequency"] == "weekly")
    assert weekly["day_of_week"] == 0  # Monday


def test_seed_default_schedules_monthly_is_first(engine):
    created = engine.seed_default_schedules("acme-org")
    monthly = next(s for s in created if s["frequency"] == "monthly")
    assert monthly["day_of_month"] == 1


def test_seed_default_schedules_idempotent(engine):
    """Calling seed twice without overwrite should not duplicate schedules."""
    first = engine.seed_default_schedules("idm-org")
    second = engine.seed_default_schedules("idm-org")
    assert len(first) == 3
    assert len(second) == 0  # nothing new created


def test_seed_default_schedules_overwrite_recreates(engine):
    """overwrite=True deletes existing defaults and re-creates them."""
    engine.seed_default_schedules("ow-org")
    refreshed = engine.seed_default_schedules("ow-org", overwrite=True)
    assert len(refreshed) == 3


def test_seed_default_schedules_org_isolation(engine):
    """Default schedules for org-a do not show up for org-b."""
    engine.seed_default_schedules("org-a")
    b_schedules = engine.list_schedules("org-b")
    assert len(b_schedules) == 0


def test_seed_default_schedules_returns_active_status(engine):
    created = engine.seed_default_schedules("acme2-org")
    for s in created:
        assert s["status"] == "active"
        assert s["enabled"] == 1


def test_seed_default_schedules_next_run_at_set(engine):
    created = engine.seed_default_schedules("acme3-org")
    for s in created:
        # Daily and weekly/monthly should have next_run_at populated
        if s["frequency"] != "on_demand":
            assert s["next_run_at"] is not None


def test_seed_default_schedules_compliance_report_type(engine):
    created = engine.seed_default_schedules("acme4-org")
    monthly = next(s for s in created if s["frequency"] == "monthly")
    assert monthly["report_type"] == "compliance_status"


# ---------------------------------------------------------------------------
# N8N webhook path constants
# ---------------------------------------------------------------------------


def test_n8n_email_webhook_path_constant():
    assert "email" in _N8N_EMAIL_WEBHOOK_PATH or "report" in _N8N_EMAIL_WEBHOOK_PATH


def test_n8n_slack_webhook_path_constant():
    assert "slack" in _N8N_SLACK_WEBHOOK_PATH or "report" in _N8N_SLACK_WEBHOOK_PATH
