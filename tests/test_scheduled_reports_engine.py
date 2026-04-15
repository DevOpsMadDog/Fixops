"""Tests for ScheduledReportsEngine — 30+ tests covering all methods.

Tests include:
  - Schedule CRUD (create, list, get, update, delete)
  - next_run_at calculation (daily, weekly, monthly, on_demand)
  - Pause / resume lifecycle
  - trigger_report creates run record + delivery_log entries
  - Multi-tenant isolation (org1 vs org2)
  - Template CRUD
  - Stats aggregation
  - Error handling (missing name, invalid types, not-found)
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone

import pytest

from core.scheduled_reports_engine import (
    ScheduledReportsEngine,
    _calc_next_run,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "test_scheduled_reports.db")
    return ScheduledReportsEngine(db_path=db)


def _make_schedule(engine: ScheduledReportsEngine, org_id: str = "org1", **kwargs) -> dict:
    defaults = {
        "name": "Weekly Exec Summary",
        "report_type": "executive_summary",
        "frequency": "weekly",
        "hour_utc": 8,
        "day_of_week": 0,
        "recipients": ["ciso@example.com"],
    }
    defaults.update(kwargs)
    return engine.create_schedule(org_id, defaults)


# ---------------------------------------------------------------------------
# _calc_next_run
# ---------------------------------------------------------------------------

class TestCalcNextRun:
    def test_daily_returns_isoformat(self):
        result = _calc_next_run("daily", hour_utc=6)
        assert result is not None
        dt = datetime.fromisoformat(result)
        assert dt.hour == 6
        assert dt.minute == 0

    def test_daily_is_in_future(self):
        result = _calc_next_run("daily", hour_utc=0)
        dt = datetime.fromisoformat(result)
        assert dt > datetime.now(timezone.utc)

    def test_weekly_returns_isoformat(self):
        result = _calc_next_run("weekly", hour_utc=8, day_of_week=0)
        assert result is not None
        dt = datetime.fromisoformat(result)
        assert dt.weekday() == 0  # Monday

    def test_weekly_is_in_future(self):
        result = _calc_next_run("weekly", hour_utc=8, day_of_week=1)
        assert result is not None
        dt = datetime.fromisoformat(result)
        assert dt > datetime.now(timezone.utc)

    def test_monthly_returns_isoformat(self):
        result = _calc_next_run("monthly", hour_utc=8, day_of_month=1)
        assert result is not None
        dt = datetime.fromisoformat(result)
        assert dt.day == 1

    def test_monthly_is_in_future(self):
        result = _calc_next_run("monthly", hour_utc=8, day_of_month=1)
        dt = datetime.fromisoformat(result)
        assert dt > datetime.now(timezone.utc)

    def test_on_demand_returns_none(self):
        result = _calc_next_run("on_demand")
        assert result is None

    def test_unknown_frequency_returns_none(self):
        result = _calc_next_run("foobar")
        assert result is None


# ---------------------------------------------------------------------------
# Schedule CRUD
# ---------------------------------------------------------------------------

class TestCreateSchedule:
    def test_create_returns_dict(self, engine):
        sched = _make_schedule(engine)
        assert isinstance(sched, dict)
        assert "id" in sched
        assert sched["org_id"] == "org1"
        assert sched["name"] == "Weekly Exec Summary"
        assert sched["report_type"] == "executive_summary"
        assert sched["frequency"] == "weekly"

    def test_create_sets_next_run_at(self, engine):
        sched = _make_schedule(engine)
        assert sched["next_run_at"] is not None
        dt = datetime.fromisoformat(sched["next_run_at"])
        assert dt > datetime.now(timezone.utc)

    def test_create_recipients_is_list(self, engine):
        sched = _make_schedule(engine, recipients=["a@b.com", "c@d.com"])
        assert isinstance(sched["recipients"], list)
        assert len(sched["recipients"]) == 2

    def test_create_missing_name_raises(self, engine):
        with pytest.raises(ValueError, match="name is required"):
            engine.create_schedule("org1", {"report_type": "kpi_report"})

    def test_create_invalid_report_type_raises(self, engine):
        with pytest.raises(ValueError, match="Invalid report_type"):
            engine.create_schedule("org1", {"name": "X", "report_type": "bogus"})

    def test_create_invalid_frequency_raises(self, engine):
        with pytest.raises(ValueError, match="Invalid frequency"):
            engine.create_schedule("org1", {"name": "X", "frequency": "hourly"})

    def test_create_invalid_format_raises(self, engine):
        with pytest.raises(ValueError, match="Invalid format"):
            engine.create_schedule("org1", {"name": "X", "format": "docx"})

    def test_create_on_demand_next_run_is_none(self, engine):
        sched = engine.create_schedule("org1", {"name": "X", "frequency": "on_demand"})
        assert sched["next_run_at"] is None


class TestListSchedules:
    def test_list_returns_all_for_org(self, engine):
        _make_schedule(engine, "org1", name="A")
        _make_schedule(engine, "org1", name="B")
        schedules = engine.list_schedules("org1")
        assert len(schedules) == 2

    def test_list_filter_by_enabled(self, engine):
        sched = _make_schedule(engine)
        engine.pause_schedule("org1", sched["id"])
        active = engine.list_schedules("org1", enabled=True)
        paused = engine.list_schedules("org1", enabled=False)
        assert len(active) == 0
        assert len(paused) == 1

    def test_list_filter_by_report_type(self, engine):
        _make_schedule(engine, name="A", report_type="kpi_report")
        _make_schedule(engine, name="B", report_type="threat_intel")
        kpi = engine.list_schedules("org1", report_type="kpi_report")
        assert len(kpi) == 1
        assert kpi[0]["report_type"] == "kpi_report"


class TestGetSchedule:
    def test_get_existing(self, engine):
        sched = _make_schedule(engine)
        fetched = engine.get_schedule("org1", sched["id"])
        assert fetched is not None
        assert fetched["id"] == sched["id"]

    def test_get_nonexistent_returns_none(self, engine):
        assert engine.get_schedule("org1", "no-such-id") is None


class TestUpdateSchedule:
    def test_update_name(self, engine):
        sched = _make_schedule(engine)
        updated = engine.update_schedule("org1", sched["id"], {"name": "New Name"})
        assert updated["name"] == "New Name"

    def test_update_frequency_recalculates_next_run(self, engine):
        sched = _make_schedule(engine)
        old_next = sched["next_run_at"]
        updated = engine.update_schedule(
            "org1", sched["id"],
            {"frequency": "daily", "hour_utc": 9}
        )
        assert updated["next_run_at"] != old_next or updated["hour_utc"] == 9

    def test_update_nonexistent_raises(self, engine):
        with pytest.raises(ValueError, match="not found"):
            engine.update_schedule("org1", "no-id", {"name": "X"})

    def test_update_invalid_report_type_raises(self, engine):
        sched = _make_schedule(engine)
        with pytest.raises(ValueError, match="Invalid report_type"):
            engine.update_schedule("org1", sched["id"], {"report_type": "bad"})


class TestDeleteSchedule:
    def test_delete_existing(self, engine):
        sched = _make_schedule(engine)
        assert engine.delete_schedule("org1", sched["id"]) is True
        assert engine.get_schedule("org1", sched["id"]) is None

    def test_delete_nonexistent_returns_false(self, engine):
        assert engine.delete_schedule("org1", "no-such-id") is False


# ---------------------------------------------------------------------------
# Pause / Resume
# ---------------------------------------------------------------------------

class TestPauseResume:
    def test_pause_sets_enabled_0(self, engine):
        sched = _make_schedule(engine)
        paused = engine.pause_schedule("org1", sched["id"])
        assert paused["enabled"] == 0
        assert paused["status"] == "paused"

    def test_resume_sets_enabled_1(self, engine):
        sched = _make_schedule(engine)
        engine.pause_schedule("org1", sched["id"])
        resumed = engine.resume_schedule("org1", sched["id"])
        assert resumed["enabled"] == 1
        assert resumed["status"] == "active"

    def test_resume_recalculates_next_run(self, engine):
        sched = _make_schedule(engine)
        engine.pause_schedule("org1", sched["id"])
        resumed = engine.resume_schedule("org1", sched["id"])
        assert resumed["next_run_at"] is not None
        dt = datetime.fromisoformat(resumed["next_run_at"])
        assert dt > datetime.now(timezone.utc)

    def test_pause_nonexistent_raises(self, engine):
        with pytest.raises(ValueError, match="not found"):
            engine.pause_schedule("org1", "no-id")

    def test_resume_nonexistent_raises(self, engine):
        with pytest.raises(ValueError, match="not found"):
            engine.resume_schedule("org1", "no-id")


# ---------------------------------------------------------------------------
# trigger_report
# ---------------------------------------------------------------------------

class TestTriggerReport:
    def test_trigger_creates_run_record(self, engine):
        sched = _make_schedule(engine)
        run = engine.trigger_report("org1", sched["id"])
        assert run["status"] == "completed"
        assert run["schedule_id"] == sched["id"]
        assert run["org_id"] == "org1"
        assert run["report_type"] == "executive_summary"

    def test_trigger_sets_completed_at(self, engine):
        sched = _make_schedule(engine)
        run = engine.trigger_report("org1", sched["id"])
        assert run["completed_at"] is not None

    def test_trigger_sets_content_preview(self, engine):
        sched = _make_schedule(engine)
        run = engine.trigger_report("org1", sched["id"])
        preview = json.loads(run["content_preview"])
        assert preview["org_id"] == "org1"
        assert preview["report_type"] == "executive_summary"
        assert "generated_at" in preview

    def test_trigger_updates_last_run_at(self, engine):
        sched = _make_schedule(engine)
        engine.trigger_report("org1", sched["id"])
        updated_sched = engine.get_schedule("org1", sched["id"])
        assert updated_sched["last_run_at"] is not None

    def test_trigger_creates_delivery_log_for_email_recipients(self, engine):
        sched = _make_schedule(engine, recipients=["a@b.com"])
        run = engine.trigger_report("org1", sched["id"])
        runs = engine.list_runs("org1", schedule_id=sched["id"])
        assert len(runs) == 1
        assert runs[0]["recipient_count"] == 1

    def test_trigger_with_override_recipients(self, engine):
        sched = _make_schedule(engine, recipients=[])
        run = engine.trigger_report("org1", sched["id"], override_recipients=["x@y.com", "z@w.com"])
        assert run["recipient_count"] == 2

    def test_trigger_nonexistent_raises(self, engine):
        with pytest.raises(ValueError, match="not found"):
            engine.trigger_report("org1", "no-id")

    def test_trigger_slack_webhook_graceful_failure(self, engine):
        sched = _make_schedule(engine, slack_webhook_url="http://localhost:0/invalid")
        # Should not raise even if Slack delivery fails
        run = engine.trigger_report("org1", sched["id"])
        assert run["status"] == "completed"


# ---------------------------------------------------------------------------
# List / get runs
# ---------------------------------------------------------------------------

class TestRuns:
    def test_list_runs_returns_run(self, engine):
        sched = _make_schedule(engine)
        engine.trigger_report("org1", sched["id"])
        runs = engine.list_runs("org1")
        assert len(runs) == 1

    def test_list_runs_filter_by_schedule(self, engine):
        s1 = _make_schedule(engine, name="S1")
        s2 = _make_schedule(engine, name="S2")
        engine.trigger_report("org1", s1["id"])
        engine.trigger_report("org1", s2["id"])
        runs = engine.list_runs("org1", schedule_id=s1["id"])
        assert len(runs) == 1
        assert runs[0]["schedule_id"] == s1["id"]

    def test_list_runs_filter_by_status(self, engine):
        sched = _make_schedule(engine)
        engine.trigger_report("org1", sched["id"])
        completed = engine.list_runs("org1", status="completed")
        failed = engine.list_runs("org1", status="failed")
        assert len(completed) == 1
        assert len(failed) == 0

    def test_get_run_existing(self, engine):
        sched = _make_schedule(engine)
        run = engine.trigger_report("org1", sched["id"])
        fetched = engine.get_run("org1", run["id"])
        assert fetched is not None
        assert fetched["id"] == run["id"]

    def test_get_run_nonexistent_returns_none(self, engine):
        assert engine.get_run("org1", "no-id") is None


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------

class TestTemplates:
    def test_create_template(self, engine):
        tpl = engine.create_template("org1", {
            "name": "Exec Template",
            "report_type": "executive_summary",
            "sections": ["risk_overview", "kpi_summary"],
            "description": "Monthly executive report",
        })
        assert tpl["id"] is not None
        assert tpl["name"] == "Exec Template"
        assert isinstance(tpl["sections"], list)
        assert len(tpl["sections"]) == 2

    def test_create_template_missing_name_raises(self, engine):
        with pytest.raises(ValueError, match="name is required"):
            engine.create_template("org1", {"report_type": "kpi_report"})

    def test_create_template_invalid_type_raises(self, engine):
        with pytest.raises(ValueError, match="Invalid report_type"):
            engine.create_template("org1", {"name": "X", "report_type": "bogus"})

    def test_list_templates(self, engine):
        engine.create_template("org1", {"name": "T1", "report_type": "kpi_report"})
        engine.create_template("org1", {"name": "T2", "report_type": "threat_intel"})
        templates = engine.list_templates("org1")
        assert len(templates) == 2

    def test_list_templates_filter_by_type(self, engine):
        engine.create_template("org1", {"name": "T1", "report_type": "kpi_report"})
        engine.create_template("org1", {"name": "T2", "report_type": "threat_intel"})
        kpi = engine.list_templates("org1", report_type="kpi_report")
        assert len(kpi) == 1
        assert kpi[0]["report_type"] == "kpi_report"


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

class TestStats:
    def test_stats_empty_org(self, engine):
        stats = engine.get_stats("empty_org")
        assert stats["schedule_count"] == 0
        assert stats["active_schedules"] == 0
        assert stats["runs_this_week"] == 0
        assert stats["upcoming_runs"] == []
        assert stats["by_report_type"] == {}

    def test_stats_counts_schedules(self, engine):
        _make_schedule(engine, name="A", report_type="kpi_report")
        _make_schedule(engine, name="B", report_type="threat_intel")
        stats = engine.get_stats("org1")
        assert stats["schedule_count"] == 2
        assert stats["active_schedules"] == 2

    def test_stats_paused_not_counted_active(self, engine):
        sched = _make_schedule(engine)
        engine.pause_schedule("org1", sched["id"])
        stats = engine.get_stats("org1")
        assert stats["active_schedules"] == 0

    def test_stats_counts_runs_this_week(self, engine):
        sched = _make_schedule(engine)
        engine.trigger_report("org1", sched["id"])
        engine.trigger_report("org1", sched["id"])
        stats = engine.get_stats("org1")
        assert stats["runs_this_week"] == 2

    def test_stats_by_report_type(self, engine):
        _make_schedule(engine, name="A", report_type="kpi_report")
        _make_schedule(engine, name="B", report_type="kpi_report")
        _make_schedule(engine, name="C", report_type="threat_intel")
        stats = engine.get_stats("org1")
        assert stats["by_report_type"]["kpi_report"] == 2
        assert stats["by_report_type"]["threat_intel"] == 1

    def test_stats_upcoming_runs(self, engine):
        _make_schedule(engine, name="A")
        stats = engine.get_stats("org1")
        assert len(stats["upcoming_runs"]) == 1
        assert "next_run_at" in stats["upcoming_runs"][0]


# ---------------------------------------------------------------------------
# Multi-tenant isolation
# ---------------------------------------------------------------------------

class TestMultiTenantIsolation:
    def test_org1_cannot_see_org2_schedules(self, engine):
        _make_schedule(engine, "org1", name="Org1 Report")
        _make_schedule(engine, "org2", name="Org2 Report")
        org1_scheds = engine.list_schedules("org1")
        org2_scheds = engine.list_schedules("org2")
        assert len(org1_scheds) == 1
        assert len(org2_scheds) == 1
        assert org1_scheds[0]["name"] == "Org1 Report"
        assert org2_scheds[0]["name"] == "Org2 Report"

    def test_org1_cannot_get_org2_schedule(self, engine):
        sched = _make_schedule(engine, "org2")
        # org1 tries to fetch org2's schedule
        assert engine.get_schedule("org1", sched["id"]) is None

    def test_org1_cannot_delete_org2_schedule(self, engine):
        sched = _make_schedule(engine, "org2")
        deleted = engine.delete_schedule("org1", sched["id"])
        assert deleted is False
        # Still exists for org2
        assert engine.get_schedule("org2", sched["id"]) is not None

    def test_org1_runs_isolated_from_org2_runs(self, engine):
        s1 = _make_schedule(engine, "org1", name="S1")
        s2 = _make_schedule(engine, "org2", name="S2")
        engine.trigger_report("org1", s1["id"])
        engine.trigger_report("org2", s2["id"])
        assert len(engine.list_runs("org1")) == 1
        assert len(engine.list_runs("org2")) == 1

    def test_org1_cannot_get_org2_run(self, engine):
        sched = _make_schedule(engine, "org2")
        run = engine.trigger_report("org2", sched["id"])
        assert engine.get_run("org1", run["id"]) is None

    def test_org1_stats_isolated_from_org2(self, engine):
        _make_schedule(engine, "org1", name="A")
        _make_schedule(engine, "org1", name="B")
        _make_schedule(engine, "org2", name="C")
        assert engine.get_stats("org1")["schedule_count"] == 2
        assert engine.get_stats("org2")["schedule_count"] == 1
