"""Tests for ExecutiveReportingEngine.

28 tests covering: init, report lifecycle, metrics, KPI management,
board presentations, exec summary, org isolation.
"""

from __future__ import annotations

import os
import pytest
from core.executive_reporting_engine import ExecutiveReportingEngine


@pytest.fixture()
def engine(tmp_path):
    db = str(tmp_path / "exec_report_test.db")
    return ExecutiveReportingEngine(db_path=db)


# ---------------------------------------------------------------------------
# 1. Initialization
# ---------------------------------------------------------------------------

def test_init_creates_db(tmp_path):
    db = str(tmp_path / "er_init.db")
    ExecutiveReportingEngine(db_path=db)
    assert os.path.exists(db)


def test_init_idempotent(tmp_path):
    db = str(tmp_path / "er_idem.db")
    ExecutiveReportingEngine(db_path=db)
    ExecutiveReportingEngine(db_path=db)  # second init should not fail


# ---------------------------------------------------------------------------
# 2. Report lifecycle
# ---------------------------------------------------------------------------

def test_create_report_returns_dict(engine):
    report = engine.create_report("org1", {
        "report_type": "monthly",
        "title": "April 2026 Security Briefing",
        "period_start": "2026-04-01",
        "period_end": "2026-04-30",
        "created_by": "ciso@acme.com",
        "sections": ["Executive Summary", "Threat Landscape"],
    })
    assert report["id"]
    assert report["status"] == "draft"
    assert report["report_type"] == "monthly"
    assert report["title"] == "April 2026 Security Briefing"
    assert isinstance(report["sections"], list)
    assert "Executive Summary" in report["sections"]


def test_create_report_invalid_type_raises(engine):
    with pytest.raises(ValueError):
        engine.create_report("org1", {"report_type": "daily"})


def test_create_report_defaults_to_draft(engine):
    report = engine.create_report("org1", {"report_type": "board"})
    assert report["status"] == "draft"


def test_list_reports_empty(engine):
    assert engine.list_reports("org-none") == []


def test_list_reports_returns_all(engine):
    engine.create_report("org2", {"report_type": "weekly"})
    engine.create_report("org2", {"report_type": "monthly"})
    reports = engine.list_reports("org2")
    assert len(reports) == 2


def test_list_reports_filter_by_type(engine):
    engine.create_report("org3", {"report_type": "weekly"})
    engine.create_report("org3", {"report_type": "board"})
    board_reports = engine.list_reports("org3", report_type="board")
    assert len(board_reports) == 1
    assert board_reports[0]["report_type"] == "board"


def test_list_reports_filter_by_status(engine):
    r = engine.create_report("org4", {"report_type": "monthly"})
    engine.publish_report("org4", r["id"])
    engine.create_report("org4", {"report_type": "quarterly"})
    published = engine.list_reports("org4", status="published")
    drafts = engine.list_reports("org4", status="draft")
    assert len(published) == 1
    assert len(drafts) == 1


def test_get_report_returns_none_for_missing(engine):
    assert engine.get_report("org1", "no-such-id") is None


def test_get_report_includes_metrics(engine):
    report = engine.create_report("org1", {"report_type": "ciso"})
    engine.add_metric("org1", report["id"], {
        "metric_name": "MTTD",
        "metric_value": 4.2,
        "metric_unit": "hours",
        "trend": "down",
    })
    result = engine.get_report("org1", report["id"])
    assert result is not None
    assert len(result["metrics"]) == 1
    assert result["metrics"][0]["metric_name"] == "MTTD"


def test_publish_report_sets_status(engine):
    report = engine.create_report("org1", {"report_type": "monthly"})
    ok = engine.publish_report("org1", report["id"])
    assert ok is True
    reports = engine.list_reports("org1", status="published")
    assert any(r["id"] == report["id"] for r in reports)


def test_publish_report_missing_returns_false(engine):
    ok = engine.publish_report("org1", "no-such-id")
    assert ok is False


# ---------------------------------------------------------------------------
# 3. Metrics
# ---------------------------------------------------------------------------

def test_add_metric_returns_dict(engine):
    report = engine.create_report("org1", {"report_type": "weekly"})
    metric = engine.add_metric("org1", report["id"], {
        "metric_name": "MTTR",
        "metric_value": 12.5,
        "metric_unit": "hours",
        "trend": "stable",
        "narrative": "Stable response time",
    })
    assert metric["id"]
    assert metric["metric_name"] == "MTTR"
    assert metric["trend"] == "stable"


def test_add_metric_invalid_trend_raises(engine):
    report = engine.create_report("org1", {"report_type": "weekly"})
    with pytest.raises(ValueError):
        engine.add_metric("org1", report["id"], {"metric_name": "X", "trend": "sideways"})


# ---------------------------------------------------------------------------
# 4. KPI management
# ---------------------------------------------------------------------------

def test_set_kpi_creates(engine):
    kpi = engine.set_kpi("org1", "patch_compliance", 87.5, 95.0, "%", "improving")
    assert kpi["kpi_name"] == "patch_compliance"
    assert kpi["kpi_value"] == 87.5
    assert kpi["target_value"] == 95.0
    assert kpi["status"] in ("on_track", "at_risk", "off_track")


def test_set_kpi_status_on_track(engine):
    kpi = engine.set_kpi("org1", "mfa_coverage", 95.0, 100.0, "%", "stable")
    assert kpi["status"] == "on_track"  # 95/100 = 0.95 >= 0.9


def test_set_kpi_status_at_risk(engine):
    kpi = engine.set_kpi("org1", "vuln_remediation", 75.0, 100.0, "%", "stable")
    assert kpi["status"] == "at_risk"  # 0.75 >= 0.7


def test_set_kpi_status_off_track(engine):
    kpi = engine.set_kpi("org1", "training_completion", 60.0, 100.0, "%", "declining")
    assert kpi["status"] == "off_track"  # 0.60 < 0.7


def test_set_kpi_upserts(engine):
    engine.set_kpi("org1", "mttd", 6.0, 4.0, "hours", "stable")
    engine.set_kpi("org1", "mttd", 3.5, 4.0, "hours", "improving")
    kpis = engine.list_kpis("org1")
    mttd_kpis = [k for k in kpis if k["kpi_name"] == "mttd"]
    assert len(mttd_kpis) == 1
    assert mttd_kpis[0]["kpi_value"] == 3.5


def test_set_kpi_invalid_trend_raises(engine):
    with pytest.raises(ValueError):
        engine.set_kpi("org1", "x", 1.0, 1.0, "", "sideways")


def test_list_kpis_empty(engine):
    assert engine.list_kpis("org-none") == []


def test_get_kpi_returns_none_for_missing(engine):
    assert engine.get_kpi("org1", "nonexistent") is None


def test_get_kpi_returns_record(engine):
    engine.set_kpi("org1", "sla_compliance", 99.1, 99.0, "%", "stable")
    kpi = engine.get_kpi("org1", "sla_compliance")
    assert kpi is not None
    assert kpi["kpi_name"] == "sla_compliance"


# ---------------------------------------------------------------------------
# 5. Board presentations
# ---------------------------------------------------------------------------

def test_create_board_presentation(engine):
    bp = engine.create_board_presentation("org1", {
        "title": "Q1 2026 Board Security Briefing",
        "presentation_date": "2026-04-15",
        "audience": "board",
        "risk_summary": "Overall risk posture improved by 12% this quarter.",
        "key_metrics": {"mttd_hours": 3.5, "open_critical_vulns": 2},
        "action_items": ["Approve ZTNA budget", "Review incident response policy"],
    })
    assert bp["id"]
    assert bp["title"] == "Q1 2026 Board Security Briefing"
    assert bp["audience"] == "board"
    assert isinstance(bp["key_metrics"], dict)
    assert isinstance(bp["action_items"], list)
    assert len(bp["action_items"]) == 2


def test_create_board_presentation_invalid_audience_raises(engine):
    with pytest.raises(ValueError):
        engine.create_board_presentation("org1", {"audience": "shareholders"})


def test_list_board_presentations_empty(engine):
    assert engine.list_board_presentations("org-none") == []


def test_list_board_presentations_returns_all(engine):
    engine.create_board_presentation("org5", {"audience": "board"})
    engine.create_board_presentation("org5", {"audience": "audit_committee"})
    bps = engine.list_board_presentations("org5")
    assert len(bps) == 2


# ---------------------------------------------------------------------------
# 6. Exec summary
# ---------------------------------------------------------------------------

def test_exec_summary_empty(engine):
    summary = engine.get_exec_summary("org-empty")
    assert summary["recent_reports"] == []
    assert summary["kpi_summary"]["on_track"] == 0
    assert summary["board_presentations_count"] == 0


def test_exec_summary_populated(engine):
    engine.create_report("org6", {"report_type": "monthly", "title": "R1"})
    engine.set_kpi("org6", "kpi_a", 90.0, 95.0, "%", "stable")  # at_risk
    engine.set_kpi("org6", "kpi_b", 99.0, 100.0, "%", "improving")  # on_track
    engine.create_board_presentation("org6", {"audience": "executive"})

    summary = engine.get_exec_summary("org6")
    assert len(summary["recent_reports"]) == 1
    assert summary["kpi_summary"]["on_track"] + summary["kpi_summary"]["at_risk"] == 2
    assert summary["board_presentations_count"] == 1


# ---------------------------------------------------------------------------
# 7. Org isolation
# ---------------------------------------------------------------------------

def test_org_isolation_reports(engine):
    engine.create_report("org-x", {"report_type": "weekly"})
    engine.create_report("org-y", {"report_type": "monthly"})
    assert len(engine.list_reports("org-x")) == 1
    assert len(engine.list_reports("org-y")) == 1


def test_org_isolation_kpis(engine):
    engine.set_kpi("org-a", "mttd", 5.0, 4.0, "h", "stable")
    engine.set_kpi("org-b", "mttr", 12.0, 8.0, "h", "declining")
    assert len(engine.list_kpis("org-a")) == 1
    assert len(engine.list_kpis("org-b")) == 1


def test_org_isolation_board_presentations(engine):
    engine.create_board_presentation("org-c", {"audience": "board"})
    engine.create_board_presentation("org-d", {"audience": "investor"})
    assert len(engine.list_board_presentations("org-c")) == 1
    assert len(engine.list_board_presentations("org-d")) == 1
