"""Tests for SecurityPostureReportingEngine — 38+ tests covering:
section status thresholds (80/60), overall_score recompute after add_section,
grade thresholds (90/80/70/60), trend detection (5% bands),
publish sets published_at, org isolation."""

from __future__ import annotations

import os
import pytest

from core.security_posture_reporting_engine import SecurityPostureReportingEngine

ORG_A = "org-alpha"
ORG_B = "org-beta"


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "test_spr.db")
    return SecurityPostureReportingEngine(db_path=db)


# ---------------------------------------------------------------------------
# Init / schema
# ---------------------------------------------------------------------------


def test_engine_init_creates_db(tmp_path):
    db = str(tmp_path / "spr.db")
    SecurityPostureReportingEngine(db_path=db)
    assert os.path.exists(db)


def test_engine_two_instances_same_db(tmp_path):
    db = str(tmp_path / "spr.db")
    e1 = SecurityPostureReportingEngine(db_path=db)
    e2 = SecurityPostureReportingEngine(db_path=db)
    e1.create_report(ORG_A, "R1", "monthly", "ciso", "2026-01-01", "2026-01-31")
    assert len(e2.list_reports(ORG_A)) == 1


# ---------------------------------------------------------------------------
# create_report
# ---------------------------------------------------------------------------


def test_create_report_returns_dict(engine):
    r = engine.create_report(ORG_A, "Q1 Board Report", "quarterly", "board", "2026-01-01", "2026-03-31")
    assert r["id"]
    assert r["org_id"] == ORG_A
    assert r["report_name"] == "Q1 Board Report"
    assert r["report_type"] == "quarterly"
    assert r["audience"] == "board"
    assert r["overall_score"] == 0.0
    assert r["grade"] == "F"
    assert r["status"] == "draft"
    assert r["published_at"] is None


def test_create_report_generated_by(engine):
    r = engine.create_report(ORG_A, "Audit Report", "audit", "auditors",
                             "2026-01-01", "2026-03-31", generated_by="CISO Bot")
    assert r["generated_by"] == "CISO Bot"


def test_create_report_default_draft(engine):
    r = engine.create_report(ORG_A, "R", "executive", "executives", "2026-01-01", "2026-01-31")
    assert r["status"] == "draft"


def test_create_report_multiple_orgs(engine):
    engine.create_report(ORG_A, "R1", "monthly", "ciso", "2026-01-01", "2026-01-31")
    engine.create_report(ORG_B, "R2", "monthly", "ciso", "2026-01-01", "2026-01-31")
    assert len(engine.list_reports(ORG_A)) == 1
    assert len(engine.list_reports(ORG_B)) == 1


# ---------------------------------------------------------------------------
# add_section — status thresholds
# ---------------------------------------------------------------------------


def test_add_section_green_at_80(engine):
    r = engine.create_report(ORG_A, "R", "monthly", "ciso", "2026-01-01", "2026-01-31")
    s = engine.add_section(r["id"], ORG_A, "Risk Overview", "risk", score=80.0)
    assert s["status"] == "green"


def test_add_section_green_above_80(engine):
    r = engine.create_report(ORG_A, "R", "monthly", "ciso", "2026-01-01", "2026-01-31")
    s = engine.add_section(r["id"], ORG_A, "Compliance", "compliance", score=95.0)
    assert s["status"] == "green"


def test_add_section_amber_at_60(engine):
    r = engine.create_report(ORG_A, "R", "monthly", "ciso", "2026-01-01", "2026-01-31")
    s = engine.add_section(r["id"], ORG_A, "Incidents", "incidents", score=60.0)
    assert s["status"] == "amber"


def test_add_section_amber_between_60_80(engine):
    r = engine.create_report(ORG_A, "R", "monthly", "ciso", "2026-01-01", "2026-01-31")
    s = engine.add_section(r["id"], ORG_A, "Vulns", "vulnerabilities", score=70.0)
    assert s["status"] == "amber"


def test_add_section_red_below_60(engine):
    r = engine.create_report(ORG_A, "R", "monthly", "ciso", "2026-01-01", "2026-01-31")
    s = engine.add_section(r["id"], ORG_A, "Summary", "summary", score=40.0)
    assert s["status"] == "red"


def test_add_section_red_at_zero(engine):
    r = engine.create_report(ORG_A, "R", "monthly", "ciso", "2026-01-01", "2026-01-31")
    s = engine.add_section(r["id"], ORG_A, "KPIs", "kpis", score=0.0)
    assert s["status"] == "red"


# ---------------------------------------------------------------------------
# add_section — overall_score recompute
# ---------------------------------------------------------------------------


def test_add_section_recomputes_overall_score_single(engine):
    r = engine.create_report(ORG_A, "R", "monthly", "ciso", "2026-01-01", "2026-01-31")
    engine.add_section(r["id"], ORG_A, "S1", "summary", score=80.0)
    detail = engine.get_report_detail(r["id"], ORG_A)
    assert abs(detail["overall_score"] - 80.0) < 0.01


def test_add_section_recomputes_overall_score_avg(engine):
    r = engine.create_report(ORG_A, "R", "monthly", "ciso", "2026-01-01", "2026-01-31")
    engine.add_section(r["id"], ORG_A, "S1", "summary", score=80.0)
    engine.add_section(r["id"], ORG_A, "S2", "risk", score=60.0)
    detail = engine.get_report_detail(r["id"], ORG_A)
    assert abs(detail["overall_score"] - 70.0) < 0.01


def test_add_section_three_sections_avg(engine):
    r = engine.create_report(ORG_A, "R", "monthly", "ciso", "2026-01-01", "2026-01-31")
    engine.add_section(r["id"], ORG_A, "S1", "summary", score=90.0)
    engine.add_section(r["id"], ORG_A, "S2", "risk", score=75.0)
    engine.add_section(r["id"], ORG_A, "S3", "compliance", score=60.0)
    detail = engine.get_report_detail(r["id"], ORG_A)
    assert abs(detail["overall_score"] - 75.0) < 0.01


# ---------------------------------------------------------------------------
# add_section — grade thresholds
# ---------------------------------------------------------------------------


def test_grade_A_at_90(engine):
    r = engine.create_report(ORG_A, "R", "monthly", "ciso", "2026-01-01", "2026-01-31")
    engine.add_section(r["id"], ORG_A, "S", "summary", score=90.0)
    detail = engine.get_report_detail(r["id"], ORG_A)
    assert detail["grade"] == "A"


def test_grade_A_above_90(engine):
    r = engine.create_report(ORG_A, "R", "monthly", "ciso", "2026-01-01", "2026-01-31")
    engine.add_section(r["id"], ORG_A, "S", "summary", score=100.0)
    detail = engine.get_report_detail(r["id"], ORG_A)
    assert detail["grade"] == "A"


def test_grade_B_at_80(engine):
    r = engine.create_report(ORG_A, "R", "monthly", "ciso", "2026-01-01", "2026-01-31")
    engine.add_section(r["id"], ORG_A, "S", "summary", score=80.0)
    detail = engine.get_report_detail(r["id"], ORG_A)
    assert detail["grade"] == "B"


def test_grade_C_at_70(engine):
    r = engine.create_report(ORG_A, "R", "monthly", "ciso", "2026-01-01", "2026-01-31")
    engine.add_section(r["id"], ORG_A, "S", "summary", score=70.0)
    detail = engine.get_report_detail(r["id"], ORG_A)
    assert detail["grade"] == "C"


def test_grade_D_at_60(engine):
    r = engine.create_report(ORG_A, "R", "monthly", "ciso", "2026-01-01", "2026-01-31")
    engine.add_section(r["id"], ORG_A, "S", "summary", score=60.0)
    detail = engine.get_report_detail(r["id"], ORG_A)
    assert detail["grade"] == "D"


def test_grade_F_below_60(engine):
    r = engine.create_report(ORG_A, "R", "monthly", "ciso", "2026-01-01", "2026-01-31")
    engine.add_section(r["id"], ORG_A, "S", "summary", score=50.0)
    detail = engine.get_report_detail(r["id"], ORG_A)
    assert detail["grade"] == "F"


def test_grade_F_default(engine):
    r = engine.create_report(ORG_A, "R", "monthly", "ciso", "2026-01-01", "2026-01-31")
    detail = engine.get_report_detail(r["id"], ORG_A)
    assert detail["grade"] == "F"


# ---------------------------------------------------------------------------
# add_metric — trend detection
# ---------------------------------------------------------------------------


def test_metric_trend_improving(engine):
    r = engine.create_report(ORG_A, "R", "monthly", "ciso", "2026-01-01", "2026-01-31")
    m = engine.add_metric(r["id"], ORG_A, "MTTR", 100.0, "min", previous_value=90.0)
    assert m["trend"] == "improving"


def test_metric_trend_improving_exactly_5pct(engine):
    r = engine.create_report(ORG_A, "R", "monthly", "ciso", "2026-01-01", "2026-01-31")
    # 90 * 1.05 = 94.5, so 95 > 94.5 = improving
    m = engine.add_metric(r["id"], ORG_A, "Score", 95.0, "%", previous_value=90.0)
    assert m["trend"] == "improving"


def test_metric_trend_declining(engine):
    r = engine.create_report(ORG_A, "R", "monthly", "ciso", "2026-01-01", "2026-01-31")
    m = engine.add_metric(r["id"], ORG_A, "Score", 80.0, "%", previous_value=90.0)
    assert m["trend"] == "declining"


def test_metric_trend_declining_exactly_5pct(engine):
    r = engine.create_report(ORG_A, "R", "monthly", "ciso", "2026-01-01", "2026-01-31")
    # 90 * 0.95 = 85.5, so 85 < 85.5 = declining
    m = engine.add_metric(r["id"], ORG_A, "Score", 85.0, "%", previous_value=90.0)
    assert m["trend"] == "declining"


def test_metric_trend_stable_within_band(engine):
    r = engine.create_report(ORG_A, "R", "monthly", "ciso", "2026-01-01", "2026-01-31")
    # 90 * 0.95 = 85.5, 90 * 1.05 = 94.5; 92 is in band
    m = engine.add_metric(r["id"], ORG_A, "Score", 92.0, "%", previous_value=90.0)
    assert m["trend"] == "stable"


def test_metric_trend_stable_zero_previous(engine):
    r = engine.create_report(ORG_A, "R", "monthly", "ciso", "2026-01-01", "2026-01-31")
    m = engine.add_metric(r["id"], ORG_A, "Score", 80.0, "%", previous_value=0.0)
    assert m["trend"] == "stable"


# ---------------------------------------------------------------------------
# publish_report
# ---------------------------------------------------------------------------


def test_publish_report_sets_status(engine):
    r = engine.create_report(ORG_A, "R", "monthly", "ciso", "2026-01-01", "2026-01-31")
    result = engine.publish_report(r["id"], ORG_A)
    assert result["status"] == "published"


def test_publish_report_sets_published_at(engine):
    r = engine.create_report(ORG_A, "R", "monthly", "ciso", "2026-01-01", "2026-01-31")
    result = engine.publish_report(r["id"], ORG_A)
    assert result["published_at"] is not None
    assert len(result["published_at"]) > 10


def test_publish_report_detail_shows_published(engine):
    r = engine.create_report(ORG_A, "R", "monthly", "ciso", "2026-01-01", "2026-01-31")
    engine.publish_report(r["id"], ORG_A)
    detail = engine.get_report_detail(r["id"], ORG_A)
    assert detail["status"] == "published"
    assert detail["published_at"] is not None


def test_publish_report_wrong_org_raises(engine):
    r = engine.create_report(ORG_A, "R", "monthly", "ciso", "2026-01-01", "2026-01-31")
    with pytest.raises(ValueError):
        engine.publish_report(r["id"], ORG_B)


# ---------------------------------------------------------------------------
# get_report_detail
# ---------------------------------------------------------------------------


def test_get_report_detail_includes_sections(engine):
    r = engine.create_report(ORG_A, "R", "monthly", "ciso", "2026-01-01", "2026-01-31")
    engine.add_section(r["id"], ORG_A, "Summary", "summary", score=75.0, sort_order=1)
    engine.add_section(r["id"], ORG_A, "Risk", "risk", score=65.0, sort_order=2)
    detail = engine.get_report_detail(r["id"], ORG_A)
    assert len(detail["sections"]) == 2


def test_get_report_detail_sections_ordered_by_sort_order(engine):
    r = engine.create_report(ORG_A, "R", "monthly", "ciso", "2026-01-01", "2026-01-31")
    engine.add_section(r["id"], ORG_A, "B", "risk", sort_order=2)
    engine.add_section(r["id"], ORG_A, "A", "summary", sort_order=1)
    detail = engine.get_report_detail(r["id"], ORG_A)
    assert detail["sections"][0]["section_name"] == "A"
    assert detail["sections"][1]["section_name"] == "B"


def test_get_report_detail_includes_metrics(engine):
    r = engine.create_report(ORG_A, "R", "monthly", "ciso", "2026-01-01", "2026-01-31")
    engine.add_metric(r["id"], ORG_A, "MTTR", 60.0, "min")
    detail = engine.get_report_detail(r["id"], ORG_A)
    assert len(detail["metrics"]) == 1
    assert detail["metrics"][0]["metric_name"] == "MTTR"


def test_get_report_detail_not_found_returns_none(engine):
    result = engine.get_report_detail("nonexistent-id", ORG_A)
    assert result is None


# ---------------------------------------------------------------------------
# list_reports
# ---------------------------------------------------------------------------


def test_list_reports_empty(engine):
    assert engine.list_reports(ORG_A) == []


def test_list_reports_returns_all(engine):
    engine.create_report(ORG_A, "R1", "monthly", "ciso", "2026-01-01", "2026-01-31")
    engine.create_report(ORG_A, "R2", "quarterly", "board", "2026-01-01", "2026-03-31")
    assert len(engine.list_reports(ORG_A)) == 2


def test_list_reports_filter_type(engine):
    engine.create_report(ORG_A, "R1", "monthly", "ciso", "2026-01-01", "2026-01-31")
    engine.create_report(ORG_A, "R2", "quarterly", "board", "2026-01-01", "2026-03-31")
    result = engine.list_reports(ORG_A, report_type="quarterly")
    assert len(result) == 1
    assert result[0]["report_type"] == "quarterly"


def test_list_reports_filter_status(engine):
    r = engine.create_report(ORG_A, "R1", "monthly", "ciso", "2026-01-01", "2026-01-31")
    engine.create_report(ORG_A, "R2", "monthly", "ciso", "2026-02-01", "2026-02-28")
    engine.publish_report(r["id"], ORG_A)
    published = engine.list_reports(ORG_A, status="published")
    assert len(published) == 1
    draft = engine.list_reports(ORG_A, status="draft")
    assert len(draft) == 1


# ---------------------------------------------------------------------------
# get_latest_report
# ---------------------------------------------------------------------------


def test_get_latest_report(engine):
    engine.create_report(ORG_A, "R1", "monthly", "ciso", "2026-01-01", "2026-01-31")
    engine.create_report(ORG_A, "R2", "monthly", "ciso", "2026-02-01", "2026-02-28")
    latest = engine.get_latest_report(ORG_A, "monthly")
    assert latest is not None
    assert latest["report_name"] == "R2"


def test_get_latest_report_none_when_empty(engine):
    result = engine.get_latest_report(ORG_A, "quarterly")
    assert result is None


# ---------------------------------------------------------------------------
# get_trend_summary
# ---------------------------------------------------------------------------


def test_get_trend_summary_published_only(engine):
    r1 = engine.create_report(ORG_A, "R1", "monthly", "ciso", "2026-01-01", "2026-01-31")
    r2 = engine.create_report(ORG_A, "R2", "monthly", "ciso", "2026-02-01", "2026-02-28")
    engine.add_metric(r1["id"], ORG_A, "MTTR", 60.0, "min", previous_value=70.0)
    engine.add_metric(r2["id"], ORG_A, "MTTR", 50.0, "min", previous_value=60.0)
    # Only publish r1
    engine.publish_report(r1["id"], ORG_A)
    trend = engine.get_trend_summary(ORG_A)
    # Should have MTTR from published r1
    assert len(trend) == 1
    assert trend[0]["metric_name"] == "MTTR"


def test_get_trend_summary_dedup_per_metric(engine):
    r1 = engine.create_report(ORG_A, "R1", "monthly", "ciso", "2026-01-01", "2026-01-31")
    r2 = engine.create_report(ORG_A, "R2", "monthly", "ciso", "2026-02-01", "2026-02-28")
    engine.add_metric(r1["id"], ORG_A, "MTTD", 120.0, "min")
    engine.add_metric(r2["id"], ORG_A, "MTTD", 100.0, "min")
    engine.publish_report(r1["id"], ORG_A)
    engine.publish_report(r2["id"], ORG_A)
    trend = engine.get_trend_summary(ORG_A)
    # Should have exactly one entry for MTTD (latest)
    assert len(trend) == 1


# ---------------------------------------------------------------------------
# Org isolation
# ---------------------------------------------------------------------------


def test_org_isolation_reports(engine):
    r = engine.create_report(ORG_A, "R1", "monthly", "ciso", "2026-01-01", "2026-01-31")
    assert engine.list_reports(ORG_B) == []
    assert engine.get_report_detail(r["id"], ORG_B) is None


def test_org_isolation_sections(engine):
    r = engine.create_report(ORG_A, "R", "monthly", "ciso", "2026-01-01", "2026-01-31")
    with pytest.raises(ValueError):
        engine.add_section(r["id"], ORG_B, "S", "summary", score=80.0)


def test_org_isolation_metrics(engine):
    r = engine.create_report(ORG_A, "R", "monthly", "ciso", "2026-01-01", "2026-01-31")
    with pytest.raises(ValueError):
        engine.add_metric(r["id"], ORG_B, "MTTR", 60.0, "min")


def test_org_isolation_publish(engine):
    r = engine.create_report(ORG_A, "R", "monthly", "ciso", "2026-01-01", "2026-01-31")
    with pytest.raises(ValueError):
        engine.publish_report(r["id"], ORG_B)
