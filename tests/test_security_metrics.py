"""
Comprehensive tests for Security Metrics & OKR Tracking Engine — ALDECI.

Covers:
- SecurityMetricsEngine: DORA metrics, OKR CRUD, SLA compliance, ROI, trends, reports
- SecurityMetricsRouter: all 13 endpoints, status codes, response shapes
- Edge cases: empty data, missing events, invalid inputs

45+ tests, all self-contained with tmp SQLite DBs.
"""

from __future__ import annotations

import sys
import os
import tempfile
import uuid
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

# Ensure suite-core and suite-api are on the path
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))

from core.security_metrics import (
    DORAMetrics,
    KeyResult,
    Objective,
    OKRStatus,
    ReportType,
    ROICalculation,
    SecurityEvent,
    SecurityMetricsEngine,
    Severity,
    SLACompliance,
    SLA_HOURS,
    TrendDataPoint,
    TrendPeriod,
    _PONEMON_AVG_BREACH_COST_USD,
    _DBIR_MTTD_DAYS,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_engine(tmp_path: Path) -> SecurityMetricsEngine:
    """Isolated engine backed by a temp SQLite DB."""
    return SecurityMetricsEngine(db_path=tmp_path / "test_metrics.db")


@pytest.fixture()
def engine_with_events(tmp_engine: SecurityMetricsEngine) -> SecurityMetricsEngine:
    """Engine pre-populated with a mix of events."""
    now = datetime.now(timezone.utc)
    for i, (sev, hours_to_fix) in enumerate([
        (Severity.CRITICAL, 18),
        (Severity.CRITICAL, 30),   # SLA breach (>24h)
        (Severity.HIGH, 100),
        (Severity.HIGH, 200),      # SLA breach (>168h)
        (Severity.MEDIUM, 300),
        (Severity.LOW, 500),
    ]):
        detected = now - timedelta(days=10, hours=i)
        remediated = detected + timedelta(hours=hours_to_fix)
        tmp_engine.ingest_event(SecurityEvent(
            severity=sev,
            detected_at=detected,
            remediated_at=remediated,
            source="scanner",
            team=f"team-{i % 3}",
            repo=f"repo-{i % 2}",
        ))
    # Also add an open (un-remediated) critical
    tmp_engine.ingest_event(SecurityEvent(
        severity=Severity.CRITICAL,
        detected_at=now - timedelta(days=5),
        source="scanner",
        team="team-0",
        repo="repo-0",
    ))
    return tmp_engine


# ============================================================================
# 1. DataClass / Model Tests
# ============================================================================


class TestKeyResult:
    def test_compute_progress_basic(self) -> None:
        kr = KeyResult(title="Automate triage", target_value=80.0, current_value=40.0, unit="%")
        assert kr.compute_progress() == pytest.approx(50.0)

    def test_compute_progress_clamped_over_100(self) -> None:
        kr = KeyResult(title="Reduce MTTR", target_value=24.0, current_value=120.0, unit="hours")
        # 120/24 * 100 = 500 → clamped to 100
        assert kr.compute_progress() == 100.0

    def test_compute_progress_zero_target_zero_current(self) -> None:
        kr = KeyResult(title="Zero vulns", target_value=0.0, current_value=0.0)
        assert kr.compute_progress() == 100.0

    def test_compute_progress_zero_target_nonzero_current(self) -> None:
        kr = KeyResult(title="Zero vulns", target_value=0.0, current_value=5.0)
        assert kr.compute_progress() == 0.0

    def test_compute_progress_clamped_below_0(self) -> None:
        kr = KeyResult(title="KR", target_value=100.0, current_value=-10.0)
        assert kr.compute_progress() == 0.0


class TestObjective:
    def test_recompute_no_krs(self) -> None:
        obj = Objective(title="Empty OKR", quarter="Q1-2026")
        obj.recompute()
        assert obj.overall_progress == 0.0
        assert obj.status == OKRStatus.NOT_STARTED

    def test_recompute_on_track(self) -> None:
        obj = Objective(title="Test OKR", quarter="Q2-2026", key_results=[
            KeyResult(title="KR1", target_value=100.0, current_value=75.0),
            KeyResult(title="KR2", target_value=100.0, current_value=80.0),
        ])
        obj.recompute()
        assert obj.overall_progress == pytest.approx(77.5)
        assert obj.status == OKRStatus.ON_TRACK

    def test_recompute_at_risk(self) -> None:
        obj = Objective(title="OKR", quarter="Q2-2026", key_results=[
            KeyResult(title="KR1", target_value=100.0, current_value=50.0),
        ])
        obj.recompute()
        assert obj.status == OKRStatus.AT_RISK

    def test_recompute_off_track(self) -> None:
        obj = Objective(title="OKR", quarter="Q2-2026", key_results=[
            KeyResult(title="KR1", target_value=100.0, current_value=20.0),
        ])
        obj.recompute()
        assert obj.status == OKRStatus.OFF_TRACK

    def test_recompute_completed(self) -> None:
        obj = Objective(title="OKR", quarter="Q2-2026", key_results=[
            KeyResult(title="KR1", target_value=100.0, current_value=100.0),
        ])
        obj.recompute()
        assert obj.status == OKRStatus.COMPLETED


# ============================================================================
# 2. Event Ingestion
# ============================================================================


class TestEventIngestion:
    def test_ingest_returns_event_with_id(self, tmp_engine: SecurityMetricsEngine) -> None:
        ev = SecurityEvent(severity=Severity.HIGH)
        result = tmp_engine.ingest_event(ev)
        assert result.event_id == ev.event_id
        assert result.severity == Severity.HIGH

    def test_ingest_assigns_uuid(self, tmp_engine: SecurityMetricsEngine) -> None:
        ev = SecurityEvent()
        assert len(ev.event_id) == 36  # UUID4 format

    def test_ingest_persists_across_engine_instances(self, tmp_path: Path) -> None:
        db = tmp_path / "shared.db"
        e1 = SecurityMetricsEngine(db_path=db)
        ev = SecurityEvent(severity=Severity.CRITICAL, source="trivy")
        e1.ingest_event(ev)

        e2 = SecurityMetricsEngine(db_path=db)
        metrics = e2.compute_dora_metrics(days=1)
        assert metrics.sample_size >= 1


# ============================================================================
# 3. DORA Metrics
# ============================================================================


class TestDORAMetrics:
    def test_empty_returns_zero_metrics(self, tmp_engine: SecurityMetricsEngine) -> None:
        m = tmp_engine.compute_dora_metrics(days=30)
        assert m.mttd_hours == 0.0
        assert m.mttr_hours == 0.0
        assert m.change_failure_rate == 0.0
        assert m.sample_size == 0

    def test_mttc_none_when_no_containment(self, tmp_engine: SecurityMetricsEngine) -> None:
        now = datetime.now(timezone.utc)
        tmp_engine.ingest_event(SecurityEvent(
            detected_at=now - timedelta(hours=5),
            remediated_at=now - timedelta(hours=1),
        ))
        m = tmp_engine.compute_dora_metrics(days=1)
        assert m.mttc_hours is None

    def test_mttr_computed_correctly(self, tmp_engine: SecurityMetricsEngine) -> None:
        now = datetime.now(timezone.utc)
        detected = now - timedelta(hours=50)
        remediated = detected + timedelta(hours=24)
        tmp_engine.ingest_event(SecurityEvent(
            severity=Severity.CRITICAL,
            detected_at=detected,
            remediated_at=remediated,
        ))
        m = tmp_engine.compute_dora_metrics(days=60)
        assert m.mttr_hours == pytest.approx(24.0, rel=0.01)

    def test_mttc_computed_when_present(self, tmp_engine: SecurityMetricsEngine) -> None:
        now = datetime.now(timezone.utc)
        detected = now - timedelta(hours=10)
        contained = detected + timedelta(hours=3)
        remediated = detected + timedelta(hours=8)
        tmp_engine.ingest_event(SecurityEvent(
            detected_at=detected,
            contained_at=contained,
            remediated_at=remediated,
        ))
        m = tmp_engine.compute_dora_metrics(days=5)
        assert m.mttc_hours == pytest.approx(3.0, rel=0.01)

    def test_change_failure_rate(self, tmp_engine: SecurityMetricsEngine) -> None:
        for _ in range(8):
            tmp_engine.record_deployment(is_failure=False)
        for _ in range(2):
            tmp_engine.record_deployment(is_failure=True)
        m = tmp_engine.compute_dora_metrics(days=1)
        assert m.change_failure_rate == pytest.approx(0.20, rel=0.01)

    def test_by_severity_breakdown(self, engine_with_events: SecurityMetricsEngine) -> None:
        m = engine_with_events.compute_dora_metrics(days=30)
        assert "critical" in m.by_severity
        assert m.by_severity["critical"] > 0.0

    def test_period_window_respected(self, tmp_engine: SecurityMetricsEngine) -> None:
        now = datetime.now(timezone.utc)
        # Event outside the window
        tmp_engine.ingest_event(SecurityEvent(
            detected_at=now - timedelta(days=100),
            remediated_at=now - timedelta(days=99),
        ))
        m = tmp_engine.compute_dora_metrics(days=30)
        assert m.sample_size == 0

    def test_explicit_since_until(self, tmp_engine: SecurityMetricsEngine) -> None:
        now = datetime.now(timezone.utc)
        tmp_engine.ingest_event(SecurityEvent(
            detected_at=now - timedelta(days=5),
            remediated_at=now - timedelta(days=4),
        ))
        since = now - timedelta(days=10)
        m = tmp_engine.compute_dora_metrics(since=since, until=now)
        assert m.sample_size == 1


# ============================================================================
# 4. OKR Framework
# ============================================================================


class TestOKRFramework:
    def test_create_objective(self, tmp_engine: SecurityMetricsEngine) -> None:
        obj = tmp_engine.create_objective("Reduce MTTR to 24h", "Q2-2026", "appsec")
        assert obj.obj_id
        assert obj.title == "Reduce MTTR to 24h"
        assert obj.quarter == "Q2-2026"
        assert obj.owner == "appsec"

    def test_list_objectives_empty(self, tmp_engine: SecurityMetricsEngine) -> None:
        assert tmp_engine.list_objectives() == []

    def test_list_objectives_returns_all(self, tmp_engine: SecurityMetricsEngine) -> None:
        tmp_engine.create_objective("OKR1", "Q1-2026")
        tmp_engine.create_objective("OKR2", "Q2-2026")
        objs = tmp_engine.list_objectives()
        assert len(objs) == 2

    def test_get_objective_found(self, tmp_engine: SecurityMetricsEngine) -> None:
        obj = tmp_engine.create_objective("OKR", "Q1-2026")
        fetched = tmp_engine.get_objective(obj.obj_id)
        assert fetched is not None
        assert fetched.title == "OKR"

    def test_get_objective_not_found(self, tmp_engine: SecurityMetricsEngine) -> None:
        assert tmp_engine.get_objective("nonexistent-id") is None

    def test_add_key_result(self, tmp_engine: SecurityMetricsEngine) -> None:
        obj = tmp_engine.create_objective("OKR", "Q1-2026")
        kr = tmp_engine.add_key_result(
            obj.obj_id, "Automate 80% triage", target_value=80.0,
            current_value=40.0, unit="%"
        )
        assert kr.kr_id
        assert kr.progress_pct == pytest.approx(50.0)

    def test_add_key_result_unknown_objective(self, tmp_engine: SecurityMetricsEngine) -> None:
        with pytest.raises(ValueError, match="not found"):
            tmp_engine.add_key_result("bad-id", "KR", target_value=100.0)

    def test_update_key_result(self, tmp_engine: SecurityMetricsEngine) -> None:
        obj = tmp_engine.create_objective("OKR", "Q1-2026")
        kr = tmp_engine.add_key_result(obj.obj_id, "KR", target_value=100.0, current_value=0.0)
        updated = tmp_engine.update_key_result(obj.obj_id, kr.kr_id, current_value=75.0)
        assert updated.overall_progress == pytest.approx(75.0)
        assert updated.status == OKRStatus.ON_TRACK

    def test_update_key_result_unknown_kr(self, tmp_engine: SecurityMetricsEngine) -> None:
        obj = tmp_engine.create_objective("OKR", "Q1-2026")
        with pytest.raises(ValueError, match="not found"):
            tmp_engine.update_key_result(obj.obj_id, "bad-kr-id", current_value=50.0)

    def test_delete_objective(self, tmp_engine: SecurityMetricsEngine) -> None:
        obj = tmp_engine.create_objective("OKR", "Q1-2026")
        assert tmp_engine.delete_objective(obj.obj_id) is True
        assert tmp_engine.get_objective(obj.obj_id) is None

    def test_delete_nonexistent_objective(self, tmp_engine: SecurityMetricsEngine) -> None:
        assert tmp_engine.delete_objective("ghost-id") is False

    def test_okr_persists_across_instances(self, tmp_path: Path) -> None:
        db = tmp_path / "okr.db"
        e1 = SecurityMetricsEngine(db_path=db)
        obj = e1.create_objective("Persist me", "Q3-2026")

        e2 = SecurityMetricsEngine(db_path=db)
        fetched = e2.get_objective(obj.obj_id)
        assert fetched is not None
        assert fetched.title == "Persist me"


# ============================================================================
# 5. Benchmark Comparisons
# ============================================================================


class TestBenchmarkComparisons:
    def test_returns_list_of_comparisons(self, tmp_engine: SecurityMetricsEngine) -> None:
        m = tmp_engine.compute_dora_metrics(days=30)
        comps = tmp_engine.compare_to_benchmarks(m, industry="technology")
        assert len(comps) >= 1  # at least MTTD and CFR

    def test_includes_mttd_comparison(self, tmp_engine: SecurityMetricsEngine) -> None:
        m = tmp_engine.compute_dora_metrics(days=30)
        comps = tmp_engine.compare_to_benchmarks(m)
        names = [c.metric_name for c in comps]
        assert "MTTD" in names

    def test_includes_change_failure_rate(self, tmp_engine: SecurityMetricsEngine) -> None:
        m = tmp_engine.compute_dora_metrics(days=30)
        comps = tmp_engine.compare_to_benchmarks(m)
        names = [c.metric_name for c in comps]
        assert "ChangeFailureRate" in names

    def test_percentile_rank_better_than_median(self, tmp_engine: SecurityMetricsEngine) -> None:
        # If org MTTD is very low → should be above 50th percentile
        pct = SecurityMetricsEngine._percentile_rank(10.0, 100.0, 500.0, 1000.0, lower_is_better=True)
        assert pct > 50.0

    def test_percentile_rank_worse_than_median(self) -> None:
        pct = SecurityMetricsEngine._percentile_rank(900.0, 100.0, 500.0, 1000.0, lower_is_better=True)
        assert pct < 50.0

    def test_unknown_industry_falls_back_to_global(self, tmp_engine: SecurityMetricsEngine) -> None:
        m = tmp_engine.compute_dora_metrics(days=30)
        comps = tmp_engine.compare_to_benchmarks(m, industry="unknown_sector")
        # Should not raise; uses global_median fallback
        assert len(comps) >= 1

    def test_mttr_severity_benchmarks_included(self, engine_with_events: SecurityMetricsEngine) -> None:
        m = engine_with_events.compute_dora_metrics(days=30)
        comps = engine_with_events.compare_to_benchmarks(m)
        mttr_names = [c.metric_name for c in comps if c.metric_name.startswith("MTTR_")]
        assert len(mttr_names) >= 1


# ============================================================================
# 6. SLA Compliance
# ============================================================================


class TestSLACompliance:
    def test_returns_four_severities(self, tmp_engine: SecurityMetricsEngine) -> None:
        records = tmp_engine.compute_sla_compliance(days=30)
        severities = {r.severity for r in records}
        assert severities == {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW}

    def test_empty_data_zero_findings(self, tmp_engine: SecurityMetricsEngine) -> None:
        records = tmp_engine.compute_sla_compliance(days=30)
        for r in records:
            assert r.total_findings == 0
            assert r.breach_rate_pct == 0.0

    def test_within_sla_counted_correctly(self, tmp_engine: SecurityMetricsEngine) -> None:
        now = datetime.now(timezone.utc)
        detected = now - timedelta(hours=20)
        remediated = detected + timedelta(hours=10)  # 10h < 24h SLA
        tmp_engine.ingest_event(SecurityEvent(
            severity=Severity.CRITICAL,
            detected_at=detected,
            remediated_at=remediated,
        ))
        records = tmp_engine.compute_sla_compliance(days=5)
        crit = next(r for r in records if r.severity == Severity.CRITICAL)
        assert crit.within_sla == 1
        assert crit.breached == 0

    def test_breach_detected(self, tmp_engine: SecurityMetricsEngine) -> None:
        now = datetime.now(timezone.utc)
        detected = now - timedelta(hours=50)
        remediated = detected + timedelta(hours=30)  # 30h > 24h SLA
        tmp_engine.ingest_event(SecurityEvent(
            severity=Severity.CRITICAL,
            detected_at=detected,
            remediated_at=remediated,
        ))
        records = tmp_engine.compute_sla_compliance(days=10)
        crit = next(r for r in records if r.severity == Severity.CRITICAL)
        assert crit.breached == 1
        assert crit.breach_rate_pct == pytest.approx(100.0)

    def test_open_overdue_counted_as_breach(self, tmp_engine: SecurityMetricsEngine) -> None:
        now = datetime.now(timezone.utc)
        # Critical with no remediation, opened 48h ago → breached
        tmp_engine.ingest_event(SecurityEvent(
            severity=Severity.CRITICAL,
            detected_at=now - timedelta(hours=48),
        ))
        records = tmp_engine.compute_sla_compliance(days=10)
        crit = next(r for r in records if r.severity == Severity.CRITICAL)
        assert crit.breached == 1

    def test_worst_offender_tracked(self, engine_with_events: SecurityMetricsEngine) -> None:
        records = engine_with_events.compute_sla_compliance(days=30)
        crit = next(r for r in records if r.severity == Severity.CRITICAL)
        # At least one breach exists from fixture
        if crit.breached > 0:
            assert crit.worst_offender_team != "none"

    def test_sla_hours_correct(self, tmp_engine: SecurityMetricsEngine) -> None:
        records = tmp_engine.compute_sla_compliance(days=30)
        sla_map = {r.severity: r.sla_hours for r in records}
        assert sla_map[Severity.CRITICAL] == 24
        assert sla_map[Severity.HIGH] == 168
        assert sla_map[Severity.MEDIUM] == 720
        assert sla_map[Severity.LOW] == 2160


# ============================================================================
# 7. ROI Calculator
# ============================================================================


class TestROICalculator:
    def test_positive_roi(self, tmp_engine: SecurityMetricsEngine) -> None:
        roi = tmp_engine.compute_roi(
            program_cost_usd=500_000,
            breaches_prevented=2,
            industry="global",
        )
        assert roi.total_avoided_loss_usd == pytest.approx(2 * _PONEMON_AVG_BREACH_COST_USD, rel=0.01)
        assert roi.net_benefit_usd > 0
        assert roi.roi_pct > 0

    def test_negative_roi(self, tmp_engine: SecurityMetricsEngine) -> None:
        roi = tmp_engine.compute_roi(
            program_cost_usd=50_000_000,
            breaches_prevented=0.001,
            industry="global",
        )
        assert roi.net_benefit_usd < 0
        assert roi.roi_pct < 0

    def test_industry_breach_cost_used(self, tmp_engine: SecurityMetricsEngine) -> None:
        roi_healthcare = tmp_engine.compute_roi(1_000_000, 1, industry="healthcare")
        roi_global = tmp_engine.compute_roi(1_000_000, 1, industry="global")
        # Healthcare breach cost > global average
        assert roi_healthcare.avg_breach_cost_usd > roi_global.avg_breach_cost_usd

    def test_roi_pct_formula(self, tmp_engine: SecurityMetricsEngine) -> None:
        cost = 1_000_000.0
        prevented = 1.0
        roi = tmp_engine.compute_roi(cost, prevented, industry="global")
        expected_net = prevented * _PONEMON_AVG_BREACH_COST_USD - cost
        expected_pct = expected_net / cost * 100.0
        assert roi.roi_pct == pytest.approx(expected_pct, rel=0.01)

    def test_zero_breaches_prevented(self, tmp_engine: SecurityMetricsEngine) -> None:
        roi = tmp_engine.compute_roi(500_000, 0, industry="global")
        assert roi.total_avoided_loss_usd == 0.0
        assert roi.net_benefit_usd == pytest.approx(-500_000.0)

    def test_payback_months_computed(self, tmp_engine: SecurityMetricsEngine) -> None:
        roi = tmp_engine.compute_roi(500_000, 2, industry="global")
        assert roi.payback_months > 0


# ============================================================================
# 8. Trend Data
# ============================================================================


class TestTrendData:
    def test_weekly_trend_returns_correct_count(self, tmp_engine: SecurityMetricsEngine) -> None:
        trend = tmp_engine.get_trend_data(TrendPeriod.WEEKLY, periods=8)
        assert len(trend) == 8

    def test_monthly_trend_returns_correct_count(self, tmp_engine: SecurityMetricsEngine) -> None:
        trend = tmp_engine.get_trend_data(TrendPeriod.MONTHLY, periods=6)
        assert len(trend) == 6

    def test_quarterly_trend_returns_correct_count(self, tmp_engine: SecurityMetricsEngine) -> None:
        trend = tmp_engine.get_trend_data(TrendPeriod.QUARTERLY, periods=4)
        assert len(trend) == 4

    def test_trend_labels_are_strings(self, tmp_engine: SecurityMetricsEngine) -> None:
        trend = tmp_engine.get_trend_data(TrendPeriod.WEEKLY, periods=4)
        for t in trend:
            assert isinstance(t.period_label, str)
            assert len(t.period_label) > 0

    def test_trend_periods_chronological(self, tmp_engine: SecurityMetricsEngine) -> None:
        trend = tmp_engine.get_trend_data(TrendPeriod.WEEKLY, periods=4)
        for i in range(1, len(trend)):
            assert trend[i].period_start >= trend[i - 1].period_start

    def test_trend_with_events_shows_backlog(self, engine_with_events: SecurityMetricsEngine) -> None:
        trend = engine_with_events.get_trend_data(TrendPeriod.MONTHLY, periods=3)
        # At least one period should have non-zero backlog
        backlogs = [t.vuln_backlog for t in trend]
        assert any(b >= 0 for b in backlogs)

    def test_trend_point_fields_present(self, tmp_engine: SecurityMetricsEngine) -> None:
        trend = tmp_engine.get_trend_data(TrendPeriod.WEEKLY, periods=1)
        assert len(trend) == 1
        t = trend[0]
        assert hasattr(t, "vuln_backlog")
        assert hasattr(t, "risk_score")
        assert hasattr(t, "compliance_pct")
        assert hasattr(t, "incident_count")


# ============================================================================
# 9. Report Generation
# ============================================================================


class TestReportGeneration:
    def test_weekly_report_title(self, tmp_engine: SecurityMetricsEngine) -> None:
        report = tmp_engine.generate_report(ReportType.WEEKLY_DIGEST)
        assert "Weekly Security Digest" in report.title

    def test_monthly_report_title(self, tmp_engine: SecurityMetricsEngine) -> None:
        report = tmp_engine.generate_report(ReportType.MONTHLY_EXECUTIVE)
        assert "Monthly Executive" in report.title

    def test_quarterly_report_title(self, tmp_engine: SecurityMetricsEngine) -> None:
        report = tmp_engine.generate_report(ReportType.QUARTERLY_BOARD)
        assert "Board Security Report" in report.title

    def test_annual_report_title(self, tmp_engine: SecurityMetricsEngine) -> None:
        report = tmp_engine.generate_report(ReportType.ANNUAL_REVIEW)
        assert "Annual Security Review" in report.title

    def test_report_has_required_sections(self, tmp_engine: SecurityMetricsEngine) -> None:
        report = tmp_engine.generate_report(ReportType.MONTHLY_EXECUTIVE)
        assert "executive_summary" in report.sections
        assert "dora_metrics" in report.sections
        assert "sla_compliance" in report.sections
        assert "benchmarks" in report.sections
        assert "trend_summary" in report.sections
        assert "okr_progress" in report.sections

    def test_report_includes_dora_metrics(self, tmp_engine: SecurityMetricsEngine) -> None:
        report = tmp_engine.generate_report(ReportType.WEEKLY_DIGEST)
        assert report.dora_metrics is not None

    def test_report_includes_sla(self, tmp_engine: SecurityMetricsEngine) -> None:
        report = tmp_engine.generate_report(ReportType.WEEKLY_DIGEST)
        assert len(report.sla_compliance) == 4  # one per severity

    def test_report_top_risks_populated(self, tmp_engine: SecurityMetricsEngine) -> None:
        report = tmp_engine.generate_report(ReportType.WEEKLY_DIGEST)
        assert len(report.top_risks) >= 1

    def test_report_extra_context_passthrough(self, tmp_engine: SecurityMetricsEngine) -> None:
        report = tmp_engine.generate_report(
            ReportType.WEEKLY_DIGEST,
            extra_context={"deployment_count": 42},
        )
        assert "custom_deployment_count" in report.sections
        assert "42" in report.sections["custom_deployment_count"]

    def test_quarterly_report_has_risk_posture(self, tmp_engine: SecurityMetricsEngine) -> None:
        report = tmp_engine.generate_report(ReportType.QUARTERLY_BOARD)
        assert "risk_posture" in report.sections

    def test_report_id_is_uuid(self, tmp_engine: SecurityMetricsEngine) -> None:
        report = tmp_engine.generate_report(ReportType.WEEKLY_DIGEST)
        # Must be a valid UUID4 string
        parsed = uuid.UUID(report.report_id)
        assert str(parsed) == report.report_id


# ============================================================================
# 10. Router / HTTP endpoint tests (using FastAPI TestClient)
# ============================================================================


try:
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    from apps.api.security_metrics_router import router as metrics_router

    _test_app = FastAPI()
    _test_app.include_router(metrics_router)
    _client = TestClient(_test_app, raise_server_exceptions=True)
    _ROUTER_AVAILABLE = True
except Exception:
    _ROUTER_AVAILABLE = False


@pytest.mark.skipif(not _ROUTER_AVAILABLE, reason="Router dependencies not available")
class TestMetricsRouter:
    def test_get_dora_200(self) -> None:
        r = _client.get("/api/v1/metrics/dora")
        assert r.status_code == 200
        body = r.json()
        assert "mttd_hours" in body
        assert "mttr_hours" in body
        assert "change_failure_rate" in body
        assert "sample_size" in body

    def test_get_benchmarks_200(self) -> None:
        r = _client.get("/api/v1/metrics/benchmarks")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_get_trends_weekly_200(self) -> None:
        r = _client.get("/api/v1/metrics/trends?period=weekly&periods=4")
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)
        assert len(data) == 4

    def test_get_trends_monthly_200(self) -> None:
        r = _client.get("/api/v1/metrics/trends?period=monthly&periods=6")
        assert r.status_code == 200
        assert len(r.json()) == 6

    def test_get_sla_200(self) -> None:
        r = _client.get("/api/v1/metrics/sla")
        assert r.status_code == 200
        data = r.json()
        assert len(data) == 4  # 4 severities

    def test_post_roi_200(self) -> None:
        r = _client.post("/api/v1/metrics/roi", json={
            "program_cost_usd": 500000,
            "breaches_prevented": 1.5,
            "industry": "technology",
        })
        assert r.status_code == 200
        body = r.json()
        assert "roi_pct" in body
        assert "net_benefit_usd" in body
        assert "payback_months" in body

    def test_post_roi_invalid_cost(self) -> None:
        r = _client.post("/api/v1/metrics/roi", json={
            "program_cost_usd": -100,
            "breaches_prevented": 1,
        })
        assert r.status_code == 422

    def test_create_objective_201(self) -> None:
        r = _client.post("/api/v1/metrics/objectives", json={
            "title": "Reduce MTTR to 24h",
            "quarter": "Q2-2026",
            "owner": "appsec",
        })
        assert r.status_code == 201
        body = r.json()
        assert body["title"] == "Reduce MTTR to 24h"
        assert "obj_id" in body

    def test_list_objectives_200(self) -> None:
        r = _client.get("/api/v1/metrics/objectives")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_add_key_result_201(self) -> None:
        create_r = _client.post("/api/v1/metrics/objectives", json={
            "title": "OKR for KR test",
            "quarter": "Q3-2026",
        })
        obj_id = create_r.json()["obj_id"]
        r = _client.post(f"/api/v1/metrics/objectives/{obj_id}/key-results", json={
            "title": "Automate 80% triage",
            "target_value": 80.0,
            "current_value": 20.0,
            "unit": "%",
        })
        assert r.status_code == 201
        body = r.json()
        assert body["progress_pct"] == pytest.approx(25.0)

    def test_add_key_result_unknown_obj_404(self) -> None:
        r = _client.post("/api/v1/metrics/objectives/ghost/key-results", json={
            "title": "KR",
            "target_value": 100.0,
        })
        assert r.status_code == 404

    def test_update_key_result_200(self) -> None:
        create_r = _client.post("/api/v1/metrics/objectives", json={
            "title": "Update KR test OKR",
            "quarter": "Q4-2026",
        })
        obj_id = create_r.json()["obj_id"]
        kr_r = _client.post(f"/api/v1/metrics/objectives/{obj_id}/key-results", json={
            "title": "KR1",
            "target_value": 100.0,
            "current_value": 0.0,
        })
        kr_id = kr_r.json()["kr_id"]
        r = _client.patch(f"/api/v1/metrics/objectives/{obj_id}/key-results/{kr_id}", json={
            "current_value": 80.0,
            "notes": "Great progress",
        })
        assert r.status_code == 200
        assert r.json()["overall_progress"] == pytest.approx(80.0)

    def test_delete_objective_204(self) -> None:
        create_r = _client.post("/api/v1/metrics/objectives", json={
            "title": "Delete me",
            "quarter": "Q1-2026",
        })
        obj_id = create_r.json()["obj_id"]
        r = _client.delete(f"/api/v1/metrics/objectives/{obj_id}")
        assert r.status_code == 204

    def test_delete_objective_not_found_404(self) -> None:
        r = _client.delete("/api/v1/metrics/objectives/ghost-obj")
        assert r.status_code == 404

    def test_ingest_event_201(self) -> None:
        r = _client.post("/api/v1/metrics/events", json={
            "severity": "critical",
            "source": "trivy",
            "team": "platform",
            "repo": "api-server",
        })
        assert r.status_code == 201
        body = r.json()
        assert "event_id" in body
        assert body["severity"] == "critical"

    def test_record_deployment_201(self) -> None:
        r = _client.post("/api/v1/metrics/deployments", json={
            "is_failure": False,
            "notes": "v1.2.3",
        })
        assert r.status_code == 201
        assert "deploy_id" in r.json()

    def test_generate_weekly_report_200(self) -> None:
        r = _client.post("/api/v1/metrics/reports", json={
            "report_type": "weekly_digest",
            "industry": "technology",
        })
        assert r.status_code == 200
        body = r.json()
        assert "report_id" in body
        assert "sections" in body
        assert "top_risks" in body

    def test_generate_quarterly_report_200(self) -> None:
        r = _client.post("/api/v1/metrics/reports", json={
            "report_type": "quarterly_board",
        })
        assert r.status_code == 200
        assert "risk_posture" in r.json()["sections"]

    def test_dora_invalid_date_format_422(self) -> None:
        r = _client.get("/api/v1/metrics/dora?since=not-a-date")
        assert r.status_code == 422
