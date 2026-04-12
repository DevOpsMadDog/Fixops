"""
Tests for ExecutiveReportEngine — ALDECI executive reporting.

Covers:
- All 6 report types generate successfully with correct section structure
- Security posture report has expected sections (risk, findings, MTTR, scanner)
- Compliance report has all 7 frameworks
- Executive summary combines data from all report types
- Report persistence (get, list, type filtering)
- JSON export produces valid JSON
- Schedule CRUD (create, list, delete)
- Multi-org isolation
- Edge cases (empty period, unknown org)

~35 tests total.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from typing import List

import pytest

# Ensure suite-core is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-api"))

from core.executive_reports import (
    ExecutiveReport,
    ExecutiveReportEngine,
    ReportFrequency,
    ReportSchedule,
    ReportSection,
    ReportType,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path) -> ExecutiveReportEngine:
    """Fresh engine backed by a temp SQLite file."""
    db = tmp_path / "test_executive_reports.db"
    return ExecutiveReportEngine(db_path=str(db))


@pytest.fixture
def now() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture
def period(now) -> tuple:
    """30-day period ending now."""
    return now - timedelta(days=30), now


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------


class TestModels:
    def test_report_section_defaults(self):
        s = ReportSection(title="Test", data={"x": 1})
        assert s.description == ""
        assert s.chart_type is None
        assert s.order == 0

    def test_report_section_full(self):
        s = ReportSection(
            title="Risk", description="desc", data={"score": 7.5},
            chart_type="line", order=1
        )
        assert s.chart_type == "line"
        assert s.order == 1

    def test_executive_report_defaults(self):
        r = ExecutiveReport(
            title="Test", type=ReportType.SECURITY_POSTURE,
            period_start="2024-01-01", period_end="2024-01-31"
        )
        assert r.id is not None
        assert r.org_id == "default"
        assert r.frequency == ReportFrequency.ON_DEMAND
        assert r.generated_by == "executive_report_engine"
        assert isinstance(r.sections, list)
        assert isinstance(r.metadata, dict)

    def test_report_schedule_defaults(self):
        s = ReportSchedule(
            report_type=ReportType.COMPLIANCE_STATUS,
            frequency=ReportFrequency.MONTHLY,
            next_run="2024-02-01T00:00:00+00:00",
        )
        assert s.enabled is True
        assert s.org_id == "default"
        assert isinstance(s.recipients, list)

    def test_report_type_enum_values(self):
        assert ReportType.SECURITY_POSTURE.value == "security_posture"
        assert ReportType.COMPLIANCE_STATUS.value == "compliance_status"
        assert ReportType.RISK_TRENDS.value == "risk_trends"
        assert ReportType.EXECUTIVE_SUMMARY.value == "executive_summary"
        assert ReportType.INCIDENT_SUMMARY.value == "incident_summary"
        assert ReportType.SCANNER_EFFECTIVENESS.value == "scanner_effectiveness"

    def test_report_frequency_enum_values(self):
        assert ReportFrequency.ON_DEMAND.value == "on_demand"
        assert ReportFrequency.WEEKLY.value == "weekly"
        assert ReportFrequency.MONTHLY.value == "monthly"
        assert ReportFrequency.QUARTERLY.value == "quarterly"


# ---------------------------------------------------------------------------
# Engine init
# ---------------------------------------------------------------------------


class TestEngineInit:
    def test_init_creates_db(self, engine: ExecutiveReportEngine):
        assert engine.db_path.exists()

    def test_init_creates_tables(self, engine: ExecutiveReportEngine):
        conn = engine._connect()
        tables = {
            r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        conn.close()
        assert "executive_reports" in tables
        assert "report_schedules" in tables


# ---------------------------------------------------------------------------
# Security Posture report
# ---------------------------------------------------------------------------


class TestSecurityPostureReport:
    def test_generates_successfully(self, engine, period):
        start, end = period
        report = engine.generate_report(
            type=ReportType.SECURITY_POSTURE,
            period_start=start,
            period_end=end,
        )
        assert isinstance(report, ExecutiveReport)
        assert report.type == ReportType.SECURITY_POSTURE

    def test_has_five_sections(self, engine, period):
        start, end = period
        report = engine.generate_report(
            type=ReportType.SECURITY_POSTURE,
            period_start=start,
            period_end=end,
        )
        assert len(report.sections) == 5

    def test_has_risk_score_section(self, engine, period):
        start, end = period
        report = engine.generate_report(type=ReportType.SECURITY_POSTURE, period_start=start, period_end=end)
        titles = [s.title for s in report.sections]
        assert "Risk Score Summary" in titles

    def test_has_findings_section(self, engine, period):
        start, end = period
        report = engine.generate_report(type=ReportType.SECURITY_POSTURE, period_start=start, period_end=end)
        titles = [s.title for s in report.sections]
        assert "Finding Counts by Severity" in titles

    def test_has_mttr_mttd_section(self, engine, period):
        start, end = period
        report = engine.generate_report(type=ReportType.SECURITY_POSTURE, period_start=start, period_end=end)
        titles = [s.title for s in report.sections]
        assert "MTTR / MTTD Metrics" in titles

    def test_has_scanner_section(self, engine, period):
        start, end = period
        report = engine.generate_report(type=ReportType.SECURITY_POSTURE, period_start=start, period_end=end)
        titles = [s.title for s in report.sections]
        assert "Scanner Coverage Summary" in titles

    def test_has_top_findings_section(self, engine, period):
        start, end = period
        report = engine.generate_report(type=ReportType.SECURITY_POSTURE, period_start=start, period_end=end)
        titles = [s.title for s in report.sections]
        assert "Top 10 Critical Findings" in titles

    def test_risk_score_section_data_keys(self, engine, period):
        start, end = period
        report = engine.generate_report(type=ReportType.SECURITY_POSTURE, period_start=start, period_end=end)
        risk_section = next(s for s in report.sections if s.title == "Risk Score Summary")
        assert "current_score" in risk_section.data
        assert "trend" in risk_section.data
        assert "delta" in risk_section.data

    def test_mttr_section_data_keys(self, engine, period):
        start, end = period
        report = engine.generate_report(type=ReportType.SECURITY_POSTURE, period_start=start, period_end=end)
        mttr_section = next(s for s in report.sections if s.title == "MTTR / MTTD Metrics")
        assert "mttr_hours" in mttr_section.data
        assert "mttd_hours" in mttr_section.data

    def test_sections_ordered(self, engine, period):
        start, end = period
        report = engine.generate_report(type=ReportType.SECURITY_POSTURE, period_start=start, period_end=end)
        orders = [s.order for s in report.sections]
        assert orders == sorted(orders)


# ---------------------------------------------------------------------------
# Compliance Status report
# ---------------------------------------------------------------------------


class TestComplianceStatusReport:
    def test_generates_successfully(self, engine, period):
        start, end = period
        report = engine.generate_report(type=ReportType.COMPLIANCE_STATUS, period_start=start, period_end=end)
        assert report.type == ReportType.COMPLIANCE_STATUS

    def test_has_four_sections(self, engine, period):
        start, end = period
        report = engine.generate_report(type=ReportType.COMPLIANCE_STATUS, period_start=start, period_end=end)
        assert len(report.sections) == 4

    def test_all_seven_frameworks_in_scores(self, engine, period):
        start, end = period
        report = engine.generate_report(type=ReportType.COMPLIANCE_STATUS, period_start=start, period_end=end)
        scores_section = next(s for s in report.sections if s.title == "Per-Framework Compliance Scores")
        frameworks = scores_section.data.get("frameworks", {})
        expected = {"SOC2", "ISO27001", "NIST_CSF", "PCI_DSS", "HIPAA", "CIS_CONTROLS", "GDPR"}
        assert set(frameworks.keys()) == expected

    def test_all_seven_frameworks_in_controls(self, engine, period):
        start, end = period
        report = engine.generate_report(type=ReportType.COMPLIANCE_STATUS, period_start=start, period_end=end)
        controls_section = next(s for s in report.sections if s.title == "Control Pass/Fail Summary")
        controls = controls_section.data.get("controls", {})
        expected = {"SOC2", "ISO27001", "NIST_CSF", "PCI_DSS", "HIPAA", "CIS_CONTROLS", "GDPR"}
        assert set(controls.keys()) == expected

    def test_scores_in_valid_range(self, engine, period):
        start, end = period
        report = engine.generate_report(type=ReportType.COMPLIANCE_STATUS, period_start=start, period_end=end)
        scores_section = next(s for s in report.sections if s.title == "Per-Framework Compliance Scores")
        for fw, score in scores_section.data["frameworks"].items():
            assert 0 <= score <= 100, f"{fw} score {score} out of range"

    def test_has_gaps_section(self, engine, period):
        start, end = period
        report = engine.generate_report(type=ReportType.COMPLIANCE_STATUS, period_start=start, period_end=end)
        titles = [s.title for s in report.sections]
        assert "Gaps and Recommended Actions" in titles

    def test_controls_have_pass_fail_keys(self, engine, period):
        start, end = period
        report = engine.generate_report(type=ReportType.COMPLIANCE_STATUS, period_start=start, period_end=end)
        controls_section = next(s for s in report.sections if s.title == "Control Pass/Fail Summary")
        for fw, ctrl in controls_section.data["controls"].items():
            assert "passed" in ctrl
            assert "failed" in ctrl
            assert "total" in ctrl


# ---------------------------------------------------------------------------
# Risk Trends report
# ---------------------------------------------------------------------------


class TestRiskTrendsReport:
    def test_generates_successfully(self, engine, period):
        start, end = period
        report = engine.generate_report(type=ReportType.RISK_TRENDS, period_start=start, period_end=end)
        assert report.type == ReportType.RISK_TRENDS

    def test_has_four_sections(self, engine, period):
        start, end = period
        report = engine.generate_report(type=ReportType.RISK_TRENDS, period_start=start, period_end=end)
        assert len(report.sections) == 4

    def test_has_sla_section(self, engine, period):
        start, end = period
        report = engine.generate_report(type=ReportType.RISK_TRENDS, period_start=start, period_end=end)
        titles = [s.title for s in report.sections]
        assert "SLA Compliance Rate" in titles

    def test_sla_section_has_thresholds(self, engine, period):
        start, end = period
        report = engine.generate_report(type=ReportType.RISK_TRENDS, period_start=start, period_end=end)
        sla = next(s for s in report.sections if s.title == "SLA Compliance Rate")
        assert "sla_thresholds_hours" in sla.data
        assert "critical" in sla.data["sla_thresholds_hours"]


# ---------------------------------------------------------------------------
# Executive Summary report
# ---------------------------------------------------------------------------


class TestExecutiveSummaryReport:
    def test_generates_successfully(self, engine, period):
        start, end = period
        report = engine.generate_report(type=ReportType.EXECUTIVE_SUMMARY, period_start=start, period_end=end)
        assert report.type == ReportType.EXECUTIVE_SUMMARY

    def test_has_four_sections(self, engine, period):
        start, end = period
        report = engine.generate_report(type=ReportType.EXECUTIVE_SUMMARY, period_start=start, period_end=end)
        assert len(report.sections) == 4

    def test_has_key_highlights(self, engine, period):
        start, end = period
        report = engine.generate_report(type=ReportType.EXECUTIVE_SUMMARY, period_start=start, period_end=end)
        titles = [s.title for s in report.sections]
        assert "Key Highlights" in titles

    def test_highlights_contains_risk_and_compliance(self, engine, period):
        start, end = period
        report = engine.generate_report(type=ReportType.EXECUTIVE_SUMMARY, period_start=start, period_end=end)
        highlights = next(s for s in report.sections if s.title == "Key Highlights")
        assert "risk_score" in highlights.data
        assert "avg_compliance_score" in highlights.data
        assert "total_open_findings" in highlights.data

    def test_has_recommendations_section(self, engine, period):
        start, end = period
        report = engine.generate_report(type=ReportType.EXECUTIVE_SUMMARY, period_start=start, period_end=end)
        titles = [s.title for s in report.sections]
        assert "Recommended Actions" in titles

    def test_recommendations_are_prioritised(self, engine, period):
        start, end = period
        report = engine.generate_report(type=ReportType.EXECUTIVE_SUMMARY, period_start=start, period_end=end)
        rec_section = next(s for s in report.sections if s.title == "Recommended Actions")
        recs = rec_section.data.get("recommendations", [])
        assert len(recs) >= 1
        for r in recs:
            assert "priority" in r
            assert "action" in r

    def test_has_budget_impact_section(self, engine, period):
        start, end = period
        report = engine.generate_report(type=ReportType.EXECUTIVE_SUMMARY, period_start=start, period_end=end)
        titles = [s.title for s in report.sections]
        assert "Budget Impact Assessment" in titles

    def test_has_board_risks_section(self, engine, period):
        start, end = period
        report = engine.generate_report(type=ReportType.EXECUTIVE_SUMMARY, period_start=start, period_end=end)
        titles = [s.title for s in report.sections]
        assert "Key Risks Requiring Board Attention" in titles


# ---------------------------------------------------------------------------
# Incident Summary and Scanner Effectiveness
# ---------------------------------------------------------------------------


class TestIncidentSummaryReport:
    def test_generates_successfully(self, engine, period):
        start, end = period
        report = engine.generate_report(type=ReportType.INCIDENT_SUMMARY, period_start=start, period_end=end)
        assert report.type == ReportType.INCIDENT_SUMMARY
        assert len(report.sections) == 4

    def test_has_incident_volume_section(self, engine, period):
        start, end = period
        report = engine.generate_report(type=ReportType.INCIDENT_SUMMARY, period_start=start, period_end=end)
        titles = [s.title for s in report.sections]
        assert "Incident Volume" in titles


class TestScannerEffectivenessReport:
    def test_generates_successfully(self, engine, period):
        start, end = period
        report = engine.generate_report(type=ReportType.SCANNER_EFFECTIVENESS, period_start=start, period_end=end)
        assert report.type == ReportType.SCANNER_EFFECTIVENESS
        assert len(report.sections) == 4

    def test_has_performance_overview_section(self, engine, period):
        start, end = period
        report = engine.generate_report(type=ReportType.SCANNER_EFFECTIVENESS, period_start=start, period_end=end)
        titles = [s.title for s in report.sections]
        assert "Scanner Performance Overview" in titles


# ---------------------------------------------------------------------------
# Persistence: get and list
# ---------------------------------------------------------------------------


class TestReportPersistence:
    def test_get_report_by_id(self, engine, period):
        start, end = period
        report = engine.generate_report(type=ReportType.SECURITY_POSTURE, period_start=start, period_end=end)
        fetched = engine.get_report(report.id)
        assert fetched is not None
        assert fetched.id == report.id
        assert fetched.type == ReportType.SECURITY_POSTURE

    def test_get_report_not_found_returns_none(self, engine):
        result = engine.get_report("nonexistent-id")
        assert result is None

    def test_list_reports_returns_generated(self, engine, period):
        start, end = period
        engine.generate_report(type=ReportType.SECURITY_POSTURE, period_start=start, period_end=end)
        engine.generate_report(type=ReportType.COMPLIANCE_STATUS, period_start=start, period_end=end)
        reports = engine.list_reports(org_id="default")
        assert len(reports) >= 2

    def test_list_reports_type_filter(self, engine, period):
        start, end = period
        engine.generate_report(type=ReportType.SECURITY_POSTURE, period_start=start, period_end=end)
        engine.generate_report(type=ReportType.COMPLIANCE_STATUS, period_start=start, period_end=end)
        posture_only = engine.list_reports(org_id="default", type_filter=ReportType.SECURITY_POSTURE)
        assert all(r.type == ReportType.SECURITY_POSTURE for r in posture_only)

    def test_list_reports_multi_org_isolation(self, engine, period):
        start, end = period
        engine.generate_report(type=ReportType.SECURITY_POSTURE, org_id="org-a", period_start=start, period_end=end)
        engine.generate_report(type=ReportType.SECURITY_POSTURE, org_id="org-b", period_start=start, period_end=end)
        org_a_reports = engine.list_reports(org_id="org-a")
        org_b_reports = engine.list_reports(org_id="org-b")
        assert all(r.org_id == "org-a" for r in org_a_reports)
        assert all(r.org_id == "org-b" for r in org_b_reports)

    def test_sections_round_trip(self, engine, period):
        start, end = period
        original = engine.generate_report(type=ReportType.SECURITY_POSTURE, period_start=start, period_end=end)
        fetched = engine.get_report(original.id)
        assert len(fetched.sections) == len(original.sections)
        for orig_s, fetched_s in zip(original.sections, fetched.sections):
            assert orig_s.title == fetched_s.title
            assert orig_s.order == fetched_s.order


# ---------------------------------------------------------------------------
# JSON export
# ---------------------------------------------------------------------------


class TestJsonExport:
    def test_export_returns_valid_json_string(self, engine, period):
        start, end = period
        report = engine.generate_report(type=ReportType.SECURITY_POSTURE, period_start=start, period_end=end)
        exported = engine.export_json(report.id)
        assert isinstance(exported, str)
        parsed = json.loads(exported)
        assert isinstance(parsed, dict)

    def test_export_contains_report_id(self, engine, period):
        start, end = period
        report = engine.generate_report(type=ReportType.SECURITY_POSTURE, period_start=start, period_end=end)
        exported = engine.export_json(report.id)
        parsed = json.loads(exported)
        assert parsed.get("id") == report.id

    def test_export_contains_sections(self, engine, period):
        start, end = period
        report = engine.generate_report(type=ReportType.SECURITY_POSTURE, period_start=start, period_end=end)
        exported = engine.export_json(report.id)
        parsed = json.loads(exported)
        assert "sections" in parsed
        assert len(parsed["sections"]) > 0

    def test_export_not_found_returns_empty_object(self, engine):
        exported = engine.export_json("nonexistent-id")
        assert exported == json.dumps({})

    def test_export_all_report_types(self, engine, period):
        start, end = period
        for rtype in ReportType:
            report = engine.generate_report(type=rtype, period_start=start, period_end=end)
            exported = engine.export_json(report.id)
            parsed = json.loads(exported)
            assert parsed["type"] == rtype.value


# ---------------------------------------------------------------------------
# Schedule CRUD
# ---------------------------------------------------------------------------


class TestScheduleCRUD:
    def test_create_schedule(self, engine):
        schedule = engine.schedule_report(
            report_type=ReportType.SECURITY_POSTURE,
            frequency=ReportFrequency.WEEKLY,
            recipients=["ciso@example.com"],
        )
        assert schedule.id is not None
        assert schedule.report_type == ReportType.SECURITY_POSTURE
        assert schedule.frequency == ReportFrequency.WEEKLY
        assert "ciso@example.com" in schedule.recipients

    def test_list_schedules(self, engine):
        engine.schedule_report(ReportType.SECURITY_POSTURE, ReportFrequency.WEEKLY, ["a@b.com"])
        engine.schedule_report(ReportType.COMPLIANCE_STATUS, ReportFrequency.MONTHLY, ["b@c.com"])
        schedules = engine.list_schedules()
        assert len(schedules) >= 2

    def test_delete_schedule(self, engine):
        schedule = engine.schedule_report(
            report_type=ReportType.RISK_TRENDS,
            frequency=ReportFrequency.MONTHLY,
            recipients=[],
        )
        result = engine.delete_schedule(schedule.id)
        assert result is True
        remaining = engine.list_schedules()
        assert not any(s.id == schedule.id for s in remaining)

    def test_delete_nonexistent_schedule_returns_false(self, engine):
        result = engine.delete_schedule("nonexistent-id")
        assert result is False

    def test_schedule_next_run_is_future(self, engine):
        schedule = engine.schedule_report(
            report_type=ReportType.EXECUTIVE_SUMMARY,
            frequency=ReportFrequency.QUARTERLY,
            recipients=["board@example.com"],
        )
        next_run = datetime.fromisoformat(schedule.next_run)
        assert next_run > datetime.now(timezone.utc)

    def test_schedule_multi_org_isolation(self, engine):
        engine.schedule_report(ReportType.SECURITY_POSTURE, ReportFrequency.WEEKLY, [], org_id="org-x")
        engine.schedule_report(ReportType.COMPLIANCE_STATUS, ReportFrequency.MONTHLY, [], org_id="org-y")
        x_schedules = engine.list_schedules(org_id="org-x")
        y_schedules = engine.list_schedules(org_id="org-y")
        assert all(s.org_id == "org-x" for s in x_schedules)
        assert all(s.org_id == "org-y" for s in y_schedules)

    def test_schedule_recipients_persist(self, engine):
        recipients = ["alpha@example.com", "beta@example.com", "gamma@example.com"]
        schedule = engine.schedule_report(
            report_type=ReportType.EXECUTIVE_SUMMARY,
            frequency=ReportFrequency.MONTHLY,
            recipients=recipients,
        )
        all_schedules = engine.list_schedules()
        persisted = next(s for s in all_schedules if s.id == schedule.id)
        assert persisted.recipients == recipients


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_report_with_same_start_end(self, engine, now):
        """Zero-day period should not crash."""
        report = engine.generate_report(
            type=ReportType.SECURITY_POSTURE,
            period_start=now,
            period_end=now,
        )
        assert report is not None
        assert len(report.sections) > 0

    def test_report_defaults_period(self, engine):
        """Calling without explicit period should use default 30-day window."""
        report = engine.generate_report(type=ReportType.RISK_TRENDS)
        assert report.period_start is not None
        assert report.period_end is not None

    def test_report_metadata_has_section_count(self, engine, period):
        start, end = period
        report = engine.generate_report(type=ReportType.SECURITY_POSTURE, period_start=start, period_end=end)
        assert "section_count" in report.metadata
        assert report.metadata["section_count"] == len(report.sections)

    def test_all_report_types_generate(self, engine, period):
        start, end = period
        for rtype in ReportType:
            report = engine.generate_report(type=rtype, period_start=start, period_end=end)
            assert isinstance(report, ExecutiveReport)
            assert len(report.sections) > 0
