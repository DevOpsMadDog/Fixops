"""Tests for ReportDB — report management database."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

import pytest
from core.report_models import (
    Report,
    ReportFormat,
    ReportSchedule,
    ReportStatus,
    ReportTemplate,
    ReportType,
)


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------
class TestReportModels:
    def test_report_type_enum(self):
        assert ReportType.SECURITY_SUMMARY == "security_summary"
        assert ReportType.COMPLIANCE == "compliance"
        assert ReportType.VULNERABILITY == "vulnerability"
        assert ReportType.AUDIT == "audit"
        assert ReportType.CUSTOM == "custom"

    def test_report_format_enum(self):
        assert ReportFormat.PDF == "pdf"
        assert ReportFormat.HTML == "html"
        assert ReportFormat.JSON == "json"
        assert ReportFormat.CSV == "csv"
        assert ReportFormat.SARIF == "sarif"

    def test_report_status_enum(self):
        assert ReportStatus.PENDING == "pending"
        assert ReportStatus.GENERATING == "generating"
        assert ReportStatus.COMPLETED == "completed"
        assert ReportStatus.FAILED == "failed"

    def test_report_to_dict(self):
        report = Report(
            id="r1",
            name="Security Summary Q1",
            report_type=ReportType.SECURITY_SUMMARY,
            format=ReportFormat.PDF,
            status=ReportStatus.COMPLETED,
            parameters={"quarter": "Q1"},
            file_path="/reports/summary.pdf",
            file_size=1024,
            generated_by="admin",
        )
        d = report.to_dict()
        assert d["id"] == "r1"
        assert d["report_type"] == "security_summary"
        assert d["format"] == "pdf"
        assert d["status"] == "completed"
        assert d["file_size"] == 1024

    def test_report_schedule_to_dict(self):
        sched = ReportSchedule(
            id="s1",
            report_type=ReportType.COMPLIANCE,
            format=ReportFormat.HTML,
            schedule_cron="0 0 * * 1",
            enabled=True,
        )
        d = sched.to_dict()
        assert d["id"] == "s1"
        assert d["schedule_cron"] == "0 0 * * 1"
        assert d["enabled"] is True

    def test_report_template_to_dict(self):
        tmpl = ReportTemplate(
            id="t1",
            name="Monthly Vuln Report",
            report_type=ReportType.VULNERABILITY,
            description="Monthly vulnerability summary",
            template_config={"sections": ["summary", "details"]},
        )
        d = tmpl.to_dict()
        assert d["id"] == "t1"
        assert d["name"] == "Monthly Vuln Report"
        assert d["template_config"]["sections"] == ["summary", "details"]


# ---------------------------------------------------------------------------
# ReportDB tests
# ---------------------------------------------------------------------------
class TestReportDB:
    @pytest.fixture
    def db(self, tmp_path):
        from core.report_db import ReportDB
        return ReportDB(db_path=str(tmp_path / "test_reports.db"))

    @pytest.fixture
    def sample_report(self, db):
        report = Report(
            id="",
            name="Test Report",
            report_type=ReportType.SECURITY_SUMMARY,
            format=ReportFormat.JSON,
            status=ReportStatus.PENDING,
            parameters={"scope": "all"},
        )
        return db.create_report(report)

    def test_create_report(self, db):
        report = Report(
            id="",
            name="New Report",
            report_type=ReportType.AUDIT,
            format=ReportFormat.PDF,
            status=ReportStatus.PENDING,
        )
        created = db.create_report(report)
        assert created.id != ""
        assert created.name == "New Report"

    def test_get_report(self, db, sample_report):
        report = db.get_report(sample_report.id)
        assert report is not None
        assert report.name == "Test Report"
        assert report.report_type == ReportType.SECURITY_SUMMARY

    def test_get_report_not_found(self, db):
        assert db.get_report("nonexistent") is None

    def test_list_reports(self, db, sample_report):
        reports = db.list_reports()
        assert len(reports) >= 1

    def test_list_reports_by_type(self, db):
        db.create_report(Report(
            id="",
            name="Vuln Report",
            report_type=ReportType.VULNERABILITY,
            format=ReportFormat.JSON,
            status=ReportStatus.COMPLETED,
        ))
        db.create_report(Report(
            id="",
            name="Audit Report",
            report_type=ReportType.AUDIT,
            format=ReportFormat.PDF,
            status=ReportStatus.COMPLETED,
        ))
        vuln_reports = db.list_reports(report_type="vulnerability")
        assert len(vuln_reports) == 1
        assert vuln_reports[0].name == "Vuln Report"

    def test_update_report(self, db, sample_report):
        from datetime import datetime
        sample_report.status = ReportStatus.COMPLETED
        sample_report.file_path = "/reports/test.json"
        sample_report.file_size = 2048
        sample_report.completed_at = datetime.utcnow()
        updated = db.update_report(sample_report)
        assert updated.status == ReportStatus.COMPLETED
        # Verify from DB
        from_db = db.get_report(sample_report.id)
        assert from_db.status == ReportStatus.COMPLETED
        assert from_db.file_path == "/reports/test.json"

    def test_delete_report(self, db, sample_report):
        result = db.delete_report(sample_report.id)
        assert result is True
        assert db.get_report(sample_report.id) is None

    def test_list_reports_pagination(self, db):
        for i in range(5):
            db.create_report(Report(
                id="",
                name=f"Report {i}",
                report_type=ReportType.CUSTOM,
                format=ReportFormat.CSV,
                status=ReportStatus.PENDING,
            ))
        page1 = db.list_reports(limit=3)
        page2 = db.list_reports(limit=3, offset=3)
        assert len(page1) == 3
        assert len(page2) == 2


# ---------------------------------------------------------------------------
# Schedule tests
# ---------------------------------------------------------------------------
class TestReportScheduleDB:
    @pytest.fixture
    def db(self, tmp_path):
        from core.report_db import ReportDB
        return ReportDB(db_path=str(tmp_path / "test_schedules.db"))

    def test_create_schedule(self, db):
        sched = ReportSchedule(
            id="",
            report_type=ReportType.COMPLIANCE,
            format=ReportFormat.PDF,
            schedule_cron="0 9 * * 1",
            enabled=True,
            created_by="admin",
        )
        created = db.create_schedule(sched)
        assert created.id != ""

    def test_list_schedules(self, db):
        db.create_schedule(ReportSchedule(
            id="",
            report_type=ReportType.SECURITY_SUMMARY,
            format=ReportFormat.HTML,
            schedule_cron="0 0 1 * *",
            enabled=True,
        ))
        schedules = db.list_schedules()
        assert len(schedules) >= 1


# ---------------------------------------------------------------------------
# Template tests
# ---------------------------------------------------------------------------
class TestReportTemplateDB:
    @pytest.fixture
    def db(self, tmp_path):
        from core.report_db import ReportDB
        return ReportDB(db_path=str(tmp_path / "test_templates.db"))

    def test_create_template(self, db):
        tmpl = ReportTemplate(
            id="",
            name="Weekly Security",
            report_type=ReportType.SECURITY_SUMMARY,
            description="Weekly security summary template",
            template_config={"header": "Security Report"},
        )
        created = db.create_template(tmpl)
        assert created.id != ""

    def test_list_templates(self, db):
        db.create_template(ReportTemplate(
            id="",
            name="Template 1",
            report_type=ReportType.VULNERABILITY,
            description="Vuln template",
        ))
        templates = db.list_templates()
        assert len(templates) >= 1
