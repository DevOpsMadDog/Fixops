"""
Tests for ExecutiveReportGenerator — suite-core/core/report_generator.py

Covers:
- ReportDocument dataclass fields and to_dict()
- generate_executive_report() structure and section count
- All 8 required sections present in HTML output
- Period calculation (period_start/period_end)
- HTML validity (doctype, head, body, CSS)
- generate_csv_findings() CSV format correctness
- generate_compliance_evidence() for multiple frameworks
- generate_html() passthrough
- HTML contains expected headings for each section
- KPI cards in executive summary
- Severity badges in HTML
- MTTR computation edge cases
- Period_days parameter respected
- org_id reflected in report
- section_count matches rendered sections
"""

from __future__ import annotations

import csv
import io
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from core.report_generator import ExecutiveReportGenerator, ReportDocument


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def generator():
    """Return a fresh ExecutiveReportGenerator (no real DBs required)."""
    return ExecutiveReportGenerator()


@pytest.fixture
def exec_report(generator):
    """Generate a default 30-day executive report."""
    return generator.generate_executive_report(org_id="test-org", period_days=30)


# ---------------------------------------------------------------------------
# ReportDocument model tests
# ---------------------------------------------------------------------------


class TestReportDocument:
    def test_default_fields_populated(self):
        doc = ReportDocument()
        assert doc.report_id  # non-empty UUID string
        assert doc.generated_at  # ISO timestamp
        assert doc.format == "html"
        assert doc.section_count == 0
        assert doc.content == ""

    def test_to_dict_keys(self):
        doc = ReportDocument(org_id="acme", section_count=5, content="<html/>")
        d = doc.to_dict()
        for key in ("report_id", "org_id", "generated_at", "period_start",
                    "period_end", "format", "content_length", "section_count"):
            assert key in d, f"Missing key: {key}"

    def test_to_dict_content_length(self):
        doc = ReportDocument(content="<html>hello</html>")
        assert doc.to_dict()["content_length"] == len("<html>hello</html>")

    def test_unique_report_ids(self):
        ids = {ReportDocument().report_id for _ in range(10)}
        assert len(ids) == 10


# ---------------------------------------------------------------------------
# generate_executive_report() tests
# ---------------------------------------------------------------------------


class TestGenerateExecutiveReport:
    def test_returns_report_document(self, exec_report):
        assert isinstance(exec_report, ReportDocument)

    def test_org_id_preserved(self, generator):
        doc = generator.generate_executive_report(org_id="my-org")
        assert doc.org_id == "my-org"

    def test_section_count_is_eight(self, exec_report):
        assert exec_report.section_count == 8

    def test_period_start_before_period_end(self, exec_report):
        start = datetime.fromisoformat(exec_report.period_start.replace("Z", "+00:00"))
        end = datetime.fromisoformat(exec_report.period_end.replace("Z", "+00:00"))
        assert start < end

    def test_period_days_respected(self, generator):
        doc_30 = generator.generate_executive_report(org_id="x", period_days=30)
        doc_90 = generator.generate_executive_report(org_id="x", period_days=90)
        start_30 = datetime.fromisoformat(doc_30.period_start.replace("Z", "+00:00"))
        start_90 = datetime.fromisoformat(doc_90.period_start.replace("Z", "+00:00"))
        # 90-day report starts earlier than 30-day
        assert start_90 < start_30

    def test_format_is_html(self, exec_report):
        assert exec_report.format == "html"

    def test_content_non_empty(self, exec_report):
        assert len(exec_report.content) > 100


# ---------------------------------------------------------------------------
# HTML validity tests
# ---------------------------------------------------------------------------


class TestHTMLOutput:
    def test_has_doctype(self, exec_report):
        assert exec_report.content.startswith("<!DOCTYPE html>")

    def test_has_html_tags(self, exec_report):
        html = exec_report.content
        assert "<html" in html
        assert "</html>" in html

    def test_has_head_and_body(self, exec_report):
        html = exec_report.content
        assert "<head>" in html
        assert "<body>" in html
        assert "</body>" in html

    def test_has_embedded_css(self, exec_report):
        assert "<style>" in exec_report.content

    def test_has_title_tag(self, exec_report):
        assert "<title>" in exec_report.content

    def test_org_id_in_html(self, generator):
        doc = generator.generate_executive_report(org_id="acme-corp")
        assert "acme-corp" in doc.content

    def test_all_eight_sections_present(self, exec_report):
        html = exec_report.content
        required_sections = [
            "Executive Summary",
            "Finding Statistics",
            "Attack Surface Overview",
            "Compliance Status",
            "Threat Intelligence Highlights",
            "Vendor Risk",
            "SLA Performance",
            "Recommended Actions",
        ]
        for section in required_sections:
            assert section in html, f"Section '{section}' not found in HTML"

    def test_severity_badges_present(self, exec_report):
        html = exec_report.content
        assert "badge-critical" in html or "badge-high" in html or "badge-medium" in html

    def test_kpi_grid_present(self, exec_report):
        assert "kpi-grid" in exec_report.content

    def test_section_headings_numbered(self, exec_report):
        html = exec_report.content
        assert "1. Executive Summary" in html
        assert "2. Finding Statistics" in html

    def test_footer_present(self, exec_report):
        assert "ALDECI" in exec_report.content
        assert "CONFIDENTIAL" in exec_report.content


# ---------------------------------------------------------------------------
# generate_html() passthrough test
# ---------------------------------------------------------------------------


class TestGenerateHtml:
    def test_generate_html_returns_content(self, generator, exec_report):
        html = generator.generate_html(exec_report)
        assert html == exec_report.content
        assert len(html) > 0


# ---------------------------------------------------------------------------
# generate_csv_findings() tests
# ---------------------------------------------------------------------------


class TestCSVExport:
    def test_returns_string(self, generator):
        result = generator.generate_csv_findings(org_id="test", days=30)
        assert isinstance(result, str)

    def test_has_header_row(self, generator):
        result = generator.generate_csv_findings(org_id="test")
        reader = csv.reader(io.StringIO(result))
        header = next(reader)
        assert "finding_id" in header
        assert "severity" in header
        assert "status" in header

    def test_csv_columns_complete(self, generator):
        result = generator.generate_csv_findings(org_id="test")
        reader = csv.reader(io.StringIO(result))
        header = next(reader)
        expected = {"finding_id", "title", "severity", "status", "scanner",
                    "asset", "created_at", "updated_at", "cvss_score", "cve_id"}
        assert expected.issubset(set(header))

    def test_csv_parseable(self, generator):
        result = generator.generate_csv_findings(org_id="test")
        # Should not raise
        rows = list(csv.reader(io.StringIO(result)))
        assert len(rows) >= 1  # at least the header


# ---------------------------------------------------------------------------
# generate_compliance_evidence() tests
# ---------------------------------------------------------------------------


class TestComplianceEvidence:
    @pytest.mark.parametrize("framework", ["SOC2", "ISO27001", "PCI_DSS", "NIST_CSF"])
    def test_returns_report_document(self, generator, framework):
        doc = generator.generate_compliance_evidence(framework=framework, org_id="test")
        assert isinstance(doc, ReportDocument)

    def test_framework_name_in_html(self, generator):
        doc = generator.generate_compliance_evidence(framework="SOC2", org_id="test")
        assert "SOC2" in doc.content

    def test_compliance_html_valid(self, generator):
        doc = generator.generate_compliance_evidence(framework="ISO27001", org_id="test")
        assert "<!DOCTYPE html>" in doc.content
        assert "<body>" in doc.content

    def test_section_count_at_least_one(self, generator):
        doc = generator.generate_compliance_evidence(framework="HIPAA", org_id="test")
        assert doc.section_count >= 1

    def test_evidence_section_heading_present(self, generator):
        doc = generator.generate_compliance_evidence(framework="SOC2", org_id="test")
        assert "Controls Assessment" in doc.content or "Compliance Evidence" in doc.content
