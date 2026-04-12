"""
Report Builder Test Suite — 30+ tests covering:
- ReportBuilder CRUD for templates
- Report generation with data population
- Export (JSON + HTML)
- Template cloning
- Stats
- Metadata endpoints (section types, data sources)
- Edge cases (missing IDs, empty sections, updates)

Run with:
    python -m pytest tests/test_report_builder.py -x --tb=short --timeout=10 -q
"""

from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

from core.report_builder import (
    DataSource,
    GeneratedReport,
    ReportBuilder,
    ReportSection,
    ReportTemplate,
    SectionType,
    _fetch_data,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def builder(tmp_path):
    """Fresh ReportBuilder backed by a temporary SQLite database."""
    return ReportBuilder(db_path=tmp_path / "test_reports.db")


def _make_section(
    section_type: SectionType = SectionType.TABLE,
    data_source: DataSource = DataSource.FINDINGS,
    order: int = 0,
) -> ReportSection:
    return ReportSection(
        type=section_type,
        title=f"Test Section ({section_type.value})",
        data_source=data_source,
        filters={"severity": "critical"},
        config={"limit": 10},
        order=order,
    )


def _make_template(name: str = "Test Report", org_id: str = "default") -> ReportTemplate:
    return ReportTemplate(
        name=name,
        description="A test report template",
        sections=[
            _make_section(SectionType.TABLE, DataSource.FINDINGS, order=0),
            _make_section(SectionType.CHART_BAR, DataSource.COMPLIANCE, order=1),
        ],
        schedule="weekly",
        recipients=["ciso@example.com", "soc@example.com"],
        org_id=org_id,
        created_by="test_user",
    )


# ============================================================================
# Enum tests
# ============================================================================


class TestEnums:
    def test_section_type_values(self):
        expected = {
            "text", "table", "chart_line", "chart_bar", "chart_pie",
            "kpi_grid", "finding_list", "compliance_matrix", "risk_heatmap",
            "executive_summary",
        }
        assert {st.value for st in SectionType} == expected

    def test_data_source_values(self):
        expected = {
            "findings", "compliance", "posture", "sla", "attack_surface",
            "vulnerabilities", "scanners", "incidents", "vendors",
        }
        assert {ds.value for ds in DataSource} == expected

    def test_section_type_count(self):
        assert len(SectionType) == 10

    def test_data_source_count(self):
        assert len(DataSource) == 9


# ============================================================================
# Pydantic model tests
# ============================================================================


class TestModels:
    def test_report_section_defaults(self):
        s = ReportSection(
            type=SectionType.TEXT,
            title="Intro",
            data_source=DataSource.POSTURE,
        )
        assert s.id is not None
        assert s.filters == {}
        assert s.config == {}
        assert s.order == 0

    def test_report_section_unique_ids(self):
        s1 = _make_section()
        s2 = _make_section()
        assert s1.id != s2.id

    def test_report_template_defaults(self):
        t = ReportTemplate(name="T1")
        assert t.id is not None
        assert t.org_id == "default"
        assert t.sections == []
        assert t.recipients == []
        assert t.schedule is None
        assert t.created_by == "system"

    def test_generated_report_defaults(self):
        r = GeneratedReport(template_id="abc")
        assert r.id is not None
        assert r.sections_data == []
        assert r.org_id == "default"
        assert r.generated_at is not None


# ============================================================================
# Template CRUD tests
# ============================================================================


class TestTemplateCRUD:
    def test_create_and_get_template(self, builder):
        tmpl = _make_template()
        created = builder.create_template(tmpl)
        assert created.id == tmpl.id
        assert created.name == "Test Report"

        fetched = builder.get_template(tmpl.id)
        assert fetched is not None
        assert fetched.name == "Test Report"
        assert fetched.org_id == "default"
        assert len(fetched.sections) == 2

    def test_get_template_not_found(self, builder):
        result = builder.get_template("nonexistent-id")
        assert result is None

    def test_list_templates_empty(self, builder):
        assert builder.list_templates() == []

    def test_list_templates_returns_all(self, builder):
        builder.create_template(_make_template("Report A"))
        builder.create_template(_make_template("Report B"))
        builder.create_template(_make_template("Report C"))
        templates = builder.list_templates()
        assert len(templates) == 3
        names = {t.name for t in templates}
        assert names == {"Report A", "Report B", "Report C"}

    def test_list_templates_org_isolation(self, builder):
        builder.create_template(_make_template("Org1 Report", org_id="org1"))
        builder.create_template(_make_template("Org2 Report", org_id="org2"))
        org1 = builder.list_templates(org_id="org1")
        org2 = builder.list_templates(org_id="org2")
        assert len(org1) == 1
        assert len(org2) == 1
        assert org1[0].name == "Org1 Report"

    def test_update_template_name(self, builder):
        tmpl = builder.create_template(_make_template())
        updated = builder.update_template(tmpl.id, {"name": "Updated Name"})
        assert updated is not None
        assert updated.name == "Updated Name"
        # description unchanged
        assert updated.description == "A test report template"

    def test_update_template_sections(self, builder):
        tmpl = builder.create_template(_make_template())
        new_sections = [
            {
                "id": str(uuid.uuid4()),
                "type": "kpi_grid",
                "title": "KPI Section",
                "data_source": "posture",
                "filters": {},
                "config": {},
                "order": 0,
            }
        ]
        updated = builder.update_template(tmpl.id, {"sections": new_sections})
        assert updated is not None
        assert len(updated.sections) == 1
        assert updated.sections[0].type == SectionType.KPI_GRID

    def test_update_template_recipients(self, builder):
        tmpl = builder.create_template(_make_template())
        updated = builder.update_template(tmpl.id, {"recipients": ["new@example.com"]})
        assert updated is not None
        assert updated.recipients == ["new@example.com"]

    def test_update_template_not_found(self, builder):
        result = builder.update_template("ghost-id", {"name": "X"})
        assert result is None

    def test_delete_template(self, builder):
        tmpl = builder.create_template(_make_template())
        deleted = builder.delete_template(tmpl.id)
        assert deleted is True
        assert builder.get_template(tmpl.id) is None

    def test_delete_template_not_found(self, builder):
        result = builder.delete_template("ghost-id")
        assert result is False

    def test_template_sections_persist(self, builder):
        tmpl = _make_template()
        tmpl.sections[0].filters = {"severity": "high"}
        builder.create_template(tmpl)
        fetched = builder.get_template(tmpl.id)
        assert fetched.sections[0].filters == {"severity": "high"}
        assert fetched.sections[0].config == {"limit": 10}

    def test_template_schedule_persists(self, builder):
        tmpl = builder.create_template(_make_template())
        fetched = builder.get_template(tmpl.id)
        assert fetched.schedule == "weekly"

    def test_template_recipients_persist(self, builder):
        tmpl = builder.create_template(_make_template())
        fetched = builder.get_template(tmpl.id)
        assert "ciso@example.com" in fetched.recipients
        assert "soc@example.com" in fetched.recipients


# ============================================================================
# Report generation tests
# ============================================================================


class TestReportGeneration:
    def test_generate_report(self, builder):
        tmpl = builder.create_template(_make_template())
        report = builder.generate_report(tmpl.id)
        assert report is not None
        assert report.template_id == tmpl.id
        assert report.template_name == tmpl.name
        assert len(report.sections_data) == 2

    def test_generate_report_section_structure(self, builder):
        tmpl = builder.create_template(_make_template())
        report = builder.generate_report(tmpl.id)
        for section in report.sections_data:
            assert "section_id" in section
            assert "section_type" in section
            assert "title" in section
            assert "data_source" in section
            assert "data" in section
            assert "order" in section

    def test_generate_report_sections_ordered(self, builder):
        tmpl = _make_template()
        # reverse the order to ensure sorting happens
        tmpl.sections[0].order = 5
        tmpl.sections[1].order = 1
        builder.create_template(tmpl)
        report = builder.generate_report(tmpl.id)
        orders = [s["order"] for s in report.sections_data]
        assert orders == sorted(orders)

    def test_generate_report_not_found(self, builder):
        result = builder.generate_report("ghost-template-id")
        assert result is None

    def test_generate_report_persisted(self, builder):
        tmpl = builder.create_template(_make_template())
        report = builder.generate_report(tmpl.id)
        fetched = builder.get_report(report.id)
        assert fetched is not None
        assert fetched.id == report.id

    def test_get_report_not_found(self, builder):
        assert builder.get_report("ghost-report-id") is None

    def test_list_reports_empty(self, builder):
        assert builder.list_reports() == []

    def test_list_reports_returns_all(self, builder):
        tmpl = builder.create_template(_make_template())
        builder.generate_report(tmpl.id)
        builder.generate_report(tmpl.id)
        reports = builder.list_reports()
        assert len(reports) == 2

    def test_list_reports_org_isolation(self, builder):
        t1 = builder.create_template(_make_template(org_id="org1"))
        t2 = builder.create_template(_make_template(org_id="org2"))
        builder.generate_report(t1.id)
        builder.generate_report(t2.id)
        assert len(builder.list_reports(org_id="org1")) == 1
        assert len(builder.list_reports(org_id="org2")) == 1

    def test_generate_report_all_data_sources(self, builder):
        """Each DataSource should produce data without raising."""
        for ds in DataSource:
            section = _make_section(SectionType.TABLE, ds)
            tmpl = ReportTemplate(
                name=f"ds-test-{ds.value}",
                sections=[section],
            )
            builder.create_template(tmpl)
            report = builder.generate_report(tmpl.id)
            assert report is not None
            assert report.sections_data[0]["data_source"] == ds.value


# ============================================================================
# Export tests
# ============================================================================


class TestExport:
    def test_export_json(self, builder):
        tmpl = builder.create_template(_make_template())
        report = builder.generate_report(tmpl.id)
        exported = builder.export_report(report.id, format="json")
        assert exported is not None
        parsed = json.loads(exported)
        assert parsed["id"] == report.id
        assert "sections_data" in parsed

    def test_export_html(self, builder):
        tmpl = builder.create_template(_make_template())
        report = builder.generate_report(tmpl.id)
        html = builder.export_report(report.id, format="html")
        assert html is not None
        assert "<!DOCTYPE html>" in html
        assert tmpl.name in html
        assert "<section class='report-section'>" in html

    def test_export_not_found(self, builder):
        result = builder.export_report("ghost-id", format="json")
        assert result is None

    def test_export_default_format_is_json(self, builder):
        tmpl = builder.create_template(_make_template())
        report = builder.generate_report(tmpl.id)
        exported = builder.export_report(report.id)
        parsed = json.loads(exported)
        assert parsed["id"] == report.id


# ============================================================================
# Clone tests
# ============================================================================


class TestClone:
    def test_clone_template(self, builder):
        original = builder.create_template(_make_template("Original"))
        clone = builder.clone_template(original.id, new_name="Cloned Report")
        assert clone is not None
        assert clone.id != original.id
        assert clone.name == "Cloned Report"
        assert clone.org_id == original.org_id
        assert clone.description == original.description

    def test_clone_template_sections_copied(self, builder):
        original = builder.create_template(_make_template())
        clone = builder.clone_template(original.id, new_name="Clone")
        assert len(clone.sections) == len(original.sections)
        # Section IDs should be different (new IDs assigned)
        original_ids = {s.id for s in original.sections}
        clone_ids = {s.id for s in clone.sections}
        assert original_ids.isdisjoint(clone_ids)

    def test_clone_template_not_found(self, builder):
        result = builder.clone_template("ghost-id", new_name="X")
        assert result is None

    def test_clone_is_independent(self, builder):
        """Updating clone should not affect original."""
        original = builder.create_template(_make_template("Original"))
        clone = builder.clone_template(original.id, new_name="Clone")
        builder.update_template(clone.id, {"name": "Modified Clone"})
        original_fetched = builder.get_template(original.id)
        assert original_fetched.name == "Original"


# ============================================================================
# Metadata tests
# ============================================================================


class TestMetadata:
    def test_get_section_types(self, builder):
        types = builder.get_section_types()
        assert len(types) == 10
        keys = {t["key"] for t in types}
        assert "executive_summary" in keys
        assert "risk_heatmap" in keys

    def test_section_types_have_description(self, builder):
        for st in builder.get_section_types():
            assert "description" in st
            assert len(st["description"]) > 0

    def test_get_data_sources(self, builder):
        sources = builder.get_available_data_sources()
        assert len(sources) == 9
        keys = {s["key"] for s in sources}
        assert "findings" in keys
        assert "vendors" in keys

    def test_data_sources_have_label(self, builder):
        for ds in builder.get_available_data_sources():
            assert "label" in ds
            assert len(ds["label"]) > 0


# ============================================================================
# Stats tests
# ============================================================================


class TestStats:
    def test_stats_empty(self, builder):
        stats = builder.get_builder_stats()
        assert stats["templates"] == 0
        assert stats["generated_reports"] == 0
        assert stats["scheduled_templates"] == 0
        assert stats["last_report_generated"] is None

    def test_stats_after_create(self, builder):
        builder.create_template(_make_template())
        stats = builder.get_builder_stats()
        assert stats["templates"] == 1
        assert stats["scheduled_templates"] == 1  # has schedule="weekly"

    def test_stats_after_generate(self, builder):
        tmpl = builder.create_template(_make_template())
        builder.generate_report(tmpl.id)
        stats = builder.get_builder_stats()
        assert stats["generated_reports"] == 1
        assert stats["last_report_generated"] is not None

    def test_stats_section_types_count(self, builder):
        stats = builder.get_builder_stats()
        assert stats["section_types_available"] == 10

    def test_stats_data_sources_count(self, builder):
        stats = builder.get_builder_stats()
        assert stats["data_sources_available"] == 9

    def test_stats_org_isolation(self, builder):
        builder.create_template(_make_template(org_id="org1"))
        builder.create_template(_make_template(org_id="org1"))
        builder.create_template(_make_template(org_id="org2"))
        assert builder.get_builder_stats(org_id="org1")["templates"] == 2
        assert builder.get_builder_stats(org_id="org2")["templates"] == 1


# ============================================================================
# Data fetcher tests
# ============================================================================


class TestDataFetchers:
    def test_fetch_findings(self):
        data = _fetch_data(DataSource.FINDINGS, {})
        assert data["source"] == "findings"
        assert "total" in data
        assert "by_severity" in data

    def test_fetch_compliance(self):
        data = _fetch_data(DataSource.COMPLIANCE, {})
        assert data["source"] == "compliance"
        assert "frameworks" in data
        assert len(data["frameworks"]) > 0

    def test_fetch_posture(self):
        data = _fetch_data(DataSource.POSTURE, {})
        assert data["source"] == "posture"
        assert "overall_score" in data

    def test_fetch_sla(self):
        data = _fetch_data(DataSource.SLA, {})
        assert data["source"] == "sla"
        assert "compliance_rate" in data

    def test_fetch_attack_surface(self):
        data = _fetch_data(DataSource.ATTACK_SURFACE, {})
        assert data["source"] == "attack_surface"
        assert "exposed_assets" in data

    def test_fetch_vulnerabilities(self):
        data = _fetch_data(DataSource.VULNERABILITIES, {})
        assert data["source"] == "vulnerabilities"
        assert "total_cves" in data

    def test_fetch_scanners(self):
        data = _fetch_data(DataSource.SCANNERS, {})
        assert data["source"] == "scanners"
        assert "scanners" in data

    def test_fetch_incidents(self):
        data = _fetch_data(DataSource.INCIDENTS, {})
        assert data["source"] == "incidents"
        assert "open" in data

    def test_fetch_vendors(self):
        data = _fetch_data(DataSource.VENDORS, {})
        assert data["source"] == "vendors"
        assert "total" in data

    def test_fetch_passes_filters(self):
        filters = {"org": "acme", "limit": 5}
        data = _fetch_data(DataSource.FINDINGS, filters)
        assert data["filters_applied"] == filters
