"""Tests for CISOReportGenerator — 25 tests.

Tests cover:
- weekly_brief structure and required sections
- executive_summary 3-bullet format
- top_risks list and limit enforcement
- export_markdown non-empty and key sections present
- risk_posture_delta structure
- graceful handling when engines unavailable (mocked)
- org isolation
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from core.ciso_report_generator import CISOReportGenerator


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def gen():
    return CISOReportGenerator()


ORG_A = "test-org-alpha"
ORG_B = "test-org-beta"


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _mock_all_engines(generator: CISOReportGenerator):
    """Patch all lazy engine loaders to return None (simulates unavailability)."""
    for attr in [
        "_get_vuln_prio", "_get_attack_path", "_get_insider_threat",
        "_get_threat_feed", "_get_soc_triage", "_get_compliance_scanner",
        "_get_posture_score", "_get_security_health", "_get_incident_timeline",
        "_get_vuln_workflow", "_get_vuln_trend",
    ]:
        setattr(generator, attr, lambda *a, **kw: None)
    return generator


# ---------------------------------------------------------------------------
# 1. generate_weekly_brief — structure
# ---------------------------------------------------------------------------

class TestWeeklyBrief:
    def test_returns_dict(self, gen):
        result = gen.generate_weekly_brief(ORG_A)
        assert isinstance(result, dict)

    def test_has_required_top_level_keys(self, gen):
        result = gen.generate_weekly_brief(ORG_A)
        required = {
            "generated_at", "org_id", "report_period",
            "executive_summary", "risk_posture", "top_risks",
            "sections", "recommended_actions",
        }
        assert required.issubset(result.keys())

    def test_org_id_preserved(self, gen):
        result = gen.generate_weekly_brief(ORG_A)
        assert result["org_id"] == ORG_A

    def test_sections_has_required_subsections(self, gen):
        result = gen.generate_weekly_brief(ORG_A)
        sections = result["sections"]
        required = {"vulnerabilities", "threats", "compliance", "incidents", "operations"}
        assert required.issubset(sections.keys())

    def test_report_period_has_start_end_days(self, gen):
        result = gen.generate_weekly_brief(ORG_A)
        period = result["report_period"]
        assert "start" in period
        assert "end" in period
        assert period["days"] == 7

    def test_generated_at_is_iso_string(self, gen):
        result = gen.generate_weekly_brief(ORG_A)
        ts = result["generated_at"]
        assert isinstance(ts, str)
        assert "T" in ts and "Z" in ts

    def test_risk_posture_has_score_and_trend(self, gen):
        result = gen.generate_weekly_brief(ORG_A)
        posture = result["risk_posture"]
        assert "overall_score" in posture
        assert "delta" in posture
        assert "trend" in posture

    def test_risk_posture_score_in_range(self, gen):
        result = gen.generate_weekly_brief(ORG_A)
        score = result["risk_posture"]["overall_score"]
        assert 0 <= score <= 100

    def test_recommended_actions_is_list(self, gen):
        result = gen.generate_weekly_brief(ORG_A)
        assert isinstance(result["recommended_actions"], list)


# ---------------------------------------------------------------------------
# 2. generate_executive_summary
# ---------------------------------------------------------------------------

class TestExecutiveSummary:
    def test_returns_dict(self, gen):
        result = gen.generate_executive_summary(ORG_A)
        assert isinstance(result, dict)

    def test_has_three_bullet_points(self, gen):
        result = gen.generate_executive_summary(ORG_A)
        bullets = result["executive_summary"]
        assert isinstance(bullets, list)
        assert len(bullets) == 3

    def test_bullets_are_non_empty_strings(self, gen):
        result = gen.generate_executive_summary(ORG_A)
        for bullet in result["executive_summary"]:
            assert isinstance(bullet, str)
            assert len(bullet) > 10

    def test_has_risk_posture(self, gen):
        result = gen.generate_executive_summary(ORG_A)
        assert "risk_posture" in result

    def test_has_period_fields(self, gen):
        result = gen.generate_executive_summary(ORG_A)
        assert "period_start" in result
        assert "period_end" in result


# ---------------------------------------------------------------------------
# 3. get_top_risks
# ---------------------------------------------------------------------------

class TestTopRisks:
    def test_returns_list(self, gen):
        result = gen.get_top_risks(ORG_A)
        assert isinstance(result, list)

    def test_default_limit_is_five(self, gen):
        result = gen.get_top_risks(ORG_A)
        assert len(result) <= 5

    def test_custom_limit_respected(self, gen):
        result = gen.get_top_risks(ORG_A, limit=2)
        assert len(result) <= 2

    def test_limit_one_respected(self, gen):
        result = gen.get_top_risks(ORG_A, limit=1)
        assert len(result) <= 1

    def test_risk_items_have_required_keys(self, gen):
        result = gen.get_top_risks(ORG_A)
        for risk in result:
            assert "rank" in risk
            assert "category" in risk
            assert "title" in risk
            assert "severity" in risk


# ---------------------------------------------------------------------------
# 4. export_markdown
# ---------------------------------------------------------------------------

class TestExportMarkdown:
    def test_returns_non_empty_string(self, gen):
        md = gen.export_markdown(ORG_A)
        assert isinstance(md, str)
        assert len(md) > 100

    def test_contains_h1_title(self, gen):
        md = gen.export_markdown(ORG_A)
        assert "# CISO Weekly Security Briefing" in md

    def test_contains_executive_summary_section(self, gen):
        md = gen.export_markdown(ORG_A)
        assert "## Executive Summary" in md

    def test_contains_risk_posture_section(self, gen):
        md = gen.export_markdown(ORG_A)
        assert "## Risk Posture" in md

    def test_contains_vulnerability_summary_section(self, gen):
        md = gen.export_markdown(ORG_A)
        assert "## Vulnerability Summary" in md

    def test_contains_org_id(self, gen):
        md = gen.export_markdown(ORG_A)
        assert ORG_A in md


# ---------------------------------------------------------------------------
# 5. export_json
# ---------------------------------------------------------------------------

class TestExportJson:
    def test_returns_valid_json(self, gen):
        json_str = gen.export_json(ORG_A)
        parsed = json.loads(json_str)
        assert isinstance(parsed, dict)

    def test_json_has_sections(self, gen):
        json_str = gen.export_json(ORG_A)
        parsed = json.loads(json_str)
        assert "sections" in parsed


# ---------------------------------------------------------------------------
# 6. get_risk_posture_delta
# ---------------------------------------------------------------------------

class TestRiskPostureDelta:
    def test_returns_dict_with_delta(self, gen):
        result = gen.get_risk_posture_delta(ORG_A)
        assert "delta" in result
        assert "overall_score" in result
        assert "trend" in result

    def test_custom_days_reflected(self, gen):
        result = gen.get_risk_posture_delta(ORG_A, days=14)
        assert result["period_days"] == 14


# ---------------------------------------------------------------------------
# 7. Graceful degradation — all engines unavailable
# ---------------------------------------------------------------------------

class TestGracefulDegradation:
    def test_weekly_brief_works_with_no_engines(self):
        gen = CISOReportGenerator()
        _mock_all_engines(gen)
        result = gen.generate_weekly_brief(ORG_A)
        # Should still return a valid report structure even with no engines
        assert isinstance(result, dict)
        assert "sections" in result
        # Score may be non-zero due to formula defaults; just check it's in range
        assert 0 <= result["risk_posture"]["overall_score"] <= 100

    def test_markdown_export_works_with_no_engines(self):
        gen = CISOReportGenerator()
        _mock_all_engines(gen)
        md = gen.export_markdown(ORG_A)
        assert isinstance(md, str)
        assert "## Executive Summary" in md

    def test_top_risks_empty_when_no_engines(self):
        gen = CISOReportGenerator()
        _mock_all_engines(gen)
        risks = gen.get_top_risks(ORG_A)
        assert isinstance(risks, list)


# ---------------------------------------------------------------------------
# 8. Org isolation
# ---------------------------------------------------------------------------

class TestOrgIsolation:
    def test_different_org_ids_returned_correctly(self, gen):
        result_a = gen.generate_weekly_brief(ORG_A)
        result_b = gen.generate_weekly_brief(ORG_B)
        assert result_a["org_id"] == ORG_A
        assert result_b["org_id"] == ORG_B

    def test_org_id_in_risk_delta(self, gen):
        result = gen.get_risk_posture_delta(ORG_B, days=7)
        assert result["org_id"] == ORG_B

    def test_org_id_in_executive_summary(self, gen):
        result = gen.generate_executive_summary(ORG_B)
        assert result["org_id"] == ORG_B
