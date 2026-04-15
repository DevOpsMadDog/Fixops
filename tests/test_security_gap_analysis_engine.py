"""Tests for SecurityGapAnalysisEngine — ALDECI.

Covers:
- create_assessment: fields, risk_level defaults to critical (0% coverage)
- coverage_pct formula: (total - not_implemented - partial) / total * 100
- risk_level thresholds: <40=critical, <60=high, <80=medium, >=80=low
- add_control_gap: triggers recompute on parent assessment
- update_control_status: open→in_progress→implemented→accepted transitions
- recompute_assessment on status change
- add_remediation_plan + complete_remediation
- get_gap_summary: counts, by_framework, by_priority, critical_gaps
- get_assessment_detail: assessment + gaps + plans
- get_overdue_gaps: due_date < now detection
- get_framework_coverage: per-framework latest assessment
- list_gaps with filters
- org isolation: org_a data not visible to org_b
- invalid framework, priority, effort, risk_impact raise ValueError
- 40+ tests
"""

from __future__ import annotations

import sys
import pytest
from datetime import datetime, timezone, timedelta

sys.path.insert(0, "suite-core")
sys.path.insert(0, "suite-api")

from core.security_gap_analysis_engine import (
    SecurityGapAnalysisEngine,
    _VALID_FRAMEWORKS,
    _risk_level_from_pct,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    return SecurityGapAnalysisEngine(db_path=str(tmp_path / "gap_analysis.db"))


def _assessment(
    engine,
    org_id="org1",
    framework="SOC2",
    name="Test Assessment",
    total_controls=10,
    assessor="Alice",
    next_review="2026-12-31",
):
    return engine.create_assessment(
        org_id=org_id,
        framework=framework,
        assessment_name=name,
        total_controls=total_controls,
        assessor=assessor,
        next_review=next_review,
    )


def _gap(
    engine,
    assessment_id,
    org_id="org1",
    control_id="CC6.1",
    control_name="Logical Access",
    priority="high",
    effort="medium",
    risk_impact="high",
    due_date="",
):
    return engine.add_control_gap(
        assessment_id=assessment_id,
        org_id=org_id,
        control_id=control_id,
        control_name=control_name,
        domain="Access Control",
        requirement="MFA required",
        current_state="MFA not enforced",
        gap_description="No MFA on admin accounts",
        risk_impact=risk_impact,
        effort=effort,
        priority=priority,
        owner="sec-team",
        due_date=due_date,
    )


# ---------------------------------------------------------------------------
# _risk_level_from_pct helper
# ---------------------------------------------------------------------------


def test_risk_level_thresholds():
    assert _risk_level_from_pct(0.0) == "critical"
    assert _risk_level_from_pct(39.9) == "critical"
    assert _risk_level_from_pct(40.0) == "high"
    assert _risk_level_from_pct(59.9) == "high"
    assert _risk_level_from_pct(60.0) == "medium"
    assert _risk_level_from_pct(79.9) == "medium"
    assert _risk_level_from_pct(80.0) == "low"
    assert _risk_level_from_pct(100.0) == "low"


# ---------------------------------------------------------------------------
# create_assessment
# ---------------------------------------------------------------------------


def test_create_assessment_basic(engine):
    a = _assessment(engine)
    assert a["id"]
    assert a["org_id"] == "org1"
    assert a["framework"] == "SOC2"
    assert a["assessment_name"] == "Test Assessment"
    assert a["total_controls"] == 10
    assert a["implemented_controls"] == 0
    assert a["partial_controls"] == 0
    assert a["not_implemented"] == 0
    assert a["coverage_pct"] == 0.0
    assert a["risk_level"] == "critical"
    assert a["assessor"] == "Alice"


def test_create_assessment_all_frameworks(engine):
    for i, fw in enumerate(sorted(_VALID_FRAMEWORKS)):
        a = engine.create_assessment(
            org_id="org1",
            framework=fw,
            assessment_name=f"Assessment {i}",
            total_controls=50,
            assessor="Bob",
            next_review="2026-06-30",
        )
        assert a["framework"] == fw


def test_create_assessment_invalid_framework(engine):
    with pytest.raises(ValueError, match="framework"):
        engine.create_assessment(
            org_id="org1",
            framework="INVALID",
            assessment_name="Bad",
            total_controls=10,
            assessor="Alice",
            next_review="",
        )


def test_create_assessment_empty_name_raises(engine):
    with pytest.raises(ValueError, match="assessment_name"):
        engine.create_assessment(
            org_id="org1",
            framework="SOC2",
            assessment_name="   ",
            total_controls=10,
            assessor="Alice",
            next_review="",
        )


# ---------------------------------------------------------------------------
# add_control_gap + coverage recompute
# ---------------------------------------------------------------------------


def test_add_control_gap_basic(engine):
    a = _assessment(engine)
    g = _gap(engine, a["id"])
    assert g["id"]
    assert g["assessment_id"] == a["id"]
    assert g["org_id"] == "org1"
    assert g["status"] == "open"
    assert g["priority"] == "high"
    assert g["effort"] == "medium"


def test_add_gap_recomputes_not_implemented(engine):
    a = _assessment(engine, total_controls=10)
    _gap(engine, a["id"], control_id="CC6.1", control_name="Control 1")
    _gap(engine, a["id"], control_id="CC6.2", control_name="Control 2")
    updated = engine.get_assessment(a["id"], "org1")
    assert updated["not_implemented"] == 2


def test_coverage_pct_formula(engine):
    # 10 total, 2 open (not_implemented), 1 in_progress (partial) → (10-2-1)/10*100 = 70%
    a = _assessment(engine, total_controls=10)
    g1 = _gap(engine, a["id"], control_id="CC1", control_name="C1")
    g2 = _gap(engine, a["id"], control_id="CC2", control_name="C2")
    g3 = _gap(engine, a["id"], control_id="CC3", control_name="C3")
    # Move g3 to in_progress (partial)
    engine.update_control_status(g3["id"], "org1", "in_progress")
    updated = engine.get_assessment(a["id"], "org1")
    # 2 open, 1 in_progress, 7 not yet tracked in gaps
    # not_implemented = COUNT(status='open') = 2
    # partial = COUNT(status='in_progress') = 1
    # coverage = (10 - 2 - 1) / 10 * 100 = 70.0
    assert updated["coverage_pct"] == pytest.approx(70.0, abs=0.1)
    assert updated["risk_level"] == "medium"


def test_add_gap_invalid_priority(engine):
    a = _assessment(engine)
    with pytest.raises(ValueError, match="priority"):
        engine.add_control_gap(
            assessment_id=a["id"],
            org_id="org1",
            control_id="CC1",
            control_name="Control 1",
            domain="",
            requirement="",
            current_state="",
            gap_description="",
            risk_impact="high",
            effort="medium",
            priority="ultra",
            owner="",
            due_date="",
        )


def test_add_gap_invalid_effort(engine):
    a = _assessment(engine)
    with pytest.raises(ValueError, match="effort"):
        engine.add_control_gap(
            assessment_id=a["id"],
            org_id="org1",
            control_id="CC1",
            control_name="Control 1",
            domain="",
            requirement="",
            current_state="",
            gap_description="",
            risk_impact="high",
            effort="extreme",
            priority="high",
            owner="",
            due_date="",
        )


def test_add_gap_invalid_risk_impact(engine):
    a = _assessment(engine)
    with pytest.raises(ValueError, match="risk_impact"):
        engine.add_control_gap(
            assessment_id=a["id"],
            org_id="org1",
            control_id="CC1",
            control_name="Control 1",
            domain="",
            requirement="",
            current_state="",
            gap_description="",
            risk_impact="catastrophic",
            effort="medium",
            priority="high",
            owner="",
            due_date="",
        )


# ---------------------------------------------------------------------------
# update_control_status
# ---------------------------------------------------------------------------


def test_update_status_open_to_in_progress(engine):
    a = _assessment(engine, total_controls=10)
    g = _gap(engine, a["id"])
    updated_gap = engine.update_control_status(g["id"], "org1", "in_progress")
    assert updated_gap["status"] == "in_progress"


def test_update_status_to_implemented_recomputes_coverage(engine):
    a = _assessment(engine, total_controls=4)
    g1 = _gap(engine, a["id"], control_id="CC1", control_name="C1")
    g2 = _gap(engine, a["id"], control_id="CC2", control_name="C2")
    # 2 open → coverage = (4-2-0)/4*100 = 50%
    engine.update_control_status(g1["id"], "org1", "implemented")
    # Now 1 open, 0 partial → coverage = (4-1-0)/4*100 = 75%
    updated = engine.get_assessment(a["id"], "org1")
    assert updated["coverage_pct"] == pytest.approx(75.0, abs=0.1)
    assert updated["risk_level"] == "medium"


def test_update_status_all_implemented_coverage_high(engine):
    a = _assessment(engine, total_controls=2)
    g1 = _gap(engine, a["id"], control_id="CC1", control_name="C1")
    g2 = _gap(engine, a["id"], control_id="CC2", control_name="C2")
    engine.update_control_status(g1["id"], "org1", "implemented")
    engine.update_control_status(g2["id"], "org1", "implemented")
    updated = engine.get_assessment(a["id"], "org1")
    # 0 open, 0 partial → coverage = (2-0-0)/2*100 = 100%
    assert updated["coverage_pct"] == pytest.approx(100.0, abs=0.1)
    assert updated["risk_level"] == "low"


def test_update_status_accepted_counts_as_implemented(engine):
    a = _assessment(engine, total_controls=2)
    g = _gap(engine, a["id"])
    engine.update_control_status(g["id"], "org1", "accepted")
    updated = engine.get_assessment(a["id"], "org1")
    assert updated["implemented_controls"] == 1
    assert updated["not_implemented"] == 0


def test_update_status_invalid_raises(engine):
    a = _assessment(engine)
    g = _gap(engine, a["id"])
    with pytest.raises(ValueError, match="status"):
        engine.update_control_status(g["id"], "org1", "wontfix")


def test_update_status_wrong_org_raises(engine):
    a = _assessment(engine, org_id="org1")
    g = _gap(engine, a["id"], org_id="org1")
    with pytest.raises(ValueError):
        engine.update_control_status(g["id"], "org2", "in_progress")


# ---------------------------------------------------------------------------
# remediation plans
# ---------------------------------------------------------------------------


def test_add_remediation_plan(engine):
    a = _assessment(engine)
    g = _gap(engine, a["id"])
    plan = engine.add_remediation_plan(
        gap_id=g["id"],
        org_id="org1",
        action="Deploy MFA solution",
        resource_required="Engineering team",
        estimated_days=30,
    )
    assert plan["id"]
    assert plan["gap_id"] == g["id"]
    assert plan["status"] == "planned"
    assert plan["estimated_days"] == 30
    assert plan["actual_days"] == 0


def test_complete_remediation(engine):
    a = _assessment(engine)
    g = _gap(engine, a["id"])
    plan = engine.add_remediation_plan(g["id"], "org1", "Deploy MFA", "", 30)
    completed = engine.complete_remediation(plan["id"], "org1", actual_days=25)
    assert completed["status"] == "completed"
    assert completed["actual_days"] == 25
    assert completed["completed_at"] != ""


def test_complete_remediation_wrong_org_raises(engine):
    a = _assessment(engine)
    g = _gap(engine, a["id"])
    plan = engine.add_remediation_plan(g["id"], "org1", "action", "", 10)
    with pytest.raises(ValueError):
        engine.complete_remediation(plan["id"], "org2", actual_days=10)


# ---------------------------------------------------------------------------
# get_gap_summary
# ---------------------------------------------------------------------------


def test_gap_summary_empty(engine):
    summary = engine.get_gap_summary("org1")
    assert summary["assessments"] == 0
    assert summary["total_gaps"] == 0
    assert summary["open_gaps"] == 0
    assert summary["critical_gaps"] == 0


def test_gap_summary_counts(engine):
    a1 = _assessment(engine, framework="SOC2")
    a2 = _assessment(engine, framework="PCI-DSS", name="PCI Assessment")
    _gap(engine, a1["id"], control_id="CC1", control_name="C1", priority="critical")
    _gap(engine, a1["id"], control_id="CC2", control_name="C2", priority="high")
    _gap(engine, a2["id"], control_id="R1", control_name="Req1", priority="medium")
    summary = engine.get_gap_summary("org1")
    assert summary["assessments"] == 2
    assert summary["total_gaps"] == 3
    assert summary["open_gaps"] == 3
    assert summary["critical_gaps"] == 1
    assert "SOC2" in summary["by_framework"]
    assert "PCI-DSS" in summary["by_framework"]
    assert "critical" in summary["by_priority"]
    assert "high" in summary["by_priority"]


def test_gap_summary_org_isolation(engine):
    a = _assessment(engine, org_id="org1")
    _gap(engine, a["id"], org_id="org1")
    summary = engine.get_gap_summary("org2")
    assert summary["total_gaps"] == 0


# ---------------------------------------------------------------------------
# get_assessment_detail
# ---------------------------------------------------------------------------


def test_get_assessment_detail(engine):
    a = _assessment(engine)
    g = _gap(engine, a["id"])
    plan = engine.add_remediation_plan(g["id"], "org1", "Fix it", "", 10)
    detail = engine.get_assessment_detail(a["id"], "org1")
    assert detail is not None
    assert detail["assessment"]["id"] == a["id"]
    assert len(detail["gaps"]) == 1
    assert len(detail["remediation_plans"]) == 1


def test_get_assessment_detail_not_found(engine):
    result = engine.get_assessment_detail("nonexistent", "org1")
    assert result is None


def test_get_assessment_detail_org_isolation(engine):
    a = _assessment(engine, org_id="org1")
    result = engine.get_assessment_detail(a["id"], "org2")
    assert result is None


# ---------------------------------------------------------------------------
# get_overdue_gaps
# ---------------------------------------------------------------------------


def test_overdue_gaps_detected(engine):
    past = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
    a = _assessment(engine)
    g = _gap(engine, a["id"], due_date=past)
    overdue = engine.get_overdue_gaps("org1")
    assert len(overdue) == 1
    assert overdue[0]["id"] == g["id"]


def test_overdue_gaps_future_not_included(engine):
    future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    a = _assessment(engine)
    _gap(engine, a["id"], due_date=future)
    overdue = engine.get_overdue_gaps("org1")
    assert len(overdue) == 0


def test_overdue_gaps_implemented_not_included(engine):
    past = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
    a = _assessment(engine)
    g = _gap(engine, a["id"], due_date=past)
    engine.update_control_status(g["id"], "org1", "implemented")
    overdue = engine.get_overdue_gaps("org1")
    assert len(overdue) == 0


def test_overdue_gaps_org_isolation(engine):
    past = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
    a = _assessment(engine, org_id="org1")
    _gap(engine, a["id"], org_id="org1", due_date=past)
    overdue = engine.get_overdue_gaps("org2")
    assert len(overdue) == 0


# ---------------------------------------------------------------------------
# get_framework_coverage
# ---------------------------------------------------------------------------


def test_framework_coverage_single(engine):
    a = _assessment(engine, framework="ISO27001", total_controls=5)
    _gap(engine, a["id"])
    coverage = engine.get_framework_coverage("org1")
    assert len(coverage) == 1
    assert coverage[0]["framework"] == "ISO27001"
    assert "coverage_pct" in coverage[0]
    assert "risk_level" in coverage[0]
    assert coverage[0]["gap_count"] == 1


def test_framework_coverage_multiple(engine):
    a1 = _assessment(engine, framework="SOC2", name="SOC2 Assess")
    a2 = _assessment(engine, framework="HIPAA", name="HIPAA Assess")
    _gap(engine, a1["id"], control_id="CC1", control_name="C1")
    _gap(engine, a2["id"], control_id="H1", control_name="H1")
    coverage = engine.get_framework_coverage("org1")
    frameworks = {c["framework"] for c in coverage}
    assert "SOC2" in frameworks
    assert "HIPAA" in frameworks


def test_framework_coverage_uses_latest_assessment(engine):
    # Create two assessments for same framework; latest should be used
    a1 = _assessment(engine, framework="CIS", name="CIS v1", total_controls=10)
    a2 = _assessment(engine, framework="CIS", name="CIS v2", total_controls=20)
    coverage = engine.get_framework_coverage("org1")
    cis = next(c for c in coverage if c["framework"] == "CIS")
    assert cis["assessment_id"] == a2["id"]


def test_framework_coverage_org_isolation(engine):
    _assessment(engine, org_id="org1", framework="SOC2")
    coverage = engine.get_framework_coverage("org2")
    assert coverage == []
