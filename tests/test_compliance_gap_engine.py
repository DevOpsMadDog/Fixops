"""Tests for ComplianceGapEngine — ALDECI.

Covers:
- Assessment CRUD and lifecycle
- All valid frameworks
- Invalid framework validation
- add_control_gap increments total_controls
- update_gap_status lifecycle (open→in_remediation→remediated)
- Remediated gap increments compliant_controls and recalculates compliance_pct
- complete_assessment computes compliance_pct
- list_gaps filters
- Remediation plan CRUD
- get_gap_stats aggregations
- Org isolation
- ~35 tests
"""
from __future__ import annotations

import sys
import pytest

sys.path.insert(0, "suite-core")
sys.path.insert(0, "suite-api")

from core.compliance_gap_engine import ComplianceGapEngine, _VALID_FRAMEWORKS


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    return ComplianceGapEngine(db_path=str(tmp_path / "compliance_gap.db"))


def _assessment(engine, org_id="org1", framework="SOC2", name="Test Assessment"):
    return engine.create_assessment(org_id, {
        "framework": framework,
        "assessment_name": name,
    })


def _gap(engine, org_id="org1", assessment_id=None, severity="high",
         control_id="CC6.1", control_name="Logical Access"):
    return engine.add_control_gap(org_id, {
        "assessment_id": assessment_id,
        "control_id": control_id,
        "control_name": control_name,
        "severity": severity,
        "gap_description": "MFA not enforced",
        "remediation_effort": 8,
    })


# ---------------------------------------------------------------------------
# create_assessment
# ---------------------------------------------------------------------------


def test_create_assessment_basic(engine):
    a = _assessment(engine)
    assert a["id"]
    assert a["org_id"] == "org1"
    assert a["framework"] == "SOC2"
    assert a["assessment_name"] == "Test Assessment"
    assert a["status"] == "in_progress"
    assert a["total_controls"] == 0
    assert a["compliant_controls"] == 0
    assert a["compliance_pct"] == 0.0


def test_create_assessment_all_valid_frameworks(engine):
    for i, fw in enumerate(sorted(_VALID_FRAMEWORKS)):
        a = engine.create_assessment("org1", {
            "framework": fw,
            "assessment_name": f"Assessment {i}",
        })
        assert a["framework"] == fw


def test_create_assessment_invalid_framework(engine):
    with pytest.raises(ValueError, match="framework"):
        engine.create_assessment("org1", {
            "framework": "INVALID_FRAMEWORK",
            "assessment_name": "X",
        })


def test_create_assessment_missing_name(engine):
    with pytest.raises(ValueError, match="assessment_name"):
        engine.create_assessment("org1", {
            "framework": "SOC2",
            "assessment_name": "",
        })


def test_create_assessment_with_total_controls(engine):
    a = engine.create_assessment("org1", {
        "framework": "NIST",
        "assessment_name": "NIST Full",
        "total_controls": 50,
    })
    assert a["total_controls"] == 50


# ---------------------------------------------------------------------------
# list / get assessment
# ---------------------------------------------------------------------------


def test_list_assessments_empty(engine):
    assert engine.list_assessments("org1") == []


def test_list_assessments_filter_framework(engine):
    _assessment(engine, framework="SOC2", name="SOC2 A")
    _assessment(engine, framework="NIST", name="NIST A")
    result = engine.list_assessments("org1", framework="SOC2")
    assert len(result) == 1
    assert result[0]["framework"] == "SOC2"


def test_list_assessments_filter_status(engine):
    a = _assessment(engine)
    engine.complete_assessment("org1", a["id"])
    in_progress = engine.list_assessments("org1", status="in_progress")
    completed = engine.list_assessments("org1", status="completed")
    assert len(in_progress) == 0
    assert len(completed) == 1


def test_get_assessment_found(engine):
    a = _assessment(engine)
    found = engine.get_assessment("org1", a["id"])
    assert found["id"] == a["id"]


def test_get_assessment_not_found(engine):
    assert engine.get_assessment("org1", "nonexistent") is None


def test_get_assessment_wrong_org(engine):
    a = _assessment(engine, org_id="org1")
    assert engine.get_assessment("org2", a["id"]) is None


# ---------------------------------------------------------------------------
# complete_assessment
# ---------------------------------------------------------------------------


def test_complete_assessment_sets_status(engine):
    a = _assessment(engine)
    gap = _gap(engine, assessment_id=a["id"])
    engine.update_gap_status("org1", gap["id"], "remediated")
    completed = engine.complete_assessment("org1", a["id"])
    assert completed["status"] == "completed"
    assert completed["completed_at"] != ""


def test_complete_assessment_computes_compliance_pct(engine):
    a = _assessment(engine)
    g1 = _gap(engine, assessment_id=a["id"], control_id="C1", control_name="Ctrl1")
    g2 = _gap(engine, assessment_id=a["id"], control_id="C2", control_name="Ctrl2")
    # Remediate one of two gaps
    engine.update_gap_status("org1", g1["id"], "remediated")
    completed = engine.complete_assessment("org1", a["id"])
    # total_controls=2, compliant_controls=1 → 50%
    assert completed["compliance_pct"] == pytest.approx(50.0)


def test_complete_assessment_not_found(engine):
    with pytest.raises(ValueError):
        engine.complete_assessment("org1", "bad-id")


# ---------------------------------------------------------------------------
# add_control_gap
# ---------------------------------------------------------------------------


def test_add_control_gap_basic(engine):
    a = _assessment(engine)
    gap = _gap(engine, assessment_id=a["id"])
    assert gap["id"]
    assert gap["status"] == "open"
    assert gap["severity"] == "high"
    assert gap["remediation_effort"] == 8


def test_add_control_gap_increments_total_controls(engine):
    a = _assessment(engine)
    _gap(engine, assessment_id=a["id"], control_id="C1", control_name="C1")
    _gap(engine, assessment_id=a["id"], control_id="C2", control_name="C2")
    updated = engine.get_assessment("org1", a["id"])
    assert updated["total_controls"] == 2


def test_add_control_gap_invalid_severity(engine):
    a = _assessment(engine)
    with pytest.raises(ValueError, match="severity"):
        engine.add_control_gap("org1", {
            "assessment_id": a["id"],
            "control_id": "C1",
            "control_name": "Ctrl",
            "severity": "extreme",
        })


def test_add_control_gap_missing_control_id(engine):
    a = _assessment(engine)
    with pytest.raises(ValueError, match="control_id"):
        engine.add_control_gap("org1", {
            "assessment_id": a["id"],
            "control_id": "",
            "control_name": "Ctrl",
            "severity": "high",
        })


def test_add_control_gap_wrong_org_assessment(engine):
    a = _assessment(engine, org_id="org1")
    with pytest.raises(ValueError):
        engine.add_control_gap("org2", {
            "assessment_id": a["id"],
            "control_id": "C1",
            "control_name": "Ctrl",
            "severity": "high",
        })


def test_add_control_gap_all_severities(engine):
    a = _assessment(engine)
    for i, sev in enumerate(["critical", "high", "medium", "low"]):
        g = engine.add_control_gap("org1", {
            "assessment_id": a["id"],
            "control_id": f"C{i}",
            "control_name": f"Ctrl {i}",
            "severity": sev,
        })
        assert g["severity"] == sev


# ---------------------------------------------------------------------------
# update_gap_status lifecycle
# ---------------------------------------------------------------------------


def test_update_gap_status_open_to_in_remediation(engine):
    a = _assessment(engine)
    g = _gap(engine, assessment_id=a["id"])
    updated = engine.update_gap_status("org1", g["id"], "in_remediation")
    assert updated["status"] == "in_remediation"


def test_update_gap_status_remediated_sets_timestamp(engine):
    a = _assessment(engine)
    g = _gap(engine, assessment_id=a["id"])
    updated = engine.update_gap_status("org1", g["id"], "remediated")
    assert updated["status"] == "remediated"
    assert updated["remediated_at"] != ""


def test_update_gap_status_remediated_increments_compliant_controls(engine):
    a = _assessment(engine)
    g = _gap(engine, assessment_id=a["id"])
    engine.update_gap_status("org1", g["id"], "remediated")
    assessment = engine.get_assessment("org1", a["id"])
    assert assessment["compliant_controls"] == 1


def test_update_gap_status_remediated_recalculates_pct(engine):
    a = _assessment(engine)
    g1 = _gap(engine, assessment_id=a["id"], control_id="C1", control_name="C1")
    g2 = _gap(engine, assessment_id=a["id"], control_id="C2", control_name="C2")
    engine.update_gap_status("org1", g1["id"], "remediated")
    assessment = engine.get_assessment("org1", a["id"])
    assert assessment["compliance_pct"] == pytest.approx(50.0)


def test_update_gap_status_full_cycle(engine):
    a = _assessment(engine)
    g = _gap(engine, assessment_id=a["id"])
    engine.update_gap_status("org1", g["id"], "in_remediation")
    engine.update_gap_status("org1", g["id"], "remediated")
    assessment = engine.get_assessment("org1", a["id"])
    assert assessment["compliant_controls"] == 1
    assert assessment["compliance_pct"] == pytest.approx(100.0)


def test_update_gap_status_invalid(engine):
    a = _assessment(engine)
    g = _gap(engine, assessment_id=a["id"])
    with pytest.raises(ValueError, match="new_status"):
        engine.update_gap_status("org1", g["id"], "invalid_status")


def test_update_gap_status_accepted(engine):
    a = _assessment(engine)
    g = _gap(engine, assessment_id=a["id"])
    updated = engine.update_gap_status("org1", g["id"], "accepted")
    assert updated["status"] == "accepted"


# ---------------------------------------------------------------------------
# list_gaps filters
# ---------------------------------------------------------------------------


def test_list_gaps_filter_assessment_id(engine):
    a1 = _assessment(engine, name="A1")
    a2 = _assessment(engine, name="A2")
    _gap(engine, assessment_id=a1["id"], control_id="C1", control_name="C1")
    _gap(engine, assessment_id=a2["id"], control_id="C2", control_name="C2")
    result = engine.list_gaps("org1", assessment_id=a1["id"])
    assert len(result) == 1


def test_list_gaps_filter_severity(engine):
    a = _assessment(engine)
    _gap(engine, assessment_id=a["id"], control_id="C1", control_name="C1", severity="critical")
    _gap(engine, assessment_id=a["id"], control_id="C2", control_name="C2", severity="low")
    result = engine.list_gaps("org1", severity="critical")
    assert len(result) == 1
    assert result[0]["severity"] == "critical"


def test_list_gaps_filter_status(engine):
    a = _assessment(engine)
    g1 = _gap(engine, assessment_id=a["id"], control_id="C1", control_name="C1")
    g2 = _gap(engine, assessment_id=a["id"], control_id="C2", control_name="C2")
    engine.update_gap_status("org1", g1["id"], "remediated")
    open_gaps = engine.list_gaps("org1", status="open")
    remediated = engine.list_gaps("org1", status="remediated")
    assert len(open_gaps) == 1
    assert len(remediated) == 1


# ---------------------------------------------------------------------------
# Remediation plans
# ---------------------------------------------------------------------------


def test_create_remediation_plan_basic(engine):
    a = _assessment(engine)
    g = _gap(engine, assessment_id=a["id"])
    plan = engine.create_remediation_plan("org1", {
        "gap_id": g["id"],
        "plan_description": "Enable MFA for all users",
        "owner": "alice",
        "target_date": "2026-06-30",
    })
    assert plan["id"]
    assert plan["status"] == "planned"
    assert plan["owner"] == "alice"


def test_create_remediation_plan_missing_fields(engine):
    a = _assessment(engine)
    g = _gap(engine, assessment_id=a["id"])
    with pytest.raises(ValueError, match="plan_description"):
        engine.create_remediation_plan("org1", {
            "gap_id": g["id"],
            "plan_description": "",
            "owner": "alice",
            "target_date": "2026-06-30",
        })


def test_create_remediation_plan_wrong_org_gap(engine):
    a = _assessment(engine, org_id="org1")
    g = _gap(engine, org_id="org1", assessment_id=a["id"])
    with pytest.raises(ValueError):
        engine.create_remediation_plan("org2", {
            "gap_id": g["id"],
            "plan_description": "Fix",
            "owner": "bob",
            "target_date": "2026-06-30",
        })


def test_update_plan_status_lifecycle(engine):
    a = _assessment(engine)
    g = _gap(engine, assessment_id=a["id"])
    plan = engine.create_remediation_plan("org1", {
        "gap_id": g["id"],
        "plan_description": "Fix it",
        "owner": "alice",
        "target_date": "2026-06-30",
    })
    active = engine.update_plan_status("org1", plan["id"], "active")
    assert active["status"] == "active"
    completed = engine.update_plan_status("org1", plan["id"], "completed")
    assert completed["status"] == "completed"


def test_update_plan_status_invalid(engine):
    a = _assessment(engine)
    g = _gap(engine, assessment_id=a["id"])
    plan = engine.create_remediation_plan("org1", {
        "gap_id": g["id"],
        "plan_description": "Fix",
        "owner": "alice",
        "target_date": "2026-06-30",
    })
    with pytest.raises(ValueError, match="new_status"):
        engine.update_plan_status("org1", plan["id"], "done")


# ---------------------------------------------------------------------------
# get_gap_stats
# ---------------------------------------------------------------------------


def test_get_gap_stats_empty(engine):
    stats = engine.get_gap_stats("org1")
    assert stats["total_assessments"] == 0
    assert stats["total_gaps"] == 0
    assert stats["critical_gaps"] == 0
    assert stats["avg_remediation_hours"] == 0.0


def test_get_gap_stats_aggregations(engine):
    a = _assessment(engine, framework="SOC2")
    g1 = engine.add_control_gap("org1", {
        "assessment_id": a["id"],
        "control_id": "C1", "control_name": "C1",
        "severity": "critical", "remediation_effort": 10,
    })
    g2 = engine.add_control_gap("org1", {
        "assessment_id": a["id"],
        "control_id": "C2", "control_name": "C2",
        "severity": "high", "remediation_effort": 6,
    })
    stats = engine.get_gap_stats("org1")
    assert stats["total_assessments"] == 1
    assert stats["total_gaps"] == 2
    assert stats["open_gaps"] == 2
    assert stats["critical_gaps"] == 1
    assert stats["avg_remediation_hours"] == pytest.approx(8.0)
    assert "SOC2" in stats["by_framework"]


def test_get_gap_stats_completed_count(engine):
    a = _assessment(engine)
    engine.complete_assessment("org1", a["id"])
    stats = engine.get_gap_stats("org1")
    assert stats["completed_assessments"] == 1


# ---------------------------------------------------------------------------
# Org isolation
# ---------------------------------------------------------------------------


def test_org_isolation_assessments(engine):
    _assessment(engine, org_id="org1")
    _assessment(engine, org_id="org2")
    assert len(engine.list_assessments("org1")) == 1
    assert len(engine.list_assessments("org2")) == 1


def test_org_isolation_gaps(engine):
    a1 = _assessment(engine, org_id="org1")
    _gap(engine, org_id="org1", assessment_id=a1["id"])
    assert len(engine.list_gaps("org1")) == 1
    assert len(engine.list_gaps("org2")) == 0


def test_org_isolation_stats(engine):
    a = _assessment(engine, org_id="org1")
    _gap(engine, org_id="org1", assessment_id=a["id"])
    stats_org1 = engine.get_gap_stats("org1")
    stats_org2 = engine.get_gap_stats("org2")
    assert stats_org1["total_gaps"] == 1
    assert stats_org2["total_gaps"] == 0
