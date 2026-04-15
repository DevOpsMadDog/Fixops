"""Tests for CloudComplianceEngine — multi-cloud compliance posture.

Coverage:
  - Assessment CRUD and lifecycle
  - Control result recording + automatic score computation
  - Assessment completion + drift detection
  - Remediation plan management
  - Drift history retrieval
  - Stats aggregation
  - Org isolation
"""

from __future__ import annotations

import pytest
import tempfile
import os
from pathlib import Path


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture()
def engine(tmp_path):
    from core.cloud_compliance_engine import CloudComplianceEngine
    db = str(tmp_path / "test_cloud_compliance.db")
    return CloudComplianceEngine(db_path=db)


ORG = "org_cc_test"
ORG2 = "org_cc_other"


# ---------------------------------------------------------------------------
# Assessment creation
# ---------------------------------------------------------------------------

def test_create_assessment_basic(engine):
    a = engine.create_assessment(ORG, {
        "cloud_provider": "aws",
        "framework": "cis_aws_v1.5",
        "scope": {"accounts": ["123456789"]},
    })
    assert a["id"]
    assert a["framework"] == "cis_aws_v1.5"
    assert a["cloud_provider"] == "aws"
    assert a["status"] == "running"
    assert a["score"] == 0.0
    assert isinstance(a["scope"], dict)


def test_create_assessment_invalid_framework(engine):
    with pytest.raises(ValueError, match="Invalid framework"):
        engine.create_assessment(ORG, {"framework": "cis_unknown"})


def test_create_assessment_invalid_provider(engine):
    with pytest.raises(ValueError, match="Invalid cloud_provider"):
        engine.create_assessment(ORG, {"framework": "soc2", "cloud_provider": "oracle"})


def test_create_assessment_all_frameworks(engine):
    frameworks = [
        "cis_aws_v1.5", "cis_azure_v1.5", "cis_gcp_v1.3",
        "nist_800_53", "soc2", "pci_dss", "hipaa", "iso27001",
    ]
    for fw in frameworks:
        a = engine.create_assessment(ORG, {"framework": fw})
        assert a["framework"] == fw


def test_create_assessment_all_providers(engine):
    for provider in ("aws", "azure", "gcp", "multi"):
        a = engine.create_assessment(ORG, {"framework": "soc2", "cloud_provider": provider})
        assert a["cloud_provider"] == provider


# ---------------------------------------------------------------------------
# List / Get assessments
# ---------------------------------------------------------------------------

def test_list_assessments_empty(engine):
    assert engine.list_assessments(ORG) == []


def test_list_assessments_returns_created(engine):
    engine.create_assessment(ORG, {"framework": "soc2", "cloud_provider": "aws"})
    engine.create_assessment(ORG, {"framework": "hipaa", "cloud_provider": "azure"})
    all_a = engine.list_assessments(ORG)
    assert len(all_a) == 2


def test_list_assessments_filter_framework(engine):
    engine.create_assessment(ORG, {"framework": "soc2"})
    engine.create_assessment(ORG, {"framework": "hipaa"})
    soc2 = engine.list_assessments(ORG, framework="soc2")
    assert len(soc2) == 1
    assert soc2[0]["framework"] == "soc2"


def test_list_assessments_filter_provider(engine):
    engine.create_assessment(ORG, {"framework": "soc2", "cloud_provider": "aws"})
    engine.create_assessment(ORG, {"framework": "soc2", "cloud_provider": "gcp"})
    aws_only = engine.list_assessments(ORG, provider="aws")
    assert len(aws_only) == 1
    assert aws_only[0]["cloud_provider"] == "aws"


def test_get_assessment_not_found(engine):
    assert engine.get_assessment(ORG, "nonexistent") is None


def test_get_assessment_includes_control_summary(engine):
    a = engine.create_assessment(ORG, {"framework": "soc2"})
    engine.add_control_result(ORG, a["id"], {"control_id": "CC1.1", "status": "passed", "severity": "high"})
    engine.add_control_result(ORG, a["id"], {"control_id": "CC1.2", "status": "failed", "severity": "critical"})
    result = engine.get_assessment(ORG, a["id"])
    assert "control_summary" in result
    assert result["passed"] == 1
    assert result["failed"] == 1


# ---------------------------------------------------------------------------
# Control results
# ---------------------------------------------------------------------------

def test_add_control_result_basic(engine):
    a = engine.create_assessment(ORG, {"framework": "cis_aws_v1.5"})
    cr = engine.add_control_result(ORG, a["id"], {
        "control_id": "1.1",
        "control_name": "Avoid root account usage",
        "severity": "critical",
        "status": "passed",
        "region": "us-east-1",
    })
    assert cr["id"]
    assert cr["control_id"] == "1.1"
    assert cr["status"] == "passed"


def test_add_control_result_updates_score(engine):
    a = engine.create_assessment(ORG, {"framework": "cis_aws_v1.5"})
    engine.add_control_result(ORG, a["id"], {"control_id": "1.1", "status": "passed", "severity": "high"})
    engine.add_control_result(ORG, a["id"], {"control_id": "1.2", "status": "passed", "severity": "high"})
    engine.add_control_result(ORG, a["id"], {"control_id": "1.3", "status": "failed", "severity": "high"})
    updated = engine.get_assessment(ORG, a["id"])
    assert updated["passed"] == 2
    assert updated["failed"] == 1
    assert updated["score"] == pytest.approx(66.67, abs=0.1)


def test_add_control_result_invalid_status(engine):
    a = engine.create_assessment(ORG, {"framework": "soc2"})
    with pytest.raises(ValueError, match="Invalid status"):
        engine.add_control_result(ORG, a["id"], {"control_id": "CC1", "status": "unknown"})


def test_add_control_result_invalid_severity(engine):
    a = engine.create_assessment(ORG, {"framework": "soc2"})
    with pytest.raises(ValueError, match="Invalid severity"):
        engine.add_control_result(ORG, a["id"], {"control_id": "CC1", "severity": "extreme"})


def test_add_control_result_requires_control_id(engine):
    a = engine.create_assessment(ORG, {"framework": "soc2"})
    with pytest.raises(ValueError, match="control_id is required"):
        engine.add_control_result(ORG, a["id"], {"control_id": ""})


def test_list_control_results_filter_status(engine):
    a = engine.create_assessment(ORG, {"framework": "soc2"})
    engine.add_control_result(ORG, a["id"], {"control_id": "C1", "status": "passed", "severity": "low"})
    engine.add_control_result(ORG, a["id"], {"control_id": "C2", "status": "failed", "severity": "high"})
    failed = engine.list_control_results(ORG, status="failed")
    assert len(failed) == 1
    assert failed[0]["control_id"] == "C2"


def test_list_control_results_filter_severity(engine):
    a = engine.create_assessment(ORG, {"framework": "soc2"})
    engine.add_control_result(ORG, a["id"], {"control_id": "C1", "status": "failed", "severity": "critical"})
    engine.add_control_result(ORG, a["id"], {"control_id": "C2", "status": "failed", "severity": "low"})
    crits = engine.list_control_results(ORG, severity="critical")
    assert len(crits) == 1
    assert crits[0]["severity"] == "critical"


# ---------------------------------------------------------------------------
# Assessment completion + drift
# ---------------------------------------------------------------------------

def test_complete_assessment(engine):
    a = engine.create_assessment(ORG, {"framework": "soc2"})
    engine.add_control_result(ORG, a["id"], {"control_id": "C1", "status": "passed", "severity": "high"})
    engine.add_control_result(ORG, a["id"], {"control_id": "C2", "status": "failed", "severity": "medium"})
    completed = engine.complete_assessment(ORG, a["id"])
    assert completed["status"] == "completed"
    assert completed["assessed_at"] is not None
    assert completed["score"] > 0


def test_complete_assessment_not_found(engine):
    assert engine.complete_assessment(ORG, "bad-id") is None


def test_complete_assessment_creates_drift_on_second(engine):
    # First assessment
    a1 = engine.create_assessment(ORG, {"framework": "soc2"})
    engine.add_control_result(ORG, a1["id"], {"control_id": "C1", "status": "passed", "severity": "high"})
    engine.add_control_result(ORG, a1["id"], {"control_id": "C2", "status": "failed", "severity": "high"})
    engine.complete_assessment(ORG, a1["id"])

    # Second assessment (should create drift record)
    a2 = engine.create_assessment(ORG, {"framework": "soc2"})
    engine.add_control_result(ORG, a2["id"], {"control_id": "C1", "status": "passed", "severity": "high"})
    engine.add_control_result(ORG, a2["id"], {"control_id": "C2", "status": "passed", "severity": "high"})
    engine.complete_assessment(ORG, a2["id"])

    drift = engine.list_drift_history(ORG, framework="soc2")
    assert len(drift) >= 1
    assert drift[0]["drift_direction"] in ("improving", "stable", "declining")


def test_score_100_when_all_passed(engine):
    a = engine.create_assessment(ORG, {"framework": "pci_dss"})
    for i in range(5):
        engine.add_control_result(ORG, a["id"], {"control_id": f"C{i}", "status": "passed", "severity": "high"})
    completed = engine.complete_assessment(ORG, a["id"])
    assert completed["score"] == pytest.approx(100.0)


def test_not_applicable_excluded_from_score(engine):
    a = engine.create_assessment(ORG, {"framework": "hipaa"})
    engine.add_control_result(ORG, a["id"], {"control_id": "C1", "status": "passed", "severity": "high"})
    engine.add_control_result(ORG, a["id"], {"control_id": "C2", "status": "not_applicable", "severity": "high"})
    updated = engine.get_assessment(ORG, a["id"])
    # passed=1, not_applicable=1, failed=0, total=2 → score = 1/2 * 100 = 50
    assert updated["score"] == pytest.approx(50.0)


# ---------------------------------------------------------------------------
# Remediation plans
# ---------------------------------------------------------------------------

def test_create_remediation_plan(engine):
    a = engine.create_assessment(ORG, {"framework": "soc2"})
    plan = engine.create_remediation_plan(ORG, {
        "assessment_id": a["id"],
        "control_id": "CC1.1",
        "priority": "p1",
        "assigned_team": "SecOps",
        "estimated_effort": "high",
        "target_date": "2026-06-01",
    })
    assert plan["id"]
    assert plan["priority"] == "p1"
    assert plan["status"] == "planned"


def test_create_remediation_plan_missing_fields(engine):
    with pytest.raises(ValueError, match="assessment_id and control_id are required"):
        engine.create_remediation_plan(ORG, {"assessment_id": "x"})


def test_create_remediation_plan_invalid_priority(engine):
    with pytest.raises(ValueError, match="Invalid priority"):
        engine.create_remediation_plan(ORG, {"assessment_id": "x", "control_id": "C1", "priority": "p0"})


def test_update_remediation_plan_status(engine):
    a = engine.create_assessment(ORG, {"framework": "soc2"})
    plan = engine.create_remediation_plan(ORG, {"assessment_id": a["id"], "control_id": "C1"})
    updated = engine.update_remediation_plan(ORG, plan["id"], "in_progress")
    assert updated is True


def test_update_remediation_plan_invalid_status(engine):
    with pytest.raises(ValueError, match="Invalid status"):
        engine.update_remediation_plan(ORG, "some-id", "done")


def test_update_remediation_plan_not_found(engine):
    result = engine.update_remediation_plan(ORG, "nonexistent", "completed")
    assert result is False


def test_list_remediation_plans_filter(engine):
    a = engine.create_assessment(ORG, {"framework": "soc2"})
    p1 = engine.create_remediation_plan(ORG, {"assessment_id": a["id"], "control_id": "C1"})
    engine.create_remediation_plan(ORG, {"assessment_id": a["id"], "control_id": "C2"})
    engine.update_remediation_plan(ORG, p1["id"], "completed")
    planned = engine.list_remediation_plans(ORG, status="planned")
    assert len(planned) == 1


# ---------------------------------------------------------------------------
# Drift history
# ---------------------------------------------------------------------------

def test_list_drift_history_empty(engine):
    assert engine.list_drift_history(ORG) == []


def test_list_drift_history_limit(engine):
    # Create multiple drift records via multiple assessments
    for _ in range(3):
        a = engine.create_assessment(ORG, {"framework": "nist_800_53"})
        engine.add_control_result(ORG, a["id"], {"control_id": "AC-1", "status": "passed", "severity": "high"})
        engine.complete_assessment(ORG, a["id"])
    history = engine.list_drift_history(ORG, limit=2)
    assert len(history) <= 2


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def test_get_compliance_stats_empty(engine):
    stats = engine.get_compliance_stats(ORG)
    assert stats["assessments_run"] == 0
    assert stats["critical_failures"] == 0
    assert stats["pass_rate"] == 0.0


def test_get_compliance_stats_populated(engine):
    a = engine.create_assessment(ORG, {"framework": "soc2"})
    engine.add_control_result(ORG, a["id"], {"control_id": "C1", "status": "passed", "severity": "high"})
    engine.add_control_result(ORG, a["id"], {"control_id": "C2", "status": "failed", "severity": "critical"})
    engine.complete_assessment(ORG, a["id"])
    engine.create_remediation_plan(ORG, {"assessment_id": a["id"], "control_id": "C2"})

    stats = engine.get_compliance_stats(ORG)
    assert stats["assessments_run"] == 1
    assert stats["critical_failures"] == 1
    assert stats["remediation_plans_active"] == 1
    assert stats["frameworks_assessed"] == 1
    assert "soc2" in stats["avg_score_by_framework"]


# ---------------------------------------------------------------------------
# Org isolation
# ---------------------------------------------------------------------------

def test_org_isolation_assessments(engine):
    engine.create_assessment(ORG, {"framework": "soc2"})
    assert engine.list_assessments(ORG2) == []


def test_org_isolation_control_results(engine):
    a = engine.create_assessment(ORG, {"framework": "soc2"})
    engine.add_control_result(ORG, a["id"], {"control_id": "C1", "status": "passed", "severity": "low"})
    assert engine.list_control_results(ORG2) == []


def test_org_isolation_remediation_plans(engine):
    a = engine.create_assessment(ORG, {"framework": "soc2"})
    engine.create_remediation_plan(ORG, {"assessment_id": a["id"], "control_id": "C1"})
    assert engine.list_remediation_plans(ORG2) == []
