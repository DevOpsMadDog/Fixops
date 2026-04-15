"""Tests for ComplianceAutomationEngine — ALDECI.

Coverage: job lifecycle, control results, stats, validation, org isolation.
"""

from __future__ import annotations

import pytest

from core.compliance_automation_engine import ComplianceAutomationEngine


@pytest.fixture
def engine(tmp_path):
    return ComplianceAutomationEngine(db_path=str(tmp_path / "ca.db"))


# ---------------------------------------------------------------------------
# create_automation_job — valid frameworks
# ---------------------------------------------------------------------------

VALID_FRAMEWORKS = ["soc2", "pci_dss", "hipaa", "gdpr", "iso27001", "nist_csf", "cis", "fedramp"]
VALID_AUTO_TYPES = [
    "evidence_collection", "control_testing", "report_generation", "gap_scan", "policy_check"
]


@pytest.mark.parametrize("framework", VALID_FRAMEWORKS)
def test_create_job_all_frameworks(engine, framework):
    job = engine.create_automation_job("org1", {
        "framework": framework,
        "automation_type": "evidence_collection",
        "description": f"Test job for {framework}",
    })
    assert job["framework"] == framework
    assert job["status"] == "queued"
    assert job["org_id"] == "org1"
    assert "id" in job
    assert "created_at" in job


@pytest.mark.parametrize("auto_type", VALID_AUTO_TYPES)
def test_create_job_all_automation_types(engine, auto_type):
    job = engine.create_automation_job("org1", {
        "framework": "soc2",
        "automation_type": auto_type,
    })
    assert job["automation_type"] == auto_type
    assert job["status"] == "queued"


def test_create_job_invalid_framework_raises(engine):
    with pytest.raises(ValueError, match="framework"):
        engine.create_automation_job("org1", {
            "framework": "notaframework",
            "automation_type": "evidence_collection",
        })


def test_create_job_invalid_automation_type_raises(engine):
    with pytest.raises(ValueError, match="automation_type"):
        engine.create_automation_job("org1", {
            "framework": "soc2",
            "automation_type": "bad_type",
        })


def test_create_job_defaults(engine):
    job = engine.create_automation_job("org1", {})
    assert job["framework"] == "soc2"
    assert job["automation_type"] == "evidence_collection"
    assert job["status"] == "queued"
    assert job["results_json"] == "{}"
    assert job["started_at"] is None
    assert job["completed_at"] is None


# ---------------------------------------------------------------------------
# list_jobs
# ---------------------------------------------------------------------------

def test_list_jobs_empty(engine):
    assert engine.list_jobs("org1") == []


def test_list_jobs_returns_all(engine):
    engine.create_automation_job("org1", {"framework": "soc2", "automation_type": "gap_scan"})
    engine.create_automation_job("org1", {"framework": "hipaa", "automation_type": "control_testing"})
    jobs = engine.list_jobs("org1")
    assert len(jobs) == 2


def test_list_jobs_filter_framework(engine):
    engine.create_automation_job("org1", {"framework": "soc2"})
    engine.create_automation_job("org1", {"framework": "hipaa"})
    soc2_jobs = engine.list_jobs("org1", framework="soc2")
    assert len(soc2_jobs) == 1
    assert soc2_jobs[0]["framework"] == "soc2"


def test_list_jobs_filter_status(engine):
    engine.create_automation_job("org1", {"framework": "soc2"})
    queued = engine.list_jobs("org1", status="queued")
    assert len(queued) == 1
    completed = engine.list_jobs("org1", status="completed")
    assert len(completed) == 0


def test_list_jobs_filter_automation_type(engine):
    engine.create_automation_job("org1", {"automation_type": "gap_scan"})
    engine.create_automation_job("org1", {"automation_type": "control_testing"})
    gaps = engine.list_jobs("org1", automation_type="gap_scan")
    assert len(gaps) == 1


def test_list_jobs_org_isolation(engine):
    engine.create_automation_job("org1", {"framework": "soc2"})
    engine.create_automation_job("org2", {"framework": "hipaa"})
    assert len(engine.list_jobs("org1")) == 1
    assert len(engine.list_jobs("org2")) == 1


# ---------------------------------------------------------------------------
# get_job
# ---------------------------------------------------------------------------

def test_get_job_returns_correct(engine):
    job = engine.create_automation_job("org1", {"framework": "gdpr"})
    fetched = engine.get_job("org1", job["id"])
    assert fetched is not None
    assert fetched["id"] == job["id"]
    assert fetched["framework"] == "gdpr"


def test_get_job_not_found_returns_none(engine):
    assert engine.get_job("org1", "nonexistent-id") is None


def test_get_job_org_isolation(engine):
    job = engine.create_automation_job("org1", {"framework": "soc2"})
    assert engine.get_job("org2", job["id"]) is None


# ---------------------------------------------------------------------------
# run_job
# ---------------------------------------------------------------------------

def test_run_job_completes(engine):
    job = engine.create_automation_job("org1", {"framework": "nist_csf"})
    result = engine.run_job("org1", job["id"])
    assert result["status"] == "completed"
    assert result["started_at"] is not None
    assert result["completed_at"] is not None


def test_run_job_has_results_json(engine):
    import json
    job = engine.create_automation_job("org1", {"framework": "pci_dss"})
    result = engine.run_job("org1", job["id"])
    parsed = json.loads(result["results_json"])
    assert "controls_tested" in parsed
    assert "passed" in parsed
    assert "failed" in parsed
    assert "partial" in parsed


def test_run_job_not_found_raises(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.run_job("org1", "bad-id")


def test_run_job_org_isolation(engine):
    job = engine.create_automation_job("org1", {"framework": "iso27001"})
    with pytest.raises(ValueError):
        engine.run_job("org2", job["id"])


# ---------------------------------------------------------------------------
# record_control_result
# ---------------------------------------------------------------------------

VALID_CTRL_RESULTS = ["pass", "fail", "partial", "na"]


@pytest.mark.parametrize("ctrl_result", VALID_CTRL_RESULTS)
def test_record_control_result_all_valid(engine, ctrl_result):
    rec = engine.record_control_result("org1", {
        "framework": "soc2",
        "control_id": "CC6.1",
        "control_name": "Logical Access",
        "result": ctrl_result,
        "evidence_url": "https://evidence.example.com/cc61",
        "notes": "Tested in Q1",
    })
    assert rec["result"] == ctrl_result
    assert rec["org_id"] == "org1"
    assert "id" in rec
    assert "tested_at" in rec


def test_record_control_result_invalid_result_raises(engine):
    with pytest.raises(ValueError, match="control result"):
        engine.record_control_result("org1", {
            "framework": "soc2",
            "result": "unknown_result",
        })


def test_record_control_result_invalid_framework_raises(engine):
    with pytest.raises(ValueError, match="framework"):
        engine.record_control_result("org1", {
            "framework": "bad_fw",
            "result": "pass",
        })


def test_record_control_result_defaults(engine):
    rec = engine.record_control_result("org1", {})
    assert rec["framework"] == "soc2"
    assert rec["result"] == "na"


# ---------------------------------------------------------------------------
# list_control_results
# ---------------------------------------------------------------------------

def test_list_control_results_empty(engine):
    assert engine.list_control_results("org1") == []


def test_list_control_results_returns_all(engine):
    engine.record_control_result("org1", {"framework": "soc2", "result": "pass"})
    engine.record_control_result("org1", {"framework": "hipaa", "result": "fail"})
    assert len(engine.list_control_results("org1")) == 2


def test_list_control_results_filter_framework(engine):
    engine.record_control_result("org1", {"framework": "soc2", "result": "pass"})
    engine.record_control_result("org1", {"framework": "hipaa", "result": "fail"})
    soc2 = engine.list_control_results("org1", framework="soc2")
    assert len(soc2) == 1
    assert soc2[0]["framework"] == "soc2"


def test_list_control_results_filter_result(engine):
    engine.record_control_result("org1", {"result": "pass"})
    engine.record_control_result("org1", {"result": "fail"})
    passes = engine.list_control_results("org1", result="pass")
    assert len(passes) == 1
    assert passes[0]["result"] == "pass"


def test_list_control_results_filter_job_id(engine):
    job = engine.create_automation_job("org1", {})
    engine.record_control_result("org1", {"job_id": job["id"], "result": "pass"})
    engine.record_control_result("org1", {"job_id": "other-job", "result": "fail"})
    by_job = engine.list_control_results("org1", job_id=job["id"])
    assert len(by_job) == 1


def test_list_control_results_org_isolation(engine):
    engine.record_control_result("org1", {"result": "pass"})
    engine.record_control_result("org2", {"result": "fail"})
    assert len(engine.list_control_results("org1")) == 1
    assert len(engine.list_control_results("org2")) == 1


# ---------------------------------------------------------------------------
# get_compliance_stats
# ---------------------------------------------------------------------------

def test_get_stats_empty(engine):
    stats = engine.get_compliance_stats("org1")
    assert stats["total_jobs"] == 0
    assert stats["completed_jobs"] == 0
    assert stats["failed_jobs"] == 0
    assert stats["total_controls_tested"] == 0
    assert stats["pass_rate"] == 0.0
    assert stats["by_framework"] == {}
    assert stats["recent_failures"] == []


def test_get_stats_with_data(engine):
    engine.create_automation_job("org1", {"framework": "soc2"})
    job2 = engine.create_automation_job("org1", {"framework": "hipaa"})
    engine.run_job("org1", job2["id"])

    engine.record_control_result("org1", {"framework": "soc2", "result": "pass"})
    engine.record_control_result("org1", {"framework": "soc2", "result": "pass"})
    engine.record_control_result("org1", {"framework": "soc2", "result": "fail", "control_id": "C1"})

    stats = engine.get_compliance_stats("org1")
    assert stats["total_jobs"] == 2
    assert stats["completed_jobs"] == 1
    assert stats["total_controls_tested"] == 3
    assert round(stats["pass_rate"], 1) == round(2 / 3 * 100, 1)
    assert "soc2" in stats["by_framework"]
    assert "hipaa" in stats["by_framework"]


def test_get_stats_recent_failures_max_5(engine):
    for i in range(7):
        engine.record_control_result("org1", {
            "result": "fail",
            "control_id": f"C{i}",
            "control_name": f"Control {i}",
        })
    stats = engine.get_compliance_stats("org1")
    assert len(stats["recent_failures"]) == 5


def test_get_stats_pass_rate_all_pass(engine):
    for _ in range(4):
        engine.record_control_result("org1", {"result": "pass"})
    stats = engine.get_compliance_stats("org1")
    assert stats["pass_rate"] == 100.0


def test_get_stats_org_isolation(engine):
    engine.create_automation_job("org1", {})
    engine.create_automation_job("org2", {})
    engine.record_control_result("org1", {"result": "pass"})

    s1 = engine.get_compliance_stats("org1")
    s2 = engine.get_compliance_stats("org2")
    assert s1["total_jobs"] == 1
    assert s2["total_jobs"] == 1
    assert s1["total_controls_tested"] == 1
    assert s2["total_controls_tested"] == 0
