"""
Tests for CNAPPEngine — 25+ tests covering all methods and org isolation.
"""
from __future__ import annotations

import pytest

from core.cnapp_engine import CNAPPEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "test_cnapp.db")
    return CNAPPEngine(db_path=db)


@pytest.fixture
def org_a():
    return "org-alpha"


@pytest.fixture
def org_b():
    return "org-beta"


def _make_workload(engine, org_id, **kwargs):
    data = {
        "name": "test-workload",
        "workload_type": "container",
        "cloud_provider": "aws",
        "region": "us-east-1",
        "running": True,
        "privileged": False,
    }
    data.update(kwargs)
    return engine.register_workload(org_id, data)


def _add_finding(engine, org_id, workload_id, **kwargs):
    data = {
        "category": "misconfiguration",
        "severity": "high",
        "title": "Test finding",
        "description": "A test finding",
        "remediation": "Fix it",
    }
    data.update(kwargs)
    return engine.add_finding(org_id, workload_id, data)


# ---------------------------------------------------------------------------
# register_workload
# ---------------------------------------------------------------------------

def test_register_workload_returns_record(engine, org_a):
    rec = _make_workload(engine, org_a)
    assert rec["workload_id"]
    assert rec["org_id"] == org_a
    assert rec["name"] == "test-workload"
    assert rec["workload_type"] == "container"
    assert rec["cloud_provider"] == "aws"
    assert rec["risk_score"] == 0.0
    assert rec["running"] == 1


def test_register_workload_invalid_type_defaults_vm(engine, org_a):
    rec = _make_workload(engine, org_a, workload_type="mainframe")
    assert rec["workload_type"] == "vm"


def test_register_workload_invalid_provider_defaults_aws(engine, org_a):
    rec = _make_workload(engine, org_a, cloud_provider="oracle")
    assert rec["cloud_provider"] == "aws"


def test_register_workload_privileged(engine, org_a):
    rec = _make_workload(engine, org_a, privileged=True)
    assert rec["privileged"] == 1


# ---------------------------------------------------------------------------
# list_workloads
# ---------------------------------------------------------------------------

def test_list_workloads_running_only(engine, org_a):
    _make_workload(engine, org_a, name="running", running=True)
    _make_workload(engine, org_a, name="stopped", running=False)
    results = engine.list_workloads(org_a, running_only=True)
    assert len(results) == 1
    assert results[0]["name"] == "running"


def test_list_workloads_all(engine, org_a):
    _make_workload(engine, org_a, name="running", running=True)
    _make_workload(engine, org_a, name="stopped", running=False)
    results = engine.list_workloads(org_a, running_only=False)
    assert len(results) == 2


def test_list_workloads_filter_type(engine, org_a):
    _make_workload(engine, org_a, name="c1", workload_type="container")
    _make_workload(engine, org_a, name="vm1", workload_type="vm")
    results = engine.list_workloads(org_a, workload_type="container", running_only=False)
    assert len(results) == 1
    assert results[0]["name"] == "c1"


def test_list_workloads_filter_provider(engine, org_a):
    _make_workload(engine, org_a, name="aws1", cloud_provider="aws")
    _make_workload(engine, org_a, name="gcp1", cloud_provider="gcp")
    results = engine.list_workloads(org_a, cloud_provider="gcp", running_only=False)
    assert len(results) == 1
    assert results[0]["name"] == "gcp1"


def test_list_workloads_org_isolation(engine, org_a, org_b):
    _make_workload(engine, org_a)
    assert len(engine.list_workloads(org_b, running_only=False)) == 0


# ---------------------------------------------------------------------------
# add_finding
# ---------------------------------------------------------------------------

def test_add_finding_returns_record(engine, org_a):
    wl = _make_workload(engine, org_a)
    finding = _add_finding(engine, org_a, wl["workload_id"])
    assert finding["finding_id"]
    assert finding["category"] == "misconfiguration"
    assert finding["severity"] == "high"
    assert finding["status"] == "open"


def test_add_finding_critical_updates_risk_score(engine, org_a):
    wl = _make_workload(engine, org_a)
    wid = wl["workload_id"]
    _add_finding(engine, org_a, wid, severity="critical")
    workloads = engine.list_workloads(org_a, running_only=False)
    assert workloads[0]["risk_score"] == pytest.approx(0.4)


def test_add_finding_high_updates_risk_score(engine, org_a):
    wl = _make_workload(engine, org_a)
    wid = wl["workload_id"]
    _add_finding(engine, org_a, wid, severity="high")
    workloads = engine.list_workloads(org_a, running_only=False)
    assert workloads[0]["risk_score"] == pytest.approx(0.2)


def test_add_finding_multiple_caps_at_1(engine, org_a):
    wl = _make_workload(engine, org_a)
    wid = wl["workload_id"]
    for _ in range(4):
        _add_finding(engine, org_a, wid, severity="critical")
    workloads = engine.list_workloads(org_a, running_only=False)
    assert workloads[0]["risk_score"] <= 1.0


def test_add_finding_invalid_category_defaults(engine, org_a):
    wl = _make_workload(engine, org_a)
    finding = _add_finding(engine, org_a, wl["workload_id"], category="unknown")
    assert finding["category"] == "misconfiguration"


def test_add_finding_invalid_severity_defaults(engine, org_a):
    wl = _make_workload(engine, org_a)
    finding = _add_finding(engine, org_a, wl["workload_id"], severity="ultra")
    assert finding["severity"] == "medium"


# ---------------------------------------------------------------------------
# list_findings
# ---------------------------------------------------------------------------

def test_list_findings_filter_category(engine, org_a):
    wl = _make_workload(engine, org_a)
    wid = wl["workload_id"]
    _add_finding(engine, org_a, wid, category="misconfiguration")
    _add_finding(engine, org_a, wid, category="vulnerability")
    results = engine.list_findings(org_a, category="vulnerability")
    assert len(results) == 1


def test_list_findings_filter_severity(engine, org_a):
    wl = _make_workload(engine, org_a)
    wid = wl["workload_id"]
    _add_finding(engine, org_a, wid, severity="critical")
    _add_finding(engine, org_a, wid, severity="low")
    results = engine.list_findings(org_a, severity="critical")
    assert len(results) == 1


def test_list_findings_filter_status(engine, org_a):
    wl = _make_workload(engine, org_a)
    wid = wl["workload_id"]
    f = _add_finding(engine, org_a, wid)
    engine.suppress_finding(org_a, f["finding_id"])
    _add_finding(engine, org_a, wid)
    open_findings = engine.list_findings(org_a, status="open")
    assert len(open_findings) == 1


def test_list_findings_org_isolation(engine, org_a, org_b):
    wl = _make_workload(engine, org_a)
    _add_finding(engine, org_a, wl["workload_id"])
    assert len(engine.list_findings(org_b)) == 0


# ---------------------------------------------------------------------------
# suppress_finding
# ---------------------------------------------------------------------------

def test_suppress_finding_returns_true(engine, org_a):
    wl = _make_workload(engine, org_a)
    f = _add_finding(engine, org_a, wl["workload_id"])
    assert engine.suppress_finding(org_a, f["finding_id"]) is True


def test_suppress_finding_nonexistent_returns_false(engine, org_a):
    assert engine.suppress_finding(org_a, "no-such-id") is False


def test_suppress_finding_org_isolation(engine, org_a, org_b):
    wl = _make_workload(engine, org_a)
    f = _add_finding(engine, org_a, wl["workload_id"])
    assert engine.suppress_finding(org_b, f["finding_id"]) is False


# ---------------------------------------------------------------------------
# create_policy / list_policies
# ---------------------------------------------------------------------------

def test_create_policy_returns_record(engine, org_a):
    policy = engine.create_policy(org_a, {
        "name": "Block Public S3",
        "policy_type": "network",
        "action": "block",
        "severity": "critical",
        "cloud_provider": "aws",
    })
    assert policy["policy_id"]
    assert policy["name"] == "Block Public S3"
    assert policy["action"] == "block"


def test_create_policy_invalid_type_defaults_network(engine, org_a):
    policy = engine.create_policy(org_a, {"name": "test", "policy_type": "quantum"})
    assert policy["policy_type"] == "network"


def test_list_policies_enabled_only(engine, org_a):
    engine.create_policy(org_a, {"name": "enabled", "enabled": True})
    engine.create_policy(org_a, {"name": "disabled", "enabled": False})
    results = engine.list_policies(org_a, enabled_only=True)
    assert len(results) == 1
    assert results[0]["name"] == "enabled"


def test_list_policies_filter_provider(engine, org_a):
    engine.create_policy(org_a, {"name": "aws-policy", "cloud_provider": "aws"})
    engine.create_policy(org_a, {"name": "gcp-policy", "cloud_provider": "gcp"})
    results = engine.list_policies(org_a, cloud_provider="gcp", enabled_only=False)
    assert len(results) == 1


def test_list_policies_org_isolation(engine, org_a, org_b):
    engine.create_policy(org_a, {"name": "p1"})
    assert len(engine.list_policies(org_b)) == 0


# ---------------------------------------------------------------------------
# calculate_cnapp_score
# ---------------------------------------------------------------------------

def test_calculate_cnapp_score_perfect_when_no_findings(engine, org_a):
    score = engine.calculate_cnapp_score(org_a)
    assert score["cspm_score"] == 100.0
    assert score["cwpp_score"] == 100.0
    assert score["ciem_score"] == 100.0
    assert score["composite_score"] == 100.0
    assert score["grade"] == "A"


def test_calculate_cnapp_score_critical_reduces_cspm(engine, org_a):
    wl = _make_workload(engine, org_a)
    _add_finding(engine, org_a, wl["workload_id"], category="misconfiguration", severity="critical")
    score = engine.calculate_cnapp_score(org_a)
    assert score["cspm_score"] == pytest.approx(85.0)  # 100 - 15


def test_calculate_cnapp_score_grade_f(engine, org_a):
    wl = _make_workload(engine, org_a)
    # Add 7 critical misconfigurations → cspm = 100 - 7*15 = -5 → 0
    for _ in range(7):
        _add_finding(engine, org_a, wl["workload_id"], category="misconfiguration", severity="critical")
    # Add 7 critical vulnerabilities → cwpp = 0
    for _ in range(7):
        _add_finding(engine, org_a, wl["workload_id"], category="vulnerability", severity="critical")
    score = engine.calculate_cnapp_score(org_a)
    assert score["grade"] == "F"


def test_calculate_cnapp_score_persisted(engine, org_a):
    engine.calculate_cnapp_score(org_a)
    engine.calculate_cnapp_score(org_a)
    scores = engine.list_scores(org_a)
    assert len(scores) == 2


def test_calculate_cnapp_score_suppressed_not_counted(engine, org_a):
    wl = _make_workload(engine, org_a)
    f = _add_finding(engine, org_a, wl["workload_id"], category="misconfiguration", severity="critical")
    engine.suppress_finding(org_a, f["finding_id"])
    score = engine.calculate_cnapp_score(org_a)
    assert score["cspm_score"] == 100.0


def test_list_scores_ordered_desc(engine, org_a):
    engine.calculate_cnapp_score(org_a)
    engine.calculate_cnapp_score(org_a)
    scores = engine.list_scores(org_a)
    assert scores[0]["calculated_at"] >= scores[1]["calculated_at"]


# ---------------------------------------------------------------------------
# get_cnapp_stats
# ---------------------------------------------------------------------------

def test_get_cnapp_stats_empty(engine, org_a):
    stats = engine.get_cnapp_stats(org_a)
    assert stats["total_workloads"] == 0
    assert stats["open_findings"] == 0
    assert stats["critical_findings"] == 0
    assert stats["by_category"] == {}
    assert stats["by_provider"] == {}
    assert stats["latest_composite_score"] is None


def test_get_cnapp_stats_counts(engine, org_a):
    wl = _make_workload(engine, org_a)
    wid = wl["workload_id"]
    _add_finding(engine, org_a, wid, category="misconfiguration", severity="critical")
    _add_finding(engine, org_a, wid, category="vulnerability", severity="high")
    stats = engine.get_cnapp_stats(org_a)
    assert stats["total_workloads"] == 1
    assert stats["open_findings"] == 2
    assert stats["critical_findings"] == 1
    assert "misconfiguration" in stats["by_category"]
    assert "aws" in stats["by_provider"]


def test_get_cnapp_stats_latest_score(engine, org_a):
    engine.calculate_cnapp_score(org_a)
    stats = engine.get_cnapp_stats(org_a)
    assert stats["latest_composite_score"] == 100.0


def test_get_cnapp_stats_org_isolation(engine, org_a, org_b):
    wl = _make_workload(engine, org_a)
    _add_finding(engine, org_a, wl["workload_id"])
    stats_b = engine.get_cnapp_stats(org_b)
    assert stats_b["total_workloads"] == 0
    assert stats_b["open_findings"] == 0
