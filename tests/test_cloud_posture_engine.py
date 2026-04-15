"""Tests for CloudPostureEngine — 35 tests."""
from __future__ import annotations

import pytest
from core.cloud_posture_engine import CloudPostureEngine, VALID_PROVIDERS, VALID_SEVERITIES


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    return CloudPostureEngine(db_path=str(tmp_path / "cp_test.db"))


def _account(engine, org_id="org1", account_id="123456789", provider="aws", **kwargs):
    data = {"account_id": account_id, "provider": provider, **kwargs}
    return engine.register_account(org_id, data)


def _finding(engine, cloud_account_id, org_id="org1", severity="medium", resource_type="compute", **kwargs):
    data = {
        "cloud_account_id": cloud_account_id,
        "severity": severity,
        "resource_type": resource_type,
        "title": "Test finding",
        **kwargs,
    }
    return engine.record_finding(org_id, data)


# ---------------------------------------------------------------------------
# register_account
# ---------------------------------------------------------------------------

def test_register_account_returns_record(engine):
    acc = _account(engine)
    assert acc["account_id"] == "123456789"
    assert acc["provider"] == "aws"
    assert acc["posture_score"] == 100.0
    assert acc["status"] == "active"
    assert "id" in acc
    assert "created_at" in acc


def test_register_account_missing_account_id_raises(engine):
    with pytest.raises(ValueError, match="account_id"):
        engine.register_account("org1", {"provider": "aws"})


def test_register_account_invalid_provider_raises(engine):
    with pytest.raises(ValueError, match="provider"):
        engine.register_account("org1", {"account_id": "abc", "provider": "bogus"})


def test_register_account_all_valid_providers(engine):
    for i, prov in enumerate(sorted(VALID_PROVIDERS)):
        acc = _account(engine, account_id=f"acct-{i}", provider=prov)
        assert acc["provider"] == prov


def test_register_account_stores_optional_fields(engine):
    acc = engine.register_account("org1", {
        "account_id": "acct-99",
        "provider": "gcp",
        "account_name": "Prod GCP",
        "region": "us-central1",
        "resource_count": 42,
    })
    assert acc["account_name"] == "Prod GCP"
    assert acc["region"] == "us-central1"
    assert acc["resource_count"] == 42


# ---------------------------------------------------------------------------
# list_accounts / get_account
# ---------------------------------------------------------------------------

def test_list_accounts_empty(engine):
    assert engine.list_accounts("org1") == []


def test_list_accounts_returns_all(engine):
    _account(engine, account_id="a1", provider="aws")
    _account(engine, account_id="a2", provider="azure")
    result = engine.list_accounts("org1")
    assert len(result) == 2


def test_list_accounts_provider_filter(engine):
    _account(engine, account_id="a1", provider="aws")
    _account(engine, account_id="a2", provider="gcp")
    aws_only = engine.list_accounts("org1", provider="aws")
    assert len(aws_only) == 1
    assert aws_only[0]["provider"] == "aws"


def test_list_accounts_org_isolation(engine):
    _account(engine, org_id="org1", account_id="a1")
    _account(engine, org_id="org2", account_id="a2")
    assert len(engine.list_accounts("org1")) == 1
    assert len(engine.list_accounts("org2")) == 1


def test_get_account_returns_record(engine):
    created = _account(engine)
    fetched = engine.get_account("org1", created["id"])
    assert fetched["id"] == created["id"]


def test_get_account_wrong_org_returns_none(engine):
    created = _account(engine, org_id="org1")
    assert engine.get_account("org2", created["id"]) is None


def test_get_account_nonexistent_returns_none(engine):
    assert engine.get_account("org1", "no-such-id") is None


# ---------------------------------------------------------------------------
# record_finding — validation
# ---------------------------------------------------------------------------

def test_record_finding_requires_cloud_account_id(engine):
    with pytest.raises(ValueError, match="cloud_account_id"):
        engine.record_finding("org1", {"severity": "high", "resource_type": "iam"})


def test_record_finding_invalid_resource_type(engine):
    with pytest.raises(ValueError, match="resource_type"):
        engine.record_finding("org1", {"cloud_account_id": "acct1", "resource_type": "bogus"})


def test_record_finding_invalid_severity(engine):
    with pytest.raises(ValueError, match="severity"):
        engine.record_finding("org1", {"cloud_account_id": "acct1", "severity": "ultra"})


# ---------------------------------------------------------------------------
# record_finding — posture score decrement
# ---------------------------------------------------------------------------

def test_record_finding_critical_decrements_10(engine):
    acc = _account(engine, account_id="acct-x")
    _finding(engine, cloud_account_id=acc["id"], severity="critical")
    updated = engine.get_account("org1", acc["id"])
    assert updated["posture_score"] == pytest.approx(90.0)


def test_record_finding_high_decrements_5(engine):
    acc = _account(engine, account_id="acct-h")
    _finding(engine, cloud_account_id=acc["id"], severity="high")
    updated = engine.get_account("org1", acc["id"])
    assert updated["posture_score"] == pytest.approx(95.0)


def test_record_finding_medium_decrements_2(engine):
    acc = _account(engine, account_id="acct-m")
    _finding(engine, cloud_account_id=acc["id"], severity="medium")
    updated = engine.get_account("org1", acc["id"])
    assert updated["posture_score"] == pytest.approx(98.0)


def test_record_finding_low_decrements_1(engine):
    acc = _account(engine, account_id="acct-l")
    _finding(engine, cloud_account_id=acc["id"], severity="low")
    updated = engine.get_account("org1", acc["id"])
    assert updated["posture_score"] == pytest.approx(99.0)


def test_record_finding_info_no_decrement(engine):
    acc = _account(engine, account_id="acct-i")
    _finding(engine, cloud_account_id=acc["id"], severity="info")
    updated = engine.get_account("org1", acc["id"])
    assert updated["posture_score"] == pytest.approx(100.0)


def test_record_finding_score_floor_at_zero(engine):
    acc = _account(engine, account_id="acct-floor")
    for _ in range(15):
        _finding(engine, cloud_account_id=acc["id"], severity="critical")
    updated = engine.get_account("org1", acc["id"])
    assert updated["posture_score"] == pytest.approx(0.0)


def test_record_finding_status_defaults_open(engine):
    acc = _account(engine, account_id="acct-s")
    f = _finding(engine, cloud_account_id=acc["id"])
    assert f["status"] == "open"
    assert f["resolved_at"] is None


# ---------------------------------------------------------------------------
# list_findings
# ---------------------------------------------------------------------------

def test_list_findings_empty(engine):
    assert engine.list_findings("org1") == []


def test_list_findings_returns_all(engine):
    _account(engine, account_id="a1")
    _finding(engine, cloud_account_id="a1", severity="high")
    _finding(engine, cloud_account_id="a1", severity="low")
    assert len(engine.list_findings("org1")) == 2


def test_list_findings_severity_filter(engine):
    _finding(engine, cloud_account_id="a1", severity="critical")
    _finding(engine, cloud_account_id="a1", severity="low")
    crits = engine.list_findings("org1", severity="critical")
    assert len(crits) == 1
    assert crits[0]["severity"] == "critical"


def test_list_findings_status_filter(engine):
    _finding(engine, cloud_account_id="a1")
    findings = engine.list_findings("org1", status="open")
    assert len(findings) == 1


def test_list_findings_resource_type_filter(engine):
    _finding(engine, cloud_account_id="a1", resource_type="iam")
    _finding(engine, cloud_account_id="a1", resource_type="storage")
    iam = engine.list_findings("org1", resource_type="iam")
    assert all(f["resource_type"] == "iam" for f in iam)


def test_list_findings_org_isolation(engine):
    _finding(engine, cloud_account_id="a1", org_id="org1")
    _finding(engine, cloud_account_id="a2", org_id="org2")
    assert len(engine.list_findings("org1")) == 1
    assert len(engine.list_findings("org2")) == 1


# ---------------------------------------------------------------------------
# update_finding_status
# ---------------------------------------------------------------------------

def test_update_finding_status_to_resolved(engine):
    acc = _account(engine, account_id="acct-r")
    f = _finding(engine, cloud_account_id=acc["id"], severity="high")
    # Score should be 95 after finding
    updated_f = engine.update_finding_status("org1", f["id"], "resolved", notes="fixed")
    assert updated_f["status"] == "resolved"
    assert updated_f["resolved_at"] is not None
    # Score should be restored to 100
    acc_after = engine.get_account("org1", acc["id"])
    assert acc_after["posture_score"] == pytest.approx(100.0)


def test_update_finding_status_to_suppressed(engine):
    f = _finding(engine, cloud_account_id="a1")
    result = engine.update_finding_status("org1", f["id"], "suppressed")
    assert result["status"] == "suppressed"


def test_update_finding_invalid_status_raises(engine):
    f = _finding(engine, cloud_account_id="a1")
    with pytest.raises(ValueError, match="status"):
        engine.update_finding_status("org1", f["id"], "unknown_status")


def test_update_finding_not_found_raises(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.update_finding_status("org1", "no-such-id", "resolved")


def test_update_finding_score_cap_at_100(engine):
    acc = _account(engine, account_id="acct-cap")
    # Resolve a finding that was never recorded (score stays at 100)
    f = _finding(engine, cloud_account_id=acc["id"], severity="critical")
    engine.update_finding_status("org1", f["id"], "resolved")
    acc_after = engine.get_account("org1", acc["id"])
    assert acc_after["posture_score"] <= 100.0


# ---------------------------------------------------------------------------
# get_posture_stats
# ---------------------------------------------------------------------------

def test_get_posture_stats_empty(engine):
    stats = engine.get_posture_stats("org1")
    assert stats["total_accounts"] == 0
    assert stats["total_findings"] == 0
    assert stats["open_findings"] == 0
    assert stats["critical_findings"] == 0
    assert stats["by_provider"] == {}
    assert stats["by_severity"] == {}


def test_get_posture_stats_counts(engine):
    acc = _account(engine, account_id="acct1", provider="aws")
    _finding(engine, cloud_account_id=acc["id"], severity="critical")
    _finding(engine, cloud_account_id=acc["id"], severity="high")
    stats = engine.get_posture_stats("org1")
    assert stats["total_accounts"] == 1
    assert stats["total_findings"] == 2
    assert stats["open_findings"] == 2
    assert stats["critical_findings"] == 1
    assert stats["by_provider"]["aws"] == 1
    assert stats["by_severity"]["critical"] == 1
    assert stats["by_severity"]["high"] == 1


def test_get_posture_stats_avg_score(engine):
    _account(engine, account_id="a1", provider="aws")
    _account(engine, account_id="a2", provider="gcp")
    stats = engine.get_posture_stats("org1")
    assert stats["avg_posture_score"] == pytest.approx(100.0)


def test_get_posture_stats_org_isolation(engine):
    acc1 = _account(engine, org_id="orgA", account_id="a1")
    _finding(engine, cloud_account_id=acc1["id"], org_id="orgA")
    _account(engine, org_id="orgB", account_id="a2")
    stats_a = engine.get_posture_stats("orgA")
    stats_b = engine.get_posture_stats("orgB")
    assert stats_a["total_findings"] == 1
    assert stats_b["total_findings"] == 0
