"""Tests for CloudAccountMonitoringEngine — Beast Mode wave 31."""

from __future__ import annotations

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'suite-core'))

from core.cloud_account_monitoring_engine import CloudAccountMonitoringEngine


@pytest.fixture
def engine(tmp_path):
    return CloudAccountMonitoringEngine(db_path=str(tmp_path / "test_cloud_accounts.db"))


ORG = "test-org"
OTHER_ORG = "other-org"


def _account(engine, org_id=ORG, **kwargs):
    params = dict(
        account_id="aws-123",
        account_name="Production AWS",
        provider="aws",
        region="us-east-1",
    )
    params.update(kwargs)
    return engine.register_account(org_id, **params)


def _event(engine, account_id="aws-123", org_id=ORG, **kwargs):
    params = dict(
        event_type="config-change",
        severity="medium",
        resource="s3://my-bucket",
        description="Bucket policy changed",
    )
    params.update(kwargs)
    return engine.record_event(account_id, org_id, **params)


# ---------------------------------------------------------------------------
# register_account
# ---------------------------------------------------------------------------

def test_register_account_basic(engine):
    account = _account(engine)
    assert account["id"]
    assert account["org_id"] == ORG
    assert account["account_id"] == "aws-123"
    assert account["provider"] == "aws"
    assert account["status"] == "healthy"
    assert account["risk_score"] == 0.0
    assert account["findings_count"] == 0
    assert account["last_scanned"] is None
    assert account["created_at"]


def test_register_account_all_providers(engine):
    providers = ["aws", "azure", "gcp", "alibaba", "oracle", "ibm", "digitalocean"]
    for i, provider in enumerate(providers):
        acc = engine.register_account(ORG, f"acc-{i}", f"Account {i}", provider)
        assert acc["provider"] == provider


def test_register_account_invalid_provider(engine):
    with pytest.raises(ValueError, match="provider"):
        engine.register_account(ORG, "acc-1", "Test", "unknown-cloud")


def test_register_account_missing_account_id(engine):
    with pytest.raises(ValueError, match="account_id"):
        engine.register_account(ORG, "", "Name", "aws")


def test_register_account_missing_name(engine):
    with pytest.raises(ValueError, match="account_name"):
        engine.register_account(ORG, "acc-1", "", "aws")


def test_register_account_org_isolation(engine):
    _account(engine, org_id=ORG)
    _account(engine, org_id=OTHER_ORG, account_id="azure-456")
    assert len(engine.list_accounts(ORG)) == 1
    assert len(engine.list_accounts(OTHER_ORG)) == 1


# ---------------------------------------------------------------------------
# update_account_scan
# ---------------------------------------------------------------------------

def test_update_account_scan_healthy(engine):
    _account(engine)
    result = engine.update_account_scan("aws-123", ORG, 5, 20.0)
    assert result["status"] == "healthy"
    assert result["risk_score"] == 20.0
    assert result["findings_count"] == 5
    assert result["last_scanned"]


def test_update_account_scan_warning(engine):
    _account(engine)
    result = engine.update_account_scan("aws-123", ORG, 20, 50.0)
    assert result["status"] == "warning"


def test_update_account_scan_critical(engine):
    _account(engine)
    result = engine.update_account_scan("aws-123", ORG, 100, 85.0)
    assert result["status"] == "critical"


def test_update_account_scan_boundary_healthy(engine):
    _account(engine)
    result = engine.update_account_scan("aws-123", ORG, 0, 29.9)
    assert result["status"] == "healthy"


def test_update_account_scan_boundary_warning(engine):
    _account(engine)
    result = engine.update_account_scan("aws-123", ORG, 0, 30.0)
    assert result["status"] == "warning"


def test_update_account_scan_boundary_critical(engine):
    _account(engine)
    result = engine.update_account_scan("aws-123", ORG, 0, 70.1)
    assert result["status"] == "critical"


def test_update_account_scan_clamps_risk(engine):
    _account(engine)
    result = engine.update_account_scan("aws-123", ORG, 0, 150.0)
    assert result["risk_score"] == 100.0


def test_update_account_scan_not_found(engine):
    with pytest.raises(KeyError):
        engine.update_account_scan("nonexistent", ORG, 0, 50.0)


def test_update_account_scan_org_isolation(engine):
    _account(engine, org_id=ORG)
    with pytest.raises(KeyError):
        engine.update_account_scan("aws-123", OTHER_ORG, 10, 50.0)


# ---------------------------------------------------------------------------
# record_event
# ---------------------------------------------------------------------------

def test_record_event_basic(engine):
    _account(engine)
    event = _event(engine)
    assert event["id"]
    assert event["account_id"] == "aws-123"
    assert event["org_id"] == ORG
    assert event["event_type"] == "config-change"
    assert event["severity"] == "medium"
    assert event["status"] == "open"
    assert event["resolved_at"] is None
    assert event["detected_at"]


def test_record_event_all_types(engine):
    _account(engine)
    types = [
        "config-change", "login-anomaly", "resource-creation", "policy-violation",
        "cost-spike", "data-access", "privilege-escalation", "compliance-breach",
    ]
    for i, etype in enumerate(types):
        ev = _event(engine, event_type=etype, resource=f"res-{i}")
        assert ev["event_type"] == etype


def test_record_event_all_severities(engine):
    _account(engine)
    for sev in ["critical", "high", "medium", "low"]:
        ev = _event(engine, severity=sev)
        assert ev["severity"] == sev


def test_record_event_invalid_type(engine):
    _account(engine)
    with pytest.raises(ValueError, match="event_type"):
        _event(engine, event_type="unknown-event")


def test_record_event_invalid_severity(engine):
    _account(engine)
    with pytest.raises(ValueError, match="severity"):
        _event(engine, severity="extreme")


# ---------------------------------------------------------------------------
# resolve_event
# ---------------------------------------------------------------------------

def test_resolve_event_basic(engine):
    _account(engine)
    event = _event(engine)
    resolved = engine.resolve_event("aws-123", event["id"], ORG)
    assert resolved["status"] == "resolved"
    assert resolved["resolved_at"]


def test_resolve_event_not_found(engine):
    _account(engine)
    with pytest.raises(KeyError):
        engine.resolve_event("aws-123", "nonexistent-event", ORG)


def test_resolve_event_org_isolation(engine):
    _account(engine, org_id=ORG)
    event = _event(engine)
    with pytest.raises(KeyError):
        engine.resolve_event("aws-123", event["id"], OTHER_ORG)


# ---------------------------------------------------------------------------
# get_account
# ---------------------------------------------------------------------------

def test_get_account_with_events(engine):
    _account(engine)
    _event(engine)
    _event(engine, event_type="login-anomaly")
    account = engine.get_account("aws-123", ORG)
    assert account["account_id"] == "aws-123"
    assert len(account["recent_events"]) == 2


def test_get_account_not_found(engine):
    assert engine.get_account("nonexistent", ORG) is None


def test_get_account_org_isolation(engine):
    _account(engine, org_id=ORG)
    assert engine.get_account("aws-123", OTHER_ORG) is None


# ---------------------------------------------------------------------------
# list_accounts
# ---------------------------------------------------------------------------

def test_list_accounts_basic(engine):
    _account(engine, account_id="acc-1")
    _account(engine, account_id="acc-2", provider="azure")
    accounts = engine.list_accounts(ORG)
    assert len(accounts) == 2


def test_list_accounts_filter_provider(engine):
    _account(engine, account_id="acc-1", provider="aws")
    _account(engine, account_id="acc-2", provider="azure")
    aws_accounts = engine.list_accounts(ORG, provider="aws")
    assert len(aws_accounts) == 1
    assert aws_accounts[0]["provider"] == "aws"


def test_list_accounts_filter_status(engine):
    _account(engine, account_id="acc-1")
    _account(engine, account_id="acc-2")
    engine.update_account_scan("acc-2", ORG, 100, 85.0)
    critical = engine.list_accounts(ORG, status="critical")
    assert len(critical) == 1
    assert critical[0]["account_id"] == "acc-2"


def test_list_accounts_org_isolation(engine):
    _account(engine, org_id=ORG)
    _account(engine, org_id=OTHER_ORG, account_id="azure-456")
    assert len(engine.list_accounts(ORG)) == 1
    assert len(engine.list_accounts(OTHER_ORG)) == 1


# ---------------------------------------------------------------------------
# create_policy
# ---------------------------------------------------------------------------

def test_create_policy_basic(engine):
    policy = engine.create_policy(ORG, "No public S3", "security", "aws")
    assert policy["id"]
    assert policy["org_id"] == ORG
    assert policy["policy_name"] == "No public S3"
    assert policy["policy_type"] == "security"
    assert policy["enabled"] == 1
    assert policy["violation_count"] == 0
    assert policy["last_evaluated"] is None


def test_create_policy_all_types(engine):
    types = ["security", "compliance", "cost", "governance", "data-protection"]
    for i, ptype in enumerate(types):
        policy = engine.create_policy(ORG, f"Policy {i}", ptype)
        assert policy["policy_type"] == ptype


def test_create_policy_invalid_type(engine):
    with pytest.raises(ValueError, match="policy_type"):
        engine.create_policy(ORG, "Bad Policy", "invalid-type")


def test_create_policy_missing_name(engine):
    with pytest.raises(ValueError, match="policy_name"):
        engine.create_policy(ORG, "", "security")


# ---------------------------------------------------------------------------
# evaluate_policy
# ---------------------------------------------------------------------------

def test_evaluate_policy_basic(engine):
    policy = engine.create_policy(ORG, "CIS Benchmark", "compliance")
    updated = engine.evaluate_policy(policy["id"], ORG, 5)
    assert updated["violation_count"] == 5
    assert updated["last_evaluated"]


def test_evaluate_policy_zero_violations(engine):
    policy = engine.create_policy(ORG, "Clean Policy", "security")
    updated = engine.evaluate_policy(policy["id"], ORG, 0)
    assert updated["violation_count"] == 0


def test_evaluate_policy_not_found(engine):
    with pytest.raises(KeyError):
        engine.evaluate_policy("nonexistent-id", ORG, 3)


def test_evaluate_policy_org_isolation(engine):
    policy = engine.create_policy(ORG, "Test Policy", "security")
    with pytest.raises(KeyError):
        engine.evaluate_policy(policy["id"], OTHER_ORG, 5)


# ---------------------------------------------------------------------------
# get_unresolved_events
# ---------------------------------------------------------------------------

def test_get_unresolved_events_basic(engine):
    _account(engine)
    _event(engine, event_type="config-change", severity="high")
    _event(engine, event_type="login-anomaly", severity="critical")
    events = engine.get_unresolved_events(ORG)
    assert len(events) == 2


def test_get_unresolved_events_excludes_resolved(engine):
    _account(engine)
    ev1 = _event(engine, event_type="config-change")
    _event(engine, event_type="login-anomaly")
    engine.resolve_event("aws-123", ev1["id"], ORG)
    events = engine.get_unresolved_events(ORG)
    assert len(events) == 1


def test_get_unresolved_events_filter_severity(engine):
    _account(engine)
    _event(engine, event_type="config-change", severity="high")
    _event(engine, event_type="login-anomaly", severity="critical")
    critical = engine.get_unresolved_events(ORG, severity="critical")
    assert len(critical) == 1
    assert critical[0]["severity"] == "critical"


def test_get_unresolved_events_org_isolation(engine):
    _account(engine, org_id=ORG)
    _account(engine, org_id=OTHER_ORG, account_id="azure-456")
    _event(engine, account_id="aws-123", org_id=ORG)
    engine.record_event("azure-456", OTHER_ORG, "login-anomaly", "high", "vm", "desc")
    assert len(engine.get_unresolved_events(ORG)) == 1
    assert len(engine.get_unresolved_events(OTHER_ORG)) == 1


# ---------------------------------------------------------------------------
# get_account_risk_summary
# ---------------------------------------------------------------------------

def test_get_account_risk_summary_empty(engine):
    result = engine.get_account_risk_summary(ORG)
    assert result["total_accounts"] == 0
    assert result["critical_accounts"] == 0
    assert result["total_findings"] == 0
    assert result["by_provider"] == {}


def test_get_account_risk_summary_basic(engine):
    _account(engine, account_id="acc-1", provider="aws")
    _account(engine, account_id="acc-2", provider="aws")
    _account(engine, account_id="acc-3", provider="azure")
    engine.update_account_scan("acc-1", ORG, 10, 80.0)  # critical
    engine.update_account_scan("acc-2", ORG, 5, 40.0)   # warning
    engine.update_account_scan("acc-3", ORG, 2, 10.0)   # healthy
    result = engine.get_account_risk_summary(ORG)
    assert result["total_accounts"] == 3
    assert result["critical_accounts"] == 1
    assert result["total_findings"] == 17
    assert "aws" in result["by_provider"]
    assert "azure" in result["by_provider"]
    assert result["by_provider"]["aws"]["account_count"] == 2
    assert result["by_provider"]["azure"]["account_count"] == 1


def test_get_account_risk_summary_org_isolation(engine):
    _account(engine, org_id=ORG, account_id="acc-1")
    _account(engine, org_id=OTHER_ORG, account_id="acc-2")
    engine.update_account_scan("acc-1", ORG, 50, 90.0)
    result_org = engine.get_account_risk_summary(ORG)
    result_other = engine.get_account_risk_summary(OTHER_ORG)
    assert result_org["critical_accounts"] == 1
    assert result_other["critical_accounts"] == 0
