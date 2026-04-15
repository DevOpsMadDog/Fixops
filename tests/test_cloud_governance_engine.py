"""Tests for CloudGovernanceEngine — multi-cloud governance policies and violations.

Coverage:
  - Policy CRUD with valid/invalid types, providers, enforcements
  - Violation recording with violation_count increment
  - Violation remediation
  - Compliance score calculation
  - Stats aggregation
  - Org isolation
"""

from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture()
def engine(tmp_path):
    from core.cloud_governance_engine import CloudGovernanceEngine
    db = str(tmp_path / "test_cloud_governance.db")
    return CloudGovernanceEngine(db_path=db)


ORG = "org_cgov_test"
ORG2 = "org_cgov_other"


# ---------------------------------------------------------------------------
# Policy creation — valid cases
# ---------------------------------------------------------------------------

def test_create_policy_basic(engine):
    p = engine.create_governance_policy(ORG, {
        "name": "S3 Access Control",
        "policy_type": "access",
        "cloud_provider": "aws",
        "enforcement": "blocking",
    })
    assert p["id"]
    assert p["name"] == "S3 Access Control"
    assert p["policy_type"] == "access"
    assert p["cloud_provider"] == "aws"
    assert p["enforcement"] == "blocking"
    assert p["status"] == "active"
    assert p["violation_count"] == 0
    assert p["org_id"] == ORG


def test_create_policy_defaults(engine):
    p = engine.create_governance_policy(ORG, {
        "name": "Cost Policy",
        "policy_type": "cost",
    })
    assert p["cloud_provider"] == "multi_cloud"
    assert p["enforcement"] == "advisory"


def test_create_policy_all_valid_types(engine):
    for ptype in ("access", "cost", "security", "compliance", "resource", "tagging"):
        p = engine.create_governance_policy(ORG, {
            "name": f"Policy {ptype}",
            "policy_type": ptype,
        })
        assert p["policy_type"] == ptype


def test_create_policy_all_valid_providers(engine):
    for provider in ("aws", "azure", "gcp", "multi_cloud", "on_premise"):
        p = engine.create_governance_policy(ORG, {
            "name": f"Provider {provider}",
            "policy_type": "security",
            "cloud_provider": provider,
        })
        assert p["cloud_provider"] == provider


def test_create_policy_all_valid_enforcements(engine):
    for enforcement in ("advisory", "warning", "blocking"):
        p = engine.create_governance_policy(ORG, {
            "name": f"Enforcement {enforcement}",
            "policy_type": "security",
            "enforcement": enforcement,
        })
        assert p["enforcement"] == enforcement


# ---------------------------------------------------------------------------
# Policy creation — invalid cases
# ---------------------------------------------------------------------------

def test_create_policy_missing_name(engine):
    with pytest.raises(ValueError, match="name is required"):
        engine.create_governance_policy(ORG, {"policy_type": "access"})


def test_create_policy_invalid_type(engine):
    with pytest.raises(ValueError, match="Invalid policy_type"):
        engine.create_governance_policy(ORG, {"name": "P", "policy_type": "invalid_type"})


def test_create_policy_invalid_provider_falls_back(engine):
    p = engine.create_governance_policy(ORG, {
        "name": "P",
        "policy_type": "security",
        "cloud_provider": "not_a_cloud",
    })
    assert p["cloud_provider"] == "multi_cloud"


def test_create_policy_invalid_enforcement_falls_back(engine):
    p = engine.create_governance_policy(ORG, {
        "name": "P",
        "policy_type": "security",
        "enforcement": "strict",
    })
    assert p["enforcement"] == "advisory"


# ---------------------------------------------------------------------------
# List and get policies
# ---------------------------------------------------------------------------

def test_list_policies_empty(engine):
    assert engine.list_governance_policies(ORG) == []


def test_list_policies_returns_all(engine):
    engine.create_governance_policy(ORG, {"name": "P1", "policy_type": "access"})
    engine.create_governance_policy(ORG, {"name": "P2", "policy_type": "cost"})
    policies = engine.list_governance_policies(ORG)
    assert len(policies) == 2


def test_list_policies_filter_by_type(engine):
    engine.create_governance_policy(ORG, {"name": "A", "policy_type": "access"})
    engine.create_governance_policy(ORG, {"name": "B", "policy_type": "cost"})
    result = engine.list_governance_policies(ORG, policy_type="access")
    assert len(result) == 1
    assert result[0]["name"] == "A"


def test_list_policies_filter_by_provider(engine):
    engine.create_governance_policy(ORG, {"name": "A", "policy_type": "security", "cloud_provider": "aws"})
    engine.create_governance_policy(ORG, {"name": "B", "policy_type": "security", "cloud_provider": "gcp"})
    result = engine.list_governance_policies(ORG, cloud_provider="aws")
    assert len(result) == 1
    assert result[0]["name"] == "A"


def test_list_policies_filter_by_enforcement(engine):
    engine.create_governance_policy(ORG, {"name": "A", "policy_type": "security", "enforcement": "blocking"})
    engine.create_governance_policy(ORG, {"name": "B", "policy_type": "security", "enforcement": "advisory"})
    result = engine.list_governance_policies(ORG, enforcement="blocking")
    assert len(result) == 1
    assert result[0]["name"] == "A"


def test_get_policy_found(engine):
    p = engine.create_governance_policy(ORG, {"name": "P", "policy_type": "tagging"})
    fetched = engine.get_governance_policy(ORG, p["id"])
    assert fetched is not None
    assert fetched["id"] == p["id"]
    assert fetched["name"] == "P"


def test_get_policy_not_found(engine):
    assert engine.get_governance_policy(ORG, "nonexistent-id") is None


# ---------------------------------------------------------------------------
# Violation recording
# ---------------------------------------------------------------------------

def test_record_violation_basic(engine):
    p = engine.create_governance_policy(ORG, {"name": "P", "policy_type": "security"})
    v = engine.record_violation(ORG, {
        "policy_id": p["id"],
        "resource_id": "bucket-123",
        "resource_type": "s3_bucket",
        "violation_details": "Public read access enabled",
        "severity": "high",
    })
    assert v["id"]
    assert v["policy_id"] == p["id"]
    assert v["resource_id"] == "bucket-123"
    assert v["severity"] == "high"
    assert v["status"] == "open"
    assert v["detected_at"]


def test_record_violation_increments_violation_count(engine):
    p = engine.create_governance_policy(ORG, {"name": "P", "policy_type": "security"})
    assert engine.get_governance_policy(ORG, p["id"])["violation_count"] == 0

    engine.record_violation(ORG, {
        "policy_id": p["id"],
        "resource_id": "r1",
        "resource_type": "vm",
        "severity": "medium",
    })
    assert engine.get_governance_policy(ORG, p["id"])["violation_count"] == 1

    engine.record_violation(ORG, {
        "policy_id": p["id"],
        "resource_id": "r2",
        "resource_type": "vm",
        "severity": "high",
    })
    assert engine.get_governance_policy(ORG, p["id"])["violation_count"] == 2


def test_record_violation_default_severity(engine):
    p = engine.create_governance_policy(ORG, {"name": "P", "policy_type": "cost"})
    v = engine.record_violation(ORG, {
        "policy_id": p["id"],
        "resource_id": "r",
        "resource_type": "t",
    })
    assert v["severity"] == "medium"


def test_record_violation_missing_policy_id(engine):
    with pytest.raises(ValueError, match="policy_id is required"):
        engine.record_violation(ORG, {"resource_id": "r", "resource_type": "t"})


def test_record_violation_missing_resource_id(engine):
    p = engine.create_governance_policy(ORG, {"name": "P", "policy_type": "access"})
    with pytest.raises(ValueError, match="resource_id is required"):
        engine.record_violation(ORG, {"policy_id": p["id"], "resource_type": "t"})


# ---------------------------------------------------------------------------
# List violations
# ---------------------------------------------------------------------------

def test_list_violations_empty(engine):
    assert engine.list_violations(ORG) == []


def test_list_violations_filter_by_severity(engine):
    p = engine.create_governance_policy(ORG, {"name": "P", "policy_type": "security"})
    engine.record_violation(ORG, {"policy_id": p["id"], "resource_id": "r1", "resource_type": "t", "severity": "critical"})
    engine.record_violation(ORG, {"policy_id": p["id"], "resource_id": "r2", "resource_type": "t", "severity": "low"})
    result = engine.list_violations(ORG, severity="critical")
    assert len(result) == 1
    assert result[0]["severity"] == "critical"


def test_list_violations_filter_by_policy_id(engine):
    p1 = engine.create_governance_policy(ORG, {"name": "P1", "policy_type": "access"})
    p2 = engine.create_governance_policy(ORG, {"name": "P2", "policy_type": "cost"})
    engine.record_violation(ORG, {"policy_id": p1["id"], "resource_id": "r1", "resource_type": "t"})
    engine.record_violation(ORG, {"policy_id": p2["id"], "resource_id": "r2", "resource_type": "t"})
    result = engine.list_violations(ORG, policy_id=p1["id"])
    assert len(result) == 1
    assert result[0]["policy_id"] == p1["id"]


# ---------------------------------------------------------------------------
# Remediation
# ---------------------------------------------------------------------------

def test_remediate_violation(engine):
    p = engine.create_governance_policy(ORG, {"name": "P", "policy_type": "security"})
    v = engine.record_violation(ORG, {
        "policy_id": p["id"],
        "resource_id": "r",
        "resource_type": "t",
        "severity": "high",
    })
    result = engine.remediate_violation(ORG, v["id"], "alice", "Disabled public access")
    assert result["status"] == "remediated"
    assert result["remediated_by"] == "alice"
    assert result["action_taken"] == "Disabled public access"
    assert result["remediated_at"]


def test_remediate_violation_not_found(engine):
    assert engine.remediate_violation(ORG, "bad-id", "alice", "action") is None


def test_list_violations_filter_by_status(engine):
    p = engine.create_governance_policy(ORG, {"name": "P", "policy_type": "security"})
    v = engine.record_violation(ORG, {"policy_id": p["id"], "resource_id": "r", "resource_type": "t"})
    engine.remediate_violation(ORG, v["id"], "alice", "fixed")
    open_viols = engine.list_violations(ORG, status="open")
    assert len(open_viols) == 0
    remediated = engine.list_violations(ORG, status="remediated")
    assert len(remediated) == 1


# ---------------------------------------------------------------------------
# Compliance score and stats
# ---------------------------------------------------------------------------

def test_stats_empty(engine):
    stats = engine.get_governance_stats(ORG)
    assert stats["total_policies"] == 0
    assert stats["total_violations"] == 0
    assert stats["compliance_score"] == 100.0


def test_stats_all_open_violations(engine):
    p = engine.create_governance_policy(ORG, {"name": "P", "policy_type": "security"})
    engine.record_violation(ORG, {"policy_id": p["id"], "resource_id": "r1", "resource_type": "t", "severity": "high"})
    engine.record_violation(ORG, {"policy_id": p["id"], "resource_id": "r2", "resource_type": "t", "severity": "critical"})
    stats = engine.get_governance_stats(ORG)
    assert stats["total_violations"] == 2
    assert stats["open_violations"] == 2
    assert stats["compliance_score"] == 0.0


def test_stats_partial_remediation(engine):
    p = engine.create_governance_policy(ORG, {"name": "P", "policy_type": "access"})
    v1 = engine.record_violation(ORG, {"policy_id": p["id"], "resource_id": "r1", "resource_type": "t", "severity": "high"})
    engine.record_violation(ORG, {"policy_id": p["id"], "resource_id": "r2", "resource_type": "t", "severity": "low"})
    engine.remediate_violation(ORG, v1["id"], "alice", "fixed")
    stats = engine.get_governance_stats(ORG)
    assert stats["total_violations"] == 2
    assert stats["open_violations"] == 1
    assert stats["remediated_violations"] == 1
    assert stats["compliance_score"] == 50.0


def test_stats_by_type_and_enforcement(engine):
    engine.create_governance_policy(ORG, {"name": "A", "policy_type": "access", "enforcement": "blocking"})
    engine.create_governance_policy(ORG, {"name": "B", "policy_type": "cost", "enforcement": "advisory"})
    engine.create_governance_policy(ORG, {"name": "C", "policy_type": "access", "enforcement": "warning"})
    stats = engine.get_governance_stats(ORG)
    assert stats["total_policies"] == 3
    assert stats["by_type"]["access"] == 2
    assert stats["by_type"]["cost"] == 1
    assert stats["by_enforcement"]["blocking"] == 1
    assert stats["by_enforcement"]["advisory"] == 1


def test_stats_critical_violations(engine):
    p = engine.create_governance_policy(ORG, {"name": "P", "policy_type": "security"})
    engine.record_violation(ORG, {"policy_id": p["id"], "resource_id": "r1", "resource_type": "t", "severity": "critical"})
    engine.record_violation(ORG, {"policy_id": p["id"], "resource_id": "r2", "resource_type": "t", "severity": "high"})
    stats = engine.get_governance_stats(ORG)
    assert stats["critical_violations"] == 1


# ---------------------------------------------------------------------------
# Org isolation
# ---------------------------------------------------------------------------

def test_org_isolation_policies(engine):
    engine.create_governance_policy(ORG, {"name": "P1", "policy_type": "access"})
    engine.create_governance_policy(ORG2, {"name": "P2", "policy_type": "cost"})
    assert len(engine.list_governance_policies(ORG)) == 1
    assert len(engine.list_governance_policies(ORG2)) == 1
    assert engine.list_governance_policies(ORG)[0]["name"] == "P1"


def test_org_isolation_violations(engine):
    p1 = engine.create_governance_policy(ORG, {"name": "P", "policy_type": "security"})
    p2 = engine.create_governance_policy(ORG2, {"name": "P", "policy_type": "security"})
    engine.record_violation(ORG, {"policy_id": p1["id"], "resource_id": "r", "resource_type": "t"})
    engine.record_violation(ORG2, {"policy_id": p2["id"], "resource_id": "r", "resource_type": "t"})
    assert len(engine.list_violations(ORG)) == 1
    assert len(engine.list_violations(ORG2)) == 1


def test_org_isolation_stats(engine):
    p = engine.create_governance_policy(ORG, {"name": "P", "policy_type": "security"})
    engine.record_violation(ORG, {"policy_id": p["id"], "resource_id": "r", "resource_type": "t"})
    stats2 = engine.get_governance_stats(ORG2)
    assert stats2["total_policies"] == 0
    assert stats2["total_violations"] == 0


def test_get_policy_org_isolation(engine):
    p = engine.create_governance_policy(ORG, {"name": "P", "policy_type": "access"})
    assert engine.get_governance_policy(ORG2, p["id"]) is None
