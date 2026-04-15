"""Tests for DataGovernanceEngine — 25+ tests covering all methods with org isolation."""

from __future__ import annotations

import json
import os
import tempfile

import pytest

from core.data_governance_engine import DataGovernanceEngine


@pytest.fixture()
def engine(tmp_path):
    db = str(tmp_path / "test_data_governance.db")
    return DataGovernanceEngine(db_path=db)


ORG_A = "org-alpha"
ORG_B = "org-beta"


# ------------------------------------------------------------------
# Data Assets
# ------------------------------------------------------------------


def test_register_asset_basic(engine):
    asset = engine.register_asset(ORG_A, {"name": "Customer DB", "asset_type": "database"})
    assert asset["asset_id"]
    assert asset["org_id"] == ORG_A
    assert asset["name"] == "Customer DB"
    assert asset["asset_type"] == "database"
    assert asset["classification"] == "internal"  # default
    assert asset["data_categories"] == []


def test_register_asset_full(engine):
    data = {
        "name": "Medical Records",
        "description": "Patient PHI store",
        "asset_type": "cloud_storage",
        "classification": "restricted",
        "owner": "privacy-team",
        "data_categories": ["PHI", "PII"],
        "retention_days": 2555,
        "location": "s3://medrecords",
        "encrypted": True,
    }
    asset = engine.register_asset(ORG_A, data)
    assert asset["classification"] == "restricted"
    assert asset["encrypted"] == 1
    assert "PHI" in asset["data_categories"]
    assert asset["retention_days"] == 2555


def test_register_asset_invalid_type_defaults(engine):
    asset = engine.register_asset(ORG_A, {"name": "X", "asset_type": "floppy_disk"})
    assert asset["asset_type"] == "database"


def test_register_asset_invalid_classification_defaults(engine):
    asset = engine.register_asset(ORG_A, {"name": "X", "classification": "top_secret"})
    assert asset["classification"] == "internal"


def test_list_assets_empty(engine):
    assert engine.list_assets(ORG_A) == []


def test_list_assets_returns_correct_org(engine):
    engine.register_asset(ORG_A, {"name": "A-Asset"})
    engine.register_asset(ORG_B, {"name": "B-Asset"})
    results = engine.list_assets(ORG_A)
    assert len(results) == 1
    assert results[0]["name"] == "A-Asset"


def test_list_assets_filter_classification(engine):
    engine.register_asset(ORG_A, {"name": "Public", "classification": "public"})
    engine.register_asset(ORG_A, {"name": "Secret", "classification": "secret"})
    public = engine.list_assets(ORG_A, classification="public")
    assert len(public) == 1
    assert public[0]["name"] == "Public"


def test_list_assets_filter_asset_type(engine):
    engine.register_asset(ORG_A, {"name": "DB1", "asset_type": "database"})
    engine.register_asset(ORG_A, {"name": "Share1", "asset_type": "file_share"})
    dbs = engine.list_assets(ORG_A, asset_type="database")
    assert len(dbs) == 1 and dbs[0]["name"] == "DB1"


def test_list_assets_deserializes_json(engine):
    engine.register_asset(ORG_A, {"name": "PII Store", "data_categories": ["PII", "PCI"]})
    assets = engine.list_assets(ORG_A)
    assert isinstance(assets[0]["data_categories"], list)
    assert "PII" in assets[0]["data_categories"]


def test_get_asset(engine):
    created = engine.register_asset(ORG_A, {"name": "My DB"})
    fetched = engine.get_asset(ORG_A, created["asset_id"])
    assert fetched is not None
    assert fetched["asset_id"] == created["asset_id"]


def test_get_asset_not_found(engine):
    assert engine.get_asset(ORG_A, "no-such-id") is None


def test_get_asset_org_isolation(engine):
    created = engine.register_asset(ORG_A, {"name": "A asset"})
    # ORG_B cannot see ORG_A's asset
    assert engine.get_asset(ORG_B, created["asset_id"]) is None


def test_update_asset_classification(engine):
    created = engine.register_asset(ORG_A, {"name": "DB", "classification": "internal"})
    result = engine.update_asset_classification(ORG_A, created["asset_id"], "confidential")
    assert result is True
    updated = engine.get_asset(ORG_A, created["asset_id"])
    assert updated["classification"] == "confidential"


def test_update_asset_classification_invalid(engine):
    created = engine.register_asset(ORG_A, {"name": "DB"})
    result = engine.update_asset_classification(ORG_A, created["asset_id"], "top_secret")
    assert result is False


def test_update_asset_classification_wrong_org(engine):
    created = engine.register_asset(ORG_A, {"name": "DB"})
    result = engine.update_asset_classification(ORG_B, created["asset_id"], "secret")
    assert result is False


# ------------------------------------------------------------------
# Governance Policies
# ------------------------------------------------------------------


def test_create_policy_basic(engine):
    policy = engine.create_policy(ORG_A, {"name": "90-day retention"})
    assert policy["policy_id"]
    assert policy["org_id"] == ORG_A
    assert policy["name"] == "90-day retention"
    assert policy["policy_type"] == "retention"
    assert policy["status"] == "draft"


def test_create_policy_full(engine):
    data = {
        "name": "PCI Encryption Policy",
        "policy_type": "encryption",
        "applies_to_classification": "restricted",
        "requirement": "AES-256 at rest",
        "enforcement": "automated",
        "status": "active",
    }
    policy = engine.create_policy(ORG_A, data)
    assert policy["policy_type"] == "encryption"
    assert policy["enforcement"] == "automated"
    assert policy["status"] == "active"


def test_create_policy_invalid_type_defaults(engine):
    policy = engine.create_policy(ORG_A, {"name": "X", "policy_type": "unknown"})
    assert policy["policy_type"] == "retention"


def test_list_policies_org_isolation(engine):
    engine.create_policy(ORG_A, {"name": "A Policy"})
    engine.create_policy(ORG_B, {"name": "B Policy"})
    assert len(engine.list_policies(ORG_A)) == 1
    assert len(engine.list_policies(ORG_B)) == 1


def test_list_policies_filter_type(engine):
    engine.create_policy(ORG_A, {"name": "Ret", "policy_type": "retention"})
    engine.create_policy(ORG_A, {"name": "Enc", "policy_type": "encryption"})
    results = engine.list_policies(ORG_A, policy_type="encryption")
    assert len(results) == 1 and results[0]["name"] == "Enc"


def test_list_policies_filter_status(engine):
    engine.create_policy(ORG_A, {"name": "Active", "status": "active"})
    engine.create_policy(ORG_A, {"name": "Draft", "status": "draft"})
    results = engine.list_policies(ORG_A, status="active")
    assert len(results) == 1 and results[0]["name"] == "Active"


# ------------------------------------------------------------------
# Policy Violations
# ------------------------------------------------------------------


def test_log_violation(engine):
    v = engine.log_violation(ORG_A, {
        "asset_id": "asset-1",
        "policy_id": "policy-1",
        "violation_type": "unencrypted_data",
        "description": "Restricted data stored unencrypted",
        "severity": "critical",
    })
    assert v["violation_id"]
    assert v["org_id"] == ORG_A
    assert v["severity"] == "critical"
    assert v["resolved_at"] is None


def test_log_violation_invalid_severity_defaults(engine):
    v = engine.log_violation(ORG_A, {"severity": "extreme"})
    assert v["severity"] == "medium"


def test_list_violations_open(engine):
    engine.log_violation(ORG_A, {"description": "Open violation"})
    results = engine.list_violations(ORG_A, resolved=False)
    assert len(results) == 1


def test_list_violations_filter_severity(engine):
    engine.log_violation(ORG_A, {"severity": "critical"})
    engine.log_violation(ORG_A, {"severity": "low"})
    results = engine.list_violations(ORG_A, severity="critical")
    assert len(results) == 1 and results[0]["severity"] == "critical"


def test_list_violations_org_isolation(engine):
    engine.log_violation(ORG_A, {"description": "A violation"})
    engine.log_violation(ORG_B, {"description": "B violation"})
    assert len(engine.list_violations(ORG_A)) == 1
    assert len(engine.list_violations(ORG_B)) == 1


def test_resolve_violation(engine):
    v = engine.log_violation(ORG_A, {"severity": "high"})
    result = engine.resolve_violation(ORG_A, v["violation_id"], "analyst@example.com")
    assert result is True
    resolved = engine.list_violations(ORG_A, resolved=True)
    assert len(resolved) == 1 and resolved[0]["resolved_by"] == "analyst@example.com"


def test_resolve_violation_not_found(engine):
    result = engine.resolve_violation(ORG_A, "no-such-id", "user")
    assert result is False


def test_resolve_violation_wrong_org(engine):
    v = engine.log_violation(ORG_A, {})
    result = engine.resolve_violation(ORG_B, v["violation_id"], "user")
    assert result is False


def test_resolve_violation_already_resolved(engine):
    v = engine.log_violation(ORG_A, {})
    engine.resolve_violation(ORG_A, v["violation_id"], "first-resolver")
    # Second resolve should return False
    result = engine.resolve_violation(ORG_A, v["violation_id"], "second-resolver")
    assert result is False


# ------------------------------------------------------------------
# Data Flows
# ------------------------------------------------------------------


def test_add_data_flow(engine):
    flow = engine.add_data_flow(ORG_A, {
        "source_asset_id": "asset-db-1",
        "destination": "analytics-warehouse",
        "flow_type": "internal",
        "data_categories": ["PII"],
        "encrypted": True,
        "approved": True,
    })
    assert flow["flow_id"]
    assert flow["org_id"] == ORG_A
    assert flow["flow_type"] == "internal"
    assert flow["encrypted"] == 1
    assert flow["approved"] == 1


def test_add_data_flow_invalid_type_defaults(engine):
    flow = engine.add_data_flow(ORG_A, {"flow_type": "fax"})
    assert flow["flow_type"] == "internal"


def test_list_data_flows_org_isolation(engine):
    engine.add_data_flow(ORG_A, {"destination": "A"})
    engine.add_data_flow(ORG_B, {"destination": "B"})
    assert len(engine.list_data_flows(ORG_A)) == 1
    assert len(engine.list_data_flows(ORG_B)) == 1


def test_list_data_flows_filter_type(engine):
    engine.add_data_flow(ORG_A, {"flow_type": "cross_border"})
    engine.add_data_flow(ORG_A, {"flow_type": "internal"})
    results = engine.list_data_flows(ORG_A, flow_type="cross_border")
    assert len(results) == 1


def test_list_data_flows_deserializes_json(engine):
    engine.add_data_flow(ORG_A, {"data_categories": ["PII", "PCI"]})
    flows = engine.list_data_flows(ORG_A)
    assert isinstance(flows[0]["data_categories"], list)
    assert "PII" in flows[0]["data_categories"]


# ------------------------------------------------------------------
# Stats
# ------------------------------------------------------------------


def test_governance_stats_empty(engine):
    stats = engine.get_governance_stats(ORG_A)
    assert stats["total_assets"] == 0
    assert stats["total_policies"] == 0
    assert stats["open_violations"] == 0
    assert stats["critical_violations"] == 0
    assert stats["cross_border_flows"] == 0
    assert stats["unencrypted_restricted"] == 0
    assert stats["by_classification"] == {}


def test_governance_stats_populated(engine):
    # Assets
    engine.register_asset(ORG_A, {"name": "DB1", "classification": "restricted", "encrypted": False})
    engine.register_asset(ORG_A, {"name": "DB2", "classification": "secret", "encrypted": False})
    engine.register_asset(ORG_A, {"name": "DB3", "classification": "public", "encrypted": True})

    # Policies
    engine.create_policy(ORG_A, {"name": "P1", "status": "active"})
    engine.create_policy(ORG_A, {"name": "P2", "status": "draft"})

    # Violations
    v_crit = engine.log_violation(ORG_A, {"severity": "critical"})
    engine.log_violation(ORG_A, {"severity": "high"})

    # Flows
    engine.add_data_flow(ORG_A, {"flow_type": "cross_border"})
    engine.add_data_flow(ORG_A, {"flow_type": "internal"})

    stats = engine.get_governance_stats(ORG_A)

    assert stats["total_assets"] == 3
    assert stats["by_classification"]["restricted"] == 1
    assert stats["by_classification"]["secret"] == 1
    assert stats["by_classification"]["public"] == 1
    assert stats["total_policies"] == 2
    assert stats["active_policies"] == 1
    assert stats["open_violations"] == 2
    assert stats["critical_violations"] == 1
    assert stats["cross_border_flows"] == 1
    assert stats["unencrypted_restricted"] == 2  # restricted + secret, both unencrypted


def test_governance_stats_org_isolation(engine):
    engine.register_asset(ORG_A, {"name": "A asset"})
    engine.register_asset(ORG_B, {"name": "B asset"})
    stats_a = engine.get_governance_stats(ORG_A)
    stats_b = engine.get_governance_stats(ORG_B)
    assert stats_a["total_assets"] == 1
    assert stats_b["total_assets"] == 1


def test_governance_stats_resolved_violations_not_counted(engine):
    v = engine.log_violation(ORG_A, {"severity": "critical"})
    engine.resolve_violation(ORG_A, v["violation_id"], "analyst")
    stats = engine.get_governance_stats(ORG_A)
    assert stats["open_violations"] == 0
    assert stats["critical_violations"] == 0


def test_unencrypted_restricted_only_counts_restricted_and_secret(engine):
    engine.register_asset(ORG_A, {"name": "Public Unenc", "classification": "public", "encrypted": False})
    engine.register_asset(ORG_A, {"name": "Internal Unenc", "classification": "internal", "encrypted": False})
    engine.register_asset(ORG_A, {"name": "Restricted Enc", "classification": "restricted", "encrypted": True})
    stats = engine.get_governance_stats(ORG_A)
    assert stats["unencrypted_restricted"] == 0
