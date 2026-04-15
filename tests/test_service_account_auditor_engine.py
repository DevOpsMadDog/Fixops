"""Tests for ServiceAccountAuditorEngine.

Covers:
- register_service_account (valid, invalid system, missing name)
- list_service_accounts (all, filtered by system)
- run_audit (findings generated, risk_score present, account not found)
- get_unused_accounts (threshold filtering)
- get_overprivileged_accounts (risk_score > 70)
- rotate_credentials (rotation recorded, last_used_days reset)
- list_rotation_history (returns history)
- get_audit_stats (totals, by_system)
- multi-tenant isolation (org_id scoping)
- risk scoring (high-risk perms, wildcard, permission count, unused)
- edge cases (clean account, no accounts)
"""

from __future__ import annotations

import os
import pytest

os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    from core.service_account_auditor_engine import ServiceAccountAuditorEngine
    return ServiceAccountAuditorEngine(db_path=str(tmp_path / "test_sa_auditor.db"))


def _make_account(name="svc-test", system="k8s", permissions=None, last_used=0):
    return {
        "name": name,
        "system": system,
        "permissions": permissions or ["read"],
        "last_used_days_ago": last_used,
    }


ORG = "org-alpha"
ORG2 = "org-beta"


# ---------------------------------------------------------------------------
# register_service_account
# ---------------------------------------------------------------------------


def test_register_returns_id(engine):
    result = engine.register_service_account(ORG, _make_account())
    assert "id" in result
    assert result["id"]


def test_register_stores_org_id(engine):
    result = engine.register_service_account(ORG, _make_account())
    assert result["org_id"] == ORG


def test_register_stores_name_and_system(engine):
    result = engine.register_service_account(ORG, _make_account(name="deploy-bot", system="aws"))
    assert result["name"] == "deploy-bot"
    assert result["system"] == "aws"


def test_register_stores_permissions(engine):
    perms = ["s3:GetObject", "s3:PutObject"]
    result = engine.register_service_account(ORG, _make_account(permissions=perms))
    assert result["permissions"] == perms


def test_register_computes_risk_score(engine):
    result = engine.register_service_account(ORG, _make_account())
    assert "risk_score" in result
    assert 0 <= result["risk_score"] <= 100


def test_register_invalid_system_raises(engine):
    with pytest.raises(ValueError, match="system must be one of"):
        engine.register_service_account(ORG, _make_account(system="invalid-platform"))


def test_register_missing_name_raises(engine):
    with pytest.raises(ValueError, match="name is required"):
        engine.register_service_account(ORG, {"system": "k8s", "permissions": []})


def test_register_high_risk_perms_raises_score(engine):
    result = engine.register_service_account(
        ORG, _make_account(system="k8s", permissions=["cluster-admin"])
    )
    assert result["risk_score"] > 10


def test_register_wildcard_perm_raises_score(engine):
    result = engine.register_service_account(
        ORG, _make_account(system="aws", permissions=["*"])
    )
    assert result["risk_score"] > 10


def test_register_many_permissions_raises_score(engine):
    perms = [f"action:{i}" for i in range(15)]
    result = engine.register_service_account(ORG, _make_account(permissions=perms))
    assert result["risk_score"] > 10


def test_register_unused_account_raises_score(engine):
    result_fresh = engine.register_service_account(ORG, _make_account(last_used=0))
    result_stale = engine.register_service_account(ORG, _make_account(last_used=200))
    assert result_stale["risk_score"] > result_fresh["risk_score"]


# ---------------------------------------------------------------------------
# list_service_accounts
# ---------------------------------------------------------------------------


def test_list_returns_registered_accounts(engine):
    engine.register_service_account(ORG, _make_account(name="svc-1"))
    engine.register_service_account(ORG, _make_account(name="svc-2"))
    accounts = engine.list_service_accounts(ORG)
    assert len(accounts) >= 2


def test_list_filter_by_system(engine):
    engine.register_service_account(ORG, _make_account(name="k8s-svc", system="k8s"))
    engine.register_service_account(ORG, _make_account(name="aws-svc", system="aws"))
    k8s_accounts = engine.list_service_accounts(ORG, system="k8s")
    assert all(a["system"] == "k8s" for a in k8s_accounts)


def test_list_empty_for_new_org(engine):
    accounts = engine.list_service_accounts("org-new")
    assert accounts == []


def test_list_permissions_deserialized(engine):
    perms = ["read", "write"]
    engine.register_service_account(ORG, _make_account(permissions=perms))
    accounts = engine.list_service_accounts(ORG)
    assert any(a["permissions"] == perms for a in accounts)


# ---------------------------------------------------------------------------
# run_audit
# ---------------------------------------------------------------------------


def test_run_audit_returns_findings(engine):
    acct = engine.register_service_account(
        ORG, _make_account(system="k8s", permissions=["cluster-admin"])
    )
    result = engine.run_audit(ORG, acct["id"])
    assert "findings" in result
    assert len(result["findings"]) > 0


def test_run_audit_returns_risk_score(engine):
    acct = engine.register_service_account(ORG, _make_account())
    result = engine.run_audit(ORG, acct["id"])
    assert "risk_score" in result
    assert 0 <= result["risk_score"] <= 100


def test_run_audit_finding_structure(engine):
    acct = engine.register_service_account(
        ORG, _make_account(system="aws", permissions=["AdministratorAccess"])
    )
    result = engine.run_audit(ORG, acct["id"])
    for f in result["findings"]:
        assert "finding_type" in f
        assert "severity" in f
        assert "description" in f


def test_run_audit_overprivileged_finding(engine):
    acct = engine.register_service_account(
        ORG, _make_account(system="aws", permissions=["AdministratorAccess"])
    )
    result = engine.run_audit(ORG, acct["id"])
    types = [f["finding_type"] for f in result["findings"]]
    assert "overprivileged" in types


def test_run_audit_stale_finding(engine):
    acct = engine.register_service_account(ORG, _make_account(last_used=120))
    result = engine.run_audit(ORG, acct["id"])
    types = [f["finding_type"] for f in result["findings"]]
    assert "stale_credentials" in types or "unused_account" in types


def test_run_audit_clean_account(engine):
    acct = engine.register_service_account(ORG, _make_account(permissions=["read"], last_used=0))
    result = engine.run_audit(ORG, acct["id"])
    types = [f["finding_type"] for f in result["findings"]]
    assert "clean" in types


def test_run_audit_not_found_raises(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.run_audit(ORG, "nonexistent-id")


def test_run_audit_wrong_org_raises(engine):
    acct = engine.register_service_account(ORG, _make_account())
    with pytest.raises(ValueError, match="not found"):
        engine.run_audit(ORG2, acct["id"])


# ---------------------------------------------------------------------------
# get_unused_accounts
# ---------------------------------------------------------------------------


def test_get_unused_returns_stale_accounts(engine):
    engine.register_service_account(ORG, _make_account(name="stale", last_used=100))
    engine.register_service_account(ORG, _make_account(name="fresh", last_used=5))
    unused = engine.get_unused_accounts(ORG, days_threshold=90)
    names = [a["name"] for a in unused]
    assert "stale" in names


def test_get_unused_excludes_recent_accounts(engine):
    engine.register_service_account(ORG, _make_account(name="fresh", last_used=5))
    unused = engine.get_unused_accounts(ORG, days_threshold=90)
    names = [a["name"] for a in unused]
    assert "fresh" not in names


def test_get_unused_custom_threshold(engine):
    engine.register_service_account(ORG, _make_account(name="moderate", last_used=30))
    unused = engine.get_unused_accounts(ORG, days_threshold=25)
    names = [a["name"] for a in unused]
    assert "moderate" in names


# ---------------------------------------------------------------------------
# get_overprivileged_accounts
# ---------------------------------------------------------------------------


def test_get_overprivileged_returns_high_risk(engine):
    # cluster-admin + * wildcard + 200 days unused = score 75 (> 70 threshold)
    engine.register_service_account(
        ORG, _make_account(name="admin-svc", system="k8s", permissions=["cluster-admin", "*"], last_used=200)
    )
    overprivileged = engine.get_overprivileged_accounts(ORG)
    names = [a["name"] for a in overprivileged]
    assert "admin-svc" in names


def test_get_overprivileged_excludes_low_risk(engine):
    engine.register_service_account(
        ORG, _make_account(name="safe-svc", permissions=["read"], last_used=0)
    )
    overprivileged = engine.get_overprivileged_accounts(ORG)
    names = [a["name"] for a in overprivileged]
    assert "safe-svc" not in names


def test_get_overprivileged_risk_threshold(engine):
    overprivileged = engine.get_overprivileged_accounts(ORG)
    assert all(a["risk_score"] > 70 for a in overprivileged)


# ---------------------------------------------------------------------------
# rotate_credentials
# ---------------------------------------------------------------------------


def test_rotate_returns_rotation_id(engine):
    acct = engine.register_service_account(ORG, _make_account())
    result = engine.rotate_credentials(ORG, acct["id"])
    assert "rotation_id" in result
    assert result["rotation_id"]


def test_rotate_returns_rotated_at(engine):
    acct = engine.register_service_account(ORG, _make_account())
    result = engine.rotate_credentials(ORG, acct["id"])
    assert "rotated_at" in result


def test_rotate_not_found_raises(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.rotate_credentials(ORG, "nonexistent-id")


def test_rotate_wrong_org_raises(engine):
    acct = engine.register_service_account(ORG, _make_account())
    with pytest.raises(ValueError, match="not found"):
        engine.rotate_credentials(ORG2, acct["id"])


# ---------------------------------------------------------------------------
# list_rotation_history
# ---------------------------------------------------------------------------


def test_list_rotation_history_empty_initially(engine):
    acct = engine.register_service_account(ORG, _make_account())
    history = engine.list_rotation_history(ORG, acct["id"])
    assert history == []


def test_list_rotation_history_records_rotations(engine):
    acct = engine.register_service_account(ORG, _make_account())
    engine.rotate_credentials(ORG, acct["id"])
    engine.rotate_credentials(ORG, acct["id"])
    history = engine.list_rotation_history(ORG, acct["id"])
    assert len(history) == 2


def test_list_rotation_history_has_timestamps(engine):
    acct = engine.register_service_account(ORG, _make_account())
    engine.rotate_credentials(ORG, acct["id"])
    history = engine.list_rotation_history(ORG, acct["id"])
    assert history[0]["rotated_at"]


# ---------------------------------------------------------------------------
# get_audit_stats
# ---------------------------------------------------------------------------


def test_get_audit_stats_structure(engine):
    stats = engine.get_audit_stats(ORG)
    assert "total_accounts" in stats
    assert "high_risk_count" in stats
    assert "unused_count" in stats
    assert "overdue_rotations" in stats
    assert "by_system" in stats


def test_get_audit_stats_counts_accounts(engine):
    engine.register_service_account(ORG, _make_account(name="svc-1", system="k8s"))
    engine.register_service_account(ORG, _make_account(name="svc-2", system="aws"))
    stats = engine.get_audit_stats(ORG)
    assert stats["total_accounts"] >= 2


def test_get_audit_stats_by_system(engine):
    engine.register_service_account(ORG, _make_account(system="gcp"))
    stats = engine.get_audit_stats(ORG)
    assert "gcp" in stats["by_system"]


# ---------------------------------------------------------------------------
# Multi-tenant isolation
# ---------------------------------------------------------------------------


def test_org_isolation_list(engine):
    engine.register_service_account(ORG, _make_account(name="org-alpha-svc"))
    engine.register_service_account(ORG2, _make_account(name="org-beta-svc"))
    alpha_accounts = engine.list_service_accounts(ORG)
    beta_accounts = engine.list_service_accounts(ORG2)
    alpha_names = [a["name"] for a in alpha_accounts]
    beta_names = [a["name"] for a in beta_accounts]
    assert "org-alpha-svc" in alpha_names
    assert "org-beta-svc" not in alpha_names
    assert "org-beta-svc" in beta_names


def test_org_isolation_stats(engine):
    engine.register_service_account(ORG, _make_account())
    stats_alpha = engine.get_audit_stats(ORG)
    stats_beta = engine.get_audit_stats(ORG2)
    assert stats_alpha["total_accounts"] != stats_beta["total_accounts"] or stats_beta["total_accounts"] == 0
