"""Tests for PasswordPolicyEngine — 22 tests covering all public methods."""

import os
import tempfile
import pytest

from core.password_policy_engine import PasswordPolicyEngine


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "test_password_policy.db")
    return PasswordPolicyEngine(db_path=db)


# ------------------------------------------------------------------
# Initialization
# ------------------------------------------------------------------

def test_init_creates_db(tmp_path):
    db = str(tmp_path / "pp.db")
    eng = PasswordPolicyEngine(db_path=db)
    assert os.path.exists(db)


def test_init_idempotent(tmp_path):
    db = str(tmp_path / "pp.db")
    PasswordPolicyEngine(db_path=db)
    PasswordPolicyEngine(db_path=db)  # second init must not raise


# ------------------------------------------------------------------
# create_policy / list_policies
# ------------------------------------------------------------------

def test_create_policy_returns_dict(engine):
    p = engine.create_policy("org1", {
        "name": "Strong Policy",
        "min_length": 12,
        "require_uppercase": True,
        "require_lowercase": True,
        "require_numbers": True,
        "require_symbols": True,
        "max_age_days": 60,
        "min_history": 10,
        "lockout_attempts": 3,
    })
    assert p["policy_id"]
    assert p["name"] == "Strong Policy"
    assert p["min_length"] == 12
    assert p["require_uppercase"] is True
    assert p["require_symbols"] is True
    assert p["complexity_score"] > 0
    assert p["created_at"]


def test_create_policy_complexity_score_increases_with_rules(engine):
    weak = engine.create_policy("org1", {"name": "Weak", "min_length": 6})
    strong = engine.create_policy("org1", {
        "name": "Strong",
        "min_length": 16,
        "require_uppercase": True,
        "require_lowercase": True,
        "require_numbers": True,
        "require_symbols": True,
        "max_age_days": 30,
        "min_history": 12,
    })
    assert strong["complexity_score"] > weak["complexity_score"]


def test_list_policies_empty(engine):
    assert engine.list_policies("org_none") == []


def test_list_policies_returns_own_org_only(engine):
    engine.create_policy("org1", {"name": "P1"})
    engine.create_policy("org2", {"name": "P2"})
    result = engine.list_policies("org1")
    assert len(result) == 1
    assert result[0]["name"] == "P1"


def test_list_policies_multiple(engine):
    engine.create_policy("org1", {"name": "A"})
    engine.create_policy("org1", {"name": "B"})
    result = engine.list_policies("org1")
    assert len(result) == 2


def test_policy_bool_fields_are_bool(engine):
    p = engine.create_policy("org1", {"require_uppercase": True, "require_symbols": False})
    assert isinstance(p["require_uppercase"], bool)
    assert isinstance(p["require_symbols"], bool)
    listed = engine.list_policies("org1")[0]
    assert isinstance(listed["require_uppercase"], bool)


# ------------------------------------------------------------------
# evaluate_password
# ------------------------------------------------------------------

def test_evaluate_password_meets_policy(engine):
    pol = engine.create_policy("org1", {
        "min_length": 8,
        "require_uppercase": True,
        "require_lowercase": True,
        "require_numbers": True,
        "require_symbols": False,
    })
    result = engine.evaluate_password(
        "org1", pol["policy_id"],
        "length:12,upper:1,lower:1,digits:1,symbols:0,entropy:50"
    )
    assert result["meets_policy"] is True
    assert result["issues"] == []
    assert 0 <= result["strength_score"] <= 100


def test_evaluate_password_fails_short(engine):
    pol = engine.create_policy("org1", {"min_length": 12})
    result = engine.evaluate_password("org1", pol["policy_id"], "length:8")
    assert result["meets_policy"] is False
    assert any("short" in i.lower() for i in result["issues"])


def test_evaluate_password_fails_missing_uppercase(engine):
    pol = engine.create_policy("org1", {"min_length": 8, "require_uppercase": True})
    result = engine.evaluate_password(
        "org1", pol["policy_id"], "length:10,upper:0,lower:1,digits:1"
    )
    assert result["meets_policy"] is False
    assert any("uppercase" in i.lower() for i in result["issues"])


def test_evaluate_password_fails_missing_symbol(engine):
    pol = engine.create_policy("org1", {"min_length": 8, "require_symbols": True})
    result = engine.evaluate_password(
        "org1", pol["policy_id"], "length:10,upper:1,lower:1,digits:1,symbols:0"
    )
    assert result["meets_policy"] is False
    assert any("symbol" in i.lower() for i in result["issues"])


def test_evaluate_password_invalid_policy(engine):
    result = engine.evaluate_password("org1", "nonexistent-id", "length:12")
    assert result["meets_policy"] is False
    assert result["strength_score"] == 0


def test_evaluate_password_strength_score_range(engine):
    pol = engine.create_policy("org1", {"min_length": 8})
    result = engine.evaluate_password("org1", pol["policy_id"], "length:20,upper:1,lower:1,digits:1,symbols:1,entropy:80")
    assert 0 <= result["strength_score"] <= 100


# ------------------------------------------------------------------
# record_audit / list_audits
# ------------------------------------------------------------------

def test_record_audit_returns_dict(engine):
    pol = engine.create_policy("org1", {"name": "AuditPol"})
    audit = engine.record_audit("org1", pol["policy_id"], 100, 10, 90.0)
    assert audit["audit_id"]
    assert audit["users_audited"] == 100
    assert audit["violations_found"] == 10
    assert audit["compliance_rate"] == 90.0


def test_list_audits_empty(engine):
    assert engine.list_audits("org_none") == []


def test_list_audits_returns_records(engine):
    pol = engine.create_policy("org1", {"name": "P"})
    engine.record_audit("org1", pol["policy_id"], 50, 5, 90.0)
    engine.record_audit("org1", pol["policy_id"], 60, 3, 95.0)
    audits = engine.list_audits("org1")
    assert len(audits) == 2


# ------------------------------------------------------------------
# create_violation / list_violations / remediate_violation
# ------------------------------------------------------------------

def test_create_violation_returns_dict(engine):
    pol = engine.create_policy("org1", {"name": "P"})
    v = engine.create_violation("org1", {
        "policy_id": pol["policy_id"],
        "user_id": "user-abc",
        "violation_type": "short",
        "severity": "high",
    })
    assert v["violation_id"]
    assert v["violation_type"] == "short"
    assert v["status"] == "open"


def test_list_violations_filter_by_status(engine):
    pol = engine.create_policy("org1", {"name": "P"})
    engine.create_violation("org1", {"policy_id": pol["policy_id"], "user_id": "u1", "violation_type": "short"})
    engine.create_violation("org1", {"policy_id": pol["policy_id"], "user_id": "u2", "violation_type": "expired", "status": "remediated"})
    open_v = engine.list_violations("org1", status="open")
    assert len(open_v) == 1
    all_v = engine.list_violations("org1")
    assert len(all_v) == 2


def test_remediate_violation(engine):
    pol = engine.create_policy("org1", {"name": "P"})
    v = engine.create_violation("org1", {"policy_id": pol["policy_id"], "user_id": "u1", "violation_type": "reused"})
    result = engine.remediate_violation("org1", v["violation_id"])
    assert result is True
    open_v = engine.list_violations("org1", status="open")
    assert len(open_v) == 0


def test_remediate_violation_wrong_org(engine):
    pol = engine.create_policy("org1", {"name": "P"})
    v = engine.create_violation("org1", {"policy_id": pol["policy_id"], "user_id": "u1", "violation_type": "reused"})
    result = engine.remediate_violation("org2", v["violation_id"])
    assert result is False


# ------------------------------------------------------------------
# get_policy_stats
# ------------------------------------------------------------------

def test_get_policy_stats_empty(engine):
    stats = engine.get_policy_stats("org_empty")
    assert stats["total_policies"] == 0
    assert stats["total_violations"] == 0
    assert stats["open_violations"] == 0


def test_get_policy_stats_counts(engine):
    pol = engine.create_policy("org1", {"name": "P", "min_length": 12, "require_uppercase": True})
    engine.create_violation("org1", {"policy_id": pol["policy_id"], "user_id": "u1", "violation_type": "short"})
    engine.create_violation("org1", {"policy_id": pol["policy_id"], "user_id": "u2", "violation_type": "expired"})
    engine.remediate_violation("org1", engine.list_violations("org1")[1]["violation_id"])
    engine.record_audit("org1", pol["policy_id"], 100, 2, 98.0)

    stats = engine.get_policy_stats("org1")
    assert stats["total_policies"] == 1
    assert stats["total_violations"] == 2
    assert stats["open_violations"] == 1
    assert stats["avg_complexity_score"] > 0


# ------------------------------------------------------------------
# Org isolation
# ------------------------------------------------------------------

def test_org_isolation_policies(engine):
    engine.create_policy("org1", {"name": "OrgA"})
    engine.create_policy("org2", {"name": "OrgB"})
    assert len(engine.list_policies("org1")) == 1
    assert len(engine.list_policies("org2")) == 1


def test_org_isolation_violations(engine):
    pol1 = engine.create_policy("org1", {"name": "P1"})
    pol2 = engine.create_policy("org2", {"name": "P2"})
    engine.create_violation("org1", {"policy_id": pol1["policy_id"], "user_id": "u1", "violation_type": "short"})
    engine.create_violation("org2", {"policy_id": pol2["policy_id"], "user_id": "u2", "violation_type": "expired"})
    assert len(engine.list_violations("org1")) == 1
    assert len(engine.list_violations("org2")) == 1
