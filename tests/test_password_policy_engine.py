"""Tests for PasswordPolicyEngine — 38+ tests covering all public methods."""

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


# ------------------------------------------------------------------
# activate_policy
# ------------------------------------------------------------------

def test_activate_policy_returns_true(engine):
    pol = engine.create_policy("org1", {"name": "P"})
    result = engine.activate_policy("org1", pol["policy_id"])
    assert result is True


def test_activate_policy_deactivates_others(engine):
    p1 = engine.create_policy("org1", {"name": "P1"})
    p2 = engine.create_policy("org1", {"name": "P2"})
    engine.activate_policy("org1", p1["policy_id"])
    engine.activate_policy("org1", p2["policy_id"])
    policies = engine.list_policies("org1")
    active = [p for p in policies if p["is_active"]]
    assert len(active) == 1
    assert active[0]["policy_id"] == p2["policy_id"]


def test_activate_policy_wrong_org_returns_false(engine):
    pol = engine.create_policy("org1", {"name": "P"})
    result = engine.activate_policy("org2", pol["policy_id"])
    assert result is False


def test_list_policies_filter_is_active(engine):
    p1 = engine.create_policy("org1", {"name": "P1"})
    engine.create_policy("org1", {"name": "P2"})
    engine.activate_policy("org1", p1["policy_id"])
    active = engine.list_policies("org1", is_active=True)
    inactive = engine.list_policies("org1", is_active=False)
    assert len(active) == 1
    assert len(inactive) == 1


# ------------------------------------------------------------------
# check_password_strength (static)
# ------------------------------------------------------------------

def test_check_password_strength_strong():
    result = PasswordPolicyEngine.check_password_strength("C0mpl3x!P@ssw0rd#2026")
    assert result["score"] >= 75
    assert result["grade"] in ("A", "B")
    assert "breakdown" in result


def test_check_password_strength_weak():
    result = PasswordPolicyEngine.check_password_strength("abc")
    assert result["score"] < 40
    assert result["grade"] == "F"


def test_check_password_strength_medium():
    result = PasswordPolicyEngine.check_password_strength("Password1")
    assert 0 <= result["score"] <= 100
    assert result["grade"] in ("A", "B", "C", "D", "F")


def test_check_password_strength_empty():
    result = PasswordPolicyEngine.check_password_strength("")
    assert result["score"] == 0
    assert result["grade"] == "F"


def test_check_password_strength_breakdown_keys():
    result = PasswordPolicyEngine.check_password_strength("Test@123")
    assert "length" in result["breakdown"]
    assert "char_classes" in result["breakdown"]
    assert "entropy" in result["breakdown"]


def test_check_password_strength_all_lower():
    result = PasswordPolicyEngine.check_password_strength("onlylowercase")
    assert result["breakdown"]["char_classes"]["lower"] is True
    assert result["breakdown"]["char_classes"]["upper"] is False
    assert result["breakdown"]["char_classes"]["special"] is False


def test_check_password_strength_score_range():
    for pw in ("a", "Abcdef1!", "Th!sIsAV3ryLongAndComplexP@ssw0rd!"):
        result = PasswordPolicyEngine.check_password_strength(pw)
        assert 0 <= result["score"] <= 100


# ------------------------------------------------------------------
# report_violation (alias) + list_violations filters
# ------------------------------------------------------------------

def test_report_violation_alias(engine):
    pol = engine.create_policy("org1", {"name": "P"})
    v = engine.report_violation("org1", {
        "policy_id": pol["policy_id"],
        "user_id": "user-xyz",
        "violation_type": "weak_password",
        "severity": "high",
        "user_email": "user@example.com",
    })
    assert v["violation_id"]
    assert v["violation_type"] == "weak_password"
    assert v["user_email"] == "user@example.com"


def test_list_violations_filter_by_user_id(engine):
    pol = engine.create_policy("org1", {"name": "P"})
    engine.create_violation("org1", {"policy_id": pol["policy_id"], "user_id": "alice", "violation_type": "expired"})
    engine.create_violation("org1", {"policy_id": pol["policy_id"], "user_id": "bob", "violation_type": "short"})
    alice_v = engine.list_violations("org1", user_id="alice")
    assert len(alice_v) == 1
    assert alice_v[0]["user_id"] == "alice"


def test_list_violations_filter_by_violation_type(engine):
    pol = engine.create_policy("org1", {"name": "P"})
    engine.create_violation("org1", {"policy_id": pol["policy_id"], "user_id": "u1", "violation_type": "expired"})
    engine.create_violation("org1", {"policy_id": pol["policy_id"], "user_id": "u2", "violation_type": "short"})
    expired = engine.list_violations("org1", violation_type="expired")
    assert len(expired) == 1


# ------------------------------------------------------------------
# run_audit / enhanced audits
# ------------------------------------------------------------------

def test_run_audit_returns_full_record(engine):
    pol = engine.create_policy("org1", {"name": "P"})
    audit = engine.run_audit("org1", pol["policy_id"], {
        "total_users_checked": 200,
        "compliant": 180,
        "non_compliant": 20,
        "weak_count": 10,
        "expired_count": 5,
        "no_mfa_count": 8,
        "audit_date": "2026-04-16",
    })
    assert audit["audit_id"]
    assert audit["total_users_checked"] == 200
    assert audit["compliant"] == 180
    assert audit["weak_count"] == 10
    assert audit["expired_count"] == 5
    assert audit["no_mfa_count"] == 8
    assert audit["compliance_rate"] == 90.0
    assert audit["audit_date"] == "2026-04-16"


def test_run_audit_auto_computes_compliance_rate(engine):
    pol = engine.create_policy("org1", {"name": "P"})
    audit = engine.run_audit("org1", pol["policy_id"], {
        "total_users_checked": 100,
        "compliant": 75,
    })
    assert audit["compliance_rate"] == 75.0


def test_list_audits_limit(engine):
    pol = engine.create_policy("org1", {"name": "P"})
    for i in range(5):
        engine.record_audit("org1", pol["policy_id"], 100, i, float(100 - i))
    audits = engine.list_audits("org1", limit=3)
    assert len(audits) == 3


# ------------------------------------------------------------------
# MFA enrollment
# ------------------------------------------------------------------

def test_register_mfa_returns_record(engine):
    rec = engine.register_mfa("org1", {
        "user_id": "user-mfa-1",
        "user_email": "mfa@example.com",
        "mfa_type": "totp",
        "enrolled": True,
    })
    assert rec["id"]
    assert rec["user_id"] == "user-mfa-1"
    assert rec["mfa_type"] == "totp"
    assert rec["enrolled"] is True


def test_register_mfa_invalid_type_raises(engine):
    with pytest.raises(ValueError):
        engine.register_mfa("org1", {"user_id": "u1", "mfa_type": "carrier_pigeon"})


def test_register_mfa_missing_user_id_raises(engine):
    with pytest.raises(ValueError):
        engine.register_mfa("org1", {"mfa_type": "totp"})


def test_list_mfa_enrollments_filter_enrolled(engine):
    engine.register_mfa("org1", {"user_id": "u1", "mfa_type": "totp", "enrolled": True})
    engine.register_mfa("org1", {"user_id": "u2", "mfa_type": "sms", "enrolled": False})
    enrolled = engine.list_mfa_enrollments("org1", enrolled=True)
    not_enrolled = engine.list_mfa_enrollments("org1", enrolled=False)
    assert len(enrolled) == 1
    assert len(not_enrolled) == 1
    assert enrolled[0]["enrolled"] is True
    assert not_enrolled[0]["enrolled"] is False


def test_list_mfa_enrollments_all(engine):
    engine.register_mfa("org1", {"user_id": "u1", "mfa_type": "totp", "enrolled": True})
    engine.register_mfa("org1", {"user_id": "u2", "mfa_type": "hardware_key", "enrolled": True})
    engine.register_mfa("org1", {"user_id": "u3", "mfa_type": "push", "enrolled": False})
    all_mfa = engine.list_mfa_enrollments("org1")
    assert len(all_mfa) == 3


def test_mfa_org_isolation(engine):
    engine.register_mfa("org1", {"user_id": "u1", "mfa_type": "totp", "enrolled": True})
    engine.register_mfa("org2", {"user_id": "u2", "mfa_type": "sms", "enrolled": True})
    assert len(engine.list_mfa_enrollments("org1")) == 1
    assert len(engine.list_mfa_enrollments("org2")) == 1


# ------------------------------------------------------------------
# get_policy_stats (enhanced)
# ------------------------------------------------------------------

def test_get_policy_stats_has_mfa_fields(engine):
    engine.register_mfa("org1", {"user_id": "u1", "mfa_type": "totp", "enrolled": True})
    engine.register_mfa("org1", {"user_id": "u2", "mfa_type": "sms", "enrolled": False})
    stats = engine.get_policy_stats("org1")
    assert "mfa_enrollment_rate" in stats
    assert "users_without_mfa" in stats
    assert stats["mfa_enrollment_rate"] == 50.0
    assert stats["users_without_mfa"] == 1


def test_get_policy_stats_active_policy(engine):
    pol = engine.create_policy("org1", {"name": "P"})
    engine.activate_policy("org1", pol["policy_id"])
    stats = engine.get_policy_stats("org1")
    assert stats["active_policy"] is not None
    assert stats["active_policy"]["policy_id"] == pol["policy_id"]


def test_get_policy_stats_by_type(engine):
    pol = engine.create_policy("org1", {"name": "P"})
    engine.create_violation("org1", {"policy_id": pol["policy_id"], "user_id": "u1", "violation_type": "expired"})
    engine.create_violation("org1", {"policy_id": pol["policy_id"], "user_id": "u2", "violation_type": "short"})
    stats = engine.get_policy_stats("org1")
    assert "by_type" in stats
    assert "expired" in stats["by_type"] or "short" in stats["by_type"]


def test_get_policy_stats_compliance_rate_latest(engine):
    pol = engine.create_policy("org1", {"name": "P"})
    engine.run_audit("org1", pol["policy_id"], {
        "total_users_checked": 100, "compliant": 80,
    })
    stats = engine.get_policy_stats("org1")
    assert stats["compliance_rate_latest"] == 80.0
