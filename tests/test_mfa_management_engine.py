"""Tests for MFAManagementEngine — 41 tests covering enrollments, events, policies, stats."""

from __future__ import annotations

import pytest
from core.mfa_management_engine import MFAManagementEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    return MFAManagementEngine(db_path=str(tmp_path / "mfa.db"))


ORG = "org-test"
ORG2 = "org-other"


# ---------------------------------------------------------------------------
# Enrollment creation
# ---------------------------------------------------------------------------

def test_enroll_user_totp(engine):
    rec = engine.enroll_user(ORG, {"user_id": "u1", "mfa_type": "totp"})
    assert rec["user_id"] == "u1"
    assert rec["mfa_type"] == "totp"
    assert rec["status"] == "pending"
    assert rec["enrolled_at"] is None


def test_enroll_user_sms(engine):
    rec = engine.enroll_user(ORG, {"user_id": "u1", "mfa_type": "sms"})
    assert rec["mfa_type"] == "sms"


def test_enroll_user_email(engine):
    rec = engine.enroll_user(ORG, {"user_id": "u1", "mfa_type": "email"})
    assert rec["mfa_type"] == "email"


def test_enroll_user_hardware_key(engine):
    rec = engine.enroll_user(ORG, {"user_id": "u1", "mfa_type": "hardware_key"})
    assert rec["mfa_type"] == "hardware_key"


def test_enroll_user_push(engine):
    rec = engine.enroll_user(ORG, {"user_id": "u1", "mfa_type": "push"})
    assert rec["mfa_type"] == "push"


def test_enroll_user_invalid_type_raises(engine):
    with pytest.raises(ValueError, match="mfa_type"):
        engine.enroll_user(ORG, {"user_id": "u1", "mfa_type": "carrier_pigeon"})


def test_enroll_user_missing_user_id_raises(engine):
    with pytest.raises(ValueError, match="user_id"):
        engine.enroll_user(ORG, {"mfa_type": "totp"})


def test_enroll_user_backup_codes(engine):
    rec = engine.enroll_user(ORG, {"user_id": "u1", "mfa_type": "totp", "backup_codes_count": 8})
    assert rec["backup_codes_count"] == 8


# ---------------------------------------------------------------------------
# Enrollment lifecycle: activate + disable
# ---------------------------------------------------------------------------

def test_activate_enrollment(engine):
    rec = engine.enroll_user(ORG, {"user_id": "u2", "mfa_type": "totp"})
    activated = engine.activate_enrollment(ORG, rec["id"])
    assert activated["status"] == "active"
    assert activated["enrolled_at"] is not None


def test_disable_enrollment(engine):
    rec = engine.enroll_user(ORG, {"user_id": "u3", "mfa_type": "sms"})
    engine.activate_enrollment(ORG, rec["id"])
    disabled = engine.disable_enrollment(ORG, rec["id"])
    assert disabled["status"] == "disabled"


def test_get_enrollment(engine):
    rec = engine.enroll_user(ORG, {"user_id": "u4", "mfa_type": "push"})
    fetched = engine.get_enrollment(ORG, rec["id"])
    assert fetched["id"] == rec["id"]


def test_get_enrollment_wrong_org_returns_none(engine):
    rec = engine.enroll_user(ORG, {"user_id": "u4", "mfa_type": "push"})
    assert engine.get_enrollment(ORG2, rec["id"]) is None


def test_list_enrollments_all(engine):
    engine.enroll_user(ORG, {"user_id": "u5", "mfa_type": "totp"})
    engine.enroll_user(ORG, {"user_id": "u6", "mfa_type": "sms"})
    result = engine.list_enrollments(ORG)
    assert len(result) == 2


def test_list_enrollments_filter_by_user(engine):
    engine.enroll_user(ORG, {"user_id": "u7", "mfa_type": "totp"})
    engine.enroll_user(ORG, {"user_id": "u8", "mfa_type": "sms"})
    result = engine.list_enrollments(ORG, user_id="u7")
    assert all(r["user_id"] == "u7" for r in result)


def test_list_enrollments_filter_by_type(engine):
    engine.enroll_user(ORG, {"user_id": "u9", "mfa_type": "totp"})
    engine.enroll_user(ORG, {"user_id": "u10", "mfa_type": "sms"})
    result = engine.list_enrollments(ORG, mfa_type="totp")
    assert all(r["mfa_type"] == "totp" for r in result)


def test_list_enrollments_filter_by_status(engine):
    r1 = engine.enroll_user(ORG, {"user_id": "u11", "mfa_type": "totp"})
    engine.activate_enrollment(ORG, r1["id"])
    engine.enroll_user(ORG, {"user_id": "u12", "mfa_type": "sms"})
    active = engine.list_enrollments(ORG, status="active")
    assert all(r["status"] == "active" for r in active)


def test_list_enrollments_org_isolation(engine):
    engine.enroll_user(ORG, {"user_id": "u13", "mfa_type": "totp"})
    result = engine.list_enrollments(ORG2)
    assert result == []


# ---------------------------------------------------------------------------
# MFA events
# ---------------------------------------------------------------------------

def test_record_mfa_event_success(engine):
    ev = engine.record_mfa_event(ORG, {
        "user_id": "u1", "event_type": "verification", "mfa_type": "totp",
        "success": True, "ip_address": "1.2.3.4",
    })
    assert ev["success"] is True
    assert ev["event_type"] == "verification"


def test_record_mfa_event_failure(engine):
    ev = engine.record_mfa_event(ORG, {
        "user_id": "u1", "event_type": "failure", "success": False,
    })
    assert ev["success"] is False


def test_record_mfa_event_all_types(engine):
    for et in ("enrollment", "verification", "bypass", "failure", "reset"):
        ev = engine.record_mfa_event(ORG, {"user_id": "u1", "event_type": et, "success": True})
        assert ev["event_type"] == et


def test_record_mfa_event_missing_user_id_raises(engine):
    with pytest.raises(ValueError, match="user_id"):
        engine.record_mfa_event(ORG, {"event_type": "verification", "success": True})


def test_record_mfa_event_invalid_event_type_raises(engine):
    with pytest.raises(ValueError, match="event_type"):
        engine.record_mfa_event(ORG, {"user_id": "u1", "event_type": "bad_type", "success": True})


def test_record_mfa_event_non_bool_success_raises(engine):
    with pytest.raises(ValueError, match="success"):
        engine.record_mfa_event(ORG, {"user_id": "u1", "event_type": "verification", "success": "yes"})


def test_get_mfa_events_filter_user(engine):
    engine.record_mfa_event(ORG, {"user_id": "u1", "event_type": "verification", "success": True})
    engine.record_mfa_event(ORG, {"user_id": "u2", "event_type": "failure", "success": False})
    result = engine.get_mfa_events(ORG, user_id="u1")
    assert all(r["user_id"] == "u1" for r in result)


def test_get_mfa_events_filter_type(engine):
    engine.record_mfa_event(ORG, {"user_id": "u1", "event_type": "bypass", "success": True})
    engine.record_mfa_event(ORG, {"user_id": "u1", "event_type": "reset", "success": True})
    result = engine.get_mfa_events(ORG, event_type="bypass")
    assert all(r["event_type"] == "bypass" for r in result)


def test_get_mfa_events_org_isolation(engine):
    engine.record_mfa_event(ORG, {"user_id": "u1", "event_type": "verification", "success": True})
    assert engine.get_mfa_events(ORG2) == []


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------

def test_create_policy(engine):
    pol = engine.create_policy(ORG, {
        "policy_name": "Corp MFA", "enforcement": "mandatory",
        "required_mfa_types": ["totp", "push"], "grace_period_days": 14,
    })
    assert pol["policy_name"] == "Corp MFA"
    assert pol["enforcement"] == "mandatory"
    assert "totp" in pol["required_mfa_types"]
    assert pol["grace_period_days"] == 14


def test_create_policy_invalid_enforcement_raises(engine):
    with pytest.raises(ValueError, match="enforcement"):
        engine.create_policy(ORG, {"policy_name": "Bad", "enforcement": "ultra-strict"})


def test_create_policy_missing_name_raises(engine):
    with pytest.raises(ValueError, match="policy_name"):
        engine.create_policy(ORG, {"enforcement": "optional"})


def test_list_policies(engine):
    engine.create_policy(ORG, {"policy_name": "P1", "enforcement": "mandatory"})
    engine.create_policy(ORG, {"policy_name": "P2", "enforcement": "optional"})
    result = engine.list_policies(ORG)
    assert len(result) == 2


def test_list_policies_org_isolation(engine):
    engine.create_policy(ORG, {"policy_name": "P1", "enforcement": "mandatory"})
    assert engine.list_policies(ORG2) == []


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def test_get_mfa_stats_empty(engine):
    stats = engine.get_mfa_stats(ORG)
    assert stats["total_enrolled"] == 0
    assert stats["total_events"] == 0
    assert stats["compliance_rate"] == 0.0


def test_get_mfa_stats_counts(engine):
    r1 = engine.enroll_user(ORG, {"user_id": "u1", "mfa_type": "totp"})
    r2 = engine.enroll_user(ORG, {"user_id": "u2", "mfa_type": "sms"})
    engine.activate_enrollment(ORG, r1["id"])
    engine.activate_enrollment(ORG, r2["id"])
    engine.record_mfa_event(ORG, {"user_id": "u1", "event_type": "verification", "success": True})
    engine.record_mfa_event(ORG, {"user_id": "u1", "event_type": "failure", "success": False})
    stats = engine.get_mfa_stats(ORG)
    assert stats["total_enrolled"] == 2
    assert stats["total_events"] == 2
    assert stats["failed_events"] == 1
    assert stats["by_type"].get("totp") == 1
    assert stats["by_type"].get("sms") == 1
    assert stats["compliance_rate"] == 1.0


def test_get_mfa_stats_partial_compliance(engine):
    r1 = engine.enroll_user(ORG, {"user_id": "u1", "mfa_type": "totp"})
    engine.activate_enrollment(ORG, r1["id"])
    engine.enroll_user(ORG, {"user_id": "u2", "mfa_type": "sms"})  # pending
    stats = engine.get_mfa_stats(ORG)
    assert stats["total_enrolled"] == 1
    # 1 active out of 2 attempted users
    assert stats["compliance_rate"] == 0.5


# ---------------------------------------------------------------------------
# MFA Policy — extended coverage
# ---------------------------------------------------------------------------

def test_create_policy_disabled_enforcement(engine):
    """Enforcement value 'disabled' must be accepted and stored correctly."""
    pol = engine.create_policy(ORG, {"policy_name": "No MFA", "enforcement": "disabled"})
    assert pol["enforcement"] == "disabled"


def test_create_policy_required_mfa_types_roundtrip(engine):
    """required_mfa_types JSON array must survive a write/read cycle."""
    types = ["totp", "hardware_key", "push"]
    pol = engine.create_policy(ORG, {
        "policy_name": "Strong MFA",
        "enforcement": "mandatory",
        "required_mfa_types": types,
    })
    fetched = engine.list_policies(ORG)
    assert fetched[0]["required_mfa_types"] == types


def test_create_policy_default_grace_period(engine):
    """When grace_period_days is omitted, default of 7 must be stored."""
    pol = engine.create_policy(ORG, {"policy_name": "Default Grace", "enforcement": "optional"})
    assert pol["grace_period_days"] == 7


def test_create_policy_zero_grace_period(engine):
    """grace_period_days of 0 (strict immediate enforcement) must be stored."""
    pol = engine.create_policy(ORG, {
        "policy_name": "Immediate",
        "enforcement": "mandatory",
        "grace_period_days": 0,
    })
    assert pol["grace_period_days"] == 0


def test_list_policies_ordered_newest_first(engine):
    """list_policies must return records ordered by created_at DESC."""
    engine.create_policy(ORG, {"policy_name": "First", "enforcement": "optional"})
    engine.create_policy(ORG, {"policy_name": "Second", "enforcement": "mandatory"})
    result = engine.list_policies(ORG)
    # Most recently created record must appear first
    assert result[0]["policy_name"] == "Second"
    assert result[1]["policy_name"] == "First"


def test_create_policy_all_enforcement_values_accepted(engine):
    """All three valid enforcement values must be accepted without error."""
    for enforcement in ("mandatory", "optional", "disabled"):
        pol = engine.create_policy(ORG, {
            "policy_name": f"Policy-{enforcement}",
            "enforcement": enforcement,
        })
        assert pol["enforcement"] == enforcement


# ---------------------------------------------------------------------------
# enforce_policy
# ---------------------------------------------------------------------------

def test_enforce_policy_mandatory_compliant(engine):
    """User with all required types active must be compliant under mandatory policy."""
    pol = engine.create_policy(ORG, {
        "policy_name": "Strict", "enforcement": "mandatory",
        "required_mfa_types": ["totp", "push"],
    })
    for mfa_type in ("totp", "push"):
        rec = engine.enroll_user(ORG, {"user_id": "alice", "mfa_type": mfa_type})
        engine.activate_enrollment(ORG, rec["id"])

    result = engine.enforce_policy(ORG, pol["id"], "alice")
    assert result["compliant"] is True
    assert result["missing_types"] == []
    assert set(result["active_types"]) == {"totp", "push"}


def test_enforce_policy_mandatory_non_compliant(engine):
    """User missing a required type must be non-compliant with missing_types populated."""
    pol = engine.create_policy(ORG, {
        "policy_name": "Strict", "enforcement": "mandatory",
        "required_mfa_types": ["totp", "hardware_key"],
    })
    rec = engine.enroll_user(ORG, {"user_id": "bob", "mfa_type": "totp"})
    engine.activate_enrollment(ORG, rec["id"])

    result = engine.enforce_policy(ORG, pol["id"], "bob")
    assert result["compliant"] is False
    assert "hardware_key" in result["missing_types"]


def test_enforce_policy_disabled_always_compliant(engine):
    """A policy with enforcement='disabled' must report compliant regardless of enrollments."""
    pol = engine.create_policy(ORG, {
        "policy_name": "Off", "enforcement": "disabled",
        "required_mfa_types": ["totp"],
    })
    # user has NO enrollments at all
    result = engine.enforce_policy(ORG, pol["id"], "carol")
    assert result["compliant"] is True
    assert result["missing_types"] == []


def test_enforce_policy_optional_partial_match(engine):
    """Optional policy is satisfied when the user has at least one required type active."""
    pol = engine.create_policy(ORG, {
        "policy_name": "Soft", "enforcement": "optional",
        "required_mfa_types": ["totp", "sms"],
    })
    rec = engine.enroll_user(ORG, {"user_id": "dave", "mfa_type": "sms"})
    engine.activate_enrollment(ORG, rec["id"])

    result = engine.enforce_policy(ORG, pol["id"], "dave")
    assert result["compliant"] is True
    assert result["grace_period_days"] == 7


def test_enforce_policy_invalid_policy_id_raises(engine):
    """Non-existent policy_id must raise ValueError."""
    with pytest.raises(ValueError, match="not found"):
        engine.enforce_policy(ORG, "no-such-id", "eve")
