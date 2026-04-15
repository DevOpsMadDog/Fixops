"""Tests for DigitalIdentityEngine — wave 18."""

import pytest
from core.digital_identity_engine import DigitalIdentityEngine


@pytest.fixture
def engine(tmp_path):
    return DigitalIdentityEngine(db_path=str(tmp_path / "digital_id.db"))


# ---------------------------------------------------------------------------
# create_profile — basic
# ---------------------------------------------------------------------------

def test_create_profile_minimal(engine):
    p = engine.create_profile("org1", {"user_id": "user-001"})
    assert p["user_id"] == "user-001"
    assert p["identity_level"] == "ial1"
    assert p["verification_status"] == "unverified"
    assert p["assurance_level"] == "aal1"
    assert isinstance(p["attributes"], dict)
    assert "id" in p
    assert "created_at" in p


def test_create_profile_all_identity_levels(engine):
    for idx, level in enumerate(["ial1", "ial2", "ial3"]):
        p = engine.create_profile("org1", {"user_id": f"user-{idx}", "identity_level": level})
        assert p["identity_level"] == level


def test_create_profile_defaults(engine):
    p = engine.create_profile("org1", {"user_id": "user-defaults"})
    assert p["verification_status"] == "unverified"
    assert p["assurance_level"] == "aal1"
    assert p["verified_at"] is None


def test_create_profile_missing_user_id_raises(engine):
    with pytest.raises(ValueError, match="user_id"):
        engine.create_profile("org1", {})


def test_create_profile_invalid_identity_level_raises(engine):
    with pytest.raises(ValueError, match="identity_level"):
        engine.create_profile("org1", {"user_id": "u1", "identity_level": "ial4"})


def test_create_profile_invalid_assurance_level_raises(engine):
    with pytest.raises(ValueError, match="assurance_level"):
        engine.create_profile("org1", {"user_id": "u2", "assurance_level": "aal4"})


# ---------------------------------------------------------------------------
# get_profile (by user_id, not id)
# ---------------------------------------------------------------------------

def test_get_profile_by_user_id(engine):
    engine.create_profile("org1", {"user_id": "user-find"})
    p = engine.get_profile("org1", "user-find")
    assert p is not None
    assert p["user_id"] == "user-find"


def test_get_profile_not_found_returns_none(engine):
    assert engine.get_profile("org1", "nonexistent") is None


def test_get_profile_org_isolation(engine):
    engine.create_profile("org1", {"user_id": "shared-user"})
    assert engine.get_profile("org2", "shared-user") is None


# ---------------------------------------------------------------------------
# list_profiles
# ---------------------------------------------------------------------------

def test_list_profiles_empty(engine):
    assert engine.list_profiles("org1") == []


def test_list_profiles_filter_by_status(engine):
    engine.create_profile("org1", {"user_id": "u-unverified"})
    engine.create_profile("org1", {"user_id": "u-pending"})
    # manually verify one
    engine.verify_identity("org1", "u-unverified", {"verification_method": "document", "identity_level": "ial2"})
    verified = engine.list_profiles("org1", verification_status="verified")
    assert len(verified) == 1
    assert verified[0]["user_id"] == "u-unverified"


def test_list_profiles_filter_by_level(engine):
    engine.create_profile("org1", {"user_id": "la1", "identity_level": "ial1"})
    engine.create_profile("org1", {"user_id": "la2", "identity_level": "ial2"})
    ial2 = engine.list_profiles("org1", identity_level="ial2")
    assert len(ial2) == 1
    assert ial2[0]["user_id"] == "la2"


# ---------------------------------------------------------------------------
# verify_identity
# ---------------------------------------------------------------------------

def test_verify_identity_updates_status(engine):
    engine.create_profile("org1", {"user_id": "v-user"})
    result = engine.verify_identity("org1", "v-user", {
        "verification_method": "biometric",
        "identity_level": "ial3",
    })
    assert result["verification_status"] == "verified"
    assert result["verified_at"] is not None
    assert result["identity_level"] == "ial3"
    assert result["verification_method"] == "biometric"


def test_verify_identity_all_methods(engine):
    for idx, method in enumerate(["self_asserted", "document", "biometric", "in_person"]):
        engine.create_profile("org1", {"user_id": f"vm-{idx}"})
        r = engine.verify_identity("org1", f"vm-{idx}", {"verification_method": method, "identity_level": "ial2"})
        assert r["verification_method"] == method


def test_verify_identity_invalid_method_raises(engine):
    engine.create_profile("org1", {"user_id": "bad-method"})
    with pytest.raises(ValueError, match="verification_method"):
        engine.verify_identity("org1", "bad-method", {"verification_method": "magic"})


def test_verify_identity_not_found_raises(engine):
    with pytest.raises(KeyError):
        engine.verify_identity("org1", "ghost-user", {"verification_method": "document", "identity_level": "ial2"})


# ---------------------------------------------------------------------------
# suspend_identity
# ---------------------------------------------------------------------------

def test_suspend_identity_changes_status(engine):
    engine.create_profile("org1", {"user_id": "susp-user"})
    result = engine.suspend_identity("org1", "susp-user", "Policy violation")
    assert result["verification_status"] == "suspended"


def test_suspend_identity_creates_event(engine):
    engine.create_profile("org1", {"user_id": "susp-evt"})
    engine.suspend_identity("org1", "susp-evt", "Suspicious activity")
    history = engine.get_verification_history("org1", "susp-evt")
    types = [e["event_type"] for e in history]
    assert "suspension" in types


def test_suspend_identity_not_found_raises(engine):
    with pytest.raises(KeyError):
        engine.suspend_identity("org1", "ghost", "reason")


# ---------------------------------------------------------------------------
# verification events
# ---------------------------------------------------------------------------

def test_record_verification_event_basic(engine):
    engine.create_profile("org1", {"user_id": "evt-user"})
    ev = engine.record_verification_event("org1", {
        "user_id": "evt-user",
        "event_type": "document_check",
        "outcome": "success",
        "evidence_type": "passport",
        "notes": "Valid passport",
    })
    assert ev["event_type"] == "document_check"
    assert ev["outcome"] == "success"


def test_record_verification_event_all_types(engine):
    types = ["initiation", "document_check", "biometric_check", "approval", "rejection", "suspension"]
    for idx, etype in enumerate(types):
        ev = engine.record_verification_event("org1", {
            "user_id": f"type-user-{idx}",
            "event_type": etype,
            "outcome": "pending",
        })
        assert ev["event_type"] == etype


def test_record_verification_event_invalid_type_raises(engine):
    with pytest.raises(ValueError, match="event_type"):
        engine.record_verification_event("org1", {
            "user_id": "u1",
            "event_type": "unknown_event",
            "outcome": "success",
        })


def test_record_verification_event_invalid_outcome_raises(engine):
    with pytest.raises(ValueError, match="outcome"):
        engine.record_verification_event("org1", {
            "user_id": "u1",
            "event_type": "initiation",
            "outcome": "maybe",
        })


def test_get_verification_history_ordered_desc(engine):
    for i in range(5):
        engine.record_verification_event("org1", {
            "user_id": "hist-user",
            "event_type": "initiation",
            "outcome": "pending",
        })
    history = engine.get_verification_history("org1", "hist-user")
    assert len(history) == 5
    # Verify DESC order
    for i in range(len(history) - 1):
        assert history[i]["created_at"] >= history[i + 1]["created_at"]


def test_get_verification_history_limit(engine):
    for i in range(10):
        engine.record_verification_event("org1", {
            "user_id": "limit-user",
            "event_type": "initiation",
            "outcome": "pending",
        })
    history = engine.get_verification_history("org1", "limit-user", limit=3)
    assert len(history) == 3


# ---------------------------------------------------------------------------
# add_attribute / list_attributes
# ---------------------------------------------------------------------------

def test_add_attribute_basic(engine):
    a = engine.add_attribute("org1", "attr-user", {
        "attribute_name": "email",
        "attribute_value": "user@example.com",
        "verified": True,
        "source": "document",
    })
    assert a["attribute_name"] == "email"
    assert a["attribute_value"] == "user@example.com"
    assert a["verified"] is True


def test_add_attribute_default_not_verified(engine):
    a = engine.add_attribute("org1", "attr-user2", {
        "attribute_name": "phone",
        "attribute_value": "+1-555-0000",
    })
    assert a["verified"] is False


def test_add_attribute_missing_name_raises(engine):
    with pytest.raises(ValueError, match="attribute_name"):
        engine.add_attribute("org1", "u1", {"attribute_value": "val"})


def test_add_attribute_missing_value_raises(engine):
    with pytest.raises(ValueError, match="attribute_value"):
        engine.add_attribute("org1", "u1", {"attribute_name": "name"})


def test_list_attributes(engine):
    engine.add_attribute("org1", "list-user", {"attribute_name": "email", "attribute_value": "a@b.com"})
    engine.add_attribute("org1", "list-user", {"attribute_name": "phone", "attribute_value": "555"})
    attrs = engine.list_attributes("org1", "list-user")
    assert len(attrs) == 2
    names = {a["attribute_name"] for a in attrs}
    assert names == {"email", "phone"}


# ---------------------------------------------------------------------------
# get_identity_stats
# ---------------------------------------------------------------------------

def test_get_identity_stats_counts(engine):
    engine.create_profile("org1", {"user_id": "st1", "identity_level": "ial1"})
    engine.create_profile("org1", {"user_id": "st2", "identity_level": "ial2"})
    engine.create_profile("org1", {"user_id": "st3", "identity_level": "ial3"})
    engine.verify_identity("org1", "st1", {"verification_method": "document", "identity_level": "ial2"})
    engine.suspend_identity("org1", "st3", "test")

    stats = engine.get_identity_stats("org1")
    assert stats["total_profiles"] == 3
    assert stats["verified_count"] == 1
    assert stats["suspended_count"] == 1
    assert stats["by_status"]["verified"] == 1
    assert stats["by_status"]["suspended"] == 1
    assert stats["total_events"] >= 2  # at least verify + suspend events


def test_get_identity_stats_org_isolation(engine):
    engine.create_profile("org1", {"user_id": "iso-user"})
    stats = engine.get_identity_stats("org2")
    assert stats["total_profiles"] == 0
    assert stats["verified_count"] == 0
