"""
Tests for IdentityAnalyticsEngine — 25+ tests covering all methods and org isolation.
"""
from __future__ import annotations

import json
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from core.identity_analytics_engine import IdentityAnalyticsEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "test_identity.db")
    return IdentityAnalyticsEngine(db_path=db)


@pytest.fixture
def org_a():
    return "org-alpha"


@pytest.fixture
def org_b():
    return "org-beta"


def _make_identity(engine, org_id, **kwargs):
    data = {
        "username": "alice",
        "email": "alice@example.com",
        "department": "engineering",
        "job_title": "engineer",
        "identity_type": "human",
        "privileged": False,
        "mfa_enabled": True,
    }
    data.update(kwargs)
    return engine.register_identity(org_id, data)


# ---------------------------------------------------------------------------
# register_identity
# ---------------------------------------------------------------------------

def test_register_identity_returns_record(engine, org_a):
    rec = _make_identity(engine, org_a)
    assert rec["identity_id"]
    assert rec["org_id"] == org_a
    assert rec["username"] == "alice"
    assert rec["identity_type"] == "human"
    assert rec["risk_score"] == 0.0
    assert rec["risk_tier"] == "low"


def test_register_identity_service_account(engine, org_a):
    rec = _make_identity(engine, org_a, identity_type="service_account", username="svc-deploy")
    assert rec["identity_type"] == "service_account"


def test_register_identity_invalid_type_defaults_human(engine, org_a):
    rec = _make_identity(engine, org_a, identity_type="alien")
    assert rec["identity_type"] == "human"


def test_register_identity_privileged_flag(engine, org_a):
    rec = _make_identity(engine, org_a, privileged=True)
    assert rec["privileged"] == 1


def test_register_identity_mfa_disabled(engine, org_a):
    rec = _make_identity(engine, org_a, mfa_enabled=False)
    assert rec["mfa_enabled"] == 0


# ---------------------------------------------------------------------------
# list_identities
# ---------------------------------------------------------------------------

def test_list_identities_all(engine, org_a):
    _make_identity(engine, org_a, username="alice")
    _make_identity(engine, org_a, username="bob", identity_type="service_account")
    results = engine.list_identities(org_a)
    assert len(results) == 2


def test_list_identities_filter_type(engine, org_a):
    _make_identity(engine, org_a, username="alice")
    _make_identity(engine, org_a, username="svc", identity_type="service_account")
    results = engine.list_identities(org_a, identity_type="service_account")
    assert len(results) == 1
    assert results[0]["username"] == "svc"


def test_list_identities_privileged_only(engine, org_a):
    _make_identity(engine, org_a, username="regular")
    _make_identity(engine, org_a, username="admin", privileged=True)
    results = engine.list_identities(org_a, privileged_only=True)
    assert len(results) == 1
    assert results[0]["username"] == "admin"


def test_list_identities_org_isolation(engine, org_a, org_b):
    _make_identity(engine, org_a, username="alice")
    _make_identity(engine, org_b, username="bob")
    assert len(engine.list_identities(org_a)) == 1
    assert len(engine.list_identities(org_b)) == 1


# ---------------------------------------------------------------------------
# ingest_login_event
# ---------------------------------------------------------------------------

def test_ingest_login_event_basic(engine, org_a):
    identity = _make_identity(engine, org_a)
    iid = identity["identity_id"]
    ev = engine.ingest_login_event(org_a, iid, {"event_type": "login", "success": True})
    assert ev["event_id"]
    assert ev["identity_id"] == iid
    assert ev["event_type"] == "login"


def test_ingest_login_event_updates_login_count(engine, org_a):
    identity = _make_identity(engine, org_a)
    iid = identity["identity_id"]
    engine.ingest_login_event(org_a, iid, {"event_type": "login", "success": True})
    engine.ingest_login_event(org_a, iid, {"event_type": "login", "success": True})
    identities = engine.list_identities(org_a)
    assert identities[0]["login_count"] == 2


def test_ingest_failed_login_increments_failed_count(engine, org_a):
    identity = _make_identity(engine, org_a)
    iid = identity["identity_id"]
    engine.ingest_login_event(org_a, iid, {"event_type": "failed_login", "success": False})
    identities = engine.list_identities(org_a)
    assert identities[0]["failed_logins"] == 1


def test_ingest_failed_login_increases_risk_score(engine, org_a):
    identity = _make_identity(engine, org_a)
    iid = identity["identity_id"]
    engine.ingest_login_event(org_a, iid, {"event_type": "failed_login", "success": False})
    identities = engine.list_identities(org_a)
    assert identities[0]["risk_score"] > 0.0


def test_credential_spray_detection(engine, org_a):
    """11 failed logins should trigger credential_spray indicator."""
    identity = _make_identity(engine, org_a, failed_logins=10)
    iid = identity["identity_id"]
    ev = engine.ingest_login_event(org_a, iid, {"event_type": "failed_login", "success": False})
    assert "credential_spray" in ev["risk_indicators"]


def test_impossible_travel_detection(engine, org_a):
    """Same identity logging in from two countries within 1 hour triggers impossible_travel."""
    identity = _make_identity(engine, org_a)
    iid = identity["identity_id"]
    # First event from US, 30 min ago
    thirty_min_ago = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
    engine.ingest_login_event(
        org_a, iid,
        {"event_type": "login", "geo_country": "US", "success": True, "observed_at": thirty_min_ago}
    )
    # Second event from UK, now → impossible travel
    ev = engine.ingest_login_event(
        org_a, iid,
        {"event_type": "login", "geo_country": "UK", "success": True}
    )
    assert "impossible_travel" in ev["risk_indicators"]


def test_no_impossible_travel_same_country(engine, org_a):
    """Same country → no impossible_travel."""
    identity = _make_identity(engine, org_a)
    iid = identity["identity_id"]
    thirty_min_ago = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
    engine.ingest_login_event(
        org_a, iid,
        {"event_type": "login", "geo_country": "US", "success": True, "observed_at": thirty_min_ago}
    )
    ev = engine.ingest_login_event(
        org_a, iid,
        {"event_type": "login", "geo_country": "US", "success": True}
    )
    assert "impossible_travel" not in ev["risk_indicators"]


def test_privilege_escalation_increases_risk_score(engine, org_a):
    identity = _make_identity(engine, org_a)
    iid = identity["identity_id"]
    engine.ingest_login_event(org_a, iid, {"event_type": "privilege_escalation"})
    identities = engine.list_identities(org_a)
    assert identities[0]["risk_score"] >= 0.5


def test_ingest_login_event_unknown_identity_raises(engine, org_a):
    with pytest.raises(ValueError, match="not found"):
        engine.ingest_login_event(org_a, "nonexistent-id", {"event_type": "login"})


def test_ingest_login_event_org_isolation(engine, org_a, org_b):
    id_a = _make_identity(engine, org_a)["identity_id"]
    # org_b should not be able to ingest for org_a's identity
    with pytest.raises(ValueError):
        engine.ingest_login_event(org_b, id_a, {"event_type": "login"})


# ---------------------------------------------------------------------------
# list_login_events
# ---------------------------------------------------------------------------

def test_list_login_events_returns_deserialized_indicators(engine, org_a):
    identity = _make_identity(engine, org_a)
    iid = identity["identity_id"]
    engine.ingest_login_event(org_a, iid, {"event_type": "login", "risk_indicators": ["new_device"]})
    events = engine.list_login_events(org_a, identity_id=iid)
    assert isinstance(events[0]["risk_indicators"], list)


def test_list_login_events_filter_by_type(engine, org_a):
    identity = _make_identity(engine, org_a)
    iid = identity["identity_id"]
    engine.ingest_login_event(org_a, iid, {"event_type": "login"})
    engine.ingest_login_event(org_a, iid, {"event_type": "failed_login", "success": False})
    events = engine.list_login_events(org_a, event_type="failed_login")
    assert len(events) == 1


# ---------------------------------------------------------------------------
# flag_risk / list_risks / resolve_risk
# ---------------------------------------------------------------------------

def test_flag_risk_creates_record(engine, org_a):
    identity = _make_identity(engine, org_a)
    iid = identity["identity_id"]
    risk = engine.flag_risk(org_a, iid, {"risk_type": "dormant_account", "severity": "low"})
    assert risk["risk_id"]
    assert risk["risk_type"] == "dormant_account"
    assert risk["severity"] == "low"


def test_flag_risk_invalid_type_defaults(engine, org_a):
    identity = _make_identity(engine, org_a)
    risk = engine.flag_risk(org_a, identity["identity_id"], {"risk_type": "fake_type"})
    assert risk["risk_type"] == "excessive_privilege"


def test_list_risks_unresolved_only(engine, org_a):
    identity = _make_identity(engine, org_a)
    iid = identity["identity_id"]
    r = engine.flag_risk(org_a, iid, {"risk_type": "dormant_account"})
    engine.resolve_risk(org_a, r["risk_id"])
    engine.flag_risk(org_a, iid, {"risk_type": "mfa_bypass"})
    open_risks = engine.list_risks(org_a, resolved=False)
    assert len(open_risks) == 1
    assert open_risks[0]["risk_type"] == "mfa_bypass"


def test_resolve_risk_returns_true(engine, org_a):
    identity = _make_identity(engine, org_a)
    r = engine.flag_risk(org_a, identity["identity_id"], {"risk_type": "dormant_account"})
    assert engine.resolve_risk(org_a, r["risk_id"]) is True


def test_resolve_risk_nonexistent_returns_false(engine, org_a):
    assert engine.resolve_risk(org_a, "no-such-id") is False


def test_list_risks_org_isolation(engine, org_a, org_b):
    id_a = _make_identity(engine, org_a)["identity_id"]
    engine.flag_risk(org_a, id_a, {"risk_type": "dormant_account"})
    assert len(engine.list_risks(org_b)) == 0


# ---------------------------------------------------------------------------
# Access Certifications
# ---------------------------------------------------------------------------

def test_create_certification(engine, org_a):
    identity = _make_identity(engine, org_a)
    cert = engine.create_certification(org_a, identity["identity_id"], {
        "reviewer": "manager@example.com",
        "status": "pending",
        "access_level": "admin",
    })
    assert cert["cert_id"]
    assert cert["status"] == "pending"
    assert cert["reviewer"] == "manager@example.com"


def test_list_certifications_filter_status(engine, org_a):
    identity = _make_identity(engine, org_a)
    iid = identity["identity_id"]
    engine.create_certification(org_a, iid, {"status": "pending"})
    engine.create_certification(org_a, iid, {"status": "approved"})
    pending = engine.list_certifications(org_a, status="pending")
    assert len(pending) == 1


def test_certifications_org_isolation(engine, org_a, org_b):
    id_a = _make_identity(engine, org_a)["identity_id"]
    engine.create_certification(org_a, id_a, {"status": "pending"})
    assert len(engine.list_certifications(org_b)) == 0


# ---------------------------------------------------------------------------
# get_identity_stats
# ---------------------------------------------------------------------------

def test_get_identity_stats_empty(engine, org_a):
    stats = engine.get_identity_stats(org_a)
    assert stats["total_identities"] == 0
    assert stats["privileged_identities"] == 0
    assert stats["mfa_disabled"] == 0
    assert stats["critical_risk_identities"] == 0
    assert stats["open_risks"] == 0
    assert stats["impossible_travel_count"] == 0
    assert stats["dormant_identities"] == 0
    assert stats["pending_certifications"] == 0


def test_get_identity_stats_counts(engine, org_a):
    id1 = _make_identity(engine, org_a, username="admin", privileged=True, mfa_enabled=False)["identity_id"]
    _make_identity(engine, org_a, username="regular")
    engine.flag_risk(org_a, id1, {"risk_type": "dormant_account"})
    engine.create_certification(org_a, id1, {"status": "pending"})
    stats = engine.get_identity_stats(org_a)
    assert stats["total_identities"] == 2
    assert stats["privileged_identities"] == 1
    assert stats["mfa_disabled"] == 1
    assert stats["open_risks"] == 1
    assert stats["pending_certifications"] == 1


def test_get_identity_stats_dormant_includes_never_logged_in(engine, org_a):
    """Identity with no last_login should count as dormant."""
    _make_identity(engine, org_a)
    stats = engine.get_identity_stats(org_a)
    assert stats["dormant_identities"] == 1


def test_get_identity_stats_org_isolation(engine, org_a, org_b):
    _make_identity(engine, org_a)
    stats_b = engine.get_identity_stats(org_b)
    assert stats_b["total_identities"] == 0
