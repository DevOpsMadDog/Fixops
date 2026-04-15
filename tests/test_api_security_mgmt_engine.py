"""Tests for APISecurityEngine (suite-core/core/api_security_mgmt_engine.py).

Covers: endpoint CRUD, API key lifecycle, abuse events, scans, stats,
org isolation, validation errors.
All tests use an in-memory temp SQLite DB — no real I/O side effects.
"""

from __future__ import annotations

import tempfile
import os
import pytest

from core.api_security_mgmt_engine import APISecurityEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "test_api_sec.db")
    return APISecurityEngine(db_path=db)


ORG = "org-alpha"
ORG2 = "org-beta"


# ---------------------------------------------------------------------------
# Endpoint tests
# ---------------------------------------------------------------------------

def test_register_endpoint_basic(engine):
    ep = engine.register_endpoint(ORG, {
        "endpoint_path": "/api/users",
        "http_method": "GET",
        "service_name": "user-svc",
    })
    assert ep["id"]
    assert ep["endpoint_path"] == "/api/users"
    assert ep["http_method"] == "GET"
    assert ep["org_id"] == ORG
    assert ep["status"] == "active"
    assert ep["authentication_required"] is True
    assert ep["is_public"] is False


def test_register_endpoint_missing_path(engine):
    with pytest.raises(ValueError, match="endpoint_path"):
        engine.register_endpoint(ORG, {})


def test_register_endpoint_invalid_method(engine):
    with pytest.raises(ValueError, match="http_method"):
        engine.register_endpoint(ORG, {"endpoint_path": "/x", "http_method": "INVALID"})


def test_register_endpoint_invalid_sensitivity(engine):
    with pytest.raises(ValueError, match="sensitivity_level"):
        engine.register_endpoint(ORG, {"endpoint_path": "/x", "sensitivity_level": "top_secret"})


def test_register_endpoint_all_fields(engine):
    ep = engine.register_endpoint(ORG, {
        "endpoint_path": "/api/admin/delete",
        "http_method": "DELETE",
        "service_name": "admin-svc",
        "authentication_required": True,
        "rate_limit_per_minute": 10,
        "is_public": False,
        "sensitivity_level": "critical",
        "risk_score": 9.5,
    })
    assert ep["sensitivity_level"] == "critical"
    assert ep["rate_limit_per_minute"] == 10
    assert ep["risk_score"] == 9.5


def test_list_endpoints_empty(engine):
    assert engine.list_endpoints(ORG) == []


def test_list_endpoints_returns_records(engine):
    engine.register_endpoint(ORG, {"endpoint_path": "/a", "service_name": "svc1"})
    engine.register_endpoint(ORG, {"endpoint_path": "/b", "service_name": "svc1"})
    engine.register_endpoint(ORG, {"endpoint_path": "/c", "service_name": "svc2"})
    assert len(engine.list_endpoints(ORG)) == 3


def test_list_endpoints_filter_service(engine):
    engine.register_endpoint(ORG, {"endpoint_path": "/a", "service_name": "svc1"})
    engine.register_endpoint(ORG, {"endpoint_path": "/b", "service_name": "svc2"})
    result = engine.list_endpoints(ORG, service_name="svc1")
    assert len(result) == 1
    assert result[0]["service_name"] == "svc1"


def test_list_endpoints_filter_is_public(engine):
    engine.register_endpoint(ORG, {"endpoint_path": "/pub", "is_public": True})
    engine.register_endpoint(ORG, {"endpoint_path": "/priv", "is_public": False})
    public = engine.list_endpoints(ORG, is_public=True)
    assert len(public) == 1
    assert public[0]["endpoint_path"] == "/pub"


def test_list_endpoints_filter_sensitivity(engine):
    engine.register_endpoint(ORG, {"endpoint_path": "/s", "sensitivity_level": "sensitive"})
    engine.register_endpoint(ORG, {"endpoint_path": "/i", "sensitivity_level": "internal"})
    result = engine.list_endpoints(ORG, sensitivity_level="sensitive")
    assert len(result) == 1


# ---------------------------------------------------------------------------
# API Key tests
# ---------------------------------------------------------------------------

def test_create_api_key_basic(engine):
    key = engine.create_api_key(ORG, {"key_name": "my-key"})
    assert key["id"]
    assert key["key_name"] == "my-key"
    assert "hashed_key" not in key
    assert key["key_hint"].endswith("...")
    assert key["status"] == "active"
    assert isinstance(key["scopes"], list)


def test_create_api_key_missing_name(engine):
    with pytest.raises(ValueError, match="key_name"):
        engine.create_api_key(ORG, {})


def test_create_api_key_with_scopes(engine):
    key = engine.create_api_key(ORG, {
        "key_name": "scoped-key",
        "scopes": ["read:findings", "write:reports"],
        "rate_limit_per_hour": 500,
    })
    assert "read:findings" in key["scopes"]
    assert key["rate_limit_per_hour"] == 500


def test_list_api_keys_no_hashed_key(engine):
    engine.create_api_key(ORG, {"key_name": "k1"})
    keys = engine.list_api_keys(ORG)
    assert len(keys) == 1
    assert "hashed_key" not in keys[0]


def test_list_api_keys_filter_status(engine):
    engine.create_api_key(ORG, {"key_name": "active-key"})
    keys = engine.list_api_keys(ORG, status="active")
    assert len(keys) == 1
    keys_revoked = engine.list_api_keys(ORG, status="revoked")
    assert len(keys_revoked) == 0


def test_revoke_api_key(engine):
    key = engine.create_api_key(ORG, {"key_name": "to-revoke"})
    result = engine.revoke_api_key(ORG, key["id"])
    assert result is True
    keys = engine.list_api_keys(ORG, status="active")
    assert len(keys) == 0


def test_revoke_nonexistent_key(engine):
    assert engine.revoke_api_key(ORG, "nonexistent-id") is False


# ---------------------------------------------------------------------------
# Abuse Event tests
# ---------------------------------------------------------------------------

def test_record_abuse_event_basic(engine):
    event = engine.record_abuse_event(ORG, {
        "event_type": "rate_limit_breach",
        "source_ip": "1.2.3.4",
        "severity": "high",
    })
    assert event["id"]
    assert event["event_type"] == "rate_limit_breach"
    assert event["severity"] == "high"
    assert event["status"] == "detected"


def test_record_abuse_event_invalid_type(engine):
    with pytest.raises(ValueError, match="event_type"):
        engine.record_abuse_event(ORG, {"event_type": "unknown_attack"})


def test_record_abuse_event_invalid_severity(engine):
    with pytest.raises(ValueError, match="severity"):
        engine.record_abuse_event(ORG, {"event_type": "bola_attempt", "severity": "extreme"})


def test_list_abuse_events_filter_type(engine):
    engine.record_abuse_event(ORG, {"event_type": "bola_attempt", "severity": "critical"})
    engine.record_abuse_event(ORG, {"event_type": "injection_attempt", "severity": "high"})
    result = engine.list_abuse_events(ORG, event_type="bola_attempt")
    assert len(result) == 1
    assert result[0]["event_type"] == "bola_attempt"


def test_list_abuse_events_filter_severity(engine):
    engine.record_abuse_event(ORG, {"event_type": "auth_bypass", "severity": "critical"})
    engine.record_abuse_event(ORG, {"event_type": "rate_limit_breach", "severity": "low"})
    crits = engine.list_abuse_events(ORG, severity="critical")
    assert len(crits) == 1


def test_list_abuse_events_limit(engine):
    for i in range(10):
        engine.record_abuse_event(ORG, {"event_type": "rate_limit_breach", "severity": "low"})
    result = engine.list_abuse_events(ORG, limit=3)
    assert len(result) == 3


# ---------------------------------------------------------------------------
# Scan tests
# ---------------------------------------------------------------------------

def test_create_scan_basic(engine):
    scan = engine.create_scan(ORG, {"scan_type": "owasp_api_top10", "target_service": "api-gw"})
    assert scan["id"]
    assert scan["status"] == "running"
    assert scan["scan_type"] == "owasp_api_top10"
    assert scan["endpoints_scanned"] == 0


def test_create_scan_invalid_type(engine):
    with pytest.raises(ValueError, match="scan_type"):
        engine.create_scan(ORG, {"scan_type": "unknown_scan"})


def test_complete_scan(engine):
    scan = engine.create_scan(ORG, {"scan_type": "fuzz", "target_service": "payments"})
    result = engine.complete_scan(ORG, scan["id"], {
        "endpoints_scanned": 42,
        "vulnerabilities_found": 3,
        "critical_count": 1,
    })
    assert result is True
    scans = engine.list_scans(ORG, status="completed")
    assert len(scans) == 1
    assert scans[0]["endpoints_scanned"] == 42
    assert scans[0]["critical_count"] == 1


def test_complete_scan_not_found(engine):
    assert engine.complete_scan(ORG, "bad-id", {}) is False


def test_list_scans_filter_status(engine):
    s1 = engine.create_scan(ORG, {"scan_type": "auth_test"})
    engine.create_scan(ORG, {"scan_type": "rate_limit_test"})
    engine.complete_scan(ORG, s1["id"], {"endpoints_scanned": 5})
    running = engine.list_scans(ORG, status="running")
    assert len(running) == 1
    completed = engine.list_scans(ORG, status="completed")
    assert len(completed) == 1


# ---------------------------------------------------------------------------
# Stats tests
# ---------------------------------------------------------------------------

def test_get_api_stats_empty(engine):
    stats = engine.get_api_stats(ORG)
    assert stats["total_endpoints"] == 0
    assert stats["active_api_keys"] == 0
    assert stats["abuse_events_24h"] == 0
    assert stats["scan_pass_rate"] == 100.0


def test_get_api_stats_populated(engine):
    engine.register_endpoint(ORG, {"endpoint_path": "/pub", "is_public": True, "sensitivity_level": "public"})
    engine.register_endpoint(ORG, {"endpoint_path": "/sec", "is_public": False, "sensitivity_level": "critical"})
    engine.create_api_key(ORG, {"key_name": "k1"})
    engine.record_abuse_event(ORG, {"event_type": "bola_attempt", "severity": "critical"})

    s = engine.create_scan(ORG, {"scan_type": "owasp_api_top10"})
    engine.complete_scan(ORG, s["id"], {"vulnerabilities_found": 2, "critical_count": 1})

    stats = engine.get_api_stats(ORG)
    assert stats["total_endpoints"] == 2
    assert stats["public_endpoints"] == 1
    assert stats["sensitive_endpoints"] == 1
    assert stats["active_api_keys"] == 1
    assert stats["abuse_events_24h"] == 1
    assert stats["critical_vulnerabilities"] == 1
    assert stats["scan_pass_rate"] == 0.0
    assert "bola_attempt" in stats["by_event_type"]
    assert "critical" in stats["by_severity"]


# ---------------------------------------------------------------------------
# Org isolation tests
# ---------------------------------------------------------------------------

def test_org_isolation_endpoints(engine):
    engine.register_endpoint(ORG, {"endpoint_path": "/secret"})
    assert engine.list_endpoints(ORG2) == []


def test_org_isolation_keys(engine):
    engine.create_api_key(ORG, {"key_name": "key-alpha"})
    assert engine.list_api_keys(ORG2) == []


def test_org_isolation_abuse_events(engine):
    engine.record_abuse_event(ORG, {"event_type": "auth_bypass", "severity": "high"})
    assert engine.list_abuse_events(ORG2) == []


def test_org_isolation_scans(engine):
    engine.create_scan(ORG, {"scan_type": "fuzz"})
    assert engine.list_scans(ORG2) == []
