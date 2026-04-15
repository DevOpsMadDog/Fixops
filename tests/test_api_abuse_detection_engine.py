"""Tests for APIAbuseDetectionEngine.

Covers:
- Endpoint registration: valid/invalid method, status
- Endpoint listing with filters, get by ID (org isolation)
- Incident recording: valid/invalid abuse_type, severity, status
- Incident listing with filters and status update
- Rule creation: valid/invalid rule_type, action; enabled flag
- Rule listing with filters
- Stats correctness: totals, by_abuse_type, by_severity, avg_abuse_score
- Multi-tenant org_id isolation throughout
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("FIXOPS_MODE", "dev")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")

from core.api_abuse_detection_engine import APIAbuseDetectionEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    return APIAbuseDetectionEngine(db_path=str(tmp_path / "aad.db"))


ORG = "org-aad-test"
ORG2 = "org-aad-other"


def _endpoint(overrides=None):
    base = {"path": "/api/v1/users", "method": "GET", "service_name": "user-service"}
    if overrides:
        base.update(overrides)
    return base


def _incident(endpoint_id, overrides=None):
    base = {
        "endpoint_id": endpoint_id,
        "abuse_type": "scraping",
        "severity": "medium",
        "request_count": 500,
    }
    if overrides:
        base.update(overrides)
    return base


def _rule(overrides=None):
    base = {"rule_name": "Rate limit rule", "rule_type": "rate_limit", "action": "block", "threshold": 100.0}
    if overrides:
        base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Endpoint Registration
# ---------------------------------------------------------------------------

class TestRegisterEndpoint:
    def test_returns_dict_with_id(self, engine):
        result = engine.register_endpoint(ORG, _endpoint())
        assert "id" in result
        assert len(result["id"]) == 36

    def test_stores_path_and_method(self, engine):
        result = engine.register_endpoint(ORG, _endpoint({"path": "/api/v1/orders", "method": "POST"}))
        assert result["path"] == "/api/v1/orders"
        assert result["method"] == "POST"

    def test_defaults_status_monitored(self, engine):
        result = engine.register_endpoint(ORG, _endpoint())
        assert result["status"] == "monitored"

    def test_defaults_rate_limit_1000(self, engine):
        result = engine.register_endpoint(ORG, _endpoint())
        assert result["rate_limit"] == 1000

    def test_defaults_abuse_score_zero(self, engine):
        result = engine.register_endpoint(ORG, _endpoint())
        assert result["abuse_score"] == 0.0

    def test_all_valid_methods(self, engine):
        methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
        for i, m in enumerate(methods):
            result = engine.register_endpoint(ORG, _endpoint({"method": m, "path": f"/api/v{i}"}))
            assert result["method"] == m

    def test_invalid_method_raises(self, engine):
        with pytest.raises(ValueError, match="method"):
            engine.register_endpoint(ORG, _endpoint({"method": "CONNECT"}))

    def test_missing_path_raises(self, engine):
        with pytest.raises(ValueError, match="path"):
            engine.register_endpoint(ORG, {"method": "GET"})

    def test_custom_rate_limit_stored(self, engine):
        result = engine.register_endpoint(ORG, _endpoint({"rate_limit": 500}))
        assert result["rate_limit"] == 500

    def test_custom_abuse_score_stored(self, engine):
        result = engine.register_endpoint(ORG, _endpoint({"abuse_score": 42.5}))
        assert result["abuse_score"] == 42.5

    def test_status_blocked_stored(self, engine):
        result = engine.register_endpoint(ORG, _endpoint({"status": "blocked"}))
        assert result["status"] == "blocked"

    def test_invalid_status_raises(self, engine):
        with pytest.raises(ValueError, match="status"):
            engine.register_endpoint(ORG, _endpoint({"status": "unknown"}))


# ---------------------------------------------------------------------------
# Endpoint Listing and Get
# ---------------------------------------------------------------------------

class TestListAndGetEndpoint:
    def test_list_returns_all_for_org(self, engine):
        engine.register_endpoint(ORG, _endpoint({"path": "/a"}))
        engine.register_endpoint(ORG, _endpoint({"path": "/b"}))
        results = engine.list_endpoints(ORG)
        assert len(results) == 2

    def test_list_filter_by_service_name(self, engine):
        engine.register_endpoint(ORG, _endpoint({"path": "/a", "service_name": "auth"}))
        engine.register_endpoint(ORG, _endpoint({"path": "/b", "service_name": "payment"}))
        results = engine.list_endpoints(ORG, service_name="auth")
        assert len(results) == 1
        assert results[0]["service_name"] == "auth"

    def test_list_filter_by_status(self, engine):
        engine.register_endpoint(ORG, _endpoint({"path": "/a", "status": "monitored"}))
        engine.register_endpoint(ORG, _endpoint({"path": "/b", "status": "blocked"}))
        results = engine.list_endpoints(ORG, status="blocked")
        assert len(results) == 1
        assert results[0]["status"] == "blocked"

    def test_get_endpoint_returns_correct(self, engine):
        ep = engine.register_endpoint(ORG, _endpoint())
        fetched = engine.get_endpoint(ORG, ep["id"])
        assert fetched["id"] == ep["id"]

    def test_get_endpoint_wrong_org_returns_none(self, engine):
        ep = engine.register_endpoint(ORG, _endpoint())
        result = engine.get_endpoint(ORG2, ep["id"])
        assert result is None

    def test_get_endpoint_not_found_returns_none(self, engine):
        result = engine.get_endpoint(ORG, "nonexistent-id")
        assert result is None


# ---------------------------------------------------------------------------
# Incident Recording
# ---------------------------------------------------------------------------

class TestRecordIncident:
    def test_returns_dict_with_id(self, engine):
        ep = engine.register_endpoint(ORG, _endpoint())
        result = engine.record_incident(ORG, _incident(ep["id"]))
        assert "id" in result
        assert len(result["id"]) == 36

    def test_defaults_status_open(self, engine):
        ep = engine.register_endpoint(ORG, _endpoint())
        result = engine.record_incident(ORG, _incident(ep["id"]))
        assert result["status"] == "open"

    def test_stores_abuse_type_and_severity(self, engine):
        ep = engine.register_endpoint(ORG, _endpoint())
        result = engine.record_incident(ORG, _incident(ep["id"], {
            "abuse_type": "credential_stuffing", "severity": "critical"
        }))
        assert result["abuse_type"] == "credential_stuffing"
        assert result["severity"] == "critical"

    def test_all_valid_abuse_types(self, engine):
        ep = engine.register_endpoint(ORG, _endpoint())
        types = [
            "credential_stuffing", "scraping", "dos", "parameter_tampering",
            "bola", "broken_auth", "rate_limit_abuse", "bot_traffic", "data_harvesting",
        ]
        for at in types:
            result = engine.record_incident(ORG, _incident(ep["id"], {"abuse_type": at}))
            assert result["abuse_type"] == at

    def test_invalid_abuse_type_raises(self, engine):
        ep = engine.register_endpoint(ORG, _endpoint())
        with pytest.raises(ValueError, match="abuse_type"):
            engine.record_incident(ORG, _incident(ep["id"], {"abuse_type": "unknown_abuse"}))

    def test_invalid_severity_raises(self, engine):
        ep = engine.register_endpoint(ORG, _endpoint())
        with pytest.raises(ValueError, match="severity"):
            engine.record_incident(ORG, _incident(ep["id"], {"severity": "extreme"}))

    def test_missing_endpoint_id_raises(self, engine):
        with pytest.raises(ValueError, match="endpoint_id"):
            engine.record_incident(ORG, {"abuse_type": "scraping", "severity": "low"})

    def test_endpoint_cross_org_raises(self, engine):
        ep = engine.register_endpoint(ORG, _endpoint())
        with pytest.raises(ValueError):
            engine.record_incident(ORG2, _incident(ep["id"]))

    def test_blocked_flag_stored(self, engine):
        ep = engine.register_endpoint(ORG, _endpoint())
        result = engine.record_incident(ORG, _incident(ep["id"], {"blocked": True}))
        assert result["blocked"] in (1, True)

    def test_source_ip_stored(self, engine):
        ep = engine.register_endpoint(ORG, _endpoint())
        result = engine.record_incident(ORG, _incident(ep["id"], {"source_ip": "192.168.1.1"}))
        assert result["source_ip"] == "192.168.1.1"

    def test_request_count_stored(self, engine):
        ep = engine.register_endpoint(ORG, _endpoint())
        result = engine.record_incident(ORG, _incident(ep["id"], {"request_count": 9999}))
        assert result["request_count"] == 9999


# ---------------------------------------------------------------------------
# Incident Listing and Status Update
# ---------------------------------------------------------------------------

class TestListAndUpdateIncident:
    def test_list_returns_all_incidents(self, engine):
        ep = engine.register_endpoint(ORG, _endpoint())
        engine.record_incident(ORG, _incident(ep["id"]))
        engine.record_incident(ORG, _incident(ep["id"], {"abuse_type": "dos"}))
        results = engine.list_incidents(ORG)
        assert len(results) == 2

    def test_list_filter_by_endpoint_id(self, engine):
        ep1 = engine.register_endpoint(ORG, _endpoint({"path": "/a"}))
        ep2 = engine.register_endpoint(ORG, _endpoint({"path": "/b"}))
        engine.record_incident(ORG, _incident(ep1["id"]))
        engine.record_incident(ORG, _incident(ep2["id"]))
        results = engine.list_incidents(ORG, endpoint_id=ep1["id"])
        assert len(results) == 1
        assert results[0]["endpoint_id"] == ep1["id"]

    def test_list_filter_by_abuse_type(self, engine):
        ep = engine.register_endpoint(ORG, _endpoint())
        engine.record_incident(ORG, _incident(ep["id"], {"abuse_type": "scraping"}))
        engine.record_incident(ORG, _incident(ep["id"], {"abuse_type": "dos"}))
        results = engine.list_incidents(ORG, abuse_type="scraping")
        assert len(results) == 1
        assert results[0]["abuse_type"] == "scraping"

    def test_list_filter_by_status(self, engine):
        ep = engine.register_endpoint(ORG, _endpoint())
        i = engine.record_incident(ORG, _incident(ep["id"]))
        engine.update_incident_status(ORG, i["id"], "resolved")
        open_inc = engine.list_incidents(ORG, status="open")
        resolved_inc = engine.list_incidents(ORG, status="resolved")
        assert len(open_inc) == 0
        assert len(resolved_inc) == 1

    def test_update_incident_status_all_valid(self, engine):
        ep = engine.register_endpoint(ORG, _endpoint())
        for status in ["investigating", "resolved", "false_positive", "open"]:
            i = engine.record_incident(ORG, _incident(ep["id"]))
            result = engine.update_incident_status(ORG, i["id"], status)
            assert result["status"] == status

    def test_update_incident_status_invalid_raises(self, engine):
        ep = engine.register_endpoint(ORG, _endpoint())
        i = engine.record_incident(ORG, _incident(ep["id"]))
        with pytest.raises(ValueError, match="status"):
            engine.update_incident_status(ORG, i["id"], "closed")

    def test_update_incident_wrong_org_raises(self, engine):
        ep = engine.register_endpoint(ORG, _endpoint())
        i = engine.record_incident(ORG, _incident(ep["id"]))
        with pytest.raises(ValueError):
            engine.update_incident_status(ORG2, i["id"], "resolved")


# ---------------------------------------------------------------------------
# Rule Management
# ---------------------------------------------------------------------------

class TestRules:
    def test_create_rule_returns_dict(self, engine):
        result = engine.create_rule(ORG, _rule())
        assert "id" in result
        assert len(result["id"]) == 36

    def test_create_rule_defaults_enabled_true(self, engine):
        result = engine.create_rule(ORG, _rule())
        assert result["enabled"] is True

    def test_create_rule_enabled_false(self, engine):
        result = engine.create_rule(ORG, _rule({"enabled": False}))
        assert result["enabled"] is False

    def test_create_rule_all_valid_types(self, engine):
        types = ["rate_limit", "ip_block", "geo_block", "user_agent", "pattern_match", "anomaly"]
        for i, rt in enumerate(types):
            result = engine.create_rule(ORG, _rule({"rule_type": rt, "rule_name": f"Rule-{i}"}))
            assert result["rule_type"] == rt

    def test_create_rule_invalid_type_raises(self, engine):
        with pytest.raises(ValueError, match="rule_type"):
            engine.create_rule(ORG, _rule({"rule_type": "magic"}))

    def test_create_rule_all_valid_actions(self, engine):
        actions = ["block", "alert", "throttle", "log"]
        for i, a in enumerate(actions):
            result = engine.create_rule(ORG, _rule({"action": a, "rule_name": f"Rule-{i}"}))
            assert result["action"] == a

    def test_create_rule_invalid_action_raises(self, engine):
        with pytest.raises(ValueError, match="action"):
            engine.create_rule(ORG, _rule({"action": "quarantine"}))

    def test_missing_rule_name_raises(self, engine):
        with pytest.raises(ValueError, match="rule_name"):
            engine.create_rule(ORG, {"rule_type": "rate_limit", "action": "block"})

    def test_list_rules_filter_by_type(self, engine):
        engine.create_rule(ORG, _rule({"rule_type": "rate_limit", "rule_name": "R1"}))
        engine.create_rule(ORG, _rule({"rule_type": "ip_block", "rule_name": "R2"}))
        results = engine.list_rules(ORG, rule_type="rate_limit")
        assert len(results) == 1
        assert results[0]["rule_type"] == "rate_limit"

    def test_list_rules_filter_by_enabled(self, engine):
        engine.create_rule(ORG, _rule({"rule_name": "Active", "enabled": True}))
        engine.create_rule(ORG, _rule({"rule_name": "Inactive", "enabled": False}))
        active = engine.list_rules(ORG, enabled=True)
        inactive = engine.list_rules(ORG, enabled=False)
        assert len(active) == 1
        assert len(inactive) == 1
        assert active[0]["enabled"] is True
        assert inactive[0]["enabled"] is False

    def test_threshold_stored(self, engine):
        result = engine.create_rule(ORG, _rule({"threshold": 250.0}))
        assert result["threshold"] == 250.0


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

class TestAbuseStats:
    def test_total_endpoints_count(self, engine):
        engine.register_endpoint(ORG, _endpoint({"path": "/a"}))
        engine.register_endpoint(ORG, _endpoint({"path": "/b"}))
        stats = engine.get_abuse_stats(ORG)
        assert stats["total_endpoints"] == 2

    def test_monitored_and_blocked_endpoints(self, engine):
        engine.register_endpoint(ORG, _endpoint({"path": "/a", "status": "monitored"}))
        engine.register_endpoint(ORG, _endpoint({"path": "/b", "status": "blocked"}))
        engine.register_endpoint(ORG, _endpoint({"path": "/c", "status": "unmonitored"}))
        stats = engine.get_abuse_stats(ORG)
        assert stats["monitored_endpoints"] == 1
        assert stats["blocked_endpoints"] == 1

    def test_incident_totals(self, engine):
        ep = engine.register_endpoint(ORG, _endpoint())
        i1 = engine.record_incident(ORG, _incident(ep["id"], {"severity": "critical"}))
        engine.record_incident(ORG, _incident(ep["id"], {"abuse_type": "dos"}))
        engine.update_incident_status(ORG, i1["id"], "resolved")
        stats = engine.get_abuse_stats(ORG)
        assert stats["total_incidents"] == 2
        assert stats["open_incidents"] == 1
        assert stats["critical_incidents"] == 1

    def test_by_abuse_type_dict(self, engine):
        ep = engine.register_endpoint(ORG, _endpoint())
        engine.record_incident(ORG, _incident(ep["id"], {"abuse_type": "scraping"}))
        engine.record_incident(ORG, _incident(ep["id"], {"abuse_type": "scraping"}))
        engine.record_incident(ORG, _incident(ep["id"], {"abuse_type": "dos"}))
        stats = engine.get_abuse_stats(ORG)
        assert stats["by_abuse_type"]["scraping"] == 2
        assert stats["by_abuse_type"]["dos"] == 1

    def test_by_severity_dict(self, engine):
        ep = engine.register_endpoint(ORG, _endpoint())
        engine.record_incident(ORG, _incident(ep["id"], {"severity": "high"}))
        engine.record_incident(ORG, _incident(ep["id"], {"severity": "low"}))
        stats = engine.get_abuse_stats(ORG)
        assert stats["by_severity"]["high"] == 1
        assert stats["by_severity"]["low"] == 1

    def test_avg_abuse_score(self, engine):
        engine.register_endpoint(ORG, _endpoint({"path": "/a", "abuse_score": 20.0}))
        engine.register_endpoint(ORG, _endpoint({"path": "/b", "abuse_score": 80.0}))
        stats = engine.get_abuse_stats(ORG)
        assert stats["avg_abuse_score"] == 50.0

    def test_empty_org_stats(self, engine):
        stats = engine.get_abuse_stats("empty-org")
        assert stats["total_endpoints"] == 0
        assert stats["monitored_endpoints"] == 0
        assert stats["total_incidents"] == 0
        assert stats["avg_abuse_score"] == 0.0


# ---------------------------------------------------------------------------
# Org Isolation
# ---------------------------------------------------------------------------

class TestOrgIsolation:
    def test_endpoints_isolated_by_org(self, engine):
        engine.register_endpoint(ORG, _endpoint({"path": "/org1"}))
        engine.register_endpoint(ORG2, _endpoint({"path": "/org2"}))
        org1_eps = engine.list_endpoints(ORG)
        org2_eps = engine.list_endpoints(ORG2)
        assert len(org1_eps) == 1
        assert org1_eps[0]["path"] == "/org1"
        assert len(org2_eps) == 1
        assert org2_eps[0]["path"] == "/org2"

    def test_incidents_isolated_by_org(self, engine):
        ep1 = engine.register_endpoint(ORG, _endpoint({"path": "/a"}))
        ep2 = engine.register_endpoint(ORG2, _endpoint({"path": "/b"}))
        engine.record_incident(ORG, _incident(ep1["id"]))
        engine.record_incident(ORG, _incident(ep1["id"]))
        engine.record_incident(ORG2, _incident(ep2["id"]))
        assert len(engine.list_incidents(ORG)) == 2
        assert len(engine.list_incidents(ORG2)) == 1

    def test_rules_isolated_by_org(self, engine):
        engine.create_rule(ORG, _rule({"rule_name": "R1"}))
        engine.create_rule(ORG2, _rule({"rule_name": "R2"}))
        assert len(engine.list_rules(ORG)) == 1
        assert len(engine.list_rules(ORG2)) == 1

    def test_stats_isolated_by_org(self, engine):
        engine.register_endpoint(ORG, _endpoint({"path": "/a"}))
        engine.register_endpoint(ORG, _endpoint({"path": "/b"}))
        stats1 = engine.get_abuse_stats(ORG)
        stats2 = engine.get_abuse_stats(ORG2)
        assert stats1["total_endpoints"] == 2
        assert stats2["total_endpoints"] == 0
