"""Tests for APIGatewaySecurityEngine — 30+ tests covering all methods.

Tests use a temporary SQLite database to ensure isolation between runs.
"""

from __future__ import annotations

import pytest

from core.api_gateway_security_engine import APIGatewaySecurityEngine


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "api_gw_security_test.db")


@pytest.fixture
def engine(db_path):
    return APIGatewaySecurityEngine(db_path=db_path)


@pytest.fixture
def org():
    return "org-acme"


@pytest.fixture
def other_org():
    return "org-rival"


@pytest.fixture
def gateway(engine, org):
    return engine.register_gateway(org, {
        "name": "ACME Kong Gateway",
        "base_url": "https://api.acme.com",
        "gateway_type": "kong",
        "environment": "prod",
    })


@pytest.fixture
def api(engine, org, gateway):
    return engine.register_api(org, {
        "gateway_id": gateway["id"],
        "name": "Payments API",
        "version": "v2",
        "path_prefix": "/api/v2/payments",
        "auth_type": "jwt",
        "rate_limit_rps": 50,
    })


# ============================================================================
# register_gateway
# ============================================================================


class TestRegisterGateway:
    def test_returns_dict_with_id(self, engine, org):
        gw = engine.register_gateway(org, {
            "name": "Test GW",
            "base_url": "https://gw.test.com",
            "gateway_type": "nginx",
            "environment": "staging",
        })
        assert gw["id"]
        assert gw["org_id"] == org
        assert gw["name"] == "Test GW"
        assert gw["gateway_type"] == "nginx"
        assert gw["environment"] == "staging"

    def test_all_gateway_types_accepted(self, engine, org):
        for gt in ("kong", "apigee", "aws_api_gw", "nginx", "custom"):
            gw = engine.register_gateway(org, {
                "name": f"GW {gt}",
                "base_url": "https://gw.test.com",
                "gateway_type": gt,
                "environment": "dev",
            })
            assert gw["gateway_type"] == gt

    def test_all_environments_accepted(self, engine, org):
        for env in ("prod", "staging", "dev"):
            gw = engine.register_gateway(org, {
                "name": f"GW {env}",
                "base_url": "https://gw.test.com",
                "gateway_type": "custom",
                "environment": env,
            })
            assert gw["environment"] == env

    def test_missing_name_raises(self, engine, org):
        with pytest.raises(ValueError, match="name"):
            engine.register_gateway(org, {
                "base_url": "https://gw.test.com",
                "gateway_type": "kong",
                "environment": "prod",
            })

    def test_missing_base_url_raises(self, engine, org):
        with pytest.raises(ValueError, match="base_url"):
            engine.register_gateway(org, {
                "name": "No URL",
                "gateway_type": "kong",
                "environment": "prod",
            })

    def test_invalid_gateway_type_raises(self, engine, org):
        with pytest.raises(ValueError, match="gateway_type"):
            engine.register_gateway(org, {
                "name": "Bad GW",
                "base_url": "https://gw.test.com",
                "gateway_type": "traefik",
                "environment": "prod",
            })

    def test_invalid_environment_raises(self, engine, org):
        with pytest.raises(ValueError, match="environment"):
            engine.register_gateway(org, {
                "name": "Bad Env",
                "base_url": "https://gw.test.com",
                "gateway_type": "kong",
                "environment": "qa",
            })


# ============================================================================
# list_gateways
# ============================================================================


class TestListGateways:
    def test_empty_org_returns_empty_list(self, engine):
        assert engine.list_gateways("org-unknown") == []

    def test_returns_gateway_for_org(self, engine, org, gateway):
        gws = engine.list_gateways(org)
        assert len(gws) == 1
        assert gws[0]["id"] == gateway["id"]

    def test_tenant_isolation(self, engine, org, other_org, gateway):
        engine.register_gateway(other_org, {
            "name": "Other GW",
            "base_url": "https://other.com",
            "gateway_type": "custom",
            "environment": "dev",
        })
        assert len(engine.list_gateways(org)) == 1
        assert len(engine.list_gateways(other_org)) == 1

    def test_multiple_gateways_returned(self, engine, org):
        for i in range(3):
            engine.register_gateway(org, {
                "name": f"GW {i}",
                "base_url": f"https://gw{i}.test.com",
                "gateway_type": "nginx",
                "environment": "dev",
            })
        assert len(engine.list_gateways(org)) == 3


# ============================================================================
# register_api
# ============================================================================


class TestRegisterApi:
    def test_returns_api_with_id(self, engine, org, gateway):
        api = engine.register_api(org, {
            "gateway_id": gateway["id"],
            "name": "Orders API",
            "version": "v1",
            "path_prefix": "/api/v1/orders",
            "auth_type": "oauth2",
            "rate_limit_rps": 200,
        })
        assert api["id"]
        assert api["org_id"] == org
        assert api["gateway_id"] == gateway["id"]
        assert api["name"] == "Orders API"
        assert api["auth_type"] == "oauth2"
        assert api["rate_limit_rps"] == 200

    def test_all_auth_types_accepted(self, engine, org, gateway):
        for at in ("api_key", "oauth2", "jwt", "none"):
            api = engine.register_api(org, {
                "gateway_id": gateway["id"],
                "name": f"API {at}",
                "version": "v1",
                "path_prefix": f"/api/{at}",
                "auth_type": at,
                "rate_limit_rps": 100,
            })
            assert api["auth_type"] == at

    def test_missing_gateway_id_raises(self, engine, org):
        with pytest.raises(ValueError, match="gateway_id"):
            engine.register_api(org, {
                "name": "No GW",
                "version": "v1",
                "path_prefix": "/api/test",
                "auth_type": "jwt",
                "rate_limit_rps": 100,
            })

    def test_missing_name_raises(self, engine, org, gateway):
        with pytest.raises(ValueError, match="name"):
            engine.register_api(org, {
                "gateway_id": gateway["id"],
                "version": "v1",
                "path_prefix": "/api/test",
                "auth_type": "jwt",
                "rate_limit_rps": 100,
            })

    def test_missing_path_prefix_raises(self, engine, org, gateway):
        with pytest.raises(ValueError, match="path_prefix"):
            engine.register_api(org, {
                "gateway_id": gateway["id"],
                "name": "No Path",
                "version": "v1",
                "path_prefix": "",
                "auth_type": "jwt",
                "rate_limit_rps": 100,
            })

    def test_invalid_auth_type_raises(self, engine, org, gateway):
        with pytest.raises(ValueError, match="auth_type"):
            engine.register_api(org, {
                "gateway_id": gateway["id"],
                "name": "Bad Auth",
                "version": "v1",
                "path_prefix": "/api/bad",
                "auth_type": "saml",
                "rate_limit_rps": 100,
            })

    def test_zero_rate_limit_raises(self, engine, org, gateway):
        with pytest.raises(ValueError, match="rate_limit_rps"):
            engine.register_api(org, {
                "gateway_id": gateway["id"],
                "name": "Zero Rate",
                "version": "v1",
                "path_prefix": "/api/zero",
                "auth_type": "jwt",
                "rate_limit_rps": 0,
            })


# ============================================================================
# list_apis
# ============================================================================


class TestListApis:
    def test_empty_org_returns_empty_list(self, engine):
        assert engine.list_apis("org-unknown") == []

    def test_returns_api_for_org(self, engine, org, api):
        apis = engine.list_apis(org)
        assert len(apis) == 1
        assert apis[0]["id"] == api["id"]

    def test_filter_by_gateway_id(self, engine, org, gateway, api):
        gw2 = engine.register_gateway(org, {
            "name": "GW2",
            "base_url": "https://gw2.test.com",
            "gateway_type": "apigee",
            "environment": "staging",
        })
        engine.register_api(org, {
            "gateway_id": gw2["id"],
            "name": "Other API",
            "version": "v1",
            "path_prefix": "/api/v1/other",
            "auth_type": "api_key",
            "rate_limit_rps": 100,
        })
        apis = engine.list_apis(org, gateway_id=gateway["id"])
        assert len(apis) == 1
        assert apis[0]["gateway_id"] == gateway["id"]

    def test_tenant_isolation(self, engine, org, other_org, api):
        assert engine.list_apis(other_org) == []


# ============================================================================
# record_security_event
# ============================================================================


class TestRecordSecurityEvent:
    def test_returns_event_with_id(self, engine, org, api):
        evt = engine.record_security_event(org, {
            "api_id": api["id"],
            "event_type": "auth_failure",
            "source_ip": "192.168.1.100",
            "request_path": "/api/v2/payments/charge",
            "severity": "high",
        })
        assert evt["id"]
        assert evt["event_type"] == "auth_failure"
        assert evt["source_ip"] == "192.168.1.100"
        assert evt["severity"] == "high"

    def test_all_event_types_accepted(self, engine, org, api):
        for et in ("auth_failure", "rate_exceeded", "injection", "schema_violation", "bot"):
            evt = engine.record_security_event(org, {
                "api_id": api["id"],
                "event_type": et,
                "source_ip": "10.0.0.1",
                "request_path": "/path",
                "severity": "medium",
            })
            assert evt["event_type"] == et

    def test_all_severities_accepted(self, engine, org, api):
        for sev in ("low", "medium", "high", "critical"):
            evt = engine.record_security_event(org, {
                "api_id": api["id"],
                "event_type": "bot",
                "source_ip": "10.0.0.2",
                "request_path": "/bot",
                "severity": sev,
            })
            assert evt["severity"] == sev

    def test_missing_api_id_raises(self, engine, org):
        with pytest.raises(ValueError, match="api_id"):
            engine.record_security_event(org, {
                "event_type": "auth_failure",
                "source_ip": "1.2.3.4",
                "request_path": "/path",
                "severity": "medium",
            })

    def test_invalid_event_type_raises(self, engine, org, api):
        with pytest.raises(ValueError, match="event_type"):
            engine.record_security_event(org, {
                "api_id": api["id"],
                "event_type": "xss",
                "source_ip": "1.2.3.4",
                "request_path": "/path",
                "severity": "medium",
            })

    def test_missing_source_ip_raises(self, engine, org, api):
        with pytest.raises(ValueError, match="source_ip"):
            engine.record_security_event(org, {
                "api_id": api["id"],
                "event_type": "injection",
                "source_ip": "",
                "request_path": "/path",
                "severity": "high",
            })

    def test_invalid_severity_raises(self, engine, org, api):
        with pytest.raises(ValueError, match="severity"):
            engine.record_security_event(org, {
                "api_id": api["id"],
                "event_type": "bot",
                "source_ip": "1.2.3.4",
                "request_path": "/path",
                "severity": "extreme",
            })


# ============================================================================
# list_security_events
# ============================================================================


class TestListSecurityEvents:
    def _make_event(self, engine, org, api, event_type="bot", severity="low"):
        return engine.record_security_event(org, {
            "api_id": api["id"],
            "event_type": event_type,
            "source_ip": "1.2.3.4",
            "request_path": "/test",
            "severity": severity,
        })

    def test_returns_all_events(self, engine, org, api):
        self._make_event(engine, org, api)
        self._make_event(engine, org, api)
        events = engine.list_security_events(org)
        assert len(events) == 2

    def test_filter_by_event_type(self, engine, org, api):
        self._make_event(engine, org, api, event_type="auth_failure")
        self._make_event(engine, org, api, event_type="bot")
        auth_events = engine.list_security_events(org, event_type="auth_failure")
        assert all(e["event_type"] == "auth_failure" for e in auth_events)
        assert len(auth_events) == 1

    def test_filter_by_severity(self, engine, org, api):
        self._make_event(engine, org, api, severity="critical")
        self._make_event(engine, org, api, severity="low")
        critical = engine.list_security_events(org, severity="critical")
        assert all(e["severity"] == "critical" for e in critical)
        assert len(critical) == 1

    def test_tenant_isolation(self, engine, org, other_org, api):
        self._make_event(engine, org, api)
        assert engine.list_security_events(other_org) == []

    def test_limit_respected(self, engine, org, api):
        for _ in range(20):
            self._make_event(engine, org, api)
        assert len(engine.list_security_events(org, limit=10)) == 10


# ============================================================================
# get_api_threat_summary
# ============================================================================


class TestGetApiThreatSummary:
    def test_empty_api_summary(self, engine, org, api):
        summary = engine.get_api_threat_summary(org, api["id"])
        assert summary["api_id"] == api["id"]
        assert summary["events_by_type"] == {}
        assert summary["top_attacking_ips"] == []
        assert summary["violation_rate"] == 0.0
        assert summary["total_events"] == 0

    def test_events_by_type_populated(self, engine, org, api):
        for et in ("auth_failure", "auth_failure", "bot"):
            engine.record_security_event(org, {
                "api_id": api["id"],
                "event_type": et,
                "source_ip": "5.6.7.8",
                "request_path": "/path",
                "severity": "medium",
            })
        summary = engine.get_api_threat_summary(org, api["id"])
        assert summary["events_by_type"]["auth_failure"] == 2
        assert summary["events_by_type"]["bot"] == 1

    def test_top_attacking_ips_populated(self, engine, org, api):
        for ip in ("1.1.1.1", "1.1.1.1", "2.2.2.2"):
            engine.record_security_event(org, {
                "api_id": api["id"],
                "event_type": "injection",
                "source_ip": ip,
                "request_path": "/inject",
                "severity": "high",
            })
        summary = engine.get_api_threat_summary(org, api["id"])
        ips = [entry["ip"] for entry in summary["top_attacking_ips"]]
        assert "1.1.1.1" in ips

    def test_total_events_count(self, engine, org, api):
        for _ in range(5):
            engine.record_security_event(org, {
                "api_id": api["id"],
                "event_type": "rate_exceeded",
                "source_ip": "3.3.3.3",
                "request_path": "/rate",
                "severity": "low",
            })
        summary = engine.get_api_threat_summary(org, api["id"])
        assert summary["total_events"] == 5

    def test_tenant_isolation(self, engine, org, other_org, api):
        engine.record_security_event(org, {
            "api_id": api["id"],
            "event_type": "bot",
            "source_ip": "9.9.9.9",
            "request_path": "/bot",
            "severity": "low",
        })
        # Other org querying same api_id sees no events (org_id filter)
        summary = engine.get_api_threat_summary(other_org, api["id"])
        assert summary["total_events"] == 0


# ============================================================================
# get_gateway_stats
# ============================================================================


class TestGetGatewayStats:
    def test_empty_org_returns_zeros(self, engine):
        stats = engine.get_gateway_stats("org-empty")
        assert stats["gateways"] == 0
        assert stats["apis"] == 0
        assert stats["events_24h"] == 0
        assert stats["by_severity"] == {}

    def test_stats_with_data(self, engine, org, gateway, api):
        for sev in ("high", "high", "low"):
            engine.record_security_event(org, {
                "api_id": api["id"],
                "event_type": "auth_failure",
                "source_ip": "1.2.3.4",
                "request_path": "/path",
                "severity": sev,
            })
        stats = engine.get_gateway_stats(org)
        assert stats["gateways"] == 1
        assert stats["apis"] == 1
        assert stats["events_24h"] == 3
        assert stats["by_severity"]["high"] == 2
        assert stats["by_severity"]["low"] == 1

    def test_tenant_isolation(self, engine, org, other_org, gateway, api):
        engine.record_security_event(org, {
            "api_id": api["id"],
            "event_type": "bot",
            "source_ip": "7.7.7.7",
            "request_path": "/bot",
            "severity": "medium",
        })
        stats = engine.get_gateway_stats(other_org)
        assert stats["gateways"] == 0
        assert stats["apis"] == 0
        assert stats["events_24h"] == 0
