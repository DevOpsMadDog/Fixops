"""Tests for APIInventoryEngine — 35+ tests covering all major paths."""

from __future__ import annotations

import pytest


@pytest.fixture
def engine(tmp_path):
    from core.api_inventory_engine import APIInventoryEngine
    return APIInventoryEngine(db_path=str(tmp_path / "api_inv.db"))


ORG = "test-org-apiinv"
ORG2 = "other-org-apiinv"


# ---------------------------------------------------------------------------
# API registration
# ---------------------------------------------------------------------------

def test_register_api_basic(engine):
    api = engine.register_api(ORG, {
        "api_name": "User Service",
        "api_type": "rest",
        "auth_type": "jwt",
    })
    assert api["id"]
    assert api["api_name"] == "User Service"
    assert api["api_type"] == "rest"
    assert api["auth_type"] == "jwt"
    assert api["org_id"] == ORG
    assert api["api_status"] == "active"
    assert api["endpoint_count"] == 0
    assert api["last_scanned"] is None


def test_register_api_all_types(engine):
    for api_type in ("rest", "graphql", "grpc", "soap", "websocket", "event"):
        api = engine.register_api(ORG, {
            "api_name": f"API-{api_type}",
            "api_type": api_type,
        })
        assert api["api_type"] == api_type


def test_register_api_all_auth_types(engine):
    for auth_type in ("api_key", "oauth2", "jwt", "basic", "none", "mutual_tls"):
        api = engine.register_api(ORG, {
            "api_name": f"API-{auth_type}",
            "api_type": "rest",
            "auth_type": auth_type,
        })
        assert api["auth_type"] == auth_type


def test_register_api_missing_name(engine):
    with pytest.raises(ValueError, match="api_name"):
        engine.register_api(ORG, {"api_type": "rest"})


def test_register_api_empty_name(engine):
    with pytest.raises(ValueError, match="api_name"):
        engine.register_api(ORG, {"api_name": "  ", "api_type": "rest"})


def test_register_api_invalid_type(engine):
    with pytest.raises(ValueError, match="api_type"):
        engine.register_api(ORG, {"api_name": "X", "api_type": "rpc_unknown"})


def test_register_api_invalid_auth_type(engine):
    with pytest.raises(ValueError, match="auth_type"):
        engine.register_api(ORG, {"api_name": "X", "api_type": "rest", "auth_type": "magic_token"})


def test_register_api_with_all_fields(engine):
    api = engine.register_api(ORG, {
        "api_name": "Payment API",
        "api_type": "rest",
        "version": "v2",
        "base_url": "https://api.example.com/v2",
        "auth_type": "oauth2",
        "owner_team": "payments",
        "documentation_url": "https://docs.example.com",
        "risk_level": "high",
    })
    assert api["version"] == "v2"
    assert api["base_url"] == "https://api.example.com/v2"
    assert api["owner_team"] == "payments"
    assert api["documentation_url"] == "https://docs.example.com"


def test_register_api_default_status_active(engine):
    api = engine.register_api(ORG, {"api_name": "MyAPI", "api_type": "rest"})
    assert api["api_status"] == "active"


# ---------------------------------------------------------------------------
# List and get APIs
# ---------------------------------------------------------------------------

def test_list_apis_empty(engine):
    assert engine.list_apis(ORG) == []


def test_list_apis_multiple(engine):
    engine.register_api(ORG, {"api_name": "A", "api_type": "rest"})
    engine.register_api(ORG, {"api_name": "B", "api_type": "graphql"})
    assert len(engine.list_apis(ORG)) == 2


def test_list_apis_filter_by_type(engine):
    engine.register_api(ORG, {"api_name": "REST", "api_type": "rest"})
    engine.register_api(ORG, {"api_name": "GQL", "api_type": "graphql"})
    rest_apis = engine.list_apis(ORG, api_type="rest")
    assert len(rest_apis) == 1
    assert rest_apis[0]["api_type"] == "rest"


def test_list_apis_filter_by_status(engine):
    engine.register_api(ORG, {"api_name": "Active", "api_type": "rest"})
    # All start as active; filter deprecated should be empty
    dep = engine.list_apis(ORG, api_status="deprecated")
    assert len(dep) == 0
    active = engine.list_apis(ORG, api_status="active")
    assert len(active) == 1


def test_list_apis_org_isolation(engine):
    engine.register_api(ORG, {"api_name": "A", "api_type": "rest"})
    assert engine.list_apis(ORG2) == []


def test_get_api_found(engine):
    api = engine.register_api(ORG, {"api_name": "Search API", "api_type": "rest"})
    result = engine.get_api(ORG, api["id"])
    assert result is not None
    assert result["id"] == api["id"]
    assert result["api_name"] == "Search API"


def test_get_api_not_found(engine):
    assert engine.get_api(ORG, "nonexistent-id") is None


def test_get_api_wrong_org(engine):
    api = engine.register_api(ORG, {"api_name": "Secret", "api_type": "grpc"})
    assert engine.get_api(ORG2, api["id"]) is None


# ---------------------------------------------------------------------------
# Status update
# ---------------------------------------------------------------------------

def test_update_api_status_to_deprecated(engine):
    api = engine.register_api(ORG, {"api_name": "Old API", "api_type": "rest"})
    updated = engine.update_api_status(ORG, api["id"], "deprecated")
    assert updated is not None
    assert updated["api_status"] == "deprecated"


def test_update_api_status_all_valid(engine):
    api = engine.register_api(ORG, {"api_name": "API", "api_type": "rest"})
    for status in ("deprecated", "retired", "beta", "internal", "active"):
        result = engine.update_api_status(ORG, api["id"], status)
        assert result["api_status"] == status


def test_update_api_status_invalid(engine):
    api = engine.register_api(ORG, {"api_name": "API", "api_type": "rest"})
    with pytest.raises(ValueError, match="api_status"):
        engine.update_api_status(ORG, api["id"], "unknown_status")


def test_update_api_status_not_found(engine):
    result = engine.update_api_status(ORG, "nonexistent-id", "deprecated")
    assert result is None


# ---------------------------------------------------------------------------
# Endpoints — add and list, endpoint_count increment
# ---------------------------------------------------------------------------

def test_add_endpoint_basic(engine):
    api = engine.register_api(ORG, {"api_name": "User API", "api_type": "rest"})
    ep = engine.add_endpoint(ORG, api["id"], {
        "method": "GET",
        "path": "/users",
        "description": "List all users",
        "is_authenticated": True,
        "is_documented": True,
        "risk_level": "low",
    })
    assert ep["id"]
    assert ep["api_id"] == api["id"]
    assert ep["method"] == "GET"
    assert ep["path"] == "/users"
    assert ep["is_authenticated"] == 1
    assert ep["is_documented"] == 1
    assert ep["risk_level"] == "low"


def test_add_endpoint_increments_count(engine):
    api = engine.register_api(ORG, {"api_name": "API", "api_type": "rest"})
    assert api["endpoint_count"] == 0
    engine.add_endpoint(ORG, api["id"], {"method": "GET", "path": "/a"})
    engine.add_endpoint(ORG, api["id"], {"method": "POST", "path": "/b"})
    updated = engine.get_api(ORG, api["id"])
    assert updated["endpoint_count"] == 2


def test_add_endpoint_all_methods(engine):
    api = engine.register_api(ORG, {"api_name": "API", "api_type": "rest"})
    for method in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
        ep = engine.add_endpoint(ORG, api["id"], {"method": method, "path": f"/{method.lower()}"})
        assert ep["method"] == method


def test_add_endpoint_invalid_method(engine):
    api = engine.register_api(ORG, {"api_name": "API", "api_type": "rest"})
    with pytest.raises(ValueError, match="method"):
        engine.add_endpoint(ORG, api["id"], {"method": "FETCH"})


def test_add_endpoint_invalid_risk_level(engine):
    api = engine.register_api(ORG, {"api_name": "API", "api_type": "rest"})
    with pytest.raises(ValueError, match="risk_level"):
        engine.add_endpoint(ORG, api["id"], {"method": "GET", "risk_level": "extreme"})


def test_add_endpoint_unauthenticated(engine):
    api = engine.register_api(ORG, {"api_name": "API", "api_type": "rest"})
    ep = engine.add_endpoint(ORG, api["id"], {
        "method": "GET",
        "path": "/public",
        "is_authenticated": False,
        "is_documented": False,
    })
    assert ep["is_authenticated"] == 0
    assert ep["is_documented"] == 0


def test_list_endpoints_filter_by_api(engine):
    api1 = engine.register_api(ORG, {"api_name": "API1", "api_type": "rest"})
    api2 = engine.register_api(ORG, {"api_name": "API2", "api_type": "graphql"})
    engine.add_endpoint(ORG, api1["id"], {"method": "GET", "path": "/a"})
    engine.add_endpoint(ORG, api2["id"], {"method": "POST", "path": "/b"})
    api1_eps = engine.list_endpoints(ORG, api_id=api1["id"])
    assert len(api1_eps) == 1
    assert api1_eps[0]["api_id"] == api1["id"]


def test_list_endpoints_filter_by_method(engine):
    api = engine.register_api(ORG, {"api_name": "API", "api_type": "rest"})
    engine.add_endpoint(ORG, api["id"], {"method": "GET", "path": "/get"})
    engine.add_endpoint(ORG, api["id"], {"method": "POST", "path": "/post"})
    gets = engine.list_endpoints(ORG, method="GET")
    assert len(gets) == 1
    assert gets[0]["method"] == "GET"


def test_list_endpoints_filter_by_risk_level(engine):
    api = engine.register_api(ORG, {"api_name": "API", "api_type": "rest"})
    engine.add_endpoint(ORG, api["id"], {"method": "GET", "path": "/safe", "risk_level": "none"})
    engine.add_endpoint(ORG, api["id"], {"method": "DELETE", "path": "/danger", "risk_level": "critical"})
    crits = engine.list_endpoints(ORG, risk_level="critical")
    assert len(crits) == 1
    assert crits[0]["risk_level"] == "critical"


def test_list_endpoints_org_isolation(engine):
    api = engine.register_api(ORG, {"api_name": "API", "api_type": "rest"})
    engine.add_endpoint(ORG, api["id"], {"method": "GET", "path": "/a"})
    assert engine.list_endpoints(ORG2) == []


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def test_get_api_stats_empty(engine):
    stats = engine.get_api_stats(ORG)
    assert stats["total_apis"] == 0
    assert stats["active_apis"] == 0
    assert stats["deprecated_apis"] == 0
    assert stats["total_endpoints"] == 0
    assert stats["unauthenticated_endpoints"] == 0
    assert stats["undocumented_endpoints"] == 0
    assert stats["by_type"] == {}


def test_get_api_stats_total_apis(engine):
    engine.register_api(ORG, {"api_name": "A", "api_type": "rest"})
    engine.register_api(ORG, {"api_name": "B", "api_type": "graphql"})
    stats = engine.get_api_stats(ORG)
    assert stats["total_apis"] == 2
    assert stats["active_apis"] == 2


def test_get_api_stats_deprecated(engine):
    api = engine.register_api(ORG, {"api_name": "Old", "api_type": "rest"})
    engine.update_api_status(ORG, api["id"], "deprecated")
    stats = engine.get_api_stats(ORG)
    assert stats["deprecated_apis"] == 1
    assert stats["active_apis"] == 0


def test_get_api_stats_endpoints(engine):
    api = engine.register_api(ORG, {"api_name": "API", "api_type": "rest"})
    engine.add_endpoint(ORG, api["id"], {"method": "GET", "path": "/a"})
    engine.add_endpoint(ORG, api["id"], {"method": "POST", "path": "/b"})
    stats = engine.get_api_stats(ORG)
    assert stats["total_endpoints"] == 2


def test_get_api_stats_unauthenticated_endpoints(engine):
    api = engine.register_api(ORG, {"api_name": "API", "api_type": "rest"})
    engine.add_endpoint(ORG, api["id"], {"method": "GET", "path": "/auth", "is_authenticated": True})
    engine.add_endpoint(ORG, api["id"], {"method": "GET", "path": "/pub", "is_authenticated": False})
    engine.add_endpoint(ORG, api["id"], {"method": "GET", "path": "/pub2", "is_authenticated": False})
    stats = engine.get_api_stats(ORG)
    assert stats["unauthenticated_endpoints"] == 2


def test_get_api_stats_undocumented_endpoints(engine):
    api = engine.register_api(ORG, {"api_name": "API", "api_type": "rest"})
    engine.add_endpoint(ORG, api["id"], {"method": "GET", "path": "/doc", "is_documented": True})
    engine.add_endpoint(ORG, api["id"], {"method": "POST", "path": "/nodoc", "is_documented": False})
    stats = engine.get_api_stats(ORG)
    assert stats["undocumented_endpoints"] == 1


def test_get_api_stats_by_type(engine):
    engine.register_api(ORG, {"api_name": "R1", "api_type": "rest"})
    engine.register_api(ORG, {"api_name": "R2", "api_type": "rest"})
    engine.register_api(ORG, {"api_name": "G1", "api_type": "graphql"})
    stats = engine.get_api_stats(ORG)
    assert stats["by_type"]["rest"] == 2
    assert stats["by_type"]["graphql"] == 1


def test_stats_org_isolation(engine):
    engine.register_api(ORG, {"api_name": "A", "api_type": "rest"})
    stats = engine.get_api_stats(ORG2)
    assert stats["total_apis"] == 0
    assert stats["by_type"] == {}
