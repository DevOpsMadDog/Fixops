"""Tests for APIDiscoveryEngine — ~35 tests."""

from __future__ import annotations

import pytest
from pathlib import Path

from core.api_discovery_engine import APIDiscoveryEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    return APIDiscoveryEngine(db_path=str(tmp_path / "api_disc.db"))


@pytest.fixture
def endpoint(engine):
    return engine.register_endpoint("org1", {
        "service_name": "user-service",
        "endpoint_path": "/api/v1/users",
        "http_method": "GET",
    })


# ---------------------------------------------------------------------------
# register_endpoint
# ---------------------------------------------------------------------------

class TestRegisterEndpoint:
    def test_basic_registration(self, engine):
        ep = engine.register_endpoint("org1", {
            "service_name": "auth-service",
            "endpoint_path": "/api/v1/login",
            "http_method": "POST",
        })
        assert ep["service_name"] == "auth-service"
        assert ep["endpoint_path"] == "/api/v1/login"
        assert ep["http_method"] == "POST"
        assert ep["auth_required"] == 1
        assert ep["is_documented"] == 0
        assert ep["is_shadow"] == 0
        assert ep["risk_level"] == "none"

    def test_missing_service_name_raises(self, engine):
        with pytest.raises(ValueError, match="service_name"):
            engine.register_endpoint("org1", {"endpoint_path": "/x", "http_method": "GET"})

    def test_missing_endpoint_path_raises(self, engine):
        with pytest.raises(ValueError, match="endpoint_path"):
            engine.register_endpoint("org1", {"service_name": "svc", "http_method": "GET"})

    def test_missing_http_method_raises(self, engine):
        with pytest.raises(ValueError, match="http_method"):
            engine.register_endpoint("org1", {"service_name": "svc", "endpoint_path": "/x", "http_method": ""})

    def test_invalid_http_method_raises(self, engine):
        with pytest.raises(ValueError, match="http_method"):
            engine.register_endpoint("org1", {
                "service_name": "svc", "endpoint_path": "/x", "http_method": "INVALID"
            })

    def test_all_valid_http_methods(self, engine):
        methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
        for method in methods:
            ep = engine.register_endpoint("org1", {
                "service_name": "svc",
                "endpoint_path": f"/x/{method.lower()}",
                "http_method": method,
            })
            assert ep["http_method"] == method

    def test_invalid_api_type_raises(self, engine):
        with pytest.raises(ValueError, match="api_type"):
            engine.register_endpoint("org1", {
                "service_name": "svc", "endpoint_path": "/x", "http_method": "GET",
                "api_type": "invalid"
            })

    def test_valid_api_types(self, engine):
        for api_type in ["rest", "graphql", "grpc", "websocket", "soap"]:
            ep = engine.register_endpoint("org1", {
                "service_name": "svc",
                "endpoint_path": f"/x/{api_type}",
                "http_method": "GET",
                "api_type": api_type,
            })
            assert ep["api_type"] == api_type

    def test_invalid_risk_level_raises(self, engine):
        with pytest.raises(ValueError, match="risk_level"):
            engine.register_endpoint("org1", {
                "service_name": "svc", "endpoint_path": "/x", "http_method": "GET",
                "risk_level": "extreme"
            })

    def test_auth_required_default_true(self, engine):
        ep = engine.register_endpoint("org1", {
            "service_name": "svc", "endpoint_path": "/x", "http_method": "GET"
        })
        assert ep["auth_required"] == 1

    def test_auth_required_false(self, engine):
        ep = engine.register_endpoint("org1", {
            "service_name": "svc", "endpoint_path": "/public", "http_method": "GET",
            "auth_required": False,
        })
        assert ep["auth_required"] == 0


# ---------------------------------------------------------------------------
# list_endpoints / get_endpoint
# ---------------------------------------------------------------------------

class TestListAndGetEndpoints:
    def test_list_all(self, engine, endpoint):
        result = engine.list_endpoints("org1")
        assert len(result) == 1

    def test_filter_by_service_name(self, engine):
        engine.register_endpoint("org1", {"service_name": "svc-a", "endpoint_path": "/a", "http_method": "GET"})
        engine.register_endpoint("org1", {"service_name": "svc-b", "endpoint_path": "/b", "http_method": "POST"})
        result = engine.list_endpoints("org1", service_name="svc-a")
        assert all(r["service_name"] == "svc-a" for r in result)

    def test_filter_by_is_shadow(self, engine):
        ep = engine.register_endpoint("org1", {"service_name": "svc", "endpoint_path": "/shadow", "http_method": "GET"})
        engine.mark_as_shadow("org1", ep["id"])
        engine.register_endpoint("org1", {"service_name": "svc", "endpoint_path": "/normal", "http_method": "GET"})
        result = engine.list_endpoints("org1", is_shadow=True)
        assert all(r["is_shadow"] == 1 for r in result)

    def test_filter_by_risk_level(self, engine):
        engine.register_endpoint("org1", {"service_name": "svc", "endpoint_path": "/low", "http_method": "GET", "risk_level": "low"})
        engine.register_endpoint("org1", {"service_name": "svc", "endpoint_path": "/high", "http_method": "GET", "risk_level": "high"})
        result = engine.list_endpoints("org1", risk_level="high")
        assert all(r["risk_level"] == "high" for r in result)

    def test_filter_by_api_type(self, engine):
        engine.register_endpoint("org1", {"service_name": "svc", "endpoint_path": "/rest", "http_method": "GET", "api_type": "rest"})
        engine.register_endpoint("org1", {"service_name": "svc", "endpoint_path": "/gql", "http_method": "POST", "api_type": "graphql"})
        result = engine.list_endpoints("org1", api_type="graphql")
        assert all(r["api_type"] == "graphql" for r in result)

    def test_get_endpoint_by_id(self, engine, endpoint):
        result = engine.get_endpoint("org1", endpoint["id"])
        assert result is not None
        assert result["id"] == endpoint["id"]

    def test_get_endpoint_wrong_org_returns_none(self, engine, endpoint):
        result = engine.get_endpoint("org2", endpoint["id"])
        assert result is None

    def test_get_endpoint_not_found_returns_none(self, engine):
        result = engine.get_endpoint("org1", "nonexistent-uuid")
        assert result is None

    def test_org_isolation(self, engine):
        engine.register_endpoint("org1", {"service_name": "svc", "endpoint_path": "/a", "http_method": "GET"})
        engine.register_endpoint("org2", {"service_name": "svc", "endpoint_path": "/b", "http_method": "GET"})
        assert len(engine.list_endpoints("org1")) == 1
        assert len(engine.list_endpoints("org2")) == 1


# ---------------------------------------------------------------------------
# mark_as_shadow / mark_as_documented
# ---------------------------------------------------------------------------

class TestMarkEndpoints:
    def test_mark_as_shadow_sets_is_shadow(self, engine, endpoint):
        result = engine.mark_as_shadow("org1", endpoint["id"])
        assert result["is_shadow"] == 1

    def test_mark_as_shadow_sets_risk_level_high(self, engine, endpoint):
        result = engine.mark_as_shadow("org1", endpoint["id"])
        assert result["risk_level"] == "high"

    def test_mark_as_shadow_not_found_raises(self, engine):
        with pytest.raises(KeyError):
            engine.mark_as_shadow("org1", "nonexistent")

    def test_mark_as_shadow_wrong_org_raises(self, engine, endpoint):
        with pytest.raises(KeyError):
            engine.mark_as_shadow("org2", endpoint["id"])

    def test_mark_as_documented_sets_flag(self, engine, endpoint):
        result = engine.mark_as_documented("org1", endpoint["id"])
        assert result["is_documented"] == 1

    def test_mark_as_documented_not_found_raises(self, engine):
        with pytest.raises(KeyError):
            engine.mark_as_documented("org1", "nonexistent")

    def test_mark_as_documented_wrong_org_raises(self, engine, endpoint):
        with pytest.raises(KeyError):
            engine.mark_as_documented("org2", endpoint["id"])


# ---------------------------------------------------------------------------
# create_scan / complete_scan
# ---------------------------------------------------------------------------

class TestScans:
    def test_create_scan(self, engine):
        scan = engine.create_scan("org1", {
            "scan_name": "Weekly Scan",
            "scan_target": "https://api.example.com",
            "scan_type": "passive",
        })
        assert scan["scan_name"] == "Weekly Scan"
        assert scan["status"] == "running"
        assert scan["endpoints_found"] == 0
        assert scan["shadow_apis_found"] == 0
        assert scan["completed_at"] is None

    def test_missing_scan_name_raises(self, engine):
        with pytest.raises(ValueError, match="scan_name"):
            engine.create_scan("org1", {"scan_target": "https://example.com"})

    def test_missing_scan_target_raises(self, engine):
        with pytest.raises(ValueError, match="scan_target"):
            engine.create_scan("org1", {"scan_name": "Scan"})

    def test_invalid_scan_type_raises(self, engine):
        with pytest.raises(ValueError, match="scan_type"):
            engine.create_scan("org1", {
                "scan_name": "Scan", "scan_target": "https://x.com", "scan_type": "invalid"
            })

    def test_valid_scan_types(self, engine):
        for st in ["passive", "active", "spider", "import"]:
            scan = engine.create_scan("org1", {
                "scan_name": f"Scan-{st}",
                "scan_target": "https://x.com",
                "scan_type": st,
            })
            assert scan["scan_type"] == st

    def test_complete_scan_updates_status(self, engine):
        scan = engine.create_scan("org1", {"scan_name": "S", "scan_target": "https://x.com"})
        result = engine.complete_scan("org1", scan["id"], {"endpoints_found": 42, "shadow_apis_found": 3})
        assert result["status"] == "completed"
        assert result["endpoints_found"] == 42
        assert result["shadow_apis_found"] == 3
        assert result["completed_at"] is not None

    def test_complete_scan_not_found_raises(self, engine):
        with pytest.raises(KeyError):
            engine.complete_scan("org1", "nonexistent", {})

    def test_complete_scan_wrong_org_raises(self, engine):
        scan = engine.create_scan("org1", {"scan_name": "S", "scan_target": "https://x.com"})
        with pytest.raises(KeyError):
            engine.complete_scan("org2", scan["id"], {})


# ---------------------------------------------------------------------------
# record_change / list_changes
# ---------------------------------------------------------------------------

class TestChanges:
    def test_record_change(self, engine, endpoint):
        change = engine.record_change("org1", {
            "endpoint_id": endpoint["id"],
            "change_type": "modified",
            "change_description": "Added new query param",
        })
        assert change["change_type"] == "modified"
        assert change["endpoint_id"] == endpoint["id"]

    def test_invalid_change_type_raises(self, engine, endpoint):
        with pytest.raises(ValueError, match="change_type"):
            engine.record_change("org1", {
                "endpoint_id": endpoint["id"],
                "change_type": "invalid",
            })

    def test_nonexistent_endpoint_raises(self, engine):
        with pytest.raises(ValueError, match="not found"):
            engine.record_change("org1", {
                "endpoint_id": "nonexistent",
                "change_type": "added",
            })

    def test_all_valid_change_types(self, engine, endpoint):
        for ct in ["added", "removed", "modified", "deprecated"]:
            change = engine.record_change("org1", {
                "endpoint_id": endpoint["id"],
                "change_type": ct,
            })
            assert change["change_type"] == ct

    def test_list_changes_filter_by_endpoint_id(self, engine, endpoint):
        ep2 = engine.register_endpoint("org1", {"service_name": "svc2", "endpoint_path": "/y", "http_method": "POST"})
        engine.record_change("org1", {"endpoint_id": endpoint["id"], "change_type": "modified"})
        engine.record_change("org1", {"endpoint_id": ep2["id"], "change_type": "added"})
        result = engine.list_changes("org1", endpoint_id=endpoint["id"])
        assert all(r["endpoint_id"] == endpoint["id"] for r in result)

    def test_list_changes_filter_by_change_type(self, engine, endpoint):
        engine.record_change("org1", {"endpoint_id": endpoint["id"], "change_type": "modified"})
        engine.record_change("org1", {"endpoint_id": endpoint["id"], "change_type": "deprecated"})
        result = engine.list_changes("org1", change_type="modified")
        assert all(r["change_type"] == "modified" for r in result)

    def test_list_changes_limit(self, engine, endpoint):
        for i in range(10):
            engine.record_change("org1", {"endpoint_id": endpoint["id"], "change_type": "modified"})
        result = engine.list_changes("org1", limit=5)
        assert len(result) == 5


# ---------------------------------------------------------------------------
# get_api_stats
# ---------------------------------------------------------------------------

class TestAPIStats:
    def test_empty_stats(self, engine):
        stats = engine.get_api_stats("org1")
        assert stats["total_endpoints"] == 0
        assert stats["shadow_apis"] == 0
        assert stats["documented_count"] == 0
        assert stats["undocumented_count"] == 0
        assert stats["by_service"] == {}
        assert stats["by_method"] == {}
        assert stats["unauthenticated_endpoints"] == 0
        assert stats["total_scans"] == 0
        assert stats["recent_changes"] == 0

    def test_totals(self, engine, endpoint):
        stats = engine.get_api_stats("org1")
        assert stats["total_endpoints"] == 1
        assert stats["undocumented_count"] == 1

    def test_shadow_apis_count(self, engine, endpoint):
        engine.mark_as_shadow("org1", endpoint["id"])
        stats = engine.get_api_stats("org1")
        assert stats["shadow_apis"] == 1

    def test_documented_count(self, engine, endpoint):
        engine.mark_as_documented("org1", endpoint["id"])
        stats = engine.get_api_stats("org1")
        assert stats["documented_count"] == 1
        assert stats["undocumented_count"] == 0

    def test_unauthenticated_endpoints(self, engine):
        engine.register_endpoint("org1", {"service_name": "svc", "endpoint_path": "/pub", "http_method": "GET", "auth_required": False})
        engine.register_endpoint("org1", {"service_name": "svc", "endpoint_path": "/priv", "http_method": "POST", "auth_required": True})
        stats = engine.get_api_stats("org1")
        assert stats["unauthenticated_endpoints"] == 1

    def test_by_service_breakdown(self, engine):
        engine.register_endpoint("org1", {"service_name": "auth", "endpoint_path": "/login", "http_method": "POST"})
        engine.register_endpoint("org1", {"service_name": "auth", "endpoint_path": "/logout", "http_method": "POST"})
        engine.register_endpoint("org1", {"service_name": "users", "endpoint_path": "/users", "http_method": "GET"})
        stats = engine.get_api_stats("org1")
        assert stats["by_service"]["auth"] == 2
        assert stats["by_service"]["users"] == 1

    def test_by_method_breakdown(self, engine):
        engine.register_endpoint("org1", {"service_name": "svc", "endpoint_path": "/a", "http_method": "GET"})
        engine.register_endpoint("org1", {"service_name": "svc", "endpoint_path": "/b", "http_method": "GET"})
        engine.register_endpoint("org1", {"service_name": "svc", "endpoint_path": "/c", "http_method": "POST"})
        stats = engine.get_api_stats("org1")
        assert stats["by_method"]["GET"] == 2
        assert stats["by_method"]["POST"] == 1

    def test_total_scans(self, engine):
        engine.create_scan("org1", {"scan_name": "S1", "scan_target": "https://x.com"})
        engine.create_scan("org1", {"scan_name": "S2", "scan_target": "https://y.com"})
        stats = engine.get_api_stats("org1")
        assert stats["total_scans"] == 2

    def test_stats_org_isolation(self, engine):
        engine.register_endpoint("org1", {"service_name": "svc", "endpoint_path": "/a", "http_method": "GET"})
        engine.register_endpoint("org2", {"service_name": "svc", "endpoint_path": "/b", "http_method": "GET"})
        stats1 = engine.get_api_stats("org1")
        assert stats1["total_endpoints"] == 1


# ---------------------------------------------------------------------------
# link_to_layer
# ---------------------------------------------------------------------------

class TestLinkToLayer:
    def test_link_happy_path(self, engine):
        """link_to_layer returns node_ref, layer, confidence, and linked=True."""
        result = engine.link_to_layer("org1", "/api/v1/users", layer="api")
        assert result["node_ref"] == "/api/v1/users"
        assert result["layer"] == "api"
        assert result["confidence"] == 0.95
        assert result["linked"] is True

    def test_link_empty_endpoint_path_raises(self, engine):
        """Empty endpoint_path must raise ValueError."""
        with pytest.raises(ValueError, match="endpoint_path"):
            engine.link_to_layer("org1", "", layer="api")

    def test_link_org_isolation(self, engine):
        """link_to_layer result is scoped — org2 returns same node_ref but
        the classification is stored under org2, not org1."""
        r1 = engine.link_to_layer("org1", "/svc/resource", layer="service")
        r2 = engine.link_to_layer("org2", "/svc/resource", layer="data")
        assert r1["layer"] == "service"
        assert r2["layer"] == "data"
        # node_ref is the same path but classifications are independent
        assert r1["node_ref"] == r2["node_ref"]

    def test_link_dep_map_unavailable_returns_linked_false(self, engine, monkeypatch):
        """When SecurityDependencyMappingEngine is not importable the method
        must degrade gracefully and return linked=False."""
        import builtins
        real_import = builtins.__import__

        def _block_dep_map(name, *args, **kwargs):
            if name == "core.security_dependency_mapping_engine":
                raise ImportError("simulated missing dep-map engine")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", _block_dep_map)
        result = engine.link_to_layer("org1", "/api/v1/orders", layer="api")
        assert result["linked"] is False
        assert result["node_ref"] == "/api/v1/orders"
        assert "dep_map_unavailable" in result["signals"]
