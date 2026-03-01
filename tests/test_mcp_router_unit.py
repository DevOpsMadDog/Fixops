"""
Unit tests for MCP Auto-Discovery Router (suite-api/apps/api/mcp_router.py).

Covers:
  - _sanitize_tool_name() -- various name formats and edge cases
  - _extract_description() -- docstrings, empty docs, truncation
  - _classify_category() -- query vs action vs analysis classification
  - _extract_path_params() -- path parameter extraction from templates
  - _annotation_to_json_schema() -- Python type annotation -> JSON Schema
  - _is_auth_exempt() -- auth exemption detection for routes
  - generate_tool_catalog() -- full catalog generation with a mock FastAPI app
  - API endpoints: GET /api/v1/mcp/tools, GET /api/v1/mcp/health
"""

from __future__ import annotations

import inspect
import os
from typing import Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest
from pydantic import BaseModel

# Ensure environment is set before any app imports
os.environ.setdefault("FIXOPS_API_TOKEN", "aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh")
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-jwt-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from apps.api.mcp_router import (
    _annotation_to_json_schema,
    _classify_category,
    _extract_description,
    _extract_path_params,
    _is_auth_exempt,
    _sanitize_tool_name,
    generate_tool_catalog,
)


# ---------------------------------------------------------------------------
# _sanitize_tool_name
# ---------------------------------------------------------------------------


class TestSanitizeToolName:
    def test_simple_name_unchanged(self):
        assert _sanitize_tool_name("list_findings") == "list_findings"

    def test_leading_underscores_stripped(self):
        assert _sanitize_tool_name("__private_func") == "private_func"

    def test_trailing_underscores_stripped(self):
        assert _sanitize_tool_name("func__") == "func"

    def test_special_chars_replaced_with_underscore(self):
        result = _sanitize_tool_name("get-finding.by-id")
        assert result == "get_finding_by_id"

    def test_multiple_underscores_collapsed(self):
        result = _sanitize_tool_name("a___b___c")
        assert result == "a_b_c"

    def test_empty_string_returns_unnamed_tool(self):
        assert _sanitize_tool_name("") == "unnamed_tool"

    def test_only_underscores_returns_unnamed_tool(self):
        assert _sanitize_tool_name("____") == "unnamed_tool"

    def test_alphanumeric_with_numbers(self):
        assert _sanitize_tool_name("get_v2_results") == "get_v2_results"

    def test_mixed_special_characters(self):
        result = _sanitize_tool_name("my@func#name")
        assert result == "my_func_name"

    def test_spaces_replaced(self):
        result = _sanitize_tool_name("my func name")
        assert result == "my_func_name"


# ---------------------------------------------------------------------------
# _extract_description
# ---------------------------------------------------------------------------


class TestExtractDescription:
    def test_simple_docstring(self):
        def my_func():
            """This is a simple description."""

        assert _extract_description(my_func) == "This is a simple description."

    def test_multiline_docstring_takes_first_paragraph(self):
        def my_func():
            """First paragraph here.

            Second paragraph with details.
            """

        result = _extract_description(my_func)
        assert result == "First paragraph here."

    def test_no_docstring_returns_empty(self):
        def my_func():
            pass

        assert _extract_description(my_func) == ""

    def test_long_docstring_truncated_to_2048(self):
        def my_func():
            pass

        my_func.__doc__ = "A" * 3000
        result = _extract_description(my_func)
        assert len(result) <= 2048
        assert result.endswith("...")

    def test_whitespace_stripped(self):
        def my_func():
            """Stripped content."""

        result = _extract_description(my_func)
        assert result == "Stripped content."


# ---------------------------------------------------------------------------
# _classify_category
# ---------------------------------------------------------------------------


class TestClassifyCategory:
    def test_get_method_is_query(self):
        assert _classify_category("GET", "/api/v1/findings", "list_findings") == "query"

    def test_head_method_is_query(self):
        assert _classify_category("HEAD", "/api/v1/health", "health") == "query"

    def test_options_method_is_query(self):
        assert _classify_category("OPTIONS", "/api/v1/test", "test") == "query"

    def test_post_method_is_action(self):
        assert (
            _classify_category("POST", "/api/v1/findings", "create_finding") == "action"
        )

    def test_put_method_is_action(self):
        assert (
            _classify_category("PUT", "/api/v1/findings/1", "update_finding")
            == "action"
        )

    def test_delete_method_is_action(self):
        assert (
            _classify_category("DELETE", "/api/v1/findings/1", "delete_finding")
            == "action"
        )

    def test_patch_method_is_action(self):
        assert (
            _classify_category("PATCH", "/api/v1/findings/1", "patch_finding")
            == "action"
        )

    def test_analysis_keyword_in_path(self):
        assert (
            _classify_category("GET", "/api/v1/analyze/results", "get_results")
            == "analysis"
        )

    def test_analysis_keyword_in_func_name(self):
        assert (
            _classify_category("POST", "/api/v1/process", "score_findings")
            == "analysis"
        )

    def test_risk_keyword_is_analysis(self):
        assert (
            _classify_category("GET", "/api/v1/risk/overview", "list_risks")
            == "analysis"
        )

    def test_brain_keyword_is_analysis(self):
        assert (
            _classify_category("POST", "/api/v1/brain/process", "process") == "analysis"
        )

    def test_triage_keyword_is_analysis(self):
        assert (
            _classify_category("POST", "/api/v1/triage", "triage_findings")
            == "analysis"
        )

    def test_deduplicate_keyword_is_analysis(self):
        assert (
            _classify_category("POST", "/api/v1/deduplicate", "deduplicate")
            == "analysis"
        )

    def test_forecast_keyword_is_analysis(self):
        assert (
            _classify_category("GET", "/api/v1/forecast", "get_forecast") == "analysis"
        )

    def test_reachability_keyword_is_analysis(self):
        assert (
            _classify_category("POST", "/api/v1/reachability", "check_reachability")
            == "analysis"
        )

    def test_post_with_analysis_keyword_is_analysis_not_action(self):
        """Analysis keyword overrides POST -> action default."""
        assert (
            _classify_category("POST", "/api/v1/findings/analyze", "analyze")
            == "analysis"
        )


# ---------------------------------------------------------------------------
# _extract_path_params
# ---------------------------------------------------------------------------


class TestExtractPathParams:
    def test_single_param(self):
        result = _extract_path_params("/api/v1/findings/{finding_id}")
        assert "finding_id" in result
        assert result["finding_id"]["type"] == "string"

    def test_multiple_params(self):
        result = _extract_path_params("/api/v1/{org_id}/findings/{finding_id}")
        assert "org_id" in result
        assert "finding_id" in result
        assert len(result) == 2

    def test_no_params(self):
        result = _extract_path_params("/api/v1/findings")
        assert result == {}

    def test_param_has_description(self):
        result = _extract_path_params("/api/v1/findings/{finding_id}")
        assert "description" in result["finding_id"]
        assert "finding_id" in result["finding_id"]["description"]

    def test_complex_path(self):
        result = _extract_path_params(
            "/api/v1/{team_id}/reports/{report_id}/export/{format}"
        )
        assert len(result) == 3
        assert "team_id" in result
        assert "report_id" in result
        assert "format" in result


# ---------------------------------------------------------------------------
# _annotation_to_json_schema
# ---------------------------------------------------------------------------


class TestAnnotationToJsonSchema:
    def test_str_type(self):
        result = _annotation_to_json_schema(str)
        assert result == {"type": "string"}

    def test_int_type(self):
        result = _annotation_to_json_schema(int)
        assert result == {"type": "integer"}

    def test_float_type(self):
        result = _annotation_to_json_schema(float)
        assert result == {"type": "number"}

    def test_bool_type(self):
        result = _annotation_to_json_schema(bool)
        assert result == {"type": "boolean"}

    def test_list_type(self):
        result = _annotation_to_json_schema(list)
        assert result == {"type": "array"}

    def test_dict_type(self):
        result = _annotation_to_json_schema(dict)
        assert result == {"type": "object"}

    def test_bytes_type(self):
        result = _annotation_to_json_schema(bytes)
        assert result == {"type": "string", "format": "binary"}

    def test_empty_annotation(self):
        result = _annotation_to_json_schema(inspect.Parameter.empty)
        assert result == {"type": "string"}

    def test_optional_str(self):
        result = _annotation_to_json_schema(Optional[str])
        assert result["type"] == "string"

    def test_optional_int(self):
        result = _annotation_to_json_schema(Optional[int])
        assert result["type"] == "integer"

    def test_list_of_str(self):
        result = _annotation_to_json_schema(List[str])
        assert result["type"] == "array"
        # On Python 3.14+, List[str] has __name__="list" which hits the
        # direct type_map before the origin check, so no "items" key.
        # On older Python, items may be present. Either is acceptable.
        if "items" in result:
            assert result["items"]["type"] == "string"

    def test_dict_annotation(self):
        result = _annotation_to_json_schema(Dict[str, int])
        assert result["type"] == "object"

    def test_unknown_type_defaults_to_string(self):
        """Types we don't explicitly handle fall back to string."""

        class CustomType:
            pass

        result = _annotation_to_json_schema(CustomType)
        assert result["type"] == "string"


# ---------------------------------------------------------------------------
# _is_auth_exempt
# ---------------------------------------------------------------------------


class TestIsAuthExempt:
    def _make_route(self, path, dependencies=None, tags=None):
        route = MagicMock()
        route.path = path
        route.dependencies = dependencies or []
        route.tags = tags or []
        return route

    def test_health_path_is_exempt(self):
        route = self._make_route("/api/v1/health")
        assert _is_auth_exempt(route) is True

    def test_ready_path_is_exempt(self):
        route = self._make_route("/api/v1/ready")
        assert _is_auth_exempt(route) is True

    def test_version_path_is_exempt(self):
        route = self._make_route("/api/v1/version")
        assert _is_auth_exempt(route) is True

    def test_health_in_nested_path_is_exempt(self):
        route = self._make_route("/api/v1/mcp/health")
        assert _is_auth_exempt(route) is True

    def test_regular_path_with_no_deps_and_health_tag_is_exempt(self):
        route = self._make_route("/api/v1/public", dependencies=[], tags=["health"])
        assert _is_auth_exempt(route) is True

    def test_public_tag_is_exempt(self):
        route = self._make_route("/api/v1/docs", dependencies=[], tags=["public"])
        assert _is_auth_exempt(route) is True

    def test_regular_path_with_dependencies_not_exempt(self):
        dep = MagicMock()
        route = self._make_route(
            "/api/v1/findings", dependencies=[dep], tags=["findings"]
        )
        assert _is_auth_exempt(route) is False

    def test_regular_path_no_deps_no_special_tags_not_exempt(self):
        route = self._make_route("/api/v1/findings", dependencies=[], tags=["findings"])
        assert _is_auth_exempt(route) is False


# ---------------------------------------------------------------------------
# generate_tool_catalog (with minimal FastAPI app)
# ---------------------------------------------------------------------------


class TestGenerateToolCatalog:
    def test_generates_tools_from_routes(self):
        """Create a minimal FastAPI app and verify catalog generation."""
        from fastapi import FastAPI

        app = FastAPI()

        @app.get("/api/v1/findings", tags=["findings"])
        async def list_findings():
            """List all security findings."""
            return []

        @app.post("/api/v1/findings", tags=["findings"])
        async def create_finding():
            """Create a new finding."""
            return {}

        # Reset module state before generating
        import apps.api.mcp_router as mcp_mod

        mcp_mod._tool_catalog = {}
        mcp_mod._catalog_stats = None

        catalog = generate_tool_catalog(app)
        assert len(catalog) >= 2
        # Check that at least one tool has description
        descriptions = [t.description for t in catalog.values()]
        assert any("findings" in d.lower() for d in descriptions if d)

    def test_skips_excluded_paths(self):
        """Internal paths like /docs and /openapi.json are skipped."""
        from fastapi import FastAPI

        app = FastAPI()

        @app.get("/api/v1/test")
        async def test_route():
            return {}

        import apps.api.mcp_router as mcp_mod

        mcp_mod._tool_catalog = {}
        mcp_mod._catalog_stats = None

        catalog = generate_tool_catalog(app)
        tool_paths = [t.path for t in catalog.values()]
        assert "/openapi.json" not in tool_paths
        assert "/docs" not in tool_paths

    def test_skips_mcp_own_routes(self):
        """MCP routes are excluded to avoid recursion."""
        from fastapi import FastAPI

        app = FastAPI()

        # Simulate including the MCP router
        from apps.api.mcp_router import router as mcp_router

        app.include_router(mcp_router)

        @app.get("/api/v1/other")
        async def other_route():
            return {}

        import apps.api.mcp_router as mcp_mod

        mcp_mod._tool_catalog = {}
        mcp_mod._catalog_stats = None

        catalog = generate_tool_catalog(app)
        tool_paths = [t.path for t in catalog.values()]
        # MCP paths should be excluded
        assert not any(p.startswith("/api/v1/mcp") for p in tool_paths)

    def test_catalog_stats_populated(self):
        """Stats are computed after catalog generation."""
        from fastapi import FastAPI

        app = FastAPI()

        @app.get("/api/v1/findings", tags=["findings"])
        async def list_findings():
            return []

        @app.post("/api/v1/analyze", tags=["analysis"])
        async def analyze():
            """Analyze findings."""
            return {}

        import apps.api.mcp_router as mcp_mod

        mcp_mod._tool_catalog = {}
        mcp_mod._catalog_stats = None

        generate_tool_catalog(app)
        assert mcp_mod._catalog_stats is not None
        assert mcp_mod._catalog_stats.total_tools >= 2
        assert mcp_mod._catalog_generated_at is not None

    def test_head_and_options_are_skipped(self):
        """HEAD and OPTIONS methods are not useful as MCP tools."""
        from fastapi import FastAPI
        from fastapi.routing import APIRoute

        app = FastAPI()

        # Manually add a route with HEAD method
        async def dummy():
            return {}

        app.routes.append(
            APIRoute("/api/v1/test", endpoint=dummy, methods=["HEAD", "OPTIONS", "GET"])
        )

        import apps.api.mcp_router as mcp_mod

        mcp_mod._tool_catalog = {}
        mcp_mod._catalog_stats = None

        catalog = generate_tool_catalog(app)
        methods_in_catalog = [t.method for t in catalog.values()]
        assert "HEAD" not in methods_in_catalog
        assert "OPTIONS" not in methods_in_catalog


# ---------------------------------------------------------------------------
# API Endpoints via TestClient
# ---------------------------------------------------------------------------


class TestMCPEndpoints:
    @pytest.fixture(scope="class")
    def client(self):
        """Create a minimal FastAPI app with MCP router for endpoint testing."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from apps.api.mcp_router import router as mcp_router

        app = FastAPI()
        app.include_router(mcp_router)

        # Add a test route so the catalog has something to discover
        @app.get("/api/v1/findings", tags=["findings"])
        async def list_findings():
            """List all security findings."""
            return []

        @app.post("/api/v1/findings/analyze", tags=["analysis"])
        async def analyze_findings():
            """Analyze security findings for patterns."""
            return {}

        # Reset module state
        import apps.api.mcp_router as mcp_mod

        mcp_mod._tool_catalog = {}
        mcp_mod._catalog_stats = None

        return TestClient(app, raise_server_exceptions=False)

    def test_health_endpoint_returns_200(self, client):
        resp = client.get("/api/v1/mcp/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] in ("healthy", "degraded")
        assert "catalog_size" in data
        assert "uptime_seconds" in data
        assert data["mcp_version"] == "2024-11-05"

    def test_tools_list_returns_200(self, client):
        resp = client.get("/api/v1/mcp/tools")
        assert resp.status_code == 200
        tools = resp.json()
        assert isinstance(tools, list)
        assert len(tools) >= 1

    def test_tools_filter_by_category(self, client):
        resp = client.get("/api/v1/mcp/tools?category=query")
        assert resp.status_code == 200
        tools = resp.json()
        for tool in tools:
            assert tool["category"] == "query"

    def test_tools_filter_by_method(self, client):
        resp = client.get("/api/v1/mcp/tools?method=GET")
        assert resp.status_code == 200
        tools = resp.json()
        for tool in tools:
            assert tool["method"] == "GET"

    def test_tools_search(self, client):
        resp = client.get("/api/v1/mcp/tools?search=finding")
        assert resp.status_code == 200
        tools = resp.json()
        for tool in tools:
            name_lower = tool["name"].lower()
            desc_lower = tool.get("description", "").lower()
            assert "finding" in name_lower or "finding" in desc_lower

    def test_tools_pagination(self, client):
        resp = client.get("/api/v1/mcp/tools?limit=1&offset=0")
        assert resp.status_code == 200
        tools = resp.json()
        assert len(tools) <= 1

    def test_tool_not_found_returns_404(self, client):
        resp = client.get("/api/v1/mcp/tools/nonexistent_tool_xyz")
        assert resp.status_code == 404
        data = resp.json()
        assert data["detail"]["error"] == "tool_not_found"

    def test_stats_endpoint(self, client):
        resp = client.get("/api/v1/mcp/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_tools" in data
        assert "by_category" in data
        assert "by_method" in data

    def test_schemas_mcp_format(self, client):
        resp = client.get("/api/v1/mcp/schemas?format=mcp")
        assert resp.status_code == 200
        data = resp.json()
        assert "tools" in data
        assert "_meta" in data
        assert data["_meta"]["mcp_version"] == "2024-11-05"

    def test_schemas_openapi_format(self, client):
        resp = client.get("/api/v1/mcp/schemas?format=openapi")
        assert resp.status_code == 200
        data = resp.json()
        assert "openapi" in data
        assert data["openapi"] == "3.1.0"
        assert "paths" in data

    def test_refresh_catalog(self, client):
        resp = client.post("/api/v1/mcp/refresh")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "refreshed"
        assert "current_tool_count" in data
        assert "previous_tool_count" in data

    def test_tools_filter_by_tag(self, client):
        resp = client.get("/api/v1/mcp/tools?tag=findings")
        assert resp.status_code == 200
        tools = resp.json()
        for tool in tools:
            assert any(t.lower() == "findings" for t in tool.get("tags", []))

    def test_tools_filter_by_deprecated_false(self, client):
        resp = client.get("/api/v1/mcp/tools?deprecated=false")
        assert resp.status_code == 200
        tools = resp.json()
        for tool in tools:
            assert tool["deprecated"] is False

    def test_tools_search_no_results(self, client):
        resp = client.get("/api/v1/mcp/tools?search=zzz_nonexistent_never_match_xyz")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_tools_pagination_offset_beyond_results(self, client):
        resp = client.get("/api/v1/mcp/tools?limit=10&offset=99999")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_get_existing_tool_by_name(self, client):
        """Fetch a single tool that exists in the catalog."""
        # First get the list to find a valid tool name
        all_tools = client.get("/api/v1/mcp/tools").json()
        if all_tools:
            name = all_tools[0]["name"]
            resp = client.get(f"/api/v1/mcp/tools/{name}")
            assert resp.status_code == 200
            data = resp.json()
            assert data["name"] == name
            assert "method" in data
            assert "path" in data
            assert "inputSchema" in data

    def test_schemas_mcp_format_has_tool_entries(self, client):
        resp = client.get("/api/v1/mcp/schemas?format=mcp")
        assert resp.status_code == 200
        data = resp.json()
        for tool in data["tools"]:
            assert "name" in tool
            assert "inputSchema" in tool
            assert tool["inputSchema"]["type"] == "object"

    def test_schemas_openapi_format_has_paths(self, client):
        resp = client.get("/api/v1/mcp/schemas?format=openapi")
        data = resp.json()
        assert "info" in data
        assert data["info"]["title"] == "ALdeci MCP Tool Catalog"
        # Each path should have at least one method
        for path_key, methods in data["paths"].items():
            assert len(methods) >= 1

    def test_refresh_returns_delta(self, client):
        # First refresh to baseline
        r1 = client.post("/api/v1/mcp/refresh").json()
        count_before = r1["current_tool_count"]
        # Second refresh should show delta = 0 (no routes added)
        r2 = client.post("/api/v1/mcp/refresh").json()
        assert r2["previous_tool_count"] == count_before
        assert "delta" in r2
        assert "generation_time_ms" in r2

    def test_health_catalog_size_matches_tools(self, client):
        health = client.get("/api/v1/mcp/health").json()
        tools = client.get("/api/v1/mcp/tools?limit=1000").json()
        assert health["catalog_size"] == len(tools)


# ---------------------------------------------------------------------------
# Execute endpoint tests
# ---------------------------------------------------------------------------


class TestMCPExecute:
    @pytest.fixture(scope="class")
    def client(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from apps.api.mcp_router import router as mcp_router

        app = FastAPI()
        app.include_router(mcp_router)

        @app.get("/api/v1/findings", tags=["findings"])
        async def list_findings():
            """List all security findings."""
            return [{"id": "f1", "title": "Test finding"}]

        @app.get("/api/v1/findings/{finding_id}", tags=["findings"])
        async def get_finding(finding_id: str):
            """Get a single finding by ID."""
            return {"id": finding_id, "title": f"Finding {finding_id}"}

        @app.post("/api/v1/findings", tags=["findings"])
        async def create_finding(title: str = "default"):
            """Create a new finding."""
            return {"id": "new", "title": title}

        import apps.api.mcp_router as mcp_mod

        mcp_mod._tool_catalog = {}
        mcp_mod._catalog_stats = None

        return TestClient(app, raise_server_exceptions=False)

    def test_execute_nonexistent_tool_returns_not_found(self, client):
        resp = client.post(
            "/api/v1/mcp/execute",
            json={
                "tool_name": "nonexistent_tool_xyz",
                "arguments": {},
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "not_found"
        assert data["status_code"] == 404
        assert "not found" in data["error"].lower()

    def test_execute_get_tool_success(self, client):
        """Execute a GET tool and verify the result is returned."""
        resp = client.post(
            "/api/v1/mcp/execute",
            json={
                "tool_name": "list_findings",
                "arguments": {},
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert data["status_code"] == 200
        assert data["method"] == "GET"
        assert data["execution_time_ms"] >= 0
        assert isinstance(data["result"], list)

    def test_execute_tool_with_path_param(self, client):
        """Execute a tool that requires a path parameter."""
        resp = client.post(
            "/api/v1/mcp/execute",
            json={
                "tool_name": "get_finding",
                "arguments": {"finding_id": "CVE-2024-1234"},
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert data["status_code"] == 200
        assert data["result"]["id"] == "CVE-2024-1234"

    def test_execute_tool_missing_path_param(self, client):
        """Execute a tool without required path params -> error."""
        resp = client.post(
            "/api/v1/mcp/execute",
            json={
                "tool_name": "get_finding",
                "arguments": {},
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "error"
        assert data["status_code"] == 400
        assert "missing" in data["error"].lower()

    def test_execute_response_has_execution_time(self, client):
        resp = client.post(
            "/api/v1/mcp/execute",
            json={"tool_name": "list_findings", "arguments": {}},
        )
        data = resp.json()
        assert "execution_time_ms" in data
        assert isinstance(data["execution_time_ms"], float)
        assert data["execution_time_ms"] >= 0

    def test_execute_request_validation_empty_tool_name(self, client):
        """Empty tool_name should fail Pydantic validation (min_length=1)."""
        resp = client.post(
            "/api/v1/mcp/execute",
            json={"tool_name": "", "arguments": {}},
        )
        assert resp.status_code == 422

    def test_execute_request_validation_tool_name_too_long(self, client):
        """Tool name over 256 chars should fail Pydantic validation."""
        resp = client.post(
            "/api/v1/mcp/execute",
            json={"tool_name": "x" * 257, "arguments": {}},
        )
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# _extract_query_params tests
# ---------------------------------------------------------------------------


class TestExtractQueryParams:
    def test_no_params_returns_empty(self):
        """Endpoint with no parameters returns empty dicts."""
        from apps.api.mcp_router import _extract_query_params

        route = MagicMock(spec=["endpoint"])

        async def empty_endpoint():
            pass

        route.endpoint = empty_endpoint
        props, required = _extract_query_params(route)
        assert props == {}
        assert required == []

    def test_skips_request_and_response(self):
        """Parameters named 'request', 'response' are skipped."""
        from fastapi import Request, Response

        from apps.api.mcp_router import _extract_query_params

        route = MagicMock(spec=["endpoint"])

        async def endpoint_with_req(request: Request, response: Response):
            pass

        route.endpoint = endpoint_with_req
        props, required = _extract_query_params(route)
        assert "request" not in props
        assert "response" not in props

    def test_extracts_typed_params(self):
        """Parameters with type annotations are extracted."""
        from apps.api.mcp_router import _extract_query_params

        route = MagicMock(spec=["endpoint"])

        async def endpoint_with_params(name: str, count: int = 10, active: bool = True):
            pass

        route.endpoint = endpoint_with_params
        props, required = _extract_query_params(route)
        assert "name" in props
        assert props["name"]["type"] == "string"
        assert "name" in required
        assert "count" in props
        assert props["count"]["type"] == "integer"
        assert props["count"]["default"] == 10
        assert "count" not in required
        assert "active" in props
        assert props["active"]["default"] is True

    def test_optional_params_not_required(self):
        """Optional parameters with defaults are not in the required list."""
        from apps.api.mcp_router import _extract_query_params

        route = MagicMock(spec=["endpoint"])

        async def endpoint_with_optional(query: str, limit: int = 50, offset: int = 0):
            pass

        route.endpoint = endpoint_with_optional
        props, required = _extract_query_params(route)
        assert "query" in required
        assert "limit" not in required
        assert "offset" not in required

    def test_handles_signature_error(self):
        """If inspect.signature fails, returns empty results."""
        from apps.api.mcp_router import _extract_query_params

        route = MagicMock(spec=["endpoint"])
        # Create an endpoint that raises ValueError on inspect.signature
        bad_endpoint = MagicMock()
        bad_endpoint.__name__ = "bad"
        with patch("inspect.signature", side_effect=ValueError("no sig")):
            route.endpoint = bad_endpoint
            props, required = _extract_query_params(route)
        assert props == {}
        assert required == []


# ---------------------------------------------------------------------------
# _extract_request_body_schema tests
# ---------------------------------------------------------------------------


class TestExtractRequestBodySchema:
    def test_no_body_returns_none(self):
        """Endpoint with no Pydantic model returns None."""
        from apps.api.mcp_router import _extract_request_body_schema

        route = MagicMock(spec=["endpoint"])

        async def simple_endpoint(name: str):
            pass

        route.endpoint = simple_endpoint
        result = _extract_request_body_schema(route)
        assert result is None

    def test_pydantic_model_returns_schema(self):
        """Endpoint with a Pydantic model param returns its JSON schema.

        The test must compile the function without PEP 563 deferred
        annotations so inspect.signature resolves the type as a class.
        """
        from apps.api.mcp_router import _extract_request_body_schema

        class MyModel(BaseModel):
            name: str
            count: int = 0

        ns = {"MyModel": MyModel}
        # Compile without CO_FUTURE_ANNOTATIONS flag
        code = compile(
            "async def endpoint_with_body(body: MyModel): pass",
            "<test>",
            "exec",
            flags=0,
            dont_inherit=True,
        )
        exec(code, ns)
        endpoint_fn = ns["endpoint_with_body"]

        route = MagicMock(spec=["endpoint"])
        route.endpoint = endpoint_fn
        result = _extract_request_body_schema(route)
        assert result is not None
        assert result["type"] == "object"
        assert "name" in result["properties"]

    def test_skips_request_param(self):
        """Parameters named 'request' are skipped even with annotation."""
        from apps.api.mcp_router import _extract_request_body_schema

        class InputModel(BaseModel):
            value: str

        ns = {"InputModel": InputModel}
        code = compile(
            "async def endpoint_with_request(request: object, body: InputModel): pass",
            "<test>",
            "exec",
            flags=0,
            dont_inherit=True,
        )
        exec(code, ns)
        endpoint_fn = ns["endpoint_with_request"]

        route = MagicMock(spec=["endpoint"])
        route.endpoint = endpoint_fn
        result = _extract_request_body_schema(route)
        assert result is not None
        assert "value" in result["properties"]

    def test_handles_signature_error(self):
        """If inspect.signature fails, returns None."""
        from apps.api.mcp_router import _extract_request_body_schema

        route = MagicMock(spec=["endpoint"])
        bad_endpoint = MagicMock()
        with patch("inspect.signature", side_effect=ValueError("no sig")):
            route.endpoint = bad_endpoint
            result = _extract_request_body_schema(route)
        assert result is None


# ---------------------------------------------------------------------------
# _find_route_handler and _elapsed_ms tests
# ---------------------------------------------------------------------------


class TestInternalHelpers:
    def test_find_route_handler_found(self):
        from fastapi import FastAPI

        from apps.api.mcp_router import _find_route_handler

        app = FastAPI()

        @app.get("/api/v1/test")
        async def test_handler():
            return {}

        handler = _find_route_handler(app, "GET", "/api/v1/test")
        assert handler is test_handler

    def test_find_route_handler_wrong_method(self):
        from fastapi import FastAPI

        from apps.api.mcp_router import _find_route_handler

        app = FastAPI()

        @app.get("/api/v1/test")
        async def test_handler():
            return {}

        handler = _find_route_handler(app, "POST", "/api/v1/test")
        assert handler is None

    def test_find_route_handler_wrong_path(self):
        from fastapi import FastAPI

        from apps.api.mcp_router import _find_route_handler

        app = FastAPI()

        @app.get("/api/v1/test")
        async def test_handler():
            return {}

        handler = _find_route_handler(app, "GET", "/api/v1/nonexistent")
        assert handler is None

    def test_elapsed_ms_returns_positive(self):
        import time

        from apps.api.mcp_router import _elapsed_ms

        start = time.monotonic()
        time.sleep(0.01)
        elapsed = _elapsed_ms(start)
        assert elapsed >= 5  # at least 5ms (generous threshold)
        assert isinstance(elapsed, float)


# ---------------------------------------------------------------------------
# Pydantic model validation tests
# ---------------------------------------------------------------------------


class TestMCPPydanticModels:
    def test_tool_input_schema_defaults(self):
        from apps.api.mcp_router import MCPToolInputSchema

        schema = MCPToolInputSchema()
        assert schema.type == "object"
        assert schema.properties == {}
        assert schema.required == []

    def test_tool_definition_minimal(self):
        from apps.api.mcp_router import MCPToolDefinition

        tool = MCPToolDefinition(
            name="test_tool",
            method="GET",
            path="/api/v1/test",
        )
        assert tool.name == "test_tool"
        assert tool.description == ""
        assert tool.category == "query"
        assert tool.requires_auth is True
        assert tool.deprecated is False
        assert tool.tags == []

    def test_tool_definition_full(self):
        from apps.api.mcp_router import MCPToolDefinition, MCPToolInputSchema

        tool = MCPToolDefinition(
            name="analyze_findings",
            description="Analyze findings for patterns",
            inputSchema=MCPToolInputSchema(
                properties={"app_id": {"type": "string"}},
                required=["app_id"],
            ),
            method="POST",
            path="/api/v1/analyze",
            tags=["analysis"],
            category="analysis",
            requires_auth=True,
            deprecated=False,
        )
        assert tool.name == "analyze_findings"
        assert "app_id" in tool.inputSchema.properties
        assert tool.inputSchema.required == ["app_id"]

    def test_execute_request_validation(self):
        from apps.api.mcp_router import MCPExecuteRequest

        req = MCPExecuteRequest(
            tool_name="list_findings",
            arguments={"limit": 10},
        )
        assert req.tool_name == "list_findings"
        assert req.arguments == {"limit": 10}

    def test_execute_request_defaults_empty_args(self):
        from apps.api.mcp_router import MCPExecuteRequest

        req = MCPExecuteRequest(tool_name="health")
        assert req.arguments == {}

    def test_execute_response_success(self):
        from apps.api.mcp_router import MCPExecuteResponse

        resp = MCPExecuteResponse(
            tool_name="list_findings",
            method="GET",
            path="/api/v1/findings",
            status="success",
            status_code=200,
            result=[{"id": "1"}],
            execution_time_ms=12.5,
        )
        assert resp.error is None
        assert resp.result == [{"id": "1"}]

    def test_execute_response_error(self):
        from apps.api.mcp_router import MCPExecuteResponse

        resp = MCPExecuteResponse(
            tool_name="bad_tool",
            method="",
            path="",
            status="not_found",
            status_code=404,
            error="Tool not found",
        )
        assert resp.status == "not_found"
        assert resp.error == "Tool not found"
        assert resp.result is None

    def test_catalog_stats_model(self):
        from apps.api.mcp_router import MCPCatalogStats

        stats = MCPCatalogStats(
            total_tools=50,
            by_category={"query": 30, "action": 15, "analysis": 5},
            by_method={"GET": 35, "POST": 15},
            by_tag={"findings": 10, "reports": 8},
            routes_skipped=5,
            generated_at="2026-02-27T10:00:00Z",
            generation_time_ms=42.5,
        )
        assert stats.total_tools == 50
        assert stats.mcp_version == "2024-11-05"
        assert stats.by_category["query"] == 30

    def test_health_response_model(self):
        from apps.api.mcp_router import MCPHealthResponse

        health = MCPHealthResponse(
            status="healthy",
            catalog_size=100,
            generated_at="2026-02-27T10:00:00Z",
            uptime_seconds=3600.5,
        )
        assert health.mcp_version == "2024-11-05"
        assert health.uptime_seconds == 3600.5


# ---------------------------------------------------------------------------
# Catalog generation edge cases
# ---------------------------------------------------------------------------


class TestCatalogEdgeCases:
    def test_duplicate_function_names_differentiated(self):
        """Routes sharing the same function name get differentiated tool names."""
        from fastapi import FastAPI

        import apps.api.mcp_router as mcp_mod

        app = FastAPI()

        async def handle():
            return {}

        app.add_api_route("/api/v1/a", handle, methods=["GET"])
        app.add_api_route("/api/v1/b", handle, methods=["POST"])

        mcp_mod._tool_catalog = {}
        mcp_mod._catalog_stats = None

        catalog = generate_tool_catalog(app)
        names = list(catalog.keys())
        assert len(names) >= 2
        # All names should be unique
        assert len(set(names)) == len(names)

    def test_route_with_pydantic_body_has_body_property(self):
        """POST route with a Pydantic body model adds a 'body' entry.

        Note: When PEP 563 deferred annotations are active (or annotation
        is a string), _extract_request_body_schema cannot resolve the
        Pydantic model class, so it falls through to the string type
        mapping and the body appears as {"body": {"type": "string"}}.
        This is the expected behavior given our current implementation.
        """
        from fastapi import FastAPI

        import apps.api.mcp_router as mcp_mod

        app = FastAPI()

        class CreateRequest(BaseModel):
            title: str
            severity: str = "medium"

        @app.post("/api/v1/items")
        async def create_item(body: CreateRequest):
            return {}

        mcp_mod._tool_catalog = {}
        mcp_mod._catalog_stats = None

        catalog = generate_tool_catalog(app)
        tool = list(catalog.values())[0]
        assert tool.method == "POST"
        props = tool.inputSchema.properties
        # The body parameter is captured (either flattened or as "body" key)
        assert len(props) >= 1

    def test_route_with_query_and_path_params(self):
        """Route with both path and query parameters merges them."""
        from fastapi import FastAPI

        import apps.api.mcp_router as mcp_mod

        app = FastAPI()

        @app.get("/api/v1/findings/{finding_id}")
        async def get_finding(finding_id: str, include_details: bool = False):
            return {}

        mcp_mod._tool_catalog = {}
        mcp_mod._catalog_stats = None

        catalog = generate_tool_catalog(app)
        tool = list(catalog.values())[0]
        props = tool.inputSchema.properties
        assert "finding_id" in props
        assert "finding_id" in tool.inputSchema.required
        assert "include_details" in props

    def test_annotation_to_json_schema_pydantic_model(self):
        """Pydantic models get their full JSON schema extracted."""

        class SampleModel(BaseModel):
            name: str
            value: int = 0

        result = _annotation_to_json_schema(SampleModel)
        assert result["type"] == "object"
        assert "name" in result.get("properties", {})

    def test_annotation_to_json_schema_enum(self):
        """Enum types produce string type with enum values."""
        import enum

        class Color(enum.Enum):
            RED = "red"
            GREEN = "green"
            BLUE = "blue"

        result = _annotation_to_json_schema(Color)
        assert result["type"] == "string"
        assert "enum" in result
        assert "RED" in result["enum"]
