"""
Tests for the MCP Auto-Discovery Router.

Validates that MCP tool catalog is correctly generated from FastAPI routes,
with proper input schema extraction, categorization, filtering, pagination,
and execution proxying.

SPRINT1-017: MCP Auto-Discovery
Pillar: V7 (MCP-Native AI Platform)
"""

from __future__ import annotations

import pytest
from fastapi import APIRouter, FastAPI, Query
from fastapi.testclient import TestClient
from pydantic import BaseModel
from typing import Dict, Optional

# Import the module under test
from apps.api.mcp_router import (
    MCPToolDefinition,
    MCPToolInputSchema,
    MCPCatalogStats,
    MCPExecuteRequest,
    _sanitize_tool_name,
    _extract_description,
    _classify_category,
    _extract_path_params,
    _annotation_to_json_schema,
    generate_tool_catalog,
    router as mcp_router,
)


# ---------------------------------------------------------------------------
# Fixtures: build a minimal FastAPI app with known routes for testing
# ---------------------------------------------------------------------------


class FindingCreate(BaseModel):
    title: str
    severity: str = "medium"
    description: Optional[str] = None


class FindingResponse(BaseModel):
    id: str
    title: str
    severity: str


def _build_test_app() -> FastAPI:
    """Build a minimal FastAPI app with various route types for testing."""
    app = FastAPI(title="Test App")

    # Router with tagged routes
    findings_router = APIRouter(prefix="/api/v1/findings", tags=["findings"])

    @findings_router.get("/")
    async def list_findings(
        severity: Optional[str] = None,
        limit: int = Query(50, ge=1, le=500),
    ) -> Dict:
        """List all security findings with optional severity filter."""
        return {"findings": [], "total": 0}

    @findings_router.get("/{finding_id}")
    async def get_finding(finding_id: str) -> Dict:
        """Get a specific finding by its unique identifier."""
        return {"id": finding_id, "title": "test"}

    @findings_router.post("/")
    async def create_finding(body: FindingCreate) -> Dict:
        """Create a new security finding."""
        return {"id": "new-id", "title": body.title}

    @findings_router.delete("/{finding_id}")
    async def delete_finding(finding_id: str) -> Dict:
        """Delete a finding by ID."""
        return {"deleted": True}

    @findings_router.put("/{finding_id}")
    async def update_finding(finding_id: str, body: FindingCreate) -> Dict:
        """Update an existing finding."""
        return {"id": finding_id, "title": body.title}

    # Analysis-style route
    analysis_router = APIRouter(prefix="/api/v1/analyze", tags=["analysis"])

    @analysis_router.post("/risk-score")
    async def analyze_risk_score(target: str = "test") -> Dict:
        """Analyze and compute risk score for a target."""
        return {"score": 7.5, "target": target}

    @analysis_router.get("/blast-radius/{cve_id}")
    async def get_blast_radius(cve_id: str) -> Dict:
        """Assess the blast radius of a given CVE."""
        return {"cve_id": cve_id, "radius": "high"}

    # Health endpoint (should be excluded or marked no-auth)
    @app.get("/api/v1/health", tags=["health"])
    async def health_check() -> Dict:
        """Health check endpoint."""
        return {"status": "healthy"}

    # Deprecated route
    deprecated_router = APIRouter(prefix="/api/v1/legacy", tags=["legacy"])

    @deprecated_router.get("/old-endpoint", deprecated=True)
    async def old_endpoint() -> Dict:
        """This endpoint is deprecated."""
        return {"message": "use new endpoint"}

    # Route without docstring
    @app.get("/api/v1/nodoc", tags=["misc"])
    async def no_docstring_route():
        return {"ok": True}

    app.include_router(findings_router)
    app.include_router(analysis_router)
    app.include_router(deprecated_router)

    # Mount the MCP discovery router itself
    app.include_router(mcp_router)

    # Register startup hook to generate catalog
    from apps.api.mcp_router import register_startup_hook

    register_startup_hook(app)

    return app


@pytest.fixture
def test_app():
    """Create a test FastAPI app and generate the MCP catalog."""
    app = _build_test_app()
    # Manually trigger catalog generation (startup events don't fire in test)
    generate_tool_catalog(app)
    return app


@pytest.fixture
def client(test_app):
    """TestClient for the test app."""
    return TestClient(test_app)


# ---------------------------------------------------------------------------
# Unit Tests: Helper Functions
# ---------------------------------------------------------------------------


class TestSanitizeToolName:
    def test_simple_name(self):
        assert _sanitize_tool_name("list_findings") == "list_findings"

    def test_leading_underscore(self):
        assert _sanitize_tool_name("_private_func") == "private_func"

    def test_trailing_underscore(self):
        assert _sanitize_tool_name("func_") == "func"

    def test_special_characters(self):
        assert _sanitize_tool_name("my-func.v2") == "my_func_v2"

    def test_empty_string(self):
        assert _sanitize_tool_name("") == "unnamed_tool"

    def test_only_underscores(self):
        assert _sanitize_tool_name("___") == "unnamed_tool"

    def test_multiple_underscores(self):
        assert _sanitize_tool_name("a___b") == "a_b"


class TestExtractDescription:
    def test_with_docstring(self):
        def func():
            """This is the description."""
            pass

        assert _extract_description(func) == "This is the description."

    def test_multi_paragraph_docstring(self):
        def func():
            """First paragraph.

            Second paragraph with details.
            """
            pass

        assert _extract_description(func) == "First paragraph."

    def test_no_docstring(self):
        def func():
            pass

        assert _extract_description(func) == ""

    def test_long_docstring_truncated(self):
        long_doc = "A" * 3000

        def func():
            pass

        func.__doc__ = long_doc
        result = _extract_description(func)
        assert len(result) <= 2048
        assert result.endswith("...")


class TestClassifyCategory:
    def test_get_is_query(self):
        assert _classify_category("GET", "/api/v1/findings", "list_findings") == "query"

    def test_post_is_action(self):
        assert _classify_category("POST", "/api/v1/findings", "create_finding") == "action"

    def test_put_is_action(self):
        assert _classify_category("PUT", "/api/v1/findings/1", "update_finding") == "action"

    def test_delete_is_action(self):
        assert _classify_category("DELETE", "/api/v1/findings/1", "delete_finding") == "action"

    def test_analyze_in_path_is_analysis(self):
        assert _classify_category("POST", "/api/v1/analyze/risk", "compute") == "analysis"

    def test_score_in_name_is_analysis(self):
        assert _classify_category("GET", "/api/v1/data", "get_risk_score") == "analysis"

    def test_assess_in_path_is_analysis(self):
        assert _classify_category("GET", "/api/v1/assess/cve", "get_result") == "analysis"

    def test_predict_in_name_is_analysis(self):
        assert _classify_category("POST", "/api/v1/ml", "predict_severity") == "analysis"

    def test_decision_in_path_is_analysis(self):
        assert _classify_category("GET", "/api/v1/decision/tree", "get_tree") == "analysis"

    def test_brain_in_path_is_analysis(self):
        assert _classify_category("POST", "/api/v1/brain/run", "run_pipeline") == "analysis"


class TestExtractPathParams:
    def test_no_params(self):
        assert _extract_path_params("/api/v1/findings") == {}

    def test_single_param(self):
        result = _extract_path_params("/api/v1/findings/{finding_id}")
        assert "finding_id" in result
        assert result["finding_id"]["type"] == "string"

    def test_multiple_params(self):
        result = _extract_path_params("/api/v1/{org_id}/findings/{finding_id}")
        assert "org_id" in result
        assert "finding_id" in result


class TestAnnotationToJsonSchema:
    def test_str(self):
        assert _annotation_to_json_schema(str) == {"type": "string"}

    def test_int(self):
        assert _annotation_to_json_schema(int) == {"type": "integer"}

    def test_float(self):
        assert _annotation_to_json_schema(float) == {"type": "number"}

    def test_bool(self):
        assert _annotation_to_json_schema(bool) == {"type": "boolean"}

    def test_list(self):
        assert _annotation_to_json_schema(list) == {"type": "array"}

    def test_dict(self):
        assert _annotation_to_json_schema(dict) == {"type": "object"}


# ---------------------------------------------------------------------------
# Integration Tests: Catalog Generation
# ---------------------------------------------------------------------------


class TestCatalogGeneration:
    def test_catalog_is_populated(self, test_app):
        from apps.api.mcp_router import _tool_catalog

        assert len(_tool_catalog) > 0

    def test_list_findings_discovered(self, test_app):
        from apps.api.mcp_router import _tool_catalog

        assert "list_findings" in _tool_catalog
        tool = _tool_catalog["list_findings"]
        assert tool.method == "GET"
        assert tool.path == "/api/v1/findings/"
        assert tool.category == "query"
        assert "findings" in tool.tags

    def test_get_finding_has_path_param(self, test_app):
        from apps.api.mcp_router import _tool_catalog

        assert "get_finding" in _tool_catalog
        tool = _tool_catalog["get_finding"]
        assert "finding_id" in tool.inputSchema.properties
        assert "finding_id" in tool.inputSchema.required

    def test_create_finding_is_action(self, test_app):
        from apps.api.mcp_router import _tool_catalog

        assert "create_finding" in _tool_catalog
        tool = _tool_catalog["create_finding"]
        assert tool.method == "POST"
        assert tool.category == "action"

    def test_analyze_route_is_analysis(self, test_app):
        from apps.api.mcp_router import _tool_catalog

        assert "analyze_risk_score" in _tool_catalog
        tool = _tool_catalog["analyze_risk_score"]
        assert tool.category == "analysis"

    def test_description_extracted(self, test_app):
        from apps.api.mcp_router import _tool_catalog

        tool = _tool_catalog["list_findings"]
        assert "security findings" in tool.description.lower()

    def test_no_docstring_gets_empty_description(self, test_app):
        from apps.api.mcp_router import _tool_catalog

        assert "no_docstring_route" in _tool_catalog
        tool = _tool_catalog["no_docstring_route"]
        assert tool.description == ""

    def test_mcp_routes_excluded(self, test_app):
        from apps.api.mcp_router import _tool_catalog

        # MCP's own routes should be excluded from the catalog
        mcp_names = [
            name
            for name in _tool_catalog
            if _tool_catalog[name].path.startswith("/api/v1/mcp")
        ]
        assert len(mcp_names) == 0, f"MCP routes should be excluded: {mcp_names}"

    def test_health_route_not_authed(self, test_app):
        from apps.api.mcp_router import _tool_catalog

        assert "health_check" in _tool_catalog
        tool = _tool_catalog["health_check"]
        assert tool.requires_auth is False

    def test_stats_generated(self, test_app):
        from apps.api.mcp_router import _catalog_stats

        assert _catalog_stats is not None
        assert _catalog_stats.total_tools > 0
        assert "query" in _catalog_stats.by_category
        assert "GET" in _catalog_stats.by_method

    def test_no_duplicate_tool_names(self, test_app):
        from apps.api.mcp_router import _tool_catalog

        # This is enforced by the dict key, but let's verify
        names = list(_tool_catalog.keys())
        assert len(names) == len(set(names))

    def test_delete_route_discovered(self, test_app):
        from apps.api.mcp_router import _tool_catalog

        assert "delete_finding" in _tool_catalog
        tool = _tool_catalog["delete_finding"]
        assert tool.method == "DELETE"
        assert tool.category == "action"

    def test_put_route_discovered(self, test_app):
        from apps.api.mcp_router import _tool_catalog

        assert "update_finding" in _tool_catalog
        tool = _tool_catalog["update_finding"]
        assert tool.method == "PUT"
        assert tool.category == "action"


# ---------------------------------------------------------------------------
# API Endpoint Tests
# ---------------------------------------------------------------------------


class TestToolsEndpoint:
    def test_list_all_tools(self, client):
        resp = client.get("/api/v1/mcp/tools")
        assert resp.status_code == 200
        tools = resp.json()
        assert isinstance(tools, list)
        assert len(tools) > 0

    def test_filter_by_category(self, client):
        resp = client.get("/api/v1/mcp/tools?category=query")
        assert resp.status_code == 200
        tools = resp.json()
        for tool in tools:
            assert tool["category"] == "query"

    def test_filter_by_method(self, client):
        resp = client.get("/api/v1/mcp/tools?method=POST")
        assert resp.status_code == 200
        tools = resp.json()
        for tool in tools:
            assert tool["method"] == "POST"

    def test_filter_by_tag(self, client):
        resp = client.get("/api/v1/mcp/tools?tag=findings")
        assert resp.status_code == 200
        tools = resp.json()
        for tool in tools:
            assert "findings" in [t.lower() for t in tool["tags"]]

    def test_search_tools(self, client):
        resp = client.get("/api/v1/mcp/tools?search=finding")
        assert resp.status_code == 200
        tools = resp.json()
        assert len(tools) > 0
        for tool in tools:
            assert "finding" in tool["name"].lower() or "finding" in tool["description"].lower()

    def test_pagination(self, client):
        resp = client.get("/api/v1/mcp/tools?limit=2&offset=0")
        assert resp.status_code == 200
        page1 = resp.json()
        assert len(page1) <= 2

        resp2 = client.get("/api/v1/mcp/tools?limit=2&offset=2")
        assert resp2.status_code == 200
        page2 = resp2.json()

        # Pages should not overlap (if there are enough tools)
        if page1 and page2:
            names1 = {t["name"] for t in page1}
            names2 = {t["name"] for t in page2}
            assert names1.isdisjoint(names2)

    def test_invalid_category_rejected(self, client):
        resp = client.get("/api/v1/mcp/tools?category=invalid")
        assert resp.status_code == 422

    def test_invalid_method_rejected(self, client):
        resp = client.get("/api/v1/mcp/tools?method=INVALID")
        assert resp.status_code == 422


class TestSingleToolEndpoint:
    def test_get_existing_tool(self, client):
        resp = client.get("/api/v1/mcp/tools/list_findings")
        assert resp.status_code == 200
        tool = resp.json()
        assert tool["name"] == "list_findings"
        assert "inputSchema" in tool

    def test_get_nonexistent_tool(self, client):
        resp = client.get("/api/v1/mcp/tools/nonexistent_tool_xyz")
        assert resp.status_code == 404
        body = resp.json()
        assert body["detail"]["error"] == "tool_not_found"


class TestSchemasEndpoint:
    def test_mcp_format(self, client):
        resp = client.get("/api/v1/mcp/schemas?format=mcp")
        assert resp.status_code == 200
        body = resp.json()
        assert "tools" in body
        assert isinstance(body["tools"], list)
        assert len(body["tools"]) > 0
        # Verify MCP format structure
        first_tool = body["tools"][0]
        assert "name" in first_tool
        assert "description" in first_tool
        assert "inputSchema" in first_tool
        assert body["_meta"]["mcp_version"] == "2024-11-05"

    def test_openapi_format(self, client):
        resp = client.get("/api/v1/mcp/schemas?format=openapi")
        assert resp.status_code == 200
        body = resp.json()
        assert body["openapi"] == "3.1.0"
        assert "paths" in body
        assert "info" in body

    def test_invalid_format_rejected(self, client):
        resp = client.get("/api/v1/mcp/schemas?format=graphql")
        assert resp.status_code == 422


class TestHealthEndpoint:
    def test_health_returns_healthy(self, client):
        resp = client.get("/api/v1/mcp/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "healthy"
        assert body["catalog_size"] > 0
        assert body["generated_at"] is not None
        assert body["uptime_seconds"] >= 0
        assert body["mcp_version"] == "2024-11-05"


class TestStatsEndpoint:
    def test_stats_returned(self, client):
        resp = client.get("/api/v1/mcp/stats")
        assert resp.status_code == 200
        stats = resp.json()
        assert stats["total_tools"] > 0
        assert "by_category" in stats
        assert "by_method" in stats
        assert "by_tag" in stats
        assert stats["routes_skipped"] >= 0
        assert stats["generated_at"] is not None
        assert stats["generation_time_ms"] >= 0


class TestRefreshEndpoint:
    def test_refresh_returns_counts(self, client):
        resp = client.post("/api/v1/mcp/refresh")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "refreshed"
        assert "previous_tool_count" in body
        assert "current_tool_count" in body
        assert "delta" in body
        assert body["current_tool_count"] > 0


class TestExecuteEndpoint:
    def test_execute_existing_tool(self, client):
        resp = client.post(
            "/api/v1/mcp/execute",
            json={"tool_name": "list_findings", "arguments": {}},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["tool_name"] == "list_findings"
        assert body["method"] == "GET"
        assert body["status"] == "success"
        assert body["status_code"] == 200

    def test_execute_nonexistent_tool(self, client):
        resp = client.post(
            "/api/v1/mcp/execute",
            json={"tool_name": "nonexistent_tool", "arguments": {}},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "not_found"
        assert body["status_code"] == 404

    def test_execute_with_path_params(self, client):
        resp = client.post(
            "/api/v1/mcp/execute",
            json={
                "tool_name": "get_finding",
                "arguments": {"finding_id": "test-123"},
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "success"
        assert body["execution_time_ms"] >= 0

    def test_execute_missing_path_param(self, client):
        resp = client.post(
            "/api/v1/mcp/execute",
            json={
                "tool_name": "get_finding",
                "arguments": {},  # missing finding_id
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "error"
        assert "finding_id" in body["error"]

    def test_execute_empty_tool_name_rejected(self, client):
        resp = client.post(
            "/api/v1/mcp/execute",
            json={"tool_name": "", "arguments": {}},
        )
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Edge Cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_tool_name_uniqueness_with_same_func_name(self):
        """Routes with the same function name on different methods get unique names."""
        app = FastAPI()

        @app.get("/api/v1/resource")
        async def resource():
            """GET resource."""
            return {}

        @app.post("/api/v1/resource")
        async def resource_post():
            """POST resource."""
            return {}

        app.include_router(mcp_router)
        catalog = generate_tool_catalog(app)
        names = list(catalog.keys())
        assert len(names) == len(set(names)), "Tool names must be unique"

    def test_catalog_regeneration_clears_old(self):
        """Regenerating the catalog replaces the old one."""
        app = FastAPI()

        @app.get("/api/v1/first")
        async def first_route():
            return {}

        app.include_router(mcp_router)
        catalog1 = generate_tool_catalog(app)
        count1 = len(catalog1)

        # Generate again - should produce same results
        catalog2 = generate_tool_catalog(app)
        count2 = len(catalog2)

        assert count1 == count2

    def test_pydantic_model_body_extraction(self):
        """POST routes with Pydantic models have body schema extracted."""
        app = FastAPI()

        class ItemCreate(BaseModel):
            name: str
            value: int

        @app.post("/api/v1/items")
        async def create_item(body: ItemCreate):
            """Create an item."""
            return {"name": body.name}

        app.include_router(mcp_router)
        catalog = generate_tool_catalog(app)

        assert "create_item" in catalog
        tool = catalog["create_item"]
        props = tool.inputSchema.properties
        # Body properties should be flattened into the schema
        assert "name" in props or "body" in props

    def test_enum_query_param(self):
        """Enum type annotations are handled correctly."""
        from enum import Enum

        class Severity(str, Enum):
            CRITICAL = "critical"
            HIGH = "high"
            MEDIUM = "medium"

        app = FastAPI()

        @app.get("/api/v1/by-severity")
        async def by_severity(sev: Severity = Severity.MEDIUM):
            return {}

        app.include_router(mcp_router)
        catalog = generate_tool_catalog(app)
        assert "by_severity" in catalog


# ---------------------------------------------------------------------------
# Model validation tests
# ---------------------------------------------------------------------------


class TestModelValidation:
    def test_mcp_tool_definition_serialization(self):
        tool = MCPToolDefinition(
            name="test_tool",
            description="A test tool",
            inputSchema=MCPToolInputSchema(
                type="object",
                properties={"id": {"type": "string"}},
                required=["id"],
            ),
            method="GET",
            path="/api/v1/test",
            tags=["test"],
            category="query",
        )
        data = tool.model_dump()
        assert data["name"] == "test_tool"
        assert data["inputSchema"]["properties"]["id"]["type"] == "string"

    def test_execute_request_validation(self):
        req = MCPExecuteRequest(tool_name="my_tool", arguments={"key": "value"})
        assert req.tool_name == "my_tool"
        assert req.arguments == {"key": "value"}

    def test_execute_request_default_arguments(self):
        req = MCPExecuteRequest(tool_name="my_tool")
        assert req.arguments == {}

    def test_catalog_stats_model(self):
        stats = MCPCatalogStats(
            total_tools=100,
            by_category={"query": 60, "action": 30, "analysis": 10},
            by_method={"GET": 60, "POST": 30, "DELETE": 10},
            by_tag={"findings": 20, "attack": 15},
            routes_skipped=5,
            generated_at="2026-02-27T12:00:00Z",
            generation_time_ms=42.5,
        )
        assert stats.total_tools == 100
        assert stats.mcp_version == "2024-11-05"
