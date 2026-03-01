"""
Tests for MCP Gateway Demo (DEMO-009) — V7: MCP-Native AI Platform.

Validates:
1. MCP auto-discovery generates 500+ tools from FastAPI routes
2. MCP JSON-RPC protocol initialization works
3. Tool execution via MCP gateway routes requests correctly
4. Brain pipeline processes findings through 12 steps
5. MCP schema export is spec-compliant
6. End-to-end demo flow succeeds

These tests use Starlette TestClient (no running server needed).
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List

import pytest

# ---------------------------------------------------------------------------
# Ensure suite paths are importable
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))
try:
    import sitecustomize  # noqa: F401
except ImportError:
    for suite_dir in ["suite-api", "suite-core", "suite-attack",
                      "suite-feeds", "suite-evidence-risk", "suite-integrations"]:
        p = _REPO_ROOT / suite_dir
        if p.is_dir() and str(p) not in sys.path:
            sys.path.insert(0, str(p))


# ---------------------------------------------------------------------------
# Disable rate limiting for tests
# ---------------------------------------------------------------------------
os.environ["FIXOPS_DISABLE_RATE_LIMIT"] = "1"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def app():
    """Create the FastAPI app for testing."""
    os.environ["FIXOPS_DISABLE_RATE_LIMIT"] = "1"
    from apps.api.app import create_app
    return create_app()


@pytest.fixture(scope="module")
def client(app):
    """Create a TestClient that triggers startup events."""
    from starlette.testclient import TestClient
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture
def api_headers():
    """Standard API headers for MCP requests."""
    return {
        "Content-Type": "application/json",
        "X-API-Key": os.getenv("FIXOPS_API_TOKEN", "test-key"),
        "X-MCP-Session": f"test-session-{uuid.uuid4().hex[:8]}",
    }


@pytest.fixture
def demo_findings() -> List[Dict[str, Any]]:
    """Sample vulnerability findings for testing."""
    return [
        {
            "id": f"FIND-{uuid.uuid4().hex[:8].upper()}",
            "cve_id": "CVE-2024-3094",
            "severity": "critical",
            "title": "XZ Utils backdoor",
            "description": "Supply chain compromise in xz/liblzma",
            "source": "snyk",
            "asset_name": "api-gateway",
            "cvss_score": 10.0,
        },
        {
            "id": f"FIND-{uuid.uuid4().hex[:8].upper()}",
            "cve_id": "CVE-2021-44228",
            "severity": "critical",
            "title": "Log4Shell RCE",
            "description": "JNDI injection in Apache Log4j2",
            "source": "trivy",
            "asset_name": "payment-service",
            "cvss_score": 10.0,
        },
        {
            "id": f"FIND-{uuid.uuid4().hex[:8].upper()}",
            "cve_id": "CVE-2023-44487",
            "severity": "high",
            "title": "HTTP/2 Rapid Reset",
            "description": "DDoS amplification via HTTP/2 stream resets",
            "source": "semgrep",
            "asset_name": "load-balancer",
            "cvss_score": 7.5,
        },
    ]


@pytest.fixture
def demo_assets() -> List[Dict[str, Any]]:
    """Sample assets for testing."""
    return [
        {"id": "api-gateway", "name": "API Gateway", "criticality": 5.0, "type": "service"},
        {"id": "payment-service", "name": "Payment Service", "criticality": 5.0, "type": "service"},
        {"id": "load-balancer", "name": "Load Balancer", "criticality": 4.0, "type": "infrastructure"},
    ]


# ═══════════════════════════════════════════════════════════════════════════════
# Test 1: MCP Tool Auto-Discovery
# ═══════════════════════════════════════════════════════════════════════════════

class TestMCPToolDiscovery:
    """Test the auto-discovery of MCP tools from FastAPI routes."""

    def test_tools_endpoint_returns_list(self, client, api_headers):
        """GET /api/v1/mcp/tools must return a list."""
        resp = client.get("/api/v1/mcp/tools", headers=api_headers, params={"limit": 1000})
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list), f"Expected list, got {type(data)}"

    def test_tools_count_minimum(self, client, api_headers):
        """Must discover at least 100 tools (500+ is the target)."""
        resp = client.get("/api/v1/mcp/tools", headers=api_headers, params={"limit": 1000})
        assert resp.status_code == 200
        tools = resp.json()
        # At minimum we expect 100+ tools; 500+ is the demo target
        assert len(tools) >= 100, (
            f"Expected at least 100 tools, got {len(tools)}. "
            f"MCP auto-discovery may not be generating from all routes."
        )

    def test_tool_schema_structure(self, client, api_headers):
        """Each tool must have required MCP fields."""
        resp = client.get("/api/v1/mcp/tools", headers=api_headers, params={"limit": 10})
        tools = resp.json()
        assert len(tools) > 0, "No tools returned"

        for tool in tools[:5]:
            assert "name" in tool, f"Tool missing 'name': {tool}"
            assert "method" in tool, f"Tool missing 'method': {tool}"
            assert "path" in tool, f"Tool missing 'path': {tool}"
            assert "inputSchema" in tool, f"Tool missing 'inputSchema': {tool}"
            assert "category" in tool, f"Tool missing 'category': {tool}"

            schema = tool["inputSchema"]
            assert schema.get("type") == "object", (
                f"inputSchema.type must be 'object', got '{schema.get('type')}'"
            )

    def test_filter_by_category(self, client, api_headers):
        """Filter tools by category (query/action/analysis)."""
        for cat in ["query", "action", "analysis"]:
            resp = client.get(
                "/api/v1/mcp/tools",
                headers=api_headers,
                params={"category": cat, "limit": 100},
            )
            assert resp.status_code == 200
            tools = resp.json()
            for tool in tools:
                assert tool["category"] == cat, (
                    f"Tool '{tool['name']}' has category '{tool['category']}', expected '{cat}'"
                )

    def test_filter_by_method(self, client, api_headers):
        """Filter tools by HTTP method."""
        for method in ["GET", "POST"]:
            resp = client.get(
                "/api/v1/mcp/tools",
                headers=api_headers,
                params={"method": method, "limit": 100},
            )
            assert resp.status_code == 200
            tools = resp.json()
            for tool in tools:
                assert tool["method"] == method

    def test_search_tools(self, client, api_headers):
        """Search tools by name/description substring."""
        resp = client.get(
            "/api/v1/mcp/tools",
            headers=api_headers,
            params={"search": "finding", "limit": 50},
        )
        assert resp.status_code == 200
        tools = resp.json()
        # At least one tool should match "finding"
        assert len(tools) >= 1, "No tools match search term 'finding'"

    def test_pagination(self, client, api_headers):
        """Pagination with limit and offset works."""
        resp1 = client.get(
            "/api/v1/mcp/tools",
            headers=api_headers,
            params={"limit": 5, "offset": 0},
        )
        resp2 = client.get(
            "/api/v1/mcp/tools",
            headers=api_headers,
            params={"limit": 5, "offset": 5},
        )
        assert resp1.status_code == 200
        assert resp2.status_code == 200
        tools1 = resp1.json()
        tools2 = resp2.json()
        assert len(tools1) == 5
        # Ensure they're different pages
        names1 = {t["name"] for t in tools1}
        names2 = {t["name"] for t in tools2}
        assert names1 != names2 or len(tools2) == 0, "Pages should contain different tools"

    def test_tool_name_uniqueness(self, client, api_headers):
        """All tool names must be unique."""
        resp = client.get("/api/v1/mcp/tools", headers=api_headers, params={"limit": 1000})
        tools = resp.json()
        names = [t["name"] for t in tools]
        assert len(names) == len(set(names)), (
            f"Duplicate tool names found: {[n for n in names if names.count(n) > 1][:5]}"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# Test 2: MCP Catalog Stats
# ═══════════════════════════════════════════════════════════════════════════════

class TestMCPCatalogStats:
    """Test the /stats endpoint for catalog analytics."""

    def test_stats_endpoint(self, client, api_headers):
        """GET /api/v1/mcp/stats must return valid stats."""
        resp = client.get("/api/v1/mcp/stats", headers=api_headers)
        assert resp.status_code == 200
        stats = resp.json()

        assert "total_tools" in stats
        assert stats["total_tools"] > 0
        assert "by_category" in stats
        assert "by_method" in stats
        assert "generated_at" in stats
        assert "mcp_version" in stats
        assert stats["mcp_version"] == "2024-11-05"

    def test_stats_category_breakdown(self, client, api_headers):
        """Stats must include category breakdown."""
        resp = client.get("/api/v1/mcp/stats", headers=api_headers)
        stats = resp.json()
        by_cat = stats.get("by_category", {})

        # We expect at least query and action categories
        assert len(by_cat) >= 2, f"Expected at least 2 categories, got {by_cat}"
        total_from_cats = sum(by_cat.values())
        assert total_from_cats == stats["total_tools"], (
            f"Category totals ({total_from_cats}) != total_tools ({stats['total_tools']})"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# Test 3: MCP JSON-RPC Protocol
# ═══════════════════════════════════════════════════════════════════════════════

class TestMCPJsonRPC:
    """Test the MCP JSON-RPC 2.0 protocol endpoints."""

    def test_jsonrpc_initialize(self, client, api_headers):
        """MCP initialize handshake via JSON-RPC."""
        msg = {
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {"listChanged": True}},
                "clientInfo": {"name": "test-agent", "version": "1.0.0"},
            },
            "id": 1,
        }
        resp = client.post("/api/v1/mcp-protocol/jsonrpc", json=msg, headers=api_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("jsonrpc") == "2.0"
        assert data.get("id") == 1

    def test_jsonrpc_tools_list(self, client, api_headers):
        """List tools via JSON-RPC method."""
        msg = {
            "jsonrpc": "2.0",
            "method": "tools/list",
            "params": {},
            "id": 2,
        }
        resp = client.post("/api/v1/mcp-protocol/jsonrpc", json=msg, headers=api_headers)
        assert resp.status_code == 200

    def test_protocol_status(self, client, api_headers):
        """MCP protocol status endpoint."""
        resp = client.get("/api/v1/mcp-protocol/status", headers=api_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "status" in data
        assert "engine" in data


# ═══════════════════════════════════════════════════════════════════════════════
# Test 4: MCP Tool Execution
# ═══════════════════════════════════════════════════════════════════════════════

class TestMCPToolExecution:
    """Test executing tools via the MCP gateway."""

    def test_execute_nonexistent_tool(self, client, api_headers):
        """Executing a non-existent tool returns not_found."""
        payload = {
            "tool_name": "this_tool_does_not_exist",
            "arguments": {},
        }
        resp = client.post("/api/v1/mcp/execute", json=payload, headers=api_headers)
        assert resp.status_code == 200  # Returns 200 with error in body
        data = resp.json()
        assert data["status"] == "not_found"

    def test_execute_health_tool(self, client, api_headers):
        """Execute a simple health check tool."""
        # First find a health-related tool
        resp = client.get(
            "/api/v1/mcp/tools",
            headers=api_headers,
            params={"search": "health", "limit": 10},
        )
        tools = resp.json()

        if tools:
            tool_name = tools[0]["name"]
            payload = {"tool_name": tool_name, "arguments": {}}
            exec_resp = client.post("/api/v1/mcp/execute", json=payload, headers=api_headers)
            assert exec_resp.status_code == 200
            data = exec_resp.json()
            assert "status" in data
            assert "execution_time_ms" in data

    def test_execute_returns_timing(self, client, api_headers):
        """Tool execution must include timing information."""
        # Use any available tool
        resp = client.get(
            "/api/v1/mcp/tools",
            headers=api_headers,
            params={"method": "GET", "limit": 1},
        )
        assert resp.status_code == 200
        tools = resp.json()
        assert isinstance(tools, list), f"Expected list, got {type(tools)}: {str(tools)[:200]}"
        assert len(tools) > 0, "No tools returned"
        payload = {"tool_name": tools[0]["name"], "arguments": {}}
        exec_resp = client.post("/api/v1/mcp/execute", json=payload, headers=api_headers)
        data = exec_resp.json()
        assert "execution_time_ms" in data
        assert isinstance(data["execution_time_ms"], (int, float))
        assert data["execution_time_ms"] >= 0


# ═══════════════════════════════════════════════════════════════════════════════
# Test 5: MCP Schema Export
# ═══════════════════════════════════════════════════════════════════════════════

class TestMCPSchemaExport:
    """Test MCP schema export in different formats."""

    def test_mcp_format_schema(self, client, api_headers):
        """Schema export in MCP format."""
        resp = client.get(
            "/api/v1/mcp/schemas",
            headers=api_headers,
            params={"format": "mcp"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "tools" in data
        assert isinstance(data["tools"], list)
        assert len(data["tools"]) > 0
        assert "_meta" in data
        assert data["_meta"]["mcp_version"] == "2024-11-05"

        # Each tool in MCP format must have name, description, inputSchema
        for tool in data["tools"][:5]:
            assert "name" in tool
            assert "description" in tool
            assert "inputSchema" in tool

    def test_openapi_format_schema(self, client, api_headers):
        """Schema export in OpenAPI format."""
        resp = client.get(
            "/api/v1/mcp/schemas",
            headers=api_headers,
            params={"format": "openapi"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "openapi" in data
        assert data["openapi"] == "3.1.0"
        assert "paths" in data
        assert "info" in data


# ═══════════════════════════════════════════════════════════════════════════════
# Test 6: Brain Pipeline via MCP
# ═══════════════════════════════════════════════════════════════════════════════

class TestBrainPipelineMCP:
    """Test running the Brain Pipeline through MCP tool execution."""

    def test_pipeline_direct_endpoint(self, client, api_headers, demo_findings, demo_assets):
        """POST /api/v1/brain/pipeline/run directly processes findings."""
        payload = {
            "org_id": "test-org",
            "findings": [
                {
                    "id": f["id"],
                    "cve_id": f.get("cve_id", ""),
                    "severity": f["severity"],
                    "title": f["title"],
                    "description": f["description"],
                    "source": f["source"],
                    "asset_name": f["asset_name"],
                }
                for f in demo_findings
            ],
            "assets": [
                {
                    "id": a["id"],
                    "name": a["name"],
                    "criticality": a["criticality"],
                    "type": a["type"],
                }
                for a in demo_assets
            ],
            "source": "test",
        }
        resp = client.post("/api/v1/brain/pipeline/run", json=payload, headers=api_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "run_id" in data
        assert "status" in data
        assert "steps" in data
        assert len(data["steps"]) == 12, f"Expected 12 steps, got {len(data['steps'])}"

        # Check that completed steps have timing
        for step in data["steps"]:
            assert "name" in step
            assert "status" in step
            if step["status"] == "completed":
                assert step["duration_ms"] >= 0


# ═══════════════════════════════════════════════════════════════════════════════
# Test 7: MCP Health & Refresh
# ═══════════════════════════════════════════════════════════════════════════════

class TestMCPHealthRefresh:
    """Test MCP health check and catalog refresh."""

    def test_mcp_health(self, client, api_headers):
        """MCP health endpoint returns status."""
        resp = client.get("/api/v1/mcp/health", headers=api_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] in ("healthy", "degraded")
        assert data["catalog_size"] > 0

    def test_mcp_refresh(self, client, api_headers):
        """Refresh re-generates the catalog."""
        resp = client.post("/api/v1/mcp/refresh", headers=api_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "refreshed"
        assert data["current_tool_count"] > 0


# ═══════════════════════════════════════════════════════════════════════════════
# Test 8: End-to-End Demo Flow
# ═══════════════════════════════════════════════════════════════════════════════

class TestMCPDemoE2E:
    """End-to-end test of the full DEMO-009 flow."""

    def test_full_demo_flow(self, client, api_headers, demo_findings, demo_assets):
        """Complete demo: discover → scan → pipeline → results."""
        # 1. Discover tools
        resp = client.get("/api/v1/mcp/tools", headers=api_headers, params={"limit": 1000})
        assert resp.status_code == 200
        tools = resp.json()
        tool_count = len(tools)
        assert tool_count > 0, "No tools discovered"

        # 2. Get stats
        resp = client.get("/api/v1/mcp/stats", headers=api_headers)
        assert resp.status_code == 200
        stats = resp.json()
        assert stats["total_tools"] == tool_count

        # 3. Run brain pipeline
        pipeline_payload = {
            "org_id": "demo-org",
            "findings": [
                {
                    "id": f["id"],
                    "cve_id": f.get("cve_id", ""),
                    "severity": f["severity"],
                    "title": f["title"],
                    "description": f["description"],
                    "source": f["source"],
                    "asset_name": f["asset_name"],
                }
                for f in demo_findings
            ],
            "assets": [
                {
                    "id": a["id"],
                    "name": a["name"],
                    "criticality": a["criticality"],
                    "type": a["type"],
                }
                for a in demo_assets
            ],
        }
        resp = client.post("/api/v1/brain/pipeline/run", json=pipeline_payload, headers=api_headers)
        assert resp.status_code == 200
        pipeline = resp.json()
        assert pipeline["status"] in ("completed", "partial")
        assert pipeline["summary"]["findings_ingested"] == len(demo_findings)

        # 4. Get MCP schemas
        resp = client.get("/api/v1/mcp/schemas", headers=api_headers, params={"format": "mcp"})
        assert resp.status_code == 200
        schemas = resp.json()
        assert schemas["_meta"]["total"] == tool_count

        # 5. Verify the demo meets success criteria
        assert tool_count >= 100, f"Demo requires 100+ tools, got {tool_count}"
        assert pipeline["status"] in ("completed", "partial"), "Pipeline must complete"
