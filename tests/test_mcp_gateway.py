"""
Tests for MCPGateway — External AI Agent Interface (suite-core/core/mcp_gateway.py)
and the FastAPI router (suite-api/apps/api/mcp_gateway_router.py).

Covers:
- MCPTool Pydantic model
- MCPResponse helpers (ok / error)
- MCPGateway.register_tool() — success and duplicate rejection
- MCPGateway.list_tools()
- MCPGateway.call_tool() — success, unknown tool, handler exception
- MCPGateway.get_schema()
- MCPGateway.get_call_log()
- All 8 built-in tool handlers — return shape validation
- get_mcp_gateway() singleton
- FastAPI router: GET /tools, POST /call, GET /schema, GET /health

Run with:
    python -m pytest tests/test_mcp_gateway.py -v --timeout=10
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

# Ensure suite-core and suite-api are importable
_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT / "suite-core"))
sys.path.insert(0, str(_ROOT / "suite-api"))

from core.mcp_gateway import (
    MCPGateway,
    MCPResponse,
    MCPTool,
    get_mcp_gateway,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture()
def gateway() -> MCPGateway:
    """Fresh MCPGateway (not the singleton) for each test."""
    return MCPGateway()


# ============================================================================
# MCPTool model
# ============================================================================


class TestMCPTool:
    def test_basic_construction(self) -> None:
        tool = MCPTool(
            name="my_tool",
            description="Does something useful",
            input_schema={"type": "object", "properties": {}},
            handler="module.my_tool",
        )
        assert tool.name == "my_tool"
        assert tool.description == "Does something useful"
        assert tool.handler == "module.my_tool"
        assert isinstance(tool.input_schema, dict)

    def test_default_input_schema(self) -> None:
        tool = MCPTool(name="t", description="d", handler="h")
        assert tool.input_schema == {}

    def test_serialisation(self) -> None:
        tool = MCPTool(name="t", description="d", handler="h")
        data = tool.model_dump()
        assert "name" in data
        assert "description" in data
        assert "input_schema" in data
        assert "handler" in data


# ============================================================================
# MCPResponse model
# ============================================================================


class TestMCPResponse:
    def test_ok_response(self) -> None:
        resp = MCPResponse.ok("all good")
        assert resp.is_error is False
        assert len(resp.content) == 1
        assert resp.content[0]["type"] == "text"
        assert resp.content[0]["text"] == "all good"

    def test_ok_response_with_data(self) -> None:
        resp = MCPResponse.ok("result", data={"score": 99})
        assert resp.is_error is False
        assert resp.content[0]["data"] == {"score": 99}

    def test_error_response(self) -> None:
        resp = MCPResponse.error("something failed")
        assert resp.is_error is True
        assert resp.content[0]["text"] == "something failed"

    def test_default_construction(self) -> None:
        resp = MCPResponse()
        assert resp.is_error is False
        assert resp.content == []

    def test_serialisation(self) -> None:
        resp = MCPResponse.ok("hi")
        data = resp.model_dump()
        assert "content" in data
        assert "is_error" in data


# ============================================================================
# MCPGateway.register_tool
# ============================================================================


class TestGatewayRegisterTool:
    def test_register_custom_tool(self, gateway: MCPGateway) -> None:
        initial_count = len(gateway.list_tools())

        def my_handler(value: int = 0) -> Dict[str, Any]:
            return {"value": value * 2}

        tool = gateway.register_tool(
            name="double_value",
            description="Doubles an integer",
            schema={"type": "object", "properties": {"value": {"type": "integer"}}},
            handler=my_handler,
        )
        assert isinstance(tool, MCPTool)
        assert tool.name == "double_value"
        assert len(gateway.list_tools()) == initial_count + 1

    def test_duplicate_raises(self, gateway: MCPGateway) -> None:
        def noop(**kwargs: Any) -> None:
            pass

        gateway.register_tool("unique_name", "desc", {}, noop)
        with pytest.raises(ValueError, match="already registered"):
            gateway.register_tool("unique_name", "desc2", {}, noop)

    def test_handler_stored_and_callable(self, gateway: MCPGateway) -> None:
        def ping() -> str:
            return "pong"

        gateway.register_tool("ping_tool", "Ping", {}, ping)
        result = gateway.call_tool("ping_tool", {})
        assert result.is_error is False
        assert "pong" in result.content[0]["text"]


# ============================================================================
# MCPGateway.list_tools
# ============================================================================


class TestGatewayListTools:
    def test_returns_list(self, gateway: MCPGateway) -> None:
        tools = gateway.list_tools()
        assert isinstance(tools, list)

    def test_built_in_tools_present(self, gateway: MCPGateway) -> None:
        names = {t.name for t in gateway.list_tools()}
        expected = {
            "search_findings",
            "get_posture_score",
            "get_compliance_status",
            "analyze_risk",
            "get_attack_surface",
            "run_scan",
            "get_threat_intel",
            "ask_copilot",
        }
        assert expected == names

    def test_all_tools_have_required_fields(self, gateway: MCPGateway) -> None:
        for tool in gateway.list_tools():
            assert tool.name
            assert tool.description
            assert isinstance(tool.input_schema, dict)
            assert tool.handler


# ============================================================================
# MCPGateway.call_tool
# ============================================================================


class TestGatewayCallTool:
    def test_unknown_tool_returns_error(self, gateway: MCPGateway) -> None:
        result = gateway.call_tool("nonexistent_tool", {})
        assert result.is_error is True
        assert "nonexistent_tool" in result.content[0]["text"]

    def test_handler_exception_returns_error(self, gateway: MCPGateway) -> None:
        def boom(**kwargs: Any) -> None:
            raise RuntimeError("handler exploded")

        gateway.register_tool("boom_tool", "explodes", {}, boom)
        result = gateway.call_tool("boom_tool", {})
        assert result.is_error is True
        assert "boom_tool" in result.content[0]["text"]

    def test_dict_result_serialised(self, gateway: MCPGateway) -> None:
        def get_data(**kwargs: Any) -> Dict[str, Any]:
            return {"key": "value", "num": 42}

        gateway.register_tool("data_tool", "returns dict", {}, get_data)
        result = gateway.call_tool("data_tool", {})
        assert result.is_error is False
        assert "key" in result.content[0]["text"]

    def test_mcp_response_passthrough(self, gateway: MCPGateway) -> None:
        def returns_response(**kwargs: Any) -> MCPResponse:
            return MCPResponse.ok("custom response")

        gateway.register_tool("resp_tool", "returns MCPResponse", {}, returns_response)
        result = gateway.call_tool("resp_tool", {})
        assert result.is_error is False
        assert result.content[0]["text"] == "custom response"

    def test_string_result(self, gateway: MCPGateway) -> None:
        def returns_str(**kwargs: Any) -> str:
            return "hello world"

        gateway.register_tool("str_tool", "returns string", {}, returns_str)
        result = gateway.call_tool("str_tool", {})
        assert result.is_error is False
        assert "hello world" in result.content[0]["text"]

    def test_arguments_passed_to_handler(self, gateway: MCPGateway) -> None:
        received: Dict[str, Any] = {}

        def capture(**kwargs: Any) -> str:
            received.update(kwargs)
            return "ok"

        gateway.register_tool("capture_tool", "captures args", {}, capture)
        gateway.call_tool("capture_tool", {"foo": "bar", "num": 7})
        assert received["foo"] == "bar"
        assert received["num"] == 7


# ============================================================================
# MCPGateway.get_schema
# ============================================================================


class TestGatewayGetSchema:
    def test_schema_structure(self, gateway: MCPGateway) -> None:
        schema = gateway.get_schema()
        assert schema["gateway"] == "aldeci-mcp-gateway"
        assert schema["version"] == "1.0.0"
        assert schema["protocol"] == "mcp-2025"
        assert isinstance(schema["tools"], list)

    def test_schema_tools_have_correct_keys(self, gateway: MCPGateway) -> None:
        schema = gateway.get_schema()
        for tool_def in schema["tools"]:
            assert "name" in tool_def
            assert "description" in tool_def
            assert "inputSchema" in tool_def

    def test_schema_tool_count_matches_list(self, gateway: MCPGateway) -> None:
        schema = gateway.get_schema()
        assert len(schema["tools"]) == len(gateway.list_tools())


# ============================================================================
# MCPGateway.get_call_log
# ============================================================================


class TestGatewayCallLog:
    def test_log_records_successful_call(self, gateway: MCPGateway) -> None:
        gateway.call_tool("search_findings", {"query": "log4j"})
        log = gateway.get_call_log()
        assert len(log) >= 1
        last = log[-1]
        assert last["tool"] == "search_findings"
        assert last["success"] is True

    def test_log_records_failed_call(self, gateway: MCPGateway) -> None:
        def boom(**kwargs: Any) -> None:
            raise ValueError("oops")

        gateway.register_tool("log_boom", "boom", {}, boom)
        gateway.call_tool("log_boom", {})
        log = gateway.get_call_log()
        failures = [e for e in log if e["tool"] == "log_boom"]
        assert failures
        assert failures[-1]["success"] is False

    def test_log_limit(self, gateway: MCPGateway) -> None:
        for _ in range(5):
            gateway.call_tool("search_findings", {"query": "test"})
        log = gateway.get_call_log(limit=2)
        assert len(log) <= 2


# ============================================================================
# Built-in tool handlers
# ============================================================================


class TestBuiltinSearchFindings:
    def test_returns_dict(self, gateway: MCPGateway) -> None:
        result = gateway.call_tool("search_findings", {"query": "sql injection"})
        assert result.is_error is False
        assert len(result.content) > 0

    def test_with_severity(self, gateway: MCPGateway) -> None:
        result = gateway.call_tool(
            "search_findings", {"query": "xss", "severity": "critical"}
        )
        assert result.is_error is False

    def test_content_has_data_key(self, gateway: MCPGateway) -> None:
        result = gateway.call_tool("search_findings", {"query": "rce"})
        # content[0] should have either 'data' key or json text
        assert result.content[0]["type"] == "text"


class TestBuiltinGetPostureScore:
    def test_returns_score(self, gateway: MCPGateway) -> None:
        result = gateway.call_tool("get_posture_score", {"org_id": "org_abc"})
        assert result.is_error is False

    def test_without_breakdown(self, gateway: MCPGateway) -> None:
        result = gateway.call_tool(
            "get_posture_score", {"org_id": "org_abc", "include_breakdown": False}
        )
        assert result.is_error is False


class TestBuiltinGetComplianceStatus:
    @pytest.mark.parametrize(
        "framework",
        ["SOC2", "ISO27001", "HIPAA", "PCI-DSS", "GDPR", "NIST-CSF", "CIS"],
    )
    def test_all_frameworks(self, gateway: MCPGateway, framework: str) -> None:
        result = gateway.call_tool("get_compliance_status", {"framework": framework})
        assert result.is_error is False

    def test_with_org_id(self, gateway: MCPGateway) -> None:
        result = gateway.call_tool(
            "get_compliance_status", {"framework": "SOC2", "org_id": "org_xyz"}
        )
        assert result.is_error is False


class TestBuiltinAnalyzeRisk:
    def test_returns_analysis(self, gateway: MCPGateway) -> None:
        result = gateway.call_tool("analyze_risk", {"asset_id": "api-gateway"})
        assert result.is_error is False

    def test_without_attack_paths(self, gateway: MCPGateway) -> None:
        result = gateway.call_tool(
            "analyze_risk",
            {"asset_id": "auth-service", "include_attack_paths": False},
        )
        assert result.is_error is False


class TestBuiltinGetAttackSurface:
    def test_returns_summary(self, gateway: MCPGateway) -> None:
        result = gateway.call_tool("get_attack_surface", {"org_id": "org_001"})
        assert result.is_error is False

    def test_without_services(self, gateway: MCPGateway) -> None:
        result = gateway.call_tool(
            "get_attack_surface", {"org_id": "org_001", "include_services": False}
        )
        assert result.is_error is False


class TestBuiltinRunScan:
    @pytest.mark.parametrize(
        "scan_type",
        ["sast", "dast", "container", "dependency", "secret", "iac", "api"],
    )
    def test_all_scan_types(self, gateway: MCPGateway, scan_type: str) -> None:
        result = gateway.call_tool(
            "run_scan", {"target": "github.com/org/repo", "scan_type": scan_type}
        )
        assert result.is_error is False

    def test_sync_scan(self, gateway: MCPGateway) -> None:
        result = gateway.call_tool(
            "run_scan",
            {"target": "myapp:latest", "scan_type": "container", "async_run": False},
        )
        assert result.is_error is False


class TestBuiltinGetThreatIntel:
    def test_returns_results(self, gateway: MCPGateway) -> None:
        result = gateway.call_tool("get_threat_intel", {"query": "log4j"})
        assert result.is_error is False

    def test_with_entity_type(self, gateway: MCPGateway) -> None:
        result = gateway.call_tool(
            "get_threat_intel", {"query": "apache", "entity_type": "CVE"}
        )
        assert result.is_error is False


class TestBuiltinAskCopilot:
    def test_returns_answer(self, gateway: MCPGateway) -> None:
        result = gateway.call_tool(
            "ask_copilot",
            {"question": "What are the critical findings in my environment?"},
        )
        assert result.is_error is False

    def test_with_agent_type(self, gateway: MCPGateway) -> None:
        result = gateway.call_tool(
            "ask_copilot",
            {
                "question": "Are we SOC2 compliant?",
                "agent_type": "compliance",
                "context": {"org_id": "org_test"},
            },
        )
        assert result.is_error is False


# ============================================================================
# Singleton
# ============================================================================


class TestSingleton:
    def test_get_mcp_gateway_returns_instance(self) -> None:
        gw = get_mcp_gateway()
        assert isinstance(gw, MCPGateway)

    def test_get_mcp_gateway_is_idempotent(self) -> None:
        gw1 = get_mcp_gateway()
        gw2 = get_mcp_gateway()
        assert gw1 is gw2


# ============================================================================
# FastAPI Router tests
# ============================================================================


class TestMCPGatewayRouter:
    """Tests for the FastAPI router endpoints using TestClient."""

    @pytest.fixture()
    def client(self) -> Any:
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from apps.api.mcp_gateway_router import router

        app = FastAPI()
        app.include_router(router)
        return TestClient(app)

    def test_health_ok(self, client: Any) -> None:
        resp = client.get("/api/v1/mcp-gateway/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] in ("ok", "degraded")
        assert "tool_count" in data
        assert "gateway_available" in data

    def test_list_tools(self, client: Any) -> None:
        resp = client.get("/api/v1/mcp-gateway/tools")
        assert resp.status_code == 200
        data = resp.json()
        assert "tools" in data
        assert "count" in data
        assert data["count"] == len(data["tools"])

    def test_list_tools_includes_builtin(self, client: Any) -> None:
        resp = client.get("/api/v1/mcp-gateway/tools")
        assert resp.status_code == 200
        names = {t["name"] for t in resp.json()["tools"]}
        assert "search_findings" in names
        assert "ask_copilot" in names

    def test_get_schema(self, client: Any) -> None:
        resp = client.get("/api/v1/mcp-gateway/schema")
        assert resp.status_code == 200
        data = resp.json()
        assert data["gateway"] == "aldeci-mcp-gateway"
        assert "tools" in data
        assert "tool_count" in data
        assert data["tool_count"] == len(data["tools"])

    def test_schema_tools_have_input_schema(self, client: Any) -> None:
        resp = client.get("/api/v1/mcp-gateway/schema")
        for tool in resp.json()["tools"]:
            assert "name" in tool
            assert "description" in tool
            assert "inputSchema" in tool

    def test_call_tool_search_findings(self, client: Any) -> None:
        resp = client.post(
            "/api/v1/mcp-gateway/call",
            json={"name": "search_findings", "arguments": {"query": "log4j"}},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "search_findings"
        assert isinstance(data["content"], list)
        assert data["is_error"] is False

    def test_call_tool_get_posture_score(self, client: Any) -> None:
        resp = client.post(
            "/api/v1/mcp-gateway/call",
            json={"name": "get_posture_score", "arguments": {"org_id": "org_test"}},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["is_error"] is False

    def test_call_tool_unknown(self, client: Any) -> None:
        resp = client.post(
            "/api/v1/mcp-gateway/call",
            json={"name": "does_not_exist", "arguments": {}},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["is_error"] is True
        assert "does_not_exist" in data["content"][0]["text"]

    def test_call_tool_run_scan(self, client: Any) -> None:
        resp = client.post(
            "/api/v1/mcp-gateway/call",
            json={
                "name": "run_scan",
                "arguments": {"target": "myapp:latest", "scan_type": "container"},
            },
        )
        assert resp.status_code == 200
        assert resp.json()["is_error"] is False

    def test_call_tool_get_compliance_status(self, client: Any) -> None:
        resp = client.post(
            "/api/v1/mcp-gateway/call",
            json={
                "name": "get_compliance_status",
                "arguments": {"framework": "SOC2"},
            },
        )
        assert resp.status_code == 200
        assert resp.json()["is_error"] is False

    def test_call_tool_ask_copilot(self, client: Any) -> None:
        resp = client.post(
            "/api/v1/mcp-gateway/call",
            json={
                "name": "ask_copilot",
                "arguments": {"question": "What is our risk posture?"},
            },
        )
        assert resp.status_code == 200
        assert resp.json()["is_error"] is False

    def test_call_tool_get_threat_intel(self, client: Any) -> None:
        resp = client.post(
            "/api/v1/mcp-gateway/call",
            json={"name": "get_threat_intel", "arguments": {"query": "ransomware"}},
        )
        assert resp.status_code == 200
        assert resp.json()["is_error"] is False

    def test_call_tool_analyze_risk(self, client: Any) -> None:
        resp = client.post(
            "/api/v1/mcp-gateway/call",
            json={"name": "analyze_risk", "arguments": {"asset_id": "db-primary"}},
        )
        assert resp.status_code == 200
        assert resp.json()["is_error"] is False

    def test_call_tool_get_attack_surface(self, client: Any) -> None:
        resp = client.post(
            "/api/v1/mcp-gateway/call",
            json={"name": "get_attack_surface", "arguments": {"org_id": "org_001"}},
        )
        assert resp.status_code == 200
        assert resp.json()["is_error"] is False

    def test_health_timestamp_present(self, client: Any) -> None:
        resp = client.get("/api/v1/mcp-gateway/health")
        assert "timestamp" in resp.json()

    def test_tools_timestamp_present(self, client: Any) -> None:
        resp = client.get("/api/v1/mcp-gateway/tools")
        assert "timestamp" in resp.json()
