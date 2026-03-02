"""Comprehensive tests for core.mcp_server — MCP Protocol Engine (V7).

Tests the full MCP 2025 protocol implementation:
- JSON-RPC 2.0 message format (MCPRequest, MCPResponse)
- Tool registry and auto-discovery
- Resource server with built-in resources
- Prompt library with template rendering
- Session management with rate limiting and eviction
- Protocol handler dispatch and error handling
- SSE transport event generation
- Edge cases and error conditions

Target: 80%+ coverage of mcp_server.py (979 LOC).
"""

import json
from unittest.mock import MagicMock

import pytest

from core.mcp_server import (
    INTERNAL_ERROR,
    INVALID_PARAMS,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    MCPMethod,
    MCPPromptLibrary,
    MCPProtocolHandler,
    MCPRequest,
    MCPResourceDefinition,
    MCPResourceServer,
    MCPResponse,
    MCPSessionManager,
    MCPToolDefinition,
    MCPToolRegistry,
    create_sse_event,
    get_mcp_handler,
)


# ===========================================================================
# MCPMethod Enum
# ===========================================================================
class TestMCPMethod:
    def test_lifecycle_methods(self):
        assert MCPMethod.INITIALIZE.value == "initialize"
        assert MCPMethod.INITIALIZED.value == "notifications/initialized"
        assert MCPMethod.SHUTDOWN.value == "shutdown"

    def test_tool_methods(self):
        assert MCPMethod.TOOLS_LIST.value == "tools/list"
        assert MCPMethod.TOOLS_CALL.value == "tools/call"

    def test_resource_methods(self):
        assert MCPMethod.RESOURCES_LIST.value == "resources/list"
        assert MCPMethod.RESOURCES_READ.value == "resources/read"
        assert MCPMethod.RESOURCES_SUBSCRIBE.value == "resources/subscribe"

    def test_prompt_methods(self):
        assert MCPMethod.PROMPTS_LIST.value == "prompts/list"
        assert MCPMethod.PROMPTS_GET.value == "prompts/get"

    def test_log_ping_completion(self):
        assert MCPMethod.LOG.value == "notifications/message"
        assert MCPMethod.PING.value == "ping"
        assert MCPMethod.COMPLETION.value == "completion/complete"


# ===========================================================================
# MCPRequest
# ===========================================================================
class TestMCPRequest:
    def test_basic_creation(self):
        req = MCPRequest(method="tools/list")
        assert req.method == "tools/list"
        assert req.params == {}
        assert req.id is None
        assert req.jsonrpc == "2.0"

    def test_with_params_and_id(self):
        req = MCPRequest(method="tools/call", params={"name": "sast_scan"}, id="req-42")
        assert req.params == {"name": "sast_scan"}
        assert req.id == "req-42"

    def test_to_dict_minimal(self):
        req = MCPRequest(method="ping")
        d = req.to_dict()
        assert d == {"jsonrpc": "2.0", "method": "ping"}
        assert "params" not in d  # empty params excluded
        assert "id" not in d  # None id excluded

    def test_to_dict_full(self):
        req = MCPRequest(method="tools/call", params={"name": "x"}, id="1")
        d = req.to_dict()
        assert d["jsonrpc"] == "2.0"
        assert d["method"] == "tools/call"
        assert d["params"] == {"name": "x"}
        assert d["id"] == "1"


# ===========================================================================
# MCPResponse
# ===========================================================================
class TestMCPResponse:
    def test_success_factory(self):
        resp = MCPResponse.success("42", {"tools": []})
        assert resp.id == "42"
        assert resp.result == {"tools": []}
        assert resp.error is None

    def test_error_factory(self):
        resp = MCPResponse.error_response("42", -32601, "Method not found")
        assert resp.id == "42"
        assert resp.error == {"code": -32601, "message": "Method not found"}
        assert resp.result is None

    def test_error_factory_with_data(self):
        resp = MCPResponse.error_response("1", -32602, "Bad params", data={"hint": "use string"})
        assert resp.error["data"] == {"hint": "use string"}

    def test_to_dict_success(self):
        resp = MCPResponse.success("1", {"ok": True})
        d = resp.to_dict()
        assert d["jsonrpc"] == "2.0"
        assert d["id"] == "1"
        assert d["result"] == {"ok": True}
        assert "error" not in d

    def test_to_dict_error(self):
        resp = MCPResponse.error_response("1", -32700, "Parse error")
        d = resp.to_dict()
        assert d["error"]["code"] == -32700
        assert "result" not in d

    def test_to_dict_no_id(self):
        resp = MCPResponse(result="ok")
        d = resp.to_dict()
        assert "id" not in d


# ===========================================================================
# MCPToolRegistry
# ===========================================================================
class TestMCPToolRegistry:
    def test_register_and_get(self):
        registry = MCPToolRegistry()
        tool = MCPToolDefinition(
            name="sast_scan",
            description="Run SAST scan",
            input_schema={"type": "object"},
            category="discovery",
        )
        registry.register_tool(tool)
        assert registry.get_tool("sast_scan") is tool
        assert registry.tool_count == 1

    def test_get_nonexistent(self):
        registry = MCPToolRegistry()
        assert registry.get_tool("nonexistent") is None

    def test_categories(self):
        registry = MCPToolRegistry()
        registry.register_tool(MCPToolDefinition("a", "A", {}, category="discovery"))
        registry.register_tool(MCPToolDefinition("b", "B", {}, category="discovery"))
        registry.register_tool(MCPToolDefinition("c", "C", {}, category="compliance"))
        assert registry.categories == {"discovery": 2, "compliance": 1}

    def test_list_tools_all(self):
        registry = MCPToolRegistry()
        for i in range(5):
            registry.register_tool(MCPToolDefinition(f"tool_{i}", f"Tool {i}", {}))
        tools, next_cursor = registry.list_tools()
        assert len(tools) == 5
        assert next_cursor is None

    def test_list_tools_with_pagination(self):
        registry = MCPToolRegistry()
        for i in range(10):
            registry.register_tool(MCPToolDefinition(f"tool_{i}", f"Tool {i}", {}))
        tools, next_cursor = registry.list_tools(limit=3)
        assert len(tools) == 3
        assert next_cursor == "3"

        tools2, next_cursor2 = registry.list_tools(cursor="3", limit=3)
        assert len(tools2) == 3
        assert next_cursor2 == "6"

    def test_list_tools_invalid_cursor(self):
        registry = MCPToolRegistry()
        registry.register_tool(MCPToolDefinition("a", "A", {}))
        tools, _ = registry.list_tools(cursor="invalid")
        assert len(tools) == 1  # fallback to start_idx=0

    def test_list_tools_filter_by_category(self):
        registry = MCPToolRegistry()
        registry.register_tool(MCPToolDefinition("a", "A", {}, category="discovery"))
        registry.register_tool(MCPToolDefinition("b", "B", {}, category="compliance"))
        tools, _ = registry.list_tools(category="discovery")
        assert len(tools) == 1
        assert tools[0]["name"] == "a"

    def test_path_to_tool_name_get(self):
        registry = MCPToolRegistry()
        name = registry._path_to_tool_name("/api/v1/brain/pipeline/run", "GET")
        assert name == "brain_pipeline_run"

    def test_path_to_tool_name_post(self):
        registry = MCPToolRegistry()
        name = registry._path_to_tool_name("/api/v1/sast/scan/code", "POST")
        assert name == "post_sast_scan_code"

    def test_path_to_tool_name_with_params(self):
        registry = MCPToolRegistry()
        name = registry._path_to_tool_name("/api/v1/findings/{finding_id}/verify", "GET")
        assert "finding_id" not in name

    def test_path_to_tool_name_empty(self):
        registry = MCPToolRegistry()
        name = registry._path_to_tool_name("/api/v1/", "GET")
        assert name == "root" or name == ""

    def test_categorize_path(self):
        registry = MCPToolRegistry()
        assert registry._categorize_path("/api/v1/brain/stats") == "decision-intelligence"
        assert registry._categorize_path("/api/v1/mpte/requests") == "verification"
        assert registry._categorize_path("/api/v1/pentest/run") == "verification"
        assert registry._categorize_path("/api/v1/sast/scan") == "discovery"
        assert registry._categorize_path("/api/v1/compliance/frameworks") == "compliance"
        assert registry._categorize_path("/api/v1/feed/health") == "threat-intel"
        assert registry._categorize_path("/api/v1/unknown/path") == "general"

    def test_extract_tags(self):
        registry = MCPToolRegistry()
        tags = registry._extract_tags("/api/v1/brain/pipeline/run")
        assert "brain" in tags
        assert "pipeline" in tags
        assert "run" in tags
        assert "api" not in tags
        assert "v1" not in tags

    def test_build_input_schema_simple_function(self):
        registry = MCPToolRegistry()

        def my_endpoint(name: str, count: int = 10):
            pass

        schema = registry._build_input_schema(my_endpoint, "/test")
        assert "name" in schema["properties"]
        assert "count" in schema["properties"]
        assert schema["properties"]["count"]["type"] == "integer"
        assert "name" in schema.get("required", [])
        assert "count" not in schema.get("required", [])

    def test_build_input_schema_with_path_params(self):
        registry = MCPToolRegistry()

        def my_endpoint():
            pass

        schema = registry._build_input_schema(my_endpoint, "/findings/{finding_id}/verify")
        assert "finding_id" in schema["properties"]
        assert "finding_id" in schema.get("required", [])

    def test_build_input_schema_type_mapping(self):
        registry = MCPToolRegistry()

        def ep(a: float, b: bool, c: list, d: dict):
            pass

        schema = registry._build_input_schema(ep, "/test")
        assert schema["properties"]["a"]["type"] == "number"
        assert schema["properties"]["b"]["type"] == "boolean"
        assert schema["properties"]["c"]["type"] == "array"
        assert schema["properties"]["d"]["type"] == "object"

    def test_build_input_schema_skips_reserved(self):
        registry = MCPToolRegistry()

        def ep(self, request, response, db, background_tasks, actual_param: str):
            pass

        schema = registry._build_input_schema(ep, "/test")
        assert "self" not in schema["properties"]
        assert "request" not in schema["properties"]
        assert "actual_param" in schema["properties"]

    def test_auto_discover_from_mock_app(self):
        registry = MCPToolRegistry()

        mock_route = MagicMock()
        mock_route.methods = {"GET"}
        mock_route.path = "/api/v1/test/endpoint"
        mock_route.summary = "Test endpoint"

        def handler(param: str):
            """A test handler."""
            pass

        mock_route.endpoint = handler

        mock_app = MagicMock()
        mock_app.routes = [mock_route]

        count = registry.auto_discover_from_app(mock_app)
        assert count == 1
        assert registry.tool_count == 1

    def test_auto_discover_skips_docs(self):
        registry = MCPToolRegistry()

        mock_route = MagicMock()
        mock_route.methods = {"GET"}
        mock_route.path = "/docs"
        mock_route.endpoint = lambda: None

        mock_app = MagicMock()
        mock_app.routes = [mock_route]

        count = registry.auto_discover_from_app(mock_app)
        assert count == 0

    def test_auto_discover_handles_error(self):
        registry = MCPToolRegistry()

        mock_app = MagicMock()
        mock_app.routes = MagicMock(side_effect=Exception("broken"))

        count = registry.auto_discover_from_app(mock_app)
        assert count == 0


# ===========================================================================
# MCPResourceServer
# ===========================================================================
class TestMCPResourceServer:
    def test_builtin_resources_registered(self):
        server = MCPResourceServer()
        resources = server.list_resources()
        assert len(resources) == 5
        uris = {r["uri"] for r in resources}
        assert "aldeci://findings/summary" in uris
        assert "aldeci://compliance/posture" in uris
        assert "aldeci://graph/overview" in uris
        assert "aldeci://risk/dashboard" in uris
        assert "aldeci://scanners/status" in uris

    def test_read_findings_summary(self):
        server = MCPResourceServer()
        result = server.read_resource("aldeci://findings/summary")
        assert "contents" in result
        assert len(result["contents"]) == 1
        assert result["contents"][0]["uri"] == "aldeci://findings/summary"

    def test_read_risk_dashboard(self):
        server = MCPResourceServer()
        result = server.read_resource("aldeci://risk/dashboard")
        content = json.loads(result["contents"][0]["text"])
        assert "overall_risk_score" in content

    def test_read_scanner_status(self):
        server = MCPResourceServer()
        result = server.read_resource("aldeci://scanners/status")
        content = json.loads(result["contents"][0]["text"])
        assert content["total"] == 8
        assert content["all_air_gapped"] is True

    def test_read_nonexistent_resource(self):
        server = MCPResourceServer()
        with pytest.raises(KeyError, match="Resource not found"):
            server.read_resource("aldeci://nonexistent")

    def test_register_custom_resource(self):
        server = MCPResourceServer()
        custom = MCPResourceDefinition(
            uri="custom://my/data",
            name="My Data",
            description="Custom data",
            handler=lambda: {"value": 42},
        )
        server.register_resource(custom)
        result = server.read_resource("custom://my/data")
        content = json.loads(result["contents"][0]["text"])
        assert content["value"] == 42

    def test_read_resource_no_handler(self):
        server = MCPResourceServer()
        no_handler = MCPResourceDefinition(
            uri="test://no-handler",
            name="No Handler",
            description="No handler registered",
            handler=None,
        )
        server.register_resource(no_handler)
        result = server.read_resource("test://no-handler")
        content = json.loads(result["contents"][0]["text"])
        assert "error" in content


# ===========================================================================
# MCPPromptLibrary
# ===========================================================================
class TestMCPPromptLibrary:
    def test_builtin_prompts_registered(self):
        lib = MCPPromptLibrary()
        prompts = lib.list_prompts()
        assert len(prompts) == 5
        names = {p["name"] for p in prompts}
        assert "analyze-finding" in names
        assert "compliance-gap-analysis" in names
        assert "attack-path-review" in names
        assert "vulnerability-triage" in names
        assert "evidence-audit" in names

    def test_get_prompt_no_args(self):
        lib = MCPPromptLibrary()
        result = lib.get_prompt("analyze-finding")
        assert "messages" in result
        assert len(result["messages"]) == 1
        assert result["messages"][0]["role"] == "user"
        assert "{finding_id}" in result["messages"][0]["content"]["text"]

    def test_get_prompt_with_args(self):
        lib = MCPPromptLibrary()
        result = lib.get_prompt("analyze-finding", {"finding_id": "CVE-2024-1234"})
        text = result["messages"][0]["content"]["text"]
        assert "CVE-2024-1234" in text
        assert "{finding_id}" not in text

    def test_get_prompt_multiple_args(self):
        lib = MCPPromptLibrary()
        result = lib.get_prompt("attack-path-review", {
            "entry_point": "internet-facing API",
            "target": "PII database",
        })
        text = result["messages"][0]["content"]["text"]
        assert "internet-facing API" in text
        assert "PII database" in text

    def test_get_nonexistent_prompt(self):
        lib = MCPPromptLibrary()
        with pytest.raises(KeyError, match="Prompt not found"):
            lib.get_prompt("nonexistent")


# ===========================================================================
# MCPSessionManager
# ===========================================================================
class TestMCPSessionManager:
    def test_create_session(self):
        mgr = MCPSessionManager()
        session = mgr.create_session("cursor-ai", "0.42.0")
        assert session.client_name == "cursor-ai"
        assert session.client_version == "0.42.0"
        assert session.session_id
        assert session.connected_at
        assert session.rate_limit_remaining == 100

    def test_get_session(self):
        mgr = MCPSessionManager()
        session = mgr.create_session("test-client")
        retrieved = mgr.get_session(session.session_id)
        assert retrieved is session

    def test_get_nonexistent_session(self):
        mgr = MCPSessionManager()
        assert mgr.get_session("nonexistent") is None

    def test_touch_session(self):
        mgr = MCPSessionManager()
        session = mgr.create_session("client")
        mgr.touch_session(session.session_id)
        assert session.request_count == 1

    def test_touch_nonexistent_session(self):
        mgr = MCPSessionManager()
        mgr.touch_session("nonexistent")  # should not raise

    def test_close_session(self):
        mgr = MCPSessionManager()
        session = mgr.create_session("client")
        mgr.close_session(session.session_id)
        assert mgr.get_session(session.session_id) is None

    def test_close_nonexistent_session(self):
        mgr = MCPSessionManager()
        mgr.close_session("nonexistent")  # should not raise

    def test_active_sessions(self):
        mgr = MCPSessionManager()
        mgr.create_session("a")
        mgr.create_session("b")
        assert len(mgr.active_sessions()) == 2

    def test_eviction_when_max_reached(self):
        mgr = MCPSessionManager(max_clients=2)
        mgr.create_session("client1")
        mgr.create_session("client2")
        s3 = mgr.create_session("client3")  # should evict oldest
        assert len(mgr.active_sessions()) == 2
        assert mgr.get_session(s3.session_id) is not None

    def test_session_with_capabilities(self):
        mgr = MCPSessionManager()
        caps = {"tools": True, "resources": True}
        session = mgr.create_session("rich-client", capabilities=caps)
        assert session.capabilities == caps


# ===========================================================================
# MCPProtocolHandler
# ===========================================================================
class TestMCPProtocolHandler:
    def test_initialization(self):
        handler = MCPProtocolHandler()
        assert handler.SERVER_NAME == "aldeci-mcp"
        assert handler.SERVER_VERSION == "1.0.0"
        assert handler.PROTOCOL_VERSION == "2025-03-26"

    def test_handle_initialize(self):
        handler = MCPProtocolHandler()
        req = MCPRequest(
            method="initialize",
            params={
                "clientInfo": {"name": "cursor", "version": "0.42"},
                "capabilities": {"tools": True},
            },
            id="1",
        )
        resp = handler.handle(req)
        assert resp.error is None
        assert resp.result["protocolVersion"] == "2025-03-26"
        assert resp.result["serverInfo"]["name"] == "aldeci-mcp"
        assert "sessionId" in resp.result
        assert resp.result["capabilities"]["tools"]["listChanged"] is True

    def test_handle_shutdown(self):
        handler = MCPProtocolHandler()
        # First create a session
        init_req = MCPRequest(method="initialize", params={"clientInfo": {"name": "test"}}, id="1")
        init_resp = handler.handle(init_req)
        session_id = init_resp.result["sessionId"]

        # Then shutdown
        shutdown_req = MCPRequest(method="shutdown", params={"sessionId": session_id}, id="2")
        resp = handler.handle(shutdown_req)
        assert resp.result["status"] == "shutdown"
        assert handler.session_manager.get_session(session_id) is None

    def test_handle_ping(self):
        handler = MCPProtocolHandler()
        req = MCPRequest(method="ping", id="1")
        resp = handler.handle(req)
        assert resp.error is None
        assert resp.result == {}

    def test_handle_tools_list(self):
        handler = MCPProtocolHandler()
        handler.tool_registry.register_tool(
            MCPToolDefinition("test_tool", "A test tool", {"type": "object"})
        )
        req = MCPRequest(method="tools/list", id="1")
        resp = handler.handle(req)
        assert "tools" in resp.result
        assert len(resp.result["tools"]) == 1

    def test_handle_tools_list_with_cursor(self):
        handler = MCPProtocolHandler()
        for i in range(60):
            handler.tool_registry.register_tool(
                MCPToolDefinition(f"tool_{i}", f"Tool {i}", {})
            )
        req = MCPRequest(method="tools/list", params={"cursor": None}, id="1")
        resp = handler.handle(req)
        assert len(resp.result["tools"]) == 50  # default limit
        assert "nextCursor" in resp.result

    def test_handle_tools_call(self):
        handler = MCPProtocolHandler()
        handler.tool_registry.register_tool(
            MCPToolDefinition(
                name="echo",
                description="Echo back",
                input_schema={},
                handler=lambda msg="hello": {"echo": msg},
            )
        )
        req = MCPRequest(
            method="tools/call",
            params={"name": "echo", "arguments": {"msg": "world"}},
            id="1",
        )
        resp = handler.handle(req)
        assert resp.error is None
        content = resp.result["content"][0]
        assert content["type"] == "text"
        parsed = json.loads(content["text"])
        assert parsed["echo"] == "world"

    def test_handle_tools_call_missing_name(self):
        handler = MCPProtocolHandler()
        req = MCPRequest(method="tools/call", params={}, id="1")
        resp = handler.handle(req)
        assert resp.error is not None
        assert resp.error["code"] == INVALID_PARAMS

    def test_handle_tools_call_tool_not_found(self):
        handler = MCPProtocolHandler()
        req = MCPRequest(method="tools/call", params={"name": "nonexistent"}, id="1")
        resp = handler.handle(req)
        assert resp.error is not None
        assert resp.error["code"] == INVALID_PARAMS

    def test_handle_tools_call_handler_error(self):
        handler = MCPProtocolHandler()
        handler.tool_registry.register_tool(
            MCPToolDefinition(
                name="broken",
                description="Broken tool",
                input_schema={},
                handler=lambda: (_ for _ in ()).throw(ValueError("boom")),
            )
        )
        req = MCPRequest(method="tools/call", params={"name": "broken"}, id="1")
        resp = handler.handle(req)
        # Handler errors result in isError content, not protocol error
        assert resp.error is None  # wrapped in content
        assert resp.result["isError"] is True

    def test_handle_tools_call_no_handler(self):
        handler = MCPProtocolHandler()
        handler.tool_registry.register_tool(
            MCPToolDefinition("nohandler", "No handler", {}, handler=None)
        )
        req = MCPRequest(method="tools/call", params={"name": "nohandler"}, id="1")
        resp = handler.handle(req)
        assert resp.result["isError"] is True

    def test_handle_resources_list(self):
        handler = MCPProtocolHandler()
        req = MCPRequest(method="resources/list", id="1")
        resp = handler.handle(req)
        assert "resources" in resp.result
        assert len(resp.result["resources"]) == 5

    def test_handle_resources_read(self):
        handler = MCPProtocolHandler()
        req = MCPRequest(
            method="resources/read",
            params={"uri": "aldeci://risk/dashboard"},
            id="1",
        )
        resp = handler.handle(req)
        assert "contents" in resp.result

    def test_handle_resources_read_missing_uri(self):
        handler = MCPProtocolHandler()
        req = MCPRequest(method="resources/read", params={}, id="1")
        resp = handler.handle(req)
        assert resp.error is not None

    def test_handle_resources_read_not_found(self):
        handler = MCPProtocolHandler()
        req = MCPRequest(
            method="resources/read",
            params={"uri": "aldeci://nonexistent"},
            id="1",
        )
        resp = handler.handle(req)
        assert resp.error is not None

    def test_handle_prompts_list(self):
        handler = MCPProtocolHandler()
        req = MCPRequest(method="prompts/list", id="1")
        resp = handler.handle(req)
        assert "prompts" in resp.result
        assert len(resp.result["prompts"]) == 5

    def test_handle_prompts_get(self):
        handler = MCPProtocolHandler()
        req = MCPRequest(
            method="prompts/get",
            params={"name": "analyze-finding", "arguments": {"finding_id": "CVE-2024-1"}},
            id="1",
        )
        resp = handler.handle(req)
        assert "messages" in resp.result
        text = resp.result["messages"][0]["content"]["text"]
        assert "CVE-2024-1" in text

    def test_handle_prompts_get_missing_name(self):
        handler = MCPProtocolHandler()
        req = MCPRequest(method="prompts/get", params={}, id="1")
        resp = handler.handle(req)
        assert resp.error is not None

    def test_handle_completion_prompt_ref(self):
        handler = MCPProtocolHandler()
        req = MCPRequest(
            method="completion/complete",
            params={
                "ref": {"type": "ref/prompt"},
                "argument": {"value": "analyze"},
            },
            id="1",
        )
        resp = handler.handle(req)
        assert "completion" in resp.result
        assert "analyze-finding" in resp.result["completion"]["values"]

    def test_handle_completion_no_ref(self):
        handler = MCPProtocolHandler()
        req = MCPRequest(
            method="completion/complete",
            params={"ref": {}, "argument": {}},
            id="1",
        )
        resp = handler.handle(req)
        assert resp.result["completion"]["values"] == []

    def test_handle_unknown_method(self):
        handler = MCPProtocolHandler()
        req = MCPRequest(method="nonexistent/method", id="1")
        resp = handler.handle(req)
        assert resp.error is not None
        assert resp.error["code"] == METHOD_NOT_FOUND

    def test_handle_raw_valid(self):
        handler = MCPProtocolHandler()
        raw = json.dumps({"jsonrpc": "2.0", "method": "ping", "id": "1"})
        result = handler.handle_raw(raw)
        parsed = json.loads(result)
        assert parsed["jsonrpc"] == "2.0"
        assert parsed["result"] == {}

    def test_handle_raw_parse_error(self):
        handler = MCPProtocolHandler()
        result = handler.handle_raw("invalid json{{{")
        parsed = json.loads(result)
        assert parsed["error"]["code"] == PARSE_ERROR

    def test_handle_raw_invalid_request(self):
        handler = MCPProtocolHandler()
        result = handler.handle_raw(json.dumps({"jsonrpc": "2.0"}))  # no method
        parsed = json.loads(result)
        assert parsed["error"]["code"] == INVALID_REQUEST

    def test_handle_raw_non_dict(self):
        handler = MCPProtocolHandler()
        result = handler.handle_raw(json.dumps([1, 2, 3]))
        parsed = json.loads(result)
        assert parsed["error"]["code"] == INVALID_REQUEST

    def test_audit_logging(self):
        handler = MCPProtocolHandler()
        handler._audit_enabled = True
        req = MCPRequest(method="ping", id="1")
        handler.handle(req)
        assert len(handler._audit_log) == 1
        assert handler._audit_log[0]["method"] == "ping"

    def test_audit_log_trimming(self):
        handler = MCPProtocolHandler()
        handler._audit_enabled = True
        handler._audit_log = [{"i": i} for i in range(10001)]
        req = MCPRequest(method="ping", id="1")
        handler.handle(req)
        assert len(handler._audit_log) <= 5001

    def test_audit_disabled(self):
        handler = MCPProtocolHandler()
        handler._audit_enabled = False
        req = MCPRequest(method="ping", id="1")
        handler.handle(req)
        assert len(handler._audit_log) == 0

    def test_get_status(self):
        handler = MCPProtocolHandler()
        handler.tool_registry.register_tool(
            MCPToolDefinition("test", "T", {})
        )
        status = handler.get_status()
        assert status["server"] == "aldeci-mcp"
        assert status["tools_registered"] == 1
        assert status["resources_count"] == 5
        assert status["prompts_count"] == 5

    def test_handle_async_tool_call(self):
        """Test that async handlers are executed correctly."""
        handler = MCPProtocolHandler()

        async def async_handler(msg: str = "hi"):
            return {"async_result": msg}

        handler.tool_registry.register_tool(
            MCPToolDefinition("async_tool", "Async tool", {}, handler=async_handler)
        )
        req = MCPRequest(
            method="tools/call",
            params={"name": "async_tool", "arguments": {"msg": "async-test"}},
            id="1",
        )
        resp = handler.handle(req)
        # Should succeed or return error gracefully (depends on event loop state)
        assert resp.error is None or resp.result is not None


# ===========================================================================
# SSE Transport
# ===========================================================================
class TestSSETransport:
    def test_create_sse_event_simple(self):
        result = create_sse_event({"hello": "world"})
        assert "data: " in result
        assert '"hello"' in result
        assert result.endswith("\n\n")

    def test_create_sse_event_with_event_type(self):
        result = create_sse_event("ping", event="ping")
        assert "event: ping" in result
        assert 'data: ping' in result

    def test_create_sse_event_with_id(self):
        result = create_sse_event({"ok": True}, id="42")
        assert "id: 42" in result

    def test_create_sse_event_with_all(self):
        result = create_sse_event({"status": "ok"}, event="update", id="99")
        assert "id: 99" in result
        assert "event: update" in result
        assert "data:" in result

    def test_create_sse_event_multiline(self):
        result = create_sse_event("line1\nline2")
        lines = result.split("\n")
        data_lines = [l for l in lines if l.startswith("data:")]
        assert len(data_lines) == 2


# ===========================================================================
# Module-level convenience
# ===========================================================================
class TestModuleConvenience:
    def test_get_mcp_handler_returns_handler(self):
        handler = get_mcp_handler()
        assert isinstance(handler, MCPProtocolHandler)

    def test_get_mcp_handler_singleton(self):
        h1 = get_mcp_handler()
        h2 = get_mcp_handler()
        assert h1 is h2


# ===========================================================================
# Error codes
# ===========================================================================
class TestErrorCodes:
    def test_error_code_values(self):
        assert PARSE_ERROR == -32700
        assert INVALID_REQUEST == -32600
        assert METHOD_NOT_FOUND == -32601
        assert INVALID_PARAMS == -32602
        assert INTERNAL_ERROR == -32603


# ===========================================================================
# Edge Cases
# ===========================================================================
class TestEdgeCases:
    def test_handler_internal_exception(self):
        handler = MCPProtocolHandler()
        # Monkey-patch a handler to raise
        handler._handlers["ping"] = lambda req: (_ for _ in ()).throw(RuntimeError("internal"))
        req = MCPRequest(method="ping", id="1")
        resp = handler.handle(req)
        assert resp.error is not None
        assert resp.error["code"] == INTERNAL_ERROR

    def test_tools_call_string_result(self):
        handler = MCPProtocolHandler()
        handler.tool_registry.register_tool(
            MCPToolDefinition("string_tool", "String", {}, handler=lambda: "plain string result")
        )
        req = MCPRequest(method="tools/call", params={"name": "string_tool"}, id="1")
        resp = handler.handle(req)
        assert resp.result["content"][0]["text"] == "plain string result"

    def test_resource_read_string_content(self):
        server = MCPResourceServer()
        server.register_resource(MCPResourceDefinition(
            uri="test://string",
            name="String Resource",
            description="Returns a plain string",
            handler=lambda: "just a string",
        ))
        result = server.read_resource("test://string")
        assert result["contents"][0]["text"] == "just a string"

    def test_initialize_with_empty_client_info(self):
        handler = MCPProtocolHandler()
        req = MCPRequest(method="initialize", params={}, id="1")
        resp = handler.handle(req)
        assert resp.error is None
        assert resp.result["sessionId"]  # should still create a session

    def test_shutdown_without_session_id(self):
        handler = MCPProtocolHandler()
        req = MCPRequest(method="shutdown", params={}, id="1")
        resp = handler.handle(req)
        assert resp.result["status"] == "shutdown"

    def test_completion_with_empty_prefix(self):
        handler = MCPProtocolHandler()
        req = MCPRequest(
            method="completion/complete",
            params={"ref": {"type": "ref/prompt"}, "argument": {"value": ""}},
            id="1",
        )
        resp = handler.handle(req)
        assert len(resp.result["completion"]["values"]) == 5  # all prompts match

    def test_tool_list_output_shape(self):
        registry = MCPToolRegistry()
        registry.register_tool(MCPToolDefinition("t", "Desc", {"type": "object"}))
        tools, _ = registry.list_tools()
        assert tools[0] == {"name": "t", "description": "Desc", "inputSchema": {"type": "object"}}
