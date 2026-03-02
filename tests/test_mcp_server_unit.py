"""
Unit tests for suite-core/core/mcp_server.py — MCP Protocol Handler [V7]

Tests the Model Context Protocol (MCP) server implementation including:
- MCPToolRegistry: tool registration, listing, schema validation
- MCPSessionManager: session lifecycle, cleanup
- MCPProtocolHandler: JSON-RPC request/response handling
- MCPResourceServer: resource registration, reading
- MCPPromptLibrary: prompt template management
- SSE event creation

Written by agent-doctor run14 for SPRINT1-008 (test coverage).
"""
import pytest
import json

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'suite-core'))

from core.mcp_server import (
    MCPToolRegistry,
    MCPToolDefinition,
    MCPSessionManager,
    MCPProtocolHandler,
    MCPResourceServer,
    MCPResourceDefinition,
    MCPPromptLibrary,
    MCPRequest,
    MCPResponse,
    MCPMethod,
    create_sse_event,
    get_mcp_handler,
    PARSE_ERROR,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    INVALID_PARAMS,
    INTERNAL_ERROR,
)


# ─── MCPToolRegistry ───────────────────────────────────────────────

class TestMCPToolRegistry:
    """Tests for MCPToolRegistry — tool registration and discovery."""

    def test_registry_init(self):
        reg = MCPToolRegistry()
        assert reg is not None
        assert hasattr(reg, 'register_tool')
        assert hasattr(reg, 'list_tools')

    def test_register_tool(self):
        reg = MCPToolRegistry()
        tool = MCPToolDefinition(
            name="test_scan",
            description="Run a test scan",
            input_schema={"type": "object", "properties": {"target": {"type": "string"}}},
            handler=lambda x: {"result": "ok"},
        )
        reg.register_tool(tool)
        tools_result = reg.list_tools()
        # list_tools returns (list, cursor) tuple
        tools_list = tools_result[0] if isinstance(tools_result, tuple) else tools_result
        found = any(
            (t.get('name') if isinstance(t, dict) else getattr(t, 'name', None)) == "test_scan"
            for t in tools_list
        )
        assert found, "Registered tool 'test_scan' not found in list_tools"

    def test_register_multiple_tools(self):
        reg = MCPToolRegistry()
        for i in range(5):
            tool = MCPToolDefinition(
                name=f"tool_{i}",
                description=f"Tool number {i}",
                input_schema={"type": "object"},
                handler=lambda x: {"i": i},
            )
            reg.register_tool(tool)
        tools_result = reg.list_tools()
        tools_list = tools_result[0] if isinstance(tools_result, tuple) else tools_result
        assert len(tools_list) >= 5

    def test_get_tool_by_name(self):
        reg = MCPToolRegistry()
        tool = MCPToolDefinition(
            name="find_vuln",
            description="Find vulnerabilities",
            input_schema={"type": "object"},
            handler=lambda x: {},
        )
        reg.register_tool(tool)
        found = reg.get_tool("find_vuln")
        assert found is not None

    def test_get_nonexistent_tool(self):
        reg = MCPToolRegistry()
        result = reg.get_tool("does_not_exist")
        assert result is None

    def test_tool_definition_fields(self):
        tool = MCPToolDefinition(
            name="scan",
            description="Run scan",
            input_schema={"type": "object", "properties": {"url": {"type": "string"}}},
            handler=lambda x: {},
        )
        assert tool.name == "scan"
        assert tool.description == "Run scan"
        assert "properties" in tool.input_schema

    def test_tool_definition_defaults(self):
        tool = MCPToolDefinition(
            name="test",
            description="Test tool",
            input_schema={"type": "object"},
        )
        assert tool.category == "general"
        assert tool.requires_auth is True
        assert tool.handler is None


# ─── MCPSessionManager ─────────────────────────────────────────────

class TestMCPSessionManager:
    """Tests for MCPSessionManager — session lifecycle."""

    def test_create_session(self):
        mgr = MCPSessionManager()
        session = mgr.create_session(client_name="test-client")
        assert session is not None
        assert hasattr(session, 'session_id')
        assert session.session_id is not None

    def test_get_session(self):
        mgr = MCPSessionManager()
        session = mgr.create_session(client_name="test-client-2")
        found = mgr.get_session(session.session_id)
        assert found is not None
        assert found.session_id == session.session_id

    def test_get_nonexistent_session(self):
        mgr = MCPSessionManager()
        result = mgr.get_session("fake-session-id")
        assert result is None

    def test_remove_session(self):
        mgr = MCPSessionManager()
        session = mgr.create_session(client_name="test-remove")
        sid = session.session_id
        # close_session is the actual method name
        mgr.close_session(sid)
        assert mgr.get_session(sid) is None

    def test_multiple_sessions(self):
        mgr = MCPSessionManager()
        sessions = [mgr.create_session(client_name=f"client-{i}") for i in range(10)]
        ids = [s.session_id for s in sessions]
        assert len(set(ids)) == 10

    def test_session_with_version(self):
        mgr = MCPSessionManager()
        session = mgr.create_session(client_name="versioned", client_version="1.0.0")
        assert session is not None

    def test_session_with_capabilities(self):
        mgr = MCPSessionManager()
        session = mgr.create_session(
            client_name="capable",
            capabilities={"tools": True, "resources": True}
        )
        assert session is not None


# ─── MCPProtocolHandler ────────────────────────────────────────────

class TestMCPProtocolHandler:
    """Tests for MCPProtocolHandler — JSON-RPC request/response."""

    def test_handler_init(self):
        handler = MCPProtocolHandler()
        assert handler is not None

    def test_get_mcp_handler_singleton(self):
        h1 = get_mcp_handler()
        h2 = get_mcp_handler()
        assert h1 is h2

    def test_handle_initialize(self):
        handler = MCPProtocolHandler()
        request = MCPRequest(
            jsonrpc="2.0",
            id=1,
            method="initialize",
            params={"capabilities": {}},
        )
        response = handler.handle(request)
        assert response is not None

    def test_handle_tools_list(self):
        handler = MCPProtocolHandler()
        request = MCPRequest(
            jsonrpc="2.0",
            id=2,
            method="tools/list",
            params={},
        )
        response = handler.handle(request)
        assert response is not None

    def test_handle_unknown_method(self):
        handler = MCPProtocolHandler()
        request = MCPRequest(
            jsonrpc="2.0",
            id=3,
            method="nonexistent/method",
            params={},
        )
        response = handler.handle(request)
        assert response is not None

    def test_handle_raw_json(self):
        handler = MCPProtocolHandler()
        raw = json.dumps({"jsonrpc": "2.0", "id": 4, "method": "tools/list", "params": {}})
        result = handler.handle_raw(raw)
        assert result is not None
        assert isinstance(result, str)

    def test_get_status(self):
        handler = MCPProtocolHandler()
        status = handler.get_status()
        assert isinstance(status, dict)

    def test_handle_raw_invalid_json(self):
        handler = MCPProtocolHandler()
        result = handler.handle_raw("not valid json{{{")
        assert result is not None
        parsed = json.loads(result)
        assert 'error' in parsed


# ─── MCPResourceServer ─────────────────────────────────────────────

class TestMCPResourceServer:
    """Tests for MCPResourceServer — resource registration."""

    def test_resource_server_init(self):
        server = MCPResourceServer()
        assert server is not None

    def test_register_resource(self):
        server = MCPResourceServer()
        resource = MCPResourceDefinition(
            uri="aldeci://test/resource",
            name="Test Resource",
            description="A test resource",
            mime_type="application/json",
        )
        server.register_resource(resource)
        resources = server.list_resources()
        uris = [r.get('uri', '') if isinstance(r, dict) else getattr(r, 'uri', '') for r in resources]
        assert "aldeci://test/resource" in uris

    def test_list_default_resources(self):
        server = MCPResourceServer()
        resources = server.list_resources()
        assert isinstance(resources, list)
        assert len(resources) >= 1

    def test_read_resource(self):
        server = MCPResourceServer()
        resources = server.list_resources()
        if resources:
            uri = resources[0].get('uri', '') if isinstance(resources[0], dict) else getattr(resources[0], 'uri', '')
            if uri:
                result = server.read_resource(uri)
                assert result is not None


# ─── MCPPromptLibrary ──────────────────────────────────────────────

class TestMCPPromptLibrary:
    """Tests for MCPPromptLibrary — prompt template management."""

    def test_prompt_library_init(self):
        lib = MCPPromptLibrary()
        assert lib is not None

    def test_list_prompts(self):
        lib = MCPPromptLibrary()
        prompts = lib.list_prompts()
        assert isinstance(prompts, list)

    def test_get_prompt_by_name(self):
        lib = MCPPromptLibrary()
        prompts = lib.list_prompts()
        if prompts:
            name = prompts[0].get('name', '') if isinstance(prompts[0], dict) else getattr(prompts[0], 'name', '')
            if name:
                result = lib.get_prompt(name)
                assert result is not None

    def test_get_nonexistent_prompt(self):
        lib = MCPPromptLibrary()
        with pytest.raises(KeyError):
            lib.get_prompt("nonexistent_prompt_xyz")


# ─── SSE Events ────────────────────────────────────────────────────

class TestSSEEvents:
    """Tests for SSE event creation."""

    def test_create_sse_event_basic(self):
        event = create_sse_event(data={"msg": "hello"})
        assert event is not None
        assert isinstance(event, str)
        assert "data:" in event

    def test_create_sse_event_with_event_type(self):
        event = create_sse_event(data={"status": "ok"}, event="status")
        assert "event:" in event
        assert "data:" in event

    def test_create_sse_event_with_id(self):
        event = create_sse_event(data={"msg": "test"}, id="evt-123")
        assert "id:" in event


# ─── MCPRequest / MCPResponse ──────────────────────────────────────

class TestMCPDataClasses:
    """Tests for MCP data classes."""

    def test_mcp_request_creation(self):
        req = MCPRequest(
            jsonrpc="2.0",
            id=1,
            method="tools/call",
            params={"name": "scan", "arguments": {"target": "http://example.com"}},
        )
        assert req.jsonrpc == "2.0"
        assert req.method == "tools/call"
        assert req.id == 1

    def test_mcp_response_creation(self):
        resp = MCPResponse(
            jsonrpc="2.0",
            id=1,
            result={"content": [{"type": "text", "text": "Scan complete"}]},
        )
        assert resp.jsonrpc == "2.0"
        assert resp.result is not None

    def test_mcp_method_enum(self):
        assert hasattr(MCPMethod, 'INITIALIZE')
        assert hasattr(MCPMethod, 'TOOLS_LIST')
        assert hasattr(MCPMethod, 'TOOLS_CALL')


# ─── Error Codes ───────────────────────────────────────────────────

class TestErrorCodes:
    """Tests for JSON-RPC error codes."""

    def test_parse_error_code(self):
        assert PARSE_ERROR == -32700

    def test_invalid_request_code(self):
        assert INVALID_REQUEST == -32600

    def test_method_not_found_code(self):
        assert METHOD_NOT_FOUND == -32601

    def test_invalid_params_code(self):
        assert INVALID_PARAMS == -32602

    def test_internal_error_code(self):
        assert INTERNAL_ERROR == -32603


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
