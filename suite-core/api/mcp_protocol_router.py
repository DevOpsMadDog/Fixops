"""MCP Protocol Server Router (V7 — MCP 2025 Full Protocol).

Exposes MCP JSON-RPC 2.0 protocol handler, SSE streaming, WebSocket transport,
session management, and tool discovery.

This is the full MCP protocol engine — complements the existing mcp_router.py
which handles MCP client management and tool execution.

Endpoints:
  GET  /health          — Health check
  GET  /status          — Protocol server status
  GET  /stats           — Server statistics
  POST /jsonrpc         — JSON-RPC 2.0 handler
  POST /raw             — Raw JSON-RPC handler
  GET  /sse             — SSE stream for notifications
  WS   /ws              — WebSocket transport for bidirectional MCP
  GET  /tools           — List auto-discovered tools
  POST /tools/execute   — Execute a tool via JSON-RPC dispatch
  GET  /resources       — List MCP resources
  GET  /resources/{uri} — Read a specific resource
  GET  /prompts         — List MCP prompts
  GET  /prompts/{name}  — Get a specific prompt
  POST /discover        — Trigger auto-discovery from app routes
  GET  /sessions        — List active MCP sessions
  DELETE /sessions/{id} — Terminate a session
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/mcp-protocol", tags=["MCP Protocol"])


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class MCPJsonRpcRequest(BaseModel):
    jsonrpc: str = Field("2.0", description="JSON-RPC version")
    method: str = Field(..., description="MCP method name")
    params: Dict[str, Any] = Field(default_factory=dict)
    id: Optional[Any] = Field(None)


class MCPToolExecuteRequest(BaseModel):
    """Execute a tool via the MCP protocol layer."""
    tool_name: str = Field(..., description="Name of the tool to execute")
    arguments: Dict[str, Any] = Field(default_factory=dict, description="Tool arguments")
    session_id: Optional[str] = Field(None, description="Optional session context")


# ---------------------------------------------------------------------------
# In-memory WebSocket session registry
# ---------------------------------------------------------------------------
_ws_sessions: Dict[str, Dict[str, Any]] = {}  # session_id -> {ws, created, last_active}


# ---------------------------------------------------------------------------
# Singleton helper
# ---------------------------------------------------------------------------
def _get_handler():
    """Get the singleton MCP protocol handler.

    Uses get_mcp_handler() to ensure session state, tool registry,
    and audit logs persist across requests.
    """
    from core.mcp_server import get_mcp_handler
    return get_mcp_handler()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@router.get("/health")
async def mcp_protocol_health() -> Dict[str, Any]:
    """Health check alias for MCP protocol server (mirrors /status)."""
    return await mcp_protocol_status()


@router.get("/status")
async def mcp_protocol_status() -> Dict[str, Any]:
    """Get MCP protocol server status."""
    try:
        handler = _get_handler()
        return {
            "status": "operational",
            "engine": "mcp-protocol",
            "version": handler.SERVER_VERSION,
            "protocol_version": handler.PROTOCOL_VERSION,
            "server_name": handler.SERVER_NAME,
            "capabilities": {
                "tools": True,
                "resources": True,
                "prompts": True,
            },
            "active_sessions": len(handler.session_manager.active_sessions()),
            "tool_count": handler.tool_registry.tool_count,
            "resource_count": len(handler.resource_server.list_resources()),
            "prompt_count": len(handler.prompt_library.list_prompts()),
        }
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        return {
            "status": "degraded",
            "engine": "mcp-protocol",
            "error": type(e).__name__,
        }


@router.get("/stats")
async def mcp_protocol_stats() -> Dict[str, Any]:
    """Get MCP protocol server statistics."""
    try:
        handler = _get_handler()
        status = handler.get_status()
        return {
            "engine": "mcp-protocol",
            "protocol_version": handler.PROTOCOL_VERSION,
            "tools_registered": status.get("tools_registered", 0),
            "tool_categories": status.get("tool_categories", {}),
            "resources_count": status.get("resources_count", 0),
            "prompts_count": status.get("prompts_count", 0),
            "active_sessions": status.get("active_sessions", 0),
            "audit_entries": status.get("audit_entries", 0),
        }
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        raise HTTPException(status_code=500, detail=type(e).__name__)


@router.post("/jsonrpc")
async def handle_jsonrpc(req: MCPJsonRpcRequest) -> Dict[str, Any]:
    """Handle a JSON-RPC 2.0 MCP protocol request."""
    try:
        from core.mcp_server import MCPRequest
        handler = _get_handler()
        mcp_req = MCPRequest(
            method=req.method,
            params=req.params,
            id=req.id,
        )
        response = handler.handle(mcp_req)
        return {
            "jsonrpc": response.jsonrpc,
            "id": response.id,
            "result": response.result,
            "error": response.error,
        }
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        return {
            "jsonrpc": "2.0",
            "id": req.id,
            "error": {"code": -32603, "message": str(e)},
        }


@router.post("/raw")
async def handle_raw_jsonrpc(request: Request) -> Dict[str, Any]:
    """Handle raw JSON-RPC 2.0 (for direct MCP client connections)."""
    try:
        handler = _get_handler()
        body = await request.body()
        response = handler.handle_raw(body.decode())
        return json.loads(response)
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        return {
            "jsonrpc": "2.0",
            "id": None,
            "error": {"code": -32603, "message": str(e)},
        }


@router.get("/sse")
async def sse_stream() -> StreamingResponse:
    """Server-Sent Events stream for MCP notifications."""
    try:
        handler = _get_handler()

        async def event_generator():
            # Send initial connection event
            yield f"event: connected\ndata: {json.dumps({'server': handler.SERVER_NAME, 'version': handler.SERVER_VERSION})}\n\n"
            # Send tool list from the registry
            tools_list, _ = handler.tool_registry.list_tools(limit=100)
            yield f"event: tools\ndata: {json.dumps({'tools': tools_list})}\n\n"

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "Connection": "keep-alive"},
        )
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        raise HTTPException(status_code=500, detail=type(e).__name__)


@router.get("/tools")
async def list_mcp_tools() -> Dict[str, Any]:
    """List all auto-discovered MCP tools."""
    try:
        handler = _get_handler()
        tools_list, next_cursor = handler.tool_registry.list_tools(limit=1000)
        return {"tools": tools_list, "total": handler.tool_registry.tool_count}
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        raise HTTPException(status_code=500, detail=type(e).__name__)


@router.get("/resources")
async def list_mcp_resources() -> Dict[str, Any]:
    """List all MCP resources."""
    try:
        handler = _get_handler()
        resources = handler.resource_server.list_resources()
        return {"resources": resources, "total": len(resources)}
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        raise HTTPException(status_code=500, detail=type(e).__name__)


@router.get("/prompts")
async def list_mcp_prompts() -> Dict[str, Any]:
    """List all MCP prompts."""
    try:
        handler = _get_handler()
        prompts = handler.prompt_library.list_prompts()
        return {"prompts": prompts, "total": len(prompts)}
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        raise HTTPException(status_code=500, detail=type(e).__name__)


@router.post("/discover")
async def auto_discover_tools(request: Request) -> Dict[str, Any]:
    """Trigger auto-discovery of tools from FastAPI app routes."""
    try:
        handler = _get_handler()
        count = handler.tool_registry.auto_discover_from_app(request.app)
        return {
            "discovered": True,
            "tool_count": handler.tool_registry.tool_count,
            "newly_discovered": count,
        }
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        raise HTTPException(status_code=500, detail=type(e).__name__)


# ---------------------------------------------------------------------------
# Tool Execution
# ---------------------------------------------------------------------------
@router.post("/tools/execute")
async def execute_tool(req: MCPToolExecuteRequest) -> Dict[str, Any]:
    """Execute a tool via the MCP protocol server.

    Dispatches to the MCP handler's tool execution, which routes
    to the appropriate backend engine (BrainPipeline, SAST, etc.).
    """
    start = time.time()
    try:
        handler = _get_handler()
        from core.mcp_server import MCPRequest

        # Create a tools/call JSON-RPC request
        mcp_req = MCPRequest(
            method="tools/call",
            params={"name": req.tool_name, "arguments": req.arguments},
            id=str(uuid.uuid4()),
        )
        response = handler.handle(mcp_req)
        elapsed = round((time.time() - start) * 1000, 2)

        if response.error:
            return {
                "success": False,
                "tool_name": req.tool_name,
                "error": response.error,
                "elapsed_ms": elapsed,
            }

        return {
            "success": True,
            "tool_name": req.tool_name,
            "result": response.result,
            "elapsed_ms": elapsed,
        }
    except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as e:
        elapsed = round((time.time() - start) * 1000, 2)
        logger.error("Tool execution error: %s — %s", req.tool_name, e)
        raise HTTPException(status_code=500, detail=f"Tool execution failed: {e}")


# ---------------------------------------------------------------------------
# Resource Detail
# ---------------------------------------------------------------------------
@router.get("/resources/{resource_uri:path}")
async def read_resource(resource_uri: str) -> Dict[str, Any]:
    """Read a specific MCP resource by URI."""
    try:
        handler = _get_handler()
        # Try to read from the resource server
        content = handler.resource_server.read_resource(resource_uri)
        return {
            "uri": resource_uri,
            "content": content,
        }
    except AttributeError:
        # read_resource may not exist — return not found
        raise HTTPException(status_code=404, detail=f"Resource not found: {resource_uri}")
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        raise HTTPException(status_code=500, detail=type(e).__name__)


# ---------------------------------------------------------------------------
# Prompt Detail
# ---------------------------------------------------------------------------
@router.get("/prompts/{prompt_name}")
async def get_prompt(prompt_name: str) -> Dict[str, Any]:
    """Get a specific MCP prompt by name."""
    try:
        handler = _get_handler()
        prompt = handler.prompt_library.get_prompt(prompt_name)
        if prompt is None:
            raise HTTPException(status_code=404, detail=f"Prompt not found: {prompt_name}")
        return {"name": prompt_name, "prompt": prompt}
    except HTTPException:
        raise
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        raise HTTPException(status_code=500, detail=type(e).__name__)


# ---------------------------------------------------------------------------
# WebSocket Transport (MCP 2025 Streamable HTTP)
# ---------------------------------------------------------------------------
@router.websocket("/ws")
async def websocket_mcp(ws: WebSocket):
    """Bidirectional WebSocket transport for MCP JSON-RPC.

    Supports persistent sessions, server-initiated notifications,
    and real-time tool execution streaming.
    """
    await ws.accept()
    session_id = str(uuid.uuid4())
    _ws_sessions[session_id] = {
        "created": time.time(),
        "last_active": time.time(),
        "messages_in": 0,
        "messages_out": 0,
    }

    try:
        handler = _get_handler()

        # Send session initialization
        init_msg = {
            "jsonrpc": "2.0",
            "method": "session/init",
            "params": {
                "session_id": session_id,
                "server": handler.SERVER_NAME,
                "version": handler.SERVER_VERSION,
                "protocol_version": handler.PROTOCOL_VERSION,
                "capabilities": {"tools": True, "resources": True, "prompts": True},
            },
        }
        await ws.send_json(init_msg)
        _ws_sessions[session_id]["messages_out"] += 1

        while True:
            raw = await ws.receive_text()
            _ws_sessions[session_id]["last_active"] = time.time()
            _ws_sessions[session_id]["messages_in"] += 1

            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                error_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": "Parse error"},
                }
                await ws.send_json(error_resp)
                _ws_sessions[session_id]["messages_out"] += 1
                continue

            # Handle JSON-RPC request
            try:
                from core.mcp_server import MCPRequest

                mcp_req = MCPRequest(
                    method=data.get("method", ""),
                    params=data.get("params", {}),
                    id=data.get("id"),
                )
                response = handler.handle(mcp_req)
                resp_dict = {
                    "jsonrpc": response.jsonrpc,
                    "id": response.id,
                }
                if response.error:
                    resp_dict["error"] = response.error
                else:
                    resp_dict["result"] = response.result

                await ws.send_json(resp_dict)
                _ws_sessions[session_id]["messages_out"] += 1

            except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
                error_resp = {
                    "jsonrpc": "2.0",
                    "id": data.get("id"),
                    "error": {"code": -32603, "message": str(e)},
                }
                await ws.send_json(error_resp)
                _ws_sessions[session_id]["messages_out"] += 1

    except WebSocketDisconnect:
        logger.info("MCP WebSocket session %s disconnected", session_id)
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        logger.error("MCP WebSocket error in session %s: %s", session_id, e)
    finally:
        _ws_sessions.pop(session_id, None)


# ---------------------------------------------------------------------------
# Session Management
# ---------------------------------------------------------------------------
@router.get("/sessions")
async def list_sessions() -> Dict[str, Any]:
    """List active MCP sessions (both WebSocket and handler-managed)."""
    try:
        handler = _get_handler()
        handler_sessions = handler.session_manager.active_sessions()
    except (ValueError, KeyError, RuntimeError, TypeError, AttributeError):
        handler_sessions = []

    ws_list = [
        {
            "session_id": sid,
            "transport": "websocket",
            "created": info["created"],
            "last_active": info["last_active"],
            "messages_in": info.get("messages_in", 0),
            "messages_out": info.get("messages_out", 0),
            "alive_seconds": round(time.time() - info["created"], 1),
        }
        for sid, info in _ws_sessions.items()
    ]

    return {
        "websocket_sessions": ws_list,
        "handler_sessions": handler_sessions,
        "total": len(ws_list) + len(handler_sessions),
    }


@router.delete("/sessions/{session_id}")
async def terminate_session(session_id: str) -> Dict[str, Any]:
    """Terminate an active MCP session."""
    if session_id in _ws_sessions:
        _ws_sessions.pop(session_id)
        return {"terminated": True, "session_id": session_id, "transport": "websocket"}

    try:
        handler = _get_handler()
        handler.session_manager.terminate(session_id)
        return {"terminated": True, "session_id": session_id, "transport": "handler"}
    except (ValueError, KeyError, RuntimeError, TypeError, AttributeError):
        raise HTTPException(status_code=404, detail=f"Session not found: {session_id}")
