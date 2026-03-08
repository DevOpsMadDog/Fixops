"""MCP Protocol Server Router (V7 — MCP 2025 Full Protocol).

Exposes MCP JSON-RPC 2.0 protocol handler, SSE streaming, and tool discovery.
This is the full MCP protocol engine — complements the existing mcp_router.py
which handles MCP client management.

FIXED 2026-03-03 (enterprise-architect Run 9):
- All handlers now use get_mcp_handler() singleton instead of creating new instances
- Fixed 9 broken attribute accesses (handler.sessions → handler.session_manager, etc.)
- Added /stats endpoint for consistency with other routers
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Request
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
    except Exception as e:
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
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


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
    except Exception as e:
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
    except Exception as e:
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
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tools")
async def list_mcp_tools() -> Dict[str, Any]:
    """List all auto-discovered MCP tools."""
    try:
        handler = _get_handler()
        tools_list, next_cursor = handler.tool_registry.list_tools(limit=1000)
        return {"tools": tools_list, "total": handler.tool_registry.tool_count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/resources")
async def list_mcp_resources() -> Dict[str, Any]:
    """List all MCP resources."""
    try:
        handler = _get_handler()
        resources = handler.resource_server.list_resources()
        return {"resources": resources, "total": len(resources)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/prompts")
async def list_mcp_prompts() -> Dict[str, Any]:
    """List all MCP prompts."""
    try:
        handler = _get_handler()
        prompts = handler.prompt_library.list_prompts()
        return {"prompts": prompts, "total": len(prompts)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


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
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
