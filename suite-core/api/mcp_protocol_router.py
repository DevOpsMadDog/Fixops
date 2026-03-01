"""MCP Protocol Server Router (V7 — MCP 2025 Full Protocol).

Exposes MCP JSON-RPC 2.0 protocol handler, SSE streaming, and tool discovery.
This is the full MCP protocol engine — complements the existing mcp_router.py
which handles MCP client management.
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
# Endpoints
# ---------------------------------------------------------------------------
@router.get("/status")
async def mcp_protocol_status() -> Dict[str, Any]:
    """Get MCP protocol server status."""
    try:
        from core.mcp_server import MCPProtocolHandler
        handler = MCPProtocolHandler()
        return {
            "status": "operational",
            "engine": "mcp-protocol",
            "version": "1.0.0",
            "protocol_version": "2025-03-26",
            "server_name": "aldeci-mcp",
            "capabilities": {
                "tools": True,
                "resources": True,
                "prompts": True,
            },
            "active_sessions": len(handler.sessions.sessions),
            "tool_count": len(handler.tools.tools),
            "resource_count": len(handler.resources.resources),
            "prompt_count": len(handler.prompts.prompts),
        }
    except Exception as e:
        return {
            "status": "degraded",
            "engine": "mcp-protocol",
            "error": str(e),
        }


@router.post("/jsonrpc")
async def handle_jsonrpc(req: MCPJsonRpcRequest) -> Dict[str, Any]:
    """Handle a JSON-RPC 2.0 MCP protocol request."""
    try:
        from core.mcp_server import MCPProtocolHandler, MCPRequest
        handler = MCPProtocolHandler()
        mcp_req = MCPRequest(
            jsonrpc=req.jsonrpc,
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
        from core.mcp_server import MCPProtocolHandler
        handler = MCPProtocolHandler()
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
        from core.mcp_server import MCPProtocolHandler
        handler = MCPProtocolHandler()

        async def event_generator():
            # Send initial connection event
            yield f"event: connected\ndata: {json.dumps({'server': 'aldeci-mcp', 'version': '1.0.0'})}\n\n"
            # Send tool list
            tools = [{"name": t.name, "description": t.description} for t in handler.tools.tools.values()]
            yield f"event: tools\ndata: {json.dumps({'tools': tools})}\n\n"

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
        from core.mcp_server import MCPProtocolHandler
        handler = MCPProtocolHandler()
        tools = [
            {
                "name": t.name,
                "description": t.description,
                "category": t.category,
                "input_schema": t.input_schema,
            }
            for t in handler.tools.tools.values()
        ]
        return {"tools": tools, "total": len(tools)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/resources")
async def list_mcp_resources() -> Dict[str, Any]:
    """List all MCP resources."""
    try:
        from core.mcp_server import MCPProtocolHandler
        handler = MCPProtocolHandler()
        resources = [
            {
                "uri": r.uri,
                "name": r.name,
                "description": r.description,
                "mime_type": r.mime_type,
            }
            for r in handler.resources.resources.values()
        ]
        return {"resources": resources, "total": len(resources)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/prompts")
async def list_mcp_prompts() -> Dict[str, Any]:
    """List all MCP prompts."""
    try:
        from core.mcp_server import MCPProtocolHandler
        handler = MCPProtocolHandler()
        prompts = [
            {
                "name": p.name,
                "description": p.description,
                "arguments": p.arguments,
            }
            for p in handler.prompts.prompts.values()
        ]
        return {"prompts": prompts, "total": len(prompts)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/discover")
async def auto_discover_tools(request: Request) -> Dict[str, Any]:
    """Trigger auto-discovery of tools from FastAPI app routes."""
    try:
        from core.mcp_server import MCPProtocolHandler
        handler = MCPProtocolHandler()
        handler.tools.auto_discover_from_app(request.app)
        return {
            "discovered": True,
            "tool_count": len(handler.tools.tools),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
