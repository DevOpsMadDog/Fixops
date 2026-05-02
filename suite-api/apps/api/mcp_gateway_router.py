"""FastAPI router for the MCP Gateway — External AI Agent Interface.

Exposes ALDECI capabilities over the Model Context Protocol (MCP) so that
external AI agents can discover and call ALDECI tools programmatically.

Endpoints:
    GET  /api/v1/mcp-gateway/tools          — List all registered MCP tools
    POST /api/v1/mcp-gateway/call           — Call a tool by name with arguments
    GET  /api/v1/mcp-gateway/schema         — Full gateway schema (MCP tool definitions)
    GET  /api/v1/mcp-gateway/health         — Gateway health / readiness check

All endpoints require API-key authentication (enforced at app mount).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# Import gateway (graceful degradation so the router still loads when
# suite-core is not on sys.path during unit testing)
try:
    from core.mcp_gateway import MCPResponse, MCPTool, get_mcp_gateway

    _GATEWAY_AVAILABLE = True
except ImportError:
    _GATEWAY_AVAILABLE = False
    logger.warning("mcp_gateway not available — router running in stub mode")


router = APIRouter(prefix="/api/v1/mcp-gateway", tags=["mcp-gateway"])


# ---------------------------------------------------------------------------
# Request / Response Models
# ---------------------------------------------------------------------------


class ToolListResponse(BaseModel):
    """Response for GET /tools."""

    tools: List[Dict[str, Any]]
    count: int
    timestamp: datetime = Field(default_factory=lambda: datetime.now(tz=timezone.utc))


class CallToolRequest(BaseModel):
    """Request body for POST /call."""

    name: str = Field(..., description="Tool name to invoke")
    arguments: Dict[str, Any] = Field(
        default_factory=dict, description="Tool input arguments"
    )


class CallToolResponse(BaseModel):
    """Response for POST /call."""

    name: str
    content: List[Dict[str, Any]]
    is_error: bool
    timestamp: datetime = Field(default_factory=lambda: datetime.now(tz=timezone.utc))


class SchemaResponse(BaseModel):
    """Response for GET /schema."""

    gateway: str
    version: str
    protocol: str
    tools: List[Dict[str, Any]]
    tool_count: int
    timestamp: datetime = Field(default_factory=lambda: datetime.now(tz=timezone.utc))


class HealthResponse(BaseModel):
    """Response for GET /health."""

    status: str  # "ok" | "degraded"
    gateway_available: bool
    tool_count: int
    message: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(tz=timezone.utc))


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/tools",
    response_model=ToolListResponse,
    summary="List MCP tools",
    description="Return all MCP tools registered with the ALDECI gateway.",
)
def list_tools() -> ToolListResponse:
    """List all available MCP tools."""
    if not _GATEWAY_AVAILABLE:
        return ToolListResponse(tools=[], count=0)

    gateway = get_mcp_gateway()
    tools = gateway.list_tools()
    tool_dicts = [
        {
            "name": t.name,
            "description": t.description,
            "inputSchema": t.input_schema,
            "handler": t.handler,
        }
        for t in tools
    ]
    return ToolListResponse(tools=tool_dicts, count=len(tool_dicts))


@router.post(
    "/call",
    response_model=CallToolResponse,
    summary="Call an MCP tool",
    description="Invoke a registered MCP tool by name with the provided arguments.",
)
def call_tool(body: CallToolRequest) -> CallToolResponse:
    """Dispatch a tool call and return the MCP response."""
    if not _GATEWAY_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="MCP gateway is not available",
        )

    gateway = get_mcp_gateway()
    response = gateway.call_tool(name=body.name, arguments=body.arguments)

    return CallToolResponse(
        name=body.name,
        content=response.content,
        is_error=response.is_error,
    )


@router.get(
    "/schema",
    response_model=SchemaResponse,
    summary="Gateway schema",
    description=(
        "Return the full MCP gateway schema — all tools as MCP tool definitions "
        "suitable for use as a tool manifest by external AI agents."
    ),
)
def get_schema() -> SchemaResponse:
    """Return the complete MCP tool manifest."""
    if not _GATEWAY_AVAILABLE:
        return SchemaResponse(
            gateway="aldeci-mcp-gateway",
            version="1.0.0",
            protocol="mcp-2025",
            tools=[],
            tool_count=0,
        )

    gateway = get_mcp_gateway()
    schema = gateway.get_schema()
    return SchemaResponse(
        gateway=schema["gateway"],
        version=schema["version"],
        protocol=schema["protocol"],
        tools=schema["tools"],
        tool_count=len(schema["tools"]),
    )


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Gateway health",
    description="Check whether the MCP gateway is operational.",
)
def health_check() -> HealthResponse:
    """Return gateway health status."""
    if not _GATEWAY_AVAILABLE:
        return HealthResponse(
            status="degraded",
            gateway_available=False,
            tool_count=0,
            message="MCP gateway module not loaded",
        )

    gateway = get_mcp_gateway()
    tool_count = len(gateway.list_tools())
    return HealthResponse(
        status="ok",
        gateway_available=True,
        tool_count=tool_count,
        message=f"MCP gateway operational with {tool_count} tools registered",
    )
