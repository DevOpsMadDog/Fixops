"""
MCP (Model Context Protocol) Server API endpoints.

This provides endpoints for managing MCP servers that enable AI agents
to connect to and interact with FixOps.
"""
import logging
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/mcp", tags=["mcp"])


# ═══════════════════════════════════════════════════════════════════════════════
# Models
# ═══════════════════════════════════════════════════════════════════════════════


class MCPClientStatus(str, Enum):
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"


class MCPTransport(str, Enum):
    STDIO = "stdio"
    HTTP_SSE = "http+sse"
    WSS = "wss"


class MCPClient(BaseModel):
    """An MCP client connection."""
    
    id: str
    name: str
    client_type: str  # "copilot", "cursor", "windsurf", "zed", "agent"
    status: MCPClientStatus
    transport: MCPTransport
    connected_at: Optional[datetime] = None
    last_activity_at: Optional[datetime] = None
    capabilities: List[str] = []
    metadata: Dict[str, Any] = {}


class MCPTool(BaseModel):
    """An MCP tool exposed by FixOps."""
    
    name: str
    description: str
    input_schema: Dict[str, Any]
    category: str  # "findings", "attack", "evidence", "remediation", etc.
    requires_auth: bool = True


class MCPResource(BaseModel):
    """An MCP resource exposed by FixOps."""
    
    uri: str
    name: str
    description: str
    mime_type: str = "application/json"


class MCPPrompt(BaseModel):
    """An MCP prompt template."""
    
    name: str
    description: str
    arguments: List[Dict[str, Any]] = []


class MCPServerConfig(BaseModel):
    """MCP server configuration."""
    
    enabled: bool = True
    transport: MCPTransport = MCPTransport.HTTP_SSE
    port: int = 8080
    allowed_origins: List[str] = ["*"]
    require_auth: bool = True
    exposed_tools: List[str] = []  # Empty = all
    exposed_resources: List[str] = []  # Empty = all
    rate_limit_per_minute: int = 100


class MCPStatusResponse(BaseModel):
    """MCP server status."""
    
    enabled: bool
    transport: MCPTransport
    connected_clients: int
    available_tools: int
    available_resources: int
    available_prompts: int
    uptime_seconds: float
    version: str = "2024-11-05"


class MCPConfigureRequest(BaseModel):
    """Request to configure MCP server."""
    
    enabled: Optional[bool] = None
    transport: Optional[MCPTransport] = None
    port: Optional[int] = None
    allowed_origins: Optional[List[str]] = None
    require_auth: Optional[bool] = None
    exposed_tools: Optional[List[str]] = None
    rate_limit_per_minute: Optional[int] = None


# ═══════════════════════════════════════════════════════════════════════════════
# In-memory store (production would use database)
# ═══════════════════════════════════════════════════════════════════════════════


_mcp_config = MCPServerConfig()
_mcp_clients: Dict[str, MCPClient] = {}
_mcp_start_time = datetime.utcnow()


# ═══════════════════════════════════════════════════════════════════════════════
# Tool definitions — what FixOps exposes to MCP clients
# ═══════════════════════════════════════════════════════════════════════════════


MCP_TOOLS: List[MCPTool] = [
    MCPTool(
        name="fixops_list_findings",
        description="List security findings with optional filtering by severity, status, source",
        input_schema={
            "type": "object",
            "properties": {
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                "status": {"type": "string", "enum": ["open", "in_progress", "resolved", "false_positive"]},
                "source": {"type": "string"},
                "limit": {"type": "integer", "default": 50},
            },
        },
        category="findings",
    ),
    MCPTool(
        name="fixops_get_finding",
        description="Get detailed information about a specific finding by ID",
        input_schema={
            "type": "object",
            "properties": {
                "finding_id": {"type": "string"},
            },
            "required": ["finding_id"],
        },
        category="findings",
    ),
    MCPTool(
        name="fixops_run_scan",
        description="Run a security scan on a target (CVE, URL, image, repo)",
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "CVE ID, URL, container image, or repo path"},
                "scan_type": {"type": "string", "enum": ["vulnerability", "reachability", "attack"]},
            },
            "required": ["target"],
        },
        category="attack",
    ),
    MCPTool(
        name="fixops_generate_evidence",
        description="Generate compliance evidence bundle for a framework",
        input_schema={
            "type": "object",
            "properties": {
                "framework": {"type": "string", "enum": ["SOC2", "ISO27001", "PCI-DSS", "SLSA"]},
                "finding_ids": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["framework"],
        },
        category="evidence",
    ),
    MCPTool(
        name="fixops_create_autofix_pr",
        description="Create an auto-fix pull request for a finding",
        input_schema={
            "type": "object",
            "properties": {
                "finding_id": {"type": "string"},
                "target_branch": {"type": "string", "default": "main"},
            },
            "required": ["finding_id"],
        },
        category="remediation",
    ),
    MCPTool(
        name="fixops_get_risk_score",
        description="Get risk score and blast radius for a CVE or finding",
        input_schema={
            "type": "object",
            "properties": {
                "cve_id": {"type": "string"},
                "finding_id": {"type": "string"},
            },
        },
        category="risk",
    ),
    MCPTool(
        name="fixops_list_connectors",
        description="List configured integrations and their health status",
        input_schema={
            "type": "object",
            "properties": {},
        },
        category="integrations",
    ),
    MCPTool(
        name="fixops_notify",
        description="Send notification via configured channels (Slack, Jira, etc.)",
        input_schema={
            "type": "object",
            "properties": {
                "channel": {"type": "string", "enum": ["slack", "jira", "email", "webhook"]},
                "message": {"type": "string"},
                "severity": {"type": "string", "enum": ["info", "warning", "critical"]},
            },
            "required": ["channel", "message"],
        },
        category="notifications",
    ),
]


MCP_RESOURCES: List[MCPResource] = [
    MCPResource(
        uri="fixops://findings/critical",
        name="Critical Findings",
        description="Real-time list of critical severity findings",
    ),
    MCPResource(
        uri="fixops://risk/score",
        name="Risk Score",
        description="Current overall risk score and trend",
    ),
    MCPResource(
        uri="fixops://connectors/status",
        name="Connector Status",
        description="Health status of all configured connectors",
    ),
    MCPResource(
        uri="fixops://pipeline/current",
        name="Current Pipeline",
        description="Status of currently running pipeline",
    ),
]


MCP_PROMPTS: List[MCPPrompt] = [
    MCPPrompt(
        name="analyze_finding",
        description="Analyze a security finding and provide remediation guidance",
        arguments=[
            {"name": "finding_id", "description": "The finding ID to analyze", "required": True},
        ],
    ),
    MCPPrompt(
        name="explain_cve",
        description="Explain a CVE with blast radius and exploitation likelihood",
        arguments=[
            {"name": "cve_id", "description": "The CVE ID (e.g., CVE-2024-3094)", "required": True},
        ],
    ),
    MCPPrompt(
        name="suggest_remediation",
        description="Suggest remediation steps for a finding",
        arguments=[
            {"name": "finding_id", "description": "The finding ID", "required": True},
            {"name": "context", "description": "Additional context about the environment", "required": False},
        ],
    ),
]


# ═══════════════════════════════════════════════════════════════════════════════
# Endpoints
# ═══════════════════════════════════════════════════════════════════════════════


@router.get("/status", response_model=MCPStatusResponse)
async def get_mcp_status():
    """Get MCP server status and statistics."""
    uptime = (datetime.utcnow() - _mcp_start_time).total_seconds()
    
    return MCPStatusResponse(
        enabled=_mcp_config.enabled,
        transport=_mcp_config.transport,
        connected_clients=len([c for c in _mcp_clients.values() if c.status == MCPClientStatus.CONNECTED]),
        available_tools=len(MCP_TOOLS),
        available_resources=len(MCP_RESOURCES),
        available_prompts=len(MCP_PROMPTS),
        uptime_seconds=uptime,
    )


@router.get("/clients", response_model=List[MCPClient])
async def list_mcp_clients(
    status: Optional[MCPClientStatus] = None,
    client_type: Optional[str] = None,
):
    """List connected MCP clients."""
    clients = list(_mcp_clients.values())
    
    if status:
        clients = [c for c in clients if c.status == status]
    if client_type:
        clients = [c for c in clients if c.client_type == client_type]
    
    return clients


@router.get("/tools", response_model=List[MCPTool])
async def list_mcp_tools(
    category: Optional[str] = None,
):
    """List available MCP tools."""
    tools = MCP_TOOLS
    
    if category:
        tools = [t for t in tools if t.category == category]
    
    # Filter by exposed_tools config if set
    if _mcp_config.exposed_tools:
        tools = [t for t in tools if t.name in _mcp_config.exposed_tools]
    
    return tools


@router.get("/resources", response_model=List[MCPResource])
async def list_mcp_resources():
    """List available MCP resources."""
    resources = MCP_RESOURCES
    
    if _mcp_config.exposed_resources:
        resources = [r for r in resources if r.uri in _mcp_config.exposed_resources]
    
    return resources


@router.get("/prompts", response_model=List[MCPPrompt])
async def list_mcp_prompts():
    """List available MCP prompts."""
    return MCP_PROMPTS


@router.get("/config", response_model=MCPServerConfig)
async def get_mcp_config():
    """Get current MCP server configuration."""
    return _mcp_config


@router.post("/configure", response_model=MCPServerConfig)
async def configure_mcp_server(config: MCPConfigureRequest):
    """Update MCP server configuration."""
    global _mcp_config
    
    if config.enabled is not None:
        _mcp_config.enabled = config.enabled
    if config.transport is not None:
        _mcp_config.transport = config.transport
    if config.port is not None:
        _mcp_config.port = config.port
    if config.allowed_origins is not None:
        _mcp_config.allowed_origins = config.allowed_origins
    if config.require_auth is not None:
        _mcp_config.require_auth = config.require_auth
    if config.exposed_tools is not None:
        _mcp_config.exposed_tools = config.exposed_tools
    if config.rate_limit_per_minute is not None:
        _mcp_config.rate_limit_per_minute = config.rate_limit_per_minute
    
    logger.info(f"MCP config updated: {_mcp_config}")
    return _mcp_config


@router.post("/clients/{client_id}/disconnect")
async def disconnect_client(client_id: str):
    """Disconnect an MCP client."""
    if client_id not in _mcp_clients:
        raise HTTPException(status_code=404, detail=f"Client {client_id} not found")
    
    _mcp_clients[client_id].status = MCPClientStatus.DISCONNECTED
    return {"message": f"Client {client_id} disconnected"}


@router.delete("/clients/{client_id}")
async def remove_client(client_id: str):
    """Remove an MCP client registration."""
    if client_id not in _mcp_clients:
        raise HTTPException(status_code=404, detail=f"Client {client_id} not found")
    
    del _mcp_clients[client_id]
    return {"message": f"Client {client_id} removed"}


# ═══════════════════════════════════════════════════════════════════════════════
# Connection manifest for IDE clients
# ═══════════════════════════════════════════════════════════════════════════════


@router.get("/manifest")
async def get_mcp_manifest():
    """
    Get MCP server manifest for IDE/agent configuration.
    
    This returns the JSON configuration that can be added to VS Code settings,
    Cursor's .cursor/mcp.json, or Claude Desktop's config.
    """
    return {
        "mcpServers": {
            "fixops": {
                "command": "uvx",
                "args": ["mcp-server-fixops"],
                "env": {
                    "FIXOPS_API_URL": "http://localhost:8000",
                    "FIXOPS_API_KEY": "${FIXOPS_API_KEY}",
                },
                "description": "FixOps security platform - findings, scans, evidence, remediation",
                "transport": _mcp_config.transport.value,
            }
        },
        "http_sse_config": {
            "url": "http://localhost:8000/api/v1/mcp/sse",
            "headers": {
                "Authorization": "Bearer ${FIXOPS_API_KEY}",
            },
        },
    }
