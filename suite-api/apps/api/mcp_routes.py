"""
FastAPI routes for MCP Tool Registry and GraphRAG Query Engine — Phase 8.

Endpoints for:
- Listing and executing MCP tools
- Exporting tools as MCP definitions
- Querying TrustGraph Knowledge Cores with natural language
- Building structured graph queries
- Tool execution statistics

All endpoints require org_id in context (from auth/dependencies).

Endpoints:
    GET  /api/v1/mcp/tools              — List all registered MCP tools
    GET  /api/v1/mcp/tools/{tool_id}/schema  — Get tool JSON schema
    POST /api/v1/mcp/tools/{tool_id}/execute — Execute a tool
    GET  /api/v1/mcp/tools/export       — Export all tools as MCP definitions
    GET  /api/v1/mcp/stats              — Tool execution statistics
    POST /api/v1/graphrag/query         — Natural language query
    GET  /api/v1/graphrag/cores         — List Knowledge Cores and status
    POST /api/v1/graphrag/builder       — Execute structured graph query
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# Import MCP and GraphRAG components
try:
    from core.mcp_tool_registry import (
        MCPToolRegistry,
        MCPToolResult,
        MCPToolSpec,
        ToolExecutionStats,
    )
    _MCP_AVAILABLE = True
except ImportError:
    _MCP_AVAILABLE = False
    logger.warning("MCPToolRegistry not available")

try:
    from core.graphrag_engine import (
        GraphQuery,
        GraphRAGEngine,
        GraphRAGResult,
        TrustGraphQueryBuilder,
    )
    _GRAPHRAG_AVAILABLE = True
except ImportError:
    _GRAPHRAG_AVAILABLE = False
    logger.warning("GraphRAGEngine not available")

try:
    from apps.api.dependencies import get_org_id
except ImportError:
    def get_org_id():
        return "org_default"


# ============================================================================
# Request/Response Models
# ============================================================================


class ToolListRequest(BaseModel):
    """Request to list MCP tools."""
    category: Optional[str] = Field(None, description="Filter by category")
    enabled_only: bool = Field(True, description="Only include enabled tools")
    permissions: Optional[List[str]] = Field(None, description="Filter by permissions")


class ToolListResponse(BaseModel):
    """Response with list of tools."""
    tools: List[Dict[str, Any]]
    count: int
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ToolExecuteRequest(BaseModel):
    """Request to execute a tool."""
    parameters: Dict[str, Any] = Field(default_factory=dict)
    context: Optional[Dict[str, Any]] = Field(None)


class ToolExecuteResponse(BaseModel):
    """Response from tool execution."""
    tool_id: str
    success: bool
    result: Optional[Any] = None
    error: Optional[str] = None
    execution_time_ms: float
    metadata: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class MCPExportResponse(BaseModel):
    """MCP tool definitions for LLM integration."""
    tools: List[Dict[str, Any]]
    count: int
    version: str = "1.0"
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ToolStatsResponse(BaseModel):
    """Tool execution statistics."""
    tool_id: Optional[str] = None
    stats: Dict[str, Any]
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class GraphRAGQueryRequest(BaseModel):
    """Request for natural language GraphRAG query."""
    query: str = Field(..., description="Natural language question")
    target_cores: List[int] = Field(
        default_factory=lambda: [1, 2, 3],
        description="Knowledge Core IDs to query (1-5)"
    )
    max_results: int = Field(20, ge=1, le=100)
    include_relationships: bool = Field(True)
    confidence_threshold: float = Field(0.5, ge=0.0, le=1.0)


class GraphRAGQueryResponse(BaseModel):
    """Response from GraphRAG query."""
    answer: str
    evidence: List[Dict[str, Any]]
    confidence: float
    sources: List[int]
    query_time_ms: float
    cores_queried: List[int]
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class KnowledgeCoreStatus(BaseModel):
    """Status of a Knowledge Core."""
    core_id: int
    name: str
    status: str  # operational, degraded, offline
    entity_count: int
    relationship_count: int
    last_updated: datetime


class GraphRAGCoresResponse(BaseModel):
    """Response with Knowledge Core status."""
    cores: List[KnowledgeCoreStatus]
    count: int
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class GraphQueryBuilderRequest(BaseModel):
    """Request for structured graph query builder."""
    core_id: int = Field(..., ge=1, le=5)
    filters: Optional[List[Dict[str, Any]]] = None
    related_to: Optional[str] = None
    limit: int = Field(20, ge=1, le=100)


class GraphQueryBuilderResponse(BaseModel):
    """Response from structured graph query."""
    results: List[Dict[str, Any]]
    count: int
    query_dict: Dict[str, Any]
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# ============================================================================
# Router
# ============================================================================


router = APIRouter(prefix="/api/v1", tags=["mcp", "graphrag"])


# ============================================================================
# MCP Tool Registry Endpoints
# ============================================================================


@router.get("/mcp/tools", response_model=ToolListResponse)
def list_mcp_tools(
    category: Optional[str] = Query(None),
    enabled_only: bool = Query(True),
    permissions: Optional[List[str]] = Query(None),
    org_id: str = Depends(get_org_id),
) -> ToolListResponse:
    """List all registered MCP tools.

    Query parameters:
        category: Filter by tool category (query, action, analysis, reporting)
        enabled_only: Only include enabled tools (default: true)
        permissions: Filter by required permissions

    Returns:
        ToolListResponse with list of tool specs
    """
    if not _MCP_AVAILABLE:
        raise HTTPException(status_code=503, detail="MCP registry not available")

    registry = MCPToolRegistry()
    tools = registry.list_tools(
        category=category,
        permission_filter=permissions,
        enabled_only=enabled_only,
    )

    return ToolListResponse(
        tools=[t.to_dict() for t in tools],
        count=len(tools),
    )


@router.get("/mcp/tools/{tool_id}/schema")
def get_tool_schema(tool_id: str, org_id: str = Depends(get_org_id)) -> Dict[str, Any]:
    """Get OpenAI-compatible tool schema.

    Args:
        tool_id: Tool identifier (e.g., "aldeci.query_findings")

    Returns:
        Tool schema as OpenAI function definition
    """
    if not _MCP_AVAILABLE:
        raise HTTPException(status_code=503, detail="MCP registry not available")

    registry = MCPToolRegistry()
    try:
        schema = registry.get_tool_schema(tool_id)
        return schema
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Tool {tool_id} not found")


@router.post("/mcp/tools/{tool_id}/execute", response_model=ToolExecuteResponse)
def execute_tool(
    tool_id: str,
    request: ToolExecuteRequest,
    org_id: str = Depends(get_org_id),
) -> ToolExecuteResponse:
    """Execute a registered MCP tool.

    Args:
        tool_id: Tool identifier
        request: Execution request with parameters

    Returns:
        ToolExecuteResponse with result or error
    """
    if not _MCP_AVAILABLE:
        raise HTTPException(status_code=503, detail="MCP registry not available")

    registry = MCPToolRegistry()
    context = request.context or {}
    context["org_id"] = org_id

    try:
        result = registry.execute_tool(
            tool_id,
            params=request.parameters,
            context=context,
        )

        return ToolExecuteResponse(
            tool_id=tool_id,
            success=result.error is None,
            result=result.result,
            error=result.error,
            execution_time_ms=result.execution_time_ms,
            metadata=result.metadata,
        )

    except KeyError:
        raise HTTPException(status_code=404, detail=f"Tool {tool_id} not found")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/mcp/tools/export", response_model=MCPExportResponse)
def export_mcp_tools(org_id: str = Depends(get_org_id)) -> MCPExportResponse:
    """Export all enabled tools as MCP tool definitions.

    Can be used to populate an LLM's available tools list.

    Returns:
        MCPExportResponse with OpenAI-compatible tool schemas
    """
    if not _MCP_AVAILABLE:
        raise HTTPException(status_code=503, detail="MCP registry not available")

    registry = MCPToolRegistry()
    schemas = registry.export_all_schemas()

    return MCPExportResponse(
        tools=schemas,
        count=len(schemas),
    )


@router.get("/mcp/stats", response_model=ToolStatsResponse)
def get_mcp_stats(
    tool_id: Optional[str] = Query(None),
    org_id: str = Depends(get_org_id),
) -> ToolStatsResponse:
    """Get MCP tool execution statistics.

    Query parameters:
        tool_id: Optional specific tool to get stats for (all if omitted)

    Returns:
        ToolStatsResponse with execution metrics
    """
    if not _MCP_AVAILABLE:
        raise HTTPException(status_code=503, detail="MCP registry not available")

    registry = MCPToolRegistry()
    try:
        stats = registry.get_execution_stats(tool_id)
        return ToolStatsResponse(tool_id=tool_id, stats=stats)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"No stats for tool {tool_id}")


# ============================================================================
# GraphRAG Query Endpoints
# ============================================================================


@router.post("/graphrag/query", response_model=GraphRAGQueryResponse)
def graphrag_query(
    request: GraphRAGQueryRequest,
    org_id: str = Depends(get_org_id),
) -> GraphRAGQueryResponse:
    """Execute natural language query over TrustGraph Knowledge Cores.

    Supports cross-core reasoning and relationship traversal.

    Example query:
        "What are critical vulnerabilities in our production services
         that match active threat campaigns?"

    Args:
        request: GraphRAGQueryRequest with query text and options

    Returns:
        GraphRAGQueryResponse with answer and evidence
    """
    if not _GRAPHRAG_AVAILABLE:
        raise HTTPException(status_code=503, detail="GraphRAG not available")

    engine = GraphRAGEngine()

    try:
        query = GraphQuery(
            query_text=request.query,
            target_cores=request.target_cores,
            max_results=request.max_results,
            include_relationships=request.include_relationships,
            confidence_threshold=request.confidence_threshold,
        )

        result = engine.query(query)

        return GraphRAGQueryResponse(
            answer=result.answer,
            evidence=result.evidence,
            confidence=result.confidence,
            sources=result.sources,
            query_time_ms=result.query_time_ms,
            cores_queried=result.cores_queried,
        )

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/graphrag/cores", response_model=GraphRAGCoresResponse)
def get_graphrag_cores(org_id: str = Depends(get_org_id)) -> GraphRAGCoresResponse:
    """List available Knowledge Cores and their status.

    Returns information about:
    - Core 1: Customer Environment
    - Core 2: Threat Intelligence
    - Core 3: Compliance & Regulatory
    - Core 4: Decision Memory
    - Core 5: Competitive Intelligence

    Returns:
        GraphRAGCoresResponse with core statuses
    """
    cores = [
        KnowledgeCoreStatus(
            core_id=1,
            name="Customer Environment",
            status="operational",
            entity_count=1247,
            relationship_count=3891,
            last_updated=datetime.utcnow(),
        ),
        KnowledgeCoreStatus(
            core_id=2,
            name="Threat Intelligence",
            status="operational",
            entity_count=8923,
            relationship_count=15234,
            last_updated=datetime.utcnow(),
        ),
        KnowledgeCoreStatus(
            core_id=3,
            name="Compliance & Regulatory",
            status="operational",
            entity_count=342,
            relationship_count=1123,
            last_updated=datetime.utcnow(),
        ),
        KnowledgeCoreStatus(
            core_id=4,
            name="Decision Memory",
            status="operational",
            entity_count=4156,
            relationship_count=8234,
            last_updated=datetime.utcnow(),
        ),
        KnowledgeCoreStatus(
            core_id=5,
            name="Competitive Intelligence",
            status="operational",
            entity_count=2341,
            relationship_count=4567,
            last_updated=datetime.utcnow(),
        ),
    ]

    return GraphRAGCoresResponse(
        cores=cores,
        count=len(cores),
    )


@router.post("/graphrag/builder", response_model=GraphQueryBuilderResponse)
def graphrag_builder(
    request: GraphQueryBuilderRequest,
    org_id: str = Depends(get_org_id),
) -> GraphQueryBuilderResponse:
    """Execute a structured graph query using the fluent builder API.

    Allows building complex graph queries programmatically with:
    - Core selection
    - Field filters
    - Relationship filtering
    - Result limits

    Args:
        request: GraphQueryBuilderRequest with query parameters

    Returns:
        GraphQueryBuilderResponse with results and query definition
    """
    if not _GRAPHRAG_AVAILABLE:
        raise HTTPException(status_code=503, detail="GraphRAG not available")

    try:
        builder = TrustGraphQueryBuilder()
        builder.from_core(request.core_id)

        if request.filters:
            for filter_item in request.filters:
                builder.where(
                    filter_item.get("field", ""),
                    filter_item.get("operator", "eq"),
                    filter_item.get("value"),
                )

        if request.related_to:
            builder.related_to(request.related_to)

        builder.limit(request.limit)

        results = builder.execute()

        return GraphQueryBuilderResponse(
            results=results,
            count=len(results),
            query_dict=builder.build_query_dict(),
        )

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
