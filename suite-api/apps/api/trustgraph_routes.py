"""
TrustGraph FastAPI Routes for ALDECI.

Provides HTTP endpoints for TrustGraph knowledge operations, MCP tool exposure,
and cross-core querying. Supports multi-tenancy via org_id context.

Routes:
- POST /api/v1/trustgraph/query — Natural language query
- POST /api/v1/trustgraph/ingest — Ingest entity
- POST /api/v1/trustgraph/search — Structured search
- POST /api/v1/trustgraph/relate — Create relationship
- GET /api/v1/trustgraph/entities/{entity_id} — Get entity
- GET /api/v1/trustgraph/cores — List cores
- GET /api/v1/trustgraph/cores/{core_id}/stats — Core stats
- GET /api/v1/trustgraph/mcp/tools — MCP tool definitions
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from trustgraph import get_mcp_server

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/trustgraph", tags=["trustgraph"])


# ============================================================================
# Request/Response Models
# ============================================================================


class QueryRequest(BaseModel):
    """Natural language query request."""

    query: str = Field(..., description="Natural language query")
    target_cores: Optional[List[int]] = Field(default=[1, 2, 3], description="Cores to query")
    max_results: Optional[int] = Field(default=20, description="Maximum results per core")


class IngestRequest(BaseModel):
    """Entity ingestion request."""

    entity_id: str
    core_id: int
    entity_type: str
    name: str
    properties: Optional[Dict[str, Any]] = Field(default_factory=dict)


class SearchRequest(BaseModel):
    """Structured search request."""

    core_id: int
    query: str
    entity_type: Optional[str] = None
    limit: Optional[int] = Field(default=20)


class RelateRequest(BaseModel):
    """Create relationship request."""

    source_id: str
    target_id: str
    rel_type: str
    confidence: Optional[float] = Field(default=1.0)
    properties: Optional[Dict[str, Any]] = Field(default_factory=dict)


class EntityResponse(BaseModel):
    """Entity with relationships."""

    entity: Dict[str, Any]
    relationships: List[Dict[str, Any]]
    relationship_count: int


class QueryResponse(BaseModel):
    """Query result."""

    answer: str
    evidence: List[Dict[str, Any]]
    confidence: float
    sources: List[int]
    query_time_ms: float


class SearchResponse(BaseModel):
    """Search results."""

    core_id: int
    query: str
    count: int
    results: List[Dict[str, Any]]


class CoreStats(BaseModel):
    """Core statistics."""

    entity_count: int
    relationship_count: int
    last_updated: Optional[str]
    entity_types: Dict[str, int]


class CoreResponse(BaseModel):
    """Knowledge Core information."""

    core_id: int
    name: str
    description: str
    entity_types: List[str]
    stats: CoreStats


class RelateResponse(BaseModel):
    """Relationship creation response."""

    status: str
    rel_id: str
    source_id: str
    target_id: str
    rel_type: str
    confidence: float


class ToolSchema(BaseModel):
    """MCP Tool schema."""

    name: str
    description: str
    inputSchema: Dict[str, Any]


# ============================================================================
# Dependencies
# ============================================================================


def get_org_id(org_id: Optional[str] = Query(None)) -> str:
    """Extract org_id from request context.

    Args:
        org_id: Organization ID from query parameter

    Returns:
        Organization ID (or 'default')
    """
    return org_id or "default"


# ============================================================================
# Endpoints: Query and Search
# ============================================================================


@router.post("/query", response_model=QueryResponse)
async def query_trustgraph(
    req: QueryRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Execute natural language query across Knowledge Cores.

    Args:
        req: Query request
        org_id: Organization ID

    Returns:
        Query result with answer, evidence, and confidence
    """
    try:
        server = get_mcp_server()
        result = server.call_tool(
            "trustgraph.query",
            {
                "query": req.query,
                "target_cores": req.target_cores,
                "max_results": req.max_results,
            },
            org_id=org_id,
        )

        if "error" in result:
            raise HTTPException(status_code=400, detail=result["error"])

        return result

    except Exception as e:  # noqa: BLE001 - router error boundary; any exception must become HTTP 500, not leak to ASGI
        logger.error(f"Query failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/search", response_model=SearchResponse)
async def search_trustgraph(
    req: SearchRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Execute structured search in a Knowledge Core.

    Args:
        req: Search request
        org_id: Organization ID

    Returns:
        Search results
    """
    try:
        server = get_mcp_server()
        params = {
            "core_id": req.core_id,
            "query": req.query,
            "limit": req.limit,
        }
        if req.entity_type:
            params["entity_type"] = req.entity_type

        result = server.call_tool(
            "trustgraph.search",
            params,
            org_id=org_id,
        )

        if "error" in result:
            raise HTTPException(status_code=400, detail=result["error"])

        return result

    except Exception as e:  # noqa: BLE001 - router error boundary; any exception must become HTTP 500, not leak to ASGI
        logger.error(f"Search failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Endpoints: Entity Management
# ============================================================================


@router.post("/ingest")
async def ingest_entity(
    req: IngestRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Ingest an entity into a Knowledge Core.

    Args:
        req: Ingestion request
        org_id: Organization ID

    Returns:
        Ingestion confirmation
    """
    try:
        server = get_mcp_server()
        params = {
            "entity_id": req.entity_id,
            "core_id": req.core_id,
            "entity_type": req.entity_type,
            "name": req.name,
            "properties": req.properties,
        }

        result = server.call_tool(
            "trustgraph.ingest",
            params,
            org_id=org_id,
        )

        if "error" in result:
            raise HTTPException(status_code=400, detail=result["error"])

        return result

    except Exception as e:  # noqa: BLE001 - router error boundary; any exception must become HTTP 500, not leak to ASGI
        logger.error(f"Ingestion failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/entities/{entity_id}", response_model=EntityResponse)
async def get_entity(entity_id: str) -> Dict[str, Any]:
    """Get entity details by ID.

    Args:
        entity_id: Entity ID to retrieve

    Returns:
        Entity with relationships
    """
    try:
        server = get_mcp_server()
        result = server.call_tool("trustgraph.get_entity", {"entity_id": entity_id})

        if "error" in result:
            raise HTTPException(status_code=404, detail=result["error"])

        return result

    except HTTPException:
        raise
    except Exception as e:  # noqa: BLE001 - router error boundary; any exception must become HTTP 500, not leak to ASGI
        logger.error(f"Get entity failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Endpoints: Relationships
# ============================================================================


@router.post("/relate", response_model=RelateResponse)
async def create_relationship(req: RelateRequest) -> Dict[str, Any]:
    """Create a relationship between entities.

    Args:
        req: Relationship creation request

    Returns:
        Relationship confirmation
    """
    try:
        server = get_mcp_server()
        result = server.call_tool(
            "trustgraph.relate",
            {
                "source_id": req.source_id,
                "target_id": req.target_id,
                "rel_type": req.rel_type,
                "confidence": req.confidence,
                "properties": req.properties,
            },
        )

        if "error" in result:
            raise HTTPException(status_code=400, detail=result["error"])

        return result

    except Exception as e:  # noqa: BLE001 - router error boundary; any exception must become HTTP 500, not leak to ASGI
        logger.error(f"Relationship creation failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Endpoints: Core Management
# ============================================================================


@router.get("/cores", response_model=Dict[str, Any])
async def list_cores() -> Dict[str, Any]:
    """List all Knowledge Cores with summary statistics.

    Returns:
        List of cores with metadata and stats
    """
    try:
        server = get_mcp_server()
        result = server.call_tool("trustgraph.list_cores", {})

        if "error" in result:
            raise HTTPException(status_code=400, detail=result["error"])

        return result

    except Exception as e:  # noqa: BLE001 - router error boundary; any exception must become HTTP 500, not leak to ASGI
        logger.error(f"List cores failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/cores/{core_id}/stats", response_model=CoreResponse)
async def get_core_stats(core_id: int) -> Dict[str, Any]:
    """Get detailed statistics for a Knowledge Core.

    Args:
        core_id: Knowledge Core ID (1-5)

    Returns:
        Core metadata and statistics
    """
    if not 1 <= core_id <= 5:
        raise HTTPException(status_code=400, detail="core_id must be 1-5")

    try:
        server = get_mcp_server()
        result = server.call_tool("trustgraph.core_stats", {"core_id": core_id})

        if "error" in result:
            raise HTTPException(status_code=400, detail=result["error"])

        return result

    except Exception as e:  # noqa: BLE001 - router error boundary; any exception must become HTTP 500, not leak to ASGI
        logger.error(f"Get core stats failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Endpoints: MCP Tool Exposure
# ============================================================================


@router.get("/mcp/tools", response_model=List[ToolSchema])
async def list_mcp_tools() -> List[Dict[str, Any]]:
    """List MCP tool definitions for integration with LLM agents.

    Returns:
        List of MCP tool schemas
    """
    try:
        server = get_mcp_server()
        tools = server.list_tools()
        return tools

    except Exception as e:  # noqa: BLE001 - router error boundary; any exception must become HTTP 500, not leak to ASGI
        logger.error(f"List MCP tools failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/audit/log", response_model=List[Dict[str, Any]])
async def get_audit_log(limit: int = Query(100, ge=1, le=1000)) -> List[Dict[str, Any]]:
    """Get recent tool call audit logs.

    Args:
        limit: Maximum records to return

    Returns:
        List of audit records
    """
    try:
        server = get_mcp_server()
        logs = server.get_audit_log(limit=limit)
        return logs

    except Exception as e:  # noqa: BLE001 - router error boundary; any exception must become HTTP 500, not leak to ASGI
        logger.error(f"Get audit log failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
