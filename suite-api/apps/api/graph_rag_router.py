"""
GraphRAG API Router for TrustGraph semantic retrieval.

Exposes graph-based retrieval augmented generation endpoints so security
analysts and the Copilot can query the TrustGraph knowledge graph with
natural language and get relationship-traversed context back.

Endpoints:
- POST /api/v1/graphrag/retrieve
- GET  /api/v1/graphrag/entities/{entity_id}/neighborhood
- POST /api/v1/graphrag/semantic-search
- GET  /api/v1/graphrag/health
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

# GraphRAG retriever — lazy import so sitecustomize.py sys.path is in effect
_retriever: Optional[Any] = None
_HAS_GRAPHRAG: Optional[bool] = None  # None = not yet probed


def _get_retriever():
    """Lazy singleton — import deferred until first request so sitecustomize paths are set."""
    global _retriever, _HAS_GRAPHRAG
    if _HAS_GRAPHRAG is None:
        try:
            from trustgraph.graph_rag import GraphRAGRetriever as _GRR
            _retriever = _GRR()
            _HAS_GRAPHRAG = True
        except Exception as _exc:
            _HAS_GRAPHRAG = False
            logging.getLogger(__name__).warning("GraphRAG not available: %s", _exc)
    return _retriever


def _graphrag_available() -> bool:
    """Probe availability (cached after first call)."""
    _get_retriever()
    return bool(_HAS_GRAPHRAG)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/graphrag", tags=["graphrag"])


# =============================================================================
# Request / Response models
# =============================================================================


class RetrieveRequest(BaseModel):
    """Request body for /retrieve."""

    query: str = Field(..., description="Natural language security query")
    top_k: int = Field(10, ge=1, le=100, description="Max seed entities")
    hops: int = Field(2, ge=0, le=3, description="Relationship traversal depth")


class SemanticSearchRequest(BaseModel):
    """Request body for /semantic-search."""

    query: str = Field(..., description="Natural language search query")
    entity_types: Optional[List[str]] = Field(
        None,
        description="Filter by entity types (e.g. CVE, Asset, Incident, Control)",
    )


class EntityResult(BaseModel):
    """A single entity in a result set."""

    id: str
    type: str
    name: str
    score: float
    properties: Dict[str, Any] = Field(default_factory=dict)


class RelationshipResult(BaseModel):
    """A single relationship in a result set."""

    from_entity: str = Field(alias="from")
    to_entity: str = Field(alias="to")
    type: str

    model_config = {"populate_by_name": True}


class RetrieveResponse(BaseModel):
    """Response from /retrieve."""

    query: str
    entities: List[Dict[str, Any]]
    relationships: List[Dict[str, Any]]
    context_summary: str
    retrieval_method: str


class NeighborhoodResponse(BaseModel):
    """Response from /entities/{entity_id}/neighborhood."""

    entity_id: str
    entities: List[Dict[str, Any]]
    relationships: List[Dict[str, Any]]


class GraphHealthResponse(BaseModel):
    """Response from /health."""

    status: str
    graph_rag_available: bool
    total_entities: int
    total_relationships: int
    cores: Dict[str, Any]


# =============================================================================
# Endpoints
# =============================================================================


@router.post("/retrieve", response_model=RetrieveResponse)
async def retrieve(body: RetrieveRequest) -> RetrieveResponse:
    """GraphRAG retrieval: find entities relevant to a query and traverse
    their relationships to build LLM-ready context.

    - **query**: Natural language security question or topic
    - **top_k**: How many seed entities to find (default 10)
    - **hops**: How many relationship hops to traverse (0-3, default 2)
    """
    if not _graphrag_available():
        raise HTTPException(status_code=503, detail={"error": "graphrag_engine_unavailable"})

    try:
        result = _get_retriever().retrieve(
            query=body.query,
            top_k=body.top_k,
            hops=body.hops,
        )
        return RetrieveResponse(**result)
    except Exception as exc:
        logger.error(f"retrieve endpoint error: {exc}")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get(
    "/entities/{entity_id}/neighborhood",
    response_model=NeighborhoodResponse,
)
async def entity_neighborhood(
    entity_id: str,
    hops: int = 1,
) -> NeighborhoodResponse:
    """Get all entities and relationships within N hops of a given entity.

    - **entity_id**: The entity to start from
    - **hops**: Traversal depth (1-3, default 1)
    """
    if hops < 1 or hops > 3:
        raise HTTPException(status_code=422, detail="hops must be between 1 and 3")

    if not _graphrag_available():
        raise HTTPException(status_code=503, detail={"error": "graphrag_engine_unavailable"})

    try:
        result = _get_retriever().get_entity_neighborhood(
            entity_id=entity_id, hops=hops
        )
        return NeighborhoodResponse(**result)
    except Exception as exc:
        logger.error(f"entity_neighborhood endpoint error: {exc}")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/semantic-search")
async def semantic_search(body: SemanticSearchRequest) -> List[Dict[str, Any]]:
    """Search entities with optional type filtering.

    - **query**: Natural language search query
    - **entity_types**: Optional list of types to restrict (CVE, Asset, Incident, Control, etc.)
    """
    if not _graphrag_available():
        raise HTTPException(status_code=503, detail={"error": "graphrag_engine_unavailable"})

    try:
        return _get_retriever().semantic_search(
            query=body.query,
            entity_types=body.entity_types,
        )
    except Exception as exc:
        logger.error(f"semantic_search endpoint error: {exc}")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/health", response_model=GraphHealthResponse)
async def health() -> GraphHealthResponse:
    """Return graph health and statistics across all knowledge cores."""
    if not _graphrag_available():
        return GraphHealthResponse(
            status="degraded",
            graph_rag_available=False,
            total_entities=0,
            total_relationships=0,
            cores={},
        )

    try:
        retriever = _get_retriever()
        store = retriever._store

        if store is None:
            return GraphHealthResponse(
                status="degraded",
                graph_rag_available=True,
                total_entities=0,
                total_relationships=0,
                cores={},
            )

        cores: Dict[str, Any] = {}
        total_entities = 0
        total_relationships = 0

        for core_id in range(1, 6):
            try:
                stats = store.core_stats(core_id)
                cores[str(core_id)] = stats
                total_entities += stats.get("entity_count", 0)
                total_relationships += stats.get("relationship_count", 0)
            except Exception as exc:
                logger.debug(f"core_stats core={core_id} failed: {exc}")
                cores[str(core_id)] = {"error": str(exc)}

        return GraphHealthResponse(
            status="ok",
            graph_rag_available=True,
            total_entities=total_entities,
            total_relationships=total_relationships,
            cores=cores,
        )
    except Exception as exc:
        logger.error(f"health endpoint error: {exc}")
        raise HTTPException(status_code=500, detail=str(exc))
