"""
TrustGraph Backbone API Router.

Exposes HTTP endpoints for entity indexing, relationship management,
impact analysis, root cause tracing, attack path queries, and
semantic search over the TrustGraph knowledge graph.

Routes:
- POST /api/v1/graph/index         — index any entity
- POST /api/v1/graph/link          — create relationship
- GET  /api/v1/graph/impact/{id}   — impact analysis
- GET  /api/v1/graph/root-cause/{id} — root cause trace
- GET  /api/v1/graph/attack-path   — attack path query
- GET  /api/v1/graph/related/{id}  — neighborhood
- GET  /api/v1/graph/search        — semantic search
- GET  /api/v1/graph/stats         — graph statistics
- GET  /api/v1/graph/emit-rate     — live EventBus emit/index rates per event type
- GET  /api/v1/graph/visualize/{id} — graph data for visualization
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/graph", tags=["trustgraph-backbone"])


# ============================================================================
# Request / Response Models
# ============================================================================


class IndexEntityRequest(BaseModel):
    """Index any ALDECI entity into TrustGraph."""

    entity_type: str = Field(
        ...,
        description="One of: finding, asset, incident, compliance_control, vendor, threat_actor",
    )
    data: Dict[str, Any] = Field(..., description="Entity data payload")
    org_id: Optional[str] = Field(default="default", description="Tenant org ID")


class IndexEntityResponse(BaseModel):
    """Response after indexing an entity."""

    entity_id: str
    entity_type: str
    status: str


class LinkEntitiesRequest(BaseModel):
    """Create a typed relationship between two entities."""

    entity_a_id: str = Field(..., description="Source entity ID")
    entity_b_id: str = Field(..., description="Target entity ID")
    relationship_type: str = Field(..., description="Relationship type (see RelationshipType constants)")
    confidence: float = Field(default=0.95, ge=0.0, le=1.0, description="Edge confidence score")
    properties: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Optional edge properties")
    org_id: Optional[str] = Field(default="default", description="Tenant org ID")


class LinkEntitiesResponse(BaseModel):
    """Response after creating a relationship."""

    rel_id: str
    entity_a_id: str
    entity_b_id: str
    relationship_type: str
    status: str


class GraphQueryResponse(BaseModel):
    """Generic graph query response."""

    available: bool
    data: Dict[str, Any]


# ============================================================================
# Dependency: backbone singleton
# ============================================================================


def _get_backbone(org_id: str = "default") -> Any:
    """Get TrustGraphBackbone instance for the request org."""
    from core.trustgraph_backbone import TrustGraphBackbone
    return TrustGraphBackbone(org_id=org_id)


def _get_graphrag(org_id: str = "default") -> Any:
    """Get GraphRAGEnhanced instance for the request org."""
    from core.trustgraph_backbone import GraphRAGEnhanced
    return GraphRAGEnhanced(org_id=org_id)


# ============================================================================
# POST /api/v1/graph/index
# ============================================================================


_INDEXERS = {
    "finding": "index_finding",
    "asset": "index_asset",
    "incident": "index_incident",
    "compliance_control": "index_compliance_control",
    "vendor": "index_vendor",
    "threat_actor": "index_threat_actor",
}


@router.post("/index", response_model=IndexEntityResponse)
async def index_entity(req: IndexEntityRequest) -> Dict[str, Any]:
    """Index any ALDECI entity into TrustGraph.

    Supports entity types: finding, asset, incident, compliance_control,
    vendor, threat_actor. Indexing is idempotent (upsert semantics).

    Args:
        req: Entity indexing request

    Returns:
        entity_id, entity_type, status
    """
    entity_type = req.entity_type.lower()
    if entity_type not in _INDEXERS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown entity_type '{entity_type}'. Valid: {list(_INDEXERS.keys())}",
        )

    try:
        backbone = _get_backbone(org_id=req.org_id or "default")
        indexer_method = getattr(backbone, _INDEXERS[entity_type])
        entity_id = indexer_method(req.data)
        return {
            "entity_id": entity_id,
            "entity_type": entity_type,
            "status": "indexed",
        }
    except Exception as exc:  # noqa: BLE001 — router error boundary
        logger.error("graph/index failed for %s: %s", entity_type, exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ============================================================================
# POST /api/v1/graph/link
# ============================================================================


@router.post("/link", response_model=LinkEntitiesResponse)
async def link_entities(req: LinkEntitiesRequest) -> Dict[str, Any]:
    """Create a typed relationship between two graph entities.

    Args:
        req: Link entities request with source, target, and relationship type

    Returns:
        rel_id and confirmation
    """
    try:
        backbone = _get_backbone(org_id=req.org_id or "default")
        rel_id = backbone.link_entities(
            entity_a_id=req.entity_a_id,
            entity_b_id=req.entity_b_id,
            relationship_type=req.relationship_type,
            confidence=req.confidence,
            properties=req.properties or {},
        )
        return {
            "rel_id": rel_id or "unavailable",
            "entity_a_id": req.entity_a_id,
            "entity_b_id": req.entity_b_id,
            "relationship_type": req.relationship_type,
            "status": "linked" if rel_id else "unavailable",
        }
    except Exception as exc:  # noqa: BLE001 — router error boundary
        logger.error("graph/link failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ============================================================================
# GET /api/v1/graph/impact/{entity_id}
# ============================================================================


@router.get("/impact/{entity_id}")
async def get_impact(
    entity_id: str,
    depth: int = Query(default=2, ge=1, le=3, description="Traversal depth"),
    org_id: str = Query(default="default", description="Tenant org ID"),
) -> Dict[str, Any]:
    """What is affected if this entity is compromised?

    Performs graph traversal to identify all transitively affected
    assets, services, and findings.

    Args:
        entity_id: Entity to analyze
        depth: Traversal depth (1-3)
        org_id: Tenant org ID

    Returns:
        Impact analysis with affected entities and summary
    """
    try:
        graphrag = _get_graphrag(org_id=org_id)
        return graphrag.query_impact(entity_id=entity_id, depth=depth)
    except Exception as exc:  # noqa: BLE001 — router error boundary
        logger.error("graph/impact failed for %s: %s", entity_id, exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ============================================================================
# GET /api/v1/graph/root-cause/{finding_id}
# ============================================================================


@router.get("/root-cause/{finding_id}")
async def get_root_cause(
    finding_id: str,
    org_id: str = Query(default="default", description="Tenant org ID"),
) -> Dict[str, Any]:
    """Trace a finding back to its root cause.

    Follows FINDING_EXPLOITS_CVE and FINDING_AFFECTS_ASSET edges to
    identify the underlying vulnerability and affected scope.

    Args:
        finding_id: Finding entity ID
        org_id: Tenant org ID

    Returns:
        Root cause analysis with CVEs, assets, and summary
    """
    try:
        graphrag = _get_graphrag(org_id=org_id)
        return graphrag.query_root_cause(finding_id=finding_id)
    except Exception as exc:  # noqa: BLE001 — router error boundary
        logger.error("graph/root-cause failed for %s: %s", finding_id, exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ============================================================================
# GET /api/v1/graph/attack-path
# ============================================================================


@router.get("/attack-path")
async def get_attack_path(
    source: str = Query(..., description="Source entity ID"),
    target: str = Query(..., description="Target entity ID"),
    org_id: str = Query(default="default", description="Tenant org ID"),
) -> Dict[str, Any]:
    """Find graph paths between source and target entities.

    Uses BFS traversal to model lateral movement or supply chain vectors.

    Args:
        source: Source entity ID
        target: Target entity ID
        org_id: Tenant org ID

    Returns:
        Paths found between source and target
    """
    try:
        graphrag = _get_graphrag(org_id=org_id)
        return graphrag.query_attack_path(source_id=source, target_id=target)
    except Exception as exc:  # noqa: BLE001 — router error boundary
        logger.error("graph/attack-path failed %s->%s: %s", source, target, exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ============================================================================
# GET /api/v1/graph/related/{entity_id}
# ============================================================================


@router.get("/related/{entity_id}")
async def get_related(
    entity_id: str,
    depth: int = Query(default=2, ge=1, le=3, description="Traversal depth"),
    org_id: str = Query(default="default", description="Tenant org ID"),
) -> Dict[str, Any]:
    """Neighborhood exploration — what's related to this entity.

    Args:
        entity_id: Entity to explore
        depth: Traversal depth (1-3)
        org_id: Tenant org ID

    Returns:
        Neighbors grouped by entity type with relationships
    """
    try:
        graphrag = _get_graphrag(org_id=org_id)
        return graphrag.query_related(entity_id=entity_id, depth=depth)
    except Exception as exc:  # noqa: BLE001 — router error boundary
        logger.error("graph/related failed for %s: %s", entity_id, exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ============================================================================
# GET /api/v1/graph/search
# ============================================================================


@router.get("/search")
async def semantic_search(
    q: str = Query(..., description="Natural language search query"),
    cores: Optional[str] = Query(
        default=None, description="Comma-separated core IDs to search (e.g. '1,2,3'). Default: all"
    ),
    limit: int = Query(default=10, ge=1, le=100, description="Max results per core"),
    org_id: str = Query(default="default", description="Tenant org ID"),
) -> Dict[str, Any]:
    """Natural language search across TrustGraph knowledge cores.

    Searches entity names and properties using FTS5 with LIKE fallback.

    Args:
        q: Search query
        cores: Comma-separated list of core IDs (1-5). Default: all cores.
        limit: Max results per core
        org_id: Tenant org ID

    Returns:
        Entities grouped by core
    """
    try:
        core_ids: Optional[List[int]] = None
        if cores:
            try:
                core_ids = [int(c.strip()) for c in cores.split(",") if c.strip()]
            except ValueError:
                raise HTTPException(status_code=400, detail="cores must be comma-separated integers")

        graphrag = _get_graphrag(org_id=org_id)
        return graphrag.semantic_search(query=q, cores=core_ids, limit=limit)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001 — router error boundary
        logger.error("graph/search failed for '%s': %s", q, exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ============================================================================
# GET /api/v1/graph/stats
# ============================================================================


@router.get("/stats")
async def get_stats(
    org_id: str = Query(default="default", description="Tenant org ID"),
) -> Dict[str, Any]:
    """Return graph statistics for all 5 Knowledge Cores.

    Args:
        org_id: Tenant org ID

    Returns:
        Per-core entity and relationship counts with aggregate totals
    """
    try:
        backbone = _get_backbone(org_id=org_id)
        return backbone.get_stats()
    except Exception as exc:  # noqa: BLE001 — router error boundary
        logger.error("graph/stats failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ============================================================================
# GET /api/v1/graph/emit-rate
# ============================================================================


@router.get("/emit-rate")
async def get_emit_rate() -> Dict[str, Any]:
    """Return live TrustGraph EventBus emit and index rates.

    Reads counters directly from the in-process EventBus singleton —
    no DB round-trip, sub-millisecond latency.

    Returns:
        bus_enabled: whether the EventBus is active.
        totals: aggregate emitted / indexed / queued / failed / dropped counts.
        by_type: per-event-type breakdown with emitted, indexed, failed,
                 avg_latency_ms, and index_rate (indexed/emitted ratio, 0-1).
        queue: offline SQLite queue stats (queued / indexed / failed / total).
    """
    try:
        from core.trustgraph_event_bus import get_event_bus

        bus = get_event_bus()
        raw = bus.metrics.to_dict()

        # Compute per-type index rate (ratio of indexed to emitted)
        by_type_annotated: Dict[str, Any] = {}
        for event_type, counters in raw.get("by_type", {}).items():
            emitted = counters.get("emitted", 0)
            indexed = counters.get("indexed", 0)
            by_type_annotated[event_type] = {
                **counters,
                "index_rate": round(indexed / emitted, 4) if emitted > 0 else None,
            }

        return {
            "bus_enabled": bus.enabled,
            "totals": {
                "events_emitted": raw.get("events_emitted", 0),
                "events_indexed": raw.get("events_indexed", 0),
                "events_queued": raw.get("events_queued", 0),
                "events_failed": raw.get("events_failed", 0),
                "events_dropped": raw.get("events_dropped", 0),
                "flush_runs": raw.get("flush_runs", 0),
                "flush_indexed": raw.get("flush_indexed", 0),
            },
            "by_type": by_type_annotated,
            "queue": bus.queue_stats(),
        }
    except Exception as exc:  # noqa: BLE001 — router error boundary
        logger.error("graph/emit-rate failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ============================================================================
# GET /api/v1/graph/pagerank
# ============================================================================


@router.get("/pagerank")
async def get_pagerank(
    limit: int = Query(default=20, ge=1, le=100, description="Top-N nodes to return"),
    alpha: float = Query(default=0.85, ge=0.01, le=0.99, description="Damping factor"),
    org_id: str = Query(default="default", description="Tenant org ID"),
) -> Dict[str, Any]:
    """Return top-N entities ranked by PageRank influence score.

    PageRank measures a node's structural importance inside the TrustGraph
    knowledge graph: nodes with many high-authority inbound edges score higher.
    High-scoring entities are the most-referenced assets, findings, or threat
    actors — the choke-points that dominate lateral movement and blast radius.

    Uses NetworkX ``pagerank`` on the in-memory MultiDiGraph (alpha=0.85 by
    default). Falls back to a degree-normalised approximation when the graph
    is empty or NetworkX is unavailable.

    Args:
        limit: Number of top nodes (1-100, default 20).
        alpha: Damping factor (0.01-0.99, default 0.85).
        org_id: Tenant org ID.

    Returns:
        ranked: list of node dicts with pagerank_score, sorted descending.
        total_nodes: total node count in graph.
        algorithm: "networkx_pagerank" or "degree_approximation".
        alpha: damping factor used.
    """
    try:
        from core.knowledge_brain import get_brain

        brain = get_brain()
        ranked = brain.pagerank(limit=limit, alpha=alpha)
        algorithm = (
            "networkx_pagerank"
            if brain._graph is not None and brain._graph.number_of_nodes() > 0
            else "degree_approximation"
        )
        return {
            "ranked": ranked,
            "total_nodes": brain.node_count(),
            "algorithm": algorithm,
            "alpha": alpha,
            "limit": limit,
        }
    except Exception as exc:  # noqa: BLE001 — router error boundary
        logger.error("graph/pagerank failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ============================================================================
# GET /api/v1/graph/visualize/{entity_id}
# ============================================================================


@router.get("/visualize/{entity_id}")
async def get_visualization(
    entity_id: str,
    depth: int = Query(default=2, ge=1, le=3, description="Traversal depth"),
    org_id: str = Query(default="default", description="Tenant org ID"),
) -> Dict[str, Any]:
    """Return graph data for frontend visualization (nodes + edges).

    Produces a structure compatible with D3, Cytoscape, and React Flow.

    Args:
        entity_id: Central entity for the visualization
        depth: Traversal depth (1-3)
        org_id: Tenant org ID

    Returns:
        nodes and edges arrays for graph rendering
    """
    try:
        graphrag = _get_graphrag(org_id=org_id)
        return graphrag.get_visualization_data(entity_id=entity_id, depth=depth)
    except Exception as exc:  # noqa: BLE001 — router error boundary
        logger.error("graph/visualize failed for %s: %s", entity_id, exc)
        raise HTTPException(status_code=500, detail=str(exc))
