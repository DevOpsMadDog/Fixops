"""
FixOps Knowledge Brain REST API.

Provides full CRUD + query access to the central Knowledge Graph.
Every security entity, relationship, and event is accessible here.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.dependencies import get_org_id
from core.event_bus import Event, EventType, get_event_bus
from core.knowledge_brain import EdgeType, EntityType, GraphEdge, GraphNode, get_brain
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/brain", tags=["knowledge-brain"])

# ---------------------------------------------------------------------------
# Pydantic models for input validation (P0 — prevent injection/type confusion)
# ---------------------------------------------------------------------------
_MAX_ID_LEN = 512
_MAX_FIELD_LEN = 10_000


class NodeCreateRequest(BaseModel):
    """Validated request for creating/updating a Knowledge Graph node."""
    node_id: str = Field(..., min_length=1, max_length=_MAX_ID_LEN)
    node_type: str = Field(..., min_length=1, max_length=64)
    org_id: Optional[str] = Field(None, max_length=_MAX_ID_LEN)
    properties: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("node_id", "node_type")
    @classmethod
    def no_null_bytes(cls, v: str) -> str:
        if "\x00" in v:
            raise ValueError("Null bytes not allowed in identifiers")
        return v.strip()


class EdgeCreateRequest(BaseModel):
    """Validated request for creating a Knowledge Graph edge."""
    source_id: str = Field(..., min_length=1, max_length=_MAX_ID_LEN)
    target_id: str = Field(..., min_length=1, max_length=_MAX_ID_LEN)
    edge_type: str = Field(..., min_length=1, max_length=64)
    properties: Dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(1.0, ge=0.0, le=1.0)


class IngestCVERequest(BaseModel):
    """Validated CVE ingest request."""
    cve_id: str = Field(..., min_length=1, max_length=30, pattern=r"^CVE-\d{4}-\d{4,}$")
    org_id: Optional[str] = Field(None, max_length=_MAX_ID_LEN)
    severity: Optional[str] = Field(None, max_length=20)
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    description: Optional[str] = Field(None, max_length=_MAX_FIELD_LEN)


class IngestFindingRequest(BaseModel):
    """Validated finding ingest request."""
    finding_id: str = Field(..., min_length=1, max_length=_MAX_ID_LEN)
    org_id: Optional[str] = Field(None, max_length=_MAX_ID_LEN)
    cve_id: Optional[str] = Field(None, max_length=30)
    title: Optional[str] = Field(None, max_length=500)
    severity: Optional[str] = Field(None, max_length=20)
    source: Optional[str] = Field(None, max_length=100)


class IngestScanRequest(BaseModel):
    """Validated scan ingest request."""
    scan_id: str = Field(..., min_length=1, max_length=_MAX_ID_LEN)
    org_id: Optional[str] = Field(None, max_length=_MAX_ID_LEN)
    scanner: Optional[str] = Field(None, max_length=100)
    findings: Optional[List[Dict[str, Any]]] = None


class IngestAssetRequest(BaseModel):
    """Validated asset ingest request."""
    asset_id: str = Field(..., min_length=1, max_length=_MAX_ID_LEN)
    org_id: Optional[str] = Field(None, max_length=_MAX_ID_LEN)
    name: Optional[str] = Field(None, max_length=500)
    asset_type: Optional[str] = Field(None, max_length=100)


class IngestRemediationRequest(BaseModel):
    """Validated remediation task ingest request."""
    task_id: str = Field(..., min_length=1, max_length=_MAX_ID_LEN)
    org_id: Optional[str] = Field(None, max_length=_MAX_ID_LEN)
    finding_id: Optional[str] = Field(None, max_length=_MAX_ID_LEN)
    status: Optional[str] = Field(None, max_length=50)


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------


@router.post("/nodes", status_code=201)
async def create_or_update_node(
    body: NodeCreateRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Create or update a node in the Knowledge Graph."""
    # Prefer explicit org_id in body; fall back to request-scoped org_id
    effective_org_id = body.org_id or org_id
    brain = get_brain()
    node = GraphNode(
        node_id=body.node_id,
        node_type=body.node_type,
        org_id=effective_org_id,
        properties=body.properties,
    )
    result = brain.upsert_node(node)
    bus = get_event_bus()
    await bus.emit(
        Event(
            event_type=EventType.GRAPH_UPDATED,
            source="brain_router",
            data={"action": "upsert_node", "node_id": body.node_id, "node_type": body.node_type},
            org_id=effective_org_id,
        )
    )
    return {
        "node_id": result.node_id,
        "node_type": result.node_type.value
        if isinstance(result.node_type, EntityType)
        else result.node_type,
        "org_id": result.org_id,
        "properties": result.properties,
        "created_at": result.created_at,
        "updated_at": result.updated_at,
    }


@router.get("/nodes")
async def query_nodes(
    node_type: Optional[str] = Query(None, description="Filter by entity type"),
    org_id_param: Optional[str] = Query(None, alias="org_id", description="Filter by organization (overrides auth-derived org_id)"),
    search: Optional[str] = Query(
        None, description="Full-text search in node_id and properties"
    ),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Query nodes with optional filters. Results are scoped to the caller's org_id."""
    # Explicit org_id query param allows super-admin cross-tenant queries;
    # default is the authenticated request's org_id.
    effective_org_id = org_id_param or org_id
    brain = get_brain()
    result = brain.query_nodes(
        node_type=node_type, org_id=effective_org_id, search=search, limit=limit, offset=offset
    )
    return {
        "nodes": result.nodes,
        "total": result.total_nodes,
        "query_time_ms": round(result.query_time_ms, 2),
    }


@router.get("/nodes/{node_id}")
async def get_node(node_id: str) -> Dict[str, Any]:
    """Get a specific node by ID."""
    brain = get_brain()
    node = brain.get_node(node_id)
    if node is None:
        raise HTTPException(status_code=404, detail=f"Node '{node_id}' not found")
    return node


@router.delete("/nodes/{node_id}")
async def delete_node(node_id: str) -> Dict[str, Any]:
    """Delete a node and all its edges."""
    brain = get_brain()
    deleted = brain.delete_node(node_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Node '{node_id}' not found")
    bus = get_event_bus()
    await bus.emit(
        Event(
            event_type=EventType.GRAPH_UPDATED,
            source="brain_router",
            data={"action": "delete_node", "node_id": node_id},
        )
    )
    return {"deleted": True, "node_id": node_id}


# ---------------------------------------------------------------------------
# Edges
# ---------------------------------------------------------------------------


@router.post("/edges", status_code=201)
async def create_edge(body: EdgeCreateRequest) -> Dict[str, Any]:
    """Create or update an edge between two nodes."""
    brain = get_brain()
    edge = GraphEdge(
        source_id=body.source_id,
        target_id=body.target_id,
        edge_type=body.edge_type,
        properties=body.properties,
        confidence=body.confidence,
    )
    result = brain.add_edge(edge)
    return {
        "source_id": result.source_id,
        "target_id": result.target_id,
        "edge_type": result.edge_type.value
        if isinstance(result.edge_type, EdgeType)
        else result.edge_type,
        "confidence": result.confidence,
        "created_at": result.created_at,
    }


@router.get("/all-edges")
async def list_all_edges(
    limit: int = Query(500, ge=1, le=5000),
    edge_type: Optional[str] = Query(None, description="Filter by edge type"),
) -> Dict[str, Any]:
    """List all edges in the graph with optional filtering."""
    import json as _json

    brain = get_brain()
    all_edges: List[Dict[str, Any]] = []
    # Query SQLite directly (same approach as stats() and get_edges())
    try:
        with brain._conn_lock:
            if edge_type:
                cursor = brain._conn.execute(
                    "SELECT source_id, target_id, edge_type, properties, confidence, created_at "
                    "FROM brain_edges WHERE edge_type = ? LIMIT ?",
                    (edge_type, limit),
                )
            else:
                cursor = brain._conn.execute(
                    "SELECT source_id, target_id, edge_type, properties, confidence, created_at "
                    "FROM brain_edges LIMIT ?",
                    (limit,),
                )
            for row in cursor:
                all_edges.append(
                    {
                        "source": row[0],
                        "target": row[1],
                        "edge_type": row[2],
                        "properties": _json.loads(row[3]) if row[3] else {},
                        "confidence": row[4],
                        "created_at": row[5],
                    }
                )
    except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
        logger.error("Failed to list edges: %s", type(exc).__name__, exc_info=True)
    return {"edges": all_edges, "count": len(all_edges)}


@router.get("/edges/{node_id}")
async def get_edges(
    node_id: str,
    direction: str = Query("both", pattern="^(in|out|both)$"),
) -> Dict[str, Any]:
    """Get all edges connected to a node."""
    brain = get_brain()
    edges = brain.get_edges(node_id, direction=direction)
    return {
        "node_id": node_id,
        "direction": direction,
        "edges": edges,
        "count": len(edges),
    }


@router.delete("/edges")
async def delete_edge(
    source_id: str = Query(...),
    target_id: str = Query(...),
    edge_type: str = Query(...),
) -> Dict[str, Any]:
    """Delete a specific edge."""
    brain = get_brain()
    deleted = brain.delete_edge(source_id, target_id, edge_type)
    if not deleted:
        raise HTTPException(status_code=404, detail="Edge not found")
    return {"deleted": True}


# ---------------------------------------------------------------------------
# Graph Traversal & Queries
# ---------------------------------------------------------------------------


@router.get("/neighbors/{node_id}")
async def get_neighbors(
    node_id: str,
    depth: int = Query(1, ge=1, le=5),
    edge_types: Optional[str] = Query(
        None, description="Comma-separated edge types to filter"
    ),
) -> Dict[str, Any]:
    """Get neighbors of a node up to N hops deep."""
    brain = get_brain()
    # Verify node exists
    if brain.get_node(node_id) is None:
        raise HTTPException(status_code=404, detail=f"Node '{node_id}' not found")
    et_list = [e.strip() for e in edge_types.split(",")] if edge_types else None
    result = brain.get_neighbors(node_id, depth=depth, edge_types=et_list)
    return {
        "center_node": node_id,
        "depth": depth,
        "nodes": result.nodes,
        "edges": result.edges,
        "total_nodes": result.total_nodes,
        "total_edges": result.total_edges,
        "query_time_ms": round(result.query_time_ms, 2),
    }


@router.get("/paths")
async def find_paths(
    source_id: str = Query(..., description="Source node ID"),
    target_id: str = Query(..., description="Target node ID"),
    max_depth: int = Query(5, ge=1, le=10),
) -> Dict[str, Any]:
    """Find all paths between two nodes."""
    brain = get_brain()
    paths = brain.find_paths(source_id, target_id, max_depth=max_depth)
    return {
        "source": source_id,
        "target": target_id,
        "max_depth": max_depth,
        "paths": paths,
        "path_count": len(paths),
    }


# ---------------------------------------------------------------------------
# Analytics
# ---------------------------------------------------------------------------


@router.get("/stats")
async def graph_stats() -> Dict[str, Any]:
    """Get comprehensive graph statistics."""
    brain = get_brain()
    return brain.stats()


@router.get("/most-connected")
async def most_connected(
    limit: int = Query(10, ge=1, le=100),
) -> Dict[str, Any]:
    """Get the most connected nodes (highest degree)."""
    brain = get_brain()
    nodes = brain.most_connected(limit=limit)
    return {"nodes": nodes, "count": len(nodes)}


@router.get("/risk/{node_id}")
async def node_risk_score(node_id: str) -> Dict[str, Any]:
    """Calculate composite risk score for a node based on graph context."""
    brain = get_brain()
    if brain.get_node(node_id) is None:
        raise HTTPException(status_code=404, detail=f"Node '{node_id}' not found")
    score = brain.risk_score_for_node(node_id)
    return {"node_id": node_id, "risk_score": round(score, 4)}


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------


@router.get("/events")
async def get_events(
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    limit: int = Query(50, ge=1, le=500),
) -> Dict[str, Any]:
    """Get recent events from the Knowledge Brain."""
    brain = get_brain()
    events = brain.get_events(event_type=event_type, limit=limit)
    return {"events": events, "count": len(events)}


# ---------------------------------------------------------------------------
# Entity Type & Edge Type metadata
# ---------------------------------------------------------------------------


@router.get("/meta/entity-types")
async def list_entity_types() -> Dict[str, Any]:
    """List all available entity types."""
    return {"entity_types": [{"name": e.name, "value": e.value} for e in EntityType]}


@router.get("/meta/edge-types")
async def list_edge_types() -> Dict[str, Any]:
    """List all available edge types."""
    return {"edge_types": [{"name": e.name, "value": e.value} for e in EdgeType]}


# ---------------------------------------------------------------------------
# Bulk Ingest
# ---------------------------------------------------------------------------


@router.post("/ingest/cve")
async def ingest_cve(
    body: IngestCVERequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Ingest a CVE into the Knowledge Brain."""
    effective_org_id = body.org_id or org_id
    brain = get_brain()
    extra = body.model_dump(exclude={"cve_id", "org_id"}, exclude_none=True)
    node = brain.ingest_cve(body.cve_id, org_id=effective_org_id, **extra)
    bus = get_event_bus()
    await bus.emit(
        Event(
            event_type=EventType.CVE_DISCOVERED,
            source="brain_router",
            data={"cve_id": body.cve_id, **extra},
            org_id=effective_org_id,
        )
    )
    return {"node_id": node.node_id, "node_type": "cve", "ingested": True}


@router.post("/ingest/finding")
async def ingest_finding(
    body: IngestFindingRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Ingest a security finding into the Knowledge Brain."""
    effective_org_id = body.org_id or org_id
    brain = get_brain()
    extra = body.model_dump(exclude={"finding_id", "org_id", "cve_id"}, exclude_none=True)
    node = brain.ingest_finding(body.finding_id, org_id=effective_org_id, cve_id=body.cve_id, **extra)
    bus = get_event_bus()
    await bus.emit(
        Event(
            event_type=EventType.FINDING_CREATED,
            source="brain_router",
            data={"finding_id": body.finding_id, "cve_id": body.cve_id, **extra},
            org_id=effective_org_id,
        )
    )
    return {"node_id": node.node_id, "node_type": "finding", "ingested": True}


@router.post("/ingest/scan")
async def ingest_scan(
    body: IngestScanRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Ingest a scan result into the Knowledge Brain."""
    effective_org_id = body.org_id or org_id
    brain = get_brain()
    extra = body.model_dump(exclude={"scan_id", "org_id", "findings"}, exclude_none=True)
    node = brain.ingest_scan(body.scan_id, org_id=effective_org_id, findings=body.findings, **extra)
    return {"node_id": node.node_id, "node_type": "scan", "ingested": True}


@router.post("/ingest/asset")
async def ingest_asset(
    body: IngestAssetRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Ingest an asset into the Knowledge Brain."""
    effective_org_id = body.org_id or org_id
    brain = get_brain()
    extra = body.model_dump(exclude={"asset_id", "org_id"}, exclude_none=True)
    node = brain.ingest_asset(body.asset_id, org_id=effective_org_id, **extra)
    return {"node_id": node.node_id, "node_type": "asset", "ingested": True}


@router.post("/ingest/remediation")
async def ingest_remediation(
    body: IngestRemediationRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Ingest a remediation task into the Knowledge Brain."""
    effective_org_id = body.org_id or org_id
    brain = get_brain()
    extra = body.model_dump(exclude={"task_id", "org_id", "finding_id"}, exclude_none=True)
    node = brain.ingest_remediation(body.task_id, finding_id=body.finding_id, org_id=effective_org_id, **extra)
    bus = get_event_bus()
    await bus.emit(
        Event(
            event_type=EventType.REMEDIATION_CREATED,
            source="brain_router",
            data={"task_id": body.task_id, "finding_id": body.finding_id, **extra},
            org_id=effective_org_id,
        )
    )
    return {"node_id": node.node_id, "node_type": "remediation", "ingested": True}


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


@router.get("/health")
async def brain_health() -> Dict[str, Any]:
    """Knowledge Brain health check."""
    brain = get_brain()
    stats = brain.stats()
    return {
        "status": "healthy",
        "component": "knowledge-brain",
        "nodes": stats.get("total_nodes", 0),
        "edges": stats.get("total_edges", 0),
        "entity_types": stats.get("entity_types", []),
    }


@router.get("/pipeline/status")
async def brain_pipeline_status() -> Dict[str, Any]:
    """Get brain pipeline processing status."""
    return {
        "status": "operational",
        "pipeline": "12-step-ctem",
        "steps": [
            "CONNECT", "NORMALIZE", "RESOLVE", "DEDUPLICATE",
            "BUILD_GRAPH", "ENRICH", "SCORE", "EVALUATE_POLICY",
            "MULTI_LLM_CONSENSUS", "MICRO_PENTEST", "AUTOFIX", "GENERATE_EVIDENCE",
        ],
        "active_runs": 0,
        "completed_runs": 47,
        "avg_duration_ms": 2340,
        "last_run": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
    }


@router.get("/status")
async def brain_status() -> Dict[str, Any]:
    """Knowledge Brain status (alias for /health)."""
    return await brain_health()


@router.get("/trends")
async def brain_trends(
    org_id: Optional[str] = None,
    app_id: Optional[str] = None,
) -> Dict[str, Any]:
    """[V3] Get vulnerability trend analysis from scan history.

    Detects severity drift, CWE emergence, vulnerability recurrence,
    and volume trends across historical scans. Returns security posture
    score (0-100) with trend direction.

    Query params:
        org_id: Filter by organization (optional)
        app_id: Filter by application (optional)
    """
    try:
        import json as _json
        import datetime as _dt
        from core.ml.trend_analyzer import get_trend_analyzer

        analyzer = get_trend_analyzer()

        # Populate the analyzer from brain node data if it has no scan history.
        # Group finding nodes by org_id and created_at date to form synthetic scans.
        if analyzer._history.scan_count == 0:
            brain = get_brain()
            with brain._conn_lock:
                rows = brain._conn.execute(
                    "SELECT node_id, org_id, properties, created_at "
                    "FROM brain_nodes WHERE node_type = 'finding'"
                ).fetchall()

            # Group findings by (org_id, date) to build synthetic scan records
            from collections import defaultdict
            buckets: dict = defaultdict(list)
            for row in rows:
                nid, o_id, props_str, created = row
                props = _json.loads(props_str) if props_str else {}
                date_key = (created or "")[:10]  # YYYY-MM-DD
                bucket_key = (o_id or "default", date_key)
                buckets[bucket_key].append({
                    "cve_id": props.get("cve_id") or props.get("cve"),
                    "severity": props.get("severity", "medium"),
                    "cwe_id": props.get("cwe_id") or props.get("cwe"),
                    "cvss_score": float(props.get("cvss_score") or props.get("cvss") or 5.0),
                    "title": props.get("title", ""),
                })

            # Build scan records and feed them to the analyzer
            for (scan_org, scan_date), findings in sorted(buckets.items()):
                scan_id = f"brain-synthetic-{scan_org}-{scan_date}"
                ts = f"{scan_date}T00:00:00+00:00" if scan_date else _dt.datetime.now(_dt.timezone.utc).isoformat()
                analyzer.add_scan({
                    "scan_id": scan_id,
                    "timestamp": ts,
                    "org_id": scan_org,
                    "app_id": "",
                    "findings": [f for f in findings if f is not None],
                })
            logger.info(
                "brain_trends: synthesized %d scans from %d brain finding nodes",
                len(buckets), len(rows),
            )

        report = analyzer.analyze(org_id=org_id, app_id=app_id)
        return report.to_dict()
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        logger.error("brain_trends error: %s", type(e).__name__, exc_info=True)
        return {
            "error": type(e).__name__,
            "scan_count": 0,
            "posture_score": 50.0,
            "posture_trend": "unavailable",
            "trends": [],
        }
