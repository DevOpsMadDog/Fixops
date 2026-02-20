"""
FixOps Knowledge Brain REST API.

Provides full CRUD + query access to the central Knowledge Graph.
Every security entity, relationship, and event is accessible here.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.event_bus import Event, EventType, get_event_bus
from core.knowledge_brain import EdgeType, EntityType, GraphEdge, GraphNode, get_brain
from fastapi import APIRouter, HTTPException, Query

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/brain", tags=["knowledge-brain"])


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------


@router.post("/nodes", status_code=201)
async def create_or_update_node(body: Dict[str, Any]) -> Dict[str, Any]:
    """Create or update a node in the Knowledge Graph."""
    node_id = body.get("node_id")
    node_type = body.get("node_type")
    if not node_id or not node_type:
        raise HTTPException(
            status_code=422, detail="node_id and node_type are required"
        )
    brain = get_brain()
    node = GraphNode(
        node_id=node_id,
        node_type=node_type,
        org_id=body.get("org_id"),
        properties=body.get("properties", {}),
    )
    result = brain.upsert_node(node)
    bus = get_event_bus()
    await bus.emit(
        Event(
            event_type=EventType.GRAPH_UPDATED,
            source="brain_router",
            data={"action": "upsert_node", "node_id": node_id, "node_type": node_type},
            org_id=body.get("org_id"),
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
    org_id: Optional[str] = Query(None, description="Filter by organization"),
    search: Optional[str] = Query(
        None, description="Full-text search in node_id and properties"
    ),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> Dict[str, Any]:
    """Query nodes with optional filters."""
    brain = get_brain()
    result = brain.query_nodes(
        node_type=node_type, org_id=org_id, search=search, limit=limit, offset=offset
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
async def create_edge(body: Dict[str, Any]) -> Dict[str, Any]:
    """Create or update an edge between two nodes."""
    source_id = body.get("source_id")
    target_id = body.get("target_id")
    edge_type = body.get("edge_type")
    if not source_id or not target_id or not edge_type:
        raise HTTPException(
            status_code=422, detail="source_id, target_id, and edge_type are required"
        )
    brain = get_brain()
    edge = GraphEdge(
        source_id=source_id,
        target_id=target_id,
        edge_type=edge_type,
        properties=body.get("properties", {}),
        confidence=body.get("confidence", 1.0),
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
    except Exception as exc:
        logger.error("Failed to list edges: %s", exc)
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
async def ingest_cve(body: Dict[str, Any]) -> Dict[str, Any]:
    """Ingest a CVE into the Knowledge Brain."""
    cve_id = body.get("cve_id")
    if not cve_id:
        raise HTTPException(status_code=422, detail="cve_id is required")
    brain = get_brain()
    org_id = body.pop("org_id", None)
    cve_id_val = body.pop("cve_id")
    node = brain.ingest_cve(cve_id_val, org_id=org_id, **body)
    bus = get_event_bus()
    await bus.emit(
        Event(
            event_type=EventType.CVE_DISCOVERED,
            source="brain_router",
            data={"cve_id": cve_id_val, **body},
            org_id=org_id,
        )
    )
    return {"node_id": node.node_id, "node_type": "cve", "ingested": True}


@router.post("/ingest/finding")
async def ingest_finding(body: Dict[str, Any]) -> Dict[str, Any]:
    """Ingest a security finding into the Knowledge Brain."""
    finding_id = body.get("finding_id")
    if not finding_id:
        raise HTTPException(status_code=422, detail="finding_id is required")
    brain = get_brain()
    org_id = body.pop("org_id", None)
    fid = body.pop("finding_id")
    cve_id = body.pop("cve_id", None)
    node = brain.ingest_finding(fid, org_id=org_id, cve_id=cve_id, **body)
    bus = get_event_bus()
    await bus.emit(
        Event(
            event_type=EventType.FINDING_CREATED,
            source="brain_router",
            data={"finding_id": fid, "cve_id": cve_id, **body},
            org_id=org_id,
        )
    )
    return {"node_id": node.node_id, "node_type": "finding", "ingested": True}


@router.post("/ingest/scan")
async def ingest_scan(body: Dict[str, Any]) -> Dict[str, Any]:
    """Ingest a scan result into the Knowledge Brain."""
    scan_id = body.get("scan_id")
    if not scan_id:
        raise HTTPException(status_code=422, detail="scan_id is required")
    brain = get_brain()
    org_id = body.pop("org_id", None)
    sid = body.pop("scan_id")
    findings = body.pop("findings", None)
    node = brain.ingest_scan(sid, org_id=org_id, findings=findings, **body)
    return {"node_id": node.node_id, "node_type": "scan", "ingested": True}


@router.post("/ingest/asset")
async def ingest_asset(body: Dict[str, Any]) -> Dict[str, Any]:
    """Ingest an asset into the Knowledge Brain."""
    asset_id = body.get("asset_id")
    if not asset_id:
        raise HTTPException(status_code=422, detail="asset_id is required")
    brain = get_brain()
    org_id = body.pop("org_id", None)
    aid = body.pop("asset_id")
    node = brain.ingest_asset(aid, org_id=org_id, **body)
    return {"node_id": node.node_id, "node_type": "asset", "ingested": True}


@router.post("/ingest/remediation")
async def ingest_remediation(body: Dict[str, Any]) -> Dict[str, Any]:
    """Ingest a remediation task into the Knowledge Brain."""
    task_id = body.get("task_id")
    if not task_id:
        raise HTTPException(status_code=422, detail="task_id is required")
    brain = get_brain()
    org_id = body.pop("org_id", None)
    tid = body.pop("task_id")
    finding_id = body.pop("finding_id", None)
    node = brain.ingest_remediation(tid, finding_id=finding_id, org_id=org_id, **body)
    bus = get_event_bus()
    await bus.emit(
        Event(
            event_type=EventType.REMEDIATION_CREATED,
            source="brain_router",
            data={"task_id": tid, "finding_id": finding_id, **body},
            org_id=org_id,
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
