"""Network Topology Router — ALDECI.

REST API for the NetworkTopologyEngine: nodes, edges, segments,
path-finding, statistics, and exposure detection.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Auth dependency — import same pattern used throughout app.py
# ---------------------------------------------------------------------------
try:
    from apps.api.auth_deps import api_key_auth as _verify_api_key
except ImportError:
    # Fallback: no-op dependency when running tests without full app context
    async def _verify_api_key():  # type: ignore[misc]
        pass

# ---------------------------------------------------------------------------
# Engine singleton
# ---------------------------------------------------------------------------
_DB_PATH = str(
    Path(__file__).resolve().parents[3] / ".fixops_data" / "network_topology.db"
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.network_topology_engine import NetworkTopologyEngine
        _engine = NetworkTopologyEngine(_DB_PATH)
    return _engine


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------
router = APIRouter(prefix="/api/v1/network-topology", tags=["network-topology"])

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class NodeCreate(BaseModel):
    org_id: str
    node_type: str = "server"
    hostname: str = ""
    ip: str = ""
    os: str = ""
    location: str = ""
    criticality: str = "medium"
    tags: List[str] = Field(default_factory=list)


class EdgeCreate(BaseModel):
    org_id: str
    src_node_id: str
    dst_node_id: str
    protocol: str
    port: int
    bidirectional: bool = True


class SegmentCreate(BaseModel):
    org_id: str
    name: str = ""
    vlan: str = ""
    subnet: str = ""
    zone: str = "internal"
    node_count: int = 0


# ---------------------------------------------------------------------------
# Node endpoints
# ---------------------------------------------------------------------------

@router.post("/nodes", summary="Add a network node")
async def create_node(
    body: NodeCreate,
    _auth=Depends(_verify_api_key),
) -> Dict[str, Any]:
    try:
        return _get_engine().add_node(body.org_id, body.model_dump())
    except Exception as exc:
        _logger.error("create_node error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/nodes", summary="List network nodes")
async def list_nodes(
     org_id: str = Query(default="default"),
    node_type: Optional[str] = Query(None),
    criticality: Optional[str] = Query(None),
    _auth=Depends(_verify_api_key),
) -> List[Dict[str, Any]]:
    try:
        return _get_engine().list_nodes(org_id, node_type=node_type, criticality=criticality)
    except Exception as exc:
        _logger.error("list_nodes error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/nodes/{node_id}/neighbors", summary="Get neighbors of a node")
async def get_neighbors(
    node_id: str,
     org_id: str = Query(default="default"),
    _auth=Depends(_verify_api_key),
) -> List[Dict[str, Any]]:
    try:
        return _get_engine().get_neighbors(org_id, node_id)
    except Exception as exc:
        _logger.error("get_neighbors error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Edge endpoints
# ---------------------------------------------------------------------------

@router.post("/edges", summary="Add a network edge")
async def create_edge(
    body: EdgeCreate,
    _auth=Depends(_verify_api_key),
) -> Dict[str, Any]:
    try:
        return _get_engine().add_edge(
            body.org_id,
            body.src_node_id,
            body.dst_node_id,
            body.protocol,
            body.port,
            body.bidirectional,
        )
    except Exception as exc:
        _logger.error("create_edge error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/edges", summary="List network edges")
async def list_edges(
     org_id: str = Query(default="default"),
    node_id: Optional[str] = Query(None),
    _auth=Depends(_verify_api_key),
) -> List[Dict[str, Any]]:
    try:
        return _get_engine().list_edges(org_id, node_id=node_id)
    except Exception as exc:
        _logger.error("list_edges error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Segment endpoints
# ---------------------------------------------------------------------------

@router.post("/segments", summary="Add a network segment")
async def create_segment(
    body: SegmentCreate,
    _auth=Depends(_verify_api_key),
) -> Dict[str, Any]:
    try:
        return _get_engine().add_segment(body.org_id, body.model_dump())
    except Exception as exc:
        _logger.error("create_segment error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/segments", summary="List network segments")
async def list_segments(
     org_id: str = Query(default="default"),
    _auth=Depends(_verify_api_key),
) -> List[Dict[str, Any]]:
    try:
        return _get_engine().list_segments(org_id)
    except Exception as exc:
        _logger.error("list_segments error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Path-finding
# ---------------------------------------------------------------------------

@router.get("/path/{src}/{dst}", summary="Find BFS path between two nodes")
async def find_path(
    src: str,
    dst: str,
     org_id: str = Query(default="default"),
    _auth=Depends(_verify_api_key),
) -> Dict[str, Any]:
    try:
        path = _get_engine().find_path(org_id, src, dst)
        return {"src": src, "dst": dst, "path": path, "hops": max(0, len(path) - 1)}
    except Exception as exc:
        _logger.error("find_path error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Analytics
# ---------------------------------------------------------------------------

@router.get("/stats", summary="Topology statistics")
async def topology_stats(
     org_id: str = Query(default="default"),
    _auth=Depends(_verify_api_key),
) -> Dict[str, Any]:
    try:
        return _get_engine().get_topology_stats(org_id)
    except Exception as exc:
        _logger.error("topology_stats error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/", summary="Network topology index")
async def network_topology_index(
    org_id: str = Query(default="default"),
    _auth=Depends(_verify_api_key),
) -> Dict[str, Any]:
    """Return topology summary: node count, edge count, and stats for the org."""
    try:
        engine = _get_engine()
        stats = engine.get_topology_stats(org_id)
        nodes = engine.list_nodes(org_id)
    except Exception as exc:
        _logger.error("network_topology_index error: %s", exc)
        return {"router": "network-topology", "org_id": org_id, "error": str(exc)}
    return {
        "router": "network-topology",
        "org_id": org_id,
        "node_count": stats.get("node_count", len(nodes)),
        "edge_count": stats.get("edge_count", 0),
        "segment_count": stats.get("segment_count", 0),
        "stats": stats,
    }


@router.get("/exposure", summary="Detect external exposure to critical nodes")
async def detect_exposure(
     org_id: str = Query(default="default"),
    _auth=Depends(_verify_api_key),
) -> List[Dict[str, Any]]:
    try:
        return _get_engine().detect_exposure(org_id)
    except Exception as exc:
        _logger.error("detect_exposure error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))
