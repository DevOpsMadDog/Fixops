"""Choke-Point Analyzer Router (GAP-026).

Ranks attack-graph edges by max-flow min-cut impact — which single edge
removal most reduces blast radius from designated source assets to
crown-jewel sinks. Uses Edmonds-Karp (unit capacity) on the existing
AttackPathEngine graph.

Prefix: /api/v1/choke-point
Auth:   api_key_auth dependency

Routes:
  POST  /api/v1/choke-point/compute
  GET   /api/v1/choke-point/analyses
  GET   /api/v1/choke-point/analyses/{id}
  GET   /api/v1/choke-point/stats
"""
from __future__ import annotations

import logging
from typing import List, Optional

from apps.api.auth_deps import api_key_auth
from core.attack_path_engine import AttackPathEngine
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/choke-point",
    tags=["Choke Point Analysis"],
    dependencies=[Depends(api_key_auth)],
)

_engine: Optional[AttackPathEngine] = None


def _get_engine() -> AttackPathEngine:
    """Lazy singleton — shares state with AttackPathEngine router."""
    global _engine
    if _engine is None:
        _engine = AttackPathEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class ComputeRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    source_ids: List[str] = Field(
        ...,
        min_length=1,
        description="Source (entry) node IDs — virtual super-source is linked to these.",
    )
    sink_ids: List[str] = Field(
        ...,
        min_length=1,
        description="Sink (crown jewel) node IDs — virtual super-sink is linked from these.",
    )
    top_k: int = Field(10, ge=1, le=100, description="Maximum choke edges to return")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/compute", summary="Rank edges by max-flow min-cut blast reduction")
def compute(req: ComputeRequest) -> dict:
    """Compute choke-points from ``source_ids`` to ``sink_ids``.

    Results are cached by (org, sources, sinks, top_k, edge-topology).
    Returns the ranked list and summary stats.
    """
    engine = _get_engine()
    try:
        edges = engine.compute_choke_points(
            org_id=req.org_id,
            source_ids=req.source_ids,
            sink_ids=req.sink_ids,
            top_k=req.top_k,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 — API boundary
        _logger.exception("choke_point compute failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {
        "org_id": req.org_id,
        "source_ids": req.source_ids,
        "sink_ids": req.sink_ids,
        "top_k": req.top_k,
        "choke_points": edges,
        "total": len(edges),
    }


@router.get("/analyses", summary="List cached choke-point analyses for an org")
def list_analyses(
    org_id: str = Query("default", description="Organisation ID"),
) -> dict:
    try:
        return {"org_id": org_id, "analyses": _get_engine().list_analyses(org_id)}
    except Exception as exc:  # noqa: BLE001
        _logger.exception("choke_point list failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/analyses/{analysis_id}",
    summary="Fetch a single cached choke-point analysis",
)
def get_analysis(
    analysis_id: str,
    org_id: str = Query("default", description="Organisation ID"),
) -> dict:
    try:
        result = _get_engine().get_analysis(analysis_id, org_id=org_id)
    except Exception as exc:  # noqa: BLE001
        _logger.exception("choke_point get failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=f"Analysis '{analysis_id}' not found for org '{org_id}'",
        )
    return result


@router.get("/stats", summary="Choke-point analysis summary stats")
def stats(
    org_id: str = Query("default", description="Organisation ID"),
) -> dict:
    try:
        return _get_engine().get_choke_point_stats(org_id=org_id)
    except Exception as exc:  # noqa: BLE001
        _logger.exception("choke_point stats failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
