"""Security Posture Score API Router — ALDECI.

Provides endpoints for computing, saving, and querying security posture scores,
component management, and industry benchmarks.
Auth is applied centrally by app.py (Depends(_verify_api_key)).
"""
from __future__ import annotations

from typing import Any, Dict, List

from core.posture_score_engine import PostureScoreEngine
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/posture-score", tags=["posture-score"])

_engine = None  # lazy-initialised on first request


def _get_engine():
    global _engine
    if _engine is None:
        _engine = PostureScoreEngine()
    return _engine

# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class ComputeRequest(BaseModel):
    org_id: str = Field("default", min_length=1)
    save: bool = Field(True, description="Persist score after computing")


class ComponentUpdateRequest(BaseModel):
    org_id: str = Field("default", min_length=1)
    score: int = Field(..., ge=0, le=100)
    source: str = Field("manual", min_length=1)


class BenchmarkRequest(BaseModel):
    org_id: str = Field("default", min_length=1)
    industry: str = Field("", description="Industry sector")
    company_size: str = Field("", description="e.g. small / medium / large / enterprise")
    avg_score: float = Field(0.0, ge=0.0, le=100.0)
    percentile_rank: int = Field(50, ge=0, le=100)
    source: str = Field("", description="Benchmark source (e.g. CIS, Gartner)")
    as_of_date: str = Field("", description="ISO-8601 date")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/compute", summary="Compute security posture score")
def compute_posture_score(req: ComputeRequest) -> Dict[str, Any]:
    """Calculate weighted posture score from current component values."""
    try:
        score_data = _get_engine().compute_posture_score(req.org_id)
        if req.save:
            saved = _get_engine().save_score(req.org_id, score_data)
            return saved
        return score_data
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/current", summary="Get current posture score")
def get_current_score(org_id: str = Query("default")) -> Dict[str, Any]:
    """Return the most recently saved posture score for an org."""
    result = _get_engine().get_current_score(org_id)
    if not result:
        raise HTTPException(status_code=404, detail="No score found for org")
    return result


@router.get("/history", summary="Get score history")
def get_score_history(
    org_id: str = Query("default"),
    days: int = Query(30, ge=1, le=365),
) -> List[Dict[str, Any]]:
    """Return posture score snapshots for the last N days."""
    return _get_engine().get_score_history(org_id, days=days)


@router.post("/components/{name}", summary="Update a component score")
def update_component(
    name: str,
    req: ComponentUpdateRequest,
) -> Dict[str, Any]:
    """Upsert a single security domain component score (0-100)."""
    ok = _get_engine().update_component(req.org_id, name, req.score, req.source)
    if not ok:
        raise HTTPException(status_code=400, detail=f"Unknown component: {name}")
    return {"component": name, "score": req.score, "source": req.source, "updated": True}


@router.get("/components", summary="List component scores")
def list_components(org_id: str = Query("default")) -> List[Dict[str, Any]]:
    """List all component scores and weights for an org."""
    return _get_engine().list_components(org_id)


@router.get("/benchmarks", summary="List benchmarks")
def list_benchmarks(org_id: str = Query("default")) -> List[Dict[str, Any]]:
    """List industry benchmarks for an org."""
    return _get_engine().list_benchmarks(org_id)


@router.post("/benchmarks", summary="Add a benchmark")
def add_benchmark(req: BenchmarkRequest) -> Dict[str, Any]:
    """Add an industry benchmark record for comparison."""
    data = req.model_dump(exclude={"org_id"})
    return _get_engine().add_benchmark(req.org_id, data)


@router.get("/stats", summary="Get posture stats")
def get_posture_stats(org_id: str = Query("default")) -> Dict[str, Any]:
    """Return summary statistics: current score, grade, 30d trend, days at risk."""
    return _get_engine().get_posture_stats(org_id)
