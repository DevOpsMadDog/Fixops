"""Security Posture Scoring API Router.

Endpoints for computing, retrieving, and trending the 0-100 posture score.

Auth is applied centrally by app.py (Depends(_verify_api_key)).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from core.posture_scoring import PostureScore, PostureScorer, get_posture_scorer

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/posture", tags=["posture"])


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class CalculatePostureRequest(BaseModel):
    org_id: str = Field("default", description="Organisation identifier")
    period: str = Field("current", description="Label for this scoring period")


class CompareOrgsRequest(BaseModel):
    org_ids: List[str] = Field(..., description="List of org IDs to compare")


# ---------------------------------------------------------------------------
# Dependency
# ---------------------------------------------------------------------------


def _get_scorer() -> PostureScorer:
    return get_posture_scorer()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/calculate", response_model=PostureScore, summary="Calculate posture score")
def calculate_posture(req: CalculatePostureRequest) -> PostureScore:
    """Compute a fresh posture score for the given org and persist it."""
    scorer = _get_scorer()
    try:
        return scorer.calculate_score(req.org_id, period=req.period)
    except Exception as exc:
        logger.exception("Failed to calculate posture score: %s", exc)
        raise HTTPException(status_code=500, detail=f"Calculation failed: {exc}") from exc


@router.get("/current", response_model=PostureScore, summary="Get latest posture score")
def get_current_posture(
    org_id: str = Query("default", description="Organisation identifier"),
) -> PostureScore:
    """Return the most recent posture score for an org."""
    scorer = _get_scorer()
    try:
        return scorer.get_latest_score(org_id)
    except Exception as exc:
        logger.exception("Failed to retrieve posture score: %s", exc)
        raise HTTPException(status_code=500, detail=f"Retrieval failed: {exc}") from exc


@router.get("/history", response_model=List[PostureScore], summary="Posture score history")
def get_posture_history(
    org_id: str = Query("default", description="Organisation identifier"),
    days: int = Query(30, ge=1, le=365, description="Look-back window in days"),
) -> List[PostureScore]:
    """Return all persisted posture scores within the last N days."""
    scorer = _get_scorer()
    try:
        return scorer.get_score_history(org_id, days=days)
    except Exception as exc:
        logger.exception("Failed to retrieve posture history: %s", exc)
        raise HTTPException(status_code=500, detail=f"History retrieval failed: {exc}") from exc


@router.get("/trend", response_model=List[Dict[str, Any]], summary="Posture score trend")
def get_posture_trend(
    org_id: str = Query("default", description="Organisation identifier"),
    days: int = Query(30, ge=1, le=365, description="Look-back window in days"),
) -> List[Dict[str, Any]]:
    """Return date + score pairs for chart rendering."""
    scorer = _get_scorer()
    try:
        return scorer.get_score_trend(org_id, days=days)
    except Exception as exc:
        logger.exception("Failed to retrieve posture trend: %s", exc)
        raise HTTPException(status_code=500, detail=f"Trend retrieval failed: {exc}") from exc


@router.get("/components", response_model=PostureScore, summary="Component score breakdown")
def get_posture_components(
    org_id: str = Query("default", description="Organisation identifier"),
) -> PostureScore:
    """Return the latest score with full component breakdown."""
    scorer = _get_scorer()
    try:
        return scorer.get_latest_score(org_id)
    except Exception as exc:
        logger.exception("Failed to retrieve component breakdown: %s", exc)
        raise HTTPException(status_code=500, detail=f"Component retrieval failed: {exc}") from exc


@router.post("/compare", response_model=List[PostureScore], summary="Compare multiple orgs")
def compare_orgs(req: CompareOrgsRequest) -> List[PostureScore]:
    """Return latest posture scores for multiple orgs, sorted by score descending."""
    if not req.org_ids:
        raise HTTPException(status_code=400, detail="org_ids must not be empty")
    scorer = _get_scorer()
    try:
        return scorer.compare_orgs(req.org_ids)
    except Exception as exc:
        logger.exception("Failed to compare orgs: %s", exc)
        raise HTTPException(status_code=500, detail=f"Comparison failed: {exc}") from exc
