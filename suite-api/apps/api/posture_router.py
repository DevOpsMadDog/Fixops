"""Security Posture Scoring API Router.

Endpoints for computing, retrieving, and trending the 0-100 posture score.

Auth is applied centrally by app.py (Depends(_verify_api_key)).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from core.posture_scoring import PostureScore, PostureScorer, get_posture_scorer
from core.posture_tracker import (
    PostureDiff,
    PostureSnapshot,
    PostureTracker,
    get_posture_tracker,
)
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

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


def _get_tracker() -> PostureTracker:
    return get_posture_tracker()


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


# ---------------------------------------------------------------------------
# Tracker endpoints (time-series snapshots + diff)
# ---------------------------------------------------------------------------


@router.post("/tracker/calculate", response_model=PostureSnapshot, summary="Calculate + record posture snapshot")
def tracker_calculate(
    org_id: str = Query("default", description="Organisation identifier"),
) -> PostureSnapshot:
    """Calculate current posture from live data and persist a snapshot."""
    tracker = _get_tracker()
    try:
        return tracker.calculate_posture(org_id)
    except Exception as exc:
        logger.exception("Failed to calculate posture snapshot: %s", exc)
        raise HTTPException(status_code=500, detail=f"Calculation failed: {exc}") from exc


@router.get("/tracker/current", response_model=PostureSnapshot, summary="Get current posture snapshot")
def tracker_current(
    org_id: str = Query("default", description="Organisation identifier"),
) -> PostureSnapshot:
    """Return the most recent posture snapshot for an org."""
    tracker = _get_tracker()
    snap = tracker.get_current_posture(org_id)
    if snap is None:
        raise HTTPException(status_code=404, detail=f"No snapshot found for org_id={org_id!r}")
    return snap


@router.get("/tracker/trend", response_model=List[PostureSnapshot], summary="30-day posture trend")
def tracker_trend(
    org_id: str = Query("default", description="Organisation identifier"),
    days: int = Query(30, ge=1, le=365, description="Look-back window in days"),
) -> List[PostureSnapshot]:
    """Return all posture snapshots within the last N days, oldest first."""
    tracker = _get_tracker()
    try:
        return tracker.get_trend(days=days, org_id=org_id)
    except Exception as exc:
        logger.exception("Failed to retrieve posture trend: %s", exc)
        raise HTTPException(status_code=500, detail=f"Trend retrieval failed: {exc}") from exc


@router.get("/tracker/compare", response_model=PostureDiff, summary="Compare two posture snapshots")
def tracker_compare(
    snapshot_id_1: str = Query(..., description="First snapshot ID"),
    snapshot_id_2: str = Query(..., description="Second snapshot ID"),
) -> PostureDiff:
    """Diff two posture snapshots and return score/finding deltas with a trend label."""
    tracker = _get_tracker()
    try:
        return tracker.compare_posture(snapshot_id_1, snapshot_id_2)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to compare snapshots: %s", exc)
        raise HTTPException(status_code=500, detail=f"Comparison failed: {exc}") from exc
