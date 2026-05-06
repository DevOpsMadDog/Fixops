"""
Composite Risk Scoring API — ML-powered multi-signal risk scores.

Endpoints:
  POST /api/v1/risk/score/finding  — score a single finding
  POST /api/v1/risk/score/asset    — score an asset
  POST /api/v1/risk/score/batch    — batch score (limit 100)
  GET  /api/v1/risk/top            — top N risks (default 10)
  GET  /api/v1/risk/score/{asset_id} — latest score for an asset
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.dependencies import get_org_id
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional core import — router works even if scorer is unavailable
# ---------------------------------------------------------------------------

_HAS_SCORER = False
_CompositeRiskScorer: Any = None
_CompositeRiskScore: Any = None
_get_scorer: Any = None

try:
    from core.composite_risk_scorer import (
        CompositeRiskScore,
        CompositeRiskScorer,
        get_composite_risk_scorer,
    )
    _HAS_SCORER = True
    _CompositeRiskScorer = CompositeRiskScorer
    _CompositeRiskScore = CompositeRiskScore
    _get_scorer = get_composite_risk_scorer
except ImportError as _e:
    logger.warning("CompositeRiskScorer not available: %s", _e)

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/api/v1/risk", tags=["composite-risk"])


def _scorer() -> Any:
    if not _HAS_SCORER or _get_scorer is None:
        raise HTTPException(
            status_code=503,
            detail="CompositeRiskScorer is not available",
        )
    return _get_scorer()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class ScoreFindingRequest(BaseModel):
    finding_id: str = Field(..., description="Finding identifier to score")
    cve_id: Optional[str] = Field(None, description="CVE ID associated with finding")
    asset_id: Optional[str] = Field(None, description="Asset affected by finding")


class ScoreAssetRequest(BaseModel):
    asset_id: str = Field(..., description="Asset identifier to score")


class BatchScoreRequest(BaseModel):
    limit: int = Field(100, ge=1, le=100, description="Max findings to score (1-100)")


class RiskFactorOut(BaseModel):
    name: str
    value: float
    weight: float
    explanation: str


class CompositeRiskScoreOut(BaseModel):
    score_id: str
    asset_id: Optional[str]
    finding_id: Optional[str]
    org_id: str
    score: float
    grade: str
    factors: List[RiskFactorOut]
    scored_at: str


def _serialise(score: Any) -> Dict[str, Any]:
    """Convert CompositeRiskScore to response dict."""
    return {
        "score_id": score.score_id,
        "asset_id": score.asset_id,
        "finding_id": score.finding_id,
        "org_id": score.org_id,
        "score": score.score,
        "grade": score.grade,
        "factors": [
            {
                "name": f.name,
                "value": f.value,
                "weight": f.weight,
                "explanation": f.explanation,
            }
            for f in score.factors
        ],
        "scored_at": score.scored_at,
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/score/finding", summary="Score a single finding")
def score_finding(
    body: ScoreFindingRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """
    Compute composite risk score for a specific finding.
    Combines CVSS, EPSS, KEV, asset criticality, SLA breach risk, and
    lateral movement signals into a single 0-100 score.
    """
    scorer = _scorer()
    try:
        result = scorer.score_finding(
            finding_id=body.finding_id,
            cve_id=body.cve_id,
            asset_id=body.asset_id,
            org_id=org_id,
        )
        return _serialise(result)
    except Exception as exc:
        logger.error("score_finding error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/score/asset", summary="Score an asset")
def score_asset(
    body: ScoreAssetRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """
    Compute composite risk score for an asset by aggregating all its
    finding scores (worst-case + average blend).
    """
    scorer = _scorer()
    try:
        result = scorer.score_asset(asset_id=body.asset_id, org_id=org_id)
        return _serialise(result)
    except Exception as exc:
        logger.error("score_asset error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/score/batch", summary="Batch score findings for an org")
def batch_score(
    body: BatchScoreRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """
    Score up to `limit` findings for the organisation.
    Results are persisted to SQLite and returned.
    """
    scorer = _scorer()
    try:
        results = scorer.batch_score(org_id=org_id, limit=body.limit)
        return {
            "org_id": org_id,
            "scored": len(results),
            "scores": [_serialise(r) for r in results],
        }
    except Exception as exc:
        logger.error("batch_score error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/top", summary="Top N risks for an org")
def top_risks(
    n: int = Query(10, ge=1, le=100, description="Number of top risks to return"),
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """
    Return the top N highest-scoring risks (sorted descending) for the org.
    """
    scorer = _scorer()
    try:
        results = scorer.top_risks(org_id=org_id, n=n)
        return {
            "org_id": org_id,
            "count": len(results),
            "top_risks": [_serialise(r) for r in results],
        }
    except Exception as exc:
        logger.error("top_risks error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/score/{asset_id}", summary="Latest composite score for an asset")
def get_asset_score(
    asset_id: str,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """
    Retrieve the most recently persisted composite score for an asset.
    Returns 404 if no score has been computed yet for this asset.
    """
    scorer = _scorer()
    try:
        result = scorer.get_latest_asset_score(asset_id=asset_id, org_id=org_id)
    except Exception as exc:
        logger.error("get_asset_score error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    if result is None:
        raise HTTPException(
            status_code=404,
            detail=f"No composite score found for asset '{asset_id}' in org '{org_id}'",
        )
    return _serialise(result)


@router.get("/", summary="Risk index", tags=["composite-risk"])
async def risk_index(org_id: str = Depends(get_org_id)) -> Dict[str, Any]:
    """Return composite risk summary for the org."""
    if not _HAS_SCORER or _get_scorer is None:
        return {"router": "risk", "org_id": org_id, "items": [], "count": 0}
    try:
        results = _get_scorer().top_risks(org_id=org_id, n=5)
        top = [_serialise(r) for r in results]
    except Exception:
        top = []
    return {"router": "risk", "org_id": org_id, "items": top, "count": len(top)}
