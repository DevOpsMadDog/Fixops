"""
Risk Scoring & Exposure REST API — ALDECI.

Endpoints:
  POST /api/v1/risk/score              Score a single finding
  POST /api/v1/risk/rank               Rank a list of findings by composite risk
  GET  /api/v1/risk/exposure/org       Organisation-wide exposure score
  GET  /api/v1/risk/exposure/{asset_id} Asset-level exposure score
  GET  /api/v1/risk/exposure/trend     30-day exposure trend (configurable)

Scoring factors:
  CVSS base score   40%
  EPSS probability  25%
  CISA KEV          20%
  Asset criticality 15%

Compliance: NIST SP 800-40, CISA KEV alignment, FIRST EPSS v3, SOC2 CC9.2
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/risk", tags=["Risk Scoring"])

# ---------------------------------------------------------------------------
# Auth (graceful degradation — app.py may wrap with dependencies instead)
# ---------------------------------------------------------------------------

try:
    from apps.api.auth_deps import api_key_auth as _api_key_auth
    from fastapi import Depends

    _AUTH_DEP: list = [Depends(_api_key_auth)]
except ImportError:
    logger.warning(
        "risk_scoring_router: auth_deps not available, "
        "relying on app.py mount-level auth"
    )
    _AUTH_DEP = []

# ---------------------------------------------------------------------------
# Lazy engine accessors
# ---------------------------------------------------------------------------


def _get_prioritizer():
    from core.risk_prioritizer import get_risk_prioritizer

    db_path = os.environ.get("RISK_PRIORITIZER_DB", "risk_prioritizer.db")
    return get_risk_prioritizer(db_path=db_path)


def _get_scorer():
    from core.exposure_scorer import get_exposure_scorer

    db_path = os.environ.get("EXPOSURE_SCORER_DB", "exposure_scorer.db")
    return get_exposure_scorer(db_path=db_path)


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class ScoreFindingRequest(BaseModel):
    """Request body to score a single finding."""

    finding: Dict[str, Any] = Field(
        ...,
        description=(
            "Finding dict. Recognised keys: id/finding_id, cve_id/cve, "
            "severity/risk_level, cvss_score/cvss_base_score, "
            "asset_environment/environment, asset_criticality."
        ),
    )


class RankFindingsRequest(BaseModel):
    """Request body to rank a list of findings."""

    findings: List[Dict[str, Any]] = Field(
        ..., min_length=1, description="List of finding dicts to rank."
    )


# ---------------------------------------------------------------------------
# POST /api/v1/risk/score
# ---------------------------------------------------------------------------


@router.post(
    "/score",
    summary="Score a single finding",
    description=(
        "Produce a composite risk score 0-100 for a finding using "
        "CVSS (40%), EPSS (25%), CISA KEV (20%), asset criticality (15%)."
    ),
    dependencies=_AUTH_DEP,
)
def score_finding(body: ScoreFindingRequest) -> Dict[str, Any]:
    engine = _get_prioritizer()
    try:
        result = engine.score_finding(body.finding)
        return result.model_dump()
    except Exception as exc:
        logger.error("score_finding error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# POST /api/v1/risk/rank
# ---------------------------------------------------------------------------


@router.post(
    "/rank",
    summary="Rank findings by composite risk",
    description=(
        "Score each finding and return them sorted highest-risk first. "
        "Also returns a prioritised remediation queue with urgency tiers."
    ),
    dependencies=_AUTH_DEP,
)
def rank_findings(body: RankFindingsRequest) -> Dict[str, Any]:
    engine = _get_prioritizer()
    try:
        ranked = engine.rank_findings(body.findings)
        queue = engine.get_remediation_priority(body.findings)
        return {
            "total": len(ranked),
            "scores": [s.model_dump() for s in ranked],
            "remediation_queue": queue.model_dump(),
        }
    except Exception as exc:
        logger.error("rank_findings error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# GET /api/v1/risk/exposure/org
# ---------------------------------------------------------------------------


@router.get(
    "/exposure/org",
    summary="Organisation exposure score",
    description="Overall organisation security exposure score 0-100.",
    dependencies=_AUTH_DEP,
)
def org_exposure(
    org_id: str = Query(default="default", description="Tenant org_id"),
) -> Dict[str, Any]:
    scorer = _get_scorer()
    try:
        result = scorer.calculate_org_exposure(org_id=org_id, snapshot=True)
        return result.model_dump()
    except Exception as exc:
        logger.error("org_exposure error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# GET /api/v1/risk/exposure/trend
# ---------------------------------------------------------------------------

# NOTE: This route MUST be defined before /exposure/{asset_id} so FastAPI
# does not treat "trend" as an asset_id path parameter.
@router.get(
    "/exposure/trend",
    summary="Exposure trend (30-day)",
    description="Return daily exposure score snapshots for dashboard charting.",
    dependencies=_AUTH_DEP,
)
def exposure_trend(
    org_id: str = Query(default="default", description="Tenant org_id"),
    days: int = Query(default=30, ge=1, le=365, description="Look-back window in days"),
) -> Dict[str, Any]:
    scorer = _get_scorer()
    try:
        trend = scorer.get_exposure_trend(org_id=org_id, days=days)
        return {
            "org_id": org_id,
            "days": days,
            "total": len(trend),
            "trend": [t.model_dump() for t in trend],
        }
    except Exception as exc:
        logger.error("exposure_trend error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# GET /api/v1/risk/exposure/{asset_id}
# ---------------------------------------------------------------------------


@router.get(
    "/exposure/{asset_id}",
    summary="Asset exposure score",
    description="Risk exposure score 0-100 for a single asset.",
    dependencies=_AUTH_DEP,
)
def asset_exposure(asset_id: str) -> Dict[str, Any]:
    scorer = _get_scorer()
    try:
        result = scorer.get_asset_exposure(asset_id)
        return result.model_dump()
    except Exception as exc:
        logger.error("asset_exposure error asset=%s: %s", asset_id, exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc)) from exc
