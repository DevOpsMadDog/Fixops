"""
Security Scorecard API router for ALDECI.

Self-hosted SecurityScorecard-style scoring with 8 risk categories.

Routes:
- POST   /api/v1/scorecard/{org_id}/generate    — generate new scorecard
- GET    /api/v1/scorecard/{org_id}             — latest scorecard
- GET    /api/v1/scorecard/{org_id}/history     — score over time
- GET    /api/v1/scorecard/{org_id}/breakdown   — per-category breakdown
- GET    /api/v1/scorecard/{org_id}/improvement — prioritized improvement plan
- POST   /api/v1/scorecard/compare              — multi-org comparison
- GET    /api/v1/scorecard/public/{org_id}      — shareable external score (no auth)
- GET    /api/v1/scorecard/categories           — list available categories + weights

Protected by api_key_auth (except /public/{org_id}).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

_SIMULATION_WARNING = {
    "is_simulated": True,
    "engine": "security_scorecard",
    "real_integration_required": "/api/v1/connectors/{sast,dast,secrets,container,cspm}/configure",
    "do_not_use_in_demo": True,
}

# ---------------------------------------------------------------------------
# Router — authenticated endpoints
# ---------------------------------------------------------------------------

router = APIRouter(
    prefix="/api/v1/scorecard",
    tags=["security-scorecard"],
    dependencies=[Depends(api_key_auth)],
)

# Public router — no auth dependency
public_router = APIRouter(
    prefix="/api/v1/scorecard",
    tags=["security-scorecard-public"],
)

# ---------------------------------------------------------------------------
# Lazy singleton — avoids import-time SQLite init during tests
# ---------------------------------------------------------------------------

_scorecard = None


def _get_scorecard():
    global _scorecard
    if _scorecard is None:
        from core.security_scorecard import SecurityScorecard
        _scorecard = SecurityScorecard()
    return _scorecard


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class GenerateScorecardRequest(BaseModel):
    validity_days: int = Field(
        default=30, ge=1, le=365, description="Days until scorecard expires"
    )


class CompareOrgsRequest(BaseModel):
    org_ids: List[str] = Field(..., min_length=2, description="List of org IDs to compare")


# ---------------------------------------------------------------------------
# Authenticated routes
# ---------------------------------------------------------------------------


@router.get("/categories", summary="List scoring categories")
async def list_categories() -> Dict[str, Any]:
    """Return all available scoring categories with their weights."""
    from core.security_scorecard import CATEGORY_WEIGHTS, ScoreCategory

    categories = [
        {
            "category": cat.value,
            "weight": CATEGORY_WEIGHTS[cat],
            "description": _CATEGORY_DESCRIPTIONS[cat.value],
        }
        for cat in ScoreCategory
    ]
    return {"categories": categories, "total": len(categories)}


@router.post("/{org_id}/generate", summary="Generate scorecard", status_code=201)
async def generate_scorecard(
    org_id: str, req: GenerateScorecardRequest = GenerateScorecardRequest()
) -> Dict[str, Any]:
    """Compute and store a new security scorecard for the organisation."""
    sc = _get_scorecard().generate_scorecard(org_id, validity_days=req.validity_days)
    return {"data": sc.model_dump(), "_simulation_warning": _SIMULATION_WARNING}


@router.get("/{org_id}", summary="Latest scorecard")
async def get_scorecard(org_id: str) -> Dict[str, Any]:
    """Return the most recently generated scorecard for an organisation."""
    sc = _get_scorecard().get_scorecard(org_id)
    if sc is None:
        raise HTTPException(
            status_code=404,
            detail=f"No scorecard found for org '{org_id}'. Call POST /{org_id}/generate first.",
        )
    return {"data": sc.model_dump(), "_simulation_warning": _SIMULATION_WARNING}


@router.get("/{org_id}/history", summary="Score history")
async def get_score_history(
    org_id: str,
    days: int = Query(default=90, ge=1, le=365, description="Number of days to look back"),
) -> Dict[str, Any]:
    """Return score history for the organisation over the past N days."""
    history = _get_scorecard().get_score_history(org_id, days=days)
    return {
        "org_id": org_id,
        "days": days,
        "history": history,
        "total": len(history),
    }


@router.get("/{org_id}/breakdown", summary="Category breakdown")
async def get_category_breakdown(org_id: str) -> Dict[str, Any]:
    """Return per-category scores, grades, weights, and trends."""
    result = _get_scorecard().get_category_breakdown(org_id)
    if not result.get("generated_at"):
        raise HTTPException(
            status_code=404,
            detail=f"No scorecard found for org '{org_id}'. Call POST /{org_id}/generate first.",
        )
    return result


@router.get("/{org_id}/improvement", summary="Improvement plan")
async def get_improvement_plan(org_id: str) -> Dict[str, Any]:
    """Return a prioritized list of actions to improve the organisation's score."""
    result = _get_scorecard().get_improvement_plan(org_id)
    if not result.get("generated_at"):
        raise HTTPException(
            status_code=404,
            detail=f"No scorecard found for org '{org_id}'. Call POST /{org_id}/generate first.",
        )
    return result


@router.post("/compare", summary="Compare organisations")
async def compare_orgs(req: CompareOrgsRequest) -> Dict[str, Any]:
    """Compare multiple organisations by their latest scorecard."""
    return _get_scorecard().compare_orgs(req.org_ids)


# ---------------------------------------------------------------------------
# Public (unauthenticated) route
# ---------------------------------------------------------------------------


@public_router.get("/public/{org_id}", summary="Public scorecard", tags=["security-scorecard-public"])
async def get_public_score(org_id: str) -> Dict[str, Any]:
    """Return a shareable, limited scorecard suitable for external consumption.

    Exposes overall score, grade, and per-category letter grades only.
    Raw numeric category scores are withheld for security.
    No authentication required — designed for partner/customer sharing.
    """
    ps = _get_scorecard().get_public_score(org_id)
    if ps is None:
        raise HTTPException(
            status_code=404,
            detail=f"No public scorecard available for org '{org_id}'.",
        )
    return ps.model_dump()


# ---------------------------------------------------------------------------
# Category descriptions (used by /categories endpoint)
# ---------------------------------------------------------------------------

_CATEGORY_DESCRIPTIONS: Dict[str, str] = {
    "network": "Exposed services, firewall hygiene, TLS configuration, and network segmentation",
    "application": "Vulnerability density, SAST findings, dependency risk, and API security",
    "patching": "Time-to-patch for CVEs, OS currency, and end-of-life software ratio",
    "dns": "DNSSEC, SPF, DMARC, and DKIM configuration quality",
    "endpoint": "EDR coverage, disk encryption, patch compliance, and MFA enforcement",
    "ip_reputation": "Blocklist appearances, botnet activity, spam reputation",
    "social_engineering": "Phishing susceptibility, security awareness training, credential exposure",
    "information_leak": "Data exposure incidents, code repository secret leaks, dark web mentions",
}
