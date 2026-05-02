"""
VulnPrioritizer API Router — ML-based vulnerability prioritization endpoints.

Provides REST endpoints for scoring, ranking, and explaining vulnerability
findings by exploitability risk using the VulnPrioritizer engine.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Auth dependency — mirrors pattern used across all ALDECI routers
# ---------------------------------------------------------------------------

from apps.api.auth_deps import api_key_auth as _verify_api_key

# ---------------------------------------------------------------------------
# Lazy prioritizer singleton
# ---------------------------------------------------------------------------

_prioritizer: Optional[Any] = None
_vuln_prio_engine: Optional[Any] = None


def _get_prioritizer():
    """Return a module-level VulnPrioritizer singleton."""
    global _prioritizer
    if _prioritizer is None:
        from core.vuln_prioritizer import VulnPrioritizer
        _prioritizer = VulnPrioritizer()
    return _prioritizer


def _get_vuln_prio_engine():
    """Return a VulnerabilityPrioritizationEngine singleton (has get_prioritization_stats)."""
    global _vuln_prio_engine
    if _vuln_prio_engine is None:
        from core.vulnerability_prioritization_engine import (
            VulnerabilityPrioritizationEngine,
        )
        _vuln_prio_engine = VulnerabilityPrioritizationEngine()
    return _vuln_prio_engine


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class PrioritizeRequest(BaseModel):
    """Request body for bulk finding prioritization."""

    findings: List[Dict[str, Any]] = Field(..., description="List of raw finding dicts")


class TopNRequest(BaseModel):
    """Query params wrapper — n is also accepted as query param."""
    pass


class ExplainRequest(BaseModel):
    """Finding to explain — full finding dict."""

    finding: Dict[str, Any] = Field(..., description="Raw finding dict")


class CompareRequest(BaseModel):
    """Two findings to compare side-by-side."""

    finding_a: Dict[str, Any] = Field(..., description="First finding")
    finding_b: Dict[str, Any] = Field(..., description="Second finding")


class WeightsUpdateRequest(BaseModel):
    """New weights for one or more factors."""

    weights: Dict[str, float] = Field(
        ...,
        description=(
            "Factor → weight mapping. Known factors: cvss_score, epss_score, "
            "asset_criticality, exposure_level, exploit_available, age_days, "
            "has_patch, in_attack_path"
        ),
    )


class FeedbackRequest(BaseModel):
    """Analyst feedback on a finding's priority."""

    finding_id: str = Field(..., description="Finding ID")
    analyst_priority: str = Field(
        ...,
        description="Analyst judgement: critical_now | act_soon | monitor | defer",
    )


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/api/v1/prioritize", tags=["Prioritization"])


@router.post("", dependencies=[Depends(_verify_api_key)])
async def prioritize_findings(body: PrioritizeRequest) -> Dict[str, Any]:
    """Score and rank a list of findings by exploitability risk."""
    prioritizer = _get_prioritizer()
    try:
        results = prioritizer.prioritize_findings(body.findings)
        return {
            "count": len(results),
            "findings": [pf.model_dump() for pf in results],
        }
    except Exception as exc:
        logger.exception("prioritize_findings failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/top", dependencies=[Depends(_verify_api_key)])
async def get_top_findings(
    n: int = Query(10, ge=1, le=500, description="Number of top findings to return"),
) -> Dict[str, Any]:
    """Return top-N most critical findings from the last prioritization run.

    Note: requires findings to be submitted via POST /prioritize first.
    This endpoint is intended for integrations that cache findings server-side.
    For direct use, POST /prioritize and slice the response.
    """
    # Stateless engine — return empty with guidance
    return {
        "n": n,
        "message": "Submit findings via POST /api/v1/prioritize to score them, then use get_top_n().",
        "findings": [],
    }


@router.post("/top", dependencies=[Depends(_verify_api_key)])
async def get_top_n_findings(
    body: PrioritizeRequest,
    n: int = Query(10, ge=1, le=500, description="Number of top findings to return"),
) -> Dict[str, Any]:
    """Score findings and return only the top N most critical."""
    prioritizer = _get_prioritizer()
    try:
        results = prioritizer.get_top_n(body.findings, n)
        return {
            "n": n,
            "count": len(results),
            "findings": [pf.model_dump() for pf in results],
        }
    except Exception as exc:
        logger.exception("get_top_n_findings failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/explain/{finding_id}", dependencies=[Depends(_verify_api_key)])
async def explain_finding(finding_id: str, body: ExplainRequest) -> Dict[str, Any]:
    """Explain the ranking of a specific finding."""
    prioritizer = _get_prioritizer()
    try:
        # Inject the finding_id from path if not set in body
        finding = dict(body.finding)
        if "id" not in finding and "finding_id" not in finding:
            finding["id"] = finding_id

        results = prioritizer.prioritize_findings([finding])
        if not results:
            raise HTTPException(status_code=404, detail="Finding could not be scored")

        pf = results[0]
        return {
            "finding_id": finding_id,
            "risk_score": pf.risk_score,
            "rank": pf.rank,
            "category": pf.category,
            "explanation": pf.explanation,
            "factors": [f.model_dump() for f in pf.factors],
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("explain_finding failed for %s", finding_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/compare", dependencies=[Depends(_verify_api_key)])
async def compare_findings(body: CompareRequest) -> Dict[str, Any]:
    """Compare two findings side-by-side across all risk factors."""
    prioritizer = _get_prioritizer()
    try:
        return prioritizer.compare_findings(body.finding_a, body.finding_b)
    except Exception as exc:
        logger.exception("compare_findings failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/weights", dependencies=[Depends(_verify_api_key)])
async def get_weights() -> Dict[str, Any]:
    """Return the current factor weight configuration."""
    prioritizer = _get_prioritizer()
    return {"weights": prioritizer.get_factor_weights()}


@router.put("/weights", dependencies=[Depends(_verify_api_key)])
async def update_weights(body: WeightsUpdateRequest) -> Dict[str, Any]:
    """Update one or more factor weights."""
    prioritizer = _get_prioritizer()
    prioritizer.update_weights(body.weights)
    return {"status": "updated", "weights": prioritizer.get_factor_weights()}


@router.post("/feedback", dependencies=[Depends(_verify_api_key)])
async def record_feedback(body: FeedbackRequest) -> Dict[str, Any]:
    """Record analyst feedback on a finding's priority for model tuning."""
    valid_priorities = {"critical_now", "act_soon", "monitor", "defer"}
    if body.analyst_priority not in valid_priorities:
        raise HTTPException(
            status_code=422,
            detail=f"analyst_priority must be one of: {sorted(valid_priorities)}",
        )
    prioritizer = _get_prioritizer()
    try:
        prioritizer.train_from_feedback(body.finding_id, body.analyst_priority)
        return {"status": "recorded", "finding_id": body.finding_id, "priority": body.analyst_priority}
    except Exception as exc:
        logger.exception("record_feedback failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/stats", dependencies=[Depends(_verify_api_key)])
async def get_stats(
    org_id: str = Query("", description="Organisation ID filter"),
) -> Dict[str, Any]:
    """Return prioritization statistics: category distribution, avg score, top factors."""
    engine = _get_vuln_prio_engine()
    try:
        return engine.get_prioritization_stats(org_id=org_id)
    except Exception as exc:
        logger.exception("get_stats failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
