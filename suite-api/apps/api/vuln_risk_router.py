"""
Vulnerability Risk Scoring Router — ALDECI.

Endpoints:
  POST   /api/v1/vuln-risk/score              Score a single vulnerability
  POST   /api/v1/vuln-risk/batch-score        Score a list of vulnerabilities
  GET    /api/v1/vuln-risk/stats              Priority distribution stats
  GET    /api/v1/vuln-risk/priority-queue     Saved scores sorted P1→P4
  GET    /api/v1/vuln-risk/trend/{cve_id}     Historical score trend for a CVE

Auth: X-API-Key header or Authorization: Bearer <jwt>
Compliance: NIST SP 800-30, ISO27001 A.12.6, SOC2 CC7.1
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

try:
    from apps.api.auth_deps import api_key_auth as _api_key_auth
    _AUTH_DEP: list = [Depends(_api_key_auth)]
except ImportError:
    logging.getLogger(__name__).warning(
        "vuln_risk_router: auth_deps not available, relying on app.py mount-level auth"
    )
    _AUTH_DEP = []

from core.vuln_risk_scoring import get_scorer

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/vuln-risk",
    tags=["Vulnerability Risk Scoring"],
    dependencies=_AUTH_DEP,
)

# ============================================================================
# REQUEST / RESPONSE MODELS
# ============================================================================


class VulnContext(BaseModel):
    asset_criticality: str = Field(
        default="medium",
        description="Asset criticality: critical | high | medium | low",
    )
    internet_exposed: bool = Field(default=False)
    has_known_exploit: bool = Field(default=False)
    epss_score: float = Field(default=0.0, ge=0.0, le=1.0)
    cvss_base: float = Field(default=0.0, ge=0.0, le=10.0)
    kev: bool = Field(default=False, description="CISA Known Exploited Vulnerability")


class ScoreRequest(BaseModel):
    cve_id: str = Field(..., description="CVE identifier, e.g. CVE-2024-12345")
    org_id: str = Field(..., description="Organization identifier")
    context: VulnContext = Field(default_factory=VulnContext)
    asset_id: Optional[str] = Field(default=None, description="Optional asset to attach score to")
    save: bool = Field(default=False, description="Persist score to DB for trending")


class BatchVulnItem(BaseModel):
    cve_id: str
    asset_criticality: str = "medium"
    internet_exposed: bool = False
    has_known_exploit: bool = False
    epss_score: float = Field(default=0.0, ge=0.0, le=1.0)
    cvss_base: float = Field(default=0.0, ge=0.0, le=10.0)
    kev: bool = False


class BatchScoreRequest(BaseModel):
    vulnerabilities: List[BatchVulnItem] = Field(..., min_length=1)
    org_id: str
    save: bool = Field(default=False, description="Persist all scores to DB")


class ScoreResponse(BaseModel):
    cve_id: str
    org_id: str
    composite_score: float
    priority: str
    factors: Dict[str, Any]
    recommendation: str
    sla_hours: int
    record_id: Optional[str] = None


class StatsResponse(BaseModel):
    org_id: str
    distribution: Dict[str, int]
    total: int


# ============================================================================
# ENDPOINTS
# ============================================================================


@router.get(
    "",
    summary="Vulnerability risk scoring — service summary",
)
def get_service_summary(
    org_id: str = Query("default", description="Organization identifier"),
) -> Dict[str, Any]:
    """Return service status and high-level stats for the vuln risk scoring domain."""
    scorer = get_scorer()
    try:
        stats = scorer.get_scoring_stats(org_id=org_id)
    except Exception as exc:
        logger.warning("get_scoring_stats failed in summary: %s", exc)
        stats = {}
    return {
        "service": "vuln-risk-scoring",
        "status": "ok",
        "org_id": org_id,
        "stats": stats,
        "endpoints": [
            "POST /api/v1/vuln-risk/score",
            "POST /api/v1/vuln-risk/batch-score",
            "GET  /api/v1/vuln-risk/stats",
            "GET  /api/v1/vuln-risk/priority-queue",
            "GET  /api/v1/vuln-risk/trend/{cve_id}",
        ],
    }


@router.post("/score", response_model=ScoreResponse, summary="Score a single vulnerability")
def score_vulnerability(req: ScoreRequest) -> ScoreResponse:
    """Compute a contextual risk score for a single CVE."""
    scorer = get_scorer()
    try:
        result = scorer.score_vulnerability(
            cve_id=req.cve_id,
            org_id=req.org_id,
            context=req.context.model_dump(),
        )
    except Exception as exc:
        logger.exception("score_vulnerability failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    record_id: Optional[str] = None
    if req.save:
        try:
            record_id = scorer.save_score(
                org_id=req.org_id,
                cve_id=req.cve_id,
                asset_id=req.asset_id,
                score_data={**result, "context": req.context.model_dump()},
            )
        except Exception as exc:
            logger.warning("save_score failed: %s", exc)

    return ScoreResponse(
        cve_id=result["cve_id"],
        org_id=result["org_id"],
        composite_score=result["composite_score"],
        priority=result["priority"],
        factors=result["factors"],
        recommendation=result["recommendation"],
        sla_hours=result["sla_hours"],
        record_id=record_id,
    )


@router.post(
    "/batch-score",
    response_model=List[ScoreResponse],
    summary="Batch-score multiple vulnerabilities",
)
def batch_score(req: BatchScoreRequest) -> List[ScoreResponse]:
    """Score a list of vulnerabilities, returned sorted by composite_score DESC."""
    scorer = get_scorer()
    vulns = [v.model_dump() for v in req.vulnerabilities]
    try:
        results = scorer.batch_score(vulnerabilities=vulns, org_id=req.org_id)
    except Exception as exc:
        logger.exception("batch_score failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    responses: List[ScoreResponse] = []
    for r in results:
        record_id: Optional[str] = None
        if req.save:
            try:
                record_id = scorer.save_score(
                    org_id=req.org_id,
                    cve_id=r["cve_id"],
                    asset_id=None,
                    score_data={**r, "context": {}},
                )
            except Exception as exc:
                logger.warning("batch save_score failed for %s: %s", r["cve_id"], exc)

        responses.append(
            ScoreResponse(
                cve_id=r["cve_id"],
                org_id=r["org_id"],
                composite_score=r["composite_score"],
                priority=r["priority"],
                factors=r["factors"],
                recommendation=r["recommendation"],
                sla_hours=r["sla_hours"],
                record_id=record_id,
            )
        )
    return responses


@router.get("/stats", response_model=StatsResponse, summary="Priority distribution statistics")
def get_stats(org_id: str = Query(..., description="Organization identifier")) -> StatsResponse:
    """Return count of saved scores per priority tier (P1/P2/P3/P4)."""
    scorer = get_scorer()
    try:
        stats = scorer.get_scoring_stats(org_id=org_id)
    except Exception as exc:
        logger.exception("get_scoring_stats failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return StatsResponse(**stats)


@router.get(
    "/priority-queue",
    response_model=List[Dict[str, Any]],
    summary="Priority-ordered queue of saved scores",
)
def get_priority_queue(
    org_id: str = Query(..., description="Organization identifier"),
) -> List[Dict[str, Any]]:
    """Return all persisted scores for the org sorted P1→P4, then by composite score."""
    scorer = get_scorer()
    try:
        return scorer.get_priority_queue(org_id=org_id)
    except Exception as exc:
        logger.exception("get_priority_queue failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/trend/{cve_id}",
    response_model=List[Dict[str, Any]],
    summary="Historical score trend for a CVE",
)
def get_trend(
    cve_id: str,
    org_id: str = Query(..., description="Organization identifier"),
) -> List[Dict[str, Any]]:
    """Return chronological score history for a given CVE in the org."""
    scorer = get_scorer()
    try:
        return scorer.get_score_trend(org_id=org_id, cve_id=cve_id)
    except Exception as exc:
        logger.exception("get_score_trend failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
