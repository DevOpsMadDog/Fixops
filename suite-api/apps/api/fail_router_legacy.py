"""
FAIL Engine API Router — /api/v1/fail/*

Exposes the FAIL scoring engine via REST API.

Endpoints:
    POST   /api/v1/fail/score         — Score a single finding
    POST   /api/v1/fail/score/batch   — Score multiple findings
    GET    /api/v1/fail/score/{id}    — Retrieve a stored FAIL score
    GET    /api/v1/fail/scores        — List FAIL scores (paginated)
    GET    /api/v1/fail/top-risks     — Top risks by FAIL score
    GET    /api/v1/fail/stats         — Aggregate FAIL statistics
    GET    /api/v1/fail/cve/{cve_id}  — FAIL scores for a specific CVE
    DELETE /api/v1/fail/score/{id}    — Delete a FAIL score
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.dependencies import get_org_id
from core.fail_db import FAILDB
from core.fail_engine import (
    ExploitMaturity,
    FAILEngine,
    FAILInput,
)
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/fail", tags=["fail-engine"])

# Singletons
_engine = FAILEngine()
_db = FAILDB()


# ---------------------------------------------------------------------------
# Request / Response models (Pydantic for API validation)
# ---------------------------------------------------------------------------


class FAILScoreRequest(BaseModel):
    """Request body for scoring a finding."""

    cve_id: Optional[str] = Field(None, description="CVE identifier (e.g. CVE-2024-3094)")
    finding_id: Optional[str] = Field(None, description="Internal finding ID")
    title: str = Field("", description="Vulnerability title")

    # Scanner scores
    cvss_score: Optional[float] = Field(None, ge=0, le=10, description="CVSS v3 base score")
    epss_score: Optional[float] = Field(None, ge=0, le=1, description="EPSS probability (0-1)")

    # Threat intel
    is_kev: bool = Field(False, description="Is in CISA KEV catalog")
    has_exploit: bool = Field(False, description="Known exploit exists")
    exploit_maturity: str = Field("unknown", description="Exploit maturity level")
    active_campaigns: int = Field(0, ge=0, description="Number of active threat campaigns")

    # Environment
    asset_criticality: str = Field("unknown", description="Asset criticality level")
    data_classification: str = Field("none", description="Data classification")
    is_reachable: bool = Field(False, description="Is vulnerability reachable")
    is_internet_facing: bool = Field(False, description="Is asset internet-facing")
    has_compensating_controls: bool = Field(False, description="Has compensating controls")

    # Organisational
    affected_assets: int = Field(1, ge=0, description="Number of affected assets")
    affected_users: int = Field(0, ge=0, description="Number of affected users")
    compliance_frameworks: List[str] = Field(default_factory=list, description="Compliance frameworks")
    sla_hours: Optional[int] = Field(None, description="SLA hours for remediation")

    # Extra
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class FAILScoreBatchRequest(BaseModel):
    """Request body for batch scoring."""

    findings: List[FAILScoreRequest] = Field(..., min_length=1, max_length=500)


class FAILScoreResponse(BaseModel):
    """FAIL score response."""

    score_id: str
    fail_score: float
    grade: str
    recommended_action: str
    cve_id: Optional[str] = None
    finding_id: Optional[str] = None
    sub_scores: Dict[str, Any]
    weights: Dict[str, float]
    scored_at: str
    engine_version: str
    computation_ms: float


class FAILBatchError(BaseModel):
    """Error entry for a failed batch item."""

    index: int
    error: str
    cve_id: Optional[str] = None
    finding_id: Optional[str] = None


class FAILBatchResponse(BaseModel):
    """Batch scoring response."""

    total: int
    results: List[FAILScoreResponse]
    errors: List[FAILBatchError] = []
    stats: Dict[str, Any]


class FAILStatsResponse(BaseModel):
    """Aggregate statistics response."""

    total: int
    average_score: float
    max_score: float
    min_score: float
    grade_distribution: Dict[str, int]


# ---------------------------------------------------------------------------
# Helper: convert request to engine input
# ---------------------------------------------------------------------------


def _request_to_input(req: FAILScoreRequest) -> FAILInput:
    """Convert Pydantic request DTO to engine FAILInput dataclass."""
    # Map exploit maturity string to enum
    try:
        maturity = ExploitMaturity(req.exploit_maturity.lower())
    except ValueError:
        maturity = ExploitMaturity.UNKNOWN

    return FAILInput(
        cve_id=req.cve_id,
        finding_id=req.finding_id,
        title=req.title,
        cvss_score=req.cvss_score,
        epss_score=req.epss_score,
        is_kev=req.is_kev,
        has_exploit=req.has_exploit,
        exploit_maturity=maturity,
        active_campaigns=req.active_campaigns,
        asset_criticality=req.asset_criticality,
        data_classification=req.data_classification,
        is_reachable=req.is_reachable,
        is_internet_facing=req.is_internet_facing,
        has_compensating_controls=req.has_compensating_controls,
        affected_assets=req.affected_assets,
        affected_users=req.affected_users,
        compliance_frameworks=req.compliance_frameworks,
        sla_hours=req.sla_hours,
        metadata=req.metadata,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/score", response_model=FAILScoreResponse, summary="Score a single finding")
async def score_finding(
    req: FAILScoreRequest,
    org_id: str = Depends(get_org_id),
):
    """
    Compute the FAIL score for a vulnerability finding.

    The engine evaluates four dimensions:
    - **$FACT**: Evidence quality (CVE, CVSS, EPSS confirmation)
    - **$ASSESS**: Attack complexity and exploit maturity
    - **$IMPACT**: Business impact and blast radius
    - **$LIKELIHOOD**: Exploitation probability from threat intel

    Returns a composite FAIL score (0-100) with grade and recommended action.
    """
    try:
        inp = _request_to_input(req)
        result = _engine.score(inp)
        result_dict = result.to_dict()

        # Persist to DB
        _db.save_score(result_dict, org_id=org_id, input_dict=req.model_dump())

        return FAILScoreResponse(**result_dict)
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        logger.exception("FAIL scoring failed: %s", e)
        raise HTTPException(status_code=500, detail=f"Scoring failed: {type(e).__name__}")


@router.post("/score/batch", response_model=FAILBatchResponse, summary="Score multiple findings")
async def score_batch(
    req: FAILScoreBatchRequest,
    org_id: str = Depends(get_org_id),
):
    """Score multiple findings in one request (max 500)."""
    results = []
    errors = []
    for idx, finding_req in enumerate(req.findings):
        try:
            inp = _request_to_input(finding_req)
            result = _engine.score(inp)
            result_dict = result.to_dict()
            _db.save_score(result_dict, org_id=org_id, input_dict=finding_req.model_dump())
            results.append(FAILScoreResponse(**result_dict))
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.warning("FAIL batch item %d failed: %s", idx, e)
            errors.append(FAILBatchError(
                index=idx,
                error=f"{type(e).__name__}: scoring failed",
                cve_id=finding_req.cve_id,
                finding_id=finding_req.finding_id,
            ))

    return FAILBatchResponse(
        total=len(results),
        results=results,
        errors=errors,
        stats=_engine.stats(),
    )


@router.get("/score/{score_id}", summary="Get a stored FAIL score")
async def get_score(score_id: str):
    """Retrieve a previously computed FAIL score by ID."""
    record = _db.get_score(score_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"FAIL score {score_id} not found")
    return record


@router.get("/scores", summary="List FAIL scores")
async def list_scores(
    org_id: str = Depends(get_org_id),
    grade: Optional[str] = Query(None, description="Filter by grade"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """List FAIL scores for the organisation (paginated, sorted by score DESC)."""
    scores = _db.get_scores_by_org(org_id=org_id, grade=grade, limit=limit, offset=offset)
    total = _db.count(org_id=org_id)
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "results": scores,
    }


@router.get("/top-risks", summary="Top risks by FAIL score")
async def top_risks(
    org_id: str = Depends(get_org_id),
    limit: int = Query(20, ge=1, le=100),
):
    """Get the highest-risk findings by FAIL score."""
    return {
        "risks": _db.get_top_risks(org_id=org_id, limit=limit),
        "total": _db.count(org_id=org_id),
    }


@router.get("/stats", response_model=FAILStatsResponse, summary="FAIL score statistics")
async def fail_stats(org_id: str = Depends(get_org_id)):
    """Aggregate FAIL scoring statistics for the organisation."""
    stats = _db.get_stats(org_id=org_id)
    return FAILStatsResponse(**stats)


@router.get("/cve/{cve_id}", summary="FAIL scores for a CVE")
async def scores_by_cve(cve_id: str):
    """Get all FAIL score history for a specific CVE."""
    scores = _db.get_scores_by_cve(cve_id)
    return {
        "cve_id": cve_id,
        "total": len(scores),
        "scores": scores,
    }


@router.delete("/score/{score_id}", summary="Delete a FAIL score")
async def delete_score(
    score_id: str,
    org_id: str = Depends(get_org_id),
):
    """Delete a stored FAIL score (requires org_id authorization)."""
    # Verify score exists and belongs to this org
    existing = _db.get_score(score_id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"FAIL score {score_id} not found")
    if existing.get("org_id") and existing["org_id"] != org_id:
        raise HTTPException(status_code=403, detail="Not authorized to delete this score")
    deleted = _db.delete_score(score_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"FAIL score {score_id} not found")
    return {"deleted": True, "score_id": score_id}


@router.get("/health", summary="FAIL engine health")
async def fail_health():
    """Health check for the FAIL scoring engine."""
    return {
        "status": "healthy",
        "engine_version": FAILEngine.VERSION,
        "total_scored": _db.count(),
        "in_memory_history": len(_engine.history),
    }


@router.get("/status", summary="FAIL engine status")
async def fail_status():
    """FAIL engine status (alias for /health)."""
    return await fail_health()
