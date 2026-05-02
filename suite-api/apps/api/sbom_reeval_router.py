"""SBOM Re-Eval + Component Claim Router — ALDECI.

Implements GAP-055 (periodic re-eval schedule) and GAP-057 (component
claim attestation). Backed by SBOMEngine (org-scoped WAL SQLite).

Prefix: /api/v1/sbom-reeval
Auth:   api_key_auth dependency on ALL endpoints

Routes:
  POST /api/v1/sbom-reeval/schedule            schedule_reeval
  GET  /api/v1/sbom-reeval/schedules           list_reeval_schedules
  POST /api/v1/sbom-reeval/mark-done           mark_reeval_done
  POST /api/v1/sbom-reeval/component-claim     register_component_claim
  GET  /api/v1/sbom-reeval/component-claims    list_component_claims
  GET  /api/v1/sbom-reeval/stats               engine_stats (for the org)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/sbom-reeval",
    tags=["SBOM Re-Eval"],
    dependencies=[Depends(api_key_auth)],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.sbom_engine import SBOMEngine
        _engine = SBOMEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class ScheduleReevalRequest(BaseModel):
    org_id: str = Field(..., description="Organisation ID")
    sbom_id: str = Field(..., description="SBOM asset / export ID to re-evaluate")
    cron_expr: str = Field(default="@daily", description="Cron expression")


class MarkDoneRequest(BaseModel):
    schedule_id: str = Field(..., description="Schedule ID")
    findings_delta: int = Field(default=0, description="Change in findings count")


class ComponentClaimRequest(BaseModel):
    org_id: str = Field(..., description="Organisation ID")
    component_purl: str = Field(..., description="Package URL")
    claimant: str = Field(..., description="Entity filing the claim")
    claim_type: str = Field(
        default="owner",
        description="owner|maintainer|distributor|redistributor|builder",
    )
    evidence_uri: str = Field(default="", description="URI to attestation evidence")
    claimed_at: Optional[str] = Field(default=None, description="ISO-8601 timestamp")


# ---------------------------------------------------------------------------
# Schedule endpoints
# ---------------------------------------------------------------------------


@router.post("/schedule", status_code=201)
async def schedule_reeval(req: ScheduleReevalRequest) -> Dict[str, Any]:
    """Create or return existing re-evaluation schedule."""
    try:
        return _get_engine().schedule_reeval(
            org_id=req.org_id,
            sbom_id=req.sbom_id,
            cron_expr=req.cron_expr,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/schedules")
async def list_reeval_schedules(
    org_id: str = Query(..., description="Organisation ID"),
    enabled: Optional[bool] = Query(default=None),
) -> Dict[str, Any]:
    """List re-eval schedules for an org; optionally filter by enabled flag."""
    schedules = _get_engine().list_reeval_schedules(org_id=org_id, enabled=enabled)
    return {"org_id": org_id, "count": len(schedules), "schedules": schedules}


@router.post("/mark-done")
async def mark_reeval_done(req: MarkDoneRequest) -> Dict[str, Any]:
    """Mark a re-eval schedule as done; advances next_run_at."""
    try:
        updated = _get_engine().mark_reeval_done(
            schedule_id=req.schedule_id,
            findings_delta=req.findings_delta,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not updated:
        raise HTTPException(status_code=404, detail="schedule_id not found")
    return updated


# ---------------------------------------------------------------------------
# Component claim endpoints
# ---------------------------------------------------------------------------


@router.post("/component-claim", status_code=201)
async def register_component_claim(req: ComponentClaimRequest) -> Dict[str, Any]:
    """Register a component claim (idempotent on org+purl+claimant)."""
    try:
        return _get_engine().register_component_claim(
            org_id=req.org_id,
            component_purl=req.component_purl,
            claimant=req.claimant,
            claim_type=req.claim_type,
            evidence_uri=req.evidence_uri,
            claimed_at=req.claimed_at,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/component-claims")
async def list_component_claims(
    org_id: str = Query(..., description="Organisation ID"),
    purl: Optional[str] = Query(default=None, description="Filter by purl"),
) -> Dict[str, Any]:
    """List component claims; optionally filter by purl."""
    claims = _get_engine().list_component_claims(org_id=org_id, purl=purl)
    return {"org_id": org_id, "purl": purl, "count": len(claims), "claims": claims}


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


@router.get("/stats")
async def sbom_reeval_stats(
    org_id: str = Query(..., description="Organisation ID"),
) -> Dict[str, Any]:
    """Return reeval + claim stats for an org."""
    eng = _get_engine()
    schedules = eng.list_reeval_schedules(org_id=org_id)
    enabled = [s for s in schedules if s.get("enabled")]
    claims = eng.list_component_claims(org_id=org_id)
    claim_types: Dict[str, int] = {}
    for c in claims:
        ct = c.get("claim_type", "unknown")
        claim_types[ct] = claim_types.get(ct, 0) + 1
    return {
        "org_id": org_id,
        "total_schedules": len(schedules),
        "enabled_schedules": len(enabled),
        "total_claims": len(claims),
        "claims_by_type": claim_types,
        "unique_purls_claimed": len({c.get("purl") for c in claims}),
    }


@router.get("/")
async def sbom_reeval_overview(
    org_id: str = Query(..., description="Organisation ID"),
) -> Dict[str, Any]:
    """Top-level SBOM re-eval overview: schedule counts and component claim summary."""
    eng = _get_engine()
    schedules = eng.list_reeval_schedules(org_id=org_id)
    enabled = [s for s in schedules if s.get("enabled")]
    claims = eng.list_component_claims(org_id=org_id)
    return {
        "status": "ok",
        "org_id": org_id,
        "total_schedules": len(schedules),
        "enabled_schedules": len(enabled),
        "total_claims": len(claims),
    }
