"""Patch Prioritizer API — EPSS + KEV + asset criticality weighted scoring.

Endpoints (prefix /api/v1/patch-priority):
  POST   /score                          score a single CVE
  POST   /batch                          score multiple CVEs, sorted
  POST   /plans                          create a patch plan
  GET    /plans                          list plans for org
  GET    /plans/{plan_id}                get a specific plan
  POST   /plans/{plan_id}/patch/{cve_id} mark CVE patched
  GET    /stats                          org-level stats
  GET    /kev/{cve_id}                   check KEV status
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
        "patch_prioritizer_router: auth_deps not available, relying on app.py mount-level auth"
    )
    _AUTH_DEP = []

from core.patch_prioritizer import PatchPrioritizer

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/patch-priority",
    tags=["patch-prioritization"],
    dependencies=_AUTH_DEP,
)

_prioritizer: Optional[PatchPrioritizer] = None


def _get_prioritizer() -> PatchPrioritizer:
    global _prioritizer
    if _prioritizer is None:
        _prioritizer = PatchPrioritizer()
    return _prioritizer


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class ScoreRequest(BaseModel):
    cve_id: str = Field(..., description="CVE identifier, e.g. CVE-2021-44228")
    cvss_score: float = Field(0.0, ge=0.0, le=10.0, description="CVSS base score 0-10")
    epss_score: float = Field(0.0, ge=0.0, le=1.0, description="EPSS probability 0-1")
    asset_criticality: str = Field(
        "medium", description="Asset criticality: low|medium|high|critical"
    )


class BatchRequest(BaseModel):
    cves: List[ScoreRequest]


class PlanCreateRequest(BaseModel):
    cves: List[ScoreRequest]
    org_id: str = Field("default", description="Organisation ID")
    plan_name: str = Field("Patch Plan", description="Human-readable plan name")


class MarkPatchedRequest(BaseModel):
    patched_by: str = Field("system", description="Who applied the patch")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "",
    summary="Patch prioritization — service summary",
)
def get_service_summary(
    org_id: str = Query("default", description="Organization identifier"),
) -> Dict[str, Any]:
    """Return service status and patch stats for the patch prioritization domain."""
    p = _get_prioritizer()
    try:
        stats = p.get_patch_stats(org_id=org_id)
    except Exception as exc:
        logger.warning("get_patch_stats failed in summary: %s", exc)
        stats = {}
    try:
        plans = p.list_plans(org_id=org_id)
        plan_count = len(plans)
    except Exception as exc:
        logger.warning("list_plans failed in summary: %s", exc)
        plan_count = 0
    return {
        "service": "patch-prioritization",
        "status": "ok",
        "org_id": org_id,
        "plan_count": plan_count,
        "stats": stats,
        "endpoints": [
            "POST /api/v1/patch-priority/score",
            "POST /api/v1/patch-priority/batch",
            "POST /api/v1/patch-priority/plans",
            "GET  /api/v1/patch-priority/plans",
            "GET  /api/v1/patch-priority/plans/{plan_id}",
            "POST /api/v1/patch-priority/plans/{plan_id}/patch/{cve_id}",
            "GET  /api/v1/patch-priority/stats",
            "GET  /api/v1/patch-priority/kev/{cve_id}",
        ],
    }


@router.post("/score", summary="Score a single CVE for patch priority")
def score_cve(req: ScoreRequest) -> Dict[str, Any]:
    """Return a priority score and band for a single CVE."""
    p = _get_prioritizer()
    return p.score_cve(
        cve_id=req.cve_id,
        cvss_score=req.cvss_score,
        epss_score=req.epss_score,
        asset_criticality=req.asset_criticality,
    )


@router.post("/batch", summary="Score multiple CVEs, sorted by priority")
def score_batch(req: BatchRequest) -> List[Dict[str, Any]]:
    """Score and rank a list of CVEs by composite priority score."""
    p = _get_prioritizer()
    cves = [c.model_dump() for c in req.cves]
    return p.prioritize_batch(cves)


@router.post("/plans", summary="Create a prioritized patch plan")
def create_plan(req: PlanCreateRequest) -> Dict[str, Any]:
    """Create and persist a patch plan from a list of CVEs."""
    p = _get_prioritizer()
    cves = [c.model_dump() for c in req.cves]
    return p.create_patch_plan(
        cves=cves,
        org_id=req.org_id,
        plan_name=req.plan_name,
    )


@router.get("/plans", summary="List patch plans for an org")
def list_plans(org_id: str = Query("default")) -> List[Dict[str, Any]]:
    """List all patch plans for the given org."""
    p = _get_prioritizer()
    return p.list_plans(org_id=org_id)


@router.get("/plans/{plan_id}", summary="Get a specific patch plan")
def get_plan(plan_id: str) -> Dict[str, Any]:
    """Retrieve a patch plan by ID."""
    p = _get_prioritizer()
    plan = p.get_plan(plan_id)
    if plan is None:
        raise HTTPException(status_code=404, detail=f"Plan {plan_id!r} not found")
    return plan


@router.post("/plans/{plan_id}/patch/{cve_id}", summary="Mark a CVE as patched")
def mark_patched(
    plan_id: str,
    cve_id: str,
    req: Optional[MarkPatchedRequest] = None,
) -> Dict[str, Any]:
    """Record that a specific CVE in a plan has been patched."""
    p = _get_prioritizer()
    patched_by = (req.patched_by if req else "system") or "system"
    return p.mark_patched(plan_id=plan_id, cve_id=cve_id, patched_by=patched_by)


@router.get("/stats", summary="Org-level patch statistics")
def get_stats(org_id: str = Query("default")) -> Dict[str, Any]:
    """Return aggregate patch stats for the org."""
    p = _get_prioritizer()
    return p.get_patch_stats(org_id=org_id)


@router.get("/kev/{cve_id}", summary="Check if CVE is in CISA KEV list")
def check_kev(cve_id: str) -> Dict[str, Any]:
    """Return KEV membership and metadata for a CVE."""
    p = _get_prioritizer()
    from core.patch_prioritizer import KEV_LIST
    is_kev = p.is_kev(cve_id)
    kev_info = KEV_LIST.get(cve_id.upper())
    return {
        "cve_id": cve_id,
        "is_kev": is_kev,
        "kev_name": kev_info["name"] if kev_info else None,
        "kev_due_date": kev_info["due_date"] if kev_info else None,
    }
