"""
CNAPP Router (Cloud Native Application Protection Platform) — ALDECI.

Prefix: /api/v1/cnapp
Auth:   X-API-Key header (injected via Depends(_verify_api_key) in app.py)
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.cnapp_engine import get_engine
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/cnapp", tags=["cnapp"])


# ---------------------------------------------------------------------------
# Root summary
# ---------------------------------------------------------------------------

@router.get("/")
def cnapp_root(
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """CNAPP root: returns live stats + latest composite score for the org."""
    try:
        return get_engine().get_cnapp_stats(org_id)
    except Exception as exc:
        _logger.error("cnapp_root failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class RegisterWorkloadRequest(BaseModel):
    name: str
    workload_type: str = "vm"
    cloud_provider: str = "aws"
    region: str = ""
    image_name: str = ""
    image_hash: str = ""
    running: bool = True
    privileged: bool = False


class AddFindingRequest(BaseModel):
    category: str = "misconfiguration"
    severity: str = "medium"
    title: str = ""
    description: str = ""
    remediation: str = ""
    cve_id: str = ""
    status: str = "open"
    detected_at: Optional[str] = None


class SuppressFindingRequest(BaseModel):
    reason: str = ""


class CreatePolicyRequest(BaseModel):
    name: str
    policy_type: str = "network"
    action: str = "alert"
    severity: str = "medium"
    cloud_provider: str = "aws"
    enabled: bool = True


# ---------------------------------------------------------------------------
# Workloads
# ---------------------------------------------------------------------------

@router.post("/workloads")
def register_workload(
    org_id: str = Query(..., description="Organisation ID"),
    body: RegisterWorkloadRequest = ...,
) -> Dict[str, Any]:
    """Register a new cloud workload."""
    try:
        return get_engine().register_workload(org_id, body.model_dump())
    except Exception as exc:
        _logger.error("register_workload failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/workloads")
def list_workloads(
     org_id: str = Query(default="default"),
    workload_type: Optional[str] = Query(None),
    cloud_provider: Optional[str] = Query(None),
    running_only: bool = Query(True),
) -> List[Dict[str, Any]]:
    """List cloud workloads with optional filters."""
    try:
        return get_engine().list_workloads(
            org_id,
            workload_type=workload_type,
            cloud_provider=cloud_provider,
            running_only=running_only,
        )
    except Exception as exc:
        _logger.error("list_workloads failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

@router.post("/workloads/{workload_id}/findings")
def add_finding(
    workload_id: str,
     org_id: str = Query(default="default"),
    body: AddFindingRequest = ...,
) -> Dict[str, Any]:
    """Add a CNAPP finding to a workload. Auto-updates workload risk_score."""
    try:
        return get_engine().add_finding(org_id, workload_id, body.model_dump())
    except Exception as exc:
        _logger.error("add_finding failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/findings")
def list_findings(
     org_id: str = Query(default="default"),
    category: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    """List CNAPP findings with optional filters."""
    try:
        return get_engine().list_findings(
            org_id,
            category=category,
            severity=severity,
            status=status,
        )
    except Exception as exc:
        _logger.error("list_findings failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/findings/{finding_id}/suppress")
def suppress_finding(
    finding_id: str,
     org_id: str = Query(default="default"),
    body: SuppressFindingRequest = SuppressFindingRequest(),
) -> Dict[str, Any]:
    """Suppress a CNAPP finding."""
    try:
        ok = get_engine().suppress_finding(org_id, finding_id, body.reason)
        if not ok:
            raise HTTPException(status_code=404, detail="Finding not found or already suppressed")
        return {"finding_id": finding_id, "suppressed": True}
    except HTTPException:
        raise
    except Exception as exc:
        _logger.error("suppress_finding failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------

@router.post("/policies")
def create_policy(
     org_id: str = Query(default="default"),
    body: CreatePolicyRequest = ...,
) -> Dict[str, Any]:
    """Create a cloud security policy."""
    try:
        return get_engine().create_policy(org_id, body.model_dump())
    except Exception as exc:
        _logger.error("create_policy failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/policies")
def list_policies(
     org_id: str = Query(default="default"),
    cloud_provider: Optional[str] = Query(None),
    enabled_only: bool = Query(True),
) -> List[Dict[str, Any]]:
    """List cloud policies."""
    try:
        return get_engine().list_policies(
            org_id,
            cloud_provider=cloud_provider,
            enabled_only=enabled_only,
        )
    except Exception as exc:
        _logger.error("list_policies failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# CNAPP Scoring
# ---------------------------------------------------------------------------

@router.post("/scores/calculate")
def calculate_cnapp_score(
     org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Calculate and persist the composite CNAPP score (CSPM + CWPP + CIEM)."""
    try:
        return get_engine().calculate_cnapp_score(org_id)
    except Exception as exc:
        _logger.error("calculate_cnapp_score failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/scores")
def list_scores(
     org_id: str = Query(default="default"),
    limit: int = Query(10, ge=1, le=100),
) -> List[Dict[str, Any]]:
    """List historical CNAPP scores ordered by calculated_at descending."""
    try:
        return get_engine().list_scores(org_id, limit=limit)
    except Exception as exc:
        _logger.error("list_scores failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats")
def get_cnapp_stats(
     org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Get aggregate CNAPP stats for an org."""
    try:
        return get_engine().get_cnapp_stats(org_id)
    except Exception as exc:
        _logger.error("get_cnapp_stats failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Policy Recommendations
# ---------------------------------------------------------------------------

@router.get("/policy-recommendations")
def get_policy_recommendations(
    org_id: str = Query(default="default"),
) -> List[Dict[str, Any]]:
    """Return actionable policy recommendations derived from open findings.

    Each recommendation maps a category+severity group to a suggested policy
    type and action. Recommendations already covered by an enabled policy are
    flagged with already_covered=True rather than suppressed.
    Sorted by priority (critical first), then finding_count descending.
    """
    try:
        return get_engine().get_policy_recommendations(org_id)
    except Exception as exc:
        _logger.error("get_policy_recommendations failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))
