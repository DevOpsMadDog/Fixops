"""Cloud Compliance Router — ALDECI.

Multi-cloud compliance posture endpoints (AWS / Azure / GCP).

Prefix: /api/v1/cloud-compliance
Auth:   api_key_auth dependency

Routes:
  POST   /assessments                              create_assessment
  GET    /assessments                              list_assessments
  GET    /assessments/{assessment_id}              get_assessment
  POST   /assessments/{assessment_id}/controls     add_control_result
  POST   /assessments/{assessment_id}/complete     complete_assessment
  GET    /controls                                 list_control_results
  POST   /remediation-plans                        create_remediation_plan
  PATCH  /remediation-plans/{plan_id}/status       update_remediation_plan
  GET    /remediation-plans                        list_remediation_plans
  GET    /drift                                    list_drift_history
  GET    /stats                                    get_compliance_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/cloud-compliance",
    tags=["cloud-compliance"],
    dependencies=[Depends(api_key_auth)],
)

# ---------------------------------------------------------------------------
# Lazy per-org singleton
# ---------------------------------------------------------------------------
_engine_cache: Dict[str, Any] = {}


def _get_engine(org_id: str):
    if org_id not in _engine_cache:
        from core.cloud_compliance_engine import get_engine
        _engine_cache[org_id] = get_engine(org_id)
    return _engine_cache[org_id]


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class AssessmentCreate(BaseModel):
    cloud_provider: str = Field("aws", description="aws/azure/gcp/multi")
    framework: str = Field(..., description="cis_aws_v1.5 / nist_800_53 / soc2 / etc.")
    scope: Dict[str, Any] = Field(default_factory=dict)
    total_controls: int = Field(0, ge=0)


class ControlResultCreate(BaseModel):
    control_id: str
    control_name: str = ""
    section: str = ""
    severity: str = Field("medium", description="critical/high/medium/low/info")
    status: str = Field("manual_check", description="passed/failed/not_applicable/manual_check")
    evidence: str = ""
    resource_id: str = ""
    resource_type: str = ""
    resource_name: str = ""
    region: str = ""
    remediation: str = ""
    auto_remediated: bool = False


class RemediationPlanCreate(BaseModel):
    assessment_id: str
    control_id: str
    priority: str = Field("p3", description="p1/p2/p3/p4")
    assigned_team: str = ""
    estimated_effort: str = Field("medium", description="low/medium/high")
    target_date: str = ""
    notes: str = ""


class RemediationStatusUpdate(BaseModel):
    status: str = Field(..., description="planned/in_progress/completed/deferred")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/assessments", response_model=Dict[str, Any], status_code=201)
def create_assessment(
    body: AssessmentCreate,
    org_id: str = Query("default", description="Organisation ID"),
):
    """Create a new cloud compliance assessment."""
    try:
        return _get_engine(org_id).create_assessment(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/assessments", response_model=List[Dict[str, Any]])
def list_assessments(
    org_id: str = Query("default"),
    framework: Optional[str] = Query(None),
    provider: Optional[str] = Query(None),
):
    """List assessments, optionally filtered by framework or cloud provider."""
    return _get_engine(org_id).list_assessments(org_id, framework=framework, provider=provider)


@router.get("/assessments/{assessment_id}", response_model=Dict[str, Any])
def get_assessment(
    assessment_id: str,
    org_id: str = Query("default"),
):
    """Return assessment details with control summary."""
    result = _get_engine(org_id).get_assessment(org_id, assessment_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Assessment not found.")
    return result


@router.post("/assessments/{assessment_id}/controls", response_model=Dict[str, Any], status_code=201)
def add_control_result(
    assessment_id: str,
    body: ControlResultCreate,
    org_id: str = Query("default"),
):
    """Record a control result against an assessment."""
    try:
        return _get_engine(org_id).add_control_result(org_id, assessment_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/assessments/{assessment_id}/complete", response_model=Dict[str, Any])
def complete_assessment(
    assessment_id: str,
    org_id: str = Query("default"),
):
    """Mark an assessment as completed and compute final score + drift."""
    result = _get_engine(org_id).complete_assessment(org_id, assessment_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Assessment not found.")
    return result


@router.get("/controls", response_model=List[Dict[str, Any]])
def list_control_results(
    org_id: str = Query("default"),
    assessment_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
):
    """List control results with optional filters."""
    return _get_engine(org_id).list_control_results(
        org_id, assessment_id=assessment_id, status=status, severity=severity
    )


@router.post("/remediation-plans", response_model=Dict[str, Any], status_code=201)
def create_remediation_plan(
    body: RemediationPlanCreate,
    org_id: str = Query("default"),
):
    """Create a remediation plan for a control failure."""
    try:
        return _get_engine(org_id).create_remediation_plan(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.patch("/remediation-plans/{plan_id}/status", response_model=Dict[str, Any])
def update_remediation_plan(
    plan_id: str,
    body: RemediationStatusUpdate,
    org_id: str = Query("default"),
):
    """Update the status of a remediation plan."""
    try:
        updated = _get_engine(org_id).update_remediation_plan(org_id, plan_id, body.status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not updated:
        raise HTTPException(status_code=404, detail="Remediation plan not found.")
    return {"plan_id": plan_id, "status": body.status, "updated": True}


@router.get("/remediation-plans", response_model=List[Dict[str, Any]])
def list_remediation_plans(
    org_id: str = Query("default"),
    assessment_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """List remediation plans with optional filters."""
    return _get_engine(org_id).list_remediation_plans(
        org_id, assessment_id=assessment_id, status=status
    )


@router.get("/drift", response_model=List[Dict[str, Any]])
def list_drift_history(
    org_id: str = Query("default"),
    framework: Optional[str] = Query(None),
    limit: int = Query(10, ge=1, le=100),
):
    """Return compliance drift history over time."""
    return _get_engine(org_id).list_drift_history(org_id, framework=framework, limit=limit)


@router.get("/stats", response_model=Dict[str, Any])
def get_compliance_stats(
    org_id: str = Query("default"),
):
    """Return aggregated cloud compliance statistics."""
    return _get_engine(org_id).get_compliance_stats(org_id)
