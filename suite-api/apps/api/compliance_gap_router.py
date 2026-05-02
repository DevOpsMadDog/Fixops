"""Compliance Gap Engine Router — ALDECI.

Compliance gap assessment, control gap tracking, and remediation plan endpoints.

Prefix: /api/v1/compliance-gaps
Auth: api_key_auth dependency

Routes:
  POST /api/v1/compliance-gaps/assessments               create_assessment
  GET  /api/v1/compliance-gaps/assessments               list_assessments
  GET  /api/v1/compliance-gaps/assessments/{id}          get_assessment
  PUT  /api/v1/compliance-gaps/assessments/{id}/complete complete_assessment
  POST /api/v1/compliance-gaps/gaps                      add_control_gap
  GET  /api/v1/compliance-gaps/gaps                      list_gaps
  PUT  /api/v1/compliance-gaps/gaps/{id}/status          update_gap_status
  POST /api/v1/compliance-gaps/remediation-plans         create_remediation_plan
  PUT  /api/v1/compliance-gaps/remediation-plans/{id}/status  update_plan_status
  GET  /api/v1/compliance-gaps/stats                     get_gap_stats
"""

from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/compliance-gaps",
    tags=["Compliance Gaps"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.compliance_gap_engine import ComplianceGapEngine
        _engine = ComplianceGapEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class CreateAssessmentRequest(BaseModel):
    framework: str = Field(
        ..., description="SOC2|ISO27001|NIST|PCI-DSS|HIPAA|GDPR|CIS"
    )
    assessment_name: str = Field(..., description="Name of the assessment")
    total_controls: int = Field(default=0, ge=0, description="Expected control count")


class AddControlGapRequest(BaseModel):
    assessment_id: str = Field(..., description="Parent assessment ID")
    control_id: str = Field(..., description="Framework control identifier")
    control_name: str = Field(..., description="Human-readable control name")
    domain: str = Field(default="", description="Control domain/category")
    severity: str = Field(..., description="critical|high|medium|low")
    gap_description: str = Field(default="", description="Description of the gap")
    current_state: str = Field(default="", description="Current implementation state")
    required_state: str = Field(default="", description="Required implementation state")
    remediation_effort: int = Field(
        default=0, ge=0, description="Estimated remediation hours"
    )


class UpdateGapStatusRequest(BaseModel):
    new_status: str = Field(
        ..., description="open|in_remediation|remediated|accepted"
    )


class CreateRemediationPlanRequest(BaseModel):
    gap_id: str = Field(..., description="Control gap ID to remediate")
    plan_description: str = Field(..., description="Remediation plan description")
    owner: str = Field(..., description="Owner responsible for remediation")
    target_date: str = Field(..., description="Target completion date (ISO)")


class UpdatePlanStatusRequest(BaseModel):
    new_status: str = Field(..., description="planned|active|completed|cancelled")


# ---------------------------------------------------------------------------
# Routes — Assessments
# ---------------------------------------------------------------------------


@router.post("/assessments", dependencies=[Depends(api_key_auth)], status_code=201)
def create_assessment(
    body: CreateAssessmentRequest,
    org_id: str = Query(default="default"),
):
    """Create a new compliance gap assessment."""
    try:
        return _get_engine().create_assessment(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error creating assessment")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/assessments", dependencies=[Depends(api_key_auth)])
def list_assessments(
    org_id: str = Query(default="default"),
    framework: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
):
    """List compliance gap assessments with optional filters."""
    return _get_engine().list_assessments(
        org_id, framework=framework, status=status
    )


@router.get("/assessments/{assessment_id}", dependencies=[Depends(api_key_auth)])
def get_assessment(
    assessment_id: str,
    org_id: str = Query(default="default"),
):
    """Get a specific compliance gap assessment."""
    result = _get_engine().get_assessment(org_id, assessment_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return result


@router.put(
    "/assessments/{assessment_id}/complete",
    dependencies=[Depends(api_key_auth)],
)
def complete_assessment(
    assessment_id: str,
    org_id: str = Query(default="default"),
):
    """Mark an assessment as completed and recalculate compliance percentage."""
    try:
        return _get_engine().complete_assessment(org_id, assessment_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error completing assessment")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Routes — Control Gaps
# ---------------------------------------------------------------------------


@router.post("/gaps", dependencies=[Depends(api_key_auth)], status_code=201)
def add_control_gap(
    body: AddControlGapRequest,
    org_id: str = Query(default="default"),
):
    """Add a control gap to an assessment."""
    try:
        return _get_engine().add_control_gap(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error adding control gap")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/gaps", dependencies=[Depends(api_key_auth)])
def list_gaps(
    org_id: str = Query(default="default"),
    assessment_id: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
):
    """List control gaps with optional filters."""
    return _get_engine().list_gaps(
        org_id,
        assessment_id=assessment_id,
        severity=severity,
        status=status,
    )


@router.put("/gaps/{gap_id}/status", dependencies=[Depends(api_key_auth)])
def update_gap_status(
    gap_id: str,
    body: UpdateGapStatusRequest,
    org_id: str = Query(default="default"),
):
    """Update the status of a control gap."""
    try:
        return _get_engine().update_gap_status(org_id, gap_id, body.new_status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error updating gap status")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Routes — Remediation Plans
# ---------------------------------------------------------------------------


@router.put(
    "/remediation-plans/{plan_id}/status",
    dependencies=[Depends(api_key_auth)],
)
def update_plan_status(
    plan_id: str,
    body: UpdatePlanStatusRequest,
    org_id: str = Query(default="default"),
):
    """Update the status of a remediation plan."""
    try:
        return _get_engine().update_plan_status(org_id, plan_id, body.new_status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error updating plan status")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/remediation-plans", dependencies=[Depends(api_key_auth)], status_code=201
)
def create_remediation_plan(
    body: CreateRemediationPlanRequest,
    org_id: str = Query(default="default"),
):
    """Create a remediation plan for a control gap."""
    try:
        return _get_engine().create_remediation_plan(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error creating remediation plan")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Routes — Stats
# ---------------------------------------------------------------------------


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_gap_stats(
    org_id: str = Query(default="default"),
):
    """Get compliance gap statistics for an org."""
    return _get_engine().get_gap_stats(org_id)
