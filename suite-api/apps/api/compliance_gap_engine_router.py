"""Compliance Gap Engine Router — ALDECI.

Compliance gap assessment, control gap tracking, and remediation plan endpoints.

Prefix: /api/v1/compliance-gaps
Auth: api_key_auth dependency
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from apps.api.auth_deps import api_key_auth

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


class CreateAssessmentRequest(BaseModel):
    framework: str = Field(..., description="SOC2|ISO27001|NIST|PCI-DSS|HIPAA|GDPR|CIS")
    assessment_name: str = Field(..., description="Name of the assessment")
    total_controls: int = Field(default=0, ge=0)


class AddControlGapRequest(BaseModel):
    assessment_id: str = Field(...)
    control_id: str = Field(...)
    control_name: str = Field(...)
    domain: str = Field(default="")
    severity: str = Field(..., description="critical|high|medium|low")
    gap_description: str = Field(default="")
    current_state: str = Field(default="")
    required_state: str = Field(default="")
    remediation_effort: int = Field(default=0, ge=0)


class UpdateGapStatusRequest(BaseModel):
    new_status: str = Field(..., description="open|in_remediation|remediated|accepted")


class CreateRemediationPlanRequest(BaseModel):
    gap_id: str = Field(...)
    plan_description: str = Field(...)
    owner: str = Field(...)
    target_date: str = Field(...)


class UpdatePlanStatusRequest(BaseModel):
    new_status: str = Field(..., description="planned|active|completed|cancelled")


@router.post("/assessments", dependencies=[Depends(api_key_auth)], status_code=201)
def create_assessment(body: CreateAssessmentRequest, org_id: str = Query(default="default")):
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
    return _get_engine().list_assessments(org_id, framework=framework, status=status)


@router.get("/assessments/{assessment_id}", dependencies=[Depends(api_key_auth)])
def get_assessment(assessment_id: str, org_id: str = Query(default="default")):
    result = _get_engine().get_assessment(org_id, assessment_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return result


@router.put("/assessments/{assessment_id}/complete", dependencies=[Depends(api_key_auth)])
def complete_assessment(assessment_id: str, org_id: str = Query(default="default")):
    try:
        return _get_engine().complete_assessment(org_id, assessment_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error completing assessment")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/gaps", dependencies=[Depends(api_key_auth)], status_code=201)
def add_control_gap(body: AddControlGapRequest, org_id: str = Query(default="default")):
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
    return _get_engine().list_gaps(org_id, assessment_id=assessment_id, severity=severity, status=status)


@router.put("/gaps/{gap_id}/status", dependencies=[Depends(api_key_auth)])
def update_gap_status(gap_id: str, body: UpdateGapStatusRequest, org_id: str = Query(default="default")):
    try:
        return _get_engine().update_gap_status(org_id, gap_id, body.new_status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error updating gap status")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/remediation-plans", dependencies=[Depends(api_key_auth)], status_code=201)
def create_remediation_plan(body: CreateRemediationPlanRequest, org_id: str = Query(default="default")):
    try:
        return _get_engine().create_remediation_plan(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error creating remediation plan")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.put("/remediation-plans/{plan_id}/status", dependencies=[Depends(api_key_auth)])
def update_plan_status(plan_id: str, body: UpdatePlanStatusRequest, org_id: str = Query(default="default")):
    try:
        return _get_engine().update_plan_status(org_id, plan_id, body.new_status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error updating plan status")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_gap_stats(org_id: str = Query(default="default")):
    return _get_engine().get_gap_stats(org_id)
