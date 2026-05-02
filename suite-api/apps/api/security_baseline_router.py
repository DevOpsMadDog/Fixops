"""Security Baseline Router — ALDECI.

Security configuration baseline management and drift detection.

Prefix: /api/v1/security-baselines
Auth: api_key_auth dependency on ALL endpoints

Routes:
  POST   /api/v1/security-baselines/baselines                create_baseline
  POST   /api/v1/security-baselines/baselines/{id}/controls  add_control
  PUT    /api/v1/security-baselines/baselines/{id}/publish    publish_baseline
  POST   /api/v1/security-baselines/baselines/{id}/assess    run_assessment
  GET    /api/v1/security-baselines/baselines/{id}           get_baseline_detail
  GET    /api/v1/security-baselines/baselines/{id}/drift     get_drift_report
  GET    /api/v1/security-baselines/baselines/{id}/trend     get_compliance_trend
  GET    /api/v1/security-baselines/baselines                list_baselines
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/security-baselines",
    tags=["Security Baselines"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_baseline_engine import SecurityBaselineEngine
        _engine = SecurityBaselineEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class CreateBaselineRequest(BaseModel):
    baseline_name: str = Field(..., description="Descriptive name for the baseline")
    target_type: str = Field(
        ...,
        description="server | workstation | network_device | cloud_instance | container | database | application",
    )
    framework: str = Field(
        ...,
        description="CIS | NIST | STIG | ISO27001 | PCI-DSS | custom",
    )
    version: str = Field(default="1.0", description="Baseline version string")
    created_by: str = Field(..., description="Username of creator")


class AddControlRequest(BaseModel):
    control_id: str = Field(..., description="Control identifier (e.g. CIS-1.1)")
    control_name: str = Field(..., description="Human-readable control name")
    category: str = Field(default="", description="Control category")
    description: str = Field(default="", description="Detailed control description")
    expected_value: str = Field(..., description="Expected configuration value")
    severity: str = Field(
        default="medium",
        description="critical | high | medium | low",
    )
    automated_check: bool = Field(default=False, description="Whether check can be automated")


class AssessmentResultItem(BaseModel):
    control_id: str = Field(..., description="Control identifier")
    control_name: str = Field(default="", description="Control name")
    status: str = Field(..., description="pass | fail | skip")
    actual_value: str = Field(default="", description="Observed configuration value")
    deviation: str = Field(default="", description="Description of deviation from expected")
    severity: str = Field(default="medium", description="critical | high | medium | low")


class RunAssessmentRequest(BaseModel):
    target_name: str = Field(..., description="Target system/host name")
    assessed_by: str = Field(..., description="Assessor username or tool name")
    results: List[AssessmentResultItem] = Field(..., description="Per-control assessment results")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/", dependencies=[Depends(api_key_auth)])
def list_security_baselines(org_id: str = Query("default")) -> Dict[str, Any]:
    """List security baselines for the org."""
    baselines = _get_engine().list_baselines(org_id=org_id)
    return {"org_id": org_id, "baselines": baselines, "total": len(baselines)}


@router.post("/baselines", dependencies=[Depends(api_key_auth)], status_code=201)
def create_baseline(
    req: CreateBaselineRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Create a new security baseline in draft status."""
    try:
        return _get_engine().create_baseline(
            org_id=org_id,
            baseline_name=req.baseline_name,
            target_type=req.target_type,
            framework=req.framework,
            version=req.version,
            created_by=req.created_by,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/baselines/{baseline_id}/controls", dependencies=[Depends(api_key_auth)], status_code=201)
def add_control(
    baseline_id: str,
    req: AddControlRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Add a control to a baseline."""
    try:
        return _get_engine().add_control(
            baseline_id=baseline_id,
            org_id=org_id,
            control_id=req.control_id,
            control_name=req.control_name,
            category=req.category,
            description=req.description,
            expected_value=req.expected_value,
            severity=req.severity,
            automated_check=req.automated_check,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.put("/baselines/{baseline_id}/publish", dependencies=[Depends(api_key_auth)])
def publish_baseline(
    baseline_id: str,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Publish a baseline (status=active, published_at=now)."""
    try:
        return _get_engine().publish_baseline(baseline_id=baseline_id, org_id=org_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/baselines/{baseline_id}/assess", dependencies=[Depends(api_key_auth)], status_code=201)
def run_assessment(
    baseline_id: str,
    req: RunAssessmentRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Run a baseline assessment against a target system."""
    try:
        results_list = [r.model_dump() for r in req.results]
        return _get_engine().run_assessment(
            baseline_id=baseline_id,
            org_id=org_id,
            target_name=req.target_name,
            results_list=results_list,
            assessed_by=req.assessed_by,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/baselines/{baseline_id}", dependencies=[Depends(api_key_auth)])
def get_baseline_detail(
    baseline_id: str,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Return baseline detail with controls and last 5 assessments."""
    detail = _get_engine().get_baseline_detail(baseline_id, org_id)
    if detail is None:
        raise HTTPException(status_code=404, detail=f"Baseline '{baseline_id}' not found")
    return detail


@router.get("/baselines/{baseline_id}/drift", dependencies=[Depends(api_key_auth)])
def get_drift_report(
    baseline_id: str,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Compare last 2 assessments to detect control drift."""
    try:
        return _get_engine().get_drift_report(baseline_id=baseline_id, org_id=org_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/baselines/{baseline_id}/trend", dependencies=[Depends(api_key_auth)])
def get_compliance_trend(
    baseline_id: str,
    org_id: str = Query(..., description="Organization ID"),
) -> List[Dict[str, Any]]:
    """Return compliance trend across all assessments."""
    try:
        return _get_engine().get_compliance_trend(baseline_id=baseline_id, org_id=org_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/baselines", dependencies=[Depends(api_key_auth)])
def list_baselines(
    org_id: str = Query(..., description="Organization ID"),
    status: Optional[str] = Query(default=None, description="draft | active | deprecated"),
) -> List[Dict[str, Any]]:
    """List baselines for an org, optionally filtered by status."""
    try:
        return _get_engine().list_baselines(org_id=org_id, status=status)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
