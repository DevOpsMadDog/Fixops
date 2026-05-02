"""Endpoint Compliance Router — ALDECI.

CIS benchmark compliance for endpoints.

Prefix: /api/v1/endpoint-compliance
Auth:   api_key_auth dependency

Routes:
  POST   /endpoints                                   register_endpoint
  GET    /endpoints                                   list_endpoints
  GET    /endpoints/{endpoint_id}                     get_endpoint
  POST   /endpoints/{endpoint_id}/checks              record_check
  POST   /endpoints/{endpoint_id}/checks/bulk         bulk_record_checks
  GET    /checks                                      list_checks
  POST   /exceptions                                  add_exception
  POST   /baselines                                   create_baseline
  GET    /baselines                                   list_baselines
  GET    /stats                                       get_endpoint_stats
  GET    /department-compliance                       get_department_compliance
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/endpoint-compliance",
    tags=["endpoint-compliance"],
    dependencies=[Depends(api_key_auth)],
)

# ---------------------------------------------------------------------------
# Lazy per-org singleton
# ---------------------------------------------------------------------------
_engine_cache: Dict[str, Any] = {}


def _get_engine(org_id: str):
    if org_id not in _engine_cache:
        from core.endpoint_compliance_engine import get_engine
        _engine_cache[org_id] = get_engine(org_id)
    return _engine_cache[org_id]


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class EndpointCreate(BaseModel):
    hostname: str
    os_type: str = Field("linux", description="windows/linux/macos/android/ios")
    os_version: str = ""
    department: str = ""
    owner_id: str = ""


class CheckCreate(BaseModel):
    check_id: str
    check_name: str = ""
    benchmark: str = Field("cis_windows_l1", description="cis_windows_l1/cis_ubuntu/etc.")
    category: str = Field("local_policy", description="account_policy/local_policy/etc.")
    severity: str = Field("medium", description="critical/high/medium/low")
    status: str = Field("failed", description="passed/failed/not_applicable/error")
    actual_value: str = ""
    expected_value: str = ""
    remediation: str = ""
    scanned_at: Optional[str] = None


class BulkChecksCreate(BaseModel):
    checks: List[CheckCreate]


class ExceptionCreate(BaseModel):
    endpoint_id: str
    check_id: str
    reason: str = ""
    approved_by: str = ""
    expires_at: str = ""


class BaselineCreate(BaseModel):
    baseline_name: str
    os_type: str = Field("linux", description="windows/linux/macos/android/ios")
    benchmark: str = Field("cis_ubuntu", description="CIS benchmark identifier")
    required_checks: List[str] = Field(default_factory=list)
    target_score: float = Field(80.0, ge=0.0, le=100.0)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/endpoints", response_model=Dict[str, Any], status_code=201)
def register_endpoint(
    body: EndpointCreate,
    org_id: str = Query("default", description="Organisation ID"),
):
    """Register a new endpoint for compliance tracking."""
    try:
        return _get_engine(org_id).register_endpoint(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/endpoints", response_model=List[Dict[str, Any]])
def list_endpoints(
    org_id: str = Query("default"),
    compliance_level: Optional[str] = Query(None, description="compliant/partial/non_compliant"),
    os_type: Optional[str] = Query(None),
    department: Optional[str] = Query(None),
):
    """List endpoints with optional compliance filters."""
    return _get_engine(org_id).list_endpoints(
        org_id,
        compliance_level=compliance_level,
        os_type=os_type,
        department=department,
    )


@router.get("/endpoints/{endpoint_id}", response_model=Dict[str, Any])
def get_endpoint(
    endpoint_id: str,
    org_id: str = Query("default"),
):
    """Return endpoint details with check summary."""
    result = _get_engine(org_id).get_endpoint(org_id, endpoint_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Endpoint not found.")
    return result


@router.post("/endpoints/{endpoint_id}/checks", response_model=Dict[str, Any], status_code=201)
def record_check(
    endpoint_id: str,
    body: CheckCreate,
    org_id: str = Query("default"),
):
    """Record a compliance check result for an endpoint."""
    try:
        return _get_engine(org_id).record_check(org_id, endpoint_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/endpoints/{endpoint_id}/checks/bulk", response_model=List[Dict[str, Any]], status_code=201)
def bulk_record_checks(
    endpoint_id: str,
    body: BulkChecksCreate,
    org_id: str = Query("default"),
):
    """Batch-record compliance checks for an endpoint."""
    checks_data = [c.model_dump() for c in body.checks]
    return _get_engine(org_id).bulk_record_checks(org_id, endpoint_id, checks_data)


@router.get("/checks", response_model=List[Dict[str, Any]])
def list_checks(
    org_id: str = Query("default"),
    endpoint_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    benchmark: Optional[str] = Query(None),
):
    """List compliance checks with optional filters."""
    return _get_engine(org_id).list_checks(
        org_id,
        endpoint_id=endpoint_id,
        status=status,
        severity=severity,
        benchmark=benchmark,
    )


@router.post("/exceptions", response_model=Dict[str, Any], status_code=201)
def add_exception(
    body: ExceptionCreate,
    org_id: str = Query("default"),
):
    """Create a compliance exception for a specific endpoint check."""
    try:
        return _get_engine(org_id).add_exception(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/baselines", response_model=Dict[str, Any], status_code=201)
def create_baseline(
    body: BaselineCreate,
    org_id: str = Query("default"),
):
    """Create a compliance baseline definition."""
    try:
        return _get_engine(org_id).create_baseline(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/baselines", response_model=List[Dict[str, Any]])
def list_baselines(
    org_id: str = Query("default"),
):
    """List all compliance baselines for the org."""
    return _get_engine(org_id).list_baselines(org_id)


@router.get("/stats", response_model=Dict[str, Any])
def get_endpoint_stats(
    org_id: str = Query("default"),
):
    """Return aggregated endpoint compliance statistics."""
    return _get_engine(org_id).get_endpoint_stats(org_id)


@router.get("/department-compliance", response_model=List[Dict[str, Any]])
def get_department_compliance(
    org_id: str = Query("default"),
):
    """Return per-department compliance rates."""
    return _get_engine(org_id).get_department_compliance(org_id)
