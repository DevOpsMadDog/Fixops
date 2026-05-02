"""Compliance Scanner Router — ALDECI.

REST API for automated compliance scanning across SOC2, ISO 27001, NIST CSF,
PCI DSS, HIPAA, GDPR, and CIS frameworks.

Prefix: /api/v1/compliance-scanner
"""

from __future__ import annotations

import logging
from typing import List, Optional

from apps.api.auth_deps import api_key_auth
from core.compliance_scanner_engine import ComplianceScannerEngine
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

_SIMULATION_WARNING = {
    "is_simulated": True,
    "engine": "compliance_scanner_engine",
    "real_integration_required": "/api/v1/connectors/compliance/configure",
    "do_not_use_in_demo": True,
}

router = APIRouter(
    prefix="/api/v1/compliance-scanner",
    tags=["Compliance Scanner"],
    dependencies=[Depends(api_key_auth)],
)

_engine = None  # lazy-initialised on first request


def _get_engine():
    global _engine
    if _engine is None:
        _engine = ComplianceScannerEngine()
    return _engine


# ------------------------------------------------------------------
# Request / Response models
# ------------------------------------------------------------------


class CreateProfileRequest(BaseModel):
    name: str
    frameworks: List[str] = Field(default_factory=lambda: ["SOC2"])
    scan_frequency_hours: int = 24


class CreateTaskRequest(BaseModel):
    title: str
    description: str = ""
    priority: str = "medium"
    assigned_to: str = ""
    due_date: str = ""


class UpdateTaskStatusRequest(BaseModel):
    status: str
    resolved_by: Optional[str] = None


# ------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------


@router.get("/", summary="Compliance scanner summary")
def get_scanner_summary(org_id: str = Query(..., description="Organization identifier")) -> dict:
    """Return compliance scanner stats: profiles, results, checks, and task counts for an org."""
    try:
        return _get_engine().get_compliance_stats(org_id)
    except Exception as exc:
        _logger.exception("compliance_scanner GET / failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ------------------------------------------------------------------
# Scan Profiles
# ------------------------------------------------------------------


@router.post("/profiles")
def create_profile(org_id: str, req: CreateProfileRequest) -> dict:
    """Create a new compliance scan profile."""
    return _get_engine().create_profile(org_id, req.model_dump())


@router.get("/profiles")
def list_profiles(org_id: str) -> list:
    """List all scan profiles for an org."""
    return _get_engine().list_profiles(org_id)


@router.get("/profiles/{profile_id}")
def get_profile(org_id: str, profile_id: str) -> dict:
    """Get a specific scan profile."""
    profile = _get_engine().get_profile(org_id, profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return profile


# ------------------------------------------------------------------
# Scans
# ------------------------------------------------------------------


@router.post("/profiles/{profile_id}/scan")
def start_scan(org_id: str, profile_id: str) -> dict:
    """Trigger a compliance scan for a profile."""
    try:
        result = _get_engine().start_scan(org_id, profile_id)
        return {"data": result, "_simulation_warning": _SIMULATION_WARNING}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/results")
def list_scan_results(
    org_id: str,
    profile_id: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=100),
) -> list:
    """List scan results for an org, most recent first."""
    return _get_engine().list_scan_results(org_id, profile_id=profile_id, limit=limit)


@router.get("/results/{result_id}")
def get_scan_result(org_id: str, result_id: str) -> dict:
    """Get a specific scan result."""
    result = _get_engine().get_scan_result(org_id, result_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan result not found")
    return result


# ------------------------------------------------------------------
# Compliance Checks
# ------------------------------------------------------------------


@router.get("/results/{result_id}/checks")
def list_checks(
    org_id: str,
    result_id: str,
    status: Optional[str] = Query(None),
    framework: Optional[str] = Query(None),
) -> list:
    """List compliance checks for a scan result."""
    return _get_engine().list_checks(org_id, result_id, status=status, framework=framework)


# ------------------------------------------------------------------
# Remediation Tasks
# ------------------------------------------------------------------


@router.post("/checks/{check_id}/tasks")
def create_remediation_task(org_id: str, check_id: str, req: CreateTaskRequest) -> dict:
    """Create a remediation task for a failed check."""
    return _get_engine().create_remediation_task(org_id, check_id, req.model_dump())


@router.get("/tasks")
def list_remediation_tasks(
    org_id: str,
    status: Optional[str] = Query(None),
    priority: Optional[str] = Query(None),
) -> list:
    """List remediation tasks for an org."""
    return _get_engine().list_remediation_tasks(org_id, status=status, priority=priority)


@router.patch("/tasks/{task_id}/status")
def update_task_status(org_id: str, task_id: str, req: UpdateTaskStatusRequest) -> dict:
    """Update the status of a remediation task."""
    updated = _get_engine().update_task_status(
        org_id, task_id, req.status, resolved_by=req.resolved_by
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Task not found or invalid status")
    return {"task_id": task_id, "status": req.status, "updated": True}


# ------------------------------------------------------------------
# Stats
# ------------------------------------------------------------------


@router.get("/stats")
def get_compliance_stats(org_id: str) -> dict:
    """Get aggregate compliance statistics for an org."""
    return _get_engine().get_compliance_stats(org_id)


@router.get("/scans")
def list_scans_alias(
    org_id: str,
    profile_id: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=100),
) -> list:
    """Alias for /results — list scan results for an org, most recent first."""
    return _get_engine().list_scan_results(org_id, profile_id=profile_id, limit=limit)


@router.get("/findings")
def list_findings_alias(
    org_id: str,
    status: Optional[str] = Query(None),
    framework: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=100),
) -> list:
    """Alias mapping /findings to scan results with optional status/framework filter."""
    results = _get_engine().list_scan_results(org_id, limit=limit)
    checks: list = []
    for r in results:
        result_id = r.get("result_id") or r.get("id", "")
        if result_id:
            batch = _get_engine().list_checks(org_id, result_id, status=status, framework=framework)
            checks.extend(batch)
    return checks
