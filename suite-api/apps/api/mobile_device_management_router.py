"""Mobile Device Management (MDM) API endpoints — ALDECI.

6 endpoints covering device enrollment, listing, compliance updates,
remote wipe, and compliance summary.

Protected via api_key_auth dependency.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from core.mobile_device_management_engine import MobileDeviceManagementEngine
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/api/v1/mdm",
    tags=["mdm"],
    dependencies=[Depends(api_key_auth)],
)

_engine: Optional[MobileDeviceManagementEngine] = None


def _get_engine() -> MobileDeviceManagementEngine:
    global _engine
    if _engine is None:
        _engine = MobileDeviceManagementEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class EnrollDeviceRequest(BaseModel):
    org_id: str = Field("default", description="Organisation identifier")
    name: str = Field(..., min_length=1, description="Device display name")
    platform: str = Field(..., description="Device platform: ios/android/windows/macos")
    serial_number: str = Field("", description="Device serial number")
    os_version: str = Field("", description="Operating system version")


class UpdateComplianceRequest(BaseModel):
    org_id: str = Field("default", description="Organisation identifier")
    compliance_score: int = Field(..., ge=0, le=100, description="Compliance score 0-100")
    issues: List[str] = Field(default_factory=list, description="List of compliance issues")


class WipeDeviceRequest(BaseModel):
    org_id: str = Field("default", description="Organisation identifier")
    reason: str = Field(..., min_length=1, description="Reason for remote wipe")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/devices", status_code=201)
async def enroll_device(body: EnrollDeviceRequest) -> Dict[str, Any]:
    """Enroll a new device into MDM."""
    try:
        return _get_engine().enroll_device(body.org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/devices")
async def list_devices(
    org_id: str = Query("default", description="Organisation identifier"),
    platform: Optional[str] = Query(None, description="Filter by platform"),
    status: Optional[str] = Query(None, description="Filter by status"),
) -> List[Dict[str, Any]]:
    """List enrolled devices with optional filters."""
    return _get_engine().list_devices(org_id, platform=platform, status=status)


@router.get("/devices/{device_id}")
async def get_device(
    device_id: str,
    org_id: str = Query("default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """Get a single device by ID."""
    try:
        return _get_engine().get_device(org_id, device_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.put("/devices/{device_id}/compliance")
async def update_compliance(
    device_id: str,
    body: UpdateComplianceRequest,
) -> Dict[str, Any]:
    """Update compliance score and issues for a device."""
    try:
        return _get_engine().update_compliance(
            body.org_id, device_id, body.compliance_score, body.issues
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/devices/{device_id}/wipe")
async def wipe_device(
    device_id: str,
    body: WipeDeviceRequest,
) -> Dict[str, Any]:
    """Initiate a remote wipe for a device."""
    try:
        return _get_engine().wipe_device(body.org_id, device_id, body.reason)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/summary")
async def get_compliance_summary(
    org_id: str = Query("default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """Get compliance summary: totals by platform and status, average score."""
    return _get_engine().get_compliance_summary(org_id)
