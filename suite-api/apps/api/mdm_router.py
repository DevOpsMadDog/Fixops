"""MDM Router — ALDECI.

Endpoints for the Mobile Device Management engine.

Prefix: /api/v1/mdm
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/mdm/devices                              enroll_device
  GET    /api/v1/mdm/devices                              list_devices
  GET    /api/v1/mdm/devices/{device_id}                  get_device
  POST   /api/v1/mdm/devices/{device_id}/compliance-check run_compliance_check
  PUT    /api/v1/mdm/devices/{device_id}/compliance       update_compliance
  POST   /api/v1/mdm/devices/{device_id}/wipe             wipe_device
  GET    /api/v1/mdm/devices/{device_id}/apps             list_device_apps
  POST   /api/v1/mdm/devices/{device_id}/apps             record_app_install
  GET    /api/v1/mdm/policies                             list_policies
  POST   /api/v1/mdm/policies                             create_policy
  GET    /api/v1/mdm/wipe-requests                        list_wipe_requests
  GET    /api/v1/mdm/stats                                get_mdm_stats
"""

from __future__ import annotations

import logging
from typing import List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/mdm",
    tags=["MDM Engine"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.mdm_engine import MDMEngine
        _engine = MDMEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class DeviceEnroll(BaseModel):
    device_name: str = ""
    platform: str = "ios"
    model: str = ""
    serial_number: str = ""
    owner_email: str = ""
    enrollment_type: str = "corporate"
    os_version: str = ""


class ComplianceUpdate(BaseModel):
    status: str
    issues: List[str] = Field(default_factory=list)


class WipeRequest(BaseModel):
    wiped_by: str
    wipe_type: str = "full"


class AppInstall(BaseModel):
    app_name: str
    app_version: str = ""
    is_approved: bool = True


class PolicyRequirements(BaseModel):
    min_os_version: str = ""
    require_encryption: bool = True
    require_passcode: bool = True
    allowed_apps: List[str] = Field(default_factory=list)


class PolicyCreate(BaseModel):
    name: str
    platform: str = "ios"
    requirements: PolicyRequirements = Field(default_factory=PolicyRequirements)


# ---------------------------------------------------------------------------
# Device routes
# ---------------------------------------------------------------------------

@router.post("/devices", dependencies=[Depends(api_key_auth)], status_code=201)
def enroll_device(body: DeviceEnroll, org_id: str = Query(default="default")):
    """Enroll a new mobile device into MDM."""
    try:
        return _get_engine().enroll_device(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/devices", dependencies=[Depends(api_key_auth)])
def list_devices(
     org_id: str = Query(default="default"),
    platform: Optional[str] = Query(None),
    compliance_status: Optional[str] = Query(None),
):
    """List enrolled devices, optionally filtered by platform and/or compliance_status.

    Falls back to live Microsoft Intune and/or Jamf Pro sync when the org
    has no enrolled devices AND the corresponding env vars are set
    (``INTUNE_TENANT_ID`` / ``JAMF_BASE_URL``). Returns
    ``{devices, total, source, hint?, intune_synced?, jamf_synced?}``.
    """
    return _get_engine().list_devices_with_mdm_fallback(
        org_id, platform=platform, compliance_status=compliance_status
    )


@router.get("/devices/{device_id}", dependencies=[Depends(api_key_auth)])
def get_device(device_id: str, org_id: str = Query(default="default")):
    """Get a single device by ID."""
    device = _get_engine().get_device(org_id, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


@router.post("/devices/{device_id}/compliance-check", dependencies=[Depends(api_key_auth)])
def run_compliance_check(device_id: str, org_id: str = Query(default="default")):
    """Run a compliance check on the device and persist the result."""
    try:
        return _get_engine().run_compliance_check(org_id, device_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.put("/devices/{device_id}/compliance", dependencies=[Depends(api_key_auth)])
def update_compliance(device_id: str, body: ComplianceUpdate, org_id: str = Query(default="default")):
    """Manually update device compliance status and issues."""
    try:
        updated = _get_engine().update_compliance(
            org_id, device_id, body.status, body.issues
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not updated:
        raise HTTPException(status_code=404, detail="Device not found")
    return {"updated": True, "device_id": device_id, "status": body.status}


@router.post("/devices/{device_id}/wipe", dependencies=[Depends(api_key_auth)], status_code=201)
def wipe_device(device_id: str, body: WipeRequest, org_id: str = Query(default="default")):
    """Queue a remote wipe request for the device."""
    try:
        return _get_engine().wipe_device(org_id, device_id, body.wiped_by, body.wipe_type)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/devices/{device_id}/apps", dependencies=[Depends(api_key_auth)])
def list_device_apps(device_id: str, org_id: str = Query(default="default")):
    """List all apps recorded on a device."""
    return _get_engine().list_device_apps(org_id, device_id)


@router.post("/devices/{device_id}/apps", dependencies=[Depends(api_key_auth)], status_code=201)
def record_app_install(device_id: str, body: AppInstall, org_id: str = Query(default="default")):
    """Record an app installation on a device."""
    return _get_engine().record_app_install(
        org_id, device_id, body.app_name, body.app_version, body.is_approved
    )


# ---------------------------------------------------------------------------
# Policy routes
# ---------------------------------------------------------------------------

@router.get("/policies", dependencies=[Depends(api_key_auth)])
def list_policies(
     org_id: str = Query(default="default"),
    platform: Optional[str] = Query(None),
):
    """List MDM policies, optionally filtered by platform."""
    return _get_engine().list_policies(org_id, platform=platform)


@router.post("/policies", dependencies=[Depends(api_key_auth)], status_code=201)
def create_policy(body: PolicyCreate, org_id: str = Query(default="default")):
    """Create a new MDM policy."""
    try:
        data = body.model_dump()
        return _get_engine().create_policy(org_id, data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Wipe requests
# ---------------------------------------------------------------------------

@router.get("/wipe-requests", dependencies=[Depends(api_key_auth)])
def list_wipe_requests(org_id: str = Query(default="default")):
    """List all pending and completed wipe requests for the org."""
    return _get_engine().list_wipe_requests(org_id)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_mdm_stats(org_id: str = Query(default="default")):
    """Return aggregated MDM statistics for the org."""
    return _get_engine().get_mdm_stats(org_id)
