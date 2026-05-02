"""Mobile Security Router — ALDECI.

Exposes the MobileSecurityEngine via REST API.

Compliance: CIS Controls v8 4.1, NIST SP 800-124r2, OWASP Mobile Top 10
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from core.mobile_security_engine import MobileSecurityEngine
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/mobile-security", tags=["mobile-security"])

# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_engine: Optional[MobileSecurityEngine] = None


def get_mobile_security_engine() -> MobileSecurityEngine:
    global _engine
    if _engine is None:
        _engine = MobileSecurityEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class DeviceBody(BaseModel):
    device_name: str = "Unknown Device"
    platform: str = "android"
    os_version: str = ""
    enrollment_status: str = "pending"
    compliance_status: str = "unknown"
    risk_score: int = 0
    jailbroken: bool = False
    last_checkin: Optional[str] = None


class DeviceComplianceBody(BaseModel):
    compliance_status: Optional[str] = None
    risk_score: Optional[int] = None
    jailbroken: Optional[bool] = None
    os_version: Optional[str] = None
    enrollment_status: Optional[str] = None
    last_checkin: Optional[str] = None


class ThreatBody(BaseModel):
    device_id: str
    threat_type: str = "malware"
    severity: str = "medium"
    description: str = ""
    status: str = "active"


class MDMPolicyBody(BaseModel):
    name: str = "Default MDM Policy"
    require_encryption: bool = True
    require_pin: bool = True
    min_os_version: str = ""
    allow_jailbroken: bool = False
    remote_wipe_enabled: bool = False


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------


@router.get("/devices")
def list_devices(
    org_id: str = Query(..., description="Organisation identifier"),
    platform: Optional[str] = Query(None, description="Filter by platform (ios/android/windows_phone)"),
    compliance_status: Optional[str] = Query(None, description="Filter by compliance status"),
    engine: MobileSecurityEngine = Depends(get_mobile_security_engine),
    _: str = Depends(api_key_auth),
) -> Dict[str, Any]:
    """List mobile devices for an org."""
    devices = engine.list_devices(org_id, platform=platform, compliance_status=compliance_status)
    return {"org_id": org_id, "count": len(devices), "devices": devices}


@router.post("/devices", status_code=201)
def register_device(
    body: DeviceBody,
    org_id: str = Query(..., description="Organisation identifier"),
    engine: MobileSecurityEngine = Depends(get_mobile_security_engine),
    _: str = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Register a mobile device."""
    device = engine.register_device(org_id, body.model_dump(exclude_none=True))
    return device


@router.patch("/devices/{device_id}/compliance")
def update_device_compliance(
    device_id: str,
    body: DeviceComplianceBody,
    org_id: str = Query(..., description="Organisation identifier"),
    engine: MobileSecurityEngine = Depends(get_mobile_security_engine),
    _: str = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Update compliance-related fields on a device."""
    updated = engine.update_device_compliance(
        org_id, device_id, body.model_dump(exclude_none=True)
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Device not found or no valid fields provided")
    return {"device_id": device_id, "updated": True}


# ---------------------------------------------------------------------------
# Threats
# ---------------------------------------------------------------------------


@router.get("/threats")
def list_threats(
    org_id: str = Query(..., description="Organisation identifier"),
    severity: Optional[str] = Query(None, description="Filter by severity (critical/high/medium/low/info)"),
    engine: MobileSecurityEngine = Depends(get_mobile_security_engine),
    _: str = Depends(api_key_auth),
) -> Dict[str, Any]:
    """List mobile threats for an org."""
    threats = engine.list_threats(org_id, severity=severity)
    return {"org_id": org_id, "count": len(threats), "threats": threats}


@router.post("/threats", status_code=201)
def create_threat(
    body: ThreatBody,
    org_id: str = Query(..., description="Organisation identifier"),
    engine: MobileSecurityEngine = Depends(get_mobile_security_engine),
    _: str = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Record a mobile threat."""
    threat = engine.create_threat(org_id, body.model_dump())
    return threat


# ---------------------------------------------------------------------------
# MDM Policies
# ---------------------------------------------------------------------------


@router.get("/policies")
def list_mdm_policies(
    org_id: str = Query(..., description="Organisation identifier"),
    engine: MobileSecurityEngine = Depends(get_mobile_security_engine),
    _: str = Depends(api_key_auth),
) -> Dict[str, Any]:
    """List MDM policies for an org."""
    policies = engine.list_mdm_policies(org_id)
    return {"org_id": org_id, "count": len(policies), "policies": policies}


@router.post("/policies", status_code=201)
def create_mdm_policy(
    body: MDMPolicyBody,
    org_id: str = Query(..., description="Organisation identifier"),
    engine: MobileSecurityEngine = Depends(get_mobile_security_engine),
    _: str = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Create an MDM policy."""
    policy = engine.create_mdm_policy(org_id, body.model_dump())
    return policy


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


@router.get("/stats")
def get_stats(
    org_id: str = Query(..., description="Organisation identifier"),
    engine: MobileSecurityEngine = Depends(get_mobile_security_engine),
    _: str = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Return mobile security statistics for an org."""
    return engine.get_mobile_stats(org_id)
