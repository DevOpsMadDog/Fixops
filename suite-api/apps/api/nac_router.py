"""NAC Router — Network Access Control API for ALDECI.

Prefix: /api/v1/nac
Auth: api_key_auth dependency

Routes:
  GET    /api/v1/nac/devices                              list_devices
  POST   /api/v1/nac/devices                              register_device
  GET    /api/v1/nac/devices/{device_id}                  get_device
  POST   /api/v1/nac/devices/{device_id}/posture-check    run_posture_check
  PUT    /api/v1/nac/devices/{device_id}/status           update_device_status
  POST   /api/v1/nac/devices/{device_id}/apply-policy     apply_policy
  GET    /api/v1/nac/policies                             list_policies
  POST   /api/v1/nac/policies                             create_policy
  GET    /api/v1/nac/events                               list_access_events
  POST   /api/v1/nac/events                               record_access_event
  GET    /api/v1/nac/stats                                get_nac_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/nac", tags=["Network Access Control"])

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.nac_engine import NACEngine
        _engine = NACEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models (router-layer thin wrappers)
# ---------------------------------------------------------------------------


class DeviceCreateReq(BaseModel):
    org_id: str
    hostname: str
    device_type: str = "laptop"
    owner: Optional[str] = None
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    os_type: Optional[str] = None


class DeviceStatusReq(BaseModel):
    org_id: str
    status: str
    reason: str
    updated_by: str


class PolicyCreateReq(BaseModel):
    org_id: str
    name: str
    device_types: List[str] = Field(default_factory=list)
    required_checks: List[str] = Field(default_factory=list)
    vlan_on_pass: Optional[str] = None
    vlan_on_fail: Optional[str] = None
    action_on_fail: str = "quarantine"


class ApplyPolicyReq(BaseModel):
    org_id: str
    policy_id: str


class AccessEventReq(BaseModel):
    org_id: str
    device_id: str
    event_type: str
    location: Optional[str] = None
    switch_port: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Device endpoints
# ---------------------------------------------------------------------------


@router.get("/devices")
def list_devices(
     org_id: str = Query(default="default"),
    device_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    _auth=Depends(api_key_auth),
) -> List[Dict[str, Any]]:
    try:
        return _get_engine().list_devices(org_id, device_type=device_type, status=status)
    except Exception as exc:
        _logger.error("nac.list_devices error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/devices", status_code=201)
def register_device(body: DeviceCreateReq, _auth=Depends(api_key_auth)) -> Dict[str, Any]:
    from core.nac_engine import DeviceCreate
    try:
        data = DeviceCreate(
            hostname=body.hostname,
            device_type=body.device_type,
            owner=body.owner,
            ip_address=body.ip_address,
            mac_address=body.mac_address,
            os_type=body.os_type,
        )
        return _get_engine().register_device(body.org_id, data)
    except Exception as exc:
        _logger.error("nac.register_device error: %s", exc)
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/devices/{device_id}")
def get_device(
    device_id: str,
     org_id: str = Query(default="default"),
    _auth=Depends(api_key_auth),
) -> Dict[str, Any]:
    try:
        return _get_engine().get_device(org_id, device_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        _logger.error("nac.get_device error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/devices/{device_id}/posture-check")
def run_posture_check(
    device_id: str,
     org_id: str = Query(default="default"),
    _auth=Depends(api_key_auth),
) -> Dict[str, Any]:
    try:
        return _get_engine().run_posture_check(org_id, device_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        _logger.error("nac.posture_check error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.put("/devices/{device_id}/status")
def update_device_status(
    device_id: str,
    body: DeviceStatusReq,
    _auth=Depends(api_key_auth),
) -> Dict[str, Any]:
    try:
        return _get_engine().update_device_status(
            body.org_id, device_id, body.status, body.reason, body.updated_by
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        _logger.error("nac.update_status error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/devices/{device_id}/apply-policy")
def apply_policy(
    device_id: str,
    body: ApplyPolicyReq,
    _auth=Depends(api_key_auth),
) -> Dict[str, Any]:
    try:
        return _get_engine().apply_policy(body.org_id, device_id, body.policy_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        _logger.error("nac.apply_policy error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Policy endpoints
# ---------------------------------------------------------------------------


@router.get("/policies")
def list_policies(
     org_id: str = Query(default="default"),
    _auth=Depends(api_key_auth),
) -> List[Dict[str, Any]]:
    try:
        return _get_engine().list_policies(org_id)
    except Exception as exc:
        _logger.error("nac.list_policies error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/policies", status_code=201)
def create_policy(body: PolicyCreateReq, _auth=Depends(api_key_auth)) -> Dict[str, Any]:
    from core.nac_engine import PolicyCreate
    try:
        data = PolicyCreate(
            name=body.name,
            device_types=body.device_types,
            required_checks=body.required_checks,
            vlan_on_pass=body.vlan_on_pass,
            vlan_on_fail=body.vlan_on_fail,
            action_on_fail=body.action_on_fail,
        )
        return _get_engine().create_policy(body.org_id, data)
    except Exception as exc:
        _logger.error("nac.create_policy error: %s", exc)
        raise HTTPException(status_code=400, detail=str(exc))


# ---------------------------------------------------------------------------
# Access event endpoints
# ---------------------------------------------------------------------------


@router.get("/events")
def list_access_events(
     org_id: str = Query(default="default"),
    device_id: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    _auth=Depends(api_key_auth),
) -> List[Dict[str, Any]]:
    try:
        return _get_engine().list_access_events(org_id, device_id=device_id, limit=limit)
    except Exception as exc:
        _logger.error("nac.list_events error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/events", status_code=201)
def record_access_event(body: AccessEventReq, _auth=Depends(api_key_auth)) -> Dict[str, Any]:
    from core.nac_engine import AccessEventCreate
    try:
        data = AccessEventCreate(
            device_id=body.device_id,
            event_type=body.event_type,
            location=body.location,
            switch_port=body.switch_port,
            details=body.details,
        )
        return _get_engine().record_access_event(body.org_id, data)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        _logger.error("nac.record_event error: %s", exc)
        raise HTTPException(status_code=400, detail=str(exc))


# ---------------------------------------------------------------------------
# Stats endpoint
# ---------------------------------------------------------------------------


@router.get("/stats")
def get_nac_stats(
     org_id: str = Query(default="default"),
    _auth=Depends(api_key_auth),
) -> Dict[str, Any]:
    try:
        return _get_engine().get_nac_stats(org_id)
    except Exception as exc:
        _logger.error("nac.stats error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))
