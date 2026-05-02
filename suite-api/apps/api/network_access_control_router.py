"""Network Access Control Router — ALDECI.

Endpoint enrollment, posture assessment, NAC status, and policy management.

Prefix: /api/v1/nac
Auth: api_key_auth dependency

Routes:
  POST  /api/v1/nac/endpoints                             register_endpoint
  GET   /api/v1/nac/endpoints                             list_endpoints
  GET   /api/v1/nac/endpoints/{endpoint_id}               get_endpoint
  POST  /api/v1/nac/endpoints/{endpoint_id}/assess-posture assess_posture
  PUT   /api/v1/nac/endpoints/{endpoint_id}/nac-status    update_nac_status
  POST  /api/v1/nac/policies                              create_nac_policy
  GET   /api/v1/nac/policies                              list_nac_policies
  GET   /api/v1/nac/stats                                 get_nac_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/nac",
    tags=["Network Access Control"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.network_access_control_engine import NetworkAccessControlEngine
        _engine = NetworkAccessControlEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class RegisterEndpointRequest(BaseModel):
    org_id: str = Field(default="default")
    name: str = Field(..., description="Endpoint name")
    mac_address: str = Field(..., description="MAC address (required)")
    ip_address: Optional[str] = Field(default=None)
    device_type: str = Field(default="workstation", description="workstation/laptop/server/mobile/iot/printer/other")


class AssessPostureRequest(BaseModel):
    org_id: str = Field(default="default")
    antivirus: bool = Field(default=False)
    firewall: bool = Field(default=False)
    os_patched: bool = Field(default=False)
    disk_encrypted: bool = Field(default=False)
    compliant_software: bool = Field(default=False)


class UpdateNacStatusRequest(BaseModel):
    org_id: str = Field(default="default")
    nac_status: str = Field(..., description="allowed/restricted/quarantined/blocked")
    reason: str = Field(default="")


class CreatePolicyRequest(BaseModel):
    org_id: str = Field(default="default")
    name: str = Field(..., description="Policy name")
    required_posture_score: int = Field(default=80, ge=0, le=100)
    action: str = Field(default="allow", description="allow/restrict/quarantine/block")
    applies_to: str = Field(default="all", description="all/workstation/laptop/server/mobile/iot")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/", dependencies=[Depends(api_key_auth)])
def get_nac_summary(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """5-state envelope summarising NAC posture for the org.

    States: ok | warning | critical | empty | error
    Calls the real engine — no mocks.
    """
    try:
        stats = _get_engine().get_nac_stats(org_id)
        total = stats.get("total_endpoints", 0)
        blocked = stats.get("blocked", 0)
        quarantined = stats.get("quarantined", 0)

        if total == 0:
            state = "empty"
            message = "No endpoints enrolled. Register endpoints via POST /endpoints."
        elif blocked > 0 or quarantined > 0:
            state = "critical" if blocked > 0 else "warning"
            message = f"{blocked} blocked, {quarantined} quarantined out of {total} endpoint(s)."
        else:
            state = "ok"
            message = f"{total} endpoint(s) enrolled, none blocked or quarantined."

        return {
            "state": state,
            "message": message,
            "org_id": org_id,
            "stats": stats,
            "links": {
                "endpoints": "/api/v1/nac/endpoints",
                "policies": "/api/v1/nac/policies",
                "stats": "/api/v1/nac/stats",
            },
        }
    except Exception as exc:
        _logger.exception("nac_summary_failed")
        return {
            "state": "error",
            "message": str(exc),
            "org_id": org_id,
            "stats": {},
            "links": {},
        }


@router.post("/endpoints", dependencies=[Depends(api_key_auth)])
def register_endpoint(req: RegisterEndpointRequest) -> Dict[str, Any]:
    """Register a new network endpoint."""
    try:
        return _get_engine().register_endpoint(req.org_id, req.model_dump(exclude={"org_id"}))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        _logger.exception("register_endpoint failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/endpoints", dependencies=[Depends(api_key_auth)])
def list_endpoints(
    org_id: str = Query(default="default"),
    device_type: Optional[str] = Query(default=None),
    nac_status: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List network endpoints."""
    try:
        return _get_engine().list_endpoints(org_id, device_type=device_type, nac_status=nac_status)
    except Exception as exc:
        _logger.exception("list_endpoints failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/endpoints/{endpoint_id}", dependencies=[Depends(api_key_auth)])
def get_endpoint(endpoint_id: str, org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Get a single endpoint by ID."""
    try:
        return _get_engine().get_endpoint(org_id, endpoint_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        _logger.exception("get_endpoint failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/endpoints/{endpoint_id}/assess-posture", dependencies=[Depends(api_key_auth)])
def assess_posture(endpoint_id: str, req: AssessPostureRequest) -> Dict[str, Any]:
    """Assess endpoint posture from 5 boolean checks."""
    try:
        posture_data = req.model_dump(exclude={"org_id"})
        return _get_engine().assess_posture(req.org_id, endpoint_id, posture_data)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        _logger.exception("assess_posture failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.put("/endpoints/{endpoint_id}/nac-status", dependencies=[Depends(api_key_auth)])
def update_nac_status(endpoint_id: str, req: UpdateNacStatusRequest) -> Dict[str, Any]:
    """Manually update NAC status for an endpoint."""
    try:
        return _get_engine().update_nac_status(req.org_id, endpoint_id, req.nac_status, req.reason)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        _logger.exception("update_nac_status failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/policies", dependencies=[Depends(api_key_auth)])
def create_nac_policy(req: CreatePolicyRequest) -> Dict[str, Any]:
    """Create a NAC policy."""
    try:
        return _get_engine().create_nac_policy(req.org_id, req.model_dump(exclude={"org_id"}))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        _logger.exception("create_nac_policy failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/policies", dependencies=[Depends(api_key_auth)])
def list_nac_policies(org_id: str = Query(default="default")) -> List[Dict[str, Any]]:
    """List all NAC policies for org."""
    try:
        return _get_engine().list_nac_policies(org_id)
    except Exception as exc:
        _logger.exception("list_nac_policies failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_nac_stats(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Get NAC stats for org."""
    try:
        return _get_engine().get_nac_stats(org_id)
    except Exception as exc:
        _logger.exception("get_nac_stats failed")
        raise HTTPException(status_code=500, detail=str(exc))
