"""Supply Chain Attack Detection Router — REST endpoints for ALDECI.

Prefix: /api/v1/supply-chain-attacks
Auth: api_key_auth dependency

Routes:
  POST   /packages                         register_package
  GET    /packages                         list_packages
  GET    /packages/{id}                    get_package
  PUT    /packages/{id}/status             update_package_status
  POST   /detections                       record_detection
  GET    /detections                       list_detections
  PUT    /detections/{id}/confirm          confirm_detection
  POST   /policies                         create_policy
  GET    /policies                         list_policies
  GET    /stats                            get_attack_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/supply-chain-attacks",
    tags=["Supply Chain Attack Detection"],
    dependencies=[Depends(api_key_auth)],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.supply_chain_attack_detection_engine import (
            SupplyChainAttackDetectionEngine,
        )
        _engine = SupplyChainAttackDetectionEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class PackageCreateReq(BaseModel):
    org_id: str
    package_name: str
    ecosystem: str = "npm"
    version: Optional[str] = None
    source_url: Optional[str] = None
    risk_score: float = 0.0
    attack_type: str = "none"
    last_scanned: Optional[str] = None


class PackageStatusReq(BaseModel):
    org_id: str
    status: str
    attack_type: Optional[str] = None


class DetectionCreateReq(BaseModel):
    org_id: str
    package_id: str
    detection_type: str
    confidence_score: float = 0.0
    evidence: Optional[str] = None
    severity: str = "medium"
    detected_at: Optional[str] = None


class DetectionConfirmReq(BaseModel):
    org_id: str
    confirmed_status: str


class PolicyCreateReq(BaseModel):
    org_id: str
    policy_name: str
    ecosystems: List[str] = Field(default_factory=list)
    action: str = "alert"
    min_confidence: float = 70.0
    enabled: bool = True


# ---------------------------------------------------------------------------
# Package endpoints
# ---------------------------------------------------------------------------


@router.post("/packages", status_code=201)
def register_package(body: PackageCreateReq) -> Dict[str, Any]:
    try:
        data = body.model_dump()
        org_id = data.pop("org_id")
        return _get_engine().register_package(org_id, data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        _logger.error("scad.register_package error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/packages")
def list_packages(
     org_id: str = Query(default="default"),
    ecosystem: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    try:
        return _get_engine().list_packages(org_id, ecosystem=ecosystem, status=status)
    except Exception as exc:
        _logger.error("scad.list_packages error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/packages/{package_id}")
def get_package(
    package_id: str,
     org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    result = _get_engine().get_package(org_id, package_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Package {package_id} not found")
    return result


@router.put("/packages/{package_id}/status")
def update_package_status(
    package_id: str,
    body: PackageStatusReq,
) -> Dict[str, Any]:
    try:
        return _get_engine().update_package_status(
            body.org_id, package_id, body.status, attack_type=body.attack_type
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        _logger.error("scad.update_package_status error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Detection endpoints
# ---------------------------------------------------------------------------


@router.post("/detections", status_code=201)
def record_detection(body: DetectionCreateReq) -> Dict[str, Any]:
    try:
        data = body.model_dump()
        org_id = data.pop("org_id")
        return _get_engine().record_detection(org_id, data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        _logger.error("scad.record_detection error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/detections")
def list_detections(
     org_id: str = Query(default="default"),
    package_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    try:
        return _get_engine().list_detections(
            org_id, package_id=package_id, severity=severity, status=status
        )
    except Exception as exc:
        _logger.error("scad.list_detections error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.put("/detections/{detection_id}/confirm")
def confirm_detection(
    detection_id: str,
    body: DetectionConfirmReq,
) -> Dict[str, Any]:
    try:
        return _get_engine().confirm_detection(body.org_id, detection_id, body.confirmed_status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        _logger.error("scad.confirm_detection error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Policy endpoints
# ---------------------------------------------------------------------------


@router.post("/policies", status_code=201)
def create_policy(body: PolicyCreateReq) -> Dict[str, Any]:
    try:
        data = body.model_dump()
        org_id = data.pop("org_id")
        return _get_engine().create_policy(org_id, data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        _logger.error("scad.create_policy error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/policies")
def list_policies(
     org_id: str = Query(default="default"),
    enabled: Optional[bool] = Query(None),
) -> List[Dict[str, Any]]:
    try:
        return _get_engine().list_policies(org_id, enabled=enabled)
    except Exception as exc:
        _logger.error("scad.list_policies error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Stats endpoint
# ---------------------------------------------------------------------------


@router.get("/stats")
def get_attack_stats(org_id: str = Query(default="default")) -> Dict[str, Any]:
    try:
        return _get_engine().get_attack_stats(org_id)
    except Exception as exc:
        _logger.error("scad.stats error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))
