"""Cloud Workload Protection Router — REST endpoints for ALDECI.

Prefix: /api/v1/cwp
Auth: api_key_auth dependency

Routes:
  POST   /workloads                        register_workload
  GET    /workloads                        list_workloads
  GET    /workloads/{id}                   get_workload
  PUT    /workloads/{id}/protection        update_protection_status
  POST   /threats                          record_threat
  GET    /threats                          list_threats
  PUT    /threats/{id}/status              update_threat_status
  POST   /policies                         create_policy
  GET    /policies                         list_policies
  GET    /stats                            get_cwp_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/cwp",
    tags=["Cloud Workload Protection"],
    dependencies=[Depends(api_key_auth)],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.cloud_workload_protection_engine import CloudWorkloadProtectionEngine
        _engine = CloudWorkloadProtectionEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class WorkloadCreateReq(BaseModel):
    org_id: str
    workload_name: str
    workload_type: str = "vm"
    cloud_provider: str = "aws"
    region: Optional[str] = None
    account_id: Optional[str] = None
    risk_score: float = 50.0
    risk_level: str = "medium"
    last_assessed: Optional[str] = None


class WorkloadProtectionReq(BaseModel):
    org_id: str
    protection_status: str


class ThreatCreateReq(BaseModel):
    org_id: str
    workload_id: str
    threat_type: str
    severity: str = "medium"
    detection_source: str = "runtime"
    detected_at: Optional[str] = None


class ThreatStatusReq(BaseModel):
    org_id: str
    status: str


class PolicyCreateReq(BaseModel):
    org_id: str
    policy_name: str
    workload_types: List[str] = Field(default_factory=list)
    controls: List[str] = Field(default_factory=list)
    enforcement: str = "alert"
    enabled: bool = True


# ---------------------------------------------------------------------------
# Workload endpoints
# ---------------------------------------------------------------------------


@router.post("/workloads", status_code=201)
def register_workload(body: WorkloadCreateReq) -> Dict[str, Any]:
    try:
        data = body.model_dump()
        org_id = data.pop("org_id")
        return _get_engine().register_workload(org_id, data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        _logger.error("cwp.register_workload error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/workloads")
def list_workloads(
     org_id: str = Query(default="default"),
    workload_type: Optional[str] = Query(None),
    cloud_provider: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """List CWP workloads with optional filters.

    Falls back to live ``ContainerSecurityConnector`` scan history (trivy +
    grype + dockle on tenant images) when the org has no registered
    workloads. Returns ``{workloads, total, source, hint?, scans_seen?}``.
    """
    try:
        return _get_engine().list_workloads_with_container_fallback(
            org_id,
            workload_type=workload_type,
            cloud_provider=cloud_provider,
            risk_level=risk_level,
        )
    except Exception as exc:
        _logger.error("cwp.list_workloads error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/workloads/{workload_id}")
def get_workload(
    workload_id: str,
     org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    result = _get_engine().get_workload(org_id, workload_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Workload {workload_id} not found")
    return result


@router.put("/workloads/{workload_id}/protection")
def update_protection_status(
    workload_id: str,
    body: WorkloadProtectionReq,
) -> Dict[str, Any]:
    try:
        return _get_engine().update_protection_status(
            body.org_id, workload_id, body.protection_status
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        _logger.error("cwp.update_protection error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Threat endpoints
# ---------------------------------------------------------------------------


@router.post("/threats", status_code=201)
def record_threat(body: ThreatCreateReq) -> Dict[str, Any]:
    try:
        data = body.model_dump()
        org_id = data.pop("org_id")
        return _get_engine().record_threat(org_id, data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        _logger.error("cwp.record_threat error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/threats")
def list_threats(
     org_id: str = Query(default="default"),
    workload_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    try:
        return _get_engine().list_threats(
            org_id, workload_id=workload_id, severity=severity, status=status
        )
    except Exception as exc:
        _logger.error("cwp.list_threats error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.put("/threats/{threat_id}/status")
def update_threat_status(
    threat_id: str,
    body: ThreatStatusReq,
) -> Dict[str, Any]:
    try:
        return _get_engine().update_threat_status(body.org_id, threat_id, body.status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        _logger.error("cwp.update_threat_status error: %s", exc)
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
        _logger.error("cwp.create_policy error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/policies")
def list_policies(
     org_id: str = Query(default="default"),
    enabled: Optional[bool] = Query(None),
) -> List[Dict[str, Any]]:
    try:
        return _get_engine().list_policies(org_id, enabled=enabled)
    except Exception as exc:
        _logger.error("cwp.list_policies error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Stats endpoint
# ---------------------------------------------------------------------------


@router.get("/stats")
def get_cwp_stats(org_id: str = Query(default="default")) -> Dict[str, Any]:
    try:
        return _get_engine().get_cwp_stats(org_id)
    except Exception as exc:
        _logger.error("cwp.stats error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))
