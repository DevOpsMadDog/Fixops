"""
Cloud Workload Protection Platform Router — ALDECI.

8 endpoints for the CWPP engine:
  POST   /api/v1/cwpp/workloads                         register_workload
  DELETE /api/v1/cwpp/workloads/{workload_id}           deregister_workload
  GET    /api/v1/cwpp/workloads                         list_workloads
  GET    /api/v1/cwpp/workloads/{workload_id}           get_workload
  POST   /api/v1/cwpp/workloads/{workload_id}/detect    detect_threats
  POST   /api/v1/cwpp/workloads/{workload_id}/compliance check_compliance
  GET    /api/v1/cwpp/threats                           get_threat_events
  GET    /api/v1/cwpp/summary                           protection_summary
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

try:
    from apps.api.auth_deps import api_key_auth as _api_key_auth
    _AUTH_DEP: list = [Depends(_api_key_auth)]
except ImportError:
    logging.getLogger(__name__).warning(
        "cwpp_router: auth_deps not available, relying on app.py mount-level auth"
    )
    _AUTH_DEP = []

from core.cwpp_engine import (
    COMPLIANCE_FRAMEWORKS,
    WORKLOAD_TYPES,
    CWPPEngine,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/cwpp",
    tags=["cwpp"],
    dependencies=_AUTH_DEP,
)

# Shared engine instance (file-backed, shared across requests)
_engine: Optional[CWPPEngine] = None


def _get_engine() -> CWPPEngine:
    global _engine
    if _engine is None:
        _engine = CWPPEngine()
    return _engine


# ============================================================================
# Request / Response models
# ============================================================================


class RegisterWorkloadRequest(BaseModel):
    workload_id: str = Field(..., description="Unique workload identifier")
    workload_type: str = Field(..., description=f"One of: {WORKLOAD_TYPES}")
    name: str = Field(..., description="Human-readable workload name")
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Optional metadata: image, namespace, node, labels, cloud_account",
    )
    org_id: str = Field("default", description="Organisation ID")


class DetectThreatsRequest(BaseModel):
    events: List[Dict[str, Any]] = Field(
        ...,
        description='List of runtime events: [{"event_type": "process_exec"|"network_conn"|"file_write", "details": {...}}]',
    )


class ComplianceCheckRequest(BaseModel):
    framework: str = Field(
        "cis_docker",
        description=f"Compliance framework. One of: {COMPLIANCE_FRAMEWORKS}",
    )


# ============================================================================
# Endpoints
# ============================================================================


@router.post("/workloads", summary="Register a workload for protection")
def register_workload(body: RegisterWorkloadRequest) -> Dict[str, Any]:
    engine = _get_engine()
    try:
        return engine.register_workload(
            workload_id=body.workload_id,
            workload_type=body.workload_type,
            name=body.name,
            metadata=body.metadata,
            org_id=body.org_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.delete("/workloads/{workload_id}", summary="Deregister a workload")
def deregister_workload(workload_id: str) -> Dict[str, Any]:
    engine = _get_engine()
    found = engine.deregister_workload(workload_id)
    if not found:
        raise HTTPException(status_code=404, detail=f"Workload '{workload_id}' not found")
    return {"workload_id": workload_id, "status": "deregistered"}


@router.get("/workloads", summary="List workloads")
def list_workloads(
    org_id: str = Query("default", description="Organisation ID"),
    workload_type: Optional[str] = Query(None, description="Filter by workload type"),
) -> Dict[str, Any]:
    rows = _get_engine().list_workloads(org_id=org_id, workload_type=workload_type)
    if not rows:
        return {
            "workloads": [],
            "total": 0,
            "hint": "Workload protection requires container runtime telemetry or a Kubernetes adapter. Register a workload manually via POST /api/v1/cwpp/workloads once a k8s connector is bound to this tenant.",
        }
    return {"workloads": rows, "total": len(rows)}


@router.get("/workloads/{workload_id}", summary="Get a specific workload")
def get_workload(workload_id: str) -> Dict[str, Any]:
    result = _get_engine().get_workload(workload_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Workload '{workload_id}' not found")
    return result


@router.post("/workloads/{workload_id}/detect", summary="Detect threats from runtime events")
def detect_threats(workload_id: str, body: DetectThreatsRequest) -> Dict[str, Any]:
    engine = _get_engine()
    workload = engine.get_workload(workload_id)
    if workload is None:
        raise HTTPException(status_code=404, detail=f"Workload '{workload_id}' not found")
    threats = engine.detect_threats(workload_id=workload_id, events=body.events)
    return {"workload_id": workload_id, "threats_detected": len(threats), "threats": threats}


@router.post("/workloads/{workload_id}/compliance", summary="Check workload compliance")
def check_compliance(workload_id: str, body: ComplianceCheckRequest) -> Dict[str, Any]:
    engine = _get_engine()
    workload = engine.get_workload(workload_id)
    if workload is None:
        raise HTTPException(status_code=404, detail=f"Workload '{workload_id}' not found")
    try:
        return engine.check_compliance(workload_id=workload_id, framework=body.framework)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/threats", summary="Get threat events")
def get_threat_events(
    org_id: str = Query("default", description="Organisation ID"),
    workload_id: Optional[str] = Query(None, description="Filter by workload ID"),
) -> List[Dict[str, Any]]:
    return _get_engine().get_threat_events(workload_id=workload_id, org_id=org_id)


@router.get("/summary", summary="Protection summary for an org")
def protection_summary(
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    return _get_engine().get_protection_summary(org_id=org_id)
