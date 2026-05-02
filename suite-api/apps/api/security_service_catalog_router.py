"""Security Service Catalog API Router — ALDECI.

Endpoints (all under /api/v1/service-catalog):

  POST   /services                        — register a service
  POST   /services/{id}/requests          — submit a service request
  PUT    /requests/{id}/acknowledge       — acknowledge request
  PUT    /requests/{id}/resolve           — resolve request
  POST   /services/{id}/outages           — record an outage
  PUT    /outages/{id}/resolve            — resolve an outage
  GET    /summary                         — catalog summary stats
  GET    /services/{id}                   — service detail + requests + outages
  GET    /sla-performance                 — per-service SLA performance
"""
from __future__ import annotations

import logging
from typing import Any, Dict

from apps.api.auth_deps import api_key_auth
from core.security_service_catalog_engine import SecurityServiceCatalogEngine
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/service-catalog",
    tags=["service-catalog"],
    dependencies=[Depends(api_key_auth)],
)

_engine = None  # lazy-initialised on first request


def _get_engine():
    global _engine
    if _engine is None:
        _engine = SecurityServiceCatalogEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class RegisterServiceIn(BaseModel):
    org_id: str
    service_name: str
    service_category: str = "monitoring"
    description: str = ""
    owner_team: str = ""
    sla_response_hours: int = 24
    sla_resolution_hours: int = 72
    cost_center: str = ""
    availability_pct: float = 99.0


class SubmitRequestIn(BaseModel):
    org_id: str
    requester: str
    requester_dept: str = ""
    priority: str = "medium"
    request_details: str = ""


class RecordOutageIn(BaseModel):
    org_id: str
    outage_type: str = "unplanned"
    severity: str = "medium"
    started_at: str
    affected_users: int = 0
    root_cause: str = ""


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/services", status_code=201)
async def register_service(body: RegisterServiceIn) -> Dict[str, Any]:
    """Register a new security service in the catalog."""
    return _get_engine().register_service(
        org_id=body.org_id,
        service_name=body.service_name,
        service_category=body.service_category,
        description=body.description,
        owner_team=body.owner_team,
        sla_response_hours=body.sla_response_hours,
        sla_resolution_hours=body.sla_resolution_hours,
        cost_center=body.cost_center,
        availability_pct=body.availability_pct,
    )


@router.post("/services/{service_id}/requests", status_code=201)
async def submit_request(service_id: str, body: SubmitRequestIn) -> Dict[str, Any]:
    """Submit a service request."""
    return _get_engine().submit_request(
        service_id=service_id,
        org_id=body.org_id,
        requester=body.requester,
        requester_dept=body.requester_dept,
        priority=body.priority,
        request_details=body.request_details,
    )


@router.put("/requests/{request_id}/acknowledge")
async def acknowledge_request(request_id: str, org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Acknowledge a service request."""
    req = _get_engine().acknowledge_request(request_id, org_id)
    if req is None:
        raise HTTPException(status_code=404, detail="Request not found")
    return req


@router.put("/requests/{request_id}/resolve")
async def resolve_request(request_id: str, org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Resolve a service request and compute SLA compliance."""
    req = _get_engine().resolve_request(request_id, org_id)
    if req is None:
        raise HTTPException(status_code=404, detail="Request not found")
    return req


@router.post("/services/{service_id}/outages", status_code=201)
async def record_outage(service_id: str, body: RecordOutageIn) -> Dict[str, Any]:
    """Record a service outage."""
    return _get_engine().record_outage(
        service_id=service_id,
        org_id=body.org_id,
        outage_type=body.outage_type,
        severity=body.severity,
        started_at=body.started_at,
        affected_users=body.affected_users,
        root_cause=body.root_cause,
    )


@router.put("/outages/{outage_id}/resolve")
async def resolve_outage(outage_id: str, org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Resolve an outage and recompute service availability."""
    outage = _get_engine().resolve_outage(outage_id, org_id)
    if outage is None:
        raise HTTPException(status_code=404, detail="Outage not found")
    return outage


@router.get("/summary")
async def get_service_summary(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Return catalog-wide statistics."""
    return _get_engine().get_service_summary(org_id)


@router.get("/services/{service_id}")
async def get_service_detail(service_id: str, org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Return service detail with recent requests and outages."""
    svc = _get_engine().get_service_detail(service_id, org_id)
    if svc is None:
        raise HTTPException(status_code=404, detail="Service not found")
    return svc


@router.get("/sla-performance")
async def get_sla_performance(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Return per-service SLA performance metrics."""
    data = _get_engine().get_sla_performance(org_id)
    return {"services": data, "total": len(data)}
