"""Incident Cost Router — ALDECI.

Endpoints for the Incident Cost engine.

Prefix: /api/v1/incident-costs
Auth:   api_key_auth dependency

Routes:
  POST   /api/v1/incident-costs/costs                              record_cost
  POST   /api/v1/incident-costs/incidents/{id}/finalize            finalize_incident
  GET    /api/v1/incident-costs/incidents/{id}/costs               get_incident_costs
  GET    /api/v1/incident-costs/incidents/{id}/summary             get_incident_summary
  POST   /api/v1/incident-costs/benchmarks                         add_benchmark
  GET    /api/v1/incident-costs/incidents/{id}/benchmark-compare   compare_to_benchmark
  GET    /api/v1/incident-costs/analytics                          get_cost_analytics
  GET    /api/v1/incident-costs/summaries                          list_summaries
"""

from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/incident-costs",
    tags=["Incident Costs"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.incident_cost_engine import IncidentCostEngine
        _engine = IncidentCostEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class CostCreate(BaseModel):
    incident_id: str
    incident_name: str
    incident_type: str
    cost_category: str
    amount: float
    currency: str = "USD"
    estimated: bool = False
    description: str = ""
    recorded_by: str = ""


class IncidentFinalize(BaseModel):
    duration_hours: float
    severity: str


class BenchmarkCreate(BaseModel):
    incident_type: str
    avg_cost: float
    median_cost: float
    p90_cost: float
    sample_size: int
    source: str
    published_year: int


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/", dependencies=[Depends(api_key_auth)])
def get_service_summary(org_id: str = Query(default="default")) -> dict:
    """Return incident-costs service summary (analytics overview).

    5-state envelope: items/total/org_id/filters_applied/hint.
    """
    analytics = _get_engine().get_cost_analytics(org_id)
    summaries = _get_engine().list_summaries(org_id)
    items = [
        {"key": "analytics", "value": analytics},
        {"key": "recent_summaries", "value": summaries[:5]},
    ]
    envelope: dict = {
        "items": items,
        "total": len(items),
        "org_id": org_id,
        "filters_applied": {},
        "service": "incident-costs",
    }
    total_incidents = analytics.get("total_incidents", 0) if isinstance(analytics, dict) else 0
    if total_incidents == 0:
        envelope["hint"] = (
            "No incident cost records yet. Record a cost via "
            "POST /api/v1/incident-costs/costs."
        )
    return envelope


@router.post("/costs", dependencies=[Depends(api_key_auth)], status_code=201)
def record_cost(body: CostCreate, org_id: str = Query(default="default")):
    """Record a cost line-item for a security incident."""
    try:
        return _get_engine().record_cost(
            org_id=org_id,
            incident_id=body.incident_id,
            incident_name=body.incident_name,
            incident_type=body.incident_type,
            cost_category=body.cost_category,
            amount=body.amount,
            currency=body.currency,
            estimated=body.estimated,
            description=body.description,
            recorded_by=body.recorded_by,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/incidents/{incident_id}/finalize", dependencies=[Depends(api_key_auth)])
def finalize_incident(
    incident_id: str, body: IncidentFinalize, org_id: str = Query(default="default")
):
    """Finalize an incident and compute cost totals."""
    try:
        return _get_engine().finalize_incident(
            org_id=org_id,
            incident_id=incident_id,
            duration_hours=body.duration_hours,
            severity=body.severity,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/incidents/{incident_id}/costs", dependencies=[Depends(api_key_auth)])
def get_incident_costs(incident_id: str, org_id: str = Query(default="default")):
    """Return all cost records for an incident."""
    return _get_engine().get_incident_costs(org_id, incident_id)


@router.get("/incidents/{incident_id}/summary", dependencies=[Depends(api_key_auth)])
def get_incident_summary(incident_id: str, org_id: str = Query(default="default")):
    """Return the finalized summary for an incident."""
    summary = _get_engine().get_incident_summary(org_id, incident_id)
    if not summary:
        raise HTTPException(status_code=404, detail="Incident summary not found")
    return summary


@router.post("/benchmarks", dependencies=[Depends(api_key_auth)], status_code=201)
def add_benchmark(body: BenchmarkCreate, org_id: str = Query(default="default")):
    """Add an industry cost benchmark."""
    try:
        return _get_engine().add_benchmark(
            org_id=org_id,
            incident_type=body.incident_type,
            avg_cost=body.avg_cost,
            median_cost=body.median_cost,
            p90_cost=body.p90_cost,
            sample_size=body.sample_size,
            source=body.source,
            published_year=body.published_year,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get(
    "/incidents/{incident_id}/benchmark-compare",
    dependencies=[Depends(api_key_auth)],
)
def compare_to_benchmark(incident_id: str, org_id: str = Query(default="default")):
    """Compare incident total cost to industry benchmark."""
    try:
        return _get_engine().compare_to_benchmark(org_id, incident_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/analytics", dependencies=[Depends(api_key_auth)])
def get_cost_analytics(org_id: str = Query(default="default")):
    """Return cost analytics across all incidents."""
    return _get_engine().get_cost_analytics(org_id)


@router.get("/summaries", dependencies=[Depends(api_key_auth)])
def list_summaries(
     org_id: str = Query(default="default"),
    incident_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
):
    """List finalized incident summaries."""
    return _get_engine().list_summaries(
        org_id, incident_type=incident_type, severity=severity
    )
