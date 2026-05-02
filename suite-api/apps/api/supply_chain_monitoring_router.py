"""Supply Chain Monitoring Router — ALDECI.

Endpoints:
  POST /api/v1/supply-chain-monitoring/suppliers
  GET  /api/v1/supply-chain-monitoring/suppliers
  GET  /api/v1/supply-chain-monitoring/suppliers/{supplier_id}
  POST /api/v1/supply-chain-monitoring/suppliers/{supplier_id}/assess
  POST /api/v1/supply-chain-monitoring/events
  GET  /api/v1/supply-chain-monitoring/events
  PUT  /api/v1/supply-chain-monitoring/events/{event_id}/resolve
  GET  /api/v1/supply-chain-monitoring/stats

Protected via api_key_auth dependency.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from core.supply_chain_monitoring_engine import SupplyChainMonitoringEngine
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/supply-chain-monitoring",
    tags=["supply-chain-monitoring"],
    dependencies=[Depends(api_key_auth)],
)

_engine: Optional[SupplyChainMonitoringEngine] = None


def _get_engine() -> SupplyChainMonitoringEngine:
    global _engine
    if _engine is None:
        _engine = SupplyChainMonitoringEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class RegisterSupplierRequest(BaseModel):
    org_id: str = Field("default", description="Organisation identifier")
    name: str = Field(..., min_length=1, description="Supplier name")
    supplier_type: str = Field(..., description="One of: software, hardware, services, cloud, logistics, manufacturing")
    risk_tier: str = Field("medium", description="One of: critical, high, medium, low")
    contact_email: str = Field("", description="Primary contact email")
    website: str = Field("", description="Supplier website URL")


class AssessSupplierRequest(BaseModel):
    org_id: str = Field("default", description="Organisation identifier")
    security_certifications: bool = Field(False, description="Supplier holds relevant security certifications")
    incident_history: bool = Field(False, description="Supplier has a history of incidents")
    financial_stability: bool = Field(False, description="Supplier is financially stable")
    compliance_status: bool = Field(False, description="Supplier is compliant with required standards")
    business_continuity: bool = Field(False, description="Supplier has a business continuity plan")


class RecordEventRequest(BaseModel):
    org_id: str = Field("default", description="Organisation identifier")
    supplier_id: str = Field(..., description="ID of the supplier involved")
    event_type: str = Field(..., description="One of: breach, disruption, compliance_violation, performance_issue, contract_breach, bankruptcy")
    severity: str = Field("medium", description="One of: low, medium, high, critical")
    description: str = Field("", description="Event description")


class ResolveEventRequest(BaseModel):
    org_id: str = Field("default", description="Organisation identifier")
    resolution: str = Field(..., min_length=1, description="Resolution description")


# ---------------------------------------------------------------------------
# Supplier endpoints
# ---------------------------------------------------------------------------


@router.post("/suppliers", response_model=Dict[str, Any], status_code=201)
async def register_supplier(body: RegisterSupplierRequest) -> Dict[str, Any]:
    """Register a new supplier."""
    engine = _get_engine()
    try:
        return engine.register_supplier(body.org_id, body.model_dump(exclude={"org_id"}))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/suppliers", response_model=List[Dict[str, Any]])
async def list_suppliers(
    org_id: str = Query("default", description="Organisation identifier"),
    supplier_type: Optional[str] = Query(None, description="Filter by supplier type"),
    risk_tier: Optional[str] = Query(None, description="Filter by risk tier"),
) -> List[Dict[str, Any]]:
    """List suppliers for an org with optional filters."""
    engine = _get_engine()
    return engine.list_suppliers(org_id, supplier_type=supplier_type, risk_tier=risk_tier)


@router.get("/suppliers/{supplier_id}", response_model=Dict[str, Any])
async def get_supplier(
    supplier_id: str,
    org_id: str = Query("default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """Get a single supplier by ID."""
    engine = _get_engine()
    supplier = engine.get_supplier(org_id, supplier_id)
    if supplier is None:
        raise HTTPException(status_code=404, detail=f"Supplier '{supplier_id}' not found")
    return supplier


@router.post("/suppliers/{supplier_id}/assess", response_model=Dict[str, Any])
async def assess_supplier(
    supplier_id: str,
    body: AssessSupplierRequest,
) -> Dict[str, Any]:
    """Run a risk assessment against a supplier."""
    engine = _get_engine()
    assessment_data = body.model_dump(exclude={"org_id"})
    return engine.assess_supplier_risk(body.org_id, supplier_id, assessment_data)


# ---------------------------------------------------------------------------
# Event endpoints
# ---------------------------------------------------------------------------


@router.post("/events", response_model=Dict[str, Any], status_code=201)
async def record_event(body: RecordEventRequest) -> Dict[str, Any]:
    """Record a supply chain event."""
    engine = _get_engine()
    try:
        return engine.record_supply_chain_event(body.org_id, body.model_dump(exclude={"org_id"}))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/events", response_model=List[Dict[str, Any]])
async def list_events(
    org_id: str = Query("default", description="Organisation identifier"),
    supplier_id: Optional[str] = Query(None, description="Filter by supplier ID"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    status: Optional[str] = Query(None, description="Filter by status (open/resolved)"),
) -> List[Dict[str, Any]]:
    """List supply chain events with optional filters."""
    engine = _get_engine()
    return engine.list_events(org_id, supplier_id=supplier_id, event_type=event_type, status=status)


@router.put("/events/{event_id}/resolve", response_model=Dict[str, Any])
async def resolve_event(
    event_id: str,
    body: ResolveEventRequest,
) -> Dict[str, Any]:
    """Resolve a supply chain event."""
    engine = _get_engine()
    return engine.resolve_event(body.org_id, event_id, body.resolution)


# ---------------------------------------------------------------------------
# Stats endpoint
# ---------------------------------------------------------------------------


@router.get("/stats", response_model=Dict[str, Any])
async def get_stats(
    org_id: str = Query("default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """Return aggregate supply chain stats for an org."""
    engine = _get_engine()
    return engine.get_supply_chain_stats(org_id)


@router.get("/", response_model=Dict[str, Any])
async def supply_chain_monitoring_overview(
    org_id: str = Query("default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """Top-level supply chain monitoring overview: supplier counts, event counts, stats."""
    engine = _get_engine()
    suppliers = engine.list_suppliers(org_id)
    events = engine.list_events(org_id)
    open_events = [e for e in events if e.get("status") != "resolved"]
    return {
        "status": "ok",
        "org_id": org_id,
        "total_suppliers": len(suppliers),
        "total_events": len(events),
        "open_events": len(open_events),
        "stats": engine.get_supply_chain_stats(org_id),
    }


__all__ = ["router"]
