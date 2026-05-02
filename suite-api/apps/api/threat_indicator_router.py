"""Threat Indicator Router — ALDECI.

Endpoints for the ThreatIndicatorEngine (SQLite-backed, org_id isolated).

Prefix: /api/v1/threat-indicators
Auth:   api_key_auth dependency

Routes:
  POST  /api/v1/threat-indicators/indicators                     add_indicator
  GET   /api/v1/threat-indicators/indicators                     get_active_indicators
  GET   /api/v1/threat-indicators/indicators/{id}                get_indicator
  POST  /api/v1/threat-indicators/indicators/{id}/enrich         enrich_indicator
  POST  /api/v1/threat-indicators/indicators/{id}/sighting       record_sighting
  POST  /api/v1/threat-indicators/indicators/{id}/false-positive mark_false_positive
  POST  /api/v1/threat-indicators/indicators/{id}/expire         expire_indicator
  GET   /api/v1/threat-indicators/expired                        get_expired_indicators
  GET   /api/v1/threat-indicators/search                         search_indicators
  GET   /api/v1/threat-indicators/summary                        get_summary
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/threat-indicators",
    tags=["Threat Indicators"],
    dependencies=[Depends(api_key_auth)],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.threat_indicator_engine import ThreatIndicatorEngine
        _engine = ThreatIndicatorEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class IndicatorCreate(BaseModel):
    indicator_value: str
    indicator_type: str
    source: str = ""
    confidence: float = 0.5
    severity: str = "medium"
    tlp: str = "amber"
    tags: List[str] = []
    expiry_at: Optional[str] = None


class EnrichmentAdd(BaseModel):
    enrichment_source: str
    enrichment_data: Dict[str, Any] = {}


class SightingAdd(BaseModel):
    source_system: str = ""
    context: str = ""
    severity: str = "medium"


# ---------------------------------------------------------------------------
# Indicators
# ---------------------------------------------------------------------------

@router.get("/")
def list_threat_indicators(org_id: str = Query("default")):
    """Get threat indicator summary for the org."""
    return _get_engine().get_summary(org_id=org_id)


@router.post("/indicators", status_code=201)
def add_indicator(body: IndicatorCreate, org_id: str = Query(default="default")):
    """Add a new threat indicator (IOC) with confidence clamping."""
    try:
        return _get_engine().add_indicator(
            org_id=org_id,
            indicator_value=body.indicator_value,
            indicator_type=body.indicator_type,
            source=body.source,
            confidence=body.confidence,
            severity=body.severity,
            tlp=body.tlp,
            tags=body.tags,
            expiry_at=body.expiry_at,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/indicators")
def get_active_indicators(
     org_id: str = Query(default="default"),
    indicator_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
):
    """Return active indicators not yet expired, with optional type/severity filters."""
    return _get_engine().get_active_indicators(
        org_id, indicator_type=indicator_type, severity=severity
    )


@router.get("/indicators/{indicator_id}")
def get_indicator(indicator_id: str, org_id: str = Query(default="default")):
    """Get a single indicator with its enrichments and sightings."""
    result = _get_engine().get_indicator(indicator_id, org_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Indicator not found")
    return result


@router.post("/indicators/{indicator_id}/enrich", status_code=201)
def enrich_indicator(
    indicator_id: str, body: EnrichmentAdd, org_id: str = Query(default="default")
):
    """Add enrichment data for an indicator."""
    return _get_engine().enrich_indicator(
        indicator_id=indicator_id,
        org_id=org_id,
        enrichment_source=body.enrichment_source,
        enrichment_data=body.enrichment_data,
    )


@router.post("/indicators/{indicator_id}/sighting", status_code=201)
def record_sighting(
    indicator_id: str, body: SightingAdd, org_id: str = Query(default="default")
):
    """Record a sighting of an indicator (increments sighting_count)."""
    try:
        return _get_engine().record_sighting(
            indicator_id=indicator_id,
            org_id=org_id,
            source_system=body.source_system,
            context=body.context,
            severity=body.severity,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/indicators/{indicator_id}/false-positive")
def mark_false_positive(indicator_id: str, org_id: str = Query(default="default")):
    """Mark an indicator as false positive and deactivate it."""
    result = _get_engine().mark_false_positive(indicator_id, org_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Indicator not found")
    return result


@router.post("/indicators/{indicator_id}/expire")
def expire_indicator(indicator_id: str, org_id: str = Query(default="default")):
    """Manually expire (deactivate) an indicator."""
    result = _get_engine().expire_indicator(indicator_id, org_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Indicator not found")
    return result


# ---------------------------------------------------------------------------
# Expired / search / summary
# ---------------------------------------------------------------------------

@router.get("/expired")
def get_expired_indicators(org_id: str = Query(default="default")):
    """Return active indicators that have passed their expiry_at timestamp."""
    return _get_engine().get_expired_indicators(org_id)


@router.get("/search")
def search_indicators(org_id: str = Query(default="default"), query: str = Query(...)):
    """LIKE search on indicator_value."""
    return _get_engine().search_indicators(org_id, query)


@router.get("/summary")
def get_summary(org_id: str = Query(default="default")):
    """Return aggregated IOC summary for an org."""
    return _get_engine().get_summary(org_id)
