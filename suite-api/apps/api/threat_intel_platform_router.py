"""Threat Intelligence Platform Router — ALDECI.

Endpoints for the Threat Intelligence Platform engine.

Prefix: /api/v1/tip
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/tip/sources                     add_source
  GET    /api/v1/tip/sources                     list_sources
  POST   /api/v1/tip/indicators                  add_indicator
  GET    /api/v1/tip/indicators                  search_indicators
  GET    /api/v1/tip/indicators/{indicator_id}   get_indicator
  POST   /api/v1/tip/indicators/bulk             bulk_ingest
  POST   /api/v1/tip/relationships               add_relationship
  GET    /api/v1/tip/relationships/{indicator_id} get_relationships
  POST   /api/v1/tip/reports                     create_report
  GET    /api/v1/tip/reports                     list_reports
  POST   /api/v1/tip/check                       check_indicator
  POST   /api/v1/tip/expire                      expire_indicators
  GET    /api/v1/tip/stats                       get_tip_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/tip",
    tags=["threat-intel-platform"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.threat_intel_platform_engine import ThreatIntelPlatformEngine
        _engine = ThreatIntelPlatformEngine()
    return _engine


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class SourceCreate(BaseModel):
    source_name: str
    source_type: str = "osint"
    feed_url: str = ""
    api_key_masked: str = ""
    status: str = "active"
    reliability_score: float = Field(0.5, ge=0.0, le=1.0)
    update_frequency_hours: int = 24
    last_updated: Optional[str] = None
    total_indicators: int = 0


class IndicatorCreate(BaseModel):
    indicator_type: str
    value: str
    source_id: str = ""
    severity: str = "medium"
    confidence: float = Field(0.5, ge=0.0, le=1.0)
    threat_category: str = "malware"
    tags: List[str] = []
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    expiry_date: Optional[str] = None
    tlp_level: str = "amber"
    hit_count: int = 0
    mitre_techniques: List[str] = []


class BulkIngestRequest(BaseModel):
    source_id: str
    indicators: List[Dict[str, Any]]


class RelationshipCreate(BaseModel):
    indicator_a_id: str
    indicator_b_id: str
    relationship_type: str = "communicates_with"
    confidence: float = Field(0.5, ge=0.0, le=1.0)
    source_id: str = ""


class ReportCreate(BaseModel):
    report_name: str
    report_type: str = "tactical"
    classification: str = "internal"
    tlp_level: str = "amber"
    summary: str = ""
    ioc_count: int = 0
    threat_actors: List[str] = []
    affected_sectors: List[str] = []
    source_ids: List[str] = []
    published_date: Optional[str] = None


class CheckIndicatorRequest(BaseModel):
    value: str
    indicator_type: str
    org_id: str = "default"


# ---------------------------------------------------------------------------
# Source endpoints
# ---------------------------------------------------------------------------

@router.post("/sources", dependencies=[Depends(api_key_auth)])
def add_source(body: SourceCreate, org_id: str = Query("default")) -> Dict[str, Any]:
    """Register a new intel source."""
    try:
        return _get_engine().add_source(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/sources", dependencies=[Depends(api_key_auth)])
def list_sources(
    org_id: str = Query("default"),
    status: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    """List intel sources."""
    return _get_engine().list_sources(org_id, status=status)


# ---------------------------------------------------------------------------
# Indicator endpoints
# ---------------------------------------------------------------------------

@router.post("/indicators", dependencies=[Depends(api_key_auth)])
def add_indicator(body: IndicatorCreate, org_id: str = Query("default")) -> Dict[str, Any]:
    """Add an IOC/indicator."""
    try:
        return _get_engine().add_indicator(org_id, body.model_dump(exclude_none=True))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/indicators", dependencies=[Depends(api_key_auth)])
def search_indicators(
    org_id: str = Query("default"),
    query: str = Query(""),
    indicator_type: Optional[str] = Query(None),
    threat_category: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
) -> List[Dict[str, Any]]:
    """Search indicators by value or tags."""
    return _get_engine().search_indicators(
        org_id, query,
        indicator_type=indicator_type,
        threat_category=threat_category,
        limit=limit,
    )


@router.get("/indicators/{indicator_id}", dependencies=[Depends(api_key_auth)])
def get_indicator(indicator_id: str, org_id: str = Query("default")) -> Dict[str, Any]:
    """Get a single indicator with relationships."""
    result = _get_engine().get_indicator(org_id, indicator_id)
    if not result:
        raise HTTPException(status_code=404, detail="Indicator not found.")
    return result


@router.post("/indicators/bulk", dependencies=[Depends(api_key_auth)])
def bulk_ingest(body: BulkIngestRequest, org_id: str = Query("default")) -> Dict[str, Any]:
    """Bulk ingest indicators from a source."""
    return _get_engine().bulk_ingest(org_id, body.source_id, body.indicators)


# ---------------------------------------------------------------------------
# Relationship endpoints
# ---------------------------------------------------------------------------

@router.post("/relationships", dependencies=[Depends(api_key_auth)])
def add_relationship(body: RelationshipCreate, org_id: str = Query("default")) -> Dict[str, Any]:
    """Add a relationship between indicators."""
    try:
        return _get_engine().add_relationship(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/relationships/{indicator_id}", dependencies=[Depends(api_key_auth)])
def get_relationships(indicator_id: str, org_id: str = Query("default")) -> List[Dict[str, Any]]:
    """Get all relationships for an indicator."""
    return _get_engine().get_relationships(org_id, indicator_id)


# ---------------------------------------------------------------------------
# Report endpoints
# ---------------------------------------------------------------------------

@router.post("/reports", dependencies=[Depends(api_key_auth)])
def create_report(body: ReportCreate, org_id: str = Query("default")) -> Dict[str, Any]:
    """Create an intel report."""
    try:
        return _get_engine().create_report(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/reports", dependencies=[Depends(api_key_auth)])
def list_reports(
    org_id: str = Query("default"),
    report_type: Optional[str] = Query(None),
    tlp_level: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    """List intel reports."""
    return _get_engine().list_reports(org_id, report_type=report_type, tlp_level=tlp_level)


# ---------------------------------------------------------------------------
# Check / expire / stats
# ---------------------------------------------------------------------------

@router.post("/check", dependencies=[Depends(api_key_auth)])
def check_indicator(body: CheckIndicatorRequest) -> Dict[str, Any]:
    """Quick lookup: is this value a known bad indicator?"""
    return _get_engine().check_indicator(body.org_id, body.value, body.indicator_type)


@router.post("/expire", dependencies=[Depends(api_key_auth)])
def expire_indicators(org_id: str = Query("default")) -> Dict[str, Any]:
    """Mark expired indicators as inactive."""
    count = _get_engine().expire_indicators(org_id)
    return {"expired": count}


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_tip_stats(org_id: str = Query("default")) -> Dict[str, Any]:
    """Return aggregated TIP stats."""
    return _get_engine().get_tip_stats(org_id)


@router.get("/", summary="TIP index", tags=["tip"])
def tip_index(org_id: str = Query("default"), _auth: None = Depends(api_key_auth)) -> Dict[str, Any]:
    """Return threat intelligence platform summary for the org."""
    engine = _get_engine()
    try:
        stats = engine.get_tip_stats(org_id=org_id)
    except Exception:
        stats = {}
    try:
        items = engine.list_sources(org_id=org_id)
    except Exception:
        items = []
    return {"router": "tip", "org_id": org_id, "stats": stats, "items": items, "count": len(items)}
