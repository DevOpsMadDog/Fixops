"""Threat Intel Enrichment Router — ALDECI.

Endpoints for the Threat Intel Enrichment engine.

Prefix: /api/v1/intel-enrichment
Auth:   api_key_auth dependency

Routes:
  POST  /api/v1/intel-enrichment/requests                        create_enrichment_request
  GET   /api/v1/intel-enrichment/requests/{id}                   get_enrichment
  POST  /api/v1/intel-enrichment/requests/{id}/results           add_enrichment_result
  GET   /api/v1/intel-enrichment/indicators/{indicator}/summary  get_indicator_summary
  POST  /api/v1/intel-enrichment/sources                         register_source
  POST  /api/v1/intel-enrichment/sources/{id}/stats              update_source_stats
  GET   /api/v1/intel-enrichment/sources                         list_sources
  GET   /api/v1/intel-enrichment/stats                           get_enrichment_stats
  POST  /api/v1/intel-enrichment/bulk                            bulk_enrich
"""

from __future__ import annotations

import logging
from typing import List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/intel-enrichment",
    tags=["Threat Intel Enrichment"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.threat_intel_enrichment_engine import ThreatIntelEnrichmentEngine
        _engine = ThreatIntelEnrichmentEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class EnrichmentRequestCreate(BaseModel):
    indicator: str
    indicator_type: str
    sources_queried: int = 0


class EnrichmentResultCreate(BaseModel):
    source: str
    reputation_score: float = 0.0
    malicious: bool = False
    tags: List[str] = []
    context: str = ""
    confidence: float = 0.0
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None


class SourceCreate(BaseModel):
    source_name: str
    source_type: str
    api_key: str = ""


class SourceStatsUpdate(BaseModel):
    success: bool


class BulkIndicator(BaseModel):
    indicator: str
    indicator_type: str
    sources_queried: int = 0


class BulkEnrichRequest(BaseModel):
    indicators: List[BulkIndicator]


# ---------------------------------------------------------------------------
# Enrichment Requests
# ---------------------------------------------------------------------------

@router.get("/", dependencies=[Depends(api_key_auth)])
def list_intel_enrichment(org_id: str = Query("default")):
    """Get threat intel enrichment statistics for the org."""
    return _get_engine().get_enrichment_stats(org_id=org_id)


@router.post("/requests", dependencies=[Depends(api_key_auth)], status_code=201)
def create_enrichment_request(body: EnrichmentRequestCreate, org_id: str = Query(default="default")):
    """Create a new enrichment request."""
    try:
        return _get_engine().create_enrichment_request(
            org_id=org_id,
            indicator=body.indicator,
            indicator_type=body.indicator_type,
            sources_queried=body.sources_queried,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/requests", dependencies=[Depends(api_key_auth)])
def list_enrichment_requests(
    org_id: str = Query(default="default"),
    status: Optional[str] = Query(None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    """List enrichment requests for an org (canonical envelope, batch-6).

    Class-c contract: empty IS correct for fresh tenants — request log only
    populates after POST /requests. Always returns full envelope with
    pagination context + filters echo + actionable hint.
    """
    rows = _get_engine().list_enrichment_requests(org_id=org_id, status=status, limit=limit) or []
    paged = rows[offset : offset + limit] if offset else rows[:limit]
    envelope = {
        "items": paged,
        "requests": paged,  # legacy key preserved for back-compat
        "total": len(rows),
        "org_id": org_id,
        "limit": limit,
        "offset": offset,
        "filters_applied": {"status": status},
    }
    if not rows:
        envelope["hint"] = (
            "Submit POST /api/v1/intel-enrichment/requests to enrich an IOC "
            "(IP, domain, hash, URL). Empty is the correct response for a "
            "fresh tenant — this is a request log, not an importable feed."
        )
    return envelope


@router.get("/requests/{request_id}", dependencies=[Depends(api_key_auth)])
def get_enrichment(request_id: str, org_id: str = Query(default="default")):
    """Get enrichment request with results."""
    result = _get_engine().get_enrichment(request_id, org_id)
    if not result:
        raise HTTPException(status_code=404, detail="Enrichment request not found")
    return result


@router.post("/requests/{request_id}/results", dependencies=[Depends(api_key_auth)], status_code=201)
def add_enrichment_result(
    request_id: str,
    body: EnrichmentResultCreate,
     org_id: str = Query(default="default"),
):
    """Add an enrichment result to a request."""
    try:
        return _get_engine().add_enrichment_result(
            request_id=request_id,
            org_id=org_id,
            source=body.source,
            reputation_score=body.reputation_score,
            malicious=body.malicious,
            tags=body.tags,
            context=body.context,
            confidence=body.confidence,
            first_seen=body.first_seen,
            last_seen=body.last_seen,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Indicator Summary
# ---------------------------------------------------------------------------

@router.get("/indicators/{indicator}/summary", dependencies=[Depends(api_key_auth)])
def get_indicator_summary(indicator: str, org_id: str = Query(default="default")):
    """Get aggregated enrichment summary for an indicator."""
    return _get_engine().get_indicator_summary(org_id, indicator)


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------

@router.post("/sources", dependencies=[Depends(api_key_auth)], status_code=201)
def register_source(body: SourceCreate, org_id: str = Query(default="default")):
    """Register a new enrichment source."""
    try:
        return _get_engine().register_source(
            org_id=org_id,
            source_name=body.source_name,
            source_type=body.source_type,
            api_key=body.api_key,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/sources/{source_id}/stats", dependencies=[Depends(api_key_auth)])
def update_source_stats(
    source_id: str,
    body: SourceStatsUpdate,
     org_id: str = Query(default="default"),
):
    """Update request_count and success_rate for a source."""
    try:
        return _get_engine().update_source_stats(source_id, org_id, body.success)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/sources", dependencies=[Depends(api_key_auth)])
def list_sources(
     org_id: str = Query(default="default"),
    enabled: Optional[bool] = Query(None),
):
    """List registered enrichment sources."""
    return _get_engine().list_sources(org_id, enabled=enabled)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_enrichment_stats(org_id: str = Query(default="default")):
    """Return aggregated enrichment statistics."""
    return _get_engine().get_enrichment_stats(org_id)


# ---------------------------------------------------------------------------
# Bulk Enrich
# ---------------------------------------------------------------------------

@router.post("/bulk", dependencies=[Depends(api_key_auth)], status_code=201)
def bulk_enrich(body: BulkEnrichRequest, org_id: str = Query(default="default")):
    """Create enrichment requests for multiple indicators."""
    try:
        indicators = [item.model_dump() for item in body.indicators]
        return _get_engine().bulk_enrich(org_id, indicators)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
