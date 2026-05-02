"""Threat Intelligence Automation Router — ALDECI.

Endpoints for the Threat Intelligence Automation engine.

Prefix: /api/v1/ti-automation
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/ti-automation/feeds                        register_feed
  GET    /api/v1/ti-automation/feeds                        list_feeds
  PUT    /api/v1/ti-automation/feeds/{feed_id}/stats        update_feed_stats
  POST   /api/v1/ti-automation/automations                  create_automation
  GET    /api/v1/ti-automation/automations                  list_automations
  PUT    /api/v1/ti-automation/automations/{id}/execute     execute_automation
  POST   /api/v1/ti-automation/enrichments                  store_enrichment
  GET    /api/v1/ti-automation/enrichments                  list_enrichments
  GET    /api/v1/ti-automation/enrichments/{ioc_value}      get_enrichment
  GET    /api/v1/ti-automation/stats                        get_ti_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/ti-automation",
    tags=["Threat Intelligence Automation"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.threat_intelligence_automation_engine import (
            ThreatIntelligenceAutomationEngine,
        )
        _engine = ThreatIntelligenceAutomationEngine()
    return _engine


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class FeedCreate(BaseModel):
    feed_name: str
    feed_type: str = "osint"
    url: str = ""
    api_key: str = ""
    format: str = "json"
    status: str = "active"
    poll_interval_minutes: int = 60
    ioc_count: int = 0
    last_polled: Optional[str] = None


class FeedStatsUpdate(BaseModel):
    ioc_count_delta: int = Field(0, description="Increment ioc_count by this value")
    last_polled: Optional[str] = None


class AutomationCreate(BaseModel):
    automation_name: str
    trigger_type: str = "manual"
    action_type: str = "alert"
    condition: Dict[str, Any] = {}
    enabled: bool = True


class EnrichmentCreate(BaseModel):
    ioc_value: str
    ioc_type: str = "ip"
    sources: List[str] = []
    confidence_score: float = Field(0.0, ge=0.0, le=100.0)
    threat_categories: List[str] = []
    is_malicious: bool = False
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None


# ---------------------------------------------------------------------------
# Feed endpoints
# ---------------------------------------------------------------------------

@router.post("/feeds", dependencies=[Depends(api_key_auth)])
def register_feed(body: FeedCreate, org_id: str = Query("default")) -> Dict[str, Any]:
    """Register a new threat intelligence feed."""
    try:
        return _get_engine().register_feed(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/feeds", dependencies=[Depends(api_key_auth)])
def list_feeds(
    org_id: str = Query("default"),
    feed_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """List registered feeds."""
    rows = _get_engine().list_feeds(org_id, feed_type=feed_type, status=status)
    if not rows:
        return {
            "feeds": [],
            "total": 0,
            "hint": "Wire global feed registry to per-org feeds via POST /api/v1/ti-automation/feeds/import-global, or register a feed manually via POST /api/v1/ti-automation/feeds.",
        }
    return {"feeds": rows, "total": len(rows)}


@router.post("/feeds/import-global", dependencies=[Depends(api_key_auth)])
def import_global_feeds(org_id: str = Query("default")) -> Dict[str, Any]:
    """Import feeds from the global feed registry into per-org tia_feeds.

    Reads the 7 catalogs in suite-feeds/feeds_service.py (AUTHORITATIVE,
    NATIONAL_CERT, EXPLOIT, THREAT_ACTOR, SUPPLY_CHAIN, CLOUD_RUNTIME,
    EARLY_SIGNAL) and bulk-registers each as a row in the org's tia_feeds
    table. Idempotent: feeds already present (matched by feed_name) are
    skipped. No mock data — every URL/name/refresh comes from feeds_service.

    Returns counts broken down by catalog and by classified feed_type.
    """
    try:
        from core.global_feed_registry_importer import import_global_feeds as _do_import
        return _do_import(_get_engine(), org_id)
    except Exception as exc:
        _logger.exception("import_global_feeds failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.put("/feeds/{feed_id}/stats", dependencies=[Depends(api_key_auth)])
def update_feed_stats(
    feed_id: str,
    body: FeedStatsUpdate,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Update feed IOC count and last polled timestamp."""
    try:
        return _get_engine().update_feed_stats(
            org_id, feed_id, body.ioc_count_delta, last_polled=body.last_polled
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


# ---------------------------------------------------------------------------
# Automation endpoints
# ---------------------------------------------------------------------------

@router.post("/automations", dependencies=[Depends(api_key_auth)])
def create_automation(body: AutomationCreate, org_id: str = Query("default")) -> Dict[str, Any]:
    """Create an automation rule."""
    try:
        return _get_engine().create_automation(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/automations", dependencies=[Depends(api_key_auth)])
def list_automations(
    org_id: str = Query("default"),
    trigger_type: Optional[str] = Query(None),
    enabled: Optional[bool] = Query(None),
) -> List[Dict[str, Any]]:
    """List automation rules."""
    return _get_engine().list_automations(org_id, trigger_type=trigger_type, enabled=enabled)


@router.put("/automations/{automation_id}/execute", dependencies=[Depends(api_key_auth)])
def execute_automation(
    automation_id: str,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Execute an automation rule (increments execution count)."""
    try:
        return _get_engine().execute_automation(org_id, automation_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


# ---------------------------------------------------------------------------
# Enrichment endpoints
# ---------------------------------------------------------------------------

@router.post("/enrichments", dependencies=[Depends(api_key_auth)])
def store_enrichment(body: EnrichmentCreate, org_id: str = Query("default")) -> Dict[str, Any]:
    """Store an IOC enrichment record."""
    try:
        return _get_engine().store_enrichment(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/enrichments", dependencies=[Depends(api_key_auth)])
def list_enrichments(
    org_id: str = Query("default"),
    ioc_type: Optional[str] = Query(None),
    is_malicious: Optional[bool] = Query(None),
) -> List[Dict[str, Any]]:
    """List IOC enrichments."""
    return _get_engine().list_enrichments(org_id, ioc_type=ioc_type, is_malicious=is_malicious)


@router.get("/enrichments/{ioc_value}", dependencies=[Depends(api_key_auth)])
def get_enrichment(ioc_value: str, org_id: str = Query("default")) -> Dict[str, Any]:
    """Get most recent enrichment for a specific IOC value."""
    result = _get_engine().get_enrichment(org_id, ioc_value)
    if result is None:
        raise HTTPException(status_code=404, detail=f"No enrichment found for {ioc_value!r}")
    return result


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_ti_stats(org_id: str = Query("default")) -> Dict[str, Any]:
    """Return aggregated threat intelligence stats."""
    return _get_engine().get_ti_stats(org_id)
