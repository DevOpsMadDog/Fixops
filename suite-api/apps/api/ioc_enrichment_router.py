"""IOC Enrichment Router — ALDECI.

Endpoints for the IOC Enrichment engine.

Prefix: /api/v1/ioc-enrichment
Auth: api_key_auth dependency

Routes:
  GET    /api/v1/ioc-enrichment/iocs                            list_iocs
  POST   /api/v1/ioc-enrichment/iocs                           add_ioc
  POST   /api/v1/ioc-enrichment/iocs/{ioc_id}/enrich           enrich_ioc
  GET    /api/v1/ioc-enrichment/iocs/{ioc_id}/enrichment        get_enrichment
  POST   /api/v1/ioc-enrichment/watchlist/{watchlist_name}      add_to_watchlist
  GET    /api/v1/ioc-enrichment/watchlist/{watchlist_name}      get_watchlist
  POST   /api/v1/ioc-enrichment/bulk-import                    bulk_import
  GET    /api/v1/ioc-enrichment/stats                          get_ioc_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

_SIMULATION_WARNING = {
    "is_simulated": True,
    "engine": "ioc_enrichment_engine",
    "real_integration_required": "/api/v1/connectors/threat-intel/configure",
    "do_not_use_in_demo": True,
}

router = APIRouter(
    prefix="/api/v1/ioc-enrichment",
    tags=["IOC Enrichment"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.ioc_enrichment_engine import IOCEnrichmentEngine
        _engine = IOCEnrichmentEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class IOCCreate(BaseModel):
    value: str
    ioc_type: str = "ip"
    severity: str = "medium"
    source: str = ""
    tags: List[str] = Field(default_factory=list)
    confidence: int = Field(default=50, ge=0, le=100)


class WatchlistAdd(BaseModel):
    ioc_id: str


class BulkImport(BaseModel):
    iocs: List[Dict[str, Any]]


# ---------------------------------------------------------------------------
# IOC CRUD routes
# ---------------------------------------------------------------------------

@router.get("/", dependencies=[Depends(api_key_auth)])
def list_ioc_enrichment(org_id: str = Query("default")):
    """Get IOC enrichment statistics for the org."""
    return _get_engine().get_ioc_stats(org_id)


@router.get("/iocs", dependencies=[Depends(api_key_auth)])
def list_iocs(
    org_id: str = Query(default="default"),
    ioc_type: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=1000),
):
    """List IOC indicators for an org, optionally filtered by type or severity."""
    results = _get_engine().list_iocs(org_id, ioc_type=ioc_type, severity=severity)
    return results[:limit]


@router.post("/iocs", dependencies=[Depends(api_key_auth)], status_code=201)
def add_ioc(body: IOCCreate, org_id: str = Query(default="default")):
    """Add a new IOC indicator."""
    try:
        return _get_engine().add_ioc(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Enrichment routes
# ---------------------------------------------------------------------------

@router.post(
    "/iocs/{ioc_id}/enrich",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def enrich_ioc(ioc_id: str, org_id: str = Query(default="default")):
    """Trigger enrichment for an IOC (reputation, geo, campaigns, verdict)."""
    result = _get_engine().enrich_ioc(org_id, ioc_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return {"data": result, "_simulation_warning": _SIMULATION_WARNING}


@router.get("/iocs/{ioc_id}/enrichment", dependencies=[Depends(api_key_auth)])
def get_enrichment(ioc_id: str, org_id: str = Query(default="default")):
    """Fetch stored enrichment for an IOC."""
    result = _get_engine().get_enrichment(org_id, ioc_id)
    if not result:
        raise HTTPException(status_code=404, detail="No enrichment found for this IOC")
    return result


# ---------------------------------------------------------------------------
# Watchlist routes
# ---------------------------------------------------------------------------

@router.post(
    "/watchlist/{watchlist_name}",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def add_to_watchlist(
    watchlist_name: str,
    body: WatchlistAdd,
    org_id: str = Query(default="default"),
):
    """Add an IOC to a named watchlist."""
    success = _get_engine().add_to_watchlist(org_id, watchlist_name, body.ioc_id)
    if not success:
        raise HTTPException(status_code=400, detail="Failed to add IOC to watchlist")
    return {"added": True, "watchlist_name": watchlist_name, "ioc_id": body.ioc_id}


@router.get("/watchlist/{watchlist_name}", dependencies=[Depends(api_key_auth)])
def get_watchlist(watchlist_name: str, org_id: str = Query(default="default")):
    """Return all IOC records on a named watchlist."""
    return _get_engine().get_watchlist(org_id, watchlist_name)


# ---------------------------------------------------------------------------
# Bulk import
# ---------------------------------------------------------------------------

@router.post("/bulk-import", dependencies=[Depends(api_key_auth)], status_code=201)
def bulk_import(body: BulkImport, org_id: str = Query(default="default")):
    """Bulk import a list of IOC dicts. Returns imported/failed counts."""
    return _get_engine().bulk_import(org_id, body.iocs)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_ioc_stats(org_id: str = Query(default="default")):
    """Return summary statistics for an org's IOC inventory."""
    return _get_engine().get_ioc_stats(org_id)
