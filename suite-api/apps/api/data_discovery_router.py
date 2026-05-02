"""Data Discovery Router — ALDECI.

Endpoints for the DataDiscoveryEngine (SQLite-backed, org_id isolated).

Prefix: /api/v1/data-discovery
Auth:   api_key_auth dependency

Routes:
  POST  /api/v1/data-discovery/datastores                              register_datastore
  GET   /api/v1/data-discovery/datastores                              list_datastores
  GET   /api/v1/data-discovery/datastores/{datastore_id}               get_datastore
  POST  /api/v1/data-discovery/datastores/{datastore_id}/discoveries   record_discovery
  GET   /api/v1/data-discovery/discoveries                             list_discoveries
  POST  /api/v1/data-discovery/datastores/{datastore_id}/scans         create_scan_job
  GET   /api/v1/data-discovery/scans                                   list_scan_jobs
  GET   /api/v1/data-discovery/stats                                   get_discovery_stats
"""
from __future__ import annotations

import logging
from typing import List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/data-discovery",
    tags=["Data Discovery"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.data_discovery_engine import DataDiscoveryEngine
        _engine = DataDiscoveryEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class DatastoreCreate(BaseModel):
    name: str
    datastore_type: str = "database"
    location: str = ""
    owner_team: str = ""
    data_types_found: List[str] = []
    risk_level: str = "none"
    record_count: int = 0


class DiscoveryCreate(BaseModel):
    data_type: str
    record_count: int = 0
    sample_path: str = ""
    confidence: int = 80
    risk_level: str = "low"
    is_classified: bool = False


class ScanJobCreate(BaseModel):
    started_at: str = ""
    records_scanned: int = 0
    findings_count: int = 0
    scanner_version: str = ""


# ---------------------------------------------------------------------------
# Datastores
# ---------------------------------------------------------------------------

@router.post("/datastores", dependencies=[Depends(api_key_auth)], status_code=201)
def register_datastore(body: DatastoreCreate, org_id: str = Query(default="default")):
    """Register a new datastore for discovery tracking."""
    try:
        return _get_engine().register_datastore(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/datastores", dependencies=[Depends(api_key_auth)])
def list_datastores(
     org_id: str = Query(default="default"),
    datastore_type: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
):
    """List datastores with optional filters."""
    return _get_engine().list_datastores(
        org_id,
        datastore_type=datastore_type,
        risk_level=risk_level,
    )


@router.get("/datastores/{datastore_id}", dependencies=[Depends(api_key_auth)])
def get_datastore(datastore_id: str, org_id: str = Query(default="default")):
    """Get a single datastore by ID."""
    result = _get_engine().get_datastore(org_id, datastore_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Datastore not found")
    return result


# ---------------------------------------------------------------------------
# Discoveries
# ---------------------------------------------------------------------------

@router.post(
    "/datastores/{datastore_id}/discoveries",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def record_discovery(
    datastore_id: str,
    body: DiscoveryCreate,
     org_id: str = Query(default="default"),
):
    """Record a data discovery finding for a datastore."""
    try:
        return _get_engine().record_discovery(org_id, datastore_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/discoveries", dependencies=[Depends(api_key_auth)])
def list_discoveries(
     org_id: str = Query(default="default"),
    datastore_id: Optional[str] = Query(None),
    data_type: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
):
    """List discoveries with optional filters."""
    return _get_engine().list_discoveries(
        org_id,
        datastore_id=datastore_id,
        data_type=data_type,
        risk_level=risk_level,
    )


# ---------------------------------------------------------------------------
# Scan Jobs
# ---------------------------------------------------------------------------

@router.post(
    "/datastores/{datastore_id}/scans",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def create_scan_job(
    datastore_id: str,
    body: ScanJobCreate,
     org_id: str = Query(default="default"),
):
    """Create a new scan job for a datastore."""
    return _get_engine().create_scan_job(org_id, datastore_id, body.model_dump())


@router.get("/scans", dependencies=[Depends(api_key_auth)])
def list_scan_jobs(
     org_id: str = Query(default="default"),
    datastore_id: Optional[str] = Query(None),
    scan_status: Optional[str] = Query(None),
):
    """List scan jobs with optional filters."""
    return _get_engine().list_scan_jobs(
        org_id,
        datastore_id=datastore_id,
        scan_status=scan_status,
    )


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_discovery_stats(org_id: str = Query(default="default")):
    """Return aggregated discovery statistics for an org."""
    return _get_engine().get_discovery_stats(org_id)
