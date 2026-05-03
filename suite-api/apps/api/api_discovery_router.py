"""API Discovery Router — ALDECI.

Endpoints for the API Discovery engine.

Prefix: /api/v1/api-discovery
Auth:   api_key_auth dependency

Routes:
  POST /api/v1/api-discovery/endpoints                       register_endpoint
  GET  /api/v1/api-discovery/endpoints                       list_endpoints
  GET  /api/v1/api-discovery/endpoints/{id}                  get_endpoint
  PUT  /api/v1/api-discovery/endpoints/{id}/mark-shadow      mark_as_shadow
  PUT  /api/v1/api-discovery/endpoints/{id}/mark-documented  mark_as_documented
  POST /api/v1/api-discovery/endpoints/{id}/link-layer       link_endpoint_to_layer
  POST /api/v1/api-discovery/scans                           create_scan
  PUT  /api/v1/api-discovery/scans/{id}/complete             complete_scan
  POST /api/v1/api-discovery/changes                         record_change
  GET  /api/v1/api-discovery/changes                         list_changes
  GET  /api/v1/api-discovery/stats                           get_api_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/api-discovery",
    tags=["API Discovery"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.api_discovery_engine import APIDiscoveryEngine
        _engine = APIDiscoveryEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class EndpointCreate(BaseModel):
    org_id: str = "default"
    service_name: str
    endpoint_path: str
    http_method: str
    version: str = ""
    api_type: str = "rest"
    auth_required: bool = True
    is_documented: bool = False
    is_shadow: bool = False
    risk_level: str = "none"


class ScanCreate(BaseModel):
    org_id: str = "default"
    scan_name: str
    scan_target: str
    scan_type: str = "passive"


class ScanComplete(BaseModel):
    endpoints_found: int = 0
    shadow_apis_found: int = 0


class ChangeCreate(BaseModel):
    org_id: str = "default"
    endpoint_id: str
    change_type: str
    change_description: str = ""


class LinkLayerRequest(BaseModel):
    org_id: str = "default"
    layer: str = "api"


# ---------------------------------------------------------------------------
# Endpoint Routes
# ---------------------------------------------------------------------------

@router.post("/endpoints", status_code=201)
async def register_endpoint(body: EndpointCreate) -> Dict[str, Any]:
    """Register a discovered API endpoint."""
    try:
        return _get_engine().register_endpoint(body.org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/endpoints")
async def list_endpoints(
    org_id: str = Query("default"),
    service_name: Optional[str] = Query(None),
    is_shadow: Optional[bool] = Query(None),
    risk_level: Optional[str] = Query(None),
    api_type: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    """List API endpoints with optional filters."""
    return _get_engine().list_endpoints(
        org_id,
        service_name=service_name,
        is_shadow=is_shadow,
        risk_level=risk_level,
        api_type=api_type,
    )


@router.get("/endpoints/{endpoint_id}")
async def get_endpoint(
    endpoint_id: str,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Get an API endpoint by UUID."""
    result = _get_engine().get_endpoint(org_id, endpoint_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Endpoint '{endpoint_id}' not found.")
    return result


@router.put("/endpoints/{endpoint_id}/mark-shadow")
async def mark_as_shadow(
    endpoint_id: str,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Mark an endpoint as a shadow API."""
    try:
        return _get_engine().mark_as_shadow(org_id, endpoint_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.put("/endpoints/{endpoint_id}/mark-documented")
async def mark_as_documented(
    endpoint_id: str,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Mark an endpoint as documented."""
    try:
        return _get_engine().mark_as_documented(org_id, endpoint_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/endpoints/{endpoint_id}/link-layer", status_code=200)
async def link_endpoint_to_layer(
    endpoint_id: str,
    body: LinkLayerRequest,
) -> Dict[str, Any]:
    """Link a discovered endpoint to its architecture layer (api/service/data/ui/standalone).

    Resolves the endpoint_path from the registry and delegates the layer
    classification write to SecurityDependencyMappingEngine.  Fails with 404
    when the endpoint does not exist in the requested org.  Fails with 422 when
    the layer value is invalid.  Succeeds with linked=False when the dep-map
    engine is unavailable (graceful degradation).
    """
    engine = _get_engine()
    ep = engine.get_endpoint(body.org_id, endpoint_id)
    if ep is None:
        raise HTTPException(
            status_code=404,
            detail=f"Endpoint '{endpoint_id}' not found in org '{body.org_id}'.",
        )
    try:
        return engine.link_to_layer(
            org_id=body.org_id,
            endpoint_path=ep["endpoint_path"],
            layer=body.layer,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


# ---------------------------------------------------------------------------
# Scan Routes
# ---------------------------------------------------------------------------

@router.post("/scans", status_code=201)
async def create_scan(body: ScanCreate) -> Dict[str, Any]:
    """Create a new API discovery scan."""
    try:
        return _get_engine().create_scan(body.org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.put("/scans/{scan_id}/complete")
async def complete_scan(
    scan_id: str,
    body: ScanComplete,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Mark a scan as completed with results."""
    try:
        return _get_engine().complete_scan(org_id, scan_id, body.model_dump())
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


# ---------------------------------------------------------------------------
# Change Routes
# ---------------------------------------------------------------------------

@router.post("/changes", status_code=201)
async def record_change(body: ChangeCreate) -> Dict[str, Any]:
    """Record an API change event."""
    try:
        return _get_engine().record_change(body.org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/changes")
async def list_changes(
    org_id: str = Query("default"),
    endpoint_id: Optional[str] = Query(None),
    change_type: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
) -> List[Dict[str, Any]]:
    """List API change events with optional filters."""
    return _get_engine().list_changes(
        org_id, endpoint_id=endpoint_id, change_type=change_type, limit=limit
    )


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats")
async def get_api_stats(
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Return aggregate API discovery stats."""
    return _get_engine().get_api_stats(org_id)
