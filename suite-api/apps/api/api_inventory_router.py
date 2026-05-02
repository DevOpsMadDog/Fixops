"""API Inventory Router — ALDECI.

Prefix: /api/v1/api-inventory
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/api-inventory/apis                        register_api
  GET    /api/v1/api-inventory/apis                        list_apis
  GET    /api/v1/api-inventory/apis/{api_id}               get_api
  PATCH  /api/v1/api-inventory/apis/{api_id}/status        update_api_status
  POST   /api/v1/api-inventory/apis/{api_id}/endpoints     add_endpoint
  GET    /api/v1/api-inventory/endpoints                   list_endpoints
  GET    /api/v1/api-inventory/stats                       get_api_stats
"""

from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/api-inventory",
    tags=["API Inventory"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.api_inventory_engine import APIInventoryEngine
        _engine = APIInventoryEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class APICreate(BaseModel):
    api_name: str
    api_type: str = "rest"
    version: str = ""
    base_url: str = ""
    auth_type: str = "none"
    owner_team: str = ""
    documentation_url: str = ""
    risk_level: str = "none"


class APIStatusUpdate(BaseModel):
    new_status: str


class EndpointCreate(BaseModel):
    method: str = "GET"
    path: str = ""
    description: str = ""
    is_authenticated: bool = True
    is_documented: bool = True
    risk_level: str = "none"
    request_count: int = Field(default=0, ge=0)


# ---------------------------------------------------------------------------
# API routes
# ---------------------------------------------------------------------------

@router.post("/apis", dependencies=[Depends(api_key_auth)], status_code=201)
def register_api(body: APICreate, org_id: str = Query(default="default")):
    """Register a new API."""
    try:
        return _get_engine().register_api(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/apis", dependencies=[Depends(api_key_auth)])
def list_apis(
     org_id: str = Query(default="default"),
    api_type: Optional[str] = Query(None),
    api_status: Optional[str] = Query(None),
):
    """List APIs with optional filters."""
    return _get_engine().list_apis(org_id, api_type=api_type, api_status=api_status)


@router.get("/apis/{api_id}", dependencies=[Depends(api_key_auth)])
def get_api(api_id: str, org_id: str = Query(default="default")):
    """Get a single API by ID."""
    api = _get_engine().get_api(org_id, api_id)
    if not api:
        raise HTTPException(status_code=404, detail="API not found")
    return api


@router.patch("/apis/{api_id}/status", dependencies=[Depends(api_key_auth)])
def update_api_status(api_id: str, body: APIStatusUpdate, org_id: str = Query(default="default")):
    """Update an API's status."""
    try:
        result = _get_engine().update_api_status(org_id, api_id, body.new_status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not result:
        raise HTTPException(status_code=404, detail="API not found")
    return result


# ---------------------------------------------------------------------------
# Endpoint routes
# ---------------------------------------------------------------------------

@router.post("/apis/{api_id}/endpoints", dependencies=[Depends(api_key_auth)], status_code=201)
def add_endpoint(api_id: str, body: EndpointCreate, org_id: str = Query(default="default")):
    """Add an endpoint to an API."""
    try:
        return _get_engine().add_endpoint(org_id, api_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/endpoints", dependencies=[Depends(api_key_auth)])
def list_endpoints(
     org_id: str = Query(default="default"),
    api_id: Optional[str] = Query(None),
    method: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
):
    """List endpoints with optional filters."""
    return _get_engine().list_endpoints(
        org_id, api_id=api_id, method=method, risk_level=risk_level
    )


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_api_stats(org_id: str = Query(default="default")):
    """Return aggregated API inventory statistics for the org."""
    return _get_engine().get_api_stats(org_id)
