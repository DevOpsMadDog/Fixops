"""API Security Management Engine Router — ALDECI.

Prefix: /api/v1/api-security-engine
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/api-security-engine/endpoints                      register_endpoint
  GET    /api/v1/api-security-engine/endpoints                      list_endpoints
  POST   /api/v1/api-security-engine/keys                           create_api_key
  GET    /api/v1/api-security-engine/keys                           list_api_keys
  POST   /api/v1/api-security-engine/keys/{key_id}/revoke           revoke_api_key
  POST   /api/v1/api-security-engine/abuse-events                   record_abuse_event
  GET    /api/v1/api-security-engine/abuse-events                   list_abuse_events
  POST   /api/v1/api-security-engine/scans                          create_scan
  POST   /api/v1/api-security-engine/scans/{scan_id}/complete       complete_scan
  GET    /api/v1/api-security-engine/scans                          list_scans
  GET    /api/v1/api-security-engine/stats                          get_api_stats
"""

from __future__ import annotations

import logging
from typing import List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/api-security-engine",
    tags=["API Security Engine"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.api_security_mgmt_engine import APISecurityEngine
        _engine = APISecurityEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class EndpointCreate(BaseModel):
    endpoint_path: str
    http_method: str = "GET"
    service_name: str = ""
    authentication_required: bool = True
    rate_limit_per_minute: int = Field(default=60, ge=0)
    is_public: bool = False
    sensitivity_level: str = "internal"
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)


class ApiKeyCreate(BaseModel):
    key_name: str
    owner_id: str = ""
    scopes: List[str] = []
    rate_limit_per_hour: int = Field(default=1000, ge=0)
    expires_at: Optional[str] = None


class AbuseEventCreate(BaseModel):
    event_type: str
    api_key_id: str = ""
    endpoint_id: str = ""
    source_ip: str = ""
    request_payload_preview: str = ""
    severity: str = "medium"
    status: str = "detected"
    detected_at: Optional[str] = None


class ScanCreate(BaseModel):
    scan_type: str = "owasp_api_top10"
    target_service: str = ""


class ScanComplete(BaseModel):
    endpoints_scanned: int = 0
    vulnerabilities_found: int = 0
    critical_count: int = 0


# ---------------------------------------------------------------------------
# Endpoint routes
# ---------------------------------------------------------------------------

@router.post("/endpoints", dependencies=[Depends(api_key_auth)], status_code=201)
def register_endpoint(body: EndpointCreate, org_id: str = Query(default="default")):
    """Register a new API endpoint."""
    try:
        return _get_engine().register_endpoint(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/endpoints", dependencies=[Depends(api_key_auth)])
def list_endpoints(
     org_id: str = Query(default="default"),
    service_name: Optional[str] = Query(None),
    is_public: Optional[bool] = Query(None),
    sensitivity_level: Optional[str] = Query(None),
):
    """List API endpoints with optional filters."""
    return _get_engine().list_endpoints(
        org_id,
        service_name=service_name,
        is_public=is_public,
        sensitivity_level=sensitivity_level,
    )


# ---------------------------------------------------------------------------
# API Key routes
# ---------------------------------------------------------------------------

@router.post("/keys", dependencies=[Depends(api_key_auth)], status_code=201)
def create_api_key(body: ApiKeyCreate, org_id: str = Query(default="default")):
    """Create an API key. Raw key is NOT stored or returned."""
    try:
        return _get_engine().create_api_key(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/keys", dependencies=[Depends(api_key_auth)])
def list_api_keys(
     org_id: str = Query(default="default"),
    status: Optional[str] = Query(None),
):
    """List API keys (hashed_key never exposed)."""
    return _get_engine().list_api_keys(org_id, status=status)


@router.post("/keys/{key_id}/revoke", dependencies=[Depends(api_key_auth)])
def revoke_api_key(key_id: str, org_id: str = Query(default="default")):
    """Revoke an API key."""
    revoked = _get_engine().revoke_api_key(org_id, key_id)
    if not revoked:
        raise HTTPException(status_code=404, detail="API key not found")
    return {"revoked": True, "key_id": key_id}


# ---------------------------------------------------------------------------
# Abuse Event routes
# ---------------------------------------------------------------------------

@router.post("/abuse-events", dependencies=[Depends(api_key_auth)], status_code=201)
def record_abuse_event(body: AbuseEventCreate, org_id: str = Query(default="default")):
    """Record an API abuse event."""
    try:
        return _get_engine().record_abuse_event(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/abuse-events", dependencies=[Depends(api_key_auth)])
def list_abuse_events(
     org_id: str = Query(default="default"),
    event_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(default=50, ge=1, le=500),
):
    """List abuse events with optional filters."""
    return _get_engine().list_abuse_events(
        org_id,
        event_type=event_type,
        severity=severity,
        status=status,
        limit=limit,
    )


# ---------------------------------------------------------------------------
# Scan routes
# ---------------------------------------------------------------------------

@router.post("/scans", dependencies=[Depends(api_key_auth)], status_code=201)
def create_scan(body: ScanCreate, org_id: str = Query(default="default")):
    """Create an API scan job."""
    try:
        return _get_engine().create_scan(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/scans/{scan_id}/complete", dependencies=[Depends(api_key_auth)])
def complete_scan(scan_id: str, body: ScanComplete, org_id: str = Query(default="default")):
    """Mark an API scan as completed with finding counts."""
    completed = _get_engine().complete_scan(org_id, scan_id, body.model_dump())
    if not completed:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"completed": True, "scan_id": scan_id}


@router.get("/scans", dependencies=[Depends(api_key_auth)])
def list_scans(
     org_id: str = Query(default="default"),
    status: Optional[str] = Query(None),
):
    """List API scans with optional status filter."""
    return _get_engine().list_scans(org_id, status=status)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_api_stats(org_id: str = Query(default="default")):
    """Return aggregated API security statistics for the org."""
    return _get_engine().get_api_stats(org_id)


@router.get("/", summary="API security engine index", tags=["api-security-engine"])
def api_security_index(org_id: str = Query("default"), _auth: None = Depends(api_key_auth)):
    """Return API security engine summary and registered endpoints for the org."""
    engine = _get_engine()
    try:
        stats = engine.get_api_stats(org_id=org_id)
    except Exception:
        stats = {}
    try:
        items = engine.list_endpoints(org_id=org_id)
    except Exception:
        items = []
    return {"router": "api-security-engine", "org_id": org_id, "stats": stats, "items": items, "count": len(items)}
