"""API Security Management Router — ALDECI.

Endpoints:
  GET    /api/v1/api-security-engine/apis              list registered API endpoints
  POST   /api/v1/api-security-engine/apis              register an API endpoint
  GET    /api/v1/api-security-engine/keys              list API keys (no raw keys returned)
  POST   /api/v1/api-security-engine/keys              create an API key
  DELETE /api/v1/api-security-engine/keys/{key_id}    revoke an API key
  GET    /api/v1/api-security-engine/abuse-events      list abuse events
  POST   /api/v1/api-security-engine/abuse-events      record an abuse event
  POST   /api/v1/api-security-engine/scan/{api_name}  run OWASP API Top 10 scan
  GET    /api/v1/api-security-engine/stats             get security stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

try:
    from apps.api.auth_deps import api_key_auth as _api_key_auth
    _AUTH_DEP: list = [Depends(_api_key_auth)]
except ImportError:
    logging.getLogger(__name__).warning(
        "api_security_mgmt_router: auth_deps not available, relying on app.py mount-level auth"
    )
    _AUTH_DEP = []

from core.api_security_mgmt_engine import APISecurityEngine

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/api-security-engine",
    tags=["api-security-mgmt"],
    dependencies=_AUTH_DEP,
)

# Shared engine instance
_engine: Optional[APISecurityEngine] = None


def _get_engine() -> APISecurityEngine:
    global _engine
    if _engine is None:
        _engine = APISecurityEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class RegisterApiRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    endpoint_path: str = Field(..., description="API endpoint path e.g. /api/users")
    http_method: str = Field("GET", description="HTTP method")
    service_name: str = Field("", description="Service or microservice name")
    authentication_required: bool = Field(True, description="Whether auth is required")
    rate_limit_per_minute: int = Field(60, description="Rate limit per minute")
    is_public: bool = Field(False, description="Whether endpoint is publicly accessible")
    sensitivity_level: str = Field("internal", description="one of: public/internal/sensitive/critical")
    risk_score: float = Field(0.0, ge=0.0, le=10.0, description="Manual risk score 0-10")


class CreateApiKeyRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    key_name: str = Field(..., description="Human-readable key name")
    owner_id: str = Field("", description="Owner user/service ID")
    scopes: List[str] = Field(default_factory=list, description="Permission scopes")
    rate_limit_per_hour: int = Field(1000, description="Rate limit per hour")
    expires_at: Optional[str] = Field(None, description="ISO expiry timestamp")


class RecordAbuseEventRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    event_type: str = Field(..., description="Abuse event type (bola, injection, auth_bypass, etc.)")
    severity: str = Field("medium", description="one of: critical/high/medium/low")
    source_ip: str = Field("", description="Source IP address")
    api_key_id: str = Field("", description="Associated API key ID if known")
    endpoint_id: str = Field("", description="Associated endpoint ID if known")
    request_payload_preview: str = Field("", description="Sanitised request payload preview")
    status: str = Field("detected", description="one of: detected/investigating/blocked/false_positive")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/apis", summary="List registered API endpoints")
def list_apis(
    org_id: str = Query("default", description="Organisation ID"),
    service_name: Optional[str] = Query(None, description="Filter by service name"),
    sensitivity_level: Optional[str] = Query(None, description="Filter by sensitivity level"),
) -> List[Dict[str, Any]]:
    """List all registered API endpoints for an org."""
    engine = _get_engine()
    return engine.list_endpoints(org_id, service_name=service_name, sensitivity_level=sensitivity_level)


@router.post("/apis", summary="Register an API endpoint")
def register_api(req: RegisterApiRequest) -> Dict[str, Any]:
    """Register a new API endpoint in the security inventory."""
    engine = _get_engine()
    try:
        return engine.register_endpoint(req.org_id, req.model_dump(exclude={"org_id"}))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to register API endpoint: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to register endpoint: {exc}") from exc


@router.get("/keys", summary="List API keys")
def list_api_keys(
    org_id: str = Query("default", description="Organisation ID"),
    status: Optional[str] = Query(None, description="Filter by status: active/revoked/expired"),
) -> List[Dict[str, Any]]:
    """List API keys. Raw key values are never returned — only prefix hints."""
    engine = _get_engine()
    return engine.list_api_keys(org_id, status=status)


@router.post("/keys", summary="Create an API key")
def create_api_key(req: CreateApiKeyRequest) -> Dict[str, Any]:
    """Create a new API key. The raw key is generated internally and never stored in plaintext."""
    engine = _get_engine()
    try:
        return engine.create_api_key(req.org_id, req.model_dump(exclude={"org_id"}))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to create API key: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to create key: {exc}") from exc


@router.delete("/keys/{key_id}", summary="Revoke an API key")
def revoke_api_key(
    key_id: str,
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Revoke an API key by ID."""
    engine = _get_engine()
    revoked = engine.revoke_api_key(org_id, key_id)
    if not revoked:
        raise HTTPException(status_code=404, detail=f"Key '{key_id}' not found for org '{org_id}'")
    return {"revoked": True, "key_id": key_id}


@router.get("/abuse-events", summary="List abuse events")
def list_abuse_events(
    org_id: str = Query("default", description="Organisation ID"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    status: Optional[str] = Query(None, description="Filter by status"),
    limit: int = Query(50, ge=1, le=500, description="Max results"),
) -> List[Dict[str, Any]]:
    """List API abuse events with optional filters."""
    engine = _get_engine()
    return engine.list_abuse_events(org_id, event_type=event_type, severity=severity, status=status, limit=limit)


@router.post("/abuse-events", summary="Record an abuse event")
def record_abuse_event(req: RecordAbuseEventRequest) -> Dict[str, Any]:
    """Record a detected API abuse event."""
    engine = _get_engine()
    try:
        return engine.record_abuse_event(req.org_id, req.model_dump(exclude={"org_id"}))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to record abuse event: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to record event: {exc}") from exc


@router.post("/scan/{api_name}", summary="Run OWASP API Top 10 scan")
def run_owasp_scan(
    api_name: str,
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Initiate an OWASP API Top 10 scan for a named service."""
    engine = _get_engine()
    try:
        scan = engine.create_scan(org_id, {"scan_type": "owasp_api_top10", "target_service": api_name})
        return scan
    except Exception as exc:
        logger.exception("Failed to create scan: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to create scan: {exc}") from exc


@router.get("/stats", summary="Get API security stats")
def get_security_stats(
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Return aggregated API security statistics for an org."""
    engine = _get_engine()
    return engine.get_api_stats(org_id)
