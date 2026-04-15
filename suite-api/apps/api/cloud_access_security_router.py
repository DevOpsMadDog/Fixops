"""Cloud Access Security Router — ALDECI.

CASB-style cloud application access control via REST endpoints.

Prefix: /api/v1/cloud-access-security

Endpoints:
  POST  /apps               — Register a cloud app
  GET   /apps               — List cloud apps (app_category, risk_level, sanctioned)
  GET   /apps/{id}          — Get a single cloud app
  POST  /events             — Record an access event
  POST  /policies           — Create a policy
  GET   /policies           — List policies (enabled, app_category)
  GET   /stats              — Cloud access stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/cloud-access-security",
    tags=["cloud-access-security"],
)

# ---------------------------------------------------------------------------
# Lazy engine loader
# ---------------------------------------------------------------------------

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        try:
            from core.cloud_access_security_engine import CloudAccessSecurityEngine
            _engine = CloudAccessSecurityEngine()
        except ImportError as exc:
            logger.error("cloud_access_security_engine import failed: %s", exc)
            raise HTTPException(
                status_code=503,
                detail=f"cloud_access_security unavailable: {exc}",
            )
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class RegisterCloudAppRequest(BaseModel):
    org_id: str = "default"
    name: str
    app_category: str = "saas"
    vendor: str = ""
    risk_level: str = "medium"
    data_exposure_level: str = "internal"
    sanctioned: bool = True
    discovered_at: Optional[str] = None


class RecordAccessEventRequest(BaseModel):
    org_id: str = "default"
    app_id: str
    user_id: str = ""
    access_type: str = "oauth"
    data_accessed: str = ""
    bytes_transferred: int = 0
    source_ip: str = ""
    success: bool = True
    occurred_at: Optional[str] = None


class CreatePolicyRequest(BaseModel):
    org_id: str = "default"
    name: str = ""
    app_category: str = "saas"
    policy_action: str = "monitor"
    conditions_json: Dict[str, Any] = {}
    enabled: bool = True


# ---------------------------------------------------------------------------
# Endpoints — Cloud Apps
# ---------------------------------------------------------------------------


@router.post("/apps", status_code=201)
def register_cloud_app(body: RegisterCloudAppRequest) -> Dict[str, Any]:
    """Register a cloud application."""
    engine = _get_engine()
    try:
        return engine.register_cloud_app(body.org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/apps")
def list_cloud_apps(
    org_id: str = Query(default="default"),
    app_category: Optional[str] = Query(default=None),
    risk_level: Optional[str] = Query(default=None),
    sanctioned: Optional[bool] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List cloud apps with optional filters."""
    engine = _get_engine()
    return engine.list_cloud_apps(
        org_id,
        app_category=app_category,
        risk_level=risk_level,
        sanctioned=sanctioned,
    )


@router.get("/apps/{app_id}")
def get_cloud_app(
    app_id: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Get a single cloud app by ID."""
    engine = _get_engine()
    app = engine.get_cloud_app(org_id, app_id)
    if app is None:
        raise HTTPException(status_code=404, detail=f"Cloud app {app_id!r} not found.")
    return app


# ---------------------------------------------------------------------------
# Endpoints — Access Events
# ---------------------------------------------------------------------------


@router.post("/events", status_code=201)
def record_access_event(body: RecordAccessEventRequest) -> Dict[str, Any]:
    """Record a cloud app access event."""
    engine = _get_engine()
    try:
        return engine.record_access_event(body.org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# ---------------------------------------------------------------------------
# Endpoints — Policies
# ---------------------------------------------------------------------------


@router.post("/policies", status_code=201)
def create_policy(body: CreatePolicyRequest) -> Dict[str, Any]:
    """Create a cloud access policy."""
    engine = _get_engine()
    try:
        return engine.create_policy(body.org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/policies")
def list_policies(
    org_id: str = Query(default="default"),
    enabled: Optional[bool] = Query(default=None),
    app_category: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List policies with optional filters."""
    engine = _get_engine()
    return engine.list_policies(
        org_id,
        enabled=enabled,
        app_category=app_category,
    )


# ---------------------------------------------------------------------------
# Endpoints — Stats
# ---------------------------------------------------------------------------


@router.get("/stats")
def get_cloud_access_stats(
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Return cloud access security statistics for an org."""
    engine = _get_engine()
    return engine.get_cloud_access_stats(org_id)
