"""UBA Router — User Behavior Analytics endpoints.

10 endpoints:
  POST   /api/v1/uba/users                    register_user
  GET    /api/v1/uba/users                    list_users
  GET    /api/v1/uba/users/{user_id}          get_user
  POST   /api/v1/uba/users/{user_id}/analyze  analyze_user
  POST   /api/v1/uba/events                   ingest_event
  GET    /api/v1/uba/events                   list_events
  POST   /api/v1/uba/alerts                   create_alert
  GET    /api/v1/uba/alerts                   list_alerts
  PATCH  /api/v1/uba/alerts/{alert_id}/status update_alert_status
  GET    /api/v1/uba/stats                    get_uba_stats
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
        "uba_router: auth_deps not available, relying on app.py mount-level auth"
    )
    _AUTH_DEP = []

from core.uba_engine import UBAEngine

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/uba",
    tags=["uba"],
    dependencies=_AUTH_DEP,
)

# Shared engine instance (SQLite-backed, shared across requests)
_engine = None  # lazy-initialised on first request


def _get_engine():
    global _engine
    if _engine is None:
        _engine = UBAEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request / Response Models
# ---------------------------------------------------------------------------

class RegisterUserRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    username: str = Field(..., description="Unique username within the org")
    department: str = Field("", description="User's department")
    role: str = Field("", description="User's job role")
    manager: str = Field("", description="Manager's username or ID")
    status: str = Field("active", description="active | suspended | terminated")
    last_seen: Optional[str] = Field(None, description="ISO-8601 datetime of last activity")


class IngestEventRequest(BaseModel):
    org_id: str
    user_id: str
    event_type: str = Field(
        ...,
        description=(
            "login | file_access | email_send | data_download | usb_use | "
            "vpn_login | after_hours_access | privilege_use | failed_login"
        ),
    )
    source_ip: str = Field("", description="Source IP address")
    device: str = Field("", description="Device identifier or hostname")
    timestamp: Optional[str] = Field(None, description="ISO-8601 event timestamp")
    bytes_transferred: int = Field(0, ge=0, description="Bytes transferred (for download events)")
    is_anomalous: bool = Field(False, description="Whether this event was flagged anomalous")


class CreateAlertRequest(BaseModel):
    org_id: str
    user_id: str
    alert_type: str = Field(..., description="Type/category of the alert")
    severity: str = Field("medium", description="low | medium | high | critical")
    description: str = Field("", description="Human-readable alert description")


class UpdateAlertStatusRequest(BaseModel):
    org_id: str
    status: str = Field(..., description="open | investigating | resolved | false_positive")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/users", summary="Register a user profile")
def register_user(req: RegisterUserRequest) -> Dict[str, Any]:
    try:
        return _get_engine().register_user(req.org_id, req.model_dump(exclude={"org_id"}))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.exception("register_user error")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/users", summary="List user profiles")
def list_users(
     org_id: str = Query(default="default"),
    status: Optional[str] = Query(None),
    min_risk_score: Optional[int] = Query(None, ge=0, le=100),
) -> List[Dict[str, Any]]:
    try:
        return _get_engine().list_users(org_id, status=status, min_risk_score=min_risk_score)
    except Exception as exc:
        logger.exception("list_users error")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/users/{user_id}", summary="Get a user profile")
def get_user(
    user_id: str,
     org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    result = _get_engine().get_user(org_id, user_id)
    if result is None:
        raise HTTPException(status_code=404, detail="User not found")
    return result


@router.post("/users/{user_id}/analyze", summary="Analyze user risk")
def analyze_user(
    user_id: str,
     org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    try:
        return _get_engine().analyze_user(org_id, user_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        logger.exception("analyze_user error")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/events", summary="Ingest a user behavior event")
def ingest_event(req: IngestEventRequest) -> Dict[str, Any]:
    try:
        return _get_engine().ingest_event(req.org_id, req.model_dump(exclude={"org_id"}))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.exception("ingest_event error")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/events", summary="List user behavior events")
def list_events(
     org_id: str = Query(default="default"),
    user_id: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    is_anomalous: Optional[bool] = Query(None),
) -> List[Dict[str, Any]]:
    try:
        return _get_engine().list_events(
            org_id,
            user_id=user_id,
            event_type=event_type,
            is_anomalous=is_anomalous,
        )
    except Exception as exc:
        logger.exception("list_events error")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/alerts", summary="Create a UBA alert")
def create_alert(req: CreateAlertRequest) -> Dict[str, Any]:
    try:
        return _get_engine().create_alert(
            req.org_id,
            req.user_id,
            req.alert_type,
            req.severity,
            req.description,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.exception("create_alert error")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/alerts", summary="List UBA alerts")
def list_alerts(
     org_id: str = Query(default="default"),
    status: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    try:
        return _get_engine().list_alerts(org_id, status=status)
    except Exception as exc:
        logger.exception("list_alerts error")
        raise HTTPException(status_code=500, detail=str(exc))


@router.patch("/alerts/{alert_id}/status", summary="Update alert status")
def update_alert_status(
    alert_id: str,
    req: UpdateAlertStatusRequest,
) -> Dict[str, Any]:
    try:
        updated = _get_engine().update_alert_status(req.org_id, alert_id, req.status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not updated:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"alert_id": alert_id, "status": req.status, "updated": True}


@router.get("/stats", summary="UBA aggregate statistics")
def get_uba_stats(org_id: str = Query(default="default")) -> Dict[str, Any]:
    try:
        return _get_engine().get_uba_stats(org_id)
    except Exception as exc:
        logger.exception("get_uba_stats error")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/health", summary="UBA service health check")
def uba_health() -> Dict[str, Any]:
    """Health check for the User Behavior Analytics service."""
    try:
        engine = _get_engine()
        stats = engine.get_uba_stats("default")
        return {
            "status": "healthy",
            "service": "aldeci-uba",
            "version": "1.0.0",
            "users_tracked": stats.get("total_users", 0),
            "alerts_open": stats.get("open_alerts", 0),
        }
    except Exception as exc:
        logger.exception("uba_health error")
        return {"status": "degraded", "service": "aldeci-uba", "error": str(exc)}


@router.get("/status", summary="UBA service status alias")
def uba_status() -> Dict[str, Any]:
    """Status alias — delegates to /health."""
    return uba_health()
