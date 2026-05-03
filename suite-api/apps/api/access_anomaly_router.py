"""Access Anomaly Router — ALDECI.

Endpoints for the Access Anomaly Detection engine.

Prefix: /api/v1/access-anomaly
Auth:   api_key_auth dependency

Routes:
  POST  /api/v1/access-anomaly/events                            record_event
  POST  /api/v1/access-anomaly/events/{id}/detect-anomalies      detect_anomalies
  POST  /api/v1/access-anomaly/baseline                          upsert_baseline
  POST  /api/v1/access-anomaly/impossible-travel/{username}      detect_impossible_travel
  POST  /api/v1/access-anomaly/anomalies/{id}/resolve            resolve_anomaly
  GET   /api/v1/access-anomaly/anomalies                         list_anomalies
  GET   /api/v1/access-anomaly/users/{username}/profile          get_user_risk_profile
  GET   /api/v1/access-anomaly/high-risk-users                   get_high_risk_users
  GET   /api/v1/access-anomaly/summary                           get_summary
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/access-anomaly",
    tags=["Access Anomaly"],
    dependencies=[Depends(api_key_auth)],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.access_anomaly_engine import AccessAnomalyEngine
        _engine = AccessAnomalyEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class EventCreate(BaseModel):
    org_id: str
    username: str
    source_ip: str = ""
    country: str = ""
    city: str = ""
    access_time: Optional[str] = None
    resource: str = ""
    action: str = ""
    success: int = 1


class DetectAnomaliesRequest(BaseModel):
    org_id: str
    username: str


class BaselineUpsert(BaseModel):
    org_id: str
    username: str
    typical_countries: List[str] = []
    typical_hours: List[int] = []
    typical_resources: List[str] = []
    avg_daily_events: float = 0.0


class ImpossibleTravelRequest(BaseModel):
    org_id: str
    hours_window: float = 4.0


class ResolveRequest(BaseModel):
    org_id: str


class ScmAnomalyCreate(BaseModel):
    org_id: str
    author_email: str
    anomaly_type: str
    evidence_json: Optional[Any] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/")
def list_access_anomaly(org_id: str = Query("default")) -> Dict[str, Any]:
    """Get access anomaly summary for the org."""
    return _get_engine().get_summary(org_id=org_id)


@router.post("/events")
def record_event(body: EventCreate) -> Dict[str, Any]:
    return _get_engine().record_event(
        org_id=body.org_id,
        username=body.username,
        source_ip=body.source_ip,
        country=body.country,
        city=body.city,
        access_time=body.access_time,
        resource=body.resource,
        action=body.action,
        success=body.success,
    )


@router.post("/events/{event_id}/detect-anomalies")
def detect_anomalies(event_id: str, body: DetectAnomaliesRequest) -> List[Dict[str, Any]]:
    try:
        return _get_engine().detect_anomalies(
            org_id=body.org_id,
            username=body.username,
            event_id=event_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/baseline")
def upsert_baseline(body: BaselineUpsert) -> Dict[str, Any]:
    return _get_engine().upsert_baseline(
        org_id=body.org_id,
        username=body.username,
        typical_countries=body.typical_countries,
        typical_hours=body.typical_hours,
        typical_resources=body.typical_resources,
        avg_daily_events=body.avg_daily_events,
    )


@router.post("/impossible-travel/{username}")
def detect_impossible_travel(
    username: str, body: ImpossibleTravelRequest
) -> List[Dict[str, Any]]:
    return _get_engine().detect_impossible_travel(
        org_id=body.org_id,
        username=username,
        hours_window=body.hours_window,
    )


@router.post("/anomalies/{anomaly_id}/resolve")
def resolve_anomaly(anomaly_id: str, body: ResolveRequest) -> Dict[str, Any]:
    try:
        return _get_engine().resolve_anomaly(
            anomaly_id=anomaly_id,
            org_id=body.org_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/anomalies")
def list_anomalies(
     org_id: str = Query(default="default"),
    status: Optional[str] = Query(None),
    anomaly_type: Optional[str] = Query(None),
    username: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    return _get_engine().list_anomalies(
        org_id=org_id,
        status=status,
        anomaly_type=anomaly_type,
        username=username,
    )


@router.get("/users/{username}/profile")
def get_user_risk_profile(
    username: str,
     org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    return _get_engine().get_user_risk_profile(org_id=org_id, username=username)


@router.get("/high-risk-users")
def get_high_risk_users(
     org_id: str = Query(default="default"),
    min_anomaly_count: int = Query(3),
) -> List[Dict[str, Any]]:
    return _get_engine().get_high_risk_users(
        org_id=org_id, min_anomaly_count=min_anomaly_count
    )


@router.get("/summary")
def get_summary(org_id: str = Query(default="default")) -> Dict[str, Any]:
    return _get_engine().get_summary(org_id=org_id)


# ---------------------------------------------------------------------------
# SCM anomaly signals (developer identity / commit-derived)
# ---------------------------------------------------------------------------

@router.post("/scm-anomalies")
def record_scm_anomaly(body: ScmAnomalyCreate) -> Dict[str, Any]:
    """Record an SCM commit-derived anomaly for a developer identity."""
    try:
        return _get_engine().record_scm_anomaly(
            org_id=body.org_id,
            author_email=body.author_email,
            anomaly_type=body.anomaly_type,
            evidence_json=body.evidence_json,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/scm-anomalies")
def list_scm_anomalies(
    org_id: str = Query(default="default"),
    author_email: Optional[str] = Query(None),
    anomaly_type: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    """List SCM anomaly signals with optional filters."""
    return _get_engine().list_scm_anomalies(
        org_id=org_id,
        author_email=author_email,
        anomaly_type=anomaly_type,
    )
