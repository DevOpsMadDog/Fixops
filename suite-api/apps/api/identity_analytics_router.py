"""
Identity Analytics Router — ALDECI.

Prefix: /api/v1/identity-analytics
Auth:   X-API-Key header (injected via Depends(_verify_api_key) in app.py)
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.identity_analytics_engine import get_engine
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/identity-analytics", tags=["identity-analytics"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class RegisterIdentityRequest(BaseModel):
    username: str
    email: str = ""
    department: str = ""
    job_title: str = ""
    identity_type: str = "human"
    privileged: bool = False
    mfa_enabled: bool = False
    last_login: Optional[str] = None
    login_count: int = 0
    failed_logins: int = 0


class IngestLoginEventRequest(BaseModel):
    event_type: str = "login"
    src_ip: str = ""
    geo_country: str = ""
    device_id: str = ""
    success: bool = True
    risk_indicators: List[str] = Field(default_factory=list)
    observed_at: Optional[str] = None


class FlagRiskRequest(BaseModel):
    risk_type: str
    severity: str = "medium"
    description: str = ""
    detected_at: Optional[str] = None


class CreateCertificationRequest(BaseModel):
    reviewer: str = ""
    status: str = "pending"
    access_level: str = ""
    certified_at: Optional[str] = None
    next_review: Optional[str] = None


# ---------------------------------------------------------------------------
# Identity Profiles
# ---------------------------------------------------------------------------

@router.post("/identities")
def register_identity(
    org_id: str = Query(..., description="Organisation ID"),
    body: RegisterIdentityRequest = ...,
) -> Dict[str, Any]:
    """Register a new identity profile."""
    try:
        return get_engine().register_identity(org_id, body.model_dump())
    except Exception as exc:
        _logger.error("register_identity failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/identities")
def list_identities(
     org_id: str = Query(default="default"),
    identity_type: Optional[str] = Query(None),
    privileged_only: bool = Query(False),
    risk_tier: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    """List identity profiles with optional filters."""
    try:
        return get_engine().list_identities(
            org_id,
            identity_type=identity_type,
            privileged_only=privileged_only,
            risk_tier=risk_tier,
        )
    except Exception as exc:
        _logger.error("list_identities failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Login Events
# ---------------------------------------------------------------------------

@router.post("/identities/{identity_id}/events")
def ingest_login_event(
    identity_id: str,
     org_id: str = Query(default="default"),
    body: IngestLoginEventRequest = ...,
) -> Dict[str, Any]:
    """Ingest a login event for an identity. Auto-detects risks."""
    try:
        return get_engine().ingest_login_event(org_id, identity_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        _logger.error("ingest_login_event failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/events")
def list_login_events(
     org_id: str = Query(default="default"),
    identity_id: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
) -> List[Dict[str, Any]]:
    """List login events with optional filters."""
    try:
        return get_engine().list_login_events(
            org_id,
            identity_id=identity_id,
            event_type=event_type,
            limit=limit,
        )
    except Exception as exc:
        _logger.error("list_login_events failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Identity Risks
# ---------------------------------------------------------------------------

@router.post("/identities/{identity_id}/risks")
def flag_risk(
    identity_id: str,
     org_id: str = Query(default="default"),
    body: FlagRiskRequest = ...,
) -> Dict[str, Any]:
    """Manually flag a risk for an identity."""
    try:
        return get_engine().flag_risk(org_id, identity_id, body.model_dump())
    except Exception as exc:
        _logger.error("flag_risk failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/risks")
def list_risks(
     org_id: str = Query(default="default"),
    risk_type: Optional[str] = Query(None),
    resolved: bool = Query(False),
    severity: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    """List identity risks."""
    try:
        return get_engine().list_risks(
            org_id,
            risk_type=risk_type,
            resolved=resolved,
            severity=severity,
        )
    except Exception as exc:
        _logger.error("list_risks failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/risks/{risk_id}/resolve")
def resolve_risk(
    risk_id: str,
     org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Resolve an identity risk."""
    try:
        ok = get_engine().resolve_risk(org_id, risk_id)
        if not ok:
            raise HTTPException(status_code=404, detail="Risk not found or already resolved")
        return {"risk_id": risk_id, "resolved": True}
    except HTTPException:
        raise
    except Exception as exc:
        _logger.error("resolve_risk failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Access Certifications
# ---------------------------------------------------------------------------

@router.post("/identities/{identity_id}/certifications")
def create_certification(
    identity_id: str,
     org_id: str = Query(default="default"),
    body: CreateCertificationRequest = ...,
) -> Dict[str, Any]:
    """Create an access certification record."""
    try:
        return get_engine().create_certification(org_id, identity_id, body.model_dump())
    except Exception as exc:
        _logger.error("create_certification failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/certifications")
def list_certifications(
     org_id: str = Query(default="default"),
    status: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    """List access certifications."""
    try:
        return get_engine().list_certifications(org_id, status=status)
    except Exception as exc:
        _logger.error("list_certifications failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats")
def get_identity_stats(
     org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Get aggregate identity analytics stats for an org."""
    try:
        return get_engine().get_identity_stats(org_id)
    except Exception as exc:
        _logger.error("get_identity_stats failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))
