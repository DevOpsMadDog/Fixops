"""Dark Web Monitoring Router — ALDECI.

Endpoints for the Dark Web Monitoring engine.

Prefix: /api/v1/dark-web
Auth:   api_key_auth dependency

Routes:
  POST  /api/v1/dark-web/mentions                      add_mention
  GET   /api/v1/dark-web/mentions                      list_mentions
  GET   /api/v1/dark-web/mentions/{id}                 get_mention
  PUT   /api/v1/dark-web/mentions/{id}/status          update_mention_status
  POST  /api/v1/dark-web/keywords                      add_keyword
  GET   /api/v1/dark-web/keywords                      list_keywords
  POST  /api/v1/dark-web/exposures                     record_credential_exposure
  GET   /api/v1/dark-web/exposures                     list_credential_exposures
  GET   /api/v1/dark-web/stats                         get_dark_web_stats
"""

from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/dark-web",
    tags=["Dark Web Monitoring"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.dark_web_monitoring_engine import DarkWebMonitoringEngine
        _engine = DarkWebMonitoringEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class MentionCreate(BaseModel):
    mention_type: str
    source_category: str
    keyword_matched: str
    severity: str = "medium"
    content_preview: str = ""
    source_url: str = ""
    url_hash: str = ""


class MentionStatusUpdate(BaseModel):
    new_status: str


class KeywordCreate(BaseModel):
    keyword: str
    keyword_type: str
    alert_threshold: int = 1


class CredentialExposureCreate(BaseModel):
    email_domain: str
    exposure_count: int = 1
    source: str
    breach_date: Optional[str] = None
    verified: bool = False


# ---------------------------------------------------------------------------
# Mentions
# ---------------------------------------------------------------------------

@router.post("/mentions", dependencies=[Depends(api_key_auth)], status_code=201)
def add_mention(body: MentionCreate, org_id: str = Query(default="default")):
    """Add a new dark web mention."""
    try:
        return _get_engine().add_mention(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/mentions", dependencies=[Depends(api_key_auth)])
def list_mentions(
     org_id: str = Query(default="default"),
    mention_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
):
    """List dark web mentions with optional filters."""
    return _get_engine().list_mentions(
        org_id,
        mention_type=mention_type,
        status=status,
        severity=severity,
    )


@router.get("/mentions/{mention_id}", dependencies=[Depends(api_key_auth)])
def get_mention(mention_id: str, org_id: str = Query(default="default")):
    """Get a single dark web mention by ID."""
    mention = _get_engine().get_mention(org_id, mention_id)
    if not mention:
        raise HTTPException(status_code=404, detail="Mention not found")
    return mention


@router.put("/mentions/{mention_id}/status", dependencies=[Depends(api_key_auth)])
def update_mention_status(
    mention_id: str,
    body: MentionStatusUpdate,
     org_id: str = Query(default="default"),
):
    """Update the status of a dark web mention."""
    try:
        return _get_engine().update_mention_status(org_id, mention_id, body.new_status)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Keywords
# ---------------------------------------------------------------------------

@router.post("/keywords", dependencies=[Depends(api_key_auth)], status_code=201)
def add_keyword(body: KeywordCreate, org_id: str = Query(default="default")):
    """Add a monitored keyword."""
    try:
        return _get_engine().add_keyword(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/keywords", dependencies=[Depends(api_key_auth)])
def list_keywords(
     org_id: str = Query(default="default"),
    keyword_type: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(None),
):
    """List monitored keywords with optional filters."""
    return _get_engine().list_keywords(
        org_id,
        keyword_type=keyword_type,
        is_active=is_active,
    )


# ---------------------------------------------------------------------------
# Credential Exposures
# ---------------------------------------------------------------------------

@router.post("/exposures", dependencies=[Depends(api_key_auth)], status_code=201)
def record_credential_exposure(body: CredentialExposureCreate, org_id: str = Query(default="default")):
    """Record a credential exposure event."""
    try:
        return _get_engine().record_credential_exposure(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/exposures", dependencies=[Depends(api_key_auth)])
def list_credential_exposures(
     org_id: str = Query(default="default"),
    verified: Optional[bool] = Query(None),
):
    """List credential exposures with optional verified filter."""
    return _get_engine().list_credential_exposures(org_id, verified=verified)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/credential-exposures", dependencies=[Depends(api_key_auth)])
def list_credential_exposures_alias(
    org_id: str = Query(default="default"),
    verified: Optional[bool] = Query(None),
):
    """Alias for /exposures — list credential exposures with optional verified filter."""
    return _get_engine().list_credential_exposures(org_id, verified=verified)


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_dark_web_stats(org_id: str = Query(default="default")):
    """Return aggregated dark web monitoring statistics."""
    return _get_engine().get_dark_web_stats(org_id)
