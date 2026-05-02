"""Digital Identity Router — ALDECI.

Endpoints for the Digital Identity engine.

Prefix: /api/v1/digital-identity
Auth:   api_key_auth dependency

Routes:
  POST /api/v1/digital-identity/profiles                        create_profile
  GET  /api/v1/digital-identity/profiles                        list_profiles
  GET  /api/v1/digital-identity/profiles/{user_id}              get_profile
  PUT  /api/v1/digital-identity/profiles/{user_id}/verify       verify_identity
  PUT  /api/v1/digital-identity/profiles/{user_id}/suspend      suspend_identity
  POST /api/v1/digital-identity/events                          record_verification_event
  GET  /api/v1/digital-identity/events/{user_id}               get_verification_history
  POST /api/v1/digital-identity/attributes/{user_id}            add_attribute
  GET  /api/v1/digital-identity/attributes/{user_id}            list_attributes
  GET  /api/v1/digital-identity/stats                           get_identity_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/digital-identity",
    tags=["Digital Identity"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.digital_identity_engine import DigitalIdentityEngine
        _engine = DigitalIdentityEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ProfileCreate(BaseModel):
    user_id: str
    identity_level: str = "ial1"
    verification_method: str = "self_asserted"
    assurance_level: str = "aal1"
    attributes: Dict[str, Any] = {}


class VerifyRequest(BaseModel):
    verification_method: str = "document"
    identity_level: str = "ial2"


class SuspendRequest(BaseModel):
    reason: str = ""


class EventCreate(BaseModel):
    user_id: str
    event_type: str
    outcome: str = "pending"
    evidence_type: str = ""
    notes: str = ""


class AttributeCreate(BaseModel):
    attribute_name: str
    attribute_value: str
    verified: bool = False
    source: str = ""


# ---------------------------------------------------------------------------
# Profiles
# ---------------------------------------------------------------------------

@router.post("/profiles", dependencies=[Depends(api_key_auth)], status_code=201)
def create_profile(body: ProfileCreate, org_id: str = Query(default="default")):
    """Create a new identity profile."""
    try:
        return _get_engine().create_profile(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/profiles", dependencies=[Depends(api_key_auth)])
def list_profiles(
     org_id: str = Query(default="default"),
    verification_status: Optional[str] = Query(None),
    identity_level: Optional[str] = Query(None),
):
    """List identity profiles with optional filters."""
    return _get_engine().list_profiles(
        org_id,
        verification_status=verification_status,
        identity_level=identity_level,
    )


@router.get("/profiles/{user_id}", dependencies=[Depends(api_key_auth)])
def get_profile(user_id: str, org_id: str = Query(default="default")):
    """Get identity profile by user_id."""
    profile = _get_engine().get_profile(org_id, user_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return profile


@router.put("/profiles/{user_id}/verify", dependencies=[Depends(api_key_auth)])
def verify_identity(user_id: str, body: VerifyRequest, org_id: str = Query(default="default")):
    """Verify an identity profile."""
    try:
        return _get_engine().verify_identity(org_id, user_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.put("/profiles/{user_id}/suspend", dependencies=[Depends(api_key_auth)])
def suspend_identity(user_id: str, body: SuspendRequest, org_id: str = Query(default="default")):
    """Suspend an identity profile."""
    try:
        return _get_engine().suspend_identity(org_id, user_id, body.reason)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

@router.post("/events", dependencies=[Depends(api_key_auth)], status_code=201)
def record_verification_event(body: EventCreate, org_id: str = Query(default="default")):
    """Record a verification event."""
    try:
        return _get_engine().record_verification_event(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/events/{user_id}", dependencies=[Depends(api_key_auth)])
def get_verification_history(
    user_id: str,
     org_id: str = Query(default="default"),
    limit: int = Query(50, ge=1, le=500),
):
    """Get verification event history for a user."""
    return _get_engine().get_verification_history(org_id, user_id, limit=limit)


# ---------------------------------------------------------------------------
# Attributes
# ---------------------------------------------------------------------------

@router.post(
    "/attributes/{user_id}", dependencies=[Depends(api_key_auth)], status_code=201
)
def add_attribute(user_id: str, body: AttributeCreate, org_id: str = Query(default="default")):
    """Add an identity attribute for a user."""
    try:
        return _get_engine().add_attribute(org_id, user_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/attributes/{user_id}", dependencies=[Depends(api_key_auth)])
def list_attributes(user_id: str, org_id: str = Query(default="default")):
    """List identity attributes for a user."""
    return _get_engine().list_attributes(org_id, user_id)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_identity_stats(org_id: str = Query(default="default")):
    """Return aggregated identity statistics."""
    return _get_engine().get_identity_stats(org_id)
