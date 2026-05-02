"""Physical Security Router — ALDECI.

Location registration, access event logging, and incident management.

Prefix: /api/v1/physical-security
Auth: api_key_auth dependency

Routes:
  POST  /api/v1/physical-security/locations                          register_location
  GET   /api/v1/physical-security/locations                          list_locations
  GET   /api/v1/physical-security/locations/{location_id}            get_location
  POST  /api/v1/physical-security/events                             record_access_event
  GET   /api/v1/physical-security/events                             list_access_events
  POST  /api/v1/physical-security/incidents                          record_incident
  PUT   /api/v1/physical-security/incidents/{incident_id}/resolve    resolve_incident
  GET   /api/v1/physical-security/stats                              get_physical_stats
"""

from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/physical-security",
    tags=["Physical Security"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.physical_security_engine import PhysicalSecurityEngine
        _engine = PhysicalSecurityEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class RegisterLocationRequest(BaseModel):
    name: str = Field(..., description="Location name")
    location_type: str = Field(
        ..., description="office | datacenter | warehouse | facility | remote"
    )
    address: Optional[str] = Field(default=None, description="Physical address")
    security_level: str = Field(
        default="medium", description="low | medium | high | critical"
    )
    capacity: Optional[int] = Field(default=None, description="Max occupancy")


class RecordAccessEventRequest(BaseModel):
    location_id: str = Field(..., description="Target location ID")
    person_id: str = Field(..., description="Person or badge ID")
    access_type: str = Field(
        ..., description="entry | exit | attempt | denied"
    )
    method: str = Field(
        ..., description="badge | biometric | pin | key | tailgate"
    )
    timestamp: Optional[str] = Field(
        default=None, description="ISO timestamp (defaults to now)"
    )


class RecordIncidentRequest(BaseModel):
    location_id: str = Field(..., description="Location where incident occurred")
    incident_type: str = Field(
        ...,
        description="tailgating | unauthorized_access | theft | vandalism | fire | flood | other",
    )
    severity: str = Field(..., description="low | medium | high | critical")
    description: Optional[str] = Field(default=None, description="Incident details")


class ResolveIncidentRequest(BaseModel):
    resolution: str = Field(..., description="Description of resolution taken")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/locations", dependencies=[Depends(api_key_auth)], status_code=201)
def register_location(
    body: RegisterLocationRequest,
    org_id: str = Query(default="default"),
):
    """Register a new physical location."""
    try:
        from core.physical_security_engine import LocationCreate
        return _get_engine().register_location(
            org_id,
            LocationCreate(**body.model_dump()),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error registering location")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/locations", dependencies=[Depends(api_key_auth)])
def list_locations(
    org_id: str = Query(default="default"),
    location_type: Optional[str] = Query(default=None),
    security_level: Optional[str] = Query(default=None),
):
    """List physical locations, optionally filtered by type or security level."""
    return _get_engine().list_locations(
        org_id, location_type=location_type, security_level=security_level
    )


@router.get("/locations/{location_id}", dependencies=[Depends(api_key_auth)])
def get_location(
    location_id: str,
    org_id: str = Query(default="default"),
):
    """Get a specific location by ID."""
    try:
        return _get_engine().get_location(org_id, location_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error fetching location")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/events", dependencies=[Depends(api_key_auth)], status_code=201)
def record_access_event(
    body: RecordAccessEventRequest,
    org_id: str = Query(default="default"),
):
    """Record a physical access event."""
    try:
        from core.physical_security_engine import AccessEventCreate
        return _get_engine().record_access_event(
            org_id,
            AccessEventCreate(**body.model_dump()),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error recording access event")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/events", dependencies=[Depends(api_key_auth)])
def list_access_events(
    org_id: str = Query(default="default"),
    location_id: Optional[str] = Query(default=None),
    access_type: Optional[str] = Query(default=None),
):
    """List access events, optionally filtered by location or access type."""
    return _get_engine().list_access_events(
        org_id, location_id=location_id, access_type=access_type
    )


@router.post("/incidents", dependencies=[Depends(api_key_auth)], status_code=201)
def record_incident(
    body: RecordIncidentRequest,
    org_id: str = Query(default="default"),
):
    """Record a new physical security incident."""
    try:
        from core.physical_security_engine import IncidentCreate
        return _get_engine().record_incident(
            org_id,
            IncidentCreate(**body.model_dump()),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error recording incident")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.put("/incidents/{incident_id}/resolve", dependencies=[Depends(api_key_auth)])
def resolve_incident(
    incident_id: str,
    body: ResolveIncidentRequest,
    org_id: str = Query(default="default"),
):
    """Resolve an open physical security incident."""
    try:
        return _get_engine().resolve_incident(org_id, incident_id, body.resolution)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error resolving incident")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_physical_stats(org_id: str = Query(default="default")):
    """Return physical security overview stats."""
    return _get_engine().get_physical_stats(org_id)
