"""Endpoint Threat Hunting API router — ALDECI.

Endpoints at /api/v1/endpoint-hunting/* for hunt campaigns, findings, IOCs, and stats.
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
        "endpoint_threat_hunting_router: auth_deps not available, relying on app-level auth"
    )
    _AUTH_DEP = []

from core.endpoint_threat_hunting_engine import EndpointThreatHuntingEngine

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/endpoint-hunting",
    tags=["Endpoint Threat Hunting"],
    dependencies=_AUTH_DEP,
)

_engine: Optional[EndpointThreatHuntingEngine] = None


def _get_engine() -> EndpointThreatHuntingEngine:
    global _engine
    if _engine is None:
        _engine = EndpointThreatHuntingEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class CreateHuntRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    hunt_name: str = Field(..., min_length=1, description="Name of the hunt")
    hypothesis: str = Field("", description="Hunt hypothesis")
    hunt_type: str = Field("proactive", description="proactive/reactive/scheduled/automated")
    technique_ids: List[str] = Field(default_factory=list, description="MITRE ATT&CK technique IDs")
    hunter: str = Field("", description="Analyst running the hunt")


class StartHuntRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")


class CompleteHuntRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    endpoints_scanned: int = Field(0, ge=0, description="Number of endpoints scanned")


class RecordFindingRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    hunt_id: str = Field(..., description="Associated hunt ID")
    endpoint_id: str = Field("", description="Endpoint where finding was detected")
    finding_type: str = Field("malware", description="Finding type")
    severity: str = Field("medium", description="Severity: critical/high/medium/low")
    process_name: str = Field("", description="Process name")
    command_line: str = Field("", description="Command line observed")
    file_path: str = Field("", description="File path involved")
    status: str = Field("new", description="Finding status")
    detected_at: Optional[str] = Field(None, description="ISO-8601 detection timestamp")


class UpdateFindingStatusRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    status: str = Field(..., description="new/investigating/confirmed/false_positive/remediated")


class AddIocRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    hunt_id: str = Field(..., description="Associated hunt ID")
    ioc_value: str = Field(..., description="IOC value (hash, IP, domain, etc.)")
    ioc_type: str = Field("hash", description="hash/ip/domain/path/registry_key/mutex/process_name/user_agent")
    confidence_score: float = Field(0.0, ge=0.0, le=100.0, description="Confidence 0-100")
    endpoints_matched: int = Field(0, ge=0, description="Number of endpoints matched")


# ---------------------------------------------------------------------------
# Hunts
# ---------------------------------------------------------------------------


@router.post("/hunts", summary="Create a threat hunt campaign")
def create_hunt(body: CreateHuntRequest) -> Dict[str, Any]:
    """Create a new endpoint threat hunt campaign."""
    engine = _get_engine()
    try:
        return engine.create_hunt(body.org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to create hunt")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/hunts", summary="List threat hunts")
def list_hunts(
    org_id: str = Query("default", description="Organisation ID"),
    status: Optional[str] = Query(None, description="Filter by status"),
    hunt_type: Optional[str] = Query(None, description="Filter by hunt type"),
) -> List[Dict[str, Any]]:
    """List threat hunt campaigns with optional filters."""
    engine = _get_engine()
    try:
        return engine.list_hunts(org_id, status=status, hunt_type=hunt_type)
    except Exception as exc:
        logger.exception("Failed to list hunts")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/hunts/{hunt_id}", summary="Get a threat hunt by ID")
def get_hunt(
    hunt_id: str,
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Get a specific threat hunt campaign."""
    engine = _get_engine()
    try:
        result = engine.get_hunt(org_id, hunt_id)
        if result is None:
            raise HTTPException(status_code=404, detail="Hunt not found")
        return result
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Failed to get hunt %s", hunt_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.put("/hunts/{hunt_id}/start", summary="Start a threat hunt")
def start_hunt(hunt_id: str, body: StartHuntRequest) -> Dict[str, Any]:
    """Set hunt status to active and record started_at timestamp."""
    engine = _get_engine()
    try:
        return engine.start_hunt(body.org_id, hunt_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to start hunt %s", hunt_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.put("/hunts/{hunt_id}/complete", summary="Complete a threat hunt")
def complete_hunt(hunt_id: str, body: CompleteHuntRequest) -> Dict[str, Any]:
    """Mark a hunt as completed and record endpoints scanned."""
    engine = _get_engine()
    try:
        return engine.complete_hunt(body.org_id, hunt_id, body.endpoints_scanned)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to complete hunt %s", hunt_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


@router.post("/findings", summary="Record a threat finding")
def record_finding(body: RecordFindingRequest) -> Dict[str, Any]:
    """Record a threat finding from a hunt."""
    engine = _get_engine()
    try:
        return engine.record_finding(body.org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to record finding")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/findings", summary="List threat findings")
def list_findings(
    org_id: str = Query("default", description="Organisation ID"),
    hunt_id: Optional[str] = Query(None, description="Filter by hunt ID"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    status: Optional[str] = Query(None, description="Filter by status"),
) -> List[Dict[str, Any]]:
    """List threat findings with optional filters."""
    engine = _get_engine()
    try:
        return engine.list_findings(org_id, hunt_id=hunt_id, severity=severity, status=status)
    except Exception as exc:
        logger.exception("Failed to list findings")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.put("/findings/{finding_id}/status", summary="Update finding status")
def update_finding_status(
    finding_id: str,
    body: UpdateFindingStatusRequest,
) -> Dict[str, Any]:
    """Update the status of a threat finding."""
    engine = _get_engine()
    try:
        return engine.update_finding_status(body.org_id, finding_id, body.status)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to update finding status %s", finding_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# IOCs
# ---------------------------------------------------------------------------


@router.post("/iocs", summary="Add an IOC to a hunt")
def add_ioc(body: AddIocRequest) -> Dict[str, Any]:
    """Add an Indicator of Compromise associated with a hunt."""
    engine = _get_engine()
    try:
        return engine.add_ioc(body.org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to add IOC")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/iocs", summary="List IOCs")
def list_iocs(
    org_id: str = Query("default", description="Organisation ID"),
    hunt_id: Optional[str] = Query(None, description="Filter by hunt ID"),
    ioc_type: Optional[str] = Query(None, description="Filter by IOC type"),
) -> List[Dict[str, Any]]:
    """List IOCs with optional filters."""
    engine = _get_engine()
    try:
        return engine.list_iocs(org_id, hunt_id=hunt_id, ioc_type=ioc_type)
    except Exception as exc:
        logger.exception("Failed to list IOCs")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


@router.get("/stats", summary="Get hunting statistics")
def get_hunting_stats(
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Return aggregate endpoint threat hunting statistics."""
    engine = _get_engine()
    try:
        return engine.get_hunting_stats(org_id)
    except Exception as exc:
        logger.exception("Failed to get hunting stats")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
