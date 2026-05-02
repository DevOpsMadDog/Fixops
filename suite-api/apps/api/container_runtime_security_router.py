"""Container Runtime Security Router — ALDECI.

Endpoints for the Container Runtime Security engine.

Prefix: /api/v1/container-runtime
Auth:   api_key_auth dependency

Routes:
  POST /api/v1/container-runtime/containers                       register_container
  GET  /api/v1/container-runtime/containers                       list_containers
  GET  /api/v1/container-runtime/containers/{container_id}        get_container
  PUT  /api/v1/container-runtime/containers/{container_id}/status update_container_status
  POST /api/v1/container-runtime/events                           record_runtime_event
  GET  /api/v1/container-runtime/events                           list_events
  PUT  /api/v1/container-runtime/events/{id}/status               update_event_status
  POST /api/v1/container-runtime/policies                         create_policy
  GET  /api/v1/container-runtime/policies                         list_policies
  GET  /api/v1/container-runtime/stats                            get_runtime_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/container-runtime",
    tags=["Container Runtime Security"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.container_runtime_security_engine import (
            ContainerRuntimeSecurityEngine,
        )
        _engine = ContainerRuntimeSecurityEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ContainerCreate(BaseModel):
    org_id: str = "default"
    container_id: str
    image_name: str
    image_tag: str = "latest"
    pod_name: str = ""
    namespace: str = "default"
    cluster: str = ""
    runtime_status: str = "running"
    privileged: bool = False
    host_network: bool = False
    security_score: int = 100


class ContainerStatusUpdate(BaseModel):
    new_status: str


class RuntimeEventCreate(BaseModel):
    org_id: str = "default"
    container_id: str
    event_type: str
    severity: str
    process_name: str = ""
    command_preview: str = ""


class EventStatusUpdate(BaseModel):
    new_status: str


class PolicyCreate(BaseModel):
    org_id: str = "default"
    policy_name: str
    policy_type: str
    enforcement: str = "audit"
    scope: List[str] = []


# ---------------------------------------------------------------------------
# Container Endpoints
# ---------------------------------------------------------------------------

@router.post("/containers", status_code=201)
async def register_container(body: ContainerCreate) -> Dict[str, Any]:
    """Register a container instance for runtime monitoring."""
    try:
        return _get_engine().register_container(body.org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/containers")
async def list_containers(
    org_id: str = Query("default"),
    namespace: Optional[str] = Query(None),
    runtime_status: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    """List container instances with optional filters."""
    return _get_engine().list_containers(org_id, namespace=namespace, runtime_status=runtime_status)


@router.get("/containers/{container_id}")
async def get_container(
    container_id: str,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Get a container by its container_id."""
    result = _get_engine().get_container(org_id, container_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Container '{container_id}' not found.")
    return result


@router.put("/containers/{container_id}/status")
async def update_container_status(
    container_id: str,
    body: ContainerStatusUpdate,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Update a container's runtime status."""
    try:
        return _get_engine().update_container_status(org_id, container_id, body.new_status)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


# ---------------------------------------------------------------------------
# Event Endpoints
# ---------------------------------------------------------------------------

@router.post("/events", status_code=201)
async def record_runtime_event(body: RuntimeEventCreate) -> Dict[str, Any]:
    """Record a container runtime security event."""
    try:
        return _get_engine().record_runtime_event(body.org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/events")
async def list_events(
    org_id: str = Query("default"),
    event_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    """List runtime events with optional filters."""
    return _get_engine().list_events(
        org_id, event_type=event_type, severity=severity, status=status
    )


@router.put("/events/{event_id}/status")
async def update_event_status(
    event_id: str,
    body: EventStatusUpdate,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Update the status of a runtime event."""
    try:
        return _get_engine().update_event_status(org_id, event_id, body.new_status)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


# ---------------------------------------------------------------------------
# Policy Endpoints
# ---------------------------------------------------------------------------

@router.post("/policies", status_code=201)
async def create_policy(body: PolicyCreate) -> Dict[str, Any]:
    """Create a runtime security policy."""
    try:
        return _get_engine().create_policy(body.org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/policies")
async def list_policies(
    org_id: str = Query("default"),
    enforcement: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    """List runtime policies with optional enforcement filter."""
    return _get_engine().list_policies(org_id, enforcement=enforcement)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats")
async def get_runtime_stats(
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Return aggregate runtime security stats."""
    return _get_engine().get_runtime_stats(org_id)
