"""Security Dependency Mapping Router — ALDECI.

Service dependency map and blast radius analysis for incident impact assessment.

Prefix: /api/v1/dependency-mapping
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/dependency-mapping/services                          register_service
  GET    /api/v1/dependency-mapping/services                          list_services
  GET    /api/v1/dependency-mapping/services/{service_id}             get_service
  POST   /api/v1/dependency-mapping/dependencies                      add_dependency
  DELETE /api/v1/dependency-mapping/dependencies/{dependency_id}      remove_dependency
  POST   /api/v1/dependency-mapping/services/{service_id}/blast-radius compute_blast_radius
  GET    /api/v1/dependency-mapping/critical-paths                    get_critical_paths
  GET    /api/v1/dependency-mapping/summary                           get_summary
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from apps.api.auth_deps import api_key_auth

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/dependency-mapping",
    tags=["Security Dependency Mapping"],
    dependencies=[Depends(api_key_auth)],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_dependency_mapping_engine import SecurityDependencyMappingEngine
        _engine = SecurityDependencyMappingEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------


class RegisterServiceBody(BaseModel):
    service_name: str = Field(..., description="Unique service name")
    service_type: str = Field(
        default="application",
        description="application | database | api | queue | cache | auth | monitoring | storage | network | external",
    )
    criticality: str = Field(default="medium", description="critical | high | medium | low")
    owner: str = Field(default="", description="Owning team or person")
    environment: str = Field(default="production", description="production | staging | development | dr")
    data_classification: str = Field(
        default="internal",
        description="public | internal | confidential | restricted",
    )


class AddDependencyBody(BaseModel):
    source_service_id: str = Field(..., description="Service ID that has the dependency")
    target_service_id: str = Field(..., description="Service ID being depended upon")
    dependency_type: str = Field(default="runtime", description="runtime | build | test | optional | fallback")
    criticality: str = Field(default="medium", description="critical | high | medium | low")
    protocol: str = Field(default="", description="Network protocol (e.g. HTTPS, gRPC)")
    port: int = Field(default=0, description="Port number (0 = not applicable)")
    description: str = Field(default="", description="Human-readable description")


class BlastRadiusBody(BaseModel):
    analysis_type: str = Field(
        default="downstream",
        description="downstream (who breaks if I go down) or upstream (what I depend on)",
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/services")
def register_service(
    body: RegisterServiceBody,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Register a new service in the dependency map."""
    try:
        return _get_engine().register_service(
            org_id=org_id,
            service_name=body.service_name,
            service_type=body.service_type,
            criticality=body.criticality,
            owner=body.owner,
            environment=body.environment,
            data_classification=body.data_classification,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/services")
def list_services(
    org_id: str = Query(default="default"),
    service_type: Optional[str] = Query(default=None),
    criticality: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List services, optionally filtered by type and criticality."""
    return _get_engine().list_services(org_id, service_type=service_type, criticality=criticality)


@router.get("/services/{service_id}")
def get_service(
    service_id: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Fetch a service with its dependency edges."""
    result = _get_engine().get_service(service_id, org_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Service not found")
    return result


@router.post("/dependencies")
def add_dependency(
    body: AddDependencyBody,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Add a directed dependency between two services."""
    try:
        return _get_engine().add_dependency(
            org_id=org_id,
            source_service_id=body.source_service_id,
            target_service_id=body.target_service_id,
            dependency_type=body.dependency_type,
            criticality=body.criticality,
            protocol=body.protocol,
            port=body.port,
            description=body.description,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.delete("/dependencies/{dependency_id}")
def remove_dependency(
    dependency_id: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Remove a dependency and update service counters."""
    try:
        return _get_engine().remove_dependency(dependency_id, org_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/services/{service_id}/blast-radius")
def compute_blast_radius(
    service_id: str,
    body: BlastRadiusBody,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Compute blast radius (BFS) from a source service."""
    try:
        return _get_engine().compute_blast_radius(org_id, service_id, body.analysis_type)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/critical-paths")
def get_critical_paths(
    org_id: str = Query(default="default"),
) -> List[Dict[str, Any]]:
    """Return critical services ordered by dependent_count (most critical first)."""
    return _get_engine().get_critical_paths(org_id)


@router.get("/summary")
def get_summary(
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Return aggregate dependency map summary for the org."""
    return _get_engine().get_summary(org_id)
