"""
API Versioning router — version discovery, deprecation registry, migration guides.

Endpoints:
  GET  /api/versions                       — list available API versions
  GET  /api/versions/endpoints             — list all versioned endpoints
  GET  /api/versions/deprecated            — deprecated endpoints only
  GET  /api/versions/sunset-schedule       — endpoints with upcoming sunset dates
  GET  /api/versions/migration/{path:path} — migration guide for an endpoint
  GET  /api/versions/stats                 — versioning statistics
  POST /api/versions/deprecate             — mark an endpoint as deprecated
  POST /api/versions/register              — register a new endpoint version
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional

from core.api_versioning import (
    APIVersion,
    APIVersionManager,
    DeprecationStatus,
    EndpointVersion,
    get_version_manager,
)
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/versions", tags=["versioning"])

# ---------------------------------------------------------------------------
# Shared manager instance (uses env override for db path in tests)
# ---------------------------------------------------------------------------

_DB_PATH = os.getenv("FIXOPS_VERSIONING_DB", "data/api_versioning.db")


def _manager() -> APIVersionManager:
    return get_version_manager(db_path=_DB_PATH)


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------


def _endpoint_to_dict(ev: EndpointVersion) -> Dict[str, Any]:
    return {
        "path": ev.path,
        "version": ev.version.value,
        "status": ev.status.value,
        "deprecated_at": ev.deprecated_at,
        "sunset_date": ev.sunset_date,
        "replacement_path": ev.replacement_path,
        "migration_guide": ev.migration_guide,
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("", summary="List available API versions")
async def list_versions() -> Dict[str, Any]:
    """Return all supported API versions with their lifecycle status."""
    return {
        "versions": [
            {
                "version": APIVersion.V1.value,
                "status": "active",
                "description": "Current stable API version",
                "base_url": "/api/v1",
            },
            {
                "version": APIVersion.V2.value,
                "status": "preview",
                "description": "Next-generation API with enhanced features",
                "base_url": "/api/v2",
            },
        ],
        "default_version": APIVersion.V1.value,
        "negotiation_methods": ["Accept-Version header", "URL prefix", "default"],
    }


@router.get("/endpoints", summary="List all versioned endpoints")
async def list_endpoints(
    version: Optional[str] = Query(None, description="Filter by version: v1 or v2"),
    status: Optional[str] = Query(
        None, description="Filter by status: active, deprecated, sunset"
    ),
) -> Dict[str, Any]:
    """Return all registered endpoints, optionally filtered by version and status."""
    version_enum: Optional[APIVersion] = None
    if version is not None:
        try:
            version_enum = APIVersion(version.lower())
        except ValueError:
            raise HTTPException(
                status_code=422,
                detail=f"Invalid version '{version}'. Must be one of: {[v.value for v in APIVersion]}",
            )

    status_enum: Optional[DeprecationStatus] = None
    if status is not None:
        try:
            status_enum = DeprecationStatus(status.lower())
        except ValueError:
            raise HTTPException(
                status_code=422,
                detail=f"Invalid status '{status}'. Must be one of: {[s.value for s in DeprecationStatus]}",
            )

    mgr = _manager()
    endpoints = mgr.list_endpoints(version=version_enum, status_filter=status_enum)
    return {
        "endpoints": [_endpoint_to_dict(e) for e in endpoints],
        "count": len(endpoints),
        "filters": {"version": version, "status": status},
    }


@router.get("/deprecated", summary="List deprecated endpoints")
async def list_deprecated(
    version: Optional[str] = Query(None, description="Filter by version: v1 or v2"),
) -> Dict[str, Any]:
    """Return all endpoints currently marked as deprecated."""
    version_enum: Optional[APIVersion] = None
    if version is not None:
        try:
            version_enum = APIVersion(version.lower())
        except ValueError:
            raise HTTPException(
                status_code=422,
                detail=f"Invalid version '{version}'. Must be one of: {[v.value for v in APIVersion]}",
            )

    mgr = _manager()
    if version_enum is not None:
        endpoints = mgr.get_deprecation_warnings(version_enum)
    else:
        endpoints = mgr.list_endpoints(status_filter=DeprecationStatus.DEPRECATED)

    return {
        "deprecated_endpoints": [_endpoint_to_dict(e) for e in endpoints],
        "count": len(endpoints),
    }


@router.get("/sunset-schedule", summary="Upcoming endpoint sunsets")
async def sunset_schedule() -> Dict[str, Any]:
    """Return all endpoints that have a scheduled sunset date, ordered by date."""
    mgr = _manager()
    endpoints = mgr.get_sunset_schedule()
    return {
        "sunset_schedule": [_endpoint_to_dict(e) for e in endpoints],
        "count": len(endpoints),
    }


@router.get("/migration/{path:path}", summary="Migration guide for an endpoint")
async def migration_guide(
    path: str,
    from_version: str = Query("v1", description="Source version"),
    to_version: str = Query("v2", description="Target version"),
) -> Dict[str, Any]:
    """Return migration instructions for moving an endpoint between versions."""
    try:
        from_v = APIVersion(from_version.lower())
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid from_version '{from_version}'.",
        )
    try:
        to_v = APIVersion(to_version.lower())
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid to_version '{to_version}'.",
        )

    # Ensure path starts with /
    normalized_path = f"/{path}" if not path.startswith("/") else path

    mgr = _manager()
    guide = mgr.get_migration_guide(normalized_path, from_v, to_v)

    ev = mgr.get_endpoint_version_for(normalized_path, from_v)
    return {
        "path": normalized_path,
        "from_version": from_v.value,
        "to_version": to_v.value,
        "migration_guide": guide,
        "replacement_path": ev.replacement_path if ev else None,
        "sunset_date": ev.sunset_date if ev else None,
    }


@router.get("/stats", summary="API versioning statistics")
async def versioning_stats() -> Dict[str, Any]:
    """Return aggregate statistics about the versioning registry."""
    mgr = _manager()
    return mgr.get_versioning_stats()


# ---------------------------------------------------------------------------
# Write endpoints
# ---------------------------------------------------------------------------


class RegisterEndpointRequest(BaseModel):
    path: str = Field(..., description="API endpoint path, e.g. /api/v1/findings")
    version: str = Field(..., description="API version: v1 or v2")
    status: str = Field(
        default="active", description="Initial status: active, deprecated, sunset"
    )


class DeprecateEndpointRequest(BaseModel):
    path: str = Field(..., description="API endpoint path to deprecate")
    version: str = Field(..., description="API version: v1 or v2")
    replacement_path: Optional[str] = Field(
        None, description="Path of the successor endpoint"
    )
    sunset_date: Optional[str] = Field(
        None, description="ISO-8601 date when this endpoint will be removed, e.g. 2027-01-01"
    )
    migration_guide: Optional[str] = Field(
        None, description="Human-readable migration instructions"
    )


@router.post("/register", summary="Register a new endpoint version", status_code=201)
async def register_endpoint(body: RegisterEndpointRequest) -> Dict[str, Any]:
    """Register (or upsert) an endpoint version entry in the deprecation registry.

    Returns the created/updated endpoint record.
    """
    try:
        version_enum = APIVersion(body.version.lower())
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid version '{body.version}'. Must be one of: {[v.value for v in APIVersion]}",
        )

    try:
        status_enum = DeprecationStatus(body.status.lower())
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid status '{body.status}'. Must be one of: {[s.value for s in DeprecationStatus]}",
        )

    mgr = _manager()
    ev = mgr.register_endpoint(body.path, version_enum, status_enum)
    return {"registered": True, "endpoint": _endpoint_to_dict(ev)}


@router.post("/deprecate", summary="Mark an endpoint as deprecated")
async def deprecate_endpoint(body: DeprecateEndpointRequest) -> Dict[str, Any]:
    """Deprecate an API endpoint and record its sunset date and replacement.

    If the endpoint is not yet registered it will be inserted as deprecated.
    Sets standard ``Deprecation`` / ``Sunset`` / ``Link`` response-header values
    that the VersioningMiddleware will inject on subsequent requests to that path.
    """
    try:
        version_enum = APIVersion(body.version.lower())
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid version '{body.version}'. Must be one of: {[v.value for v in APIVersion]}",
        )

    mgr = _manager()
    ev = mgr.deprecate_endpoint(
        path=body.path,
        version=version_enum,
        replacement_path=body.replacement_path,
        sunset_date=body.sunset_date,
        migration_guide=body.migration_guide,
    )
    return {
        "deprecated": True,
        "endpoint": _endpoint_to_dict(ev),
        "sunset_date": ev.sunset_date,
        "replacement_path": ev.replacement_path,
    }
