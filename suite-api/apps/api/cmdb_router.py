"""CMDB Router — Configuration Management Database endpoints.

6 endpoint groups:
  GET    /api/v1/cmdb/cis                          list_cis
  POST   /api/v1/cmdb/cis                          create_ci
  GET    /api/v1/cmdb/cis/{ci_id}                  get_ci
  PATCH  /api/v1/cmdb/cis/{ci_id}                  update_ci
  GET    /api/v1/cmdb/relationships                 list_relationships
  POST   /api/v1/cmdb/relationships                 create_relationship
  GET    /api/v1/cmdb/changes                       list_changes
  POST   /api/v1/cmdb/changes                       record_change
  GET    /api/v1/cmdb/stats                         get_stats
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
        "cmdb_router: auth_deps not available, relying on app.py mount-level auth"
    )
    _AUTH_DEP = []

from core.cmdb_engine import CMDBEngine

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/cmdb",
    tags=["cmdb"],
    dependencies=_AUTH_DEP,
)

# Shared engine instance (SQLite-backed, thread-safe)
_engine = None  # lazy-initialised on first request


def _get_engine():
    global _engine
    if _engine is None:
        _engine = CMDBEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request / Response Models
# ---------------------------------------------------------------------------

class CreateCIRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    name: str = Field(..., description="CI display name")
    ci_type: str = Field(
        ...,
        description=(
            "server | vm | container | database | application | "
            "network_device | storage | cloud_resource"
        ),
    )
    category: str = Field("", description="Free-form category label")
    owner: str = Field("", description="Owning team or individual")
    status: str = Field("active", description="active | decommissioned | maintenance")
    environment: str = Field("prod", description="prod | staging | dev | dr")
    location: str = Field("", description="Physical or logical location")
    ip_address: str = Field("", description="Primary IP address")
    os: str = Field("", description="Operating system or platform")
    version: str = Field("", description="Software/firmware version")
    criticality: str = Field("medium", description="low | medium | high | critical")
    support_tier: str = Field("", description="Support tier / SLA tier")
    tags: List[str] = Field(default_factory=list, description="Arbitrary tags")


class UpdateCIRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    name: Optional[str] = None
    category: Optional[str] = None
    owner: Optional[str] = None
    status: Optional[str] = None
    environment: Optional[str] = None
    location: Optional[str] = None
    ip_address: Optional[str] = None
    os: Optional[str] = None
    version: Optional[str] = None
    criticality: Optional[str] = None
    support_tier: Optional[str] = None
    tags: Optional[List[str]] = None


class CreateRelationshipRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    src_ci_id: str = Field(..., description="Source CI identifier")
    dst_ci_id: str = Field(..., description="Destination CI identifier")
    rel_type: str = Field(
        ...,
        description="depends_on | hosts | connects_to | backs_up | manages",
    )


class RecordChangeRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    ci_id: str = Field(..., description="CI that was changed")
    change_type: str = Field(
        ...,
        description=(
            "created | updated | decommissioned | patched | "
            "config_change | incident"
        ),
    )
    description: str = Field("", description="Human-readable change description")
    changed_by: str = Field("", description="User or system that made the change")
    change_date: Optional[str] = Field(None, description="ISO-8601 effective change date")


# ---------------------------------------------------------------------------
# CI Endpoints
# ---------------------------------------------------------------------------

@router.get("/cis", summary="List configuration items")
def list_cis(
     org_id: str = Query(default="default"),
    ci_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    environment: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    try:
        return _get_engine().list_cis(org_id, ci_type=ci_type, status=status, environment=environment)
    except Exception as exc:
        logger.exception("list_cis error")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/cis", summary="Create a configuration item", status_code=201)
def create_ci(req: CreateCIRequest) -> Dict[str, Any]:
    try:
        return _get_engine().add_ci(req.org_id, req.model_dump(exclude={"org_id"}))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.exception("create_ci error")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/cis/{ci_id}", summary="Get a configuration item")
def get_ci(
    ci_id: str,
     org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    result = _get_engine().get_ci(org_id, ci_id)
    if result is None:
        raise HTTPException(status_code=404, detail="CI not found")
    return result


@router.patch("/cis/{ci_id}", summary="Update a configuration item")
def update_ci(
    ci_id: str,
    req: UpdateCIRequest,
) -> Dict[str, Any]:
    try:
        updated = _get_engine().update_ci(
            req.org_id,
            ci_id,
            req.model_dump(exclude={"org_id"}, exclude_none=True),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not updated:
        raise HTTPException(status_code=404, detail="CI not found")
    return {"ci_id": ci_id, "updated": True}


# ---------------------------------------------------------------------------
# Relationship Endpoints
# ---------------------------------------------------------------------------

@router.get("/relationships", summary="List CI relationships")
def list_relationships(
     org_id: str = Query(default="default"),
    ci_id: Optional[str] = Query(None, description="Filter by src or dst CI"),
) -> List[Dict[str, Any]]:
    try:
        return _get_engine().list_relationships(org_id, ci_id=ci_id)
    except Exception as exc:
        logger.exception("list_relationships error")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/relationships", summary="Create a CI relationship", status_code=201)
def create_relationship(req: CreateRelationshipRequest) -> Dict[str, Any]:
    try:
        return _get_engine().add_relationship(
            req.org_id, req.src_ci_id, req.dst_ci_id, req.rel_type
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.exception("create_relationship error")
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Change Record Endpoints
# ---------------------------------------------------------------------------

@router.get("/changes", summary="List CI change records")
def list_changes(
     org_id: str = Query(default="default"),
    ci_id: Optional[str] = Query(None, description="Filter by CI"),
) -> List[Dict[str, Any]]:
    try:
        return _get_engine().list_changes(org_id, ci_id=ci_id)
    except Exception as exc:
        logger.exception("list_changes error")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/changes", summary="Record a CI change event", status_code=201)
def record_change(req: RecordChangeRequest) -> Dict[str, Any]:
    try:
        return _get_engine().record_change(
            req.org_id,
            req.ci_id,
            req.change_type,
            req.description,
            req.changed_by,
            req.change_date,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.exception("record_change error")
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Stats Endpoint
# ---------------------------------------------------------------------------

@router.get("/stats", summary="CMDB aggregate statistics")
def get_stats(org_id: str = Query(default="default")) -> Dict[str, Any]:
    try:
        return _get_engine().get_cmdb_stats(org_id)
    except Exception as exc:
        logger.exception("get_cmdb_stats error")
        raise HTTPException(status_code=500, detail=str(exc))
