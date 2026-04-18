"""Org Management Router — ALDECI multi-tenancy.

Prefix: /api/v1/orgs
Auth: api_key_auth dependency

Routes:
  GET    /api/v1/orgs                    list_orgs
  POST   /api/v1/orgs                    create_org
  GET    /api/v1/orgs/{org_id}/summary   get_org_summary
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from apps.api.auth_deps import api_key_auth

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/orgs",
    tags=["Organizations"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.org_engine import OrgEngine
        _engine = OrgEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class CreateOrgRequest(BaseModel):
    org_id: str = Field(..., description="Unique org identifier (e.g. acme-corp)")
    name: str = Field(..., description="Human-readable display name")
    description: Optional[str] = Field(default="", description="Optional description")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("", dependencies=[Depends(api_key_auth)])
def list_orgs(
    include_discovered: bool = Query(
        default=True,
        description="Include org_ids discovered from engine databases",
    ),
) -> List[Dict[str, Any]]:
    """List all known organisations.

    Returns registered orgs plus any org_ids discovered by scanning engine
    SQLite databases (when ``include_discovered=true``).
    """
    return _get_engine().list_orgs(include_discovered=include_discovered)


@router.post("", dependencies=[Depends(api_key_auth)])
def create_org(req: CreateOrgRequest) -> Dict[str, Any]:
    """Create a new organisation in the registry."""
    try:
        return _get_engine().create_org(
            org_id=req.org_id,
            name=req.name,
            description=req.description or "",
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/{org_id}/summary", dependencies=[Depends(api_key_auth)])
def get_org_summary(org_id: str) -> Dict[str, Any]:
    """Return a dashboard summary for a specific org.

    Shows how many engine databases contain data for this org_id and the
    total row count across all tables.
    """
    try:
        return _get_engine().get_org_summary(org_id)
    except Exception as exc:
        _logger.exception("Error fetching org summary for %s", org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc
