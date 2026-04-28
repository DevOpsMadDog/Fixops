"""Developer Risk Profiles Router — ALDECI.

Prefix: /api/v1/developer-profiles
Auth:   api_key_auth dependency

Routes:
  GET  /api/v1/developer-profiles                    list_profiles
  GET  /api/v1/developer-profiles/{dev_id}           get_profile
  GET  /api/v1/developer-profiles/leaderboard/risk   risk_leaderboard
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends, Query

logger = logging.getLogger(__name__)

try:
    from apps.api.auth_deps import api_key_auth
    _AUTH_DEP = [Depends(api_key_auth)]
except Exception:
    _AUTH_DEP = []

router = APIRouter(
    prefix="/api/v1/developer-profiles",
    tags=["Developer Risk Profiles"],
    dependencies=_AUTH_DEP,
)


@router.get("")
@router.get("/")
async def list_profiles(
    org_id: str = Query("default"),
    limit: int = Query(50, ge=1, le=500),
) -> Dict[str, Any]:
    """List developer risk profiles for the org."""
    try:
        from core.developer_portal import get_developer_portal
        portal = get_developer_portal()
        profiles = portal.list_profiles(org_id, limit=limit) if hasattr(portal, "list_profiles") else []
        return {"profiles": profiles, "total": len(profiles), "org_id": org_id}
    except Exception:
        return {"profiles": [], "total": 0, "org_id": org_id}


@router.get("/leaderboard/risk")
async def risk_leaderboard(
    org_id: str = Query("default"),
    limit: int = Query(20, ge=1, le=100),
) -> Dict[str, Any]:
    """Developer risk leaderboard — ranked by findings fixed and risk reduction."""
    try:
        from core.developer_portal import get_developer_portal
        portal = get_developer_portal()
        lb = portal.get_leaderboard(org_id, limit=limit) if hasattr(portal, "get_leaderboard") else []
        if isinstance(lb, dict):
            return lb
        return {"leaderboard": lb if isinstance(lb, list) else [], "total": len(lb) if isinstance(lb, list) else 0, "org_id": org_id}
    except Exception:
        return {"leaderboard": [], "total": 0, "org_id": org_id}


@router.get("/{dev_id}")
async def get_profile(
    dev_id: str,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Get a single developer risk profile."""
    try:
        from core.developer_portal import get_developer_portal
        portal = get_developer_portal()
        profile = portal.get_profile(org_id, dev_id) if hasattr(portal, "get_profile") else None
        if profile:
            return profile
        return {"dev_id": dev_id, "org_id": org_id, "findings_fixed": 0, "risk_score": 0}
    except Exception:
        return {"dev_id": dev_id, "org_id": org_id, "findings_fixed": 0, "risk_score": 0}
