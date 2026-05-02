"""DBIR / VERIS Community Database Router — ALDECI.

Endpoints to import and query Verizon DBIR / VCDB breach incidents.

Prefix: /api/v1/dbir
Auth:   api_key_auth dependency

Routes:
  POST /api/v1/dbir/import     trigger_import
  GET  /api/v1/dbir/incidents  list_incidents
  GET  /api/v1/dbir/stats      get_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/dbir",
    tags=["DBIR"],
)


def _get_importer():
    from feeds.dbir.importer import get_store_stats, list_incidents, run_import
    return run_import, list_incidents, get_store_stats


@router.post("/import", dependencies=[Depends(api_key_auth)])
def trigger_import() -> Dict[str, Any]:
    """Download and import the VERIS Community Database master archive.

    Pulls https://github.com/vz-risk/VCDB/archive/refs/heads/master.tar.gz,
    walks data/json/validated/, parses each incident JSON, and upserts into
    the local dbir.db keyed by incident_id.

    Returns a summary keyed by action_pattern, actor type, and victim NAICS.
    """
    try:
        run_import, _l, _s = _get_importer()
        return run_import()
    except Exception as exc:
        logger.exception("DBIR import failed")
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/incidents", dependencies=[Depends(api_key_auth)])
def list_dbir_incidents(
    action_pattern: Optional[str] = Query(
        default=None,
        description="Filter by VERIS action pattern: malware | hacking | social | error | misuse | physical | environmental",
    ),
    actor: Optional[str] = Query(
        default=None,
        description="Filter by actor type: external | internal | partner",
    ),
    industry_naics: Optional[str] = Query(
        default=None,
        description="Filter by victim industry NAICS prefix (e.g. '52' for Finance)",
    ),
    limit: int = Query(default=500, ge=1, le=5000),
    offset: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    """List DBIR/VCDB incidents from the local DB with optional filters."""
    try:
        _r, list_incidents, _s = _get_importer()
        incidents = list_incidents(
            action_pattern=action_pattern,
            actor=actor,
            industry_naics=industry_naics,
            limit=limit,
            offset=offset,
        )
        return {
            "incidents": incidents,
            "total": len(incidents),
            "offset": offset,
            "limit": limit,
        }
    except Exception as exc:
        logger.exception("Failed to list DBIR incidents")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_stats() -> Dict[str, Any]:
    """Return total DBIR incident count and breakdowns."""
    try:
        _r, _l, get_store_stats = _get_importer()
        return get_store_stats()
    except Exception as exc:
        logger.exception("Failed to get DBIR stats")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
