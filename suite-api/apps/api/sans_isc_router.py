"""SANS Internet Storm Center (ISC) Router — ALDECI.

Endpoints to import and query SANS ISC threat-intel data.

Prefix: /api/v1/sans-isc
Auth:   api_key_auth dependency

Routes:
  POST /api/v1/sans-isc/import         trigger_import
  GET  /api/v1/sans-isc/top-sources    get_top_sources
  GET  /api/v1/sans-isc/top-ports      get_top_ports
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/sans-isc",
    tags=["SANS ISC"],
)


def _get_importer():
    from feeds.sans_isc.importer import (
        get_top_ports,
        get_top_sources,
        run_import,
    )
    return run_import, get_top_sources, get_top_ports


@router.post("/import", dependencies=[Depends(api_key_auth)])
def trigger_import() -> Dict[str, Any]:
    """Pull SANS ISC top attack sources and top ports. Returns import summary."""
    try:
        run_import, _s, _p = _get_importer()
        return run_import()
    except Exception as exc:
        logger.exception("SANS ISC import failed")
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/top-sources", dependencies=[Depends(api_key_auth)])
def get_top_sources_endpoint(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    """Return top attack source IPs sorted by attack_count descending."""
    try:
        _i, get_top_sources, _p = _get_importer()
        rows = get_top_sources(limit=limit, offset=offset)
        return {
            "top_sources": rows,
            "total": len(rows),
            "offset": offset,
            "limit": limit,
        }
    except Exception as exc:
        logger.exception("Failed to list SANS ISC top sources")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/top-ports", dependencies=[Depends(api_key_auth)])
def get_top_ports_endpoint(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    """Return top attacked ports sorted by attack_count descending."""
    try:
        _i, _s, get_top_ports = _get_importer()
        rows = get_top_ports(limit=limit, offset=offset)
        return {
            "top_ports": rows,
            "total": len(rows),
            "offset": offset,
            "limit": limit,
        }
    except Exception as exc:
        logger.exception("Failed to list SANS ISC top ports")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
