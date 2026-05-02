"""Spamhaus DROP/EDROP Router — ALDECI.

Import and query the Spamhaus DROP (Don't Route Or Peer) and EDROP blocklists.

Prefix: /api/v1/spamhaus
Auth:   api_key_auth dependency

Routes:
  POST /api/v1/spamhaus/import           trigger_import
  GET  /api/v1/spamhaus/cidrs            list_cidrs_endpoint
  GET  /api/v1/spamhaus/check/{ip}       check_ip_endpoint
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Path, Query

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/spamhaus",
    tags=["Spamhaus DROP"],
)


def _get_importer():
    from feeds.spamhaus_drop.importer import (
        check_ip,
        get_store_stats,
        list_cidrs,
        run_import,
    )
    return run_import, list_cidrs, check_ip, get_store_stats


@router.post("/import", dependencies=[Depends(api_key_auth)])
def trigger_import() -> Dict[str, Any]:
    """Pull the Spamhaus DROP and EDROP lists and replace the store.

    Returns ``{"drop_cidrs": N, "edrop_cidrs": N}``.
    """
    try:
        run_import, _l, _c, _s = _get_importer()
        return run_import()
    except Exception as exc:
        logger.exception("Spamhaus DROP import failed")
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/cidrs", dependencies=[Depends(api_key_auth)])
def list_cidrs_endpoint(
    list_name: Optional[str] = Query(
        default=None,
        description="Filter by list: 'drop' or 'edrop'",
    ),
    limit: int = Query(default=1000, ge=1, le=50_000),
    offset: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    """List stored CIDR entries with optional list_name filter."""
    try:
        _r, list_cidrs, _c, _s = _get_importer()
        rows = list_cidrs(list_name=list_name, limit=limit, offset=offset)
        return {
            "cidrs": rows,
            "total": len(rows),
            "offset": offset,
            "limit": limit,
            "list_name": list_name,
        }
    except Exception as exc:
        logger.exception("Failed to list Spamhaus CIDRs")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/check/{ip}", dependencies=[Depends(api_key_auth)])
def check_ip_endpoint(
    ip: str = Path(..., description="IPv4 or IPv6 address to check against DROP/EDROP"),
) -> Dict[str, Any]:
    """Check whether an IP address falls within any DROP or EDROP CIDR block.

    Always returns 200 with ``matched: true/false`` — use the ``matched``
    field to determine blocklist membership.
    """
    try:
        _r, _l, check_ip, _s = _get_importer()
        return check_ip(ip)
    except Exception as exc:
        logger.exception("Failed to check IP %s against Spamhaus DROP", ip)
        raise HTTPException(status_code=500, detail=str(exc)) from exc
