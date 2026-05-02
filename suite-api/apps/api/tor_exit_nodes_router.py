"""Tor Exit Node Router — ALDECI.

Endpoints to import and query the Tor exit-node IP list sourced from
https://check.torproject.org/torbulkexitlist (plain text, ~1500 IPs,
refreshed every 30 min, public domain).

Prefix: /api/v1/tor-exit
Auth:   api_key_auth dependency

Routes:
  POST /api/v1/tor-exit/import        trigger_import
  GET  /api/v1/tor-exit/ips           list_ips_endpoint
  GET  /api/v1/tor-exit/check/{ip}    check_ip_endpoint
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any, Dict

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi import Path as FPath

logger = logging.getLogger(__name__)

# Ensure suite-feeds is on sys.path for the lazy importer
_HERE = Path(__file__).resolve()
_PROJECT_ROOT = _HERE.parents[3]  # suite-api/apps/api -> project root
_SUITE_FEEDS = str(_PROJECT_ROOT / "suite-feeds")
if _SUITE_FEEDS not in sys.path:
    sys.path.insert(0, _SUITE_FEEDS)

router = APIRouter(
    prefix="/api/v1/tor-exit",
    tags=["Tor Exit Nodes"],
)


def _get_importer():
    from feeds.tor_exit_nodes.importer import (
        check_ip,
        list_exit_ips,
        run_import,
        total_count,
    )
    return run_import, list_exit_ips, check_ip, total_count


# ---------------------------------------------------------------------------
# POST /import
# ---------------------------------------------------------------------------

@router.post("/import", dependencies=[Depends(api_key_auth)])
def trigger_import() -> Dict[str, Any]:
    """Pull the TorProject bulk exit list and replace the local store.

    The list is fetched from https://check.torproject.org/torbulkexitlist.
    Replace semantics: each call is idempotent — the list IS the new state.

    Returns:
        {"ips": N, "imported_at": "<iso8601>"}
    """
    try:
        run_import, _l, _c, _t = _get_importer()
        return run_import()
    except Exception as exc:
        logger.exception("Tor exit-node import failed")
        raise HTTPException(status_code=502, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# GET /ips
# ---------------------------------------------------------------------------

@router.get("/ips", dependencies=[Depends(api_key_auth)])
def list_ips_endpoint(
    limit: int = Query(default=1000, ge=1, le=5000, description="Max IPs to return"),
    offset: int = Query(default=0, ge=0, description="Pagination offset"),
) -> Dict[str, Any]:
    """List known Tor exit-node IPs.

    Returns:
        {"ips": [...], "total": N, "limit": N, "offset": N}
    """
    try:
        _r, list_exit_ips, _c, total_count = _get_importer()
        ips = list_exit_ips(limit=limit, offset=offset)
        total = total_count()
        return {"ips": ips, "total": total, "limit": limit, "offset": offset}
    except Exception as exc:
        logger.exception("Tor exit-node list failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# GET /check/{ip}
# ---------------------------------------------------------------------------

@router.get("/check/{ip:path}", dependencies=[Depends(api_key_auth)])
def check_ip_endpoint(
    ip: str = FPath(..., description="IPv4 or IPv6 address to look up"),
) -> Dict[str, Any]:
    """Check whether a single IP is a known Tor exit node.

    Returns:
        {"ip": "...", "is_tor_exit": bool, "entry": {...} | null}
    """
    try:
        _r, _l, check_ip, _t = _get_importer()
        entry = check_ip(ip.strip())
        return {
            "ip": ip.strip(),
            "is_tor_exit": entry is not None,
            "entry": entry,
        }
    except Exception as exc:
        logger.exception("Tor exit-node check failed for %s", ip)
        raise HTTPException(status_code=500, detail=str(exc)) from exc
