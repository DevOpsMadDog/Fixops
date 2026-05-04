"""PhishTank phishing-URL API router.

Endpoints:
    POST /api/v1/phishtank/import          — trigger feed import
    GET  /api/v1/phishtank/phishes         — paginated phish list
    GET  /api/v1/phishtank/check?url=...   — URL membership check
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from apps.api.auth_deps import api_key_auth

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/phishtank", tags=["phishtank"])

# ---------------------------------------------------------------------------
# Lazy importer bootstrap — resolve project root so imports work regardless
# of CWD when the router is mounted.
# ---------------------------------------------------------------------------

_PROJECT_ROOT = Path(__file__).resolve().parents[3]  # suite-api/apps/api -> project root
_SUITE_FEEDS = str(_PROJECT_ROOT / "suite-feeds")
_DEFAULT_DB = str(_PROJECT_ROOT / "data" / "phishtank.db")


def _get_importer():
    if _SUITE_FEEDS not in sys.path:
        sys.path.insert(0, _SUITE_FEEDS)
    from feeds.phishtank.importer import PhishTankImporter
    return PhishTankImporter(db_path=_DEFAULT_DB)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/import", summary="Trigger PhishTank feed import", dependencies=[Depends(api_key_auth)])
async def import_phishtank():
    """Pull the latest PhishTank online-valid JSON feed, upsert into local DB,
    expire stale records (online=no for 30+ days), and return a summary."""
    try:
        imp = _get_importer()
        result = imp.run()
        return result
    except Exception as exc:
        logger.exception("PhishTank import failed")
        raise HTTPException(status_code=502, detail=f"Import failed: {exc}") from exc


@router.get("/phishes", summary="List phishing URLs", dependencies=[Depends(api_key_auth)])
async def list_phishes(
    page: int = Query(1, ge=1, description="Page number (1-based)"),
    page_size: int = Query(50, ge=1, le=500, description="Entries per page"),
    target: Optional[str] = Query(None, description="Filter by brand name (e.g. PayPal)"),
    online_only: bool = Query(False, description="Return only currently-online phishes"),
):
    """Return a paginated list of phishing URLs with optional brand and
    online-status filters."""
    try:
        imp = _get_importer()
        return imp.list_phishes(
            page=page,
            page_size=page_size,
            target=target,
            online_only=online_only,
        )
    except Exception as exc:
        logger.exception("PhishTank list_phishes failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/check", summary="Check if a URL is a known phish", dependencies=[Depends(api_key_auth)])
async def check_url(
    url: str = Query(..., description="URL to check for phishing membership"),
):
    """Exact-match lookup against the local PhishTank DB.  Returns
    ``{"found": true, ...record...}`` or ``{"found": false, "url": "..."}``.
    """
    if not url:
        raise HTTPException(status_code=400, detail="url query parameter is required")
    try:
        imp = _get_importer()
        return imp.check_url(url)
    except Exception as exc:
        logger.exception("PhishTank check_url failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
