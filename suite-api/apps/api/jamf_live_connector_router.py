"""Jamf Pro Live Connector Router.

Prefix: /api/v1/connectors/jamf-live
Auth:   api_key_auth dependency

Routes:
  GET  /health   — connector health probe
  GET  /status   — alias of /health (Demo-001 contract)
  POST /sync     — fetch live device inventory from Jamf Pro API
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/connectors/jamf-live",
    tags=["Jamf Pro Live Connector"],
)


def _conn():
    from connectors.jamf_connector import get_jamf_connector
    return get_jamf_connector()


class SyncRequest(BaseModel):
    org_id: str = Field(default="default", min_length=1, max_length=128)
    force_refresh: bool = Field(default=False)


@router.get("/health", dependencies=[Depends(api_key_auth)])
def health() -> Dict[str, Any]:
    """Health probe for the Jamf Pro live connector."""
    try:
        from connectors.jamf_connector import _creds_present
        has_creds = _creds_present()
        _conn()
        return {
            "status": "ok",
            "service": "jamf-live-connector",
            "source_tool": "jamf_pro",
            "credentials_configured": has_creds,
            "mode": "live" if has_creds else "needs_credentials",
        }
    except (ImportError, RuntimeError, OSError) as exc:
        _logger.exception("jamf-live connector health failed")
        raise HTTPException(status_code=503, detail=f"connector unavailable: {exc}") from exc


@router.get("/status", dependencies=[Depends(api_key_auth)])
def status() -> Dict[str, Any]:
    """Status alias of /health (Demo-001 contract)."""
    return health()


@router.post("/sync", dependencies=[Depends(api_key_auth)])
def sync(req: SyncRequest) -> Dict[str, Any]:
    """Fetch live device inventory from Jamf Pro API."""
    try:
        conn = _conn()
        return conn.sync(org_id=req.org_id, force_refresh=req.force_refresh)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (RuntimeError, OSError, TypeError) as exc:
        _logger.exception("jamf-live sync failed")
        raise HTTPException(status_code=500, detail=f"sync failed: {exc}") from exc
