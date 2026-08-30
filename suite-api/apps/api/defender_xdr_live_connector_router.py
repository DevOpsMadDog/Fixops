"""Microsoft Defender XDR Live Connector Router.

Prefix: /api/v1/connectors/defender-xdr-live
Auth:   api_key_auth dependency

Routes:
  GET  /health   — connector health probe
  GET  /status   — alias of /health (Demo-001 contract)
  POST /sync     — fetch live incidents from Defender XDR API
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from apps.api.auth_deps import api_key_auth
from apps.api.dependencies import get_org_id
from apps.api.tenant_resolution import resolve_tenant
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/connectors/defender-xdr-live",
    tags=["Defender XDR Live Connector"],
)


def _conn():
    from connectors.defender_xdr_live_connector import get_defender_xdr_live_connector
    return get_defender_xdr_live_connector()


class SyncRequest(BaseModel):
    org_id: str = Field(default="default", min_length=1, max_length=128)
    force_refresh: bool = Field(default=False)
    max_incidents: int = Field(default=200, ge=1, le=5000)


@router.get("/health", dependencies=[Depends(api_key_auth)])
def health() -> Dict[str, Any]:
    """Health probe for the Defender XDR live connector."""
    try:
        from connectors.defender_xdr_live_connector import _creds_present
        has_creds = _creds_present()
        _conn()
        return {
            "status": "ok",
            "service": "defender-xdr-live-connector",
            "source_tool": "microsoft_defender_xdr",
            "credentials_configured": has_creds,
            "mode": "live" if has_creds else "needs_credentials",
        }
    except (ImportError, RuntimeError, OSError) as exc:
        _logger.exception("defender-xdr-live connector health failed")
        raise HTTPException(status_code=503, detail=f"connector unavailable: {exc}") from exc


@router.get("/status", dependencies=[Depends(api_key_auth)])
def status() -> Dict[str, Any]:
    """Status alias of /health (Demo-001 contract)."""
    return health()


@router.post("/sync", dependencies=[Depends(api_key_auth)])
def sync(
    req: SyncRequest, org_id: str = Depends(get_org_id)
) -> Dict[str, Any]:
    """Fetch live incidents from Microsoft Defender XDR REST API."""
    # The credential decides the tenant. This handler is authenticated but
    # took org_id from the request body, so any valid key could sync a
    # connector into — and pull data for — an org it does not own.
    try:
        conn = _conn()
        return conn.sync(org_id=resolve_tenant(org_id, req), force_refresh=req.force_refresh)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (RuntimeError, OSError, TypeError) as exc:
        _logger.exception("defender-xdr-live sync failed")
        raise HTTPException(status_code=500, detail=f"sync failed: {exc}") from exc
