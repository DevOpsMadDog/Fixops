"""AppOmni Live Connector Router (SSPM).

Prefix: /api/v1/connectors/appomni-live
Auth:   api_key_auth dependency

Routes:
  GET  /health   — connector health probe
  GET  /status   — alias of /health (Demo-001 contract)
  POST /sync     — fetch SaaS security posture findings from AppOmni
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/connectors/appomni-live",
    tags=["AppOmni Live Connector"],
)


def _conn():
    from connectors.appomni_connector import get_appomni_connector
    return get_appomni_connector()


class SyncRequest(BaseModel):
    org_id: str = Field(default="default", min_length=1, max_length=128)
    force_refresh: bool = Field(default=False)
    max_findings: int = Field(default=1000, ge=1, le=50000)


@router.get("/health", dependencies=[Depends(api_key_auth)])
def health() -> Dict[str, Any]:
    """Health probe for the AppOmni SSPM live connector."""
    try:
        from connectors.appomni_connector import _creds_present
        has_creds = _creds_present()
        _conn()
        return {
            "status": "ok",
            "service": "appomni-live-connector",
            "source_tool": "appomni",
            "credentials_configured": has_creds,
            "mode": "live" if has_creds else "needs_credentials",
        }
    except (ImportError, RuntimeError, OSError) as exc:
        _logger.exception("appomni-live connector health failed")
        raise HTTPException(status_code=503, detail=f"connector unavailable: {exc}") from exc


@router.get("/status", dependencies=[Depends(api_key_auth)])
def status() -> Dict[str, Any]:
    """Status alias of /health (Demo-001 contract)."""
    return health()


@router.post("/sync", dependencies=[Depends(api_key_auth)])
def sync(req: SyncRequest) -> Dict[str, Any]:
    """Fetch SaaS security posture findings from AppOmni REST API."""
    try:
        conn = _conn()
        return conn.sync(org_id=req.org_id, force_refresh=req.force_refresh)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (RuntimeError, OSError, TypeError) as exc:
        _logger.exception("appomni-live sync failed")
        raise HTTPException(status_code=500, detail=f"sync failed: {exc}") from exc
