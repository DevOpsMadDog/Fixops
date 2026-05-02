"""CrowdStrike Falcon Live Connector Router.

Prefix: /api/v1/connectors/crowdstrike-live
Auth:   api_key_auth dependency

Routes:
  GET  /health   — connector health probe
  GET  /status   — alias of /health (Demo-001 contract)
  POST /sync     — fetch live detections from Falcon API
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/connectors/crowdstrike-live",
    tags=["CrowdStrike Live Connector"],
)


def _conn():
    from connectors.crowdstrike_live_connector import get_crowdstrike_live_connector
    return get_crowdstrike_live_connector()


class SyncRequest(BaseModel):
    org_id: str = Field(default="default", min_length=1, max_length=128)
    filter_expr: Optional[str] = Field(default=None, max_length=512)
    force_refresh: bool = Field(default=False)
    max_detections: int = Field(default=500, ge=1, le=10000)


@router.get("/health", dependencies=[Depends(api_key_auth)])
def health() -> Dict[str, Any]:
    """Health probe for the CrowdStrike Falcon live connector."""
    try:
        from connectors.crowdstrike_live_connector import _creds_present
        has_creds = _creds_present()
        _conn()
        return {
            "status": "ok",
            "service": "crowdstrike-live-connector",
            "source_tool": "crowdstrike_falcon",
            "credentials_configured": has_creds,
            "mode": "live" if has_creds else "needs_credentials",
        }
    except (ImportError, RuntimeError, OSError) as exc:
        _logger.exception("crowdstrike-live connector health failed")
        raise HTTPException(status_code=503, detail=f"connector unavailable: {exc}") from exc


@router.get("/status", dependencies=[Depends(api_key_auth)])
def status() -> Dict[str, Any]:
    """Status alias of /health (Demo-001 contract)."""
    return health()


@router.post("/sync", dependencies=[Depends(api_key_auth)])
def sync(req: SyncRequest) -> Dict[str, Any]:
    """Fetch live detections from CrowdStrike Falcon REST API."""
    try:
        conn = _conn()
        kwargs: Dict[str, Any] = {
            "org_id": req.org_id,
            "force_refresh": req.force_refresh,
        }
        if req.filter_expr:
            kwargs["filter_expr"] = req.filter_expr
        return conn.fetch_detections(**kwargs)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (RuntimeError, OSError, TypeError) as exc:
        _logger.exception("crowdstrike-live sync failed")
        raise HTTPException(status_code=500, detail=f"sync failed: {exc}") from exc
