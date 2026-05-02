"""Splunk SOAR / Phantom Live Connector Router.

Prefix: /api/v1/connectors/splunk-soar-live
Auth:   api_key_auth dependency

Routes:
  GET  /health               — connector health probe
  GET  /status               — alias of /health (Demo-001 contract)
  POST /sync                 — fetch SOAR containers/incidents
  POST /playbook/trigger     — trigger a playbook on a container
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/connectors/splunk-soar-live",
    tags=["Splunk SOAR Live Connector"],
)


def _conn():
    from connectors.splunk_soar_connector import get_splunk_soar_connector
    return get_splunk_soar_connector()


class SyncRequest(BaseModel):
    org_id: str = Field(default="default", min_length=1, max_length=128)
    force_refresh: bool = Field(default=False)
    max_containers: int = Field(default=200, ge=1, le=10000)
    label_filter: Optional[str] = Field(default=None, max_length=128)


class TriggerPlaybookRequest(BaseModel):
    org_id: str = Field(default="default", min_length=1, max_length=128)
    container_id: str = Field(..., min_length=1, max_length=64)
    playbook_id: str = Field(..., min_length=1, max_length=128)


@router.get("/health", dependencies=[Depends(api_key_auth)])
def health() -> Dict[str, Any]:
    """Health probe for the Splunk SOAR live connector."""
    try:
        from connectors.splunk_soar_connector import _creds_present
        has_creds = _creds_present()
        _conn()
        return {
            "status": "ok",
            "service": "splunk-soar-live-connector",
            "source_tool": "splunk_soar",
            "credentials_configured": has_creds,
            "mode": "live" if has_creds else "needs_credentials",
        }
    except (ImportError, RuntimeError, OSError) as exc:
        _logger.exception("splunk-soar-live connector health failed")
        raise HTTPException(status_code=503, detail=f"connector unavailable: {exc}") from exc


@router.get("/status", dependencies=[Depends(api_key_auth)])
def status() -> Dict[str, Any]:
    """Status alias of /health (Demo-001 contract)."""
    return health()


@router.post("/sync", dependencies=[Depends(api_key_auth)])
def sync(req: SyncRequest) -> Dict[str, Any]:
    """Fetch SOAR containers/incidents from Splunk SOAR REST API."""
    try:
        conn = _conn()
        return conn.sync(org_id=req.org_id, force_refresh=req.force_refresh)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (RuntimeError, OSError, TypeError) as exc:
        _logger.exception("splunk-soar-live sync failed")
        raise HTTPException(status_code=500, detail=f"sync failed: {exc}") from exc


@router.post("/playbook/trigger", dependencies=[Depends(api_key_auth)])
def trigger_playbook(req: TriggerPlaybookRequest) -> Dict[str, Any]:
    """Trigger a Splunk SOAR playbook on a specific container."""
    try:
        from connectors.splunk_soar_connector import trigger_playbook as _trigger
        return _trigger(
            org_id=req.org_id,
            container_id=req.container_id,
            playbook_id=req.playbook_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (RuntimeError, OSError, TypeError) as exc:
        _logger.exception("splunk-soar playbook trigger failed")
        raise HTTPException(status_code=500, detail=f"trigger failed: {exc}") from exc
