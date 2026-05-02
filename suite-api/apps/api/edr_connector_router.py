"""EDR/XDR Connector Router — exposes Falco + osquery + Wazuh sync endpoints.

Prefix: /api/v1/connectors/edr
Auth:   api_key_auth dependency

Routes:
  POST /api/v1/connectors/edr/sync         — single-org sync (live or fallback)
  POST /api/v1/connectors/edr/sync/falco   — Falco-only sync
  POST /api/v1/connectors/edr/sync/osquery — osquery-only sync
  POST /api/v1/connectors/edr/sync/wazuh   — Wazuh-only sync
  POST /api/v1/connectors/edr/sync/all-tenants — fan-out to many orgs
  GET  /api/v1/connectors/edr/health       — connector health probe
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/connectors/edr",
    tags=["EDR Connector"],
)


def _conn():
    from connectors.edr_connector import get_edr_connector
    return get_edr_connector()


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------
class SyncRequest(BaseModel):
    org_id: str = Field(default="default", min_length=1, max_length=128)
    hostname: str = Field(default="kind-aldeci-edr-control-plane", max_length=255)
    max_events: int = Field(default=5, ge=1, le=100)
    force_fallback: bool = Field(default=False)


class OsqueryRequest(BaseModel):
    org_id: str = Field(default="default", min_length=1, max_length=128)
    log_file: Optional[str] = Field(default=None, max_length=1024)
    max_events: int = Field(default=5, ge=1, le=100)


class WazuhRequest(BaseModel):
    org_id: str = Field(default="default", min_length=1, max_length=128)
    alerts_file: Optional[str] = Field(default=None, max_length=1024)
    max_events: int = Field(default=5, ge=1, le=100)


class TenantFanoutRequest(BaseModel):
    org_ids: List[str] = Field(..., min_length=1, max_length=100)
    events_per_org: int = Field(default=4, ge=3, le=5)
    force_fallback: bool = Field(default=True)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@router.get("/health", dependencies=[Depends(api_key_auth)])
def health() -> Dict[str, Any]:
    """Health probe for the EDR connector."""
    try:
        conn = _conn()
        return {
            "status": "ok",
            "service": "edr-connector",
            "kube_context": conn._kube_context,
            "falco_namespace": conn._falco_ns,
            "kubectl_path": conn._kubectl,
        }
    except (ImportError, RuntimeError, OSError) as exc:
        _logger.exception("edr connector health failed")
        raise HTTPException(status_code=503, detail=f"connector unavailable: {exc}") from exc


@router.get("/status", dependencies=[Depends(api_key_auth)])
def status() -> Dict[str, Any]:
    """Status alias of /health (Demo-001 contract)."""
    return health()


@router.post("/sync", dependencies=[Depends(api_key_auth)])
def sync(req: SyncRequest) -> Dict[str, Any]:
    """Run a Falco sync for a single org."""
    try:
        return _conn().sync_from_falco(
            org_id=req.org_id,
            hostname=req.hostname,
            max_events=req.max_events,
            force_fallback=req.force_fallback,
        )
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (RuntimeError, OSError) as exc:
        _logger.exception("edr sync failed")
        raise HTTPException(status_code=500, detail=f"sync failed: {exc}") from exc


@router.post("/sync/falco", dependencies=[Depends(api_key_auth)])
def sync_falco(req: SyncRequest) -> Dict[str, Any]:
    return sync(req)


@router.post("/sync/osquery", dependencies=[Depends(api_key_auth)])
def sync_osquery(req: OsqueryRequest) -> Dict[str, Any]:
    try:
        return _conn().sync_from_osquery(
            org_id=req.org_id,
            log_file=req.log_file,
            max_events=req.max_events,
        )
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (RuntimeError, OSError) as exc:
        _logger.exception("osquery sync failed")
        raise HTTPException(status_code=500, detail=f"sync failed: {exc}") from exc


@router.post("/sync/wazuh", dependencies=[Depends(api_key_auth)])
def sync_wazuh(req: WazuhRequest) -> Dict[str, Any]:
    try:
        return _conn().sync_from_wazuh(
            org_id=req.org_id,
            alerts_file=req.alerts_file,
            max_events=req.max_events,
        )
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (RuntimeError, OSError) as exc:
        _logger.exception("wazuh sync failed")
        raise HTTPException(status_code=500, detail=f"sync failed: {exc}") from exc


@router.post("/sync/all-tenants", dependencies=[Depends(api_key_auth)])
def sync_all_tenants(req: TenantFanoutRequest) -> Dict[str, Any]:
    """Fan out across many tenants — synthesizes 3-5 alerts per org."""
    try:
        return _conn().sync_all_tenants(
            org_ids=req.org_ids,
            events_per_org=req.events_per_org,
            force_fallback=req.force_fallback,
        )
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (RuntimeError, OSError) as exc:
        _logger.exception("multi-tenant edr sync failed")
        raise HTTPException(status_code=500, detail=f"sync failed: {exc}") from exc
