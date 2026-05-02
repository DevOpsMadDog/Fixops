"""HashiCorp Vault Live Connector Router (PAM).

Prefix: /api/v1/connectors/vault-live
Auth:   api_key_auth dependency

Routes:
  GET  /health   — connector health probe
  GET  /status   — alias of /health (Demo-001 contract)
  POST /sync     — fetch secrets metadata and lease findings from Vault
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/connectors/vault-live",
    tags=["HashiCorp Vault Live Connector"],
)


def _conn():
    from connectors.vault_connector import get_vault_connector
    return get_vault_connector()


class SyncRequest(BaseModel):
    org_id: str = Field(default="default", min_length=1, max_length=128)
    force_refresh: bool = Field(default=False)
    kv_mount: Optional[str] = Field(default=None, max_length=128)
    secret_path: Optional[str] = Field(default=None, max_length=512)


@router.get("/health", dependencies=[Depends(api_key_auth)])
def health() -> Dict[str, Any]:
    """Health probe for the HashiCorp Vault live connector."""
    try:
        from connectors.vault_connector import _creds_present
        has_creds = _creds_present()
        _conn()
        return {
            "status": "ok",
            "service": "vault-live-connector",
            "source_tool": "hashicorp_vault",
            "credentials_configured": has_creds,
            "mode": "live" if has_creds else "needs_credentials",
        }
    except (ImportError, RuntimeError, OSError) as exc:
        _logger.exception("vault-live connector health failed")
        raise HTTPException(status_code=503, detail=f"connector unavailable: {exc}") from exc


@router.get("/status", dependencies=[Depends(api_key_auth)])
def status() -> Dict[str, Any]:
    """Status alias of /health (Demo-001 contract)."""
    return health()


@router.post("/sync", dependencies=[Depends(api_key_auth)])
def sync(req: SyncRequest) -> Dict[str, Any]:
    """Fetch secrets metadata and lease findings from HashiCorp Vault."""
    try:
        conn = _conn()
        kwargs: Dict[str, Any] = {
            "org_id": req.org_id,
            "force_refresh": req.force_refresh,
        }
        if req.kv_mount:
            kwargs["kv_mount"] = req.kv_mount
        if req.secret_path:
            kwargs["secret_path"] = req.secret_path
        return conn.sync(**kwargs)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (RuntimeError, OSError, TypeError) as exc:
        _logger.exception("vault-live sync failed")
        raise HTTPException(status_code=500, detail=f"sync failed: {exc}") from exc
