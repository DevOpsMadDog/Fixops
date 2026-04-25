"""IAM / SSO Connector Router — ALDECI.

Real Keycloak-backed IAM/SSO integration replacing five stubs:
Okta, Auth0, Microsoft Entra (Azure AD), OneLogin, Google Workspace.

Prefix:  /api/v1/connectors/iam-sso
Auth:    api_key_auth dependency

Routes:
  GET   /api/v1/connectors/iam-sso/providers     -- list aliased providers
  GET   /api/v1/connectors/iam-sso/health        -- check Keycloak reachability
  POST  /api/v1/connectors/iam-sso/sync          -- provision realms + pull events
  GET   /api/v1/connectors/iam-sso/status        -- last sync result (in-memory)
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from apps.api.auth_deps import api_key_auth

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/connectors/iam-sso",
    tags=["IAM/SSO Connector"],
    dependencies=[Depends(api_key_auth)],
)

# ---------------------------------------------------------------------------
# Singleton connector + last result cache
# ---------------------------------------------------------------------------

_connector_lock = threading.Lock()
_connector_instance = None
_last_result: Optional[Dict[str, Any]] = None


def _get_connector():
    """Lazy import + singleton — keeps import-time cost zero."""
    global _connector_instance
    if _connector_instance is None:
        with _connector_lock:
            if _connector_instance is None:
                from connectors.iam_sso_connector import IAMSSoConnector
                _connector_instance = IAMSSoConnector()
    return _connector_instance


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class SyncRequest(BaseModel):
    org_id_prefix: str = Field("tenant", min_length=1, max_length=32,
                               pattern=r"^[a-z][a-z0-9_-]*$",
                               description="Realm/org_id prefix; e.g. 'tenant' -> tenant-001..N")
    realm_count: int = Field(15, ge=1, le=100,
                             description="How many realms to provision (default 15)")
    force_synthetic: bool = Field(False,
                                  description="Skip Keycloak entirely; emit synthetic events")


class ProviderEntry(BaseModel):
    alias: str
    implementation: str
    status: str


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/providers", response_model=List[ProviderEntry])
def list_providers() -> List[Dict[str, str]]:
    """Return the list of vendor providers this connector replaces."""
    return _get_connector().list_providers()


@router.get("/health")
def health() -> Dict[str, Any]:
    """Probe Keycloak; return reachability + last-sync summary."""
    conn = _get_connector()
    try:
        client = conn._get_client()  # noqa: SLF001 — intentional internal access
        reachable = client.ping()
    except Exception as exc:  # ConnectionError, etc.
        logger.warning("IAM/SSO health probe failed: %s", exc)
        reachable = False
    return {
        "keycloak_url": conn.cfg.keycloak_url,
        "keycloak_reachable": reachable,
        "providers_replaced": sorted(set(__import__(
            "connectors.iam_sso_connector", fromlist=["PROVIDER_ALIASES"]
        ).PROVIDER_ALIASES.keys())),
        "last_sync": _last_result,
    }


@router.post("/sync")
def sync(req: SyncRequest) -> Dict[str, Any]:
    """Provision realms + ingest audit events into ALDECI engines."""
    global _last_result
    try:
        result = _get_connector().sync(
            org_id_prefix=req.org_id_prefix,
            realm_count=req.realm_count,
            force_synthetic=req.force_synthetic,
        )
    except Exception as exc:
        logger.exception("IAM/SSO sync failed")
        raise HTTPException(status_code=500, detail=f"sync_failed: {exc}") from exc
    _last_result = result.to_dict()
    return _last_result


@router.get("/status")
def status() -> Dict[str, Any]:
    """Return cached last-sync result (or empty if never run)."""
    return {"last_sync": _last_result}


# Alias `/health` <=> `/status` is intentionally NOT collapsed:
# /health includes a live Keycloak probe; /status is cache-only and cheap.
