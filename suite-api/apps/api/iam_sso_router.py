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

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

_SIMULATION_WARNING = {
    "is_simulated": True,
    "engine": "iam_sso_connector",
    "real_integration_required": "/api/v1/connectors/iam-sso/configure",
    "do_not_use_in_demo": True,
}

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


class IngestVendorRequest(BaseModel):
    """Ingest already-collected events from a third-party IdP."""
    vendor: str = Field(..., pattern=r"^(keycloak|okta|auth0|entra|azure_ad)$",
                        description="IdP vendor whose raw event format to parse")
    realm: str = Field(..., min_length=1, max_length=64,
                       pattern=r"^[a-z0-9][a-z0-9_-]*$",
                       description="Target realm / org_id for the events")
    events: List[Dict[str, Any]] = Field(..., max_length=1000,
                                         description="Raw vendor events (max 1000)")


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
    return {"data": _last_result, "_simulation_warning": _SIMULATION_WARNING}


@router.get("/status")
def status() -> Dict[str, Any]:
    """Return cached last-sync result (or empty if never run)."""
    return {"last_sync": _last_result}


# Alias `/health` <=> `/status` is intentionally NOT collapsed:
# /health includes a live Keycloak probe; /status is cache-only and cheap.


@router.post("/ingest-vendor")
def ingest_vendor(req: IngestVendorRequest) -> Dict[str, Any]:
    """Ingest already-collected raw events from Okta / Auth0 / Entra / Keycloak.

    Each event is normalized via the vendor adapter, then mirrored to the same
    SecurityFindingsEngine + AccessAnomalyEngine path used by ``/sync``.
    """
    from connectors.iam_sso_connector import (  # local import keeps cold start cheap
        _admin_to_finding_payload,
        _login_to_anomaly_event,
        _login_to_finding_payload,
        _safe_import_anomaly_engine,
        _safe_import_findings_engine,
        normalize_vendor_event,
    )

    findings_engine = _safe_import_findings_engine()
    anomaly_engine = _safe_import_anomaly_engine()

    accepted = 0
    skipped = 0
    findings_emitted = 0
    anomaly_emitted = 0
    errors: List[str] = []

    for raw in req.events:
        try:
            kc_ev = normalize_vendor_event(req.vendor, raw, req.realm)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if kc_ev is None:
            skipped += 1
            continue
        accepted += 1
        # Login-shape events have a top-level 'type'; admin-shape have 'operationType'.
        if "type" in kc_ev:
            payload = _login_to_finding_payload(kc_ev)
            if payload and findings_engine is not None:
                try:
                    findings_engine.record_finding(org_id=req.realm, **payload)
                    findings_emitted += 1
                except Exception as exc:
                    errors.append(f"finding: {exc}")
            anom = _login_to_anomaly_event(kc_ev)
            if anom and anomaly_engine is not None:
                try:
                    anomaly_engine.record_event(org_id=req.realm, **anom)
                    anomaly_emitted += 1
                except Exception as exc:
                    errors.append(f"anomaly: {exc}")
        elif "operationType" in kc_ev:
            payload = _admin_to_finding_payload(kc_ev)
            if payload and findings_engine is not None:
                try:
                    findings_engine.record_finding(org_id=req.realm, **payload)
                    findings_emitted += 1
                except Exception as exc:
                    errors.append(f"finding: {exc}")

    return {
        "vendor": req.vendor,
        "realm": req.realm,
        "events_received": len(req.events),
        "events_accepted": accepted,
        "events_skipped_irrelevant": skipped,
        "findings_emitted": findings_emitted,
        "anomaly_events_emitted": anomaly_emitted,
        "errors": errors,
    }
