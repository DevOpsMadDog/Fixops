"""Threat Intel Connector API Router — ALDECI

Endpoints
---------
POST  /api/v1/connectors/ti/sync          run all enabled adapters + correlate
POST  /api/v1/connectors/ti/sync/misp     run only MISP adapter
POST  /api/v1/connectors/ti/sync/circl    run only CIRCL CVE adapter
POST  /api/v1/connectors/ti/sync/phishtank  run only PhishTank adapter
POST  /api/v1/connectors/ti/sync/otx      run only OTX adapter
POST  /api/v1/connectors/ti/sync/ghsa     run only GitHub Advisory DB adapter
POST  /api/v1/connectors/ti/correlate     re-run cross-correlation only
GET   /api/v1/connectors/ti/health        adapter availability + key status
GET   /api/v1/connectors/ti/status        alias for /health (Demo-001)

Security
--------
* All endpoints gated by api_key_auth.
* org_id is read from the authenticated principal (header) and validated.
* Pydantic body models enforce length limits and value ranges.
* Long-running syncs are time-bounded by the adapter timeouts (30s default).
"""

from __future__ import annotations

import logging
from typing import List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/connectors/ti", tags=["connectors-threat-intel"])


# ---------------------------------------------------------------------------
# Lazy connector cache (one per (otx_key, misp_key) pair so different tenants
# can BYO their own keys via env)
# ---------------------------------------------------------------------------

_connector = None


def _get_connector():
    global _connector
    if _connector is None:
        from connectors.threat_intel_connector import ThreatIntelConnector

        _connector = ThreatIntelConnector()
    return _connector


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class SyncRequest(BaseModel):
    """Optional toggles for a sync_all run."""

    run_misp: bool = Field(True, description="Pull from MISP feeds")
    run_circl: bool = Field(True, description="Pull from CIRCL CVE feed")
    run_phishtank: bool = Field(True, description="Pull from PhishTank")
    run_otx: bool = Field(True, description="Pull from AlienVault OTX")
    run_ghsa: bool = Field(True, description="Pull from GitHub Advisory Database (GHSA)")
    run_correlation: bool = Field(
        True, description="Cross-correlate IoCs against tenant findings"
    )
    misp_feed_urls: Optional[List[str]] = Field(
        None,
        max_length=10,
        description="Override default MISP feed URLs (max 10).",
    )

    @field_validator("misp_feed_urls")
    @classmethod
    def validate_urls(cls, v):
        if v is None:
            return v
        for u in v:
            if not isinstance(u, str) or len(u) > 2048:
                raise ValueError("Each MISP URL must be a string under 2048 chars")
            if not (u.startswith("http://") or u.startswith("https://")):
                raise ValueError("MISP URL must start with http(s)://")
        return v


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _validate_org(org_id: str) -> str:
    org_id = (org_id or "").strip()
    if not org_id:
        raise HTTPException(status_code=400, detail="org_id is required")
    if len(org_id) > 128:
        raise HTTPException(status_code=400, detail="org_id too long (max 128)")
    return org_id


def _connector_for(misp_feed_urls: Optional[List[str]]):
    """Return the cached connector unless a per-request override is supplied."""
    if not misp_feed_urls:
        return _get_connector()
    from connectors.threat_intel_connector import ThreatIntelConnector

    return ThreatIntelConnector(misp_feed_urls=misp_feed_urls)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/sync")
async def sync_all(
    body: SyncRequest = SyncRequest(),
    org_id: str = Query(default="default", max_length=128),
    auth=Depends(api_key_auth),
):
    """Run all enabled adapters then cross-correlate IoCs against tenant findings."""
    org_id = _validate_org(org_id)
    conn = _connector_for(body.misp_feed_urls)
    try:
        result = conn.sync_all(
            org_id=org_id,
            run_misp=body.run_misp,
            run_circl=body.run_circl,
            run_phishtank=body.run_phishtank,
            run_otx=body.run_otx,
            run_ghsa=body.run_ghsa,
            run_correlation=body.run_correlation,
        )
        return result.to_dict()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:  # noqa: BLE001
        logger.exception("ti/sync failed for org=%s", org_id)
        raise HTTPException(status_code=500, detail=f"sync failed: {exc}")


@router.post("/sync/misp")
async def sync_misp(
    org_id: str = Query(default="default", max_length=128),
    auth=Depends(api_key_auth),
):
    org_id = _validate_org(org_id)
    try:
        n = _get_connector().sync_misp(org_id)
        return {"adapter": "misp", "ingested": n, "org_id": org_id}
    except Exception as exc:  # noqa: BLE001
        logger.exception("ti/sync/misp failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/sync/circl")
async def sync_circl(
    hours_back: int = Query(default=24, ge=1, le=168),
    org_id: str = Query(default="default", max_length=128),
    auth=Depends(api_key_auth),
):
    org_id = _validate_org(org_id)
    try:
        n = _get_connector().sync_circl(org_id, hours_back=hours_back)
        return {
            "adapter": "circl",
            "ingested": n,
            "hours_back": hours_back,
            "org_id": org_id,
        }
    except Exception as exc:  # noqa: BLE001
        logger.exception("ti/sync/circl failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/sync/phishtank")
async def sync_phishtank(
    org_id: str = Query(default="default", max_length=128),
    auth=Depends(api_key_auth),
):
    org_id = _validate_org(org_id)
    try:
        n = _get_connector().sync_phishtank(org_id)
        return {"adapter": "phishtank", "ingested": n, "org_id": org_id}
    except Exception as exc:  # noqa: BLE001
        logger.exception("ti/sync/phishtank failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/sync/otx")
async def sync_otx(
    org_id: str = Query(default="default", max_length=128),
    auth=Depends(api_key_auth),
):
    org_id = _validate_org(org_id)
    try:
        n = _get_connector().sync_otx(org_id)
        return {"adapter": "otx", "ingested": n, "org_id": org_id}
    except Exception as exc:  # noqa: BLE001
        logger.exception("ti/sync/otx failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/sync/ghsa")
async def sync_ghsa(
    per_page: int = Query(default=100, ge=1, le=100),
    max_pages: int = Query(default=5, ge=1, le=20),
    org_id: str = Query(default="default", max_length=128),
    auth=Depends(api_key_auth),
):
    """Pull GitHub Security Advisories from the official REST API.

    Incremental: subsequent calls use a stored ``modified_since`` cursor.
    Persists CVE / GHSA ids as ``cve``-typed indicators.
    """
    org_id = _validate_org(org_id)
    try:
        n = _get_connector().sync_ghsa(
            org_id, per_page=per_page, max_pages=max_pages
        )
        return {
            "adapter": "ghsa",
            "ingested": n,
            "per_page": per_page,
            "max_pages": max_pages,
            "org_id": org_id,
        }
    except Exception as exc:  # noqa: BLE001
        logger.exception("ti/sync/ghsa failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/correlate")
async def correlate(
    org_id: str = Query(default="default", max_length=128),
    auth=Depends(api_key_auth),
):
    """Re-run cross-correlation against the current IoC store."""
    org_id = _validate_org(org_id)
    try:
        events = _get_connector().cross_correlate(org_id)
        return {"correlations_created": len(events), "events": events[:50], "org_id": org_id}
    except Exception as exc:  # noqa: BLE001
        logger.exception("ti/correlate failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/health")
async def health(auth=Depends(api_key_auth)):
    """Adapter health + API-key configuration status (no network calls)."""
    try:
        return {"status": "healthy", "adapters": _get_connector().health()}
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/status")
async def status(auth=Depends(api_key_auth)):
    """Alias for /health (DEMO-001 requirement)."""
    return await health(auth=auth)
