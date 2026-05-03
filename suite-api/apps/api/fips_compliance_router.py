"""FIPS Compliance Mode Router — ALDECI.

Exposes FIPSComplianceModeEngine endpoints for FIPS 140-3 and PQC readiness.

Prefix: /api/v1/fips
Auth:   api_key_auth dependency on all routes

Routes:
  GET  /api/v1/fips/status               get_fips_status(org_id)
  POST /api/v1/fips/activate             activate_fips_mode(org_id)
  POST /api/v1/fips/deactivate           deactivate_fips_mode(org_id)
  POST /api/v1/fips/pqc/register        register_pqc_algo(org_id, service_ref, algo, category)
  GET  /api/v1/fips/pqc/inventory       list_pqc_inventory(org_id, category?)
  POST /api/v1/fips/crypto/scan         scan_crypto_usage(org_id)
  GET  /api/v1/fips/crypto/scans        list_crypto_scans(org_id, scan_id?, legacy_only?)
  GET  /api/v1/fips/readiness           fips_readiness_score(org_id)
  GET  /api/v1/fips/stats               stats(org_id)
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/fips",
    tags=["FIPS Compliance Mode"],
    dependencies=[Depends(api_key_auth)],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.fips_compliance_mode_engine import get_engine
        _engine = get_engine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class OrgRequest(BaseModel):
    org_id: str = Field(default="default", min_length=1, max_length=128)


class RegisterPqcAlgoRequest(BaseModel):
    org_id: str = Field(default="default", min_length=1, max_length=128)
    service_ref: str = Field(..., min_length=1, max_length=512)
    algo: str = Field(..., min_length=1, max_length=64)
    category: str = Field(..., min_length=1, max_length=64)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/status")
def get_fips_status(
    org_id: str = Query(default="default", max_length=128),
) -> Dict[str, Any]:
    """Return current FIPS 140-3 mode status for an org."""
    return _get_engine().get_fips_status(org_id=org_id)


@router.post("/activate")
def activate_fips_mode(body: OrgRequest) -> Dict[str, Any]:
    """Activate FIPS 140-3 mode for an org (idempotent)."""
    return _get_engine().activate_fips_mode(org_id=body.org_id)


@router.post("/deactivate")
def deactivate_fips_mode(body: OrgRequest) -> Dict[str, Any]:
    """Deactivate FIPS 140-3 mode for an org (idempotent)."""
    return _get_engine().deactivate_fips_mode(org_id=body.org_id)


@router.post("/pqc/register")
def register_pqc_algo(body: RegisterPqcAlgoRequest) -> Dict[str, Any]:
    """Register a PQC or legacy algorithm usage for a service."""
    try:
        return _get_engine().register_pqc_algo(
            org_id=body.org_id,
            service_ref=body.service_ref,
            algo=body.algo,
            category=body.category,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/pqc/inventory")
def list_pqc_inventory(
    org_id: str = Query(default="default", max_length=128),
    category: Optional[str] = Query(default=None, max_length=64),
) -> Dict[str, Any]:
    """List PQC inventory entries, optionally filtered by category."""
    try:
        items = _get_engine().list_pqc_inventory(org_id=org_id, category=category)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {"org_id": org_id, "count": len(items), "inventory": items}


@router.post("/crypto/scan")
def scan_crypto_usage(body: OrgRequest) -> Dict[str, Any]:
    """Scan PQC inventory for legacy algorithms and persist a scan record."""
    return _get_engine().scan_crypto_usage(org_id=body.org_id)


@router.get("/crypto/scans")
def list_crypto_scans(
    org_id: str = Query(default="default", max_length=128),
    scan_id: Optional[str] = Query(default=None, max_length=128),
    legacy_only: bool = Query(default=False),
) -> Dict[str, Any]:
    """List crypto usage scan entries for an org."""
    items = _get_engine().list_crypto_scans(
        org_id=org_id,
        scan_id=scan_id,
        legacy_only=legacy_only,
    )
    return {"org_id": org_id, "count": len(items), "scans": items}


@router.get("/readiness")
def fips_readiness_score(
    org_id: str = Query(default="default", max_length=128),
) -> Dict[str, Any]:
    """Return FIPS/PQC readiness score 0-100 with interpretation."""
    return _get_engine().fips_readiness_score(org_id=org_id)


@router.get("/stats")
def get_stats(
    org_id: str = Query(default="default", max_length=128),
) -> Dict[str, Any]:
    """Aggregate FIPS/PQC stats for an org."""
    return _get_engine().stats(org_id=org_id)
