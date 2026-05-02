"""FIPS Compliance Mode Router — ALDECI.

GAP-042: FIPS 140-3 mode + PQC inventory + FedRAMP audit evidence export.

Prefix: /api/v1/fips
Auth:   api_key_auth dependency

Routes:
  POST  /api/v1/fips/activate         activate_fips_mode
  POST  /api/v1/fips/deactivate       deactivate_fips_mode
  POST  /api/v1/fips/scan             scan_crypto_usage
  POST  /api/v1/fips/pqc-algo         register_pqc_algo
  GET   /api/v1/fips/pqc-inventory    list_pqc_inventory
  GET   /api/v1/fips/readiness        fips_readiness_score
  GET   /api/v1/fips/evidence         export_fips_evidence
  GET   /api/v1/fips/stats            stats
  GET   /api/v1/fips/status           get_fips_status
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/fips",
    tags=["FIPS Compliance"],
    dependencies=[Depends(api_key_auth)],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.fips_compliance_mode_engine import FIPSComplianceModeEngine
        _engine = FIPSComplianceModeEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class OrgOnlyRequest(BaseModel):
    org_id: str


class PQCAlgoRegister(BaseModel):
    org_id: str
    service_ref: str
    algo: str
    category: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/activate")
def activate_fips_mode(body: OrgOnlyRequest) -> Dict[str, Any]:
    return _get_engine().activate_fips_mode(org_id=body.org_id)


@router.post("/deactivate")
def deactivate_fips_mode(body: OrgOnlyRequest) -> Dict[str, Any]:
    return _get_engine().deactivate_fips_mode(org_id=body.org_id)


@router.post("/scan")
def scan_crypto_usage(body: OrgOnlyRequest) -> Dict[str, Any]:
    return _get_engine().scan_crypto_usage(org_id=body.org_id)


@router.post("/pqc-algo")
def register_pqc_algo(body: PQCAlgoRegister) -> Dict[str, Any]:
    try:
        return _get_engine().register_pqc_algo(
            org_id=body.org_id,
            service_ref=body.service_ref,
            algo=body.algo,
            category=body.category,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/pqc-inventory")
def list_pqc_inventory(
    org_id: str = Query(...),
    category: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    try:
        return _get_engine().list_pqc_inventory(org_id=org_id, category=category)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/readiness")
def fips_readiness_score(org_id: str = Query(...)) -> Dict[str, Any]:
    return _get_engine().fips_readiness_score(org_id=org_id)


@router.get("/evidence")
def export_fips_evidence(org_id: str = Query(...)) -> Dict[str, Any]:
    return _get_engine().export_fips_evidence(org_id=org_id)


@router.get("/status")
def get_fips_status(org_id: str = Query(...)) -> Dict[str, Any]:
    return _get_engine().get_fips_status(org_id=org_id)


@router.get("/runtime-status")
def get_runtime_fips_status() -> Dict[str, Any]:
    """Return live OpenSSL FIPS boundary status (no org scope required).

    Response always contains:
      - ``enabled``            — bool: True only when OpenSSL FIPS module is active
      - ``openssl_version``    — str: e.g. "OpenSSL 3.0.7 1 Nov 2022"
      - ``validated_module``   — str | None: populated only when enabled=True
      - ``algorithms_allowed`` — list[str]: FIPS 140-3 approved algorithms (MD5/SHA1 excluded)
    """
    from core.fips_boot import get_runtime_fips_status as _runtime_status
    return _runtime_status()


@router.get("/stats")
def stats(org_id: str = Query(...)) -> Dict[str, Any]:
    return _get_engine().stats(org_id=org_id)


# Health/status aliases for enterprise API compliance
@router.get("/health")
def health() -> Dict[str, Any]:
    return {"status": "ok", "component": "fips_compliance_mode"}
