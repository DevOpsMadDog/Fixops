"""Air-Gap Bundle Router — ALDECI (GAP-001).

Endpoints for the Air-Gap Bundle engine.

Prefix: /api/v1/air-gap
Auth:   api_key_auth dependency

Routes:
  POST /api/v1/air-gap/bundle/export                 export a signed bundle
  POST /api/v1/air-gap/bundle/verify/{bundle_id}     verify manifest + entries
  POST /api/v1/air-gap/bundle/apply/{bundle_id}      apply (idempotent upsert)
  POST /api/v1/air-gap/bundle/transfer               record transfer event
  GET  /api/v1/air-gap/bundle/list                   list bundles
  GET  /api/v1/air-gap/bundle/{bundle_id}            get bundle detail
  GET  /api/v1/air-gap/bundle/stats                  aggregated stats
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/air-gap",
    tags=["Air-Gap Bundle (GAP-001)"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.air_gap_bundle_engine import AirGapBundleEngine
        _engine = AirGapBundleEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class ExportRequest(BaseModel):
    bundle_version: Optional[str] = Field(default=None)
    include_cve: bool = True
    include_ti: bool = True
    include_policy: bool = True
    exported_by: str = "system"


class ApplyRequest(BaseModel):
    dry_run: bool = False
    applied_by: str = "system"
    require_verified: bool = True


class TransferRequest(BaseModel):
    bundle_id: str
    from_site: str = ""
    to_site: str = ""
    transport_method: str = "manual_usb"
    checksum_verified: bool = False
    notes: str = ""


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------


@router.post("/bundle/export", dependencies=[Depends(api_key_auth)], status_code=201)
def export_bundle(body: ExportRequest, org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Export a signed intelligence bundle for air-gapped consumption."""
    try:
        return _get_engine().export_bundle(
            org_id=org_id,
            bundle_version=body.bundle_version,
            include_cve=body.include_cve,
            include_ti=body.include_ti,
            include_policy=body.include_policy,
            exported_by=body.exported_by,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------


@router.post("/bundle/verify/{bundle_id}", dependencies=[Depends(api_key_auth)])
def verify_bundle(bundle_id: str) -> Dict[str, Any]:
    """Verify manifest + entry hashes + signature placeholder for a stored bundle."""
    try:
        return _get_engine().verify_bundle(bundle_id)
    except (KeyError, FileNotFoundError) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------


@router.post("/bundle/apply/{bundle_id}", dependencies=[Depends(api_key_auth)])
def apply_bundle(bundle_id: str, body: ApplyRequest) -> Dict[str, Any]:
    """Idempotently apply bundle entries into target tables. Respect dry_run."""
    try:
        return _get_engine().apply_bundle(
            bundle_id=bundle_id,
            dry_run=body.dry_run,
            applied_by=body.applied_by,
            require_verified=body.require_verified,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Transfer
# ---------------------------------------------------------------------------


@router.post("/bundle/transfer", dependencies=[Depends(api_key_auth)], status_code=201)
def record_transfer(body: TransferRequest) -> Dict[str, Any]:
    """Record a physical/logical transfer event for chain-of-custody."""
    try:
        return _get_engine().record_transfer(
            bundle_id=body.bundle_id,
            from_site=body.from_site,
            to_site=body.to_site,
            transport_method=body.transport_method,
            checksum_verified=body.checksum_verified,
            notes=body.notes,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------


@router.get("/bundle/list", dependencies=[Depends(api_key_auth)])
def list_bundles(
    org_id: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
) -> List[Dict[str, Any]]:
    """List bundles with optional filters."""
    try:
        return _get_engine().list_bundles(org_id=org_id, status=status, limit=limit)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/bundle/stats", dependencies=[Depends(api_key_auth)])
def get_bundle_stats(org_id: Optional[str] = Query(default=None)) -> Dict[str, Any]:
    """Return aggregated bundle stats (counts by status, size, entries by type)."""
    return _get_engine().stats(org_id=org_id)


# Note: this must come AFTER /bundle/list and /bundle/stats so FastAPI
# doesn't swallow "list"/"stats" as {bundle_id}.
@router.get("/bundle/{bundle_id}", dependencies=[Depends(api_key_auth)])
def get_bundle(bundle_id: str) -> Dict[str, Any]:
    """Get a bundle record including entries, transfers, and applications."""
    result = _get_engine().get_bundle(bundle_id)
    if result is None:
        raise HTTPException(status_code=404, detail="bundle not found")
    return result


@router.get("/", summary="Air-gap bundles index", tags=["air-gap"])
def air_gap_index(org_id: str = Query(default="default"), _auth: None = Depends(api_key_auth)) -> Dict[str, Any]:
    """Return a list of air-gap bundles for the org."""
    try:
        engine = _get_engine()
        bundles = engine.list_bundles(org_id=org_id) if hasattr(engine, "list_bundles") else []
    except Exception:
        bundles = []
    return {"router": "air-gap", "org_id": org_id, "items": bundles, "count": len(bundles)}
