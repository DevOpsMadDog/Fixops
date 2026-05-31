"""Data Residency Router — ALDECI.

Endpoints for geographic data-residency tracking and violation reporting.
Uses DataSecurityEngine.residency_tracker (DataResidencyTracker) from
core.data_security.  There is NO module called core.geo_engine — the real
engine lives in core.data_security.

Prefix: /api/v1/data-residency
Auth:   api_key_auth dependency

Routes:
  GET  /api/v1/data-residency/health       — liveness probe
  GET  /api/v1/data-residency/records      — all registered dataset records
  GET  /api/v1/data-residency/violations   — records where compliant=False
  POST /api/v1/data-residency/register     — register a dataset and check residency
"""

from __future__ import annotations

import logging
from typing import List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/data-residency",
    tags=["Data Residency"],
)

# ---------------------------------------------------------------------------
# Lazy engine accessor.
# Real module: core.data_security  (NOT core.geo_engine — that does not exist)
# Real singleton factory: get_engine() -> DataSecurityEngine
# Residency methods on engine: get_residency_status(), register_dataset()
# ---------------------------------------------------------------------------

def _engine():
    from core.data_security import get_engine  # noqa: PLC0415
    return get_engine()


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class RegisterDatasetRequest(BaseModel):
    dataset_name: str = Field(..., description="Human-readable dataset name")
    data_categories: List[str] = Field(
        ...,
        description="e.g. ['pii', 'phi', 'pci', 'classified', 'financial', 'credentials', 'unknown']",
    )
    storage_region: str = Field(
        ...,
        description="e.g. 'us-east', 'us-west', 'eu-west', 'eu-central', 'apac', 'unknown'",
    )
    approved_regions: Optional[List[str]] = Field(
        default=None,
        description="Explicit approved regions; auto-derived from categories if omitted",
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/health")
def residency_health():
    """Liveness probe — no auth required."""
    return {"status": "healthy", "router": "data-residency", "version": "1.0.0"}


@router.get("/records", dependencies=[Depends(api_key_auth)])
def list_residency_records():
    """Return all registered dataset residency records."""
    try:
        records = _engine().get_residency_status()
        return {
            "records": [_serialise(r) for r in records],
            "count": len(records),
        }
    except Exception as exc:
        _logger.error("data_residency.records error: %s", exc)
        raise HTTPException(status_code=503, detail=f"Data residency engine unavailable: {exc}") from exc


@router.get("/violations", dependencies=[Depends(api_key_auth)])
def list_violations():
    """Return dataset records that have residency violations (compliant=False)."""
    try:
        records = _engine().get_residency_status()
        violations = [_serialise(r) for r in records if not r.compliant]
        return {"violations": violations, "count": len(violations)}
    except Exception as exc:
        _logger.error("data_residency.violations error: %s", exc)
        raise HTTPException(status_code=503, detail=f"Data residency engine unavailable: {exc}") from exc


@router.post("/register", dependencies=[Depends(api_key_auth)], status_code=201)
def register_dataset(body: RegisterDatasetRequest):
    """
    Register a dataset's geographic location and check for residency violations.

    data_categories values map to core.data_security.DataCategory enum values
    (pii, phi, pci, classified, financial, generic).
    storage_region values map to core.data_security.Region enum values.
    """
    from core.data_security import DataCategory, Region  # noqa: PLC0415

    # Map string inputs to enums — unknown values fall back to GENERIC/UNKNOWN
    try:
        cats = [DataCategory(c.lower()) for c in body.data_categories]
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid data_category: {exc}") from exc

    try:
        region = Region(body.storage_region.lower().replace("_", "-"))
    except ValueError:
        region = Region.UNKNOWN

    approved: Optional[List[Region]] = None
    if body.approved_regions:
        try:
            approved = [Region(r.lower().replace("_", "-")) for r in body.approved_regions]
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"Invalid approved_region: {exc}") from exc

    try:
        record = _engine().register_dataset(
            dataset_name=body.dataset_name,
            data_categories=cats,
            storage_region=region,
            approved_regions=approved,
        )
        return _serialise(record)
    except Exception as exc:
        _logger.error("data_residency.register error: %s", exc)
        raise HTTPException(status_code=503, detail=f"Data residency engine unavailable: {exc}") from exc


# ---------------------------------------------------------------------------
# Serialisation helper (ResidencyRecord is a dataclass, not a Pydantic model)
# ---------------------------------------------------------------------------

def _serialise(record) -> dict:
    try:
        return {
            "record_id": record.record_id,
            "dataset_name": record.dataset_name,
            "data_categories": [c.value if hasattr(c, "value") else str(c) for c in record.data_categories],
            "storage_region": record.storage_region.value if hasattr(record.storage_region, "value") else str(record.storage_region),
            "approved_regions": [r.value if hasattr(r, "value") else str(r) for r in (record.approved_regions or [])],
            "violations": record.violations,
            "regulations_at_risk": [r.value if hasattr(r, "value") else str(r) for r in (record.regulations_at_risk or [])],
            "compliant": record.compliant,
            "checked_at": record.checked_at.isoformat() if hasattr(record.checked_at, "isoformat") else str(record.checked_at),
        }
    except Exception:  # pragma: no cover
        return {"raw": str(record)}
