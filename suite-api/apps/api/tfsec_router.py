"""tfsec IaC Scan Router — Terraform-only static-analysis endpoints.

Mounted at ``/api/v1/tfsec``.

Endpoints
---------
- ``GET  /api/v1/tfsec/``                — capability summary (8 providers, 4 severities)
- ``GET  /api/v1/tfsec/providers``       — provider catalog with rule counts
- ``POST /api/v1/tfsec/scan``            — queue a Terraform scan
- ``GET  /api/v1/tfsec/scan/{scan_id}``  — fetch scan + severity/provider counts + findings

Auth scopes (mounted in app.py)
- ``read:scans`` for GET endpoints
- ``write:scans`` for POST (kept under same gate for now)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from core.tfsec_scan_engine import (
    PROVIDERS,
    SEVERITY_LEVELS,
    get_tfsec_scan_engine,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/tfsec", tags=["IaC", "tfsec", "Terraform"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class TfsecCapabilityResponse(BaseModel):
    service: str = Field(default="tfsec")
    scope: str = Field(default="terraform-only")
    providers: List[str]
    severity_levels: List[str]
    status: str
    tfsec_binary_available: bool
    scan_count: int
    db_path: str


class ProviderCatalogEntry(BaseModel):
    provider: str
    rule_count: int
    description: str


class TfsecProviderCatalogResponse(BaseModel):
    providers: List[ProviderCatalogEntry]
    total_providers: int
    total_rules: int


class TfsecScanCreateRequest(BaseModel):
    target_path: str = Field(..., min_length=1, max_length=4096)
    exclude_checks: Optional[List[str]] = Field(default=None)
    minimum_severity: Optional[str] = Field(default=None)
    soft_fail: Optional[bool] = Field(default=None)


class TfsecScanQueuedResponse(BaseModel):
    scan_id: str
    target_path: str
    queued_at: str
    status: str


class TfsecFinding(BaseModel):
    rule_id: str
    severity: str
    provider: str
    resource: str
    file_path: str
    line: int
    description: str


class TfsecScanDetailResponse(BaseModel):
    scan_id: str
    target_path: str
    status: str
    severity_counts: Dict[str, int] = Field(default_factory=dict)
    provider_counts: Dict[str, int] = Field(default_factory=dict)
    findings: List[TfsecFinding] = Field(default_factory=list)
    started_at: str
    completed_at: Optional[str] = None
    exit_code: Optional[int] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/",
    response_model=TfsecCapabilityResponse,
    summary="tfsec capability summary",
)
async def tfsec_capability_summary() -> TfsecCapabilityResponse:
    """Return tfsec capability envelope: providers, severity levels, status."""
    engine = get_tfsec_scan_engine()
    summary = engine.capability_summary()
    return TfsecCapabilityResponse(**summary)


@router.get(
    "/providers",
    response_model=TfsecProviderCatalogResponse,
    summary="tfsec provider catalog with rule counts",
)
async def tfsec_provider_catalog() -> TfsecProviderCatalogResponse:
    """Return the static catalog of supported providers + rule counts."""
    engine = get_tfsec_scan_engine()
    catalog = engine.provider_catalog()
    return TfsecProviderCatalogResponse(**catalog)


@router.post(
    "/scan",
    response_model=TfsecScanQueuedResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Queue a tfsec Terraform scan",
)
async def queue_tfsec_scan(payload: TfsecScanCreateRequest) -> TfsecScanQueuedResponse:
    engine = get_tfsec_scan_engine()
    try:
        record = engine.queue_scan(
            target_path=payload.target_path,
            exclude_checks=payload.exclude_checks,
            minimum_severity=payload.minimum_severity,
            soft_fail=payload.soft_fail,
        )
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:  # noqa: BLE001
        logger.exception("Failed to queue tfsec scan")
        raise HTTPException(status_code=500, detail=f"queue_tfsec_scan failed: {e!s}")
    return TfsecScanQueuedResponse(**record)


@router.get(
    "/scan/{scan_id}",
    response_model=TfsecScanDetailResponse,
    summary="Fetch tfsec scan status + severity/provider counts + findings",
)
async def get_tfsec_scan(scan_id: str) -> TfsecScanDetailResponse:
    engine = get_tfsec_scan_engine()
    try:
        rec = engine.get_scan(scan_id)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    if rec is None:
        raise HTTPException(status_code=404, detail=f"Unknown scan_id: {scan_id}")
    # Strip private fields before returning.
    rec = dict(rec)
    rec.pop("_request", None)
    return TfsecScanDetailResponse(**rec)
