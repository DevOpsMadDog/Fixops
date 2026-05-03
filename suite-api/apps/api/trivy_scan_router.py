"""Trivy Image Scan Router — async-queued model.

Prefix: /api/v1/trivy

Complementary to the legacy /api/v1/scan/trivy router (synchronous in-memory
TrivyScanner).  This router is the durable async-queue front door:

    GET  /              — capability summary
    POST /image         — queue an image scan, returns {scan_id, queued_at}
    GET  /image/{id}    — fetch scan record (status, severity_counts, vulns)

Backed by core.trivy_scan_engine.TrivyScanEngine (SQLite at
data/security/trivy_scans.db).
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/trivy",
    tags=["trivy-scan"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class ImageScanRequest(BaseModel):
    image: str = Field(..., description="Image reference, e.g. nginx:1.25-alpine")
    severities: Optional[List[str]] = Field(
        default=None,
        description="Subset of CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN to filter on",
    )
    skip_files: Optional[List[str]] = Field(
        default=None, description="Paths to pass to --skip-files"
    )
    ignore_unfixed: bool = Field(
        default=False, description="Pass --ignore-unfixed to trivy"
    )


class ImageScanQueuedResponse(BaseModel):
    scan_id: str
    image: str
    queued_at: str


class ImageScanRecordResponse(BaseModel):
    scan_id: str
    image: str
    status: str
    severity_counts: Dict[str, int]
    scan_started_at: Optional[str] = None
    scan_completed_at: Optional[str] = None
    vulnerabilities: List[Dict[str, Any]] = Field(default_factory=list)


class CapabilitySummary(BaseModel):
    service: str
    scanners: List[str]
    supported_formats: List[str]
    valid_severities: List[str]
    binary_present: bool
    scan_count: int
    status: str  # ok | empty | degraded


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/",
    response_model=CapabilitySummary,
    summary="Trivy scan engine capability summary",
)
def trivy_root() -> Dict[str, Any]:
    from core.trivy_scan_engine import get_trivy_scan_engine

    engine = get_trivy_scan_engine()
    return engine.capability_summary()


@router.post(
    "/image",
    response_model=ImageScanQueuedResponse,
    summary="Queue an image scan",
)
def queue_image_scan(body: ImageScanRequest) -> Dict[str, Any]:
    from core.trivy_scan_engine import get_trivy_scan_engine

    if not body.image or not body.image.strip():
        raise HTTPException(status_code=422, detail="image must be a non-empty string")

    if body.severities:
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
        bad = [s for s in body.severities if s.upper() not in valid]
        if bad:
            raise HTTPException(
                status_code=422,
                detail=f"invalid severities: {bad} — allowed: {sorted(valid)}",
            )

    engine = get_trivy_scan_engine()
    try:
        return engine.queue_scan(
            image=body.image,
            severities=body.severities,
            skip_files=body.skip_files,
            ignore_unfixed=body.ignore_unfixed,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:  # noqa: BLE001
        logger.error("queue_image_scan failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get(
    "/image/{scan_id}",
    response_model=ImageScanRecordResponse,
    summary="Fetch image scan record",
)
def get_image_scan(scan_id: str) -> Dict[str, Any]:
    from core.trivy_scan_engine import get_trivy_scan_engine

    engine = get_trivy_scan_engine()
    record = engine.get_scan(scan_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"scan_id {scan_id!r} not found")
    return record
