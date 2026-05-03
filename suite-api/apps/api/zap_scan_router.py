"""ZAP DAST Scan Router — OWASP ZAP scan orchestration endpoints.

Mounted at ``/api/v1/zap`` to keep it disjoint from the existing
``/api/v1/dast`` router (suite-attack/api/dast_router.py) and the
``/api/v1/connectors/dast`` router (apps/api/dast_pentest_router.py).

Endpoints
---------
- ``GET  /api/v1/zap/``           — capability summary (profiles, status envelope)
- ``POST /api/v1/zap/scans``      — queue a new ZAP scan
- ``GET  /api/v1/zap/scans/{id}`` — fetch a scan + finding counts by severity

Security
--------
- SSRF prevention on ``target_url`` (handled in engine)
- Profile is whitelisted to {baseline, active, api}
- depth bounded to [1, 10]
- contexts is a list of opaque strings; not passed to shell

Auth scopes (mounted in platform_app.py)
- ``read:scan``  for GET endpoints
- ``write:scan`` for POST endpoints
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field, field_validator

from core.zap_scan_engine import (
    PROFILES,
    get_zap_scan_engine,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/zap", tags=["DAST", "ZAP"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class ZapScanCreateRequest(BaseModel):
    """Request payload for POST /api/v1/zap/scans."""

    target_url: str = Field(..., min_length=1, max_length=2048)
    profile: str = Field(default="baseline")
    depth: Optional[int] = Field(default=None, ge=1, le=10)
    contexts: Optional[List[str]] = Field(default=None)

    @field_validator("profile")
    @classmethod
    def _v_profile(cls, v: str) -> str:
        if v not in PROFILES:
            raise ValueError(
                f"profile must be one of: {list(PROFILES)}"
            )
        return v

    @field_validator("contexts")
    @classmethod
    def _v_contexts(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is None:
            return None
        if not isinstance(v, list):
            raise ValueError("contexts must be a list of strings")
        cleaned: List[str] = []
        for c in v:
            if not isinstance(c, str):
                raise ValueError("contexts entries must be strings")
            c2 = c.strip()
            if not c2:
                continue
            if len(c2) > 256:
                raise ValueError("context entry exceeds 256 chars")
            cleaned.append(c2)
        return cleaned


class ZapScanResponse(BaseModel):
    scan_id: str
    target: str
    profile: str
    status: str
    started_at: str
    completed_at: Optional[str] = None
    finding_summary: Dict[str, int] = Field(default_factory=dict)
    scan_metadata: Dict[str, Any] = Field(default_factory=dict)


class ZapCapabilityResponse(BaseModel):
    engine: str
    status: str
    zap_client_available: bool
    profiles: List[str]
    supported_scan_types: List[str]
    scan_count: int
    db_path: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/", response_model=ZapCapabilityResponse, summary="ZAP capability summary")
async def zap_capability_summary() -> ZapCapabilityResponse:
    """Return ZAP scan-engine capabilities + status envelope (ok|empty|degraded)."""
    engine = get_zap_scan_engine()
    summary = engine.capability_summary()
    return ZapCapabilityResponse(**summary)


@router.post(
    "/scans",
    response_model=ZapScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Queue a ZAP scan",
)
async def queue_zap_scan(payload: ZapScanCreateRequest) -> ZapScanResponse:
    """Queue a new ZAP scan against ``target_url`` using the chosen profile."""
    engine = get_zap_scan_engine()
    try:
        record = engine.queue_scan(
            target_url=payload.target_url,
            profile=payload.profile,
            depth=payload.depth,
            contexts=payload.contexts,
        )
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:  # noqa: BLE001
        logger.exception("Failed to queue ZAP scan")
        raise HTTPException(status_code=500, detail=f"queue_zap_scan failed: {e!s}")

    full = engine.get_scan(record["scan_id"]) or record
    return ZapScanResponse(**full)


@router.get(
    "/scans/{scan_id}",
    response_model=ZapScanResponse,
    summary="Fetch ZAP scan status + finding counts",
)
async def get_zap_scan(scan_id: str) -> ZapScanResponse:
    engine = get_zap_scan_engine()
    try:
        rec = engine.get_scan(scan_id)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    if rec is None:
        raise HTTPException(status_code=404, detail=f"Unknown scan_id: {scan_id}")
    return ZapScanResponse(**rec)
