"""Grype Vulnerability Scanner Router — ALDECI.

Wraps `core.grype_scan_engine.GrypeScanEngine` to expose REST endpoints
for queueing image / SBOM / directory scans and inspecting results.

Prefix: /api/v1/grype
Auth:   api_key_auth dependency (mount layer adds scope checks)

Routes:
  GET  /api/v1/grype/                  capability summary
  POST /api/v1/grype/scan              queue a new scan
  GET  /api/v1/grype/scan/{scan_id}    fetch scan status + findings

NO MOCKS rule: when the grype binary is missing the engine records the
job as ``unavailable`` with an explanatory error — no fake vulns are
returned. Consumers should render an EmptyState with the error text.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)


router = APIRouter(
    prefix="/api/v1/grype",
    tags=["Grype Vulnerability Scanner"],
)


def _engine():
    # Indirection so tests can patch the module-level engine via reset_grype_scan_engine().
    from core.grype_scan_engine import get_grype_scan_engine

    return get_grype_scan_engine()


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    input_type: str = Field(
        ...,
        description="One of: image, sbom, dir",
    )
    target: str = Field(
        ...,
        description="Image ref (e.g. nginx:1.25), SBOM file path, or directory path",
    )
    scope: Optional[str] = Field(
        default=None,
        description="Image scope: Squashed | AllLayers (image input only)",
    )
    only_fixed: Optional[bool] = Field(
        default=False,
        description="If True, return only vulnerabilities with available fixes",
    )


class CapabilityResponse(BaseModel):
    service: str
    input_types: List[str]
    output_formats: List[str]
    severities: List[str]
    binary_available: bool
    scan_count: int
    status: str


class ScanQueuedResponse(BaseModel):
    scan_id: str
    input_type: str
    target: str
    queued_at: str


class VulnerabilityRow(BaseModel):
    vuln_id: str
    severity: str
    package: str
    version: str
    fixed_version: str


class SeverityCounts(BaseModel):
    Critical: int = 0
    High: int = 0
    Medium: int = 0
    Low: int = 0
    Negligible: int = 0


class ScanDetailResponse(BaseModel):
    scan_id: str
    input_type: str
    target: str
    status: str
    severity_counts: SeverityCounts
    vulnerabilities: List[VulnerabilityRow]
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error: Optional[str] = None
    scope: Optional[str] = None
    only_fixed: bool = False


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/",
    response_model=CapabilityResponse,
    dependencies=[Depends(api_key_auth)],
    summary="Grype capability summary",
)
def grype_capability() -> Dict[str, Any]:
    """Return a capability summary for the Grype scanner integration."""
    try:
        return _engine().capability()
    except Exception as exc:  # pragma: no cover
        _logger.exception("grype capability failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/scan",
    response_model=ScanQueuedResponse,
    dependencies=[Depends(api_key_auth)],
    summary="Queue a new Grype scan",
)
def grype_scan(req: ScanRequest) -> Dict[str, Any]:
    """Queue a new Grype vulnerability scan. The scan runs synchronously when
    the grype binary is available; otherwise the job is recorded with status
    ``unavailable`` and clients can poll ``GET /scan/{scan_id}`` for the error
    detail.
    """
    try:
        return _engine().queue_scan(
            input_type=req.input_type,
            target=req.target,
            scope=req.scope,
            only_fixed=bool(req.only_fixed),
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:  # pragma: no cover
        _logger.exception("grype_scan failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/scan/{scan_id}",
    response_model=ScanDetailResponse,
    dependencies=[Depends(api_key_auth)],
    summary="Get a Grype scan record by id",
)
def grype_scan_detail(scan_id: str) -> Dict[str, Any]:
    """Return the full scan record including severity_counts and vulnerabilities."""
    try:
        return _engine().get_scan(scan_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"scan_id {scan_id!r} not found")
    except Exception as exc:  # pragma: no cover
        _logger.exception("grype_scan_detail failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


__all__ = ["router"]
