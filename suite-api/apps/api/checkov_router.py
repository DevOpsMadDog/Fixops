"""Checkov IaC Scanner Router — ALDECI.

Wraps `core.checkov_scan_engine.CheckovScanEngine` to expose REST endpoints
for queueing IaC scans across 14 frameworks (Terraform, Kubernetes, Helm,
CloudFormation, Dockerfile, GitHub Actions, ARM, Bicep, GitLab CI,
CircleCI, Argo Workflows, OpenAPI, SCA Image, Secrets) and inspecting
results.

Prefix: /api/v1/checkov
Auth:   api_key_auth dependency (mount layer adds scope checks)

Routes:
  GET  /api/v1/checkov/                  capability summary
  GET  /api/v1/checkov/frameworks        framework catalog
  POST /api/v1/checkov/scan              queue a new scan
  GET  /api/v1/checkov/scan/{scan_id}    fetch scan status + findings

NO MOCKS rule: when the checkov binary is missing the engine records the
job as ``unavailable`` with an explanatory error — no fake findings are
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
    prefix="/api/v1/checkov",
    tags=["Checkov IaC Scanner"],
)


def _engine():
    # Indirection so tests can patch the module-level engine accessor.
    from core.checkov_scan_engine import get_checkov_scan_engine

    return get_checkov_scan_engine()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    target_path: str = Field(..., description="Filesystem path to scan (file or directory)")
    frameworks: Optional[List[str]] = Field(
        default=None,
        description="Optional subset of Checkov frameworks (default: all).",
    )
    check_ids: Optional[List[str]] = Field(
        default=None,
        description="Optional list of explicit check IDs to run (e.g. CKV_AWS_8).",
    )
    skip_checks: Optional[List[str]] = Field(
        default=None,
        description="Optional list of check IDs to skip.",
    )
    soft_fail: Optional[bool] = Field(
        default=False,
        description="If True, scan returns 0 even when failed checks are found.",
    )


class CapabilityResponse(BaseModel):
    service: str
    frameworks: List[str]
    severity_levels: List[str]
    binary_available: bool
    scan_count: int
    framework_count: int
    status: str


class FrameworkDetail(BaseModel):
    framework: str
    description: str


class FrameworkCatalogResponse(BaseModel):
    frameworks: List[FrameworkDetail]
    count: int


class ScanQueuedResponse(BaseModel):
    scan_id: str
    target_path: str
    frameworks: List[str]
    queued_at: str


class FindingRow(BaseModel):
    check_id: str
    severity: str
    framework: str
    file_path: str
    resource: str


class SeverityCounts(BaseModel):
    INFO: int = 0
    LOW: int = 0
    MEDIUM: int = 0
    HIGH: int = 0
    CRITICAL: int = 0


class ScanDetailResponse(BaseModel):
    scan_id: str
    target_path: str
    frameworks: List[str]
    status: str
    severity_counts: SeverityCounts
    framework_counts: Dict[str, int]
    findings: List[FindingRow]
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/",
    response_model=CapabilityResponse,
    dependencies=[Depends(api_key_auth)],
    summary="Checkov capability summary",
)
def checkov_capability() -> Dict[str, Any]:
    """Return capability summary for the Checkov IaC scanner integration."""
    try:
        return _engine().capability()
    except Exception as exc:  # pragma: no cover
        _logger.exception("checkov capability failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/frameworks",
    response_model=FrameworkCatalogResponse,
    dependencies=[Depends(api_key_auth)],
    summary="List supported Checkov frameworks",
)
def list_frameworks() -> Dict[str, Any]:
    """Return the catalog of 14 supported Checkov frameworks with descriptions."""
    from core.checkov_scan_engine import CheckovScanEngine

    frameworks = CheckovScanEngine.list_frameworks()
    return {"frameworks": frameworks, "count": len(frameworks)}


@router.post(
    "/scan",
    response_model=ScanQueuedResponse,
    status_code=202,
    dependencies=[Depends(api_key_auth)],
    summary="Queue a new Checkov scan",
)
def checkov_scan(req: ScanRequest) -> Dict[str, Any]:
    """Queue a new Checkov IaC scan. Runs synchronously when the checkov
    binary is on PATH; otherwise the job is recorded with status
    ``unavailable`` and clients can poll ``GET /scan/{scan_id}`` for the
    error detail.
    """
    try:
        return _engine().queue_scan(
            target_path=req.target_path,
            frameworks=req.frameworks,
            check_ids=req.check_ids,
            skip_checks=req.skip_checks,
            soft_fail=bool(req.soft_fail),
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:  # pragma: no cover
        _logger.exception("checkov_scan failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/scan/{scan_id}",
    response_model=ScanDetailResponse,
    dependencies=[Depends(api_key_auth)],
    summary="Get a Checkov scan record by id",
)
def checkov_scan_detail(scan_id: str) -> Dict[str, Any]:
    """Return the full scan record including severity/framework counts and findings."""
    try:
        return _engine().get_scan(scan_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"scan_id {scan_id!r} not found")
    except Exception as exc:  # pragma: no cover
        _logger.exception("checkov_scan_detail failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


__all__ = ["router"]
