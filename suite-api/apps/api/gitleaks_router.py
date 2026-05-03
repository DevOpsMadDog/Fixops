"""Gitleaks Secret-Detection Router — ALDECI.

Wraps ``core.gitleaks_scan_engine.GitleaksScanEngine`` to expose REST
endpoints for queueing repository / filesystem secret scans, browsing the
default rule catalog, and inspecting results.

Prefix: /api/v1/gitleaks
Auth:   api_key_auth dependency (mount layer adds scope checks — read:scans)

Routes:
  GET  /api/v1/gitleaks/                  capability summary
  GET  /api/v1/gitleaks/rules             default rule catalog (12+ rules)
  POST /api/v1/gitleaks/scan              queue a new scan
  GET  /api/v1/gitleaks/scan/{scan_id}    fetch scan status + secrets

NO MOCKS rule: when the gitleaks binary is missing the engine records the
job as ``unavailable`` with an explanatory error — no fake secrets are
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
    prefix="/api/v1/gitleaks",
    tags=["Gitleaks Secret Detection"],
)


def _engine():
    # Indirection so tests can patch the module-level engine via reset_gitleaks_scan_engine().
    from core.gitleaks_scan_engine import get_gitleaks_scan_engine

    return get_gitleaks_scan_engine()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CapabilityResponse(BaseModel):
    service: str
    default_rules: List[str]
    scan_modes: List[str]
    binary_available: bool
    scan_count: int
    status: str  # ok | empty


class RuleEntry(BaseModel):
    rule_id: str
    description: str
    severity: str


class RuleCatalogResponse(BaseModel):
    count: int
    rules: List[RuleEntry]


class ScanRequest(BaseModel):
    repo_path: str = Field(
        ..., description="Absolute or relative path to the repository / directory to scan"
    )
    branch: Optional[str] = Field(
        default=None,
        description="Branch reference to constrain --log-opts (history scans only)",
    )
    all_history: bool = Field(
        default=False,
        description="Scan full git history (otherwise only the working tree is inspected)",
    )
    exclude_paths: List[str] = Field(
        default_factory=list,
        description="Paths / glob configs to exclude from the scan",
    )


class ScanQueuedResponse(BaseModel):
    scan_id: str
    repo_path: str
    branch: Optional[str] = None
    queued_at: str


class SecretRow(BaseModel):
    rule_id: str
    file: str
    line: int
    commit: Optional[str] = None
    redacted_match: str


class SecretCounts(BaseModel):
    by_rule: Dict[str, int] = Field(default_factory=dict)


class ScanDetailResponse(BaseModel):
    scan_id: str
    repo_path: str
    branch: Optional[str] = None
    all_history: bool = False
    status: str
    secret_counts: SecretCounts
    secrets: List[SecretRow]
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
    summary="Gitleaks capability summary",
)
def gitleaks_capability() -> Dict[str, Any]:
    """Return capability summary (default rules + scan modes + scan_count)."""
    try:
        return _engine().capability_summary()
    except Exception as exc:  # pragma: no cover
        _logger.exception("gitleaks capability failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/rules",
    response_model=RuleCatalogResponse,
    dependencies=[Depends(api_key_auth)],
    summary="Default rule catalog (12+ rules)",
)
def gitleaks_rules() -> Dict[str, Any]:
    """Return the documented default rule catalog with descriptions."""
    try:
        rules = _engine().list_rules()
        return {"count": len(rules), "rules": rules}
    except Exception as exc:  # pragma: no cover
        _logger.exception("gitleaks list_rules failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/scan",
    response_model=ScanQueuedResponse,
    dependencies=[Depends(api_key_auth)],
    summary="Queue a new Gitleaks scan",
)
def gitleaks_scan(req: ScanRequest) -> Dict[str, Any]:
    """Queue a Gitleaks secret-detection scan. The scan runs synchronously when
    the gitleaks binary is available; otherwise the job is recorded with status
    ``unavailable`` and clients can poll ``GET /scan/{scan_id}`` for the error
    detail.
    """
    try:
        return _engine().queue_scan(
            repo_path=req.repo_path,
            branch=req.branch,
            all_history=bool(req.all_history),
            exclude_paths=list(req.exclude_paths or []),
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:  # pragma: no cover
        _logger.exception("gitleaks_scan failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/scan/{scan_id}",
    response_model=ScanDetailResponse,
    dependencies=[Depends(api_key_auth)],
    summary="Get a Gitleaks scan record by id",
)
def gitleaks_scan_detail(scan_id: str) -> Dict[str, Any]:
    """Return the full scan record including secret_counts and secrets array."""
    try:
        return _engine().get_scan(scan_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"scan_id {scan_id!r} not found")
    except Exception as exc:  # pragma: no cover
        _logger.exception("gitleaks_scan_detail failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


__all__ = ["router"]
