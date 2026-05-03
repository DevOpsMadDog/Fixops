"""Semgrep SAST Scan Router — async-queued model.

Prefix: /api/v1/semgrep

Complementary to the legacy /api/v1/scan/semgrep router (synchronous
SemgrepScanner). This router is the durable async-queue front door:

    GET  /                  — capability summary (rule packs, severity levels)
    GET  /rule-packs        — catalog of supported rule packs
    POST /scan              — queue a scan, returns {scan_id, target_path,
                              rule_packs, queued_at}
    GET  /scan/{scan_id}    — fetch scan record (status, severity counts,
                              findings)

Backed by core.semgrep_scan_engine.SemgrepScanEngine (SQLite at
data/security/semgrep_scans.db).

Vision Pillars: V1 (APP_ID-Centric), V3 (Decision Intelligence), V9 (Air-Gapped)
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/semgrep",
    tags=["semgrep-scan"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Lazy engine accessor (allows test override via monkeypatch)
# ---------------------------------------------------------------------------


def _get_engine():
    from core.semgrep_scan_engine import get_semgrep_scan_engine

    return get_semgrep_scan_engine()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CapabilitySummary(BaseModel):
    service: str
    rule_packs: List[str]
    severity_levels: List[str]
    status: str  # ok | empty | unavailable
    binary_present: bool
    scan_count: int


class RulePack(BaseModel):
    id: str
    name: str
    description: str


class RulePacksResponse(BaseModel):
    rule_packs: List[RulePack]
    count: int


class ScanRequest(BaseModel):
    target_path: str = Field(..., description="Filesystem path to scan")
    rule_packs: Optional[List[str]] = Field(
        default=None,
        description=(
            "Optional list of rule pack IDs (default: ['r2c-security-audit']). "
            "See GET /api/v1/semgrep/rule-packs for the catalog."
        ),
    )
    severity_threshold: Optional[str] = Field(
        default=None,
        description="Severity floor: INFO | WARNING | ERROR (default: WARNING)",
    )
    exclude_dirs: Optional[List[str]] = Field(
        default=None,
        description="Optional directories or globs to pass to --exclude",
    )


class ScanQueuedResponse(BaseModel):
    scan_id: str
    target_path: str
    rule_packs: List[str]
    queued_at: str


class SeverityCounts(BaseModel):
    INFO: int = 0
    WARNING: int = 0
    ERROR: int = 0


class Finding(BaseModel):
    rule_id: Optional[str] = None
    severity: str
    file_path: Optional[str] = None
    line: Optional[int] = None
    message: Optional[str] = None


class ScanRecordResponse(BaseModel):
    scan_id: str
    target_path: str
    rule_packs: List[str]
    status: str
    severity_counts: Dict[str, int]
    findings: List[Finding] = Field(default_factory=list)
    started_at: Optional[str] = None
    completed_at: Optional[str] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/",
    response_model=CapabilitySummary,
    summary="Semgrep SAST capability summary",
)
def capability_summary() -> Dict[str, Any]:
    """Return Semgrep capability descriptor — rule packs, severity vocabulary,
    and overall status (``ok`` if scans recorded, ``empty`` if none yet, or
    ``unavailable`` when the semgrep binary is not installed)."""
    engine = _get_engine()
    return engine.capability_summary()


@router.get(
    "/rule-packs",
    response_model=RulePacksResponse,
    summary="List supported Semgrep rule packs",
)
def list_rule_packs() -> Dict[str, Any]:
    """Return the catalog of rule packs supported by this engine, with
    human-readable descriptions."""
    engine = _get_engine()
    packs = engine.list_rule_packs()
    return {"rule_packs": packs, "count": len(packs)}


@router.post(
    "/scan",
    response_model=ScanQueuedResponse,
    status_code=202,
    summary="Queue a Semgrep SAST scan",
)
def queue_scan(body: ScanRequest) -> Dict[str, Any]:
    """Queue a Semgrep scan job. Returns the scan id and ``status=queued``.

    The scan executes inline against the semgrep CLI when present; otherwise
    the record is persisted with ``status=unavailable`` (no fake findings)."""
    engine = _get_engine()
    if not body.target_path or not body.target_path.strip():
        raise HTTPException(status_code=422, detail="target_path must be a non-empty string")

    try:
        return engine.queue_scan(
            target_path=body.target_path,
            rule_packs=body.rule_packs,
            severity_threshold=body.severity_threshold,
            exclude_dirs=body.exclude_dirs,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:  # noqa: BLE001
        logger.error("semgrep queue_scan failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get(
    "/scan/{scan_id}",
    response_model=ScanRecordResponse,
    summary="Fetch Semgrep scan record",
)
def get_scan(scan_id: str) -> Dict[str, Any]:
    """Return a single scan record by id. Returns 404 when unknown."""
    engine = _get_engine()
    record = engine.get_scan(scan_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"scan_id {scan_id!r} not found")
    return record
