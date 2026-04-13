"""Data Loss Prevention Router — ALDECI.

Endpoints:
  POST   /api/v1/dlp/scan              scan text for sensitive data
  POST   /api/v1/dlp/scan-file         scan a file for sensitive data
  POST   /api/v1/dlp/redact            redact sensitive data from text
  GET    /api/v1/dlp/results           list scan results
  GET    /api/v1/dlp/results/{scan_id} get single scan result
  GET    /api/v1/dlp/stats             aggregated statistics
  POST   /api/v1/dlp/patterns          add custom detection pattern
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

try:
    from apps.api.auth_deps import api_key_auth as _api_key_auth
    _AUTH_DEP: list = [Depends(_api_key_auth)]
except ImportError:
    logging.getLogger(__name__).warning(
        "dlp_router: auth_deps not available, relying on app.py mount-level auth"
    )
    _AUTH_DEP = []

from core.dlp_engine import DLPEngine

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/dlp",
    tags=["dlp"],
    dependencies=_AUTH_DEP,
)

# Shared engine instance
_engine: Optional[DLPEngine] = None


def _get_engine() -> DLPEngine:
    global _engine
    if _engine is None:
        _engine = DLPEngine()
    return _engine


# ============================================================================
# Request / Response Models
# ============================================================================

class ScanTextRequest(BaseModel):
    text: str = Field(..., description="Text to scan for sensitive data")
    context: str = Field("", description="Optional context label for the scan")
    org_id: str = Field("default", description="Organisation identifier")


class ScanFileRequest(BaseModel):
    file_path: str = Field(..., description="Absolute path to file to scan")
    org_id: str = Field("default", description="Organisation identifier")


class RedactRequest(BaseModel):
    text: str = Field(..., description="Text to redact sensitive data from")
    org_id: str = Field("default", description="Organisation identifier")


class AddPatternRequest(BaseModel):
    name: str = Field(..., description="Unique pattern name")
    pattern: str = Field(..., description="Python regex pattern string")
    severity: str = Field(..., description="Severity: low | medium | high | critical")
    category: str = Field(..., description="Category label (e.g. pii, pci, credentials)")
    org_id: str = Field("default", description="Organisation identifier")


# ============================================================================
# Endpoints
# ============================================================================

@router.post("/scan", summary="Scan text for sensitive data")
def scan_text(req: ScanTextRequest, engine: DLPEngine = Depends(_get_engine)) -> Dict[str, Any]:
    """Scan plain text for PII, PCI, credentials, and other sensitive patterns."""
    result = engine.scan_text(req.text, context=req.context, org_id=req.org_id)
    return result


@router.post("/scan-file", summary="Scan a file for sensitive data")
def scan_file(req: ScanFileRequest, engine: DLPEngine = Depends(_get_engine)) -> Dict[str, Any]:
    """Read a file from disk and scan its contents."""
    try:
        result = engine.scan_file(req.file_path, org_id=req.org_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return result


@router.post("/redact", summary="Redact sensitive data from text")
def redact_text(req: RedactRequest, engine: DLPEngine = Depends(_get_engine)) -> Dict[str, Any]:
    """Replace all detected sensitive patterns with [REDACTED-TYPE] placeholders."""
    redacted = engine.redact_text(req.text, org_id=req.org_id)
    return {"redacted_text": redacted}


@router.get("/results", summary="List scan results")
def list_results(
    org_id: str = Query("default", description="Organisation identifier"),
    risk_level: Optional[str] = Query(None, description="Filter by risk level"),
    limit: int = Query(50, ge=1, le=500),
    engine: DLPEngine = Depends(_get_engine),
) -> List[Dict[str, Any]]:
    """List scan results, optionally filtered by risk level."""
    return engine.list_scan_results(org_id=org_id, risk_level=risk_level, limit=limit)


@router.get("/results/{scan_id}", summary="Get a scan result by ID")
def get_result(scan_id: str, engine: DLPEngine = Depends(_get_engine)) -> Dict[str, Any]:
    """Retrieve a specific scan result."""
    result = engine.get_scan_result(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Scan result {scan_id!r} not found")
    return result


@router.get("/stats", summary="DLP statistics")
def get_stats(
    org_id: str = Query("default", description="Organisation identifier"),
    engine: DLPEngine = Depends(_get_engine),
) -> Dict[str, Any]:
    """Return aggregated DLP statistics for an organisation."""
    return engine.get_stats(org_id=org_id)


@router.post("/patterns", summary="Add a custom detection pattern")
def add_pattern(req: AddPatternRequest, engine: DLPEngine = Depends(_get_engine)) -> Dict[str, Any]:
    """Register a custom regex pattern for an organisation."""
    try:
        result = engine.add_custom_pattern(
            name=req.name,
            pattern=req.pattern,
            severity=req.severity,
            category=req.category,
            org_id=req.org_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return result
