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


# ============================================================================
# Policy-based DLP endpoints
# ============================================================================

class PolicyCreate(BaseModel):
    org_id: str = Field("default")
    policy_name: str
    data_types: List[str] = Field(default_factory=list)
    channels: List[str] = Field(default_factory=list)
    action: str = Field("alert")
    severity: str = Field("medium")
    enabled: bool = Field(True)


class DetectIncidentRequest(BaseModel):
    org_id: str = Field("default")
    data_type: str = Field("")
    channel: str = Field("")
    content: str = Field("")
    user_id: str = Field("")
    user_email: str = Field("")
    endpoint_hostname: str = Field("")
    file_name: str = Field("")
    destination: str = Field("")


class IncidentStatusUpdate(BaseModel):
    status: str


class ExceptionCreate(BaseModel):
    org_id: str = Field("default")
    user_id: str
    policy_id: str = Field("")
    reason: str = Field("")
    approved_by: str = Field("")
    expires_at: Optional[str] = None


@router.post("/policies", summary="Create DLP policy")
def create_policy(req: PolicyCreate, engine: DLPEngine = Depends(_get_engine)) -> Dict[str, Any]:
    try:
        return engine.create_policy(req.org_id, req.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/policies", summary="List DLP policies")
def list_policies(
    org_id: str = Query("default"),
    enabled: Optional[bool] = Query(None),
    engine: DLPEngine = Depends(_get_engine),
) -> List[Dict[str, Any]]:
    return engine.list_policies(org_id, enabled=enabled)


@router.get("/policies/{policy_id}", summary="Get DLP policy")
def get_policy(
    policy_id: str,
    org_id: str = Query("default"),
    engine: DLPEngine = Depends(_get_engine),
) -> Dict[str, Any]:
    pol = engine.get_policy(org_id, policy_id)
    if pol is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    return pol


@router.post("/detect", summary="Detect DLP incident")
def detect_incident(req: DetectIncidentRequest, engine: DLPEngine = Depends(_get_engine)) -> Dict[str, Any]:
    result = engine.detect_incident(req.org_id, req.model_dump())
    if result is None:
        return {"matched": False, "incident": None}
    return {"matched": True, "incident": result}


@router.get("/incidents", summary="List DLP incidents")
def list_incidents(
    org_id: str = Query("default"),
    severity: Optional[str] = Query(None),
    channel: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    engine: DLPEngine = Depends(_get_engine),
) -> List[Dict[str, Any]]:
    return engine.list_incidents(org_id, severity=severity, channel=channel,
                                  status=status, limit=limit)


@router.patch("/incidents/{incident_id}/status", summary="Update incident status")
def update_incident_status(
    incident_id: str,
    req: IncidentStatusUpdate,
    org_id: str = Query("default"),
    engine: DLPEngine = Depends(_get_engine),
) -> Dict[str, Any]:
    try:
        updated = engine.update_incident_status(org_id, incident_id, req.status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not updated:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"updated": True}


@router.post("/exceptions", summary="Create policy exception")
def create_exception(req: ExceptionCreate, engine: DLPEngine = Depends(_get_engine)) -> Dict[str, Any]:
    try:
        return engine.create_exception(req.org_id, req.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/exceptions", summary="List policy exceptions")
def list_exceptions(
    org_id: str = Query("default"),
    engine: DLPEngine = Depends(_get_engine),
) -> List[Dict[str, Any]]:
    return engine.list_exceptions(org_id)


@router.get("/dlp-stats", summary="DLP policy/incident stats")
def get_dlp_stats(
    org_id: str = Query("default"),
    engine: DLPEngine = Depends(_get_engine),
) -> Dict[str, Any]:
    return engine.get_dlp_stats(org_id)


@router.get("/daily-trends", summary="Daily incident trend")
def get_daily_trends(
    org_id: str = Query("default"),
    days: int = Query(30, ge=1, le=365),
    engine: DLPEngine = Depends(_get_engine),
) -> List[Dict[str, Any]]:
    return engine.get_daily_trends(org_id, days=days)


# ---------------------------------------------------------------------------
# Root summary endpoint (5-state envelope)
# ---------------------------------------------------------------------------


@router.get("/", summary="DLP domain summary")
def get_dlp_summary(
    org_id: str = Query("default", description="Organisation identifier"),
    engine: DLPEngine = Depends(_get_engine),
) -> Dict[str, Any]:
    """Return a 5-state summary envelope for the DLP domain.

    States:
      healthy   — policies active, no critical incidents
      degraded  — open critical/high incidents present
      empty     — fresh tenant, no policies or scans yet
      error     — engine raised an exception
      unknown   — stats structure unexpected
    """
    try:
        stats = engine.get_stats(org_id=org_id)
        dlp_stats = engine.get_dlp_stats(org_id)
    except Exception as exc:
        logger.error("dlp.summary error: %s", exc)
        return {
            "status": "error",
            "org_id": org_id,
            "error": str(exc),
            "domain": "dlp",
        }

    total_scans = stats.get("total_scans", 0)
    total_policies = dlp_stats.get("total_policies", 0)
    open_incidents = dlp_stats.get("open_incidents", dlp_stats.get("incidents_by_status", {}).get("open", 0))

    if total_scans == 0 and total_policies == 0:
        status = "empty"
    elif open_incidents > 0:
        status = "degraded"
    else:
        status = "healthy"

    envelope: Dict[str, Any] = {
        "status": status,
        "org_id": org_id,
        "domain": "dlp",
        "scan_stats": stats,
        "policy_stats": dlp_stats,
    }
    if status == "empty":
        envelope["hint"] = (
            "Add DLP policies via POST /api/v1/dlp/policies and scan content "
            "via POST /api/v1/dlp/scan to begin data-loss prevention monitoring."
        )
    return envelope
