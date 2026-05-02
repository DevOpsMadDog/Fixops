"""Secret Scanner Engine Router — ALDECI.

Endpoints for the SecretScannerEngine (scan jobs, findings, patterns, suppression).

Prefix: /api/v1/secret-scanner
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/secret-scanner/jobs                          create_scan_job
  GET    /api/v1/secret-scanner/jobs                          list_scan_jobs
  GET    /api/v1/secret-scanner/jobs/{job_id}                 get_scan_job
  POST   /api/v1/secret-scanner/jobs/{job_id}/start           start_scan
  GET    /api/v1/secret-scanner/findings                      list_findings
  PATCH  /api/v1/secret-scanner/findings/{finding_id}         update_finding
  POST   /api/v1/secret-scanner/findings/{finding_id}/validate validate_finding
  POST   /api/v1/secret-scanner/engine-patterns               create_pattern
  GET    /api/v1/secret-scanner/engine-patterns               list_patterns
  POST   /api/v1/secret-scanner/suppressions                  add_suppression
  GET    /api/v1/secret-scanner/suppressions                  list_suppressions
  GET    /api/v1/secret-scanner/stats                         get_scanner_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/secret-scanner",
    tags=["secret-scanner"],
)

_engines: Dict[str, Any] = {}


def _get_engine(org_id: str):
    if org_id not in _engines:
        from core.secret_scanner_engine import SecretScannerEngine
        _engines[org_id] = SecretScannerEngine(org_id)
    return _engines[org_id]


# ---------------------------------------------------------------------------
# SecurityFindingsEngine mirror — mirrors the SAST router's `_persist_sast_findings`
# pattern in suite-api/apps/api/sast_router.py. Without this the customer-facing
# dashboard (/api/v1/security-findings/findings?source_tool=secret_scanner) shows
# empty even though the engine recorded findings.
# ---------------------------------------------------------------------------

_SEVERITY_TO_CVSS = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 3.0,
    "info": 1.0,
}


def _mirror_secret_findings_to_dashboard(
    org_id: str,
    job_id: str,
    findings: List[Dict[str, Any]],
) -> int:
    """Mirror secret-scanner findings to SecurityFindingsEngine.

    Stable ``correlation_key = secret_scanner|<secret_type>|<file_path>:<line>``
    so re-scans dedup and lifecycle works. Returns count successfully mirrored.
    """
    if not findings or not org_id:
        return 0
    try:
        from core.security_findings_engine import SecurityFindingsEngine
    except ImportError:
        _logger.exception("SecurityFindingsEngine import failed; cannot mirror")
        return 0

    sfe = SecurityFindingsEngine()
    mirrored = 0
    for f in findings:
        try:
            severity = (f.get("severity") or "medium").lower()
            cvss = _SEVERITY_TO_CVSS.get(severity, 5.0)
            file_path = f.get("file_path") or "unknown"
            line = f.get("line_number") or 0
            secret_type = f.get("secret_type") or "generic"
            corr_key = f"secret_scanner|{secret_type}|{file_path}:{line}"
            title = f"Secret leaked: {secret_type} in {file_path}"
            description = (
                f"Secret of type '{secret_type}' detected in {file_path}:{line}. "
                f"Masked value: {f.get('value_masked', 'N/A')}, "
                f"entropy: {f.get('entropy', 'N/A')}."
            )
            remediation = (
                "Rotate the credential immediately, remove from the file, "
                "and scrub from git history."
            )
            sfe.record_finding(
                org_id=org_id,
                title=title,
                finding_type="secret",
                source_tool="secret_scanner",
                severity=severity,
                cvss_score=cvss,
                asset_id=file_path,
                asset_type="source_file",
                description=description,
                remediation=remediation,
                correlation_key=corr_key,
                scan_id=job_id,
            )
            mirrored += 1
        except (OSError, ValueError, KeyError, RuntimeError, TypeError):
            _logger.exception(
                "Failed to mirror secret finding to SecurityFindingsEngine "
                "(org_id=%s, finding_id=%s)",
                org_id,
                f.get("id"),
            )
    return mirrored


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ScanJobCreate(BaseModel):
    target_type: str = "filesystem"
    target_path: str = ""


class FindingUpdate(BaseModel):
    status: str
    notes: Optional[str] = None


class FindingValidate(BaseModel):
    is_valid: bool


class PatternCreate(BaseModel):
    pattern_name: str
    regex_pattern: str
    secret_type: str = "generic_api_key"
    severity: str = "medium"
    enabled: bool = True
    false_positive_rate: float = 0.0


class SuppressionCreate(BaseModel):
    file_pattern: str
    secret_type: str
    reason: str = ""
    approved_by: str = ""
    expires_at: Optional[str] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/jobs", dependencies=[Depends(api_key_auth)])
def create_scan_job(
    payload: ScanJobCreate,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Create a new scan job in pending state."""
    engine = _get_engine(org_id)
    try:
        return engine.create_scan_job(org_id, payload.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/jobs", dependencies=[Depends(api_key_auth)])
def list_scan_jobs(
    org_id: str = Query(..., description="Organization ID"),
    status: Optional[str] = Query(None),
    target_type: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    """List scan jobs with optional filters."""
    engine = _get_engine(org_id)
    return engine.list_scan_jobs(org_id, status=status, target_type=target_type)


@router.get("/jobs/{job_id}", dependencies=[Depends(api_key_auth)])
def get_scan_job(
    job_id: str,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Get a scan job with its findings."""
    engine = _get_engine(org_id)
    result = engine.get_scan_job(org_id, job_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Scan job {job_id} not found.")
    return result


@router.post("/jobs/{job_id}/start", dependencies=[Depends(api_key_auth)])
def start_scan(
    job_id: str,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Start a pending scan job (runs simulation synchronously).

    Findings are mirrored to ``SecurityFindingsEngine`` so the customer-facing
    dashboard at ``/api/v1/security-findings/findings?source_tool=secret_scanner``
    is populated. Mirror count is returned in the ``mirrored_count`` field.
    """
    engine = _get_engine(org_id)
    try:
        result = engine.start_scan(org_id, job_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    # Mirror findings to SecurityFindingsEngine (mirrors SAST router pattern).
    try:
        job_with_findings = engine.get_scan_job(org_id, job_id) or {}
        findings = job_with_findings.get("findings", []) or []
        mirrored = _mirror_secret_findings_to_dashboard(org_id, job_id, findings)
        result["mirrored_count"] = mirrored
    except (OSError, ValueError, KeyError, RuntimeError) as exc:
        _logger.exception("Mirror to SecurityFindingsEngine failed: %s", exc)
        result["mirrored_count"] = 0
    return result


@router.get("/findings", dependencies=[Depends(api_key_auth)])
def list_findings(
    org_id: str = Query(..., description="Organization ID"),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    secret_type: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
) -> List[Dict[str, Any]]:
    """List findings with optional filters."""
    engine = _get_engine(org_id)
    return engine.list_findings(
        org_id,
        severity=severity,
        status=status,
        secret_type=secret_type,
        limit=limit,
    )


@router.patch("/findings/{finding_id}", dependencies=[Depends(api_key_auth)])
def update_finding(
    finding_id: str,
    payload: FindingUpdate,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Update finding status and optional notes."""
    engine = _get_engine(org_id)
    try:
        updated = engine.update_finding(org_id, finding_id, payload.status, payload.notes)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if not updated:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found.")
    return {"finding_id": finding_id, "status": payload.status, "updated": True}


@router.post("/findings/{finding_id}/validate", dependencies=[Depends(api_key_auth)])
def validate_finding(
    finding_id: str,
    payload: FindingValidate,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Validate a finding as confirmed or false_positive."""
    engine = _get_engine(org_id)
    updated = engine.validate_finding(org_id, finding_id, payload.is_valid)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found.")
    validity = "confirmed" if payload.is_valid else "false_positive"
    return {"finding_id": finding_id, "is_valid_secret": validity, "updated": True}


@router.post("/engine-patterns", dependencies=[Depends(api_key_auth)])
def create_pattern(
    payload: PatternCreate,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Create a custom detection pattern."""
    engine = _get_engine(org_id)
    try:
        return engine.create_pattern(org_id, payload.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/engine-patterns", dependencies=[Depends(api_key_auth)])
def list_patterns(
    org_id: str = Query(..., description="Organization ID"),
) -> List[Dict[str, Any]]:
    """List all detection patterns for org."""
    engine = _get_engine(org_id)
    return engine.list_patterns(org_id)


@router.post("/suppressions", dependencies=[Depends(api_key_auth)])
def add_suppression(
    payload: SuppressionCreate,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Add a suppression rule for a file pattern + secret type."""
    engine = _get_engine(org_id)
    try:
        return engine.add_suppression(org_id, payload.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/suppressions", dependencies=[Depends(api_key_auth)])
def list_suppressions(
    org_id: str = Query(..., description="Organization ID"),
) -> List[Dict[str, Any]]:
    """List all suppression rules for org."""
    engine = _get_engine(org_id)
    return engine.list_suppressions(org_id)


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_scanner_stats(
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Return aggregated scanner stats for org."""
    engine = _get_engine(org_id)
    return engine.get_scanner_stats(org_id)
