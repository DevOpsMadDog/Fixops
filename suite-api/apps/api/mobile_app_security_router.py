"""Mobile App Security Router — REST endpoints for mobile app security management.

Endpoints under /api/v1/mobile-app-security:
  POST   /apps                          — Register a mobile app
  GET    /apps                          — List apps (filter: platform, risk_level)
  GET    /apps/{app_id}                 — Get a single app
  POST   /findings                      — Record a security finding
  GET    /findings                      — List findings (filter: app_id, severity, status)
  PUT    /findings/{finding_id}/status  — Update finding status
  POST   /scans                         — Create a scan
  PUT    /scans/{scan_id}/complete      — Complete a scan
  GET    /scans                         — List scans (filter: app_id, scan_type)
  GET    /stats                         — Mobile app security statistics
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/mobile-app-security",
    tags=["Mobile App Security"],
    dependencies=[Depends(api_key_auth)],
)

_engine_instance = None


def _get_engine():
    global _engine_instance
    if _engine_instance is None:
        try:
            from core.mobile_app_security_engine import MobileAppSecurityEngine
            _engine_instance = MobileAppSecurityEngine()
        except Exception as exc:
            _logger.error("MobileAppSecurityEngine unavailable: %s", exc)
            raise HTTPException(status_code=503, detail=f"Mobile app security engine unavailable: {exc}")
    return _engine_instance


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class RegisterAppRequest(BaseModel):
    app_name: str
    bundle_id: str
    platform: str
    version: str = "1.0.0"
    category: str
    risk_score: float = 50.0
    risk_level: str = "medium"
    status: str = "active"
    last_scanned: Optional[str] = None


class RecordFindingRequest(BaseModel):
    app_id: str
    finding_type: str
    severity: str
    title: str
    description: Optional[str] = None
    owasp_category: Optional[str] = None
    status: str = "open"
    cwe_id: Optional[str] = None
    discovered_at: Optional[str] = None


class UpdateFindingStatusRequest(BaseModel):
    status: str


class CreateScanRequest(BaseModel):
    app_id: str
    scan_type: str
    status: str = "queued"
    started_at: Optional[str] = None


class CompleteScanRequest(BaseModel):
    total_findings: int
    critical_findings: int
    scan_score: float


# ---------------------------------------------------------------------------
# App endpoints
# ---------------------------------------------------------------------------

@router.post("/apps", response_model=Dict[str, Any])
def register_app(body: RegisterAppRequest, org_id: str = Query("default")):
    eng = _get_engine()
    data = body.model_dump()
    if data.get("last_scanned") is None:
        data.pop("last_scanned", None)
    try:
        app = eng.register_app(org_id, data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return app


@router.get("/apps", response_model=Dict[str, Any])
def list_apps(
    org_id: str = Query("default"),
    platform: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
):
    """List mobile apps with optional filters.

    Falls back to live ``MobSFConnector`` scan corpus
    (``MOBSF_API_URL`` + ``MOBSF_API_KEY`` env vars) when the org has no
    registered apps. Returns ``{apps, total, source, hint?, scans_pulled?}``.
    """
    eng = _get_engine()
    try:
        return eng.list_apps_with_mobsf_fallback(
            org_id, platform=platform, risk_level=risk_level,
        )
    except Exception as exc:
        _logger.error("mobile_app_security.list_apps error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/apps/{app_id}", response_model=Dict[str, Any])
def get_app(app_id: str, org_id: str = Query("default")):
    eng = _get_engine()
    app = eng.get_app(org_id, app_id)
    if app is None:
        raise HTTPException(status_code=404, detail=f"App {app_id!r} not found")
    return app


# ---------------------------------------------------------------------------
# Finding endpoints
# ---------------------------------------------------------------------------

@router.post("/findings", response_model=Dict[str, Any])
def record_finding(body: RecordFindingRequest, org_id: str = Query("default")):
    eng = _get_engine()
    data = body.model_dump()
    if data.get("discovered_at") is None:
        data.pop("discovered_at", None)
    try:
        finding = eng.record_finding(org_id, data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return finding


@router.get("/findings", response_model=Dict[str, Any])
def list_findings(
    org_id: str = Query("default"),
    app_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    eng = _get_engine()
    findings = eng.list_findings(org_id, app_id=app_id, severity=severity, status=status)
    return {"total": len(findings), "findings": findings}


@router.put("/findings/{finding_id}/status", response_model=Dict[str, Any])
def update_finding_status(
    finding_id: str,
    body: UpdateFindingStatusRequest,
    org_id: str = Query("default"),
):
    eng = _get_engine()
    try:
        result = eng.update_finding_status(org_id, finding_id, body.status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return result


# ---------------------------------------------------------------------------
# Scan endpoints
# ---------------------------------------------------------------------------

@router.post("/scans", response_model=Dict[str, Any])
def create_scan(body: CreateScanRequest, org_id: str = Query("default")):
    eng = _get_engine()
    data = body.model_dump()
    if data.get("started_at") is None:
        data.pop("started_at", None)
    try:
        scan = eng.create_scan(org_id, data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return scan


@router.put("/scans/{scan_id}/complete", response_model=Dict[str, Any])
def complete_scan(
    scan_id: str,
    body: CompleteScanRequest,
    org_id: str = Query("default"),
):
    eng = _get_engine()
    try:
        result = eng.complete_scan(
            org_id, scan_id,
            body.total_findings, body.critical_findings, body.scan_score,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return result


@router.get("/scans", response_model=Dict[str, Any])
def list_scans(
    org_id: str = Query("default"),
    app_id: Optional[str] = Query(None),
    scan_type: Optional[str] = Query(None),
):
    eng = _get_engine()
    scans = eng.list_scans(org_id, app_id=app_id, scan_type=scan_type)
    return {"total": len(scans), "scans": scans}


# ---------------------------------------------------------------------------
# Stats endpoint
# ---------------------------------------------------------------------------

@router.get("/stats", response_model=Dict[str, Any])
def get_mobile_stats(org_id: str = Query("default")):
    eng = _get_engine()
    return eng.get_mobile_stats(org_id)
