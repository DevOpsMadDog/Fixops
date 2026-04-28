"""Digital Risk Protection Router — ALDECI.

6 endpoints for the DRP engine:
  POST /api/v1/drp/scan                  run full external risk scan
  GET  /api/v1/drp/risks                 list external risks (filter by type/severity)
  POST /api/v1/drp/check/credential      check email exposure
  GET  /api/v1/drp/typosquats/{domain}   get typosquat variants
  GET  /api/v1/drp/certificates/{domain} certificate transparency lookup
  GET  /api/v1/drp/summary               aggregate risk summary
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

try:
    from apps.api.auth_deps import api_key_auth as _api_key_auth
    _AUTH_DEP: list = [Depends(_api_key_auth)]
except ImportError:
    logging.getLogger(__name__).warning(
        "drp_router: auth_deps not available, relying on app.py mount-level auth"
    )
    _AUTH_DEP = []

from core.digital_risk_protection import DRPEngine, ExposureType, RiskSeverity

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/drp",
    tags=["Digital Risk Protection"],
    dependencies=_AUTH_DEP,
)

# Shared engine instance (file-backed, shared across requests)
_engine: Optional[DRPEngine] = None


def _get_engine() -> DRPEngine:
    global _engine
    if _engine is None:
        _engine = DRPEngine()
    return _engine


# ============================================================================
# REQUEST / RESPONSE MODELS
# ============================================================================


class FullScanRequest(BaseModel):
    """Body for triggering a full external risk scan."""

    org_id: str = Field(..., description="Organisation identifier")
    domain: str = Field(..., description="Primary domain to scan (e.g. acme.io)")
    email_domain: str = Field(..., description="Email domain for credential probe (e.g. acme.io)")


class CredentialCheckRequest(BaseModel):
    """Body for a credential exposure check."""

    email: str = Field(..., description="Email address to check")
    org_id: str = Field("default", description="Organisation ID for persistence")


# ============================================================================
# ENDPOINTS
# ============================================================================


@router.post("/scan", summary="Run full external risk scan")
def run_full_scan(body: FullScanRequest) -> Dict[str, Any]:
    """Trigger a full DRP scan: credentials, paste sites, cert transparency, TOR nodes."""
    engine = _get_engine()
    try:
        risks = engine.run_full_scan(
            org_id=body.org_id,
            domain=body.domain,
            email_domain=body.email_domain,
        )
        return {
            "org_id": body.org_id,
            "domain": body.domain,
            "risks_found": len(risks),
            "risks": [r.to_dict() for r in risks],
        }
    except Exception as exc:
        logger.exception("Full DRP scan failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/risks", summary="List external risks")
def list_risks(
    org_id: str = Query(..., description="Organisation ID"),
    risk_type: Optional[str] = Query(None, description="Filter by exposure type"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    limit: int = Query(100, ge=1, le=500, description="Max results"),
) -> Dict[str, Any]:
    """List persisted external risks with optional type and severity filters."""
    # Validate enum values if provided
    if risk_type:
        valid_types = [e.value for e in ExposureType]
        if risk_type not in valid_types:
            raise HTTPException(
                status_code=422,
                detail=f"Invalid risk_type '{risk_type}'. Valid: {valid_types}",
            )
    if severity:
        valid_severities = [e.value for e in RiskSeverity]
        if severity not in valid_severities:
            raise HTTPException(
                status_code=422,
                detail=f"Invalid severity '{severity}'. Valid: {valid_severities}",
            )

    engine = _get_engine()
    try:
        risks = engine.list_risks(
            org_id=org_id,
            risk_type=risk_type,
            severity=severity,
            limit=limit,
        )
        return {
            "org_id": org_id,
            "count": len(risks),
            "risks": [r.to_dict() for r in risks],
        }
    except Exception as exc:
        logger.exception("List risks failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/check/credential", summary="Check email credential exposure")
def check_credential(body: CredentialCheckRequest) -> Dict[str, Any]:
    """Check whether an email address appears in known breach databases."""
    engine = _get_engine()
    try:
        risks = engine.check_credential_exposure(
            email=body.email,
            org_id=body.org_id,
        )
        return {
            "email": body.email,
            "exposed": len(risks) > 0,
            "breach_count": len(risks),
            "risks": [r.to_dict() for r in risks],
        }
    except Exception as exc:
        logger.exception("Credential check failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/typosquats/{domain}", summary="Get typosquat variants for a domain")
def get_typosquats(domain: str) -> Dict[str, Any]:
    """Generate typosquat variants and check DNS resolvability."""
    engine = _get_engine()
    try:
        result = engine.detect_typosquats(domain)
        return result
    except Exception as exc:
        logger.exception("Typosquat detection failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/certificates/{domain}", summary="Certificate transparency lookup")
def get_certificates(domain: str) -> Dict[str, Any]:
    """Query crt.sh for certificates issued for the given domain."""
    engine = _get_engine()
    try:
        certs = engine.check_certificate_transparency(domain)
        return {
            "domain": domain,
            "cert_count": len(certs),
            "certificates": certs,
        }
    except Exception as exc:
        logger.exception("Certificate transparency lookup failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/summary", summary="Aggregate risk summary for an org")
def get_summary(
    org_id: str = Query(..., description="Organisation ID"),
) -> Dict[str, Any]:
    """Return aggregate DRP stats: total risks, breakdown by type and severity, recent findings."""
    engine = _get_engine()
    try:
        return engine.get_risk_summary(org_id)
    except Exception as exc:
        logger.exception("Risk summary failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))
