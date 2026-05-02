"""Certificate Lifecycle Router — ALDECI.

Full lifecycle management of certificates: registration, expiry monitoring,
renewal tracking, and revocation.

Prefix: /api/v1/certificates
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/certificates/                              register_certificate
  GET    /api/v1/certificates/                              list_certificates
  GET    /api/v1/certificates/expiring                      get_expiring_certificates
  GET    /api/v1/certificates/stats                         get_certificate_stats
  GET    /api/v1/certificates/{cert_id}                     get_certificate
  POST   /api/v1/certificates/{cert_id}/renew               renew_certificate
  POST   /api/v1/certificates/{cert_id}/revoke              revoke_certificate
  GET    /api/v1/certificates/{cert_id}/renewal-history     get_renewal_history
"""

from __future__ import annotations

import logging
from typing import List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/certificates",
    tags=["Certificate Lifecycle"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.certificate_lifecycle_engine import CertificateLifecycleEngine
        _engine = CertificateLifecycleEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class RegisterCertificateRequest(BaseModel):
    domain: str = Field(default="", description="Primary domain / subject CN")
    issuer: str = Field(default="", description="Certificate Authority name")
    cert_type: str = Field(
        default="ssl",
        description="Certificate type: ssl | code_signing | client | ca",
    )
    expiry_date: str = Field(
        default="",
        description="Expiry timestamp in ISO 8601 format (e.g. 2027-01-01T00:00:00+00:00)",
    )
    san_list: List[str] = Field(
        default_factory=list,
        description="Subject Alternative Names",
    )
    auto_renew: bool = Field(default=False, description="Whether to auto-renew before expiry")


class RenewCertificateRequest(BaseModel):
    new_expiry_date: str = Field(
        ...,
        description="New expiry date in ISO 8601 format",
    )


class RevokeCertificateRequest(BaseModel):
    reason: str = Field(..., description="Reason for revocation")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/", dependencies=[Depends(api_key_auth)], status_code=201)
def register_certificate(
    body: RegisterCertificateRequest,
    org_id: str = Query(default="default"),
):
    """Register a new certificate for the org."""
    try:
        return _get_engine().register_certificate(org_id, body.model_dump())
    except Exception as exc:
        _logger.exception("Error registering certificate")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/expiring", dependencies=[Depends(api_key_auth)])
def get_expiring_certificates(
    org_id: str = Query(default="default"),
    days_ahead: int = Query(default=30, ge=1, le=365),
):
    """Return non-revoked certificates expiring within the next N days."""
    return _get_engine().get_expiring_certificates(org_id, days_ahead=days_ahead)


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_certificate_stats(org_id: str = Query(default="default")):
    """Return aggregated certificate statistics for the org."""
    return _get_engine().get_certificate_stats(org_id)


@router.get("/", dependencies=[Depends(api_key_auth)])
def list_certificates(
    org_id: str = Query(default="default"),
    cert_type: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
):
    """List certificates for an org, optionally filtered by cert_type and/or status."""
    return _get_engine().list_certificates(org_id, cert_type=cert_type, status=status)


@router.get("/{cert_id}", dependencies=[Depends(api_key_auth)])
def get_certificate(
    cert_id: str,
    org_id: str = Query(default="default"),
):
    """Fetch a single certificate by ID (org-scoped)."""
    cert = _get_engine().get_certificate(org_id, cert_id)
    if not cert:
        raise HTTPException(status_code=404, detail="Certificate not found")
    return cert


@router.post("/{cert_id}/renew", dependencies=[Depends(api_key_auth)], status_code=200)
def renew_certificate(
    cert_id: str,
    body: RenewCertificateRequest,
    org_id: str = Query(default="default"),
):
    """Renew a certificate with a new expiry date."""
    try:
        return _get_engine().renew_certificate(org_id, cert_id, body.new_expiry_date)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error renewing certificate")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/{cert_id}/revoke", dependencies=[Depends(api_key_auth)], status_code=200)
def revoke_certificate(
    cert_id: str,
    body: RevokeCertificateRequest,
    org_id: str = Query(default="default"),
):
    """Revoke a certificate with a stated reason."""
    try:
        return _get_engine().revoke_certificate(org_id, cert_id, body.reason)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error revoking certificate")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/{cert_id}/renewal-history", dependencies=[Depends(api_key_auth)])
def get_renewal_history(
    cert_id: str,
    org_id: str = Query(default="default"),
):
    """Return all renewal records for a certificate."""
    return _get_engine().get_renewal_history(org_id, cert_id)
