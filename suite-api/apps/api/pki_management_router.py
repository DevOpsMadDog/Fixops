"""PKI Management Router — ALDECI.

Certificate and CA lifecycle management endpoints.

Prefix: /api/v1/pki
Auth: api_key_auth dependency

Routes:
  POST /api/v1/pki/certificates                    issue_certificate
  GET  /api/v1/pki/certificates                    list_certificates
  GET  /api/v1/pki/certificates/expiring           get_expiring_certificates
  GET  /api/v1/pki/certificates/{cert_id}          get_certificate
  PUT  /api/v1/pki/certificates/{cert_id}/revoke   revoke_certificate
  POST /api/v1/pki/cas                             register_ca
  GET  /api/v1/pki/cas                             list_cas
  GET  /api/v1/pki/audit-log                       get_audit_log
  GET  /api/v1/pki/stats                           get_pki_stats
"""

from __future__ import annotations

import logging
from typing import List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/pki",
    tags=["PKI Management"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.pki_management_engine import PKIManagementEngine
        _engine = PKIManagementEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class IssueCertificateRequest(BaseModel):
    common_name: str = Field(..., description="Common name (CN) for the certificate")
    expires_at: str = Field(..., description="ISO expiry timestamp")
    serial_number: Optional[str] = Field(default="", description="Serial number")
    issuer: Optional[str] = Field(default="", description="Issuing CA")
    subject_alt_names: Optional[List[str]] = Field(default=None, description="SANs")
    key_algorithm: Optional[str] = Field(default="RSA", description="RSA | ECDSA | DSA")
    key_size: Optional[int] = Field(default=2048, description="Key size in bits")
    cert_type: Optional[str] = Field(
        default="server",
        description="root_ca | intermediate_ca | server | client | code_signing | email",
    )
    status: Optional[str] = Field(default="active", description="initial status")
    issued_at: Optional[str] = Field(default=None, description="ISO issued timestamp")
    auto_renew: Optional[bool] = Field(default=False, description="Auto-renew flag")
    actor: Optional[str] = Field(default="system", description="Issuing actor")


class RevokeCertificateRequest(BaseModel):
    reason: str = Field(default="", description="Revocation reason")


class RegisterCARequest(BaseModel):
    name: str = Field(..., description="CA name")
    ca_type: str = Field(..., description="root | intermediate | external")
    subject: Optional[str] = Field(default="", description="CA subject DN")
    key_algorithm: Optional[str] = Field(default="RSA", description="Key algorithm")
    status: Optional[str] = Field(default="active", description="active | inactive | compromised")
    cert_count: Optional[int] = Field(default=0, description="Certificates issued")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/certificates", dependencies=[Depends(api_key_auth)], status_code=201)
def issue_certificate(
    body: IssueCertificateRequest,
    org_id: str = Query(default="default"),
):
    """Issue a new PKI certificate."""
    try:
        return _get_engine().issue_certificate(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error issuing certificate")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/certificates/expiring", dependencies=[Depends(api_key_auth)])
def get_expiring_certificates(
    org_id: str = Query(default="default"),
    days_ahead: int = Query(default=30, ge=1, le=365),
):
    """List active certificates expiring within days_ahead days."""
    return _get_engine().get_expiring_certificates(org_id, days_ahead=days_ahead)


@router.get("/certificates", dependencies=[Depends(api_key_auth)])
def list_certificates(
    org_id: str = Query(default="default"),
    cert_type: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
):
    """List certificates, optionally filtered by cert_type or status."""
    return _get_engine().list_certificates(org_id, cert_type=cert_type, status=status)


@router.get("/certificates/{cert_id}", dependencies=[Depends(api_key_auth)])
def get_certificate(
    cert_id: str,
    org_id: str = Query(default="default"),
):
    """Get a specific certificate by ID."""
    result = _get_engine().get_certificate(org_id, cert_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Certificate not found")
    return result


@router.put("/certificates/{cert_id}/revoke", dependencies=[Depends(api_key_auth)])
def revoke_certificate(
    cert_id: str,
    body: RevokeCertificateRequest,
    org_id: str = Query(default="default"),
):
    """Revoke a certificate."""
    try:
        return _get_engine().revoke_certificate(org_id, cert_id, body.reason)
    except Exception as exc:
        _logger.exception("Error revoking certificate")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/cas", dependencies=[Depends(api_key_auth)], status_code=201)
def register_ca(
    body: RegisterCARequest,
    org_id: str = Query(default="default"),
):
    """Register a certificate authority."""
    try:
        return _get_engine().register_ca(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error registering CA")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/cas", dependencies=[Depends(api_key_auth)])
def list_cas(
    org_id: str = Query(default="default"),
    status: Optional[str] = Query(default=None),
):
    """List certificate authorities."""
    return _get_engine().list_cas(org_id, status=status)


@router.get("/audit-log", dependencies=[Depends(api_key_auth)])
def get_audit_log(
    org_id: str = Query(default="default"),
    entity_id: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
):
    """Retrieve PKI audit log entries."""
    return _get_engine().get_audit_log(org_id, entity_id=entity_id, limit=limit)


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_pki_stats(
    org_id: str = Query(default="default"),
):
    """Return aggregated PKI statistics."""
    return _get_engine().get_pki_stats(org_id)
