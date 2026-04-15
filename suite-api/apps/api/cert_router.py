"""TLS Certificate Management Router — ALDECI.

8 endpoints under /api/v1/certificates:
  POST   /                      add a certificate to inventory
  GET    /                      list certificates (org scoped)
  GET    /{cert_id}             get a single certificate
  PUT    /{cert_id}             update certificate fields
  DELETE /{cert_id}             remove a certificate
  GET    /alerts/expiry         expiry alert groups (expired/7d/30d/90d)
  GET    /weak                  weak-config certificates
  GET    /stats                 summary statistics
  POST   /check                 live-probe a domain for its TLS cert
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
        "cert_router: auth_deps not available, relying on app.py mount-level auth"
    )
    _AUTH_DEP = []

from core.cert_manager import CertificateManager

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/certificates",
    tags=["certificates"],
    dependencies=_AUTH_DEP,
)

_manager: Optional[CertificateManager] = None


def _get_manager() -> CertificateManager:
    global _manager
    if _manager is None:
        _manager = CertificateManager()
    return _manager


# ============================================================================
# REQUEST / RESPONSE MODELS
# ============================================================================


class AddCertRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    domain: str = Field(..., description="Primary domain")
    issuer: str = Field("", description="Certificate issuer CN/O")
    serial: str = Field("", description="Serial number")
    not_before: str = Field("", description="Validity start (ISO-8601)")
    not_after: str = Field("", description="Validity end (ISO-8601)")
    algorithm: str = Field("", description="Signature algorithm (e.g. sha256WithRSAEncryption)")
    key_size: int = Field(0, description="Public key size in bits")
    san_list: List[str] = Field(default_factory=list, description="Subject Alternative Names")
    wildcard: bool = Field(False, description="Wildcard certificate flag")


class UpdateCertRequest(BaseModel):
    domain: Optional[str] = None
    issuer: Optional[str] = None
    serial: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    algorithm: Optional[str] = None
    key_size: Optional[int] = None
    san_list: Optional[List[str]] = None
    wildcard: Optional[bool] = None
    self_signed: Optional[bool] = None


class CheckDomainRequest(BaseModel):
    domain: str = Field(..., description="Domain to probe")
    port: int = Field(443, description="TLS port (default 443)")
    timeout: int = Field(5, description="Socket timeout in seconds")


class AddCertResponse(BaseModel):
    cert_id: str
    message: str = "Certificate added"


class DeleteResponse(BaseModel):
    deleted: bool
    message: str


# ============================================================================
# ENDPOINTS
# ============================================================================


@router.post("/", response_model=AddCertResponse, summary="Add certificate to inventory")
def add_certificate(body: AddCertRequest, mgr: CertificateManager = Depends(_get_manager)):
    cert_id = mgr.add_certificate(body.org_id, body.model_dump(exclude={"org_id"}))
    return AddCertResponse(cert_id=cert_id)


@router.get("/", response_model=List[Dict[str, Any]], summary="List certificates")
def list_certificates(
    org_id: str = Query("default"),
    expired_only: bool = Query(False),
    expiring_days: Optional[int] = Query(None),
    mgr: CertificateManager = Depends(_get_manager),
):
    return mgr.list_certificates(org_id, expired_only=expired_only, expiring_days=expiring_days)


@router.get("/alerts/expiry", response_model=Dict[str, Any], summary="Get expiry alert groups")
def get_expiry_alerts(
    org_id: str = Query("default"),
    mgr: CertificateManager = Depends(_get_manager),
):
    return mgr.get_expiry_alerts(org_id)


@router.get("/weak", response_model=List[Dict[str, Any]], summary="List weak certificates")
def get_weak_certificates(
    org_id: str = Query("default"),
    mgr: CertificateManager = Depends(_get_manager),
):
    return mgr.get_weak_certificates(org_id)


@router.get("/stats", response_model=Dict[str, Any], summary="Certificate statistics")
def get_cert_stats(
    org_id: str = Query("default"),
    mgr: CertificateManager = Depends(_get_manager),
):
    return mgr.get_cert_stats(org_id)


@router.post("/check", response_model=Dict[str, Any], summary="Live-probe a domain TLS cert")
def check_certificate(body: CheckDomainRequest, mgr: CertificateManager = Depends(_get_manager)):
    return mgr.check_certificate(body.domain, port=body.port, timeout=body.timeout)


@router.get("/{cert_id}", response_model=Dict[str, Any], summary="Get a certificate by ID")
def get_certificate(
    cert_id: str,
    org_id: str = Query("default"),
    mgr: CertificateManager = Depends(_get_manager),
):
    cert = mgr.get_certificate(cert_id, org_id)
    if cert is None:
        raise HTTPException(status_code=404, detail="Certificate not found")
    return cert


@router.put("/{cert_id}", response_model=Dict[str, Any], summary="Update certificate fields")
def update_certificate(
    cert_id: str,
    body: UpdateCertRequest,
    org_id: str = Query("default"),
    mgr: CertificateManager = Depends(_get_manager),
):
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    updated = mgr.update_certificate(cert_id, org_id, updates)
    if not updated:
        raise HTTPException(status_code=404, detail="Certificate not found or no changes")
    cert = mgr.get_certificate(cert_id, org_id)
    return cert or {"updated": True}


@router.delete("/{cert_id}", response_model=DeleteResponse, summary="Delete a certificate")
def delete_certificate(
    cert_id: str,
    org_id: str = Query("default"),
    mgr: CertificateManager = Depends(_get_manager),
):
    deleted = mgr.delete_certificate(cert_id, org_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Certificate not found")
    return DeleteResponse(deleted=True, message="Certificate deleted")
