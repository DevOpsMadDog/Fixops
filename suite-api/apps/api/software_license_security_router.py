"""Software License Security Router — ALDECI.

Exposes software license compliance and open-source security risk management
as REST endpoints.

Prefix: /api/v1/license-security

Endpoints:
  POST   /records                    — Add a license record
  GET    /records                    — List records (license_type, license_risk, approved)
  GET    /records/{id}               — Get a single record
  PUT    /records/{id}/approve       — Approve a license record
  POST   /violations                 — Record a license violation
  PUT    /violations/{id}/resolve    — Resolve a violation (waived/remediated)
  GET    /violations                 — List violations (severity, status)
  POST   /policies                   — Create a license policy
  GET    /policies                   — List policies
  GET    /stats                      — License compliance statistics
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/license-security",
    tags=["license-security"],
)


# ---------------------------------------------------------------------------
# Lazy engine loader
# ---------------------------------------------------------------------------


def _get_engine():
    try:
        from core.software_license_security_engine import SoftwareLicenseSecurityEngine
        return SoftwareLicenseSecurityEngine()
    except ImportError as exc:
        logger.error("software_license_security_engine import failed: %s", exc)
        raise HTTPException(
            status_code=503,
            detail=f"software_license_security unavailable: {exc}",
        )


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class AddLicenseRecordRequest(BaseModel):
    org_id: str = "default"
    package_name: str
    package_version: str = ""
    license_type: str = "unknown"
    license_risk: str = "low"
    is_oss: bool = True
    has_vulnerabilities: bool = False
    vuln_count: int = 0
    approved: bool = False


class RecordViolationRequest(BaseModel):
    org_id: str = "default"
    record_id: str
    violation_type: str = "unknown"
    severity: str = "medium"
    description: str = ""


class ResolveViolationRequest(BaseModel):
    resolution_type: str


class CreatePolicyRequest(BaseModel):
    org_id: str = "default"
    policy_name: str
    allowed_licenses: List[str] = []
    blocked_licenses: List[str] = []
    require_approval: bool = True


# ---------------------------------------------------------------------------
# Endpoints — License Records
# ---------------------------------------------------------------------------


@router.post("/records", status_code=201)
def add_license_record(body: AddLicenseRecordRequest) -> Dict[str, Any]:
    """Add a software license record."""
    engine = _get_engine()
    try:
        return engine.add_license_record(body.org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/records")
def list_license_records(
    org_id: str = Query(default="default"),
    license_type: Optional[str] = Query(default=None),
    license_risk: Optional[str] = Query(default=None),
    approved: Optional[bool] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List license records with optional filters."""
    engine = _get_engine()
    return engine.list_license_records(
        org_id,
        license_type=license_type,
        license_risk=license_risk,
        approved=approved,
    )


@router.get("/records/{record_id}")
def get_license_record(record_id: str, org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Get a single license record by ID."""
    engine = _get_engine()
    record = engine.get_license_record(org_id, record_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"License record {record_id!r} not found.")
    return record


@router.put("/records/{record_id}/approve")
def approve_license(record_id: str, org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Approve a license record."""
    engine = _get_engine()
    try:
        return engine.approve_license(org_id, record_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


# ---------------------------------------------------------------------------
# Endpoints — Violations
# ---------------------------------------------------------------------------


@router.post("/violations", status_code=201)
def record_violation(body: RecordViolationRequest) -> Dict[str, Any]:
    """Record a license violation."""
    engine = _get_engine()
    try:
        return engine.record_violation(body.org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.put("/violations/{violation_id}/resolve")
def resolve_violation(
    violation_id: str,
    body: ResolveViolationRequest,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Resolve a license violation (waived or remediated)."""
    engine = _get_engine()
    try:
        return engine.resolve_violation(org_id, violation_id, body.resolution_type)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/violations")
def list_violations(
    org_id: str = Query(default="default"),
    severity: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List license violations with optional filters."""
    engine = _get_engine()
    return engine.list_violations(org_id, severity=severity, status=status)


# ---------------------------------------------------------------------------
# Endpoints — Policies
# ---------------------------------------------------------------------------


@router.post("/policies", status_code=201)
def create_policy(body: CreatePolicyRequest) -> Dict[str, Any]:
    """Create a license policy."""
    engine = _get_engine()
    try:
        return engine.create_policy(body.org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/policies")
def list_policies(org_id: str = Query(default="default")) -> List[Dict[str, Any]]:
    """List all license policies for an org."""
    engine = _get_engine()
    return engine.list_policies(org_id)


# ---------------------------------------------------------------------------
# Endpoints — Stats
# ---------------------------------------------------------------------------


@router.get("/stats")
def get_license_stats(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Return aggregated license compliance statistics."""
    engine = _get_engine()
    return engine.get_license_stats(org_id)
