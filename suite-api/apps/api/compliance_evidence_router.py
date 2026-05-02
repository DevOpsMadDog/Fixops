"""Compliance Evidence Router — ALDECI.

Endpoints for the ComplianceEvidenceCollector engine.
Handles evidence collection, submission, approval, and audit readiness.

Prefix: /api/v1/compliance-evidence
Auth: api_key_auth dependency
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/compliance-evidence",
    tags=["Compliance Evidence"],
)

_engine = None

_DB_PATH = os.environ.get(
    "COMPLIANCE_EVIDENCE_DB_PATH",
    "/tmp/aldeci_compliance_evidence.db",  # nosec B108
)


def _get_engine():
    global _engine
    if _engine is None:
        from core.compliance_evidence_collector import ComplianceEvidenceCollector
        _engine = ComplianceEvidenceCollector(db_path=_DB_PATH)
    return _engine


# ── Pydantic models ────────────────────────────────────────────────────────


class EvidenceRequestCreate(BaseModel):
    framework: str = Field("SOC2", description="SOC2 | ISO27001 | PCI-DSS | HIPAA")
    control_id: str = Field("", description="Control identifier")
    control_name: str = Field("", description="Human-readable control name")
    description: str = Field("", description="What evidence is needed")
    due_date: str = Field("", description="ISO date string")
    assignee: str = Field("", description="Who is responsible")


class EvidenceSubmit(BaseModel):
    evidence_type: str = Field("document", description="document | screenshot | log | config | attestation")
    filename: str = Field("", description="Filename of the evidence artifact")
    content_summary: str = Field("", description="Brief summary of evidence content")
    source_system: str = Field("", description="System the evidence was pulled from")
    collected_at: str = Field("", description="ISO timestamp when collected (defaults to now)")


class ApproveRequest(BaseModel):
    approved_by: str = Field(..., description="Username or email of approver")
    notes: str = Field("", description="Optional approval notes")


class RejectRequest(BaseModel):
    rejected_by: str = Field(..., description="Username or email of reviewer")
    reason: str = Field("", description="Reason for rejection")


class AutoCollectRequest(BaseModel):
    framework: str = Field(..., description="SOC2 | ISO27001 | PCI-DSS | HIPAA")


# ── Routes ─────────────────────────────────────────────────────────────────


@router.get("/requests")
def list_requests(
    org_id: str = Query("default"),
    framework: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    _auth=Depends(api_key_auth),
) -> List[Dict[str, Any]]:
    """List evidence collection requests."""
    try:
        return _get_engine().list_evidence_requests(org_id, framework=framework, status=status)
    except Exception as exc:
        _logger.exception("list_requests failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/requests", status_code=201)
def create_request(
    body: EvidenceRequestCreate,
    org_id: str = Query("default"),
    _auth=Depends(api_key_auth),
) -> Dict[str, Any]:
    """Create a new evidence collection request."""
    try:
        return _get_engine().create_evidence_request(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        _logger.exception("create_request failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/requests/{request_id}/evidence")
def list_evidence(
    request_id: str,
    org_id: str = Query("default"),
    _auth=Depends(api_key_auth),
) -> List[Dict[str, Any]]:
    """List evidence items for a request."""
    try:
        return _get_engine().list_evidence(org_id, request_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        _logger.exception("list_evidence failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/requests/{request_id}/evidence", status_code=201)
def submit_evidence(
    request_id: str,
    body: EvidenceSubmit,
    org_id: str = Query("default"),
    _auth=Depends(api_key_auth),
) -> Dict[str, Any]:
    """Submit evidence for a request."""
    try:
        return _get_engine().submit_evidence(org_id, request_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        _logger.exception("submit_evidence failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/requests/{request_id}/approve")
def approve_evidence(
    request_id: str,
    body: ApproveRequest,
    org_id: str = Query("default"),
    _auth=Depends(api_key_auth),
) -> Dict[str, Any]:
    """Approve evidence for a request."""
    try:
        return _get_engine().approve_evidence(org_id, request_id, body.approved_by, body.notes)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        _logger.exception("approve_evidence failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/requests/{request_id}/reject")
def reject_evidence(
    request_id: str,
    body: RejectRequest,
    org_id: str = Query("default"),
    _auth=Depends(api_key_auth),
) -> Dict[str, Any]:
    """Reject evidence for a request."""
    try:
        return _get_engine().reject_evidence(org_id, request_id, body.rejected_by, body.reason)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        _logger.exception("reject_evidence failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/auto-collect")
def auto_collect(
    body: AutoCollectRequest,
    org_id: str = Query("default"),
    _auth=Depends(api_key_auth),
) -> Dict[str, Any]:
    """Trigger automated evidence collection from connected systems."""
    try:
        items = _get_engine().auto_collect(org_id, body.framework)
        return {"collected": len(items), "framework": body.framework, "items": items}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        _logger.exception("auto_collect failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/audit-readiness")
def audit_readiness(
    org_id: str = Query("default"),
    framework: str = Query("SOC2"),
    _auth=Depends(api_key_auth),
) -> Dict[str, Any]:
    """Get audit readiness score for a framework."""
    try:
        return _get_engine().get_audit_readiness(org_id, framework)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        _logger.exception("audit_readiness failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/stats")
def collection_stats(
    org_id: str = Query("default"),
    _auth=Depends(api_key_auth),
) -> Dict[str, Any]:
    """Get overall evidence collection statistics."""
    try:
        return _get_engine().get_collection_stats(org_id)
    except Exception as exc:
        _logger.exception("collection_stats failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/collect-all")
def collect_all(
    org_id: str = Query("default"),
    _auth=Depends(api_key_auth),
) -> Dict[str, Any]:
    """Trigger evidence collection from all wired security engines.

    Gathers evidence from AlertTriage, AccessControl, PasswordPolicy,
    VulnScan, SecurityTraining, and IncidentResponse engines.
    Maps evidence to SOC2 CC7.2, CC6.1, CC1.4, CC7.3, NIST AC-7, PCI-DSS 11.2.
    """
    try:
        return _get_engine().collect_all(org_id)
    except Exception as exc:
        _logger.exception("collect_all failed")
        raise HTTPException(status_code=500, detail=str(exc))
