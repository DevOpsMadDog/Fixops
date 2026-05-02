"""Cloud Posture Router — ALDECI.

Cloud Security Posture Management (CSPM) endpoints.

Prefix: /api/v1/cloud-posture
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/cloud-posture/accounts              register_account
  GET    /api/v1/cloud-posture/accounts              list_accounts
  GET    /api/v1/cloud-posture/accounts/{id}         get_account
  POST   /api/v1/cloud-posture/findings              record_finding
  GET    /api/v1/cloud-posture/findings              list_findings
  PATCH  /api/v1/cloud-posture/findings/{id}/status  update_finding_status
  GET    /api/v1/cloud-posture/stats                 get_posture_stats
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/cloud-posture",
    tags=["Cloud Posture"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.cloud_posture_engine import CloudPostureEngine
        _engine = CloudPostureEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class RegisterAccountRequest(BaseModel):
    org_id: str = Field(default="default", description="Organisation identifier")
    account_id: str = Field(..., description="Cloud provider account/subscription ID")
    account_name: str = Field(default="", description="Human-readable account name")
    provider: str = Field(default="aws", description="Cloud provider: aws, azure, gcp, alibaba, oracle, ibm")
    region: str = Field(default="", description="Primary region")
    resource_count: int = Field(default=0, ge=0, description="Number of resources in account")
    status: str = Field(default="active", description="Account status")


class RecordFindingRequest(BaseModel):
    org_id: str = Field(default="default", description="Organisation identifier")
    cloud_account_id: str = Field(..., description="Internal cloud account id or account_id")
    resource_id: str = Field(default="", description="Affected resource identifier")
    resource_type: str = Field(default="compute", description="Resource type: iam, storage, compute, network, database, serverless, container")
    provider: str = Field(default="aws", description="Cloud provider")
    severity: str = Field(default="medium", description="Severity: critical, high, medium, low, info")
    title: str = Field(default="", description="Short finding title")
    description: str = Field(default="", description="Detailed finding description")
    remediation: str = Field(default="", description="Remediation steps")
    notes: str = Field(default="", description="Additional notes")


class UpdateFindingStatusRequest(BaseModel):
    org_id: str = Field(default="default", description="Organisation identifier")
    status: str = Field(..., description="New status: open, suppressed, resolved, false_positive")
    notes: str = Field(default="", description="Status update notes")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/accounts", dependencies=[Depends(api_key_auth)])
def register_account(req: RegisterAccountRequest) -> Dict[str, Any]:
    """Register a new cloud account for posture tracking."""
    try:
        return _get_engine().register_account(req.org_id, req.model_dump(exclude={"org_id"}))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        _logger.exception("register_account failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/accounts", dependencies=[Depends(api_key_auth)])
def list_accounts(
    org_id: str = Query(default="default"),
    provider: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List cloud accounts for the org."""
    try:
        return _get_engine().list_accounts(org_id, provider=provider)
    except Exception as exc:
        _logger.exception("list_accounts failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/accounts/{account_id}", dependencies=[Depends(api_key_auth)])
def get_account(
    account_id: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Get a single cloud account by internal id."""
    try:
        result = _get_engine().get_account(org_id, account_id)
        if not result:
            raise HTTPException(status_code=404, detail=f"Account {account_id} not found")
        return result
    except HTTPException:
        raise
    except Exception as exc:
        _logger.exception("get_account failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/findings", dependencies=[Depends(api_key_auth)])
def record_finding(req: RecordFindingRequest) -> Dict[str, Any]:
    """Record a cloud posture finding."""
    try:
        return _get_engine().record_finding(req.org_id, req.model_dump(exclude={"org_id"}))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        _logger.exception("record_finding failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/findings", dependencies=[Depends(api_key_auth)])
def list_findings(
    org_id: str = Query(default="default"),
    provider: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    resource_type: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    """List cloud posture findings with optional filters.

    Falls back to live ``CSPMConnector`` output (Prowler/Checkov/Trivy/
    CloudSploit/agentless) when the org has no recorded cp_findings AND
    those scanners have produced rows in ``SecurityFindingsEngine``.
    Returns ``{findings, total, source, hint?, projected_from?}``.
    """
    try:
        return _get_engine().list_findings_with_cspm_fallback(
            org_id,
            provider=provider,
            severity=severity,
            status=status,
            resource_type=resource_type,
        )
    except Exception as exc:
        _logger.exception("list_findings failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.patch("/findings/{finding_id}/status", dependencies=[Depends(api_key_auth)])
def update_finding_status(
    finding_id: str,
    req: UpdateFindingStatusRequest,
) -> Dict[str, Any]:
    """Update the status of a cloud posture finding."""
    try:
        return _get_engine().update_finding_status(req.org_id, finding_id, req.status, req.notes)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        _logger.exception("update_finding_status failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_posture_stats(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Return aggregate cloud posture statistics for the org."""
    try:
        return _get_engine().get_posture_stats(org_id)
    except Exception as exc:
        _logger.exception("get_posture_stats failed")
        raise HTTPException(status_code=500, detail=str(exc))
