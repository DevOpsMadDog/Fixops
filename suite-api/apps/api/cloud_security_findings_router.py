"""Cloud Security Findings Router — ALDECI.

Multi-cloud security findings aggregator with dedup, suppression, and remediation tracking.

Prefix: /api/v1/cloud-findings
Auth: api_key_auth on ALL endpoints

Routes:
  POST   /api/v1/cloud-findings/findings                  ingest_finding
  POST   /api/v1/cloud-findings/findings/bulk             bulk_ingest
  PUT    /api/v1/cloud-findings/findings/{id}/resolve     resolve_finding
  POST   /api/v1/cloud-findings/findings/{id}/suppress    suppress_finding
  POST   /api/v1/cloud-findings/findings/{id}/remediation assign_remediation
  PUT    /api/v1/cloud-findings/remediation/{id}          update_remediation
  GET    /api/v1/cloud-findings/findings                  get_findings
  GET    /api/v1/cloud-findings/summary                   get_finding_summary
  GET    /api/v1/cloud-findings/top-resources             get_top_affected_resources
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/cloud-findings",
    tags=["Cloud Security Findings"],
    dependencies=[Depends(api_key_auth)],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.cloud_security_findings_engine import CloudSecurityFindingsEngine
        _engine = CloudSecurityFindingsEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class IngestFindingRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    provider: str = Field(..., description="aws/azure/gcp/alibaba/oci/ibm")
    account_id: str = Field(..., description="Cloud account/subscription ID")
    region: str = Field(default="", description="Cloud region")
    resource_type: str = Field(default="", description="Resource type (e.g. s3, vm)")
    resource_id: str = Field(..., description="Resource identifier")
    finding_title: str = Field(..., description="Short finding title")
    finding_type: str = Field(default="misconfiguration",
                              description="misconfiguration/vulnerability/compliance/threat/exposure")
    severity: str = Field(..., description="critical/high/medium/low/informational")
    cvss_score: float = Field(default=0.0, ge=0.0, le=10.0, description="CVSS score 0-10")
    remediation: str = Field(default="", description="Remediation guidance")


class BulkIngestRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    findings: List[Dict[str, Any]] = Field(..., description="List of finding dicts")


class ResolveRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")


class SuppressRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    suppressed_by: str = Field(..., description="Who suppressed")
    reason: str = Field(..., description="Suppression reason")
    expires_at: str = Field(default="", description="ISO-8601 expiry (optional)")


class AssignRemediationRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    assignee: str = Field(..., description="Assigned engineer/team")
    due_date: str = Field(..., description="ISO-8601 due date")
    notes: str = Field(default="", description="Additional notes")


class UpdateRemediationRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    status: str = Field(..., description="assigned/in_progress/completed/cancelled")
    notes: str = Field(default="", description="Updated notes")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/findings", summary="Ingest a cloud security finding (dedup on open findings)")
def ingest_finding(req: IngestFindingRequest) -> Dict[str, Any]:
    try:
        return _get_engine().ingest_finding(
            org_id=req.org_id,
            provider=req.provider,
            account_id=req.account_id,
            region=req.region,
            resource_type=req.resource_type,
            resource_id=req.resource_id,
            finding_title=req.finding_title,
            finding_type=req.finding_type,
            severity=req.severity,
            cvss_score=req.cvss_score,
            remediation=req.remediation,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/findings/bulk", summary="Bulk ingest cloud findings")
def bulk_ingest(req: BulkIngestRequest) -> Dict[str, int]:
    return _get_engine().bulk_ingest(org_id=req.org_id, findings_list=req.findings)


@router.put("/findings/{finding_id}/resolve", summary="Resolve a finding")
def resolve_finding(finding_id: str, req: ResolveRequest) -> Dict[str, Any]:
    try:
        return _get_engine().resolve_finding(finding_id=finding_id, org_id=req.org_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/findings/{finding_id}/suppress", summary="Suppress a finding")
def suppress_finding(finding_id: str, req: SuppressRequest) -> Dict[str, Any]:
    try:
        return _get_engine().suppress_finding(
            finding_id=finding_id,
            org_id=req.org_id,
            suppressed_by=req.suppressed_by,
            reason=req.reason,
            expires_at=req.expires_at,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/findings/{finding_id}/remediation", summary="Assign remediation for a finding")
def assign_remediation(finding_id: str, req: AssignRemediationRequest) -> Dict[str, Any]:
    try:
        return _get_engine().assign_remediation(
            finding_id=finding_id,
            org_id=req.org_id,
            assignee=req.assignee,
            due_date=req.due_date,
            notes=req.notes,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.put("/remediation/{remediation_id}", summary="Update remediation status")
def update_remediation(remediation_id: str, req: UpdateRemediationRequest) -> Dict[str, Any]:
    try:
        return _get_engine().update_remediation(
            remediation_id=remediation_id,
            org_id=req.org_id,
            status=req.status,
            notes=req.notes,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/findings", summary="List findings with optional filters")
def get_findings(
     org_id: str = Query(default="default"),
    provider: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    return _get_engine().get_findings(
        org_id=org_id, provider=provider, severity=severity, status=status
    )


@router.get("/summary", summary="Get finding summary stats")
def get_finding_summary(org_id: str = Query(default="default")) -> Dict[str, Any]:
    return _get_engine().get_finding_summary(org_id=org_id)


@router.get("/top-resources", summary="Top resources by finding count")
def get_top_affected_resources(
     org_id: str = Query(default="default"),
    limit: int = Query(default=10, ge=1, le=100),
) -> List[Dict[str, Any]]:
    return _get_engine().get_top_affected_resources(org_id=org_id, limit=limit)


@router.get(
    "/export/csv",
    summary="Export cloud findings as CSV",
    response_class=Response,
    responses={200: {"content": {"text/csv": {}}, "description": "CSV export of cloud findings"}},
)
def export_findings_csv(
    org_id: str = Query(default="default"),
    provider: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
) -> Response:
    """Export filtered cloud findings as a downloadable CSV file."""
    csv_data = _get_engine().export_findings_csv(
        org_id=org_id, provider=provider, severity=severity, status=status
    )
    filename = f"cloud-findings-{org_id}.csv"
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
