"""Security Findings Router — ALDECI.

Endpoints for the Security Findings engine (unified findings aggregator).

Prefix: /api/v1/security-findings
Auth:   api_key_auth dependency

Routes:
  POST  /api/v1/security-findings/findings                         record_finding
  PATCH /api/v1/security-findings/findings/{finding_id}/status     update_status
  POST  /api/v1/security-findings/findings/{finding_id}/evidence   add_evidence
  POST  /api/v1/security-findings/findings/{finding_id}/suppress   suppress_finding
  GET   /api/v1/security-findings/findings/{finding_id}            get_finding
  GET   /api/v1/security-findings/findings                         list_findings
  GET   /api/v1/security-findings/assets/{asset_id}/findings       get_asset_findings
  GET   /api/v1/security-findings/summary                          get_findings_summary
  GET   /api/v1/security-findings/export                           export_findings
"""
from __future__ import annotations

import csv
import io
import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/security-findings",
    tags=["Security Findings"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_findings_engine import SecurityFindingsEngine
        _engine = SecurityFindingsEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class FindingCreate(BaseModel):
    org_id: str
    title: str
    finding_type: str = "vulnerability"
    source_tool: str = "custom"
    severity: str = "medium"
    cvss_score: float = Field(default=0.0, ge=0.0, le=10.0)
    asset_id: str = ""
    asset_type: str = ""
    description: str = ""
    remediation: str = ""


class FindingStatusUpdate(BaseModel):
    org_id: str
    status: str
    assigned_to: Optional[str] = None


class EvidenceAdd(BaseModel):
    org_id: str
    evidence_type: str = "log"
    content: str = ""


class FindingSuppress(BaseModel):
    org_id: str
    reason: str
    suppressed_by: str
    expires_at: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/", dependencies=[Depends(api_key_auth)])
def list_security_findings(org_id: str = Query("default")) -> Dict[str, Any]:
    """List security findings for the org."""
    findings = _get_engine().list_findings(org_id=org_id)
    return {"org_id": org_id, "findings": findings, "total": len(findings)}


@router.post("/findings", dependencies=[Depends(api_key_auth)])
def record_finding(body: FindingCreate) -> Dict[str, Any]:
    """Record a finding; deduplicates if matching non-resolved finding exists."""
    try:
        return _get_engine().record_finding(
            org_id=body.org_id,
            title=body.title,
            finding_type=body.finding_type,
            source_tool=body.source_tool,
            severity=body.severity,
            cvss_score=body.cvss_score,
            asset_id=body.asset_id,
            asset_type=body.asset_type,
            description=body.description,
            remediation=body.remediation,
        )
    except Exception as exc:
        _logger.exception("record_finding error")
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.patch("/findings/{finding_id}/status", dependencies=[Depends(api_key_auth)])
def update_status(finding_id: str, body: FindingStatusUpdate) -> Dict[str, Any]:
    """Update the status of a finding."""
    result = _get_engine().update_status(
        finding_id=finding_id,
        org_id=body.org_id,
        status=body.status,
        assigned_to=body.assigned_to,
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return result


@router.post("/findings/{finding_id}/evidence", dependencies=[Depends(api_key_auth)])
def add_evidence(finding_id: str, body: EvidenceAdd) -> Dict[str, Any]:
    """Add evidence to a finding."""
    return _get_engine().add_evidence(
        finding_id=finding_id,
        org_id=body.org_id,
        evidence_type=body.evidence_type,
        content=body.content,
    )


@router.post("/findings/{finding_id}/suppress", dependencies=[Depends(api_key_auth)])
def suppress_finding(finding_id: str, body: FindingSuppress) -> Dict[str, Any]:
    """Suppress a finding with reason and expiry."""
    result = _get_engine().suppress_finding(
        finding_id=finding_id,
        org_id=body.org_id,
        reason=body.reason,
        suppressed_by=body.suppressed_by,
        expires_at=body.expires_at,
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return result


@router.get("/findings/{finding_id}", dependencies=[Depends(api_key_auth)])
def get_finding(
    finding_id: str,
     org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Get a finding with evidence and suppressions."""
    result = _get_engine().get_finding(finding_id=finding_id, org_id=org_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return result


@router.get("/findings", dependencies=[Depends(api_key_auth)])
def list_findings(
     org_id: str = Query(default="default"),
    status: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    source_tool: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List findings with optional filters."""
    return _get_engine().list_findings(
        org_id=org_id,
        status=status,
        severity=severity,
        source_tool=source_tool,
    )


@router.get("/assets/{asset_id}/findings", dependencies=[Depends(api_key_auth)])
def get_asset_findings(
    asset_id: str,
     org_id: str = Query(default="default"),
) -> List[Dict[str, Any]]:
    """Get all findings for a specific asset."""
    return _get_engine().get_asset_findings(org_id=org_id, asset_id=asset_id)


@router.get("/summary", dependencies=[Depends(api_key_auth)])
def get_findings_summary(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Get findings summary: counts, severity breakdown, source breakdown, top assets."""
    return _get_engine().get_findings_summary(org_id=org_id)


@router.get("/export", dependencies=[Depends(api_key_auth)])
def export_findings(
    org_id: str = Query(default="default"),
    format: str = Query(default="csv", pattern="^(csv|json)$"),
) -> StreamingResponse:
    """Export findings as CSV or JSON stream.

    Query params:
      - org_id: organization ID (default: "default")
      - format: export format - "csv" or "json" (default: "csv")

    Returns StreamingResponse with findings data.
    """
    findings = _get_engine().list_findings(org_id=org_id)

    if format == "json":
        # JSON export
        import json

        def generate_json():
            yield "["
            for i, finding in enumerate(findings):
                if i > 0:
                    yield ","
                yield json.dumps(finding, default=str)
            yield "]"

        return StreamingResponse(
            generate_json(),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=findings_{org_id}.json"},
        )

    # CSV export (default)
    def generate_csv():
        columns = [
            "id",
            "severity",
            "title",
            "description",
            "source_tool",
            "asset_id",
            "status",
            "created_at",
            "resolved_at",
        ]
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        yield output.getvalue()
        output.truncate(0)
        output.seek(0)

        for finding in findings:
            writer.writerow(finding)
            chunk = output.getvalue()
            if chunk:
                yield chunk
                output.truncate(0)
                output.seek(0)

    return StreamingResponse(
        generate_csv(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=findings_{org_id}.csv"},
    )
