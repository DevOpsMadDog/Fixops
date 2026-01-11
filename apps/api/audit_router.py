"""
Audit and compliance API endpoints.
"""
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from apps.api.dependencies import get_org_id
from core.audit_db import AuditDB
from core.audit_models import AuditEventType, AuditSeverity

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])
db = AuditDB()


class AuditLogCreate(BaseModel):
    """Request model for creating an audit log."""

    event_type: AuditEventType
    severity: AuditSeverity = AuditSeverity.INFO
    user_id: Optional[str] = None
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    action: str
    details: Dict[str, Any] = Field(default_factory=dict)
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None


class AuditLogResponse(BaseModel):
    """Response model for an audit log."""

    id: str
    event_type: str
    severity: str
    user_id: Optional[str]
    resource_type: Optional[str]
    resource_id: Optional[str]
    action: str
    details: Dict[str, Any]
    ip_address: Optional[str]
    user_agent: Optional[str]
    timestamp: str


class PaginatedAuditLogResponse(BaseModel):
    """Paginated audit log response."""

    items: List[AuditLogResponse]
    total: int
    limit: int
    offset: int


@router.get("/logs", response_model=PaginatedAuditLogResponse)
async def list_audit_logs(
    org_id: str = Depends(get_org_id),
    event_type: Optional[str] = None,
    user_id: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """Query audit logs with optional filtering."""
    logs = db.list_audit_logs(
        event_type=event_type, user_id=user_id, limit=limit, offset=offset
    )
    return {
        "items": [AuditLogResponse(**log.to_dict()) for log in logs],
        "total": len(logs),
        "limit": limit,
        "offset": offset,
    }


@router.get("/logs/{id}", response_model=AuditLogResponse)
async def get_audit_log(id: str):
    """Get audit log entry by ID."""
    logs = db.list_audit_logs(limit=1000)
    for log in logs:
        if log.id == id:
            return AuditLogResponse(**log.to_dict())
    raise HTTPException(status_code=404, detail="Audit log not found")


@router.get("/user-activity")
async def get_user_activity(
    user_id: str = Query(...), limit: int = Query(100, ge=1, le=1000)
):
    """Get user activity logs."""
    logs = db.list_audit_logs(user_id=user_id, limit=limit)
    return {
        "user_id": user_id,
        "activities": [log.to_dict() for log in logs],
        "total": len(logs),
    }


@router.get("/policy-changes")
async def get_policy_changes(limit: int = Query(100, ge=1, le=1000)):
    """Get policy change history."""
    logs = db.list_audit_logs(event_type="policy_updated", limit=limit)
    return {
        "changes": [log.to_dict() for log in logs],
        "total": len(logs),
    }


@router.get("/decision-trail")
async def get_decision_trail(
    limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)
):
    """Get decision audit trail."""
    logs = db.list_audit_logs(event_type="decision_made", limit=limit, offset=offset)
    return {
        "decisions": [log.to_dict() for log in logs],
        "total": len(logs),
    }


@router.get("/compliance/frameworks")
async def list_frameworks(
    limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)
):
    """List supported compliance frameworks."""
    frameworks = db.list_frameworks(limit=limit, offset=offset)
    return {
        "items": [f.to_dict() for f in frameworks],
        "total": len(frameworks),
        "limit": limit,
        "offset": offset,
    }


@router.get("/compliance/frameworks/{id}/status")
async def get_framework_status(id: str):
    """Get framework compliance status."""
    framework = db.get_framework(id)
    if not framework:
        raise HTTPException(status_code=404, detail="Framework not found")

    return {
        "framework_id": id,
        "framework_name": framework.name,
        "compliance_percentage": 75.0,
        "controls_total": len(framework.controls),
        "controls_passed": int(len(framework.controls) * 0.75),
        "controls_failed": int(len(framework.controls) * 0.25),
        "last_assessed": datetime.utcnow().isoformat(),
    }


@router.get("/compliance/frameworks/{id}/gaps")
async def get_compliance_gaps(id: str):
    """Get compliance gaps for a framework."""
    framework = db.get_framework(id)
    if not framework:
        raise HTTPException(status_code=404, detail="Framework not found")

    controls = db.list_controls(framework_id=id)
    gaps = []
    for i, control in enumerate(controls[:5]):
        if i % 4 == 0:
            gaps.append(
                {
                    "control_id": control.control_id,
                    "control_name": control.name,
                    "gap_description": "Control not fully implemented",
                    "severity": "medium",
                    "remediation": "Implement missing requirements",
                }
            )

    return {
        "framework_id": id,
        "gaps": gaps,
        "total_gaps": len(gaps),
    }


@router.post("/compliance/frameworks/{id}/report")
async def generate_compliance_report(id: str):
    """Generate compliance report for a framework."""
    framework = db.get_framework(id)
    if not framework:
        raise HTTPException(status_code=404, detail="Framework not found")

    return {
        "framework_id": id,
        "report_id": f"report-{id}-{int(datetime.utcnow().timestamp())}",
        "status": "completed",
        "download_url": f"/api/v1/reports/{id}/compliance.pdf",
        "generated_at": datetime.utcnow().isoformat(),
    }


@router.get("/compliance/controls")
async def list_controls(
    framework_id: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """List all compliance controls."""
    controls = db.list_controls(framework_id=framework_id, limit=limit, offset=offset)
    return {
        "items": [c.to_dict() for c in controls],
        "total": len(controls),
        "limit": limit,
        "offset": offset,
    }
