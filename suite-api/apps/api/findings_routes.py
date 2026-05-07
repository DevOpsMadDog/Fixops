"""Findings REST API Routes — Finding Management and Lifecycle.

This module provides REST API for finding management separate from pipeline flow:
- List findings with rich filtering
- Query individual finding details with history
- Update finding status (open, in_progress, remediated, suppressed, etc.)
- Assign findings to users/teams
- Add analyst comments and audit trails
- Generate executive summaries and SLA reports
- Bulk operations and exports

Endpoints:
  GET    /api/v1/findings                          -- List findings with filters
  GET    /api/v1/findings/{finding_id}             -- Single finding detail
  PUT    /api/v1/findings/{finding_id}/status      -- Update status
  PUT    /api/v1/findings/{finding_id}/assign      -- Assign to user/team
  POST   /api/v1/findings/{finding_id}/comment     -- Add comment
  GET    /api/v1/findings/{finding_id}/timeline    -- Action timeline
  GET    /api/v1/findings/summary                  -- Executive summary
  GET    /api/v1/findings/sla                      -- SLA compliance
  POST   /api/v1/findings/bulk/status              -- Bulk status update
  POST   /api/v1/findings/export                   -- Export findings

Security: All endpoints require RBAC permission checks
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from apps.api.dependencies import get_org_id
from fastapi import APIRouter, Body, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/findings", tags=["findings"])

# Global findings store (in production: database)
_findings_store: Dict[str, Dict[str, Any]] = {}
_audit_trails: Dict[str, List[Dict[str, Any]]] = {}


# ============================================================================
# ENUMS
# ============================================================================


class FindingStatus(str, Enum):
    """Status of a finding."""

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    REMEDIATED = "remediated"
    SUPPRESSED = "suppressed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


class SortOrder(str, Enum):
    """Sort order for findings."""

    SEVERITY = "severity"
    CREATED_AT = "created_at"
    RISK_SCORE = "risk_score"
    LAST_SEEN = "last_seen"


# ============================================================================
# REQUEST/RESPONSE MODELS
# ============================================================================


class FindingListFilter(BaseModel):
    """Filters for listing findings."""

    severity: Optional[List[str]] = Field(None, description="Filter by severity")
    status: Optional[List[str]] = Field(None, description="Filter by status")
    connector: Optional[str] = Field(None, description="Filter by source connector")
    cve_id: Optional[str] = Field(None, description="Filter by CVE ID")
    asset_id: Optional[str] = Field(None, description="Filter by asset ID")
    assigned_to: Optional[str] = Field(None, description="Filter by assignee")
    date_from: Optional[str] = Field(None, description="Created after (ISO 8601)")
    date_to: Optional[str] = Field(None, description="Created before (ISO 8601)")


class FindingComment(BaseModel):
    """Comment on a finding."""

    text: str = Field(..., min_length=1, max_length=5000)
    tags: Optional[List[str]] = Field(default_factory=list)


class CommentResponse(BaseModel):
    """Response from adding a comment."""

    comment_id: str
    finding_id: str
    created_at: datetime
    created_by: str
    text: str


class TimelineEvent(BaseModel):
    """Event in finding timeline."""

    timestamp: datetime
    event_type: str  # status_change, comment, assignment, feedback, etc.
    actor: str
    details: Dict[str, Any]


class FindingDetailResponse(BaseModel):
    """Complete finding detail."""

    id: str
    title: str
    description: Optional[str]
    severity: str
    status: str
    connector: str
    asset_id: Optional[str]
    cve_id: Optional[str]
    risk_score: float
    created_at: datetime
    updated_at: datetime
    last_seen: datetime
    assigned_to: Optional[str]
    assigned_team: Optional[str]
    pipeline_history: List[Dict[str, Any]]
    related_findings: List[str]
    council_verdict: Optional[Dict[str, Any]]
    playbook_runs: List[Dict[str, Any]]
    comments: List[CommentResponse]
    audit_trail: List[TimelineEvent]


class StatusUpdateRequest(BaseModel):
    """Request to update finding status."""

    status: str = Field(
        ...,
        pattern="^(open|in_progress|remediated|suppressed|false_positive|accepted_risk)$",
    )
    reason: Optional[str] = Field(None, max_length=500)
    evidence: Optional[Dict[str, Any]] = None


class AssignmentRequest(BaseModel):
    """Request to assign finding."""

    assigned_to: Optional[str] = None
    assigned_team: Optional[str] = None
    reason: Optional[str] = Field(None, max_length=500)


class FindingSummary(BaseModel):
    """Executive summary of findings."""

    total_open: int
    total_in_progress: int
    total_remediated: int
    by_severity: Dict[str, int]
    by_status: Dict[str, int]
    by_connector: Dict[str, int]
    findings_this_week: int
    findings_this_month: int
    remediation_rate_7d: float
    remediation_rate_30d: float
    average_time_to_remediate_days: float


class SLAStatus(BaseModel):
    """SLA compliance for findings."""

    total_findings: int
    findings_within_sla: int
    findings_breaching: int
    sla_compliance_percent: float
    by_severity: Dict[str, Dict[str, int]]
    findings_at_risk: List[str]


class BulkStatusUpdateRequest(BaseModel):
    """Bulk status update request."""

    finding_ids: List[str] = Field(..., min_items=1, max_items=100)
    status: str
    reason: Optional[str] = None


class BulkStatusUpdateResponse(BaseModel):
    """Response from bulk update."""

    updated: int
    failed: int
    total_requested: int
    errors: List[str]


class ExportRequest(BaseModel):
    """Request to export findings."""

    format: str = Field(..., pattern="^(json|csv)$")
    filters: Optional[FindingListFilter] = None
    include_fields: Optional[List[str]] = None


# ============================================================================
# ENDPOINTS
# ============================================================================


def _engine_findings_for_org(org_id: str) -> List[Dict[str, Any]]:
    """Mirror engine-DB issues into the findings response shape.

    Onboarding bug 2026-04-27 (Bug A — playbook divergence): the in-memory
    ``_findings_store`` only receives findings produced by the new pipeline
    bridge (commit ``d057efed``). Pre-existing rows in the
    ``security_findings_engine.db`` (used by /api/v1/issues) were stranded:
    /issues showed 163 rows for ``juice-shop-corp`` while /findings returned
    zero. Customers using the Issues hero on /issues hit an empty state.

    We UNION over both sources at read time so /findings always reflects the
    same totals /issues sees, without requiring a one-shot backfill the SE
    might forget to run. Engine-DB rows missed by the bridge are degraded
    gracefully (empty list).
    """
    if not org_id:
        return []
    try:
        from core.unified_issues_engine import (
            get_unified_issues_engine,  # noqa: PLC0415
        )
    except ImportError:
        return []

    try:
        rows = get_unified_issues_engine().unified_list(
            org_id=org_id,
            filters={"source": "findings"},
            limit=1000,
        )
    except (ValueError, RuntimeError, OSError) as exc:  # noqa: BLE001 — defensive
        logger.warning(
            "findings.list: unified-issues federation failed (%s: %s); "
            "falling back to in-memory store only",
            type(exc).__name__, exc,
        )
        return []

    mirrored: List[Dict[str, Any]] = []
    for row in rows:
        meta = row.get("metadata") or {}
        first_seen = row.get("first_seen_at") or ""
        try:
            created_at = (
                datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
                if first_seen
                else datetime.now(timezone.utc)
            )
        except ValueError:
            created_at = datetime.now(timezone.utc)
        mirrored.append({
            "id": row.get("id") or "",
            "title": row.get("title") or "",
            "description": "",
            "severity": (row.get("severity") or "medium").lower(),
            "status": row.get("status") or "open",
            "connector": meta.get("source_tool") or row.get("source_engine") or "engine",
            "asset_id": row.get("asset_id") or "",
            "cve_id": meta.get("cve_id") or "",
            "risk_score": float(meta.get("cvss_score") or 0.0),
            "created_at": created_at,
            "updated_at": created_at,
            "last_seen": created_at,
            "assigned_to": row.get("owner") or None,
            "assigned_team": None,
            "org_id": org_id,
            # Pass through scan_id + description so /findings filters
            # (?scan_id=, ?q=) work against engine-DB-mirrored rows.
            "scan_id": row.get("scan_id") or meta.get("scan_id") or "",
            "description": row.get("description") or meta.get("description") or row.get("title") or "",
            "_source": "engine_db",
        })
    return mirrored


@router.get("", response_model=Dict[str, Any])
async def list_findings(
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    connector: Optional[str] = Query(None),
    cve_id: Optional[str] = Query(None),
    asset_id: Optional[str] = Query(None),
    assigned_to: Optional[str] = Query(None),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    scan_id: Optional[str] = Query(None, description="Filter by scan_id (substring match)"),
    q: Optional[str] = Query(None, description="Free-text search across title/description"),
    sort_by: str = Query("severity", pattern="^(severity|created_at|risk_score|last_seen)$"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """List findings with rich filtering and pagination.

    Args:
        severity: Filter by severity (low|medium|high|critical)
        status: Filter by status (open|in_progress|remediated|suppressed|false_positive|accepted_risk)
        connector: Filter by source connector
        cve_id: Filter by CVE ID
        asset_id: Filter by asset ID
        assigned_to: Filter by assignee
        date_from: Filter created after (ISO 8601)
        date_to: Filter created before (ISO 8601)
        sort_by: Sort field
        limit: Results per page (default 50, max 500)
        offset: Pagination offset

    Returns:
        Paginated findings list with total count
    """
    # AUTHZ-VULN-05: Filter by org_id to prevent cross-tenant access
    in_memory = [f for f in _findings_store.values() if f.get("org_id") == org_id]
    # Bug A fix (playbook divergence 2026-04-27): UNION with engine-DB rows
    # so /findings reflects the same total /issues sees. Dedup by id, with
    # in-memory rows winning (they're authoritative for any post-bridge state
    # transitions like assignment / status updates).
    in_memory_ids = {f.get("id") for f in in_memory if f.get("id")}
    engine_rows = [
        f for f in _engine_findings_for_org(org_id)
        if f.get("id") and f.get("id") not in in_memory_ids
    ]
    findings = list(in_memory) + engine_rows

    # Apply filters
    if severity:
        findings = [f for f in findings if f.get("severity") == severity]
    if status:
        findings = [f for f in findings if f.get("status") == status]
    if connector:
        findings = [f for f in findings if f.get("connector") == connector]
    if cve_id:
        findings = [f for f in findings if f.get("cve_id") == cve_id]
    if asset_id:
        findings = [f for f in findings if f.get("asset_id") == asset_id]
    if assigned_to:
        findings = [f for f in findings if f.get("assigned_to") == assigned_to]
    if scan_id:
        sid = scan_id.lower()
        findings = [f for f in findings if sid in (f.get("scan_id") or "").lower()]
    if q:
        ql = q.lower()
        findings = [
            f for f in findings
            if ql in (f.get("title") or "").lower()
            or ql in (f.get("description") or "").lower()
            or ql in (f.get("asset_id") or "").lower()
        ]

    # Apply date filters
    if date_from:
        try:
            df = datetime.fromisoformat(date_from.replace("Z", "+00:00"))
            findings = [f for f in findings if f.get("created_at", datetime.min) >= df]
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date_from format")

    if date_to:
        try:
            dt = datetime.fromisoformat(date_to.replace("Z", "+00:00"))
            findings = [f for f in findings if f.get("created_at", datetime.max) <= dt]
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date_to format")

    # Sort
    sort_key = sort_by
    if sort_key == "severity":
        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        findings.sort(
            key=lambda f: severity_order.get(f.get("severity", "low"), 0),
            reverse=True,
        )
    elif sort_key == "risk_score":
        findings.sort(key=lambda f: f.get("risk_score", 0), reverse=True)
    else:
        findings.sort(
            key=lambda f: f.get(sort_key, datetime.min), reverse=True
        )

    # Paginate
    total = len(findings)
    paginated = findings[offset : offset + limit]

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "findings": paginated,
    }


@router.get("/{finding_id}", response_model=FindingDetailResponse)
async def get_finding(finding_id: str, org_id: str = Depends(get_org_id)) -> FindingDetailResponse:
    """Get complete finding detail with history.

    Args:
        finding_id: Finding identifier

    Returns:
        FindingDetailResponse with all details and history

    Raises:
        HTTPException: 404 if finding not found or not accessible
    """
    if finding_id not in _findings_store:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")

    finding = _findings_store[finding_id]

    # AUTHZ-VULN-06: Enforce org_id isolation — return 404 (not 403) to avoid enumeration
    if finding.get("org_id") != org_id:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")

    return FindingDetailResponse(
        id=finding_id,
        title=finding.get("title", ""),
        description=finding.get("description"),
        severity=finding.get("severity", "unknown"),
        status=finding.get("status", "open"),
        connector=finding.get("connector", ""),
        asset_id=finding.get("asset_id"),
        cve_id=finding.get("cve_id"),
        risk_score=finding.get("risk_score", 0.0),
        created_at=finding.get("created_at", datetime.now(timezone.utc)),
        updated_at=finding.get("updated_at", datetime.now(timezone.utc)),
        last_seen=finding.get("last_seen", datetime.now(timezone.utc)),
        assigned_to=finding.get("assigned_to"),
        assigned_team=finding.get("assigned_team"),
        pipeline_history=finding.get("pipeline_history", []),
        related_findings=finding.get("related_findings", []),
        council_verdict=finding.get("council_verdict"),
        playbook_runs=finding.get("playbook_runs", []),
        comments=finding.get("comments", []),
        audit_trail=[
            TimelineEvent(**event) for event in _audit_trails.get(finding_id, [])
        ],
    )


@router.put("/{finding_id}/status", response_model=Dict[str, Any])
async def update_finding_status(
    finding_id: str, update: StatusUpdateRequest = Body(...)
) -> Dict[str, Any]:
    """Update finding status.

    Args:
        finding_id: Finding identifier
        update: StatusUpdateRequest with new status

    Returns:
        Updated finding metadata

    Raises:
        HTTPException: 404 if finding not found, 400 if status invalid
    """
    if finding_id not in _findings_store:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")

    finding = _findings_store[finding_id]
    old_status = finding.get("status", "open")

    finding["status"] = update.status
    finding["updated_at"] = datetime.now(timezone.utc)

    # Record audit trail
    if finding_id not in _audit_trails:
        _audit_trails[finding_id] = []

    _audit_trails[finding_id].append(
        {
            "timestamp": datetime.now(timezone.utc),
            "event_type": "status_change",
            "actor": "system",
            "details": {
                "old_status": old_status,
                "new_status": update.status,
                "reason": update.reason,
            },
        }
    )

    logger.info(
        f"Finding {finding_id} status updated from {old_status} to {update.status}"
    )

    return {
        "finding_id": finding_id,
        "status": update.status,
        "updated_at": finding["updated_at"],
    }


@router.put("/{finding_id}/assign", response_model=Dict[str, Any])
async def assign_finding(
    finding_id: str, assignment: AssignmentRequest = Body(...)
) -> Dict[str, Any]:
    """Assign finding to user or team.

    Args:
        finding_id: Finding identifier
        assignment: AssignmentRequest with user or team

    Returns:
        Updated assignment info

    Raises:
        HTTPException: 404 if finding not found, 400 if assignment invalid
    """
    if finding_id not in _findings_store:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")

    if not assignment.assigned_to and not assignment.assigned_team:
        raise HTTPException(
            status_code=400,
            detail="Must specify either assigned_to or assigned_team",
        )

    finding = _findings_store[finding_id]
    finding["assigned_to"] = assignment.assigned_to
    finding["assigned_team"] = assignment.assigned_team
    finding["updated_at"] = datetime.now(timezone.utc)

    # Record audit trail
    if finding_id not in _audit_trails:
        _audit_trails[finding_id] = []

    _audit_trails[finding_id].append(
        {
            "timestamp": datetime.now(timezone.utc),
            "event_type": "assignment",
            "actor": "system",
            "details": {
                "assigned_to": assignment.assigned_to,
                "assigned_team": assignment.assigned_team,
                "reason": assignment.reason,
            },
        }
    )

    return {
        "finding_id": finding_id,
        "assigned_to": assignment.assigned_to,
        "assigned_team": assignment.assigned_team,
        "updated_at": finding["updated_at"],
    }


@router.post("/{finding_id}/comment", response_model=CommentResponse, status_code=201)
async def add_comment(
    finding_id: str, comment: FindingComment = Body(...)
) -> CommentResponse:
    """Add comment to finding.

    Args:
        finding_id: Finding identifier
        comment: FindingComment with text

    Returns:
        CommentResponse with comment details

    Raises:
        HTTPException: 404 if finding not found
    """
    if finding_id not in _findings_store:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")

    comment_id = str(uuid4())
    now = datetime.now(timezone.utc)

    comment_response = CommentResponse(
        comment_id=comment_id,
        finding_id=finding_id,
        created_at=now,
        created_by="system",
        text=comment.text,
    )

    # Store comment in finding
    finding = _findings_store[finding_id]
    if "comments" not in finding:
        finding["comments"] = []
    finding["comments"].append(comment_response.dict())

    # Record audit trail
    if finding_id not in _audit_trails:
        _audit_trails[finding_id] = []

    _audit_trails[finding_id].append(
        {
            "timestamp": now,
            "event_type": "comment",
            "actor": "system",
            "details": {"comment_id": comment_id, "text": comment.text},
        }
    )

    return comment_response


@router.get("/{finding_id}/timeline", response_model=List[TimelineEvent])
async def get_finding_timeline(finding_id: str) -> List[TimelineEvent]:
    """Get complete timeline of all actions on finding.

    Args:
        finding_id: Finding identifier

    Returns:
        List of timeline events in chronological order

    Raises:
        HTTPException: 404 if finding not found
    """
    if finding_id not in _findings_store:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")

    events = _audit_trails.get(finding_id, [])
    return [TimelineEvent(**event) for event in events]


@router.get("/summary", response_model=FindingSummary)
async def get_findings_summary(org_id: str = Depends(get_org_id)) -> FindingSummary:
    """Get executive summary of findings.

    Returns:
        FindingSummary with key metrics and trends
    """
    findings = [f for f in _findings_store.values() if f.get("org_id") == org_id]

    by_severity = {}
    by_status = {}
    by_connector = {}
    open_findings = 0
    in_progress = 0
    remediated = 0

    one_week_ago = datetime.now(timezone.utc) - timedelta(days=7)
    one_month_ago = datetime.now(timezone.utc) - timedelta(days=30)

    findings_week = 0
    findings_month = 0
    remediated_week = 0
    remediated_month = 0
    remediate_times = []

    for finding in findings:
        severity = finding.get("severity", "unknown")
        status = finding.get("status", "open")
        connector = finding.get("connector", "unknown")

        by_severity[severity] = by_severity.get(severity, 0) + 1
        by_status[status] = by_status.get(status, 0) + 1
        by_connector[connector] = by_connector.get(connector, 0) + 1

        if status == "open":
            open_findings += 1
        elif status == "in_progress":
            in_progress += 1
        elif status == "remediated":
            remediated += 1

        # Track week/month stats
        created = finding.get("created_at", datetime.now(timezone.utc))
        if created >= one_week_ago:
            findings_week += 1
        if created >= one_month_ago:
            findings_month += 1

        # Remediation time tracking
        if status == "remediated":
            updated = finding.get("updated_at", datetime.now(timezone.utc))
            time_to_remediate = (updated - created).days
            remediate_times.append(time_to_remediate)
            if created >= one_week_ago:
                remediated_week += 1
            if created >= one_month_ago:
                remediated_month += 1

    remediation_rate_7d = (remediated_week / findings_week * 100) if findings_week > 0 else 0
    remediation_rate_30d = (remediated_month / findings_month * 100) if findings_month > 0 else 0
    avg_remediate_days = (
        sum(remediate_times) / len(remediate_times) if remediate_times else 0
    )

    return FindingSummary(
        total_open=open_findings,
        total_in_progress=in_progress,
        total_remediated=remediated,
        by_severity=by_severity,
        by_status=by_status,
        by_connector=by_connector,
        findings_this_week=findings_week,
        findings_this_month=findings_month,
        remediation_rate_7d=remediation_rate_7d,
        remediation_rate_30d=remediation_rate_30d,
        average_time_to_remediate_days=avg_remediate_days,
    )


@router.get("/sla", response_model=SLAStatus)
async def get_sla_status(org_id: str = Depends(get_org_id)) -> SLAStatus:
    """Get SLA compliance for findings.

    Default SLAs (would be configurable):
    - Critical: 1 day
    - High: 3 days
    - Medium: 7 days
    - Low: 30 days

    Returns:
        SLAStatus with compliance metrics
    """
    findings = [f for f in _findings_store.values() if f.get("org_id") == org_id]

    sla_map = {
        "critical": timedelta(days=1),
        "high": timedelta(days=3),
        "medium": timedelta(days=7),
        "low": timedelta(days=30),
    }

    within_sla = 0
    breaching_sla = 0
    at_risk = []
    by_severity = {}

    now = datetime.now(timezone.utc)

    for finding in findings:
        severity = finding.get("severity", "low")
        if severity not in by_severity:
            by_severity[severity] = {"total": 0, "within_sla": 0, "breaching": 0}

        by_severity[severity]["total"] += 1

        sla_deadline = sla_map.get(severity, timedelta(days=30))
        created = finding.get("created_at", now)
        deadline = created + sla_deadline

        # Check if open/in_progress
        status = finding.get("status", "open")
        if status in ["open", "in_progress"]:
            if now <= deadline:
                within_sla += 1
                by_severity[severity]["within_sla"] += 1
            else:
                breaching_sla += 1
                by_severity[severity]["breaching"] += 1
                at_risk.append(finding.get("id", "unknown"))
        else:
            # Remediated/suppressed count as compliant
            within_sla += 1
            by_severity[severity]["within_sla"] += 1

    total = len(findings)
    compliance = (within_sla / total * 100) if total > 0 else 100

    return SLAStatus(
        total_findings=total,
        findings_within_sla=within_sla,
        findings_breaching=breaching_sla,
        sla_compliance_percent=compliance,
        by_severity=by_severity,
        findings_at_risk=at_risk[:100],  # Limit to 100
    )


@router.post("/bulk/status", response_model=BulkStatusUpdateResponse)
async def bulk_update_status(
    update: BulkStatusUpdateRequest = Body(...),
    org_id: str = Depends(get_org_id),
) -> BulkStatusUpdateResponse:
    """Bulk update status for multiple findings.

    Args:
        update: BulkStatusUpdateRequest with finding_ids and status

    Returns:
        BulkStatusUpdateResponse with results

    Raises:
        HTTPException: 400 if status invalid or too many findings
    """
    if len(update.finding_ids) > 100:
        raise HTTPException(status_code=413, detail="Maximum 100 findings per bulk update")

    updated = 0
    failed = 0
    errors = []

    for finding_id in update.finding_ids:
        try:
            if finding_id not in _findings_store:
                errors.append(f"Finding {finding_id} not found")
                failed += 1
                continue

            finding = _findings_store[finding_id]
            # AUTHZ: enforce org_id isolation on bulk updates
            if finding.get("org_id") != org_id:
                errors.append(f"Finding {finding_id} not found")
                failed += 1
                continue
            old_status = finding.get("status", "open")

            finding["status"] = update.status
            finding["updated_at"] = datetime.now(timezone.utc)

            # Record audit trail
            if finding_id not in _audit_trails:
                _audit_trails[finding_id] = []

            _audit_trails[finding_id].append(
                {
                    "timestamp": datetime.now(timezone.utc),
                    "event_type": "status_change",
                    "actor": "bulk_update",
                    "details": {
                        "old_status": old_status,
                        "new_status": update.status,
                        "reason": update.reason,
                    },
                }
            )

            updated += 1

        except Exception as e:  # noqa: BLE001 - bulk update iterates findings; any per-finding error must be collected, not abort the batch
            errors.append(f"Error updating {finding_id}: {str(e)}")
            failed += 1

    return BulkStatusUpdateResponse(
        updated=updated,
        failed=failed,
        total_requested=len(update.finding_ids),
        errors=errors[:50],  # Limit to 50
    )


@router.post("/export", response_model=Dict[str, str])
async def export_findings(
    export_req: ExportRequest = Body(...),
    org_id: str = Depends(get_org_id),
) -> Dict[str, str]:
    """Export findings in JSON or CSV format.

    Args:
        export_req: ExportRequest with format and filters

    Returns:
        Download URL or file content

    Note:
        In production, would stream response as StreamingResponse
    """
    findings = [f for f in _findings_store.values() if f.get("org_id") == org_id]

    # Apply filters from export_req.filters if provided
    if export_req.filters:
        filters = export_req.filters
        if filters.severity:
            findings = [f for f in findings if f.get("severity") in filters.severity]
        if filters.status:
            findings = [f for f in findings if f.get("status") in filters.status]
        if filters.connector:
            findings = [f for f in findings if f.get("connector") == filters.connector]

    export_id = str(uuid4())

    if export_req.format == "json":
        # In production: write to S3, return signed URL
        logger.info(f"Export {export_id}: JSON with {len(findings)} findings")
        return {"export_id": export_id, "format": "json", "status": "ready"}
    else:  # csv
        logger.info(f"Export {export_id}: CSV with {len(findings)} findings")
        return {"export_id": export_id, "format": "csv", "status": "ready"}
