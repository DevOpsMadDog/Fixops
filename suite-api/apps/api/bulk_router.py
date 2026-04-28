"""
Enterprise Bulk Operations API endpoints with async job support.

This module provides real bulk operations that interact with the DeduplicationService
for cluster management and external connectors for ticket creation.
"""

import logging
import os
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from core.analytics_db import AnalyticsDB
from core.analytics_models import FindingStatus
from core.connectors import (
    AzureDevOpsConnector,
    GitHubConnector,
    GitLabConnector,
    JiraConnector,
    ServiceNowConnector,
)
from core.integration_db import IntegrationDB
from core.integration_models import IntegrationType
from core.persistent_store import get_persistent_store
from core.policy_db import PolicyDB
from core.services.deduplication import ClusterStatus, DeduplicationService
from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/bulk", tags=["bulk"])

# Initialize services
_DATA_DIR = Path("data/deduplication")
_EXPORTS_DIR = Path("data/exports")
_EXPORTS_DIR.mkdir(parents=True, exist_ok=True)
_dedup_service: Optional[DeduplicationService] = None
_integration_db: Optional[IntegrationDB] = None
_analytics_db: Optional[AnalyticsDB] = None
_policy_db: Optional[PolicyDB] = None


def get_dedup_service() -> DeduplicationService:
    """Get or create deduplication service instance."""
    global _dedup_service
    if _dedup_service is None:
        _dedup_service = DeduplicationService(_DATA_DIR / "clusters.db")
    return _dedup_service


def get_integration_db() -> IntegrationDB:
    """Get or create integration database instance."""
    global _integration_db
    if _integration_db is None:
        _integration_db = IntegrationDB()
    return _integration_db


def get_analytics_db() -> AnalyticsDB:
    """Get or create analytics database instance."""
    global _analytics_db
    if _analytics_db is None:
        _analytics_db = AnalyticsDB()
    return _analytics_db


def get_policy_db() -> PolicyDB:
    """Get or create policy database instance."""
    global _policy_db
    if _policy_db is None:
        _policy_db = PolicyDB()
    return _policy_db


class JobStatus(str, Enum):
    """Status of a bulk job."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"
    CANCELLED = "cancelled"


def _is_job_cancelled(job_id: str) -> bool:
    """Check if job has been cancelled."""
    if job_id not in _jobs:
        return True
    return _jobs[job_id].get("cancel_requested", False)


class ActionType(str, Enum):
    """Types of bulk actions."""

    UPDATE_STATUS = "update_status"
    ASSIGN = "assign"
    CREATE_TICKETS = "create_tickets"
    ACCEPT_RISK = "accept_risk"
    EXPORT = "export"
    DELETE = "delete"


# Persistent job store — survives restarts
_jobs = get_persistent_store("bulk_jobs")


class BulkUpdateRequest(BaseModel):
    """Request model for bulk update operations."""

    ids: List[str] = Field(..., min_length=1)
    updates: Dict[str, Any]


class BulkDeleteRequest(BaseModel):
    """Request model for bulk delete operations."""

    ids: List[str] = Field(..., min_length=1)


class BulkAssignRequest(BaseModel):
    """Request model for bulk assign operations."""

    ids: List[str] = Field(..., min_length=1)
    assignee: str = Field(..., max_length=255)
    assignee_email: Optional[str] = Field(default=None, max_length=255)


_BULK_ALLOWED_STATUSES = frozenset({
    "open",
    "in_progress",
    "resolved",
    "false_positive",
    "accepted_risk",
    "wont_fix",
    "closed",
})


class BulkStatusUpdateRequest(BaseModel):
    """Request model for bulk status update."""

    ids: List[str] = Field(..., min_length=1)
    new_status: str = Field(..., max_length=64)
    reason: Optional[str] = Field(default=None, max_length=1000)
    changed_by: Optional[str] = Field(default=None, max_length=255)

    @field_validator("new_status")
    @classmethod
    def validate_new_status(cls, v: str) -> str:
        normalised = v.strip().lower()
        if normalised not in _BULK_ALLOWED_STATUSES:
            allowed = ", ".join(sorted(_BULK_ALLOWED_STATUSES))
            raise ValueError(f"new_status must be one of: {allowed}")
        return normalised


class BulkAcceptRiskRequest(BaseModel):
    """Request model for bulk accept risk."""

    ids: List[str] = Field(..., min_length=1)
    justification: str = Field(..., max_length=2000)
    approved_by: str = Field(..., max_length=255)
    expiry_days: Optional[int] = 90


class BulkCreateTicketsRequest(BaseModel):
    """Request model for bulk ticket creation."""

    ids: List[str] = Field(..., min_length=1)
    integration_id: str = Field(..., max_length=128)
    project_key: Optional[str] = Field(default=None, max_length=128)
    issue_type: str = Field(default="Bug", max_length=64)
    priority_mapping: Optional[Dict[str, str]] = None


class BulkExportRequest(BaseModel):
    """Request model for bulk export."""

    ids: List[str] = Field(..., min_length=1)
    format: str = Field(default="json", max_length=10)
    include_fields: Optional[List[str]] = None
    org_id: str = Field(..., max_length=128)


class BulkApplyPoliciesRequest(BaseModel):
    """Request model for bulk policy application."""

    policy_ids: List[str] = Field(..., min_length=1)
    target_ids: List[str] = Field(..., min_length=1)


class BulkOperationResponse(BaseModel):
    """Response model for bulk operations."""

    success_count: int
    failure_count: int
    errors: List[Dict[str, Any]] = Field(default_factory=list)


class JobResponse(BaseModel):
    """Response model for job creation."""

    job_id: str
    status: str
    total_items: int
    message: str


class JobStatusResponse(BaseModel):
    """Response model for job status."""

    job_id: str
    status: str
    action_type: str
    total_items: int
    processed_items: int
    success_count: int
    failure_count: int
    progress_percent: float
    started_at: str
    completed_at: Optional[str] = None
    results: Optional[List[Dict[str, Any]]] = None
    errors: List[Dict[str, Any]] = Field(default_factory=list)


def _create_job(action_type: str, total_items: int, metadata: Dict[str, Any]) -> str:
    """Create a new bulk job."""
    job_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    _jobs[job_id] = {
        "job_id": job_id,
        "status": JobStatus.PENDING.value,
        "action_type": action_type,
        "total_items": total_items,
        "processed_items": 0,
        "success_count": 0,
        "failure_count": 0,
        "progress_percent": 0.0,
        "started_at": now,
        "completed_at": None,
        "results": [],
        "errors": [],
        "metadata": metadata,
    }

    return job_id


def _update_job_progress(
    job_id: str,
    processed: int,
    success: int,
    failure: int,
    result: Optional[Dict[str, Any]] = None,
    error: Optional[Dict[str, Any]] = None,
):
    """Update job progress."""
    if job_id not in _jobs:
        return

    job = _jobs[job_id]
    job["processed_items"] = processed
    job["success_count"] = success
    job["failure_count"] = failure
    job["progress_percent"] = round((processed / job["total_items"]) * 100, 1)

    if result:
        job["results"].append(result)
    if error:
        job["errors"].append(error)
    _jobs.persist(job_id)


def _complete_job(job_id: str, status: str):
    """Mark job as complete. Does not overwrite terminal states."""
    if job_id not in _jobs:
        return

    job = _jobs[job_id]
    terminal_states = [
        JobStatus.COMPLETED.value,
        JobStatus.FAILED.value,
        JobStatus.PARTIAL.value,
        JobStatus.CANCELLED.value,
    ]
    if job["status"] in terminal_states:
        return

    job["status"] = status
    job["completed_at"] = datetime.now(timezone.utc).isoformat()
    _jobs.persist(job_id)


async def _process_bulk_status(
    job_id: str,
    ids: List[str],
    new_status: str,
    reason: Optional[str],
    changed_by: Optional[str] = None,
):
    """Process bulk status update in background using real DeduplicationService."""
    if _is_job_cancelled(job_id):
        return
    _jobs[job_id]["status"] = JobStatus.IN_PROGRESS.value
    _jobs.persist(job_id)
    success = 0
    failure = 0

    dedup_service = get_dedup_service()

    for i, cluster_id in enumerate(ids):
        if _is_job_cancelled(job_id):
            _complete_job(job_id, JobStatus.CANCELLED.value)
            return
        try:
            updated = dedup_service.update_cluster_status(
                cluster_id=cluster_id,
                new_status=new_status,
                changed_by=changed_by,
                reason=reason,
            )
            if updated:
                success += 1
                _update_job_progress(
                    job_id,
                    i + 1,
                    success,
                    failure,
                    result={
                        "id": cluster_id,
                        "status": "updated",
                        "new_status": new_status,
                    },
                )
            else:
                failure += 1
                _update_job_progress(
                    job_id,
                    i + 1,
                    success,
                    failure,
                    error={"id": cluster_id, "error": "Cluster not found"},
                )
        except ValueError as e:
            failure += 1
            _update_job_progress(
                job_id,
                i + 1,
                success,
                failure,
                error={"id": cluster_id, "error": type(e).__name__},
            )
        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as e:
            failure += 1
            logger.error(f"Failed to update cluster {cluster_id}: {e}")
            _update_job_progress(
                job_id,
                i + 1,
                success,
                failure,
                error={"id": cluster_id, "error": type(e).__name__},
            )

    final_status = (
        JobStatus.COMPLETED.value
        if failure == 0
        else (JobStatus.PARTIAL.value if success > 0 else JobStatus.FAILED.value)
    )
    _complete_job(job_id, final_status)


async def _process_bulk_assign(
    job_id: str, ids: List[str], assignee: str, assignee_email: Optional[str]
):
    """Process bulk assign in background using real DeduplicationService."""
    if _is_job_cancelled(job_id):
        return
    _jobs[job_id]["status"] = JobStatus.IN_PROGRESS.value
    _jobs.persist(job_id)
    success = 0
    failure = 0

    dedup_service = get_dedup_service()

    for i, cluster_id in enumerate(ids):
        if _is_job_cancelled(job_id):
            _complete_job(job_id, JobStatus.CANCELLED.value)
            return
        try:
            updated = dedup_service.assign_cluster(cluster_id, assignee)
            if updated:
                success += 1
                _update_job_progress(
                    job_id,
                    i + 1,
                    success,
                    failure,
                    result={
                        "id": cluster_id,
                        "status": "assigned",
                        "assignee": assignee,
                    },
                )
            else:
                failure += 1
                _update_job_progress(
                    job_id,
                    i + 1,
                    success,
                    failure,
                    error={"id": cluster_id, "error": "Cluster not found"},
                )
        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as e:
            failure += 1
            logger.error(f"Failed to assign cluster {cluster_id}: {e}")
            _update_job_progress(
                job_id,
                i + 1,
                success,
                failure,
                error={"id": cluster_id, "error": type(e).__name__},
            )

    final_status = (
        JobStatus.COMPLETED.value
        if failure == 0
        else (JobStatus.PARTIAL.value if success > 0 else JobStatus.FAILED.value)
    )
    _complete_job(job_id, final_status)


async def _process_bulk_accept_risk(
    job_id: str,
    ids: List[str],
    justification: str,
    approved_by: str,
    expiry_days: int,
):
    """Process bulk accept risk in background using real DeduplicationService.

    Sets cluster status to 'accepted_risk' with audit trail including
    justification and approval information.
    """
    if _is_job_cancelled(job_id):
        return
    _jobs[job_id]["status"] = JobStatus.IN_PROGRESS.value
    _jobs.persist(job_id)
    success = 0
    failure = 0

    dedup_service = get_dedup_service()

    for i, cluster_id in enumerate(ids):
        if _is_job_cancelled(job_id):
            _complete_job(job_id, JobStatus.CANCELLED.value)
            return
        try:
            reason = f"Risk accepted by {approved_by}. Justification: {justification}. Expires in {expiry_days} days."
            updated = dedup_service.update_cluster_status(
                cluster_id=cluster_id,
                new_status=ClusterStatus.ACCEPTED_RISK.value,
                changed_by=approved_by,
                reason=reason,
            )
            if updated:
                success += 1
                _update_job_progress(
                    job_id,
                    i + 1,
                    success,
                    failure,
                    result={
                        "id": cluster_id,
                        "status": "risk_accepted",
                        "approved_by": approved_by,
                        "expiry_days": expiry_days,
                    },
                )
            else:
                failure += 1
                _update_job_progress(
                    job_id,
                    i + 1,
                    success,
                    failure,
                    error={"id": cluster_id, "error": "Cluster not found"},
                )
        except ValueError as e:
            failure += 1
            _update_job_progress(
                job_id,
                i + 1,
                success,
                failure,
                error={"id": cluster_id, "error": type(e).__name__},
            )
        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as e:
            failure += 1
            logger.error(f"Failed to accept risk for cluster {cluster_id}: {e}")
            _update_job_progress(
                job_id,
                i + 1,
                success,
                failure,
                error={"id": cluster_id, "error": type(e).__name__},
            )

    final_status = (
        JobStatus.COMPLETED.value
        if failure == 0
        else (JobStatus.PARTIAL.value if success > 0 else JobStatus.FAILED.value)
    )
    _complete_job(job_id, final_status)


async def _process_bulk_tickets(
    job_id: str,
    ids: List[str],
    integration_id: str,
    project_key: Optional[str],
    issue_type: str,
):
    """Process bulk ticket creation in background using real connectors.

    Creates tickets in external systems (Jira, ServiceNow, GitLab, GitHub, Azure DevOps)
    based on the integration configuration and links them to clusters.
    """
    if _is_job_cancelled(job_id):
        return
    _jobs[job_id]["status"] = JobStatus.IN_PROGRESS.value
    _jobs.persist(job_id)
    success = 0
    failure = 0

    integration_db = get_integration_db()
    dedup_service = get_dedup_service()

    integration = integration_db.get_integration(integration_id)
    if not integration:
        _jobs[job_id]["errors"].append(
            {"error": f"Integration {integration_id} not found"}
        )
        _complete_job(job_id, JobStatus.FAILED.value)
        return

    connector_type = integration.integration_type
    connector: Union[
        JiraConnector,
        ServiceNowConnector,
        GitLabConnector,
        GitHubConnector,
        AzureDevOpsConnector,
    ]

    if connector_type == IntegrationType.JIRA:
        connector = JiraConnector(integration.config)
    elif connector_type == IntegrationType.SERVICENOW:
        connector = ServiceNowConnector(integration.config)
    elif connector_type == IntegrationType.GITLAB:
        connector = GitLabConnector(integration.config)
    elif connector_type == IntegrationType.GITHUB:
        connector = GitHubConnector(integration.config)
    elif connector_type == IntegrationType.AZURE_DEVOPS:
        connector = AzureDevOpsConnector(integration.config)
    else:
        _jobs[job_id]["errors"].append(
            {"error": f"Unsupported integration type: {connector_type.value}"}
        )
        _complete_job(job_id, JobStatus.FAILED.value)
        return

    if not connector.configured:
        _jobs[job_id]["errors"].append(
            {"error": f"Integration {integration_id} is not fully configured"}
        )
        _complete_job(job_id, JobStatus.FAILED.value)
        return

    for i, cluster_id in enumerate(ids):
        if _is_job_cancelled(job_id):
            _complete_job(job_id, JobStatus.CANCELLED.value)
            return
        try:
            cluster = dedup_service.get_cluster(cluster_id)
            if not cluster:
                failure += 1
                _update_job_progress(
                    job_id,
                    i + 1,
                    success,
                    failure,
                    error={"id": cluster_id, "error": "Cluster not found"},
                )
                continue

            summary = cluster.get("title") or f"Security Finding: {cluster_id}"
            description = (
                f"Cluster ID: {cluster_id}\n"
                f"Severity: {cluster.get('severity', 'unknown')}\n"
                f"Category: {cluster.get('category', 'unknown')}\n"
                f"CVE: {cluster.get('cve_id', 'N/A')}\n"
                f"First Seen: {cluster.get('first_seen', 'unknown')}\n"
                f"Occurrences: {cluster.get('occurrence_count', 1)}"
            )

            action = {
                "summary": summary,
                "description": description,
                "issue_type": issue_type,
                "priority": _severity_to_priority(cluster.get("severity", "medium")),
            }
            if project_key:
                action["project_key"] = project_key

            outcome = None
            # Use connector_type for dispatch since connector is already assigned
            # based on connector_type above. Type narrowing is guaranteed by the
            # if/elif chain that assigns connector.
            if connector_type == IntegrationType.JIRA:
                outcome = connector.create_issue(action)  # type: ignore[union-attr]
            elif connector_type == IntegrationType.SERVICENOW:
                outcome = connector.create_incident(action)  # type: ignore[union-attr]
            elif connector_type == IntegrationType.GITLAB:
                outcome = connector.create_issue(action)  # type: ignore[union-attr]
            elif connector_type == IntegrationType.GITHUB:
                outcome = connector.create_issue(action)  # type: ignore[union-attr]
            elif connector_type == IntegrationType.AZURE_DEVOPS:
                outcome = connector.create_work_item(action)  # type: ignore[union-attr]

            if outcome and outcome.success:
                ticket_id = (
                    outcome.details.get("issue_key")
                    or outcome.details.get("issue_id")
                    or outcome.details.get("number")
                    or outcome.details.get("id")
                )
                ticket_url = outcome.details.get("url") or outcome.details.get(
                    "endpoint"
                )

                dedup_service.link_to_ticket(cluster_id, str(ticket_id), ticket_url)

                success += 1
                _update_job_progress(
                    job_id,
                    i + 1,
                    success,
                    failure,
                    result={
                        "id": cluster_id,
                        "status": "ticket_created",
                        "ticket_id": ticket_id,
                        "ticket_url": ticket_url,
                        "integration_id": integration_id,
                    },
                )
            else:
                error_msg = (
                    outcome.details.get("reason", "Unknown error")
                    if outcome
                    else "Connector returned no outcome"
                )
                failure += 1
                _update_job_progress(
                    job_id,
                    i + 1,
                    success,
                    failure,
                    error={"id": cluster_id, "error": error_msg},
                )
        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as e:
            failure += 1
            logger.error(f"Failed to create ticket for cluster {cluster_id}: {e}")
            _update_job_progress(
                job_id,
                i + 1,
                success,
                failure,
                error={"id": cluster_id, "error": type(e).__name__},
            )

    final_status = (
        JobStatus.COMPLETED.value
        if failure == 0
        else (JobStatus.PARTIAL.value if success > 0 else JobStatus.FAILED.value)
    )
    _complete_job(job_id, final_status)


def _severity_to_priority(severity: str) -> str:
    """Map severity to ticket priority."""
    mapping = {
        "critical": "Highest",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Lowest",
    }
    return mapping.get(severity.lower(), "Medium")


async def _process_bulk_export(
    job_id: str,
    ids: List[str],
    fmt: str,
    org_id: str,
    include_fields: Optional[List[str]],
):
    """Process bulk export in background — creates a real file on disk."""
    import csv
    import io
    import json as _json

    if _is_job_cancelled(job_id):
        return
    _jobs[job_id]["status"] = JobStatus.IN_PROGRESS.value
    _jobs.persist(job_id)

    try:
        db = get_analytics_db()
        findings_data: List[Dict[str, Any]] = []

        for idx, fid in enumerate(ids):
            if _is_job_cancelled(job_id):
                _complete_job(job_id, JobStatus.CANCELLED.value)
                return

            finding = db.get_finding(fid)
            if finding is None:
                _jobs[job_id]["errors"].append(
                    {"id": fid, "error": "Finding not found"}
                )
                _jobs[job_id]["failure_count"] = (
                    _jobs[job_id].get("failure_count", 0) + 1
                )
                _jobs.persist(job_id)
                continue

            record: Dict[str, Any] = {
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity.value,
                "status": finding.status.value,
                "source": finding.source,
                "rule_id": finding.rule_id,
                "cve_id": finding.cve_id,
                "cvss_score": finding.cvss_score,
                "epss_score": finding.epss_score,
                "exploitable": finding.exploitable,
                "description": finding.description,
                "created_at": finding.created_at.isoformat(),
                "updated_at": finding.updated_at.isoformat(),
            }
            if include_fields:
                record = {k: v for k, v in record.items() if k in include_fields}
            findings_data.append(record)

            _jobs[job_id]["processed_items"] = idx + 1
            _jobs[job_id]["progress_percent"] = round((idx + 1) / len(ids) * 100, 1)
            _jobs.persist(job_id)

        export_id = str(uuid.uuid4())[:8]
        filename = f"{export_id}.{fmt}"
        filepath = _EXPORTS_DIR / filename

        if fmt == "json":
            filepath.write_text(
                _json.dumps(
                    {
                        "org_id": org_id,
                        "findings": findings_data,
                        "count": len(findings_data),
                    },
                    indent=2,
                )
            )
        elif fmt == "csv":
            if findings_data:
                buf = io.StringIO()
                writer = csv.DictWriter(buf, fieldnames=findings_data[0].keys())
                writer.writeheader()
                writer.writerows(findings_data)
                filepath.write_text(buf.getvalue())
            else:
                filepath.write_text("")
        elif fmt == "sarif":
            sarif = {
                "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "FixOps", "version": "1.0.0"}},
                        "results": [
                            {
                                "ruleId": f.get("rule_id", ""),
                                "level": "error"
                                if f.get("severity") in ("critical", "high")
                                else "warning",
                                "message": {"text": f.get("title", "")},
                            }
                            for f in findings_data
                        ],
                    }
                ],
            }
            filepath.write_text(_json.dumps(sarif, indent=2))
        else:
            filepath.write_text(_json.dumps(findings_data, indent=2))

        file_size = filepath.stat().st_size
        download_url = f"/api/v1/bulk/exports/{filename}"

        _jobs[job_id]["results"] = [
            {
                "export_id": export_id,
                "format": fmt,
                "item_count": len(findings_data),
                "file_size": file_size,
                "download_url": download_url,
            }
        ]
        _jobs[job_id]["success_count"] = len(findings_data)
        _jobs[job_id]["progress_percent"] = 100.0
        _complete_job(job_id, JobStatus.COMPLETED.value)
        logger.info(
            "Export %s completed: %d findings → %s (%d bytes)",
            export_id,
            len(findings_data),
            filepath,
            file_size,
        )
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        logger.exception("Export job %s failed", job_id)
        _jobs[job_id]["errors"].append({"error": type(e).__name__})
        _complete_job(job_id, JobStatus.FAILED.value)


@router.post("/clusters/status", response_model=JobResponse)
async def bulk_update_cluster_status(
    request: BulkStatusUpdateRequest, background_tasks: BackgroundTasks
):
    """Bulk update cluster status."""
    job_id = _create_job(
        ActionType.UPDATE_STATUS.value,
        len(request.ids),
        {"new_status": request.new_status, "reason": request.reason},
    )

    background_tasks.add_task(
        _process_bulk_status,
        job_id,
        request.ids,
        request.new_status,
        request.reason,
        request.changed_by,
    )

    return JobResponse(
        job_id=job_id,
        status=JobStatus.PENDING.value,
        total_items=len(request.ids),
        message=f"Bulk status update job created for {len(request.ids)} items",
    )


@router.post("/clusters/assign", response_model=JobResponse)
async def bulk_assign_clusters(
    request: BulkAssignRequest, background_tasks: BackgroundTasks
):
    """Bulk assign clusters to a user."""
    job_id = _create_job(
        ActionType.ASSIGN.value,
        len(request.ids),
        {"assignee": request.assignee},
    )

    background_tasks.add_task(
        _process_bulk_assign,
        job_id,
        request.ids,
        request.assignee,
        request.assignee_email,
    )

    return JobResponse(
        job_id=job_id,
        status=JobStatus.PENDING.value,
        total_items=len(request.ids),
        message=f"Bulk assign job created for {len(request.ids)} items",
    )


@router.post("/clusters/accept-risk", response_model=JobResponse)
async def bulk_accept_risk(
    request: BulkAcceptRiskRequest, background_tasks: BackgroundTasks
):
    """Bulk accept risk for clusters."""
    job_id = _create_job(
        ActionType.ACCEPT_RISK.value,
        len(request.ids),
        {"approved_by": request.approved_by, "expiry_days": request.expiry_days},
    )

    background_tasks.add_task(
        _process_bulk_accept_risk,
        job_id,
        request.ids,
        request.justification,
        request.approved_by,
        request.expiry_days or 90,
    )

    return JobResponse(
        job_id=job_id,
        status=JobStatus.PENDING.value,
        total_items=len(request.ids),
        message=f"Bulk accept risk job created for {len(request.ids)} items",
    )


@router.post("/clusters/create-tickets", response_model=JobResponse)
async def bulk_create_tickets(
    request: BulkCreateTicketsRequest, background_tasks: BackgroundTasks
):
    """Bulk create tickets for clusters."""
    job_id = _create_job(
        ActionType.CREATE_TICKETS.value,
        len(request.ids),
        {"integration_id": request.integration_id, "issue_type": request.issue_type},
    )

    background_tasks.add_task(
        _process_bulk_tickets,
        job_id,
        request.ids,
        request.integration_id,
        request.project_key,
        request.issue_type,
    )

    return JobResponse(
        job_id=job_id,
        status=JobStatus.PENDING.value,
        total_items=len(request.ids),
        message=f"Bulk ticket creation job created for {len(request.ids)} items",
    )


@router.post("/export", response_model=JobResponse)
async def bulk_export(request: BulkExportRequest, background_tasks: BackgroundTasks):
    """Bulk export findings/clusters in specified format."""
    if request.format not in ["json", "csv", "sarif", "pdf"]:
        raise HTTPException(
            status_code=400,
            detail="Invalid format. Must be one of: json, csv, sarif, pdf",
        )

    job_id = _create_job(
        ActionType.EXPORT.value,
        len(request.ids),
        {"format": request.format, "org_id": request.org_id},
    )

    background_tasks.add_task(
        _process_bulk_export,
        job_id,
        request.ids,
        request.format,
        request.org_id,
        request.include_fields,
    )

    return JobResponse(
        job_id=job_id,
        status=JobStatus.PENDING.value,
        total_items=len(request.ids),
        message=f"Bulk export job created for {len(request.ids)} items",
    )


@router.get("/exports/{filename}")
async def download_export(filename: str):
    """Download an export file produced by /export."""
    from fastapi.responses import FileResponse

    # Reject path traversal attempts before any path construction.
    # Check for directory separators and parent-directory sequences in the
    # raw string so that encoded variants (e.g. %2F) handled by the framework
    # are also caught after URL decoding.
    if ".." in filename or "/" in filename or "\\" in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")

    # Allow only known safe extensions produced by the export job.
    _ALLOWED_EXTENSIONS = {".json", ".csv", ".sarif"}
    suffix = Path(filename).suffix.lower()
    if suffix not in _ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail="Invalid file extension")

    filepath = _EXPORTS_DIR / filename

    # Resolve symlinks and verify the canonical path stays inside _EXPORTS_DIR.
    # This is a defence-in-depth check against any edge case not caught above.
    try:
        resolved = filepath.resolve()
        exports_resolved = _EXPORTS_DIR.resolve()
        resolved.relative_to(exports_resolved)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid filename")

    if not filepath.exists():
        raise HTTPException(status_code=404, detail="Export file not found")

    media = "application/json"
    if suffix == ".csv":
        media = "text/csv"
    elif suffix == ".sarif":
        media = "application/sarif+json"
    return FileResponse(path=str(filepath), media_type=media, filename=filename)


@router.get("/jobs/{job_id}", response_model=JobStatusResponse)
async def get_job_status(job_id: str):
    """Get status of a bulk job."""
    if job_id not in _jobs:
        raise HTTPException(status_code=404, detail="Job not found")

    job = _jobs[job_id]
    return JobStatusResponse(
        job_id=job["job_id"],
        status=job["status"],
        action_type=job["action_type"],
        total_items=job["total_items"],
        processed_items=job["processed_items"],
        success_count=job["success_count"],
        failure_count=job["failure_count"],
        progress_percent=job["progress_percent"],
        started_at=job["started_at"],
        completed_at=job["completed_at"],
        results=(
            job["results"]
            if job["status"]
            in [
                JobStatus.COMPLETED.value,
                JobStatus.PARTIAL.value,
                JobStatus.CANCELLED.value,
            ]
            else None
        ),
        errors=job["errors"],
    )


@router.get("/jobs")
async def list_jobs(
    status: Optional[str] = None,
    action_type: Optional[str] = None,
    limit: int = Query(default=20, le=100),
) -> Dict[str, Any]:
    """List bulk jobs with optional filters."""
    jobs = list(_jobs.values())

    if status:
        jobs = [j for j in jobs if j["status"] == status]
    if action_type:
        jobs = [j for j in jobs if j["action_type"] == action_type]

    jobs.sort(key=lambda x: x["started_at"], reverse=True)

    return {
        "jobs": jobs[:limit],
        "count": len(jobs[:limit]),
        "total": len(jobs),
    }


@router.delete("/jobs/{job_id}")
async def cancel_job(job_id: str) -> Dict[str, Any]:
    """Cancel a pending or in-progress job."""
    if job_id not in _jobs:
        raise HTTPException(status_code=404, detail="Job not found")

    job = _jobs[job_id]
    terminal_states = [
        JobStatus.COMPLETED.value,
        JobStatus.FAILED.value,
        JobStatus.PARTIAL.value,
        JobStatus.CANCELLED.value,
    ]
    if job["status"] in terminal_states:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot cancel job with status: {job['status']}",
        )

    job["cancel_requested"] = True
    job["errors"].append({"error": "Job cancelled by user"})

    if job["status"] == JobStatus.PENDING.value:
        job["status"] = JobStatus.CANCELLED.value
        job["completed_at"] = datetime.now(timezone.utc).isoformat()

    _jobs.persist(job_id)
    return {"status": "cancelled", "job_id": job_id}


# ── Legacy endpoints wired to real AnalyticsDB / PolicyDB ──────────────


@router.post("/findings/update", response_model=BulkOperationResponse)
async def bulk_update_findings(request: BulkUpdateRequest):
    """Bulk update findings in AnalyticsDB.

    Supported update fields: status, metadata (merged).
    """
    db = get_analytics_db()
    success = 0
    errors: List[Dict[str, Any]] = []

    for finding_id in request.ids:
        try:
            finding = db.get_finding(finding_id)
            if finding is None:
                errors.append({"id": finding_id, "error": "Finding not found"})
                continue

            # Apply supported updates
            if "status" in request.updates:
                finding.status = FindingStatus(request.updates["status"])
            if "metadata" in request.updates and isinstance(
                request.updates["metadata"], dict
            ):
                finding.metadata.update(request.updates["metadata"])
            if "resolved_at" in request.updates:
                from datetime import datetime as _dt

                finding.resolved_at = _dt.fromisoformat(request.updates["resolved_at"])

            db.update_finding(finding)
            success += 1
        except ImportError as e:
            errors.append({"id": finding_id, "error": type(e).__name__})

    return BulkOperationResponse(
        success_count=success,
        failure_count=len(errors),
        errors=errors,
    )


@router.post("/findings/delete", response_model=BulkOperationResponse)
async def bulk_delete_findings(request: BulkDeleteRequest):
    """Bulk delete findings from AnalyticsDB."""
    db = get_analytics_db()
    success = 0
    errors: List[Dict[str, Any]] = []

    for finding_id in request.ids:
        try:
            deleted = db.delete_finding(finding_id)
            if deleted:
                success += 1
            else:
                errors.append({"id": finding_id, "error": "Finding not found"})
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            errors.append({"id": finding_id, "error": type(e).__name__})

    return BulkOperationResponse(
        success_count=success,
        failure_count=len(errors),
        errors=errors,
    )


@router.post("/findings/assign", response_model=BulkOperationResponse)
async def bulk_assign_findings(request: BulkAssignRequest):
    """Bulk assign findings to a user via AnalyticsDB metadata update."""
    db = get_analytics_db()
    success = 0
    errors: List[Dict[str, Any]] = []

    for finding_id in request.ids:
        try:
            finding = db.get_finding(finding_id)
            if finding is None:
                errors.append({"id": finding_id, "error": "Finding not found"})
                continue

            finding.metadata["assignee"] = request.assignee
            if request.assignee_email:
                finding.metadata["assignee_email"] = request.assignee_email
            finding.metadata["assigned_at"] = datetime.now(timezone.utc).isoformat()

            db.update_finding(finding)
            success += 1
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            errors.append({"id": finding_id, "error": type(e).__name__})

    return BulkOperationResponse(
        success_count=success,
        failure_count=len(errors),
        errors=errors,
    )


@router.post("/policies/apply", response_model=BulkOperationResponse)
async def bulk_apply_policies(request: BulkApplyPoliciesRequest):
    """Bulk apply policies to target findings.

    For each (policy, finding) pair the policy rules are evaluated and the
    result is stored in the finding's metadata under ``applied_policies``.
    """
    pdb = get_policy_db()
    adb = get_analytics_db()
    success = 0
    errors: List[Dict[str, Any]] = []

    # Pre-fetch policies
    policies = {}
    for pid in request.policy_ids:
        policy = pdb.get_policy(pid)
        if policy is None:
            errors.append({"policy_id": pid, "error": "Policy not found"})
        else:
            policies[pid] = policy

    if not policies:
        return BulkOperationResponse(
            success_count=0,
            failure_count=len(errors),
            errors=errors,
        )

    for finding_id in request.target_ids:
        try:
            finding = adb.get_finding(finding_id)
            if finding is None:
                errors.append({"id": finding_id, "error": "Finding not found"})
                continue

            applied: List[Dict[str, Any]] = finding.metadata.get("applied_policies", [])
            for pid, policy in policies.items():
                applied.append(
                    {
                        "policy_id": pid,
                        "policy_name": policy.name,
                        "policy_type": policy.policy_type,
                        "applied_at": datetime.now(timezone.utc).isoformat(),
                        "rules": policy.rules,
                    }
                )
            finding.metadata["applied_policies"] = applied

            adb.update_finding(finding)
            success += 1
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            errors.append({"id": finding_id, "error": type(e).__name__})

    return BulkOperationResponse(
        success_count=success,
        failure_count=len(errors),
        errors=errors,
    )


@router.get("/status")
async def bulk_status():
    """Bulk operations status — running jobs, completed, failed."""
    jobs: list = []
    try:
        import glob
        import json as _json
        job_dir = os.path.join(os.path.dirname(__file__), "..", "..", "data", "bulk_jobs")
        if os.path.isdir(job_dir):
            for fp in sorted(glob.glob(os.path.join(job_dir, "*.json")))[-50:]:
                with open(fp) as fh:
                    jobs.append(_json.load(fh))
    except ImportError:
        pass

    running = sum(1 for j in jobs if j.get("status") == "running")
    completed = sum(1 for j in jobs if j.get("status") in ("completed", "done"))
    failed = sum(1 for j in jobs if j.get("status") == "failed")

    return {
        "status": "ok",
        "running": running,
        "completed": completed,
        "failed": failed,
        "total_jobs": len(jobs),
        "recent_jobs": jobs[-10:] if jobs else [],
    }
