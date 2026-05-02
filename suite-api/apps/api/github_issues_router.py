"""
ALDECI GitHub Issues Integration API Router.

Provides REST endpoints for creating, listing, syncing, and querying
GitHub Issues as an ALM/ticketing system for security findings.

All operations use the authenticated `gh` CLI — real GitHub API calls.

Endpoints:
  POST /api/v1/github/issues/create   — Create GitHub issue from a finding
  GET  /api/v1/github/issues          — List ALDECI-created issues
  POST /api/v1/github/issues/sync     — Bidirectional sync
  GET  /api/v1/github/issues/metrics  — Aggregate metrics
  POST /api/v1/github/issues/update   — Add comment to an existing issue
  GET  /api/v1/github/issues/search   — Search for an issue by title
  GET  /api/v1/github/issues/auth     — Check gh CLI auth status
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/github/issues",
    tags=["github-issues"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Lazy singleton
# ---------------------------------------------------------------------------


def _get_client():
    from core.github_issues_integration import get_github_issues_client
    return get_github_issues_client()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class FindingRequest(BaseModel):
    """A finding to create or sync as a GitHub issue."""

    finding_id: str = Field(..., description="Unique finding identifier")
    title: str = Field(..., description="Short finding title")
    severity: str = Field(..., description="critical | high | medium | low | informational")
    finding_type: str = Field("sast", description="sast | dast | sca | iac | secret | cloud | network")
    description: str = Field("", description="Full finding description (Markdown)")
    cwe: Optional[str] = Field(None, description="CWE identifier, e.g. 'CWE-79'")
    cvss: Optional[float] = Field(None, description="CVSS score, e.g. 9.8")
    affected_file: Optional[str] = Field(None, description="Source file path")
    affected_line: Optional[int] = Field(None, description="Line number in affected file")
    remediation: Optional[str] = Field(None, description="Remediation guidance (Markdown)")
    scanner: Optional[str] = Field(None, description="Scanner that found this (semgrep, trivy, etc.)")
    cve_id: Optional[str] = Field(None, description="CVE identifier, e.g. 'CVE-2024-1234'")
    status: str = Field("open", description="open | resolved | in_progress | accepted_risk")
    extra: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class CreateIssueRequest(BaseModel):
    """Create a GitHub issue from a finding."""

    finding: FindingRequest
    assignee: Optional[str] = Field(None, description="GitHub username to assign")
    extra_labels: List[str] = Field(default_factory=list, description="Additional labels")


class UpdateIssueRequest(BaseModel):
    """Add a comment to a GitHub issue."""

    finding_id: str = Field(..., description="Finding identifier (used to look up issue number)")
    comment: str = Field(..., description="Markdown comment body")
    issue_number: Optional[int] = Field(None, description="Override issue number if not linked")


class SyncRequest(BaseModel):
    """Bidirectional sync request."""

    findings: List[FindingRequest] = Field(
        default_factory=list,
        description="Findings to push to GitHub. Leave empty for GitHub→ALDECI pull only.",
    )
    direction: str = Field(
        "both",
        description="'to_github' | 'from_github' | 'both'",
    )
    dry_run: bool = Field(False, description="Log without making API calls")


class SyncResultItem(BaseModel):
    success: bool
    action: str
    finding_id: str
    issue_number: Optional[int] = None
    issue_url: Optional[str] = None
    detail: str = ""
    error: Optional[str] = None


class SyncResponse(BaseModel):
    total: int
    succeeded: int
    failed: int
    push_results: List[SyncResultItem] = []
    pull_results: List[Dict[str, Any]] = []


class GitHubIssueItem(BaseModel):
    number: int
    title: str
    state: str
    url: str
    labels: List[str]
    assignees: List[str]
    created_at: str
    updated_at: str
    closed_at: Optional[str] = None


class MetricsResponse(BaseModel):
    total_created: int
    total_open: int
    total_closed: int
    avg_time_to_close_hours: float
    by_severity: Dict[str, int]
    by_type: Dict[str, int]
    by_state: Dict[str, int]


class AuthStatusResponse(BaseModel):
    available: bool
    authenticated: bool
    gh_bin: Optional[str] = None
    username: Optional[str] = None
    repo: Optional[str] = None
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _to_finding(req: FindingRequest):
    from core.github_issues_integration import Finding
    return Finding(
        finding_id=req.finding_id,
        title=req.title,
        severity=req.severity,
        finding_type=req.finding_type,
        description=req.description,
        cwe=req.cwe,
        cvss=req.cvss,
        affected_file=req.affected_file,
        affected_line=req.affected_line,
        remediation=req.remediation,
        scanner=req.scanner,
        cve_id=req.cve_id,
        status=req.status,
        extra=req.extra,
    )


def _result_to_model(result) -> SyncResultItem:
    return SyncResultItem(
        success=result.success,
        action=result.action,
        finding_id=result.finding_id,
        issue_number=result.issue_number,
        issue_url=result.issue_url,
        detail=result.detail,
        error=result.error,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/create",
    response_model=SyncResultItem,
    summary="Create a GitHub issue from a security finding",
)
def create_issue(req: CreateIssueRequest):
    """
    Create a real GitHub Issue for the given ALDECI finding.

    Uses `gh issue create` under the hood. Deduplicates: if an issue
    already exists for this ``finding_id``, the existing link is returned
    instead of creating a duplicate.

    Labels applied automatically:
    - ``aldeci`` (always)
    - Severity label (critical / high / medium / low / informational)
    - Type label (sast / dast / sca / iac / secret / cloud / network)
    - Any extra labels specified in the request
    """
    client = _get_client()
    finding = _to_finding(req.finding)
    try:
        result = client.create_issue_from_finding(
            finding,
            assignee=req.assignee,
            extra_labels=req.extra_labels or None,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    if not result.success and result.action == "error":
        raise HTTPException(status_code=502, detail=result.error or "GitHub API error")

    return _result_to_model(result)


@router.get(
    "",
    response_model=List[GitHubIssueItem],
    summary="List ALDECI-created GitHub issues",
)
def list_issues(
    state: str = Query("open", description="open | closed | all"),
    limit: int = Query(50, ge=1, le=200, description="Max issues to return"),
    label: Optional[str] = Query(None, description="Extra label filter (default: 'aldeci')"),
):
    """
    List GitHub Issues created by ALDECI.

    All ALDECI issues are tagged with the ``aldeci`` label. Supports
    filtering by state and optional additional label.
    """
    client = _get_client()
    try:
        issues = client.list_issues(state=state, limit=limit, label=label)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    return [
        GitHubIssueItem(
            number=i.number,
            title=i.title,
            state=i.state,
            url=i.url,
            labels=i.labels,
            assignees=i.assignees,
            created_at=i.created_at,
            updated_at=i.updated_at,
            closed_at=i.closed_at,
        )
        for i in issues
    ]


@router.post(
    "/sync",
    response_model=SyncResponse,
    summary="Bidirectional sync between ALDECI findings and GitHub Issues",
)
def sync_issues(req: SyncRequest):
    """
    Bidirectional sync:

    - **to_github** — push finding status changes (close/reopen issues)
    - **from_github** — pull closed GitHub issues and return findings to resolve
    - **both** — do both directions

    Set ``dry_run=true`` to preview without making API calls.
    """
    client = _get_client()
    push_results: List[SyncResultItem] = []
    pull_results: List[Dict[str, Any]] = []

    direction = req.direction.lower()

    if direction in ("to_github", "both") and req.findings:
        findings = [_to_finding(f) for f in req.findings]
        try:
            raw_results = client.sync_all_findings(findings, dry_run=req.dry_run)
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail=str(exc))
        push_results = [_result_to_model(r) for r in raw_results]

    if direction in ("from_github", "both"):
        try:
            pull_results = client.sync_github_to_findings()
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail=str(exc))

    total = len(push_results)
    succeeded = sum(1 for r in push_results if r.success)
    failed = total - succeeded

    return SyncResponse(
        total=total,
        succeeded=succeeded,
        failed=failed,
        push_results=push_results,
        pull_results=pull_results,
    )


@router.get(
    "/metrics",
    response_model=MetricsResponse,
    summary="Aggregate metrics for ALDECI GitHub Issues",
)
def get_metrics():
    """
    Return aggregate metrics for all ALDECI-created GitHub Issues:

    - Total created / open / closed
    - Average time to close (hours)
    - Breakdown by severity and finding type
    """
    client = _get_client()
    m = client.get_metrics()
    return MetricsResponse(
        total_created=m.total_created,
        total_open=m.total_open,
        total_closed=m.total_closed,
        avg_time_to_close_hours=m.avg_time_to_close_hours,
        by_severity=m.by_severity,
        by_type=m.by_type,
        by_state=m.by_state,
    )


@router.post(
    "/update",
    response_model=SyncResultItem,
    summary="Add a comment to an existing GitHub issue",
)
def update_issue(req: UpdateIssueRequest):
    """
    Add a Markdown comment to the GitHub issue linked to the given finding.

    Useful for recording scan re-runs, SLA escalations, or status transitions.
    """
    client = _get_client()
    try:
        result = client.update_issue(
            req.finding_id,
            req.comment,
            issue_number=req.issue_number,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    if not result.success:
        raise HTTPException(status_code=502, detail=result.error or "Update failed")

    return _result_to_model(result)


@router.get(
    "/search",
    response_model=Optional[GitHubIssueItem],
    summary="Search for a GitHub issue by finding title (dedup check)",
)
def search_issue(
    title: str = Query(..., description="Finding title substring to search for"),
):
    """
    Search ALDECI GitHub Issues by title pattern.

    Used as a dedup check before creating a new issue.
    Returns the first matching issue or ``null`` if none found.
    """
    client = _get_client()
    try:
        issue = client.search_issue(title)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    if issue is None:
        return None

    return GitHubIssueItem(
        number=issue.number,
        title=issue.title,
        state=issue.state,
        url=issue.url,
        labels=issue.labels,
        assignees=issue.assignees,
        created_at=issue.created_at,
        updated_at=issue.updated_at,
        closed_at=issue.closed_at,
    )


@router.get(
    "/auth",
    response_model=AuthStatusResponse,
    summary="Check gh CLI availability and authentication status",
)
def check_auth():
    """
    Verify that the `gh` CLI is installed and authenticated.

    Returns the authenticated GitHub username and the configured repo.
    """
    client = _get_client()
    status = client.check_auth()
    return AuthStatusResponse(**status)
