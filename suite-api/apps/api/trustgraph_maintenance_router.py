"""TrustGraph Maintenance API Router.

Exposes HTTP endpoints for post-ingest Knowledge Core integrity validation.
Inspired by the Graph Reviewer + lint-the-wiki patterns.

Routes:
- POST /api/v1/trustgraph/maintenance/sweep   — run full integrity sweep
- GET  /api/v1/trustgraph/maintenance/health  — per-core health scores (0-100)
- POST /api/v1/trustgraph/maintenance/fix     — auto-fix safe issues
- GET  /api/v1/trustgraph/maintenance/issues  — list current issues (no sweep)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/trustgraph/maintenance", tags=["trustgraph-maintenance"])

# Lazy singleton — avoids import-time DB access
_agent = None


def _get_agent():
    """Lazy-load TrustGraphMaintenanceAgent singleton."""
    global _agent
    if _agent is None:
        from trustgraph.maintenance_agent import TrustGraphMaintenanceAgent
        _agent = TrustGraphMaintenanceAgent()
    return _agent


# ============================================================================
# Request / Response Models
# ============================================================================


class MaintenanceIssueResponse(BaseModel):
    """A single detected integrity issue."""

    issue_id: str
    severity: str
    issue_type: str
    entity_id: str
    description: str
    suggested_fix: str
    core_id: int
    extra: Dict[str, Any]
    detected_at: str


class MaintenanceReportResponse(BaseModel):
    """Full maintenance sweep report."""

    checked_at: str
    cores_checked: List[int]
    issues: List[MaintenanceIssueResponse]
    stats: Dict[str, int]
    duration_ms: float
    org_id: str
    issue_count: int
    critical_count: int
    high_count: int


class CoreHealthResponse(BaseModel):
    """Health score for a single Knowledge Core."""

    core_id: int
    core_name: str
    score: int
    total_entities: int
    connected_pct: float
    stale_pct: float
    missing_severity_count: int
    reason: str


class FixRequest(BaseModel):
    """Request body for auto-fix endpoint."""

    dry_run: bool = Field(
        default=True,
        description="If true, report what would be fixed without writing to the database.",
    )
    issue_types: Optional[List[str]] = Field(
        default=None,
        description="Limit fixes to these issue types (orphan, duplicate). None = all fixable.",
    )


class FixResponse(BaseModel):
    """Result of an auto-fix operation."""

    dry_run: bool
    fixes_applied: int
    fixes_skipped: int
    errors: int
    details: List[Dict[str, Any]]


# ============================================================================
# Endpoints
# ============================================================================


@router.post("/sweep", response_model=MaintenanceReportResponse)
async def run_maintenance_sweep(
    org_id: str = Query(default="default", description="Organisation/tenant scope for the sweep"),
) -> Dict[str, Any]:
    """Run a full Knowledge Core integrity sweep across all 5 cores.

    Checks performed:
    - Cross-core contradiction detection (Core 2 vs Core 4 verdicts)
    - Orphaned entity detection (no relationships in any core)
    - Duplicate finding detection (same source+rule+file in Core 2)
    - Temporal staleness (entities not updated in >30 days)
    - Missing required fields (severity in Core 2 findings)
    - Entity type consistency (type matches core assignment)

    Returns:
        MaintenanceReport with all issues found and summary stats.
    """
    try:
        agent = _get_agent()
        report = agent.run_full_sweep(org_id=org_id)
        return report.to_dict()
    except Exception as exc:
        logger.error("Maintenance sweep failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/health", response_model=Dict[str, CoreHealthResponse])
async def get_core_health() -> Dict[str, Any]:
    """Get health scores (0-100) for all 5 Knowledge Cores.

    Score penalises:
    - Low entity connectivity (no relationships)
    - High staleness (not updated in 30 days)
    - Missing required fields (severity in Core 2)

    Returns:
        Dict mapping core_id string to health details and score.
    """
    try:
        agent = _get_agent()
        health = agent.get_core_health()
        return health
    except Exception as exc:
        logger.error("Core health check failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/fix", response_model=FixResponse)
async def auto_fix_issues(req: FixRequest) -> Dict[str, Any]:
    """Auto-fix safe integrity issues detected in the Knowledge Cores.

    Fixable issue types:
    - orphan: Links orphaned entity to its core anchor via belongs_to_core relationship
    - duplicate: Soft-deletes all but the primary duplicate finding

    Args:
        req: FixRequest with dry_run flag and optional issue_types filter.

    Returns:
        FixResponse with counts of fixes applied, skipped, and errors.
    """
    try:
        agent = _get_agent()

        # First run a sweep to collect current issues
        report = agent.run_full_sweep()
        issues = report.issues

        # Filter by requested issue types if specified
        if req.issue_types:
            issues = [i for i in issues if i.issue_type in req.issue_types]

        result = agent.auto_fix(issues, dry_run=req.dry_run)
        return result
    except Exception as exc:
        logger.error("Auto-fix failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/issues", response_model=List[MaintenanceIssueResponse])
async def get_current_issues(
    severity: Optional[str] = Query(
        default=None,
        description="Filter by severity: critical | high | medium | low",
    ),
    issue_type: Optional[str] = Query(
        default=None,
        description="Filter by issue type: contradiction | orphan | duplicate | stale | missing_field | type_mismatch",
    ),
    core_id: Optional[int] = Query(
        default=None,
        description="Filter by Knowledge Core ID (1-5). 0 = cross-core.",
    ),
    limit: int = Query(default=100, ge=1, le=1000, description="Maximum issues to return"),
) -> List[Dict[str, Any]]:
    """Run a maintenance sweep and return the detected issues with optional filters.

    Args:
        severity: Filter to a specific severity level.
        issue_type: Filter to a specific issue type.
        core_id: Filter to issues in a specific Knowledge Core.
        limit: Maximum number of issues to return.

    Returns:
        List of MaintenanceIssue dicts, ordered by severity (critical first).
    """
    try:
        agent = _get_agent()
        report = agent.run_full_sweep()
        issues = report.issues

        # Apply filters
        if severity:
            issues = [i for i in issues if i.severity == severity]
        if issue_type:
            issues = [i for i in issues if i.issue_type == issue_type]
        if core_id is not None:
            issues = [i for i in issues if i.core_id == core_id]

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        issues.sort(key=lambda i: severity_order.get(i.severity, 99))

        return [i.to_dict() for i in issues[:limit]]
    except Exception as exc:
        logger.error("Issue listing failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))
