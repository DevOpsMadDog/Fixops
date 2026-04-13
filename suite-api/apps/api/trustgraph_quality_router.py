"""
TrustGraph Quality Monitor API Router.

Exposes HTTP endpoints for TrustGraph data quality monitoring, orphan detection,
backfill operations, and graph statistics.

Routes:
- GET  /api/v1/trustgraph/quality/coverage  — per-core coverage report
- GET  /api/v1/trustgraph/quality/orphans   — orphaned findings in Core 2
- POST /api/v1/trustgraph/quality/backfill  — index missing data
- GET  /api/v1/trustgraph/quality/stats     — graph statistics
- GET  /api/v1/trustgraph/quality/issues    — quality issue list
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/trustgraph/quality", tags=["trustgraph-quality"])

# Lazy singleton
_monitor = None


def _get_monitor():
    """Lazy-load TrustGraphQualityMonitor singleton."""
    global _monitor
    if _monitor is None:
        from core.trustgraph_quality_monitor import TrustGraphQualityMonitor
        _monitor = TrustGraphQualityMonitor()
    return _monitor


# ============================================================================
# Request / Response Models
# ============================================================================


class CoreCoverageResponse(BaseModel):
    """Coverage stats for one Knowledge Core."""

    core_id: int
    core_name: str
    total_entities: int
    connected_entities: int
    orphaned_entities: int
    coverage_pct: float
    entity_type_breakdown: Dict[str, int]
    last_updated: Optional[str]


class CoverageReportResponse(BaseModel):
    """Overall coverage report across all Knowledge Cores."""

    cores: Dict[str, CoreCoverageResponse]
    total_coverage_pct: float
    total_entities: int
    connected_entities: int
    orphaned_count: int
    last_checked: str


class BackfillRequest(BaseModel):
    """Request to backfill orphaned entities."""

    dry_run: bool = Field(default=True, description="If true, only simulate — do not write.")


class BackfillResponse(BaseModel):
    """Backfill operation result."""

    dry_run: bool
    would_index: int
    actually_indexed: int
    skipped: int
    errors: int
    items: List[Dict[str, Any]]
    started_at: str
    completed_at: Optional[str]


class GraphStatsResponse(BaseModel):
    """High-level graph statistics."""

    total_entities: int
    total_relationships: int
    entities_per_core: Dict[str, int]
    relationships_per_core: Dict[str, int]
    coverage_pct: float
    orphaned_count: int
    last_updated: Optional[str]
    db_path: str


class QualityIssueResponse(BaseModel):
    """A single quality issue detected in TrustGraph."""

    issue_id: str
    type: str
    severity: str
    description: str
    entity_count: int
    auto_fixable: bool
    example_ids: List[str]
    detected_at: str


# ============================================================================
# Endpoints
# ============================================================================


@router.get("/coverage", response_model=CoverageReportResponse)
async def get_coverage_report() -> Dict[str, Any]:
    """Get TrustGraph coverage report — what % of ALDECI data is indexed per core.

    Returns:
        Per-core coverage percentages, entity counts, and orphaned entity counts.
    """
    try:
        monitor = _get_monitor()
        report = monitor.get_coverage_report()
        result = report.to_dict()
        # Convert int keys to strings for JSON compatibility
        result["cores"] = {str(k): v for k, v in result["cores"].items()}
        return result
    except Exception as exc:  # noqa: BLE001
        logger.error("Coverage report failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/orphans", response_model=List[Dict[str, Any]])
async def get_orphaned_findings(
    include_assets: bool = Query(default=False, description="Also include disconnected assets from Core 1"),
) -> List[Dict[str, Any]]:
    """Find security findings (Core 2) not connected to any other TrustGraph entity.

    Args:
        include_assets: If true, also returns disconnected assets from Core 1.

    Returns:
        List of orphaned entity dicts.
    """
    try:
        monitor = _get_monitor()
        orphans = monitor.find_orphaned_findings()
        if include_assets:
            orphans += monitor.find_disconnected_assets()
        return orphans
    except Exception as exc:  # noqa: BLE001
        logger.error("Orphan search failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/backfill", response_model=BackfillResponse)
async def backfill_missing_data(req: BackfillRequest) -> Dict[str, Any]:
    """Index orphaned findings and disconnected assets into TrustGraph.

    Args:
        req: BackfillRequest with dry_run flag.

    Returns:
        BackfillReport with counts of what was (or would be) indexed.
    """
    try:
        monitor = _get_monitor()
        report = monitor.backfill_missing_data(dry_run=req.dry_run)
        return report.to_dict()
    except Exception as exc:  # noqa: BLE001
        logger.error("Backfill failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/stats", response_model=GraphStatsResponse)
async def get_graph_stats() -> Dict[str, Any]:
    """Get high-level TrustGraph statistics: entity counts, relationship counts, coverage %.

    Returns:
        GraphStats summary across all Knowledge Cores.
    """
    try:
        monitor = _get_monitor()
        stats = monitor.get_graph_stats()
        result = stats.to_dict()
        # Convert int keys to strings for JSON serialization
        result["entities_per_core"] = {str(k): v for k, v in result["entities_per_core"].items()}
        result["relationships_per_core"] = {str(k): v for k, v in result["relationships_per_core"].items()}
        return result
    except Exception as exc:  # noqa: BLE001
        logger.error("Graph stats failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/issues", response_model=List[QualityIssueResponse])
async def get_quality_issues() -> List[Dict[str, Any]]:
    """Run TrustGraph quality checks and return all detected issues.

    Checks performed:
    - Findings without severity
    - Assets without classification
    - Duplicate findings (same source+rule+file)
    - Stale entities (not updated in 30 days)
    - Disconnected subgraphs (entities with no relationships)

    Returns:
        List of QualityIssue dicts, ordered by severity (critical -> low).
    """
    try:
        monitor = _get_monitor()
        issues = monitor.run_quality_checks()
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        issues.sort(key=lambda i: severity_order.get(i.severity, 99))
        return [issue.to_dict() for issue in issues]
    except Exception as exc:  # noqa: BLE001
        logger.error("Quality checks failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))
