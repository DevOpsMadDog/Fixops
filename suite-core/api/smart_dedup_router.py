"""
Smart Dedup Router — Cross-Scanner Vulnerability Deduplication API.

Endpoints:
  POST   /api/v1/smart-dedup/deduplicate          -- run all strategies
  GET    /api/v1/smart-dedup/groups               -- list dedup groups
  GET    /api/v1/smart-dedup/groups/{id}          -- group detail
  POST   /api/v1/smart-dedup/groups/{id}/merge    -- merge duplicates into canonical
  GET    /api/v1/smart-dedup/stats/{org_id}       -- dedup stats
  GET    /api/v1/smart-dedup/noise-reduction/{org_id} -- before/after counts + fatigue score

Security: All endpoints require api_key_auth via dependency injection at app mount.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/smart-dedup",
    tags=["smart-dedup"],
)


# ---------------------------------------------------------------------------
# Lazy engine accessor
# ---------------------------------------------------------------------------


def _get_engine():
    from core.smart_dedup import SmartDedup
    return SmartDedup()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class DeduplicateRequest(BaseModel):
    findings: List[Dict[str, Any]] = Field(
        ..., description="List of finding dicts to deduplicate"
    )
    org_id: str = Field(default="", description="Tenant / org identifier")
    fuzzy_threshold: float = Field(
        default=0.82,
        ge=0.0,
        le=1.0,
        description="Levenshtein ratio threshold for fuzzy title matching (0-1)",
    )


class MergeResponse(BaseModel):
    group_id: str
    canonical_finding_id: str
    merged_count: int
    merged_duplicate_ids: List[str]
    strategy: str
    confidence: float


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/deduplicate", summary="Run smart deduplication across all strategies")
def deduplicate(body: DeduplicateRequest) -> Dict[str, Any]:
    """Run all five dedup strategies on the supplied findings.

    Strategies applied:
    - EXACT_CVE: same CVE from different scanners
    - FUZZY_TITLE: similar titles via Levenshtein ratio
    - SAME_FILE_LINE: same file + overlapping line range
    - CROSS_SCANNER: same issue from 2+ scanners
    - COMPONENT_VERSION: same package@version

    Returns groups, surviving canonical findings, duplicate count, and
    alert fatigue score (0-100).
    """
    engine = _get_engine()
    result = engine.deduplicate(
        body.findings,
        org_id=body.org_id,
        fuzzy_threshold=body.fuzzy_threshold,
    )
    return {
        "finding_count": len(body.findings),
        "canonical_count": len(result["canonical_findings"]),
        "duplicate_count": result["duplicate_count"],
        "group_count": len(result["groups"]),
        "alert_fatigue_score": result["alert_fatigue_score"],
        "groups": [g.model_dump() for g in result["groups"]],
        "canonical_findings": result["canonical_findings"],
    }


@router.get("/groups", summary="List dedup groups")
def list_groups(
    org_id: Optional[str] = Query(default=None, description="Filter by org"),
    strategy: Optional[str] = Query(
        default=None,
        description="Filter by strategy: exact_cve | fuzzy_title | same_file_line | cross_scanner | component_version",
    ),
    limit: int = Query(default=100, ge=1, le=1000, description="Max results"),
) -> Dict[str, Any]:
    """List persisted DedupGroups with optional org and strategy filters."""
    engine = _get_engine()
    groups = engine.list_groups(org_id=org_id, strategy=strategy, limit=limit)
    return {
        "count": len(groups),
        "groups": [g.model_dump() for g in groups],
    }


@router.get("/groups/{group_id}", summary="Get a specific dedup group")
def get_group(group_id: str) -> Dict[str, Any]:
    """Retrieve a single DedupGroup by ID."""
    engine = _get_engine()
    group = engine.get_group(group_id)
    if group is None:
        raise HTTPException(status_code=404, detail=f"Dedup group '{group_id}' not found")
    return group.model_dump()


@router.post("/groups/{group_id}/merge", summary="Merge duplicates into canonical finding")
def merge_group(group_id: str) -> MergeResponse:
    """Merge all duplicates in a group into the canonical finding.

    Returns the canonical finding ID and list of merged duplicate IDs.
    """
    engine = _get_engine()
    result = engine.merge_group(group_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Dedup group '{group_id}' not found")
    return MergeResponse(**result)


@router.get("/stats/{org_id}", summary="Dedup statistics for an org")
def get_stats(org_id: str) -> Dict[str, Any]:
    """Return deduplication statistics.

    Includes: total_groups, total_duplicates_removed, reduction_ratio,
    avg_group_size, strategies_used, by_strategy breakdown.
    """
    engine = _get_engine()
    return engine.get_dedup_stats(org_id)


@router.get("/noise-reduction/{org_id}", summary="Before/after finding counts and alert fatigue score")
def get_noise_reduction(org_id: str) -> Dict[str, Any]:
    """Return noise reduction metrics across all dedup runs for an org.

    Includes total input/output finding counts, duplicates removed,
    and alert fatigue score (0-100, higher = more noise eliminated).
    """
    engine = _get_engine()
    return engine.get_noise_reduction(org_id)
