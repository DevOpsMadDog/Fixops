"""Unified Issues Router — ALDECI (GAP-049 + GAP-066).

Federates rows from the three existing issue-like tables and exposes:

Prefix: /api/v1/issues
Auth:   api_key_auth dependency

Routes:
  GET  /api/v1/issues                  unified_list (filters: severity, status, source,
                                       first_seen_after, first_seen_before)
  GET  /api/v1/issues/counts           issue_counts_by_source
  POST /api/v1/issues/diff             compute_diff (baseline_scan_id, current_scan_id)
  GET  /api/v1/issues/diff-history     diff_history (scan list)
  GET  /api/v1/issues/stats            issue_stats (counts + by-severity + by-status)
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/issues",
    tags=["Unified Issues"],
    dependencies=[Depends(api_key_auth)],
)


def _engine():
    # Lazy import to avoid loading engine at module import time.
    from core.unified_issues_engine import get_unified_issues_engine
    return get_unified_issues_engine()


class DiffRequest(BaseModel):
    baseline_scan_id: str = Field(..., min_length=1, description="Prior scan to compare against")
    current_scan_id: str = Field(..., min_length=1, description="Scan being diffed")


@router.get("", summary="Unified issues queue")
@router.get("/", summary="Unified issues queue (trailing slash)")
def list_issues(
    org_id: str = Query(..., min_length=1),
    severity: Optional[str] = Query(None, description="critical|high|medium|low|info"),
    status: Optional[str] = Query(None, description="open|resolved|triaging|…"),
    source: Optional[str] = Query(None, description="findings|exposures|alerts"),
    first_seen_after: Optional[str] = Query(None, description="ISO timestamp, inclusive"),
    first_seen_before: Optional[str] = Query(None, description="ISO timestamp, exclusive"),
    limit: int = Query(100, ge=1, le=1000),
) -> Dict[str, Any]:
    filters = {
        "severity": severity,
        "status": status,
        "source": source,
        "first_seen_after": first_seen_after,
        "first_seen_before": first_seen_before,
    }
    try:
        issues = _engine().unified_list(org_id=org_id, filters=filters, limit=limit)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"issues": issues, "count": len(issues), "filters": filters}


@router.get("/counts", summary="Issue counts per source")
def counts(org_id: str = Query(..., min_length=1)) -> Dict[str, Any]:
    try:
        data = _engine().issue_counts_by_source(org_id=org_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return data


@router.post("/diff", summary="Diff two scans (new/unchanged/resolved)")
def diff(
    payload: DiffRequest,
    org_id: str = Query(..., min_length=1),
) -> Dict[str, Any]:
    try:
        return _engine().compute_diff(
            org_id=org_id,
            baseline_scan_id=payload.baseline_scan_id,
            current_scan_id=payload.current_scan_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/diff-history", summary="List scans available for diffing")
def diff_history(
    org_id: str = Query(..., min_length=1),
    limit: int = Query(20, ge=1, le=200),
) -> Dict[str, Any]:
    try:
        scans = _engine().diff_history(org_id=org_id, limit=limit)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"scans": scans, "count": len(scans)}


@router.get("/stats", summary="Unified issue stats (counts + by severity/status)")
def stats(org_id: str = Query(..., min_length=1)) -> Dict[str, Any]:
    try:
        return _engine().issue_stats(org_id=org_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get(
    "/index-state",
    summary="Pipeline → Issues bridge state (refresh epoch for UI polling)",
)
def index_state() -> Dict[str, Any]:
    """Return the federation refresh-epoch counter.

    The Issues dashboard polls this and refetches the queue whenever
    ``refresh_epoch`` increments. This eliminates the onboarding-bug
    workaround where customers had to click Admin → System → Refresh Finding
    Index after the Brain Pipeline completed.

    Wired to ``EventType.FINDINGS_INDEX_REFRESH`` and ``PIPELINE_COMPLETED``.
    """
    return _engine().index_state()
