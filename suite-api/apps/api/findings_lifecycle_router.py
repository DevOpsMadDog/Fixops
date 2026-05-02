"""Findings Lifecycle Router — ALDECI (GAP-063).

Violation lifecycle chain: firstSeenAt / previousViolationId / resolvedAt.

Prefix: /api/v1/findings/lifecycle
Auth:   api_key_auth dependency on every route.

Routes:
  POST  /api/v1/findings/lifecycle/reconcile              reconcile_scans
  GET   /api/v1/findings/lifecycle/summary                lifecycle_summary
  GET   /api/v1/findings/lifecycle/{finding_id}/history   lifecycle_history

Unblocks:
  - GAP-049 (unified /issues queue) — diff-aware badges
  - GAP-066 (diff-mode UI)           — new/unchanged/resolved selector
  - GAP-011 (material change)        — violation-level resolution signal
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/findings/lifecycle",
    tags=["Findings Lifecycle"],
)

_engine = None


def _get_engine():
    """Lazy-initialize the shared SecurityFindingsEngine instance."""
    global _engine
    if _engine is None:
        from core.security_findings_engine import SecurityFindingsEngine
        _engine = SecurityFindingsEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class ReconcileRequest(BaseModel):
    """Body for POST /reconcile."""

    org_id: str = Field(default="default", description="Tenant org identifier")
    prior_scan_id: str = Field(..., min_length=1, description="The previous scan run id")
    current_scan_id: str = Field(..., min_length=1, description="The current scan run id")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/reconcile", dependencies=[Depends(api_key_auth)])
def reconcile(body: ReconcileRequest) -> Dict[str, Any]:
    """Compute new / unchanged / resolved diff between two scans.

    Side effects:
      - Unchanged violations have their ``previous_violation_id`` set to the
        matching prior row and ``unchanged_scan_count`` incremented.
      - Violations only present in the prior scan are marked
        ``status='resolved'`` with ``resolved_at=NOW()``.
    """
    if body.prior_scan_id == body.current_scan_id:
        raise HTTPException(
            status_code=400,
            detail="prior_scan_id and current_scan_id must differ",
        )
    try:
        return _get_engine().reconcile_scans(
            org_id=body.org_id,
            prior_scan_id=body.prior_scan_id,
            current_scan_id=body.current_scan_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # pragma: no cover — defensive
        _logger.exception("reconcile error")
        raise HTTPException(status_code=500, detail="Reconcile failed") from exc


@router.get("/summary", dependencies=[Depends(api_key_auth)])
def summary(
    org_id: str = Query(default="default"),
    days: int = Query(default=7, ge=1, le=365),
) -> Dict[str, Any]:
    """Rolling `{new, unchanged, resolved}` counts over the last N days.

    Defaults to a 7-day window — use `days` to expand (max 365)."""
    return _get_engine().lifecycle_summary(org_id=org_id, days=days)


@router.get("/{finding_id}/history", dependencies=[Depends(api_key_auth)])
def history(
    finding_id: str,
    org_id: str = Query(default="default"),
    max_depth: int = Query(default=50, ge=1, le=500),
) -> Dict[str, Any]:
    """Walk the ``previous_violation_id`` chain for a finding.

    Returns ancestors oldest-first. Cycle-safe.
    """
    chain: List[Dict[str, Any]] = _get_engine().lifecycle_history(
        finding_id=finding_id,
        org_id=org_id,
        max_depth=max_depth,
    )
    if not chain:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {
        "finding_id": finding_id,
        "org_id": org_id,
        "depth": len(chain),
        "chain": chain,
    }
