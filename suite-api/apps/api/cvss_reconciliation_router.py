"""CVSS Cross-Tool Reconciliation API Router.

Exposes endpoints so teams can:
  - POST a batch of multi-scanner findings and get back conflict groups
  - GET all conflict groups for an org (with spread filter)
  - POST a validated CVSS override (who / when / why)
  - GET the authoritative CVSS for a specific CVE
  - GET override history for an org
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from apps.api.dependencies import get_org_id
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/cvss-reconciliation",
    tags=["cvss-reconciliation"],
)

# ---------------------------------------------------------------------------
# Auth dependency (mirrors the pattern used across all ALDECI routers)
# ---------------------------------------------------------------------------

try:
    from apps.api.auth import _verify_api_key as _auth  # type: ignore
except ImportError:
    try:
        from apps.api.middleware import require_auth as _auth  # type: ignore
    except ImportError:
        async def _auth() -> None:  # type: ignore[misc]
            return None


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------


class DetectConflictsRequest(BaseModel):
    """Batch of raw findings from multiple scanners."""

    org_id: str = Field(..., description="Tenant identifier")
    findings: List[Dict[str, Any]] = Field(
        ...,
        description=(
            "List of finding dicts.  Each must include: id (or finding_id), "
            "scanner (or tool), cvss_score (or cvss), and ideally cve_id."
        ),
    )
    min_spread: float = Field(
        default=0.0,
        ge=0.0,
        le=10.0,
        description="Only return groups with CVSS spread >= this value.",
    )


class RecordOverrideRequest(BaseModel):
    """Team-validated authoritative CVSS decision."""

    org_id: str
    conflict_group_id: str = Field(..., description="ID from a CvssConflictGroup")
    cve_id: str = Field(..., description="CVE identifier (e.g. CVE-2023-1234) or title slug")
    authoritative_cvss: float = Field(..., ge=0.0, le=10.0)
    authoritative_severity: str = Field(
        ...,
        description="critical | high | medium | low | info",
    )
    decided_by: str = Field(..., description="User / team member making the decision")
    reason: str = Field(..., min_length=10, description="Mandatory justification (min 10 chars)")


# ---------------------------------------------------------------------------
# Engine singleton
# ---------------------------------------------------------------------------

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.cvss_reconciliation_engine import CvssReconciliationEngine  # type: ignore
        _engine = CvssReconciliationEngine()
    return _engine


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/", summary="Service health check")
async def root(_=Depends(_auth)) -> Dict[str, str]:
    """Confirm the CVSS reconciliation service is reachable."""
    return {"status": "ok", "service": "cvss-reconciliation"}


@router.post(
    "/detect",
    summary="Detect CVSS conflicts across tools",
    status_code=status.HTTP_200_OK,
)
async def detect_conflicts(
    body: DetectConflictsRequest,
    _=Depends(_auth),
) -> Dict[str, Any]:
    """Group multi-scanner findings by CVE and surface CVSS divergence.

    Returns one conflict group per CVE/title where at least two scanners
    reported different CVSS scores.  Each group includes per-tool scores,
    min/max/spread, and whether a team override already exists.
    """
    try:
        engine = _get_engine()
        groups = engine.detect_conflicts(
            findings=body.findings,
            org_id=body.org_id,
            min_spread=body.min_spread,
            persist=True,
        )
        serialised = []
        for g in groups:
            serialised.append({
                "id":           g.id,
                "cve_id":       g.cve_id,
                "tool_scores":  [e.model_dump() for e in g.tool_scores],
                "finding_ids":  g.finding_ids,
                "min_cvss":     g.min_cvss,
                "max_cvss":     g.max_cvss,
                "spread":       g.spread,
                "has_divergence": g.has_divergence,
                "created_at":   g.created_at,
                "override":     engine.get_authoritative_cvss(body.org_id, g.cve_id),
            })
        return {
            "org_id":         body.org_id,
            "findings_input": len(body.findings),
            "conflict_count": len(serialised),
            "conflicts":      serialised,
        }
    except Exception as exc:
        logger.exception("detect_conflicts error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        )


@router.get(
    "/conflicts",
    summary="List CVSS conflict groups for an org",
)
async def list_conflicts(
    org_id: str = Query(..., description="Tenant identifier"),
    min_spread: float = Query(default=0.0, ge=0.0, le=10.0),
    limit: int = Query(default=100, ge=1, le=500),
    _=Depends(_auth),
) -> Dict[str, Any]:
    """Return all known CVSS conflict groups for the given org.

    Each group shows the per-tool scores and the current team override (if any).
    Filter by ``min_spread`` to focus on the most contentious divergences.
    """
    try:
        engine = _get_engine()
        conflicts = engine.list_conflicts(org_id=org_id, min_spread=min_spread, limit=limit)
        return {
            "org_id":         org_id,
            "conflict_count": len(conflicts),
            "conflicts":      conflicts,
        }
    except Exception as exc:
        logger.exception("list_conflicts error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post(
    "/override",
    summary="Record a team-validated authoritative CVSS",
    status_code=status.HTTP_201_CREATED,
)
async def record_override(
    body: RecordOverrideRequest,
    _=Depends(_auth),
) -> Dict[str, Any]:
    """Persist the team's authoritative CVSS for a conflict group.

    Requires ``decided_by`` (user identity) and ``reason`` (minimum 10 chars).
    The decision is chained — a new record always sets ``supersedes_id`` to the
    previous decision so the full audit trail is preserved.
    """
    try:
        engine = _get_engine()
        decision = engine.record_override(
            org_id=body.org_id,
            conflict_group_id=body.conflict_group_id,
            cve_id=body.cve_id,
            authoritative_cvss=body.authoritative_cvss,
            authoritative_severity=body.authoritative_severity,
            decided_by=body.decided_by,
            reason=body.reason,
        )
        return {
            "decision_id":            decision.id,
            "org_id":                 decision.org_id,
            "conflict_group_id":      decision.conflict_group_id,
            "cve_id":                 decision.cve_id,
            "authoritative_cvss":     decision.authoritative_cvss,
            "authoritative_severity": decision.authoritative_severity,
            "decided_by":             decision.decided_by,
            "reason":                 decision.reason,
            "decided_at":             decision.decided_at,
            "supersedes_id":          decision.supersedes_id,
        }
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
    except Exception as exc:
        logger.exception("record_override error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get(
    "/authoritative",
    summary="Get authoritative CVSS for a CVE",
)
async def get_authoritative(
    org_id: str = Depends(get_org_id),
    cve_id: str = Query(..., description="e.g. CVE-2023-1234"),
    _=Depends(_auth),
) -> Dict[str, Any]:
    """Return the latest team-validated CVSS for a specific CVE.

    Returns 404 when no decision has been recorded yet.
    """
    try:
        engine = _get_engine()
        decision = engine.get_authoritative_cvss(org_id=org_id, cve_id=cve_id)
        if decision is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No authoritative CVSS decision found for cve_id={cve_id!r} in org={org_id!r}",
            )
        return {"org_id": org_id, "cve_id": cve_id, **decision}
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("get_authoritative error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get(
    "/overrides",
    summary="List all override decisions for an org",
)
async def list_overrides(
    org_id: str = Depends(get_org_id),
    limit: int = Query(default=100, ge=1, le=500),
    _=Depends(_auth),
) -> Dict[str, Any]:
    """Return the full override history for an org (newest first).

    Each entry includes the full audit trail: who decided, when, and why.
    The ``supersedes_id`` chain lets auditors trace the decision history for
    any CVE.
    """
    try:
        engine = _get_engine()
        overrides = engine.list_overrides(org_id=org_id, limit=limit)
        return {
            "org_id":         org_id,
            "override_count": len(overrides),
            "overrides":      overrides,
        }
    except Exception as exc:
        logger.exception("list_overrides error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))
