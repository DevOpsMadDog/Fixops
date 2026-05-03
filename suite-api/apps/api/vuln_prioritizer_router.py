"""
Vulnerability Prioritization Router — ALDECI.

7 endpoints:
  GET  /api/v1/vulns/prioritized          Prioritized vulnerability list with composite scores
  GET  /api/v1/vulns/epss/{cve_id}        EPSS score for a CVE
  GET  /api/v1/vulns/reachability/{fid}   Reachability analysis for a finding
  GET  /api/v1/vulns/sla-status           SLA compliance dashboard
  GET  /api/v1/vulns/trends               Vulnerability trend data
  GET  /api/v1/vulns/groups               Auto-grouped vulnerabilities
  POST /api/v1/vulns/prioritize           Trigger re-prioritization
"""

from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query

try:
    from apps.api.auth_deps import api_key_auth as _api_key_auth
    from fastapi import Depends
    _AUTH_DEP: list = [Depends(_api_key_auth)]
except ImportError:
    logging.getLogger(__name__).warning(
        "vuln_prioritizer_router: auth_deps not available, "
        "relying on app.py mount-level auth"
    )
    _AUTH_DEP = []

from core.vuln_prioritizer import (
    EPSSScore,
    PrioritizationSummary,
    PrioritizedVuln,
    PrioritizeRequest,
    ReachabilityResult,
    RiskBucket,
    SLAStatus,
    ScoringConfig,
    VulnGroup,
    VulnPrioritizer,
    VulnTrend,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/vulns",
    tags=["Vulnerability Prioritization"],
    dependencies=_AUTH_DEP,
)

# Shared engine instance (file-backed SQLite, shared across requests)
_engine: Optional[VulnPrioritizer] = None


def _get_engine() -> VulnPrioritizer:
    global _engine
    if _engine is None:
        _engine = VulnPrioritizer()
    return _engine


# ============================================================================
# GET /api/v1/vulns/prioritized
# ============================================================================


@router.get(
    "/prioritized",
    response_model=List[PrioritizedVuln],
    summary="Prioritized vulnerability list",
    description=(
        "Return all open vulnerabilities sorted by composite risk score (highest first). "
        "Optionally filter by risk bucket or asset."
    ),
)
def list_prioritized(
    org_id: str = Query(default="default", description="Tenant org_id"),
    bucket: Optional[RiskBucket] = Query(default=None, description="Filter by risk bucket"),
    asset_id: Optional[str] = Query(default=None, description="Filter by asset_id"),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> List[PrioritizedVuln]:
    engine = _get_engine()
    try:
        return engine.list_prioritized(
            org_id=org_id,
            bucket=bucket,
            asset_id=asset_id,
            limit=limit,
            offset=offset,
        )
    except Exception as exc:
        logger.error("list_prioritized error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ============================================================================
# GET /api/v1/vulns/epss/{cve_id}
# ============================================================================


@router.get(
    "/epss/{cve_id}",
    response_model=EPSSScore,
    summary="EPSS score for a CVE",
    description=(
        "Return the EPSS (Exploit Prediction Scoring System) probability score for a CVE. "
        "Fetches from FIRST.org API on first call; subsequent calls use local cache."
    ),
)
def get_epss(
    cve_id: str,
    force_refresh: bool = Query(
        default=False, description="Bypass cache and re-fetch from FIRST.org"
    ),
) -> EPSSScore:
    engine = _get_engine()
    if not cve_id.upper().startswith("CVE-"):
        raise HTTPException(
            status_code=422,
            detail=f"Invalid CVE ID format: {cve_id!r}. Expected CVE-YYYY-NNNNN.",
        )
    try:
        return engine.get_epss_score(cve_id, force_refresh=force_refresh)
    except Exception as exc:
        logger.error("get_epss error cve=%s: %s", cve_id, exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ============================================================================
# GET /api/v1/vulns/reachability/{finding_id}
# ============================================================================


@router.get(
    "/reachability/{finding_id}",
    response_model=Optional[ReachabilityResult],
    summary="Reachability analysis for a finding",
    description=(
        "Return the reachability level for a specific finding_id. "
        "Levels: confirmed_reachable, potentially_reachable, not_reachable, unknown."
    ),
)
def get_reachability(finding_id: str) -> Optional[ReachabilityResult]:
    engine = _get_engine()
    try:
        result = engine.get_reachability(finding_id)
        if result is None:
            raise HTTPException(
                status_code=404,
                detail=f"No reachability data for finding_id={finding_id!r}",
            )
        return result
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("get_reachability error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ============================================================================
# GET /api/v1/vulns/sla-status
# ============================================================================


@router.get(
    "/sla-status",
    response_model=SLAStatus,
    summary="SLA compliance dashboard",
    description=(
        "Return SLA compliance metrics: total open, within SLA, breached, "
        "breach rate, and breakdown by risk bucket. Optionally filter by team."
    ),
)
def get_sla_status(
    org_id: str = Query(default="default"),
    team: Optional[str] = Query(default=None, description="Filter by assigned_team"),
) -> SLAStatus:
    engine = _get_engine()
    try:
        return engine.get_sla_status(org_id=org_id, team=team)
    except Exception as exc:
        logger.error("get_sla_status error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ============================================================================
# GET /api/v1/vulns/trends
# ============================================================================


@router.get(
    "/trends",
    response_model=VulnTrend,
    summary="Vulnerability trend data",
    description=(
        "Return trend metrics for the vulnerability backlog: new vs resolved, "
        "total open, SLA breach rate, risk debt accumulation, and per-bucket counts."
    ),
)
def get_trends(
    org_id: str = Query(default="default"),
    days: int = Query(default=30, ge=1, le=365, description="Lookback window in days"),
) -> VulnTrend:
    engine = _get_engine()
    try:
        return engine.compute_trend(org_id=org_id, days=days)
    except Exception as exc:
        logger.error("get_trends error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ============================================================================
# GET /api/v1/vulns/groups
# ============================================================================


@router.get(
    "/groups",
    response_model=List[VulnGroup],
    summary="Auto-grouped vulnerabilities",
    description=(
        "Return auto-grouped vulnerability clusters: same CVE across assets, "
        "same library across repos, same misconfiguration pattern. "
        "Fix once, resolve many."
    ),
)
def list_groups(
    org_id: str = Query(default="default"),
    rebuild: bool = Query(
        default=False,
        description="Rebuild groups from current findings before returning",
    ),
) -> List[VulnGroup]:
    engine = _get_engine()
    try:
        if rebuild:
            return engine.rebuild_groups(org_id=org_id)
        return engine.list_groups(org_id=org_id)
    except Exception as exc:
        logger.error("list_groups error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ============================================================================
# POST /api/v1/vulns/prioritize
# ============================================================================


@router.post(
    "/prioritize",
    response_model=PrioritizationSummary,
    summary="Trigger re-prioritization",
    description=(
        "Re-compute composite risk scores for all (or a filtered subset of) vulnerabilities. "
        "Refreshes EPSS scores, recalculates business impact, reapplies SLA deadlines. "
        "Returns a summary of evaluated and updated findings."
    ),
)
def trigger_prioritization(body: PrioritizeRequest) -> PrioritizationSummary:
    engine = _get_engine()
    try:
        result = engine.run_prioritization(
            org_id=body.org_id,
            asset_ids=body.asset_ids,
            force_epss_refresh=body.force_epss_refresh,
        )
        # TrustGraph explicit indexing (fire-and-forget)
        try:
            from core.trustgraph_event_bus import EVENT_FINDING_CREATED
            from core.trustgraph_event_bus import get_event_bus as _get_eb
            _bus = _get_eb()
            if _bus and _bus.enabled:
                import asyncio as _asyncio
                _asyncio.ensure_future(_bus.emit(EVENT_FINDING_CREATED, {
                    "finding_id": f"vuln-prioritize-{body.org_id}",
                    "type": "vuln_prioritization", "severity": "high",
                    "source": "vuln_prioritizer_router",
                    "data": {"org_id": body.org_id, "evaluated": getattr(result, "evaluated", 0)},
                }))
        except Exception:
            pass
        return result
    except Exception as exc:
        logger.error("trigger_prioritization error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ============================================================================
# GET /api/v1/vulns/scoring-config
# ============================================================================


@router.get(
    "/scoring-config",
    response_model=ScoringConfig,
    summary="Get scoring weights and bucket thresholds",
    description=(
        "Return the operator-tunable scoring configuration for an org: "
        "business-impact weights (revenue, data_sensitivity, customer, regulatory) "
        "and composite-score bucket thresholds (critical/high/medium/low). "
        "Falls back to hardcoded defaults when no config has been saved."
    ),
)
def get_scoring_config(
    org_id: str = Query(default="default", description="Tenant org_id"),
) -> ScoringConfig:
    engine = _get_engine()
    try:
        return engine.get_scoring_config(org_id=org_id)
    except Exception as exc:
        logger.error("get_scoring_config error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ============================================================================
# PUT /api/v1/vulns/scoring-config
# ============================================================================


@router.put(
    "/scoring-config",
    response_model=ScoringConfig,
    summary="Update scoring weights and bucket thresholds",
    description=(
        "Persist operator-tuned scoring weights and bucket thresholds for an org. "
        "All subsequent calls to /prioritize and vulnerability upserts will use "
        "the updated values. Changes take effect immediately — no restart required."
    ),
)
def put_scoring_config(body: ScoringConfig) -> ScoringConfig:
    engine = _get_engine()
    try:
        return engine.upsert_scoring_config(body)
    except Exception as exc:
        logger.error("put_scoring_config error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc)) from exc
