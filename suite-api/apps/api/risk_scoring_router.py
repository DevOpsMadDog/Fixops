"""
Risk Scoring & Exposure REST API — ALDECI.

Endpoints:
  POST /api/v1/risk-scoring/score              Score a single finding
  POST /api/v1/risk-scoring/rank               Rank a list of findings
  GET  /api/v1/risk-scoring/summary            Org-wide risk summary (rollup)
  GET  /api/v1/risk-scoring/exposure/org       Organisation exposure score
  GET  /api/v1/risk-scoring/exposure/{asset_id} Asset-level exposure score
  GET  /api/v1/risk-scoring/exposure/trend     30-day exposure trend

Scoring factors:
  CVSS base score   40%
  EPSS probability  25%
  CISA KEV          20%
  Asset criticality 15%

Compliance: NIST SP 800-40, CISA KEV alignment, FIRST EPSS v3, SOC2 CC9.2
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/risk-scoring", tags=["Risk Scoring"])

# ---------------------------------------------------------------------------
# Auth (graceful degradation — app.py may wrap with dependencies instead)
# ---------------------------------------------------------------------------

try:
    from apps.api.auth_deps import api_key_auth as _api_key_auth
    from fastapi import Depends

    _AUTH_DEP: list = [Depends(_api_key_auth)]
except ImportError:
    logger.warning(
        "risk_scoring_router: auth_deps not available, "
        "relying on app.py mount-level auth"
    )
    _AUTH_DEP = []

# ---------------------------------------------------------------------------
# Lazy engine accessors
# ---------------------------------------------------------------------------


def _get_prioritizer():
    from core.risk_prioritizer import get_risk_prioritizer

    db_path = os.environ.get("RISK_PRIORITIZER_DB", "risk_prioritizer.db")
    return get_risk_prioritizer(db_path=db_path)


def _get_scorer():
    from core.exposure_scorer import get_exposure_scorer

    db_path = os.environ.get("EXPOSURE_SCORER_DB", "exposure_scorer.db")
    return get_exposure_scorer(db_path=db_path)


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class ScoreFindingRequest(BaseModel):
    """Request body to score a single finding."""

    finding: Dict[str, Any] = Field(
        ...,
        description=(
            "Finding dict. Recognised keys: id/finding_id, cve_id/cve, "
            "severity/risk_level, cvss_score/cvss_base_score, "
            "asset_environment/environment, asset_criticality."
        ),
    )


class RankFindingsRequest(BaseModel):
    """Request body to rank a list of findings."""

    findings: List[Dict[str, Any]] = Field(
        ..., min_length=1, description="List of finding dicts to rank."
    )


# ---------------------------------------------------------------------------
# POST /api/v1/risk/score
# ---------------------------------------------------------------------------


@router.post(
    "/score",
    summary="Score a single finding",
    description=(
        "Produce a composite risk score 0-100 for a finding using "
        "CVSS (40%), EPSS (25%), CISA KEV (20%), asset criticality (15%)."
    ),
    dependencies=_AUTH_DEP,
)
def score_finding(body: ScoreFindingRequest) -> Dict[str, Any]:
    engine = _get_prioritizer()
    try:
        result = engine.score_finding(body.finding)
        result_dict = result.model_dump()
        # TrustGraph explicit indexing (fire-and-forget)
        try:
            from core.trustgraph_event_bus import EVENT_FINDING_CREATED
            from core.trustgraph_event_bus import get_event_bus as _get_eb
            _bus = _get_eb()
            if _bus and _bus.enabled:
                import asyncio as _asyncio
                _asyncio.ensure_future(_bus.emit(EVENT_FINDING_CREATED, {
                    "finding_id": str(body.finding.get("id", body.finding.get("finding_id", "risk-scored"))),
                    "type": "risk_score", "severity": str(body.finding.get("severity", "medium")),
                    "source": "risk_scoring_router", "data": result_dict,
                }))
        except Exception:
            pass
        return result_dict
    except Exception as exc:
        logger.error("score_finding error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# POST /api/v1/risk/rank
# ---------------------------------------------------------------------------


@router.post(
    "/rank",
    summary="Rank findings by composite risk",
    description=(
        "Score each finding and return them sorted highest-risk first. "
        "Also returns a prioritised remediation queue with urgency tiers."
    ),
    dependencies=_AUTH_DEP,
)
def rank_findings(body: RankFindingsRequest) -> Dict[str, Any]:
    engine = _get_prioritizer()
    try:
        ranked = engine.rank_findings(body.findings)
        queue = engine.get_remediation_priority(body.findings)
        return {
            "total": len(ranked),
            "scores": [s.model_dump() for s in ranked],
            "remediation_queue": queue.model_dump(),
        }
    except Exception as exc:
        logger.error("rank_findings error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# GET /api/v1/risk-scoring/summary
# ---------------------------------------------------------------------------


@router.get(
    "/summary",
    summary="Org-wide risk-scoring rollup",
    description=(
        "Aggregate risk-scoring summary for a tenant: open finding count by "
        "tier, weighted-risk average, distinct assets at risk, and overall "
        "exposure score. Drives dashboard cards that don't need per-finding "
        "detail."
    ),
    dependencies=_AUTH_DEP,
)
def risk_scoring_summary(
    org_id: str = Query(default="default", description="Tenant org_id"),
) -> Dict[str, Any]:
    import datetime as _dt
    scorer = _get_scorer()
    try:
        org = scorer.calculate_org_exposure(org_id=org_id, snapshot=False)
        org_dict = org.model_dump()
        total = (
            int(org_dict.get("critical_count", 0))
            + int(org_dict.get("high_count", 0))
            + int(org_dict.get("medium_count", 0))
            + int(org_dict.get("low_count", 0))
        ) or int(org_dict.get("open_findings_count", 0))

        # Pull by_source breakdown from SecurityFindingsEngine (best-effort).
        by_source: dict = {}
        last_updated: str = (
            org_dict.get("calculated_at")
            if isinstance(org_dict.get("calculated_at"), str)
            else (
                org_dict["calculated_at"].isoformat()
                if org_dict.get("calculated_at")
                else _dt.datetime.now(_dt.timezone.utc).isoformat()
            )
        )
        try:
            from core.security_findings_engine import SecurityFindingsEngine
            sfe = SecurityFindingsEngine()
            rows = sfe.list_findings(
                org_id=org_id, limit=10_000, offset=0,
                status="open",
            )
            for row in rows:
                row_d = row.model_dump() if hasattr(row, "model_dump") else (
                    row.dict() if hasattr(row, "dict") else row if isinstance(row, dict) else {}
                )
                tool = str(row_d.get("source_tool") or "unknown")
                by_source[tool] = by_source.get(tool, 0) + 1
                # Track most-recent updated_at as last_updated
                updated = row_d.get("updated_at") or row_d.get("created_at")
                if updated:
                    upd_str = updated.isoformat() if hasattr(updated, "isoformat") else str(updated)
                    if upd_str > last_updated:
                        last_updated = upd_str
        except Exception:
            pass  # by_source stays {}

        # by_severity from tier counts
        by_severity = {
            "critical": org_dict.get("critical_count", 0),
            "high": org_dict.get("high_count", 0),
            "medium": org_dict.get("medium_count", 0),
            "low": org_dict.get("low_count", 0),
        }

        return {
            "org_id": org_id,
            "total": total,
            "exposure_score": org_dict.get("exposure_score", 0.0),
            "rating": org_dict.get("rating"),
            "weighted_risk_avg": org_dict.get("weighted_risk_avg", 0.0),
            "open_findings_count": org_dict.get("open_findings_count", 0),
            "by_severity": by_severity,
            "by_tier": by_severity,  # alias kept for backwards compat
            "by_source": by_source,
            "last_updated": last_updated,
            "assets_at_risk": org_dict.get("assets_at_risk", 0),
            "patch_velocity_score": org_dict.get("patch_velocity_score", 0.0),
            "total_scored": total,
        }
    except Exception as exc:
        logger.error("risk_scoring_summary error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# GET /api/v1/risk-scoring/exposure/org
# ---------------------------------------------------------------------------


@router.get(
    "/exposure/org",
    summary="Organisation exposure score",
    description="Overall organisation security exposure score 0-100.",
    dependencies=_AUTH_DEP,
)
def org_exposure(
    org_id: str = Query(default="default", description="Tenant org_id"),
) -> Dict[str, Any]:
    scorer = _get_scorer()
    try:
        result = scorer.calculate_org_exposure(org_id=org_id, snapshot=True)
        return result.model_dump()
    except Exception as exc:
        logger.error("org_exposure error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# GET /api/v1/risk/exposure/trend
# ---------------------------------------------------------------------------

# NOTE: This route MUST be defined before /exposure/{asset_id} so FastAPI
# does not treat "trend" as an asset_id path parameter.
@router.get(
    "/exposure/trend",
    summary="Exposure trend (30-day)",
    description="Return daily exposure score snapshots for dashboard charting.",
    dependencies=_AUTH_DEP,
)
def exposure_trend(
    org_id: str = Query(default="default", description="Tenant org_id"),
    days: int = Query(default=30, ge=1, le=365, description="Look-back window in days"),
) -> Dict[str, Any]:
    scorer = _get_scorer()
    try:
        trend = scorer.get_exposure_trend(org_id=org_id, days=days)
        return {
            "org_id": org_id,
            "days": days,
            "total": len(trend),
            "trend": [t.model_dump() for t in trend],
        }
    except Exception as exc:
        logger.error("exposure_trend error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# GET /api/v1/risk/exposure/{asset_id}
# ---------------------------------------------------------------------------


@router.get(
    "/exposure/{asset_id}",
    summary="Asset exposure score",
    description="Risk exposure score 0-100 for a single asset.",
    dependencies=_AUTH_DEP,
)
def asset_exposure(asset_id: str) -> Dict[str, Any]:
    scorer = _get_scorer()
    try:
        result = scorer.get_asset_exposure(asset_id)
        return result.model_dump()
    except Exception as exc:
        logger.error("asset_exposure error asset=%s: %s", asset_id, exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc)) from exc
