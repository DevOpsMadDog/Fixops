"""Developer Risk Profiles API Router.

Exposes the DeveloperRiskProfiler engine as REST endpoints.
Competitive with Apiiro's developer risk analysis — tracks which developers
introduce the most vulnerabilities and scores their security risk.

Prefix: /api/v1/developer-profiles
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/developer-profiles", tags=["developer-risk"])

# Lazy-init profiler singleton
_profiler = None


def _get_profiler():
    global _profiler
    if _profiler is None:
        from core.developer_risk_profiler import DeveloperRiskProfiler
        _profiler = DeveloperRiskProfiler()
    return _profiler


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ContributionRequest(BaseModel):
    author_email: str = Field(..., min_length=3, max_length=256)
    commit_sha: str = Field(..., min_length=6, max_length=64)
    files_changed: List[str] = Field(default_factory=list, max_length=200)
    lines_added: int = Field(default=0, ge=0)
    lines_deleted: int = Field(default=0, ge=0)
    findings_introduced: List[str] = Field(default_factory=list, max_length=100)


class FixRequest(BaseModel):
    developer_email: str = Field(..., min_length=3, max_length=256)
    finding_id: str = Field(..., min_length=1, max_length=128)


class BulkIngestRequest(BaseModel):
    findings: List[Dict[str, Any]] = Field(..., max_length=1000)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/health")
async def health():
    return {"status": "healthy", "service": "developer-risk-profiler"}


@router.post("/contributions", status_code=201)
async def record_contribution(req: ContributionRequest):
    """Record a developer's commit and any vulnerabilities introduced."""
    profiler = _get_profiler()
    dev_id = profiler.record_contribution(
        commit_sha=req.commit_sha,
        author_email=req.author_email,
        files_changed=req.files_changed,
        lines_added=req.lines_added,
        lines_deleted=req.lines_deleted,
        findings_introduced=req.findings_introduced if req.findings_introduced else None,
    )
    return {"developer_id": dev_id, "findings_recorded": len(req.findings_introduced)}


@router.post("/fixes")
async def record_fix(req: FixRequest):
    """Record that a developer fixed a finding."""
    profiler = _get_profiler()
    profiler.record_fix(req.developer_email, req.finding_id)
    return {"status": "recorded"}


@router.get("/{identifier}/risk")
async def get_developer_risk(identifier: str):
    """Get developer risk context. Identifier can be email or developer_id."""
    profiler = _get_profiler()
    if "@" in identifier:
        ctx = profiler.get_pr_risk_context(identifier, files_changed=[])
    else:
        profile = profiler.get_profile_by_id(identifier[:64]) if hasattr(profiler, "get_profile_by_id") else None
        if not profile:
            raise HTTPException(404, "Developer not found")
        ctx = {
            "developer_known": True,
            "developer_id": profile.developer_id,
            "risk_score": profile.risk_score,
            "risk_trend": profile.risk_trend,
            "total_commits": profile.total_commits,
            "findings_introduced": profile.total_findings_introduced,
            "findings_fixed": profile.findings_fixed,
        }
    return ctx


@router.get("/{identifier}/profile")
async def get_developer_profile(identifier: str):
    """Get full developer profile with risk scoring breakdown."""
    profiler = _get_profiler()
    if "@" not in identifier:
        raise HTTPException(400, "Provide email address for full profile")
    profile = profiler.get_profile(identifier)
    if not profile:
        raise HTTPException(404, "Developer not found")
    return {
        "developer_id": profile.developer_id,
        "email_domain": profile.email_domain,
        "display_name": profile.display_name,
        "first_seen": profile.first_seen,
        "last_seen": profile.last_seen,
        "total_commits": profile.total_commits,
        "total_findings_introduced": profile.total_findings_introduced,
        "findings_by_severity": profile.findings_by_severity,
        "findings_fixed": profile.findings_fixed,
        "avg_fix_time_hours": profile.avg_fix_time_hours,
        "risk_score": profile.risk_score,
        "risk_trend": profile.risk_trend,
    }


@router.get("/{identifier}/trend")
async def get_developer_trend(identifier: str, days: int = 90):
    """Get developer risk trend over time."""
    profiler = _get_profiler()
    if "@" not in identifier:
        raise HTTPException(400, "Provide email address for trend analysis")
    trend = profiler.get_risk_trend(identifier, days=min(days, 365))
    return {"developer_email_domain": identifier.split("@")[-1], "trend": trend}


@router.get("/leaderboard/risk")
async def get_risk_leaderboard(limit: int = 20):
    """Get team risk leaderboard — highest risk developers first."""
    profiler = _get_profiler()
    return {"developers": profiler.get_team_leaderboard(limit=min(limit, 100))}


@router.post("/bulk-ingest")
async def bulk_ingest_findings(req: BulkIngestRequest):
    """Ingest historical findings to build developer profiles retroactively."""
    profiler = _get_profiler()
    result = profiler.bulk_ingest_from_findings(req.findings)
    return result


__all__ = ["router"]
