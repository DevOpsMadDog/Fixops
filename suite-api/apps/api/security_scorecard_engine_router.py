"""
Security Scorecard Engine API router.

Endpoints for creating scorecards, tracking trends, managing benchmarks,
and comparing entities against industry benchmarks.

Prefix: /api/v1/security-scorecard
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/security-scorecard", tags=["security-scorecard-engine"])

# Lazy singleton
_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_scorecard_engine import SecurityScorecardEngine
        db_path = os.environ.get(
            "SCORECARD_ENGINE_DB_PATH",
            "security_scorecard_engine.db",
        )
        _engine = SecurityScorecardEngine(db_path=db_path)
    return _engine


# ------------------------------------------------------------------
# Request models
# ------------------------------------------------------------------


class DimensionInput(BaseModel):
    dimension: str = Field(..., description=(
        "One of: vulnerability_hygiene, patch_compliance, security_training, "
        "access_control, incident_response, threat_awareness, code_security, "
        "configuration_hardening"
    ))
    score: float = Field(..., ge=0.0, le=100.0)
    weight: float = Field(default=0.125, ge=0.0, le=1.0)
    evidence: str = Field(default="")


class ScorecardCreate(BaseModel):
    entity_type: str = Field(default="team", description="team|asset|project|vendor|service")
    entity_id: str = Field(..., min_length=1)
    entity_name: str = Field(default="")
    period_label: str = Field(default="", description="e.g. '2026-Q1'")
    dimensions: List[DimensionInput] = Field(default_factory=list)


class DomainScorecardCreate(BaseModel):
    """6-domain weighted scorecard (identity 20%, endpoint 20%, network 15%,
    cloud 15%, data 15%, application 15%)."""
    identity: float = Field(default=0.0, ge=0.0, le=100.0)
    endpoint: float = Field(default=0.0, ge=0.0, le=100.0)
    network: float = Field(default=0.0, ge=0.0, le=100.0)
    cloud: float = Field(default=0.0, ge=0.0, le=100.0)
    data: float = Field(default=0.0, ge=0.0, le=100.0)
    application: float = Field(default=0.0, ge=0.0, le=100.0)


class BenchmarkSet(BaseModel):
    industry: str = Field(..., min_length=1)
    entity_type: str = Field(..., min_length=1)
    avg_score: float = Field(..., ge=0.0, le=100.0)
    top_quartile_score: float = Field(..., ge=0.0, le=100.0)


# ------------------------------------------------------------------
# Scorecards
# ------------------------------------------------------------------


@router.post("/scorecards", status_code=201, response_model=Dict[str, Any])
async def create_scorecard(
    body: ScorecardCreate,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Create a new scorecard with dimension scores. Computes weighted overall score and grade."""
    engine = _get_engine()
    data = body.model_dump()
    return engine.create_scorecard(org_id, data)


@router.post("/scorecards/domain", status_code=201, response_model=Dict[str, Any])
async def generate_domain_scorecard(
    body: DomainScorecardCreate,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Generate a scorecard from 6 weighted domain scores.

    Domains: identity(20%), endpoint(20%), network(15%), cloud(15%),
    data(15%), application(15%).
    """
    engine = _get_engine()
    return engine.generate_scorecard(org_id, body.model_dump())


@router.get("/scorecards", response_model=List[Dict[str, Any]])
async def list_scorecards(
    org_id: str = Query(default="default"),
    entity_type: Optional[str] = Query(default=None),
    period_label: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List scorecards for an org, optionally filtered by entity_type and/or period_label."""
    engine = _get_engine()
    return engine.list_scorecards(org_id, entity_type=entity_type, period_label=period_label)


@router.get("/scorecards/{scorecard_id}", response_model=Dict[str, Any])
async def get_scorecard(
    scorecard_id: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Get a scorecard by ID with dimensions embedded."""
    engine = _get_engine()
    sc = engine.get_scorecard(org_id, scorecard_id)
    if sc is None:
        raise HTTPException(
            status_code=404,
            detail=f"Scorecard '{scorecard_id}' not found for org '{org_id}'.",
        )
    return sc


# ------------------------------------------------------------------
# Trends
# ------------------------------------------------------------------


@router.get("/trends/{entity_type}/{entity_id}", response_model=List[Dict[str, Any]])
async def get_entity_trend(
    entity_type: str,
    entity_id: str,
    org_id: str = Query(default="default"),
) -> List[Dict[str, Any]]:
    """Return trend records for an entity ordered by recorded_at ascending."""
    engine = _get_engine()
    return engine.get_entity_trend(org_id, entity_id, entity_type)


@router.get("/trend", response_model=List[Dict[str, Any]])
async def get_org_trend(
    org_id: str = Query(default="default"),
    days: int = Query(default=30, ge=1, le=365),
) -> List[Dict[str, Any]]:
    """Return the org's own scorecard trend for the last N days.

    Uses generate_scorecard history where entity_id == org_id.
    """
    engine = _get_engine()
    return engine.get_trend(org_id, days=days)


# ------------------------------------------------------------------
# Benchmarks
# ------------------------------------------------------------------


@router.post("/benchmarks", status_code=201, response_model=Dict[str, Any])
async def set_benchmark(
    body: BenchmarkSet,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Set or update an industry benchmark for an entity type."""
    engine = _get_engine()
    return engine.set_benchmark(
        org_id,
        body.industry,
        body.entity_type,
        body.avg_score,
        body.top_quartile_score,
    )


@router.get("/benchmarks", response_model=List[Dict[str, Any]])
async def get_benchmarks(
    org_id: str = Query(default="default"),
    entity_type: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List industry benchmarks, optionally filtered by entity_type."""
    engine = _get_engine()
    return engine.get_benchmarks(org_id, entity_type=entity_type)


@router.get("/scorecards/{scorecard_id}/compare", response_model=Dict[str, Any])
async def compare_to_benchmark(
    scorecard_id: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Compare a scorecard to its industry benchmark.

    Returns scorecard fields + benchmark_avg + benchmark_top_quartile + vs_avg + percentile_estimate.
    """
    engine = _get_engine()
    result = engine.compare_to_benchmark(org_id, scorecard_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=f"Scorecard '{scorecard_id}' not found for org '{org_id}'.",
        )
    return result


# ------------------------------------------------------------------
# Stats
# ------------------------------------------------------------------


@router.get("/stats", response_model=Dict[str, Any])
async def get_stats(
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Aggregate scorecard stats: total, by_grade, by_entity_type, avg_overall_score, top_performers."""
    engine = _get_engine()
    return engine.get_scorecard_stats(org_id)
