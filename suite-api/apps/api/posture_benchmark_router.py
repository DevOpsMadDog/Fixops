"""Security Posture Benchmarking API Router.

Endpoints for generating, retrieving, and trending industry benchmark reports.

Auth is applied centrally by app.py (Depends(_verify_api_key)).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.posture_benchmark import (
    BenchmarkReport,
    IndustryVertical,
    PostureBenchmark,
    get_posture_benchmark,
)
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/posture-benchmark", tags=["posture-benchmark"])


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class GenerateBenchmarkRequest(BaseModel):
    org_id: str = Field("default", description="Organisation identifier")
    vertical: IndustryVertical = Field(..., description="Industry vertical for comparison")
    org_metrics: Optional[Dict[str, float]] = Field(
        None, description="Metric name -> measured value (optional; previously stored values used if omitted)"
    )


# ---------------------------------------------------------------------------
# Dependency
# ---------------------------------------------------------------------------


def _get_benchmark() -> PostureBenchmark:
    return get_posture_benchmark()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/generate", response_model=BenchmarkReport, summary="Generate benchmark report")
def generate_benchmark(req: GenerateBenchmarkRequest) -> BenchmarkReport:
    """Compare org posture against industry-vertical benchmarks and persist the report."""
    benchmark = _get_benchmark()
    try:
        return benchmark.generate_benchmark(
            org_id=req.org_id,
            vertical=req.vertical,
            org_metrics=req.org_metrics,
        )
    except Exception as exc:
        logger.exception("Failed to generate benchmark: %s", exc)
        raise HTTPException(status_code=500, detail=f"Benchmark generation failed: {exc}") from exc


@router.get(
    "/industry-averages",
    response_model=Dict[str, Dict[str, Any]],
    summary="Get industry benchmark averages",
)
def get_industry_averages(
    vertical: IndustryVertical = Query(..., description="Industry vertical"),
) -> Dict[str, Dict[str, Any]]:
    """Return benchmark statistics (avg, p90, direction) for every metric in the vertical."""
    benchmark = _get_benchmark()
    try:
        return benchmark.get_industry_averages(vertical)
    except Exception as exc:
        logger.exception("Failed to retrieve industry averages: %s", exc)
        raise HTTPException(status_code=500, detail=f"Industry averages retrieval failed: {exc}") from exc


@router.get(
    "/percentile",
    response_model=Dict[str, Any],
    summary="Get percentile rank for a metric",
)
def get_percentile_rank(
    org_id: str = Query("default", description="Organisation identifier"),
    metric_name: str = Query(..., description="Metric name (e.g. 'mttr_days')"),
) -> Dict[str, Any]:
    """Return where the org stands percentile-wise for a specific metric."""
    benchmark = _get_benchmark()
    try:
        rank = benchmark.get_percentile_rank(org_id, metric_name)
        if rank is None:
            raise HTTPException(
                status_code=404,
                detail=f"No benchmark data found for org '{org_id}'. Generate a report first.",
            )
        return {"org_id": org_id, "metric_name": metric_name, "percentile_rank": rank}
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Failed to retrieve percentile rank: %s", exc)
        raise HTTPException(status_code=500, detail=f"Percentile retrieval failed: {exc}") from exc


@router.get(
    "/improvement-priorities",
    response_model=List[Dict[str, Any]],
    summary="Get improvement priorities",
)
def get_improvement_priorities(
    org_id: str = Query("default", description="Organisation identifier"),
) -> List[Dict[str, Any]]:
    """Return metrics ranked by improvement opportunity (worst percentile first) with recommendations."""
    benchmark = _get_benchmark()
    try:
        priorities = benchmark.get_improvement_priorities(org_id)
        if not priorities:
            raise HTTPException(
                status_code=404,
                detail=f"No benchmark data found for org '{org_id}'. Generate a report first.",
            )
        return priorities
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Failed to retrieve improvement priorities: %s", exc)
        raise HTTPException(status_code=500, detail=f"Priority retrieval failed: {exc}") from exc


@router.get(
    "/history",
    response_model=List[BenchmarkReport],
    summary="Get benchmark history",
)
def get_benchmark_history(
    org_id: str = Query("default", description="Organisation identifier"),
) -> List[BenchmarkReport]:
    """Return all historical benchmark reports for an org, ordered chronologically."""
    benchmark = _get_benchmark()
    try:
        return benchmark.get_benchmark_history(org_id)
    except Exception as exc:
        logger.exception("Failed to retrieve benchmark history: %s", exc)
        raise HTTPException(status_code=500, detail=f"History retrieval failed: {exc}") from exc


@router.get(
    "/latest",
    response_model=BenchmarkReport,
    summary="Get latest benchmark report",
)
def get_latest_report(
    org_id: str = Query("default", description="Organisation identifier"),
) -> BenchmarkReport:
    """Return the most recent benchmark report for an org."""
    benchmark = _get_benchmark()
    try:
        report = benchmark.get_latest_report(org_id)
        if report is None:
            raise HTTPException(
                status_code=404,
                detail=f"No benchmark report found for org '{org_id}'. Generate one first.",
            )
        return report
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Failed to retrieve latest benchmark report: %s", exc)
        raise HTTPException(status_code=500, detail=f"Report retrieval failed: {exc}") from exc
