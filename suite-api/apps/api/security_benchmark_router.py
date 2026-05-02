"""Security Benchmark Router — ALDECI.

Endpoints for the SecurityBenchmarkEngine (SQLite-backed, org_id isolated).

Prefix: /api/v1/security-benchmarks
Auth:   api_key_auth dependency

Routes:
  POST  /api/v1/security-benchmarks/benchmarks                      create_benchmark
  POST  /api/v1/security-benchmarks/metrics                         record_org_metric
  POST  /api/v1/security-benchmarks/compare                         compare_to_benchmark
  GET   /api/v1/security-benchmarks/summary                         get_org_benchmark_summary
  GET   /api/v1/security-benchmarks/benchmarks                      list_benchmarks
  GET   /api/v1/security-benchmarks/metrics/{metric_name}/trend     get_metric_trend
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/security-benchmarks",
    tags=["Security Benchmarks"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_benchmark_engine import SecurityBenchmarkEngine
        _engine = SecurityBenchmarkEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class BenchmarkCreate(BaseModel):
    benchmark_name: str
    benchmark_source: str
    sector: str
    metric_name: str
    metric_category: str
    p25: float
    p50: float
    p75: float
    p90: float
    unit: str = ""
    higher_is_better: bool = True
    published_date: str = ""


class OrgMetricCreate(BaseModel):
    metric_name: str
    metric_category: str
    value: float
    unit: str = ""
    source: str = ""


class CompareRequest(BaseModel):
    benchmark_id: str
    org_metric_id: str


# ---------------------------------------------------------------------------
# Benchmarks
# ---------------------------------------------------------------------------

@router.post("/benchmarks", dependencies=[Depends(api_key_auth)], status_code=201)
def create_benchmark(body: BenchmarkCreate, org_id: str = Query(default="default")):
    """Create an industry benchmark definition."""
    try:
        return _get_engine().create_benchmark(
            org_id=org_id,
            benchmark_name=body.benchmark_name,
            benchmark_source=body.benchmark_source,
            sector=body.sector,
            metric_name=body.metric_name,
            metric_category=body.metric_category,
            p25=body.p25,
            p50=body.p50,
            p75=body.p75,
            p90=body.p90,
            unit=body.unit,
            higher_is_better=body.higher_is_better,
            published_date=body.published_date,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/benchmarks", dependencies=[Depends(api_key_auth)])
def list_benchmarks(
     org_id: str = Query(default="default"),
    sector: Optional[str] = Query(None),
    metric_category: Optional[str] = Query(None),
):
    """List benchmarks for the org, falling back to imported DBIR catalog if empty.

    Resolution order:
      1. Org-registered benchmarks (source=org_registered)
      2. Imported Verizon DBIR / VCDB incident corpus projected as derived
         per-(sector, action_pattern) benchmarks (source=dbir-derived) —
         real public data, no mocks
      3. Structured empty with import hint (source=empty)
    """
    return _get_engine().list_benchmarks_with_dbir_fallback(
        org_id, sector=sector, metric_category=metric_category
    )


@router.post("/import-dbir", dependencies=[Depends(api_key_auth)])
def import_dbir_benchmarks(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Import Verizon DBIR / VERIS Community Database breach incidents.

    Pulls https://github.com/vz-risk/VCDB and upserts every validated incident
    into the local dbir.db. The benchmark engine can then derive industry
    breach-rate distributions from this incident corpus.
    """
    try:
        from feeds.dbir.importer import run_import
        return run_import()
    except Exception as exc:
        _logger.exception("DBIR import failed")
        raise HTTPException(status_code=502, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Org Metrics
# ---------------------------------------------------------------------------

@router.post("/metrics", dependencies=[Depends(api_key_auth)], status_code=201)
def record_org_metric(body: OrgMetricCreate, org_id: str = Query(default="default")):
    """Record an org security metric measurement."""
    try:
        return _get_engine().record_org_metric(
            org_id=org_id,
            metric_name=body.metric_name,
            metric_category=body.metric_category,
            value=body.value,
            unit=body.unit,
            source=body.source,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/metrics/{metric_name}/trend", dependencies=[Depends(api_key_auth)])
def get_metric_trend(
    metric_name: str,
     org_id: str = Query(default="default"),
    days: int = Query(90, ge=1, le=365),
):
    """Return metric trend for an org over the past N days."""
    return _get_engine().get_metric_trend(org_id, metric_name, days=days)


# ---------------------------------------------------------------------------
# Comparisons
# ---------------------------------------------------------------------------

@router.post("/compare", dependencies=[Depends(api_key_auth)], status_code=201)
def compare_to_benchmark(body: CompareRequest, org_id: str = Query(default="default")):
    """Compare an org metric to a benchmark and compute percentile rank."""
    try:
        return _get_engine().compare_to_benchmark(
            org_id=org_id,
            benchmark_id=body.benchmark_id,
            org_metric_id=body.org_metric_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/summary", dependencies=[Depends(api_key_auth)])
def get_org_benchmark_summary(org_id: str = Query(default="default")):
    """Return benchmark comparison summary with performance counts and overall percentile."""
    return _get_engine().get_org_benchmark_summary(org_id)


@router.get("/", dependencies=[Depends(api_key_auth)])
def get_root(org_id: str = Query(default="default")):
    """Root endpoint — returns benchmarks list for dashboard health-checks."""
    return _get_engine().list_benchmarks(org_id)
