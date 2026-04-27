"""Security Posture Benchmarking Router — ALDECI.

Framework benchmarking, per-control assessments, and peer-group comparisons.

Prefix: /api/v1/posture-benchmarking
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/posture-benchmarking/benchmarks               create_benchmark
  GET    /api/v1/posture-benchmarking/benchmarks               list_benchmarks
  GET    /api/v1/posture-benchmarking/benchmarks/{id}          get_benchmark
  PUT    /api/v1/posture-benchmarking/benchmarks/{id}/complete  complete_assessment
  POST   /api/v1/posture-benchmarking/controls                 record_control
  GET    /api/v1/posture-benchmarking/controls                 list_controls
  POST   /api/v1/posture-benchmarking/comparisons              add_comparison
  GET    /api/v1/posture-benchmarking/comparisons              list_comparisons
  GET    /api/v1/posture-benchmarking/stats                    get_benchmarking_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from apps.api.auth_deps import api_key_auth

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/posture-benchmarking",
    tags=["Security Posture Benchmarking"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_posture_benchmarking_engine import SecurityPostureBenchmarkingEngine
        _engine = SecurityPostureBenchmarkingEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class CreateBenchmarkRequest(BaseModel):
    org_id: str = Field(default="default", description="Organisation identifier")
    benchmark_name: str = Field(..., description="Name of the benchmark")
    framework: str = Field(
        ...,
        description="Framework: cis, nist, iso27001, soc2, pci_dss, hipaa, custom"
    )
    version: str = Field(default="", description="Framework version")
    category: str = Field(
        ...,
        description="Category: network, endpoint, cloud, identity, application, data, operations, compliance"
    )
    total_controls: int = Field(default=0, ge=0, description="Total number of controls")
    score: float = Field(default=0.0, ge=0.0, le=100.0, description="Initial score")
    industry_avg_score: float = Field(default=0.0, ge=0.0, le=100.0)
    percentile: int = Field(default=50, ge=0, le=100)
    status: str = Field(default="draft", description="Status: active, archived, draft")


class RecordControlRequest(BaseModel):
    org_id: str = Field(default="default")
    benchmark_id: str = Field(..., description="Parent benchmark ID")
    control_id: str = Field(default="", description="Control identifier (e.g. CIS 1.1)")
    title: str = Field(default="", description="Control title")
    description: str = Field(default="", description="Control description")
    result: str = Field(
        ..., description="Result: pass, fail, partial, not_applicable"
    )
    severity: str = Field(
        ..., description="Severity: critical, high, medium, low"
    )
    remediation: str = Field(default="", description="Remediation guidance")


class AddComparisonRequest(BaseModel):
    org_id: str = Field(default="default")
    benchmark_id: str = Field(..., description="Benchmark to compare")
    peer_group: str = Field(
        ...,
        description="Peer group: enterprise, smb, startup, government, healthcare, finance, retail"
    )
    peer_avg_score: float = Field(default=0.0, ge=0.0, le=100.0)
    our_score: float = Field(default=0.0, ge=0.0, le=100.0)
    percentile_rank: int = Field(default=50, ge=0, le=100)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/benchmarks", dependencies=[Depends(api_key_auth)])
def create_benchmark(req: CreateBenchmarkRequest) -> Dict[str, Any]:
    """Create a new security posture benchmark."""
    try:
        return _get_engine().create_benchmark(req.org_id, req.model_dump(exclude={"org_id"}))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        _logger.exception("create_benchmark failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/benchmarks", dependencies=[Depends(api_key_auth)])
def list_benchmarks(
    org_id: str = Query(default="default"),
    framework: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    """List benchmarks for the org, optionally filtered."""
    try:
        rows = _get_engine().list_benchmarks(org_id, framework=framework, status=status)
        if not rows:
            return {
                "benchmarks": [],
                "total": 0,
                "hint": "Import CIS/NIST benchmark definitions via POST /api/v1/posture-benchmarking/import-cis, or create one manually via POST /api/v1/posture-benchmarking/benchmarks.",
            }
        return {"benchmarks": rows, "total": len(rows)}
    except Exception as exc:
        _logger.exception("list_benchmarks failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/import-cis", dependencies=[Depends(api_key_auth)])
def import_cis_benchmarks(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Import CIS Benchmark definitions from public XML catalog (NOT YET IMPLEMENTED)."""
    raise HTTPException(
        status_code=501,
        detail={
            "error": "not_implemented",
            "endpoint": "POST /api/v1/posture-benchmarking/import-cis",
            "reason": "CIS Benchmark XML importer not yet built. Public source: https://www.cisecurity.org/cis-benchmarks",
            "tracking": "docs/empty_endpoints_triage_2026-04-26.md#8",
        },
    )


@router.get("/benchmarks/{benchmark_id}", dependencies=[Depends(api_key_auth)])
def get_benchmark(
    benchmark_id: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Get a single benchmark by ID."""
    try:
        result = _get_engine().get_benchmark(org_id, benchmark_id)
        if result is None:
            raise HTTPException(status_code=404, detail=f"Benchmark {benchmark_id} not found")
        return result
    except HTTPException:
        raise
    except Exception as exc:
        _logger.exception("get_benchmark failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.put("/benchmarks/{benchmark_id}/complete", dependencies=[Depends(api_key_auth)])
def complete_assessment(
    benchmark_id: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Complete a benchmark assessment — sets status=active, recomputes score."""
    try:
        result = _get_engine().complete_assessment(org_id, benchmark_id)
        if not result:
            raise HTTPException(status_code=404, detail=f"Benchmark {benchmark_id} not found")
        return result
    except HTTPException:
        raise
    except Exception as exc:
        _logger.exception("complete_assessment failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/controls", dependencies=[Depends(api_key_auth)])
def record_control(req: RecordControlRequest) -> Dict[str, Any]:
    """Record a control assessment result."""
    try:
        return _get_engine().record_control(req.org_id, req.model_dump(exclude={"org_id"}))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        _logger.exception("record_control failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/controls", dependencies=[Depends(api_key_auth)])
def list_controls(
    org_id: str = Query(default="default"),
    benchmark_id: Optional[str] = Query(default=None),
    result: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List controls, optionally filtered."""
    try:
        return _get_engine().list_controls(
            org_id, benchmark_id=benchmark_id, result=result, severity=severity
        )
    except Exception as exc:
        _logger.exception("list_controls failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/comparisons", dependencies=[Depends(api_key_auth)])
def add_comparison(req: AddComparisonRequest) -> Dict[str, Any]:
    """Add a peer-group comparison for a benchmark."""
    try:
        return _get_engine().add_comparison(req.org_id, req.model_dump(exclude={"org_id"}))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        _logger.exception("add_comparison failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/comparisons", dependencies=[Depends(api_key_auth)])
def list_comparisons(
    org_id: str = Query(default="default"),
    benchmark_id: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List peer-group comparisons, optionally filtered by benchmark."""
    try:
        return _get_engine().list_comparisons(org_id, benchmark_id=benchmark_id)
    except Exception as exc:
        _logger.exception("list_comparisons failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_benchmarking_stats(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Return aggregate benchmarking statistics for the org."""
    try:
        return _get_engine().get_benchmarking_stats(org_id)
    except Exception as exc:
        _logger.exception("get_benchmarking_stats failed")
        raise HTTPException(status_code=500, detail=str(exc))
