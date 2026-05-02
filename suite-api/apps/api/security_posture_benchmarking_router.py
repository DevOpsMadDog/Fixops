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

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/posture-benchmarking",
    tags=["Security Posture Benchmarking"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_posture_benchmarking_engine import (
            SecurityPostureBenchmarkingEngine,
        )
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
    """List benchmarks for the org, falling back to imported CIS catalog if empty.

    Resolution order:
      1. Org-registered benchmarks (status=org_registered)
      2. Imported CIS Benchmark catalog projected as derived rows
         (source=cis-benchmark-derived) — real public data, no mocks
      3. Structured empty with import hint (source=empty)
    """
    try:
        return _get_engine().list_benchmarks_with_cis_fallback(
            org_id, framework=framework, status=status
        )
    except Exception as exc:
        _logger.exception("list_benchmarks failed")
        raise HTTPException(status_code=500, detail=str(exc))


_cis_importer = None


def _get_cis_importer(file_path: Optional[str] = None, url: Optional[str] = None):
    """Return a configured CisBenchmarkImporter. file_path overrides url."""
    from feeds.cis_benchmark.importer import (
        CIS_BENCHMARK_DEFAULT_URL,
        CisBenchmarkImporter,
    )
    global _cis_importer
    # Always rebuild if a one-off source override is supplied (admin upload).
    if file_path or url:
        return CisBenchmarkImporter(
            url=url or None,
            file_path=file_path or None,
        )
    if _cis_importer is None:
        # Default: live URL fetch. Operator can swap to file_path via API.
        _cis_importer = CisBenchmarkImporter(url=CIS_BENCHMARK_DEFAULT_URL)
    return _cis_importer


class ImportCisRequest(BaseModel):
    file_path: Optional[str] = Field(
        default=None,
        description=(
            "Local XCCDF file path (admin-uploaded fallback). Required when "
            "the CIS source URL is gated behind registration. Mutually "
            "exclusive with url."
        ),
    )
    url: Optional[str] = Field(
        default=None,
        description="Override the CIS XCCDF source URL (defaults to public SCAP-Repository mirror).",
    )
    idempotent: bool = Field(
        default=True,
        description="Skip controls already present in DB (default true).",
    )


@router.post("/import-cis", dependencies=[Depends(api_key_auth)])
def import_cis_benchmarks(
    req: Optional[ImportCisRequest] = None,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Import CIS Benchmark XCCDF controls into local catalog.

    Source resolution order:
      1. ``req.file_path`` (admin-uploaded XCCDF doc — used when CIS source is gated)
      2. ``req.url`` (caller-supplied HTTP source)
      3. Default public SCAP-Repository mirror (CIS Controls v8)
    """
    from feeds.cis_benchmark.importer import CisBenchmarkSourceError

    payload = req or ImportCisRequest()
    try:
        importer = _get_cis_importer(file_path=payload.file_path, url=payload.url)
        result = importer.run(idempotent=payload.idempotent)
    except CisBenchmarkSourceError as exc:
        raise HTTPException(
            status_code=502,
            detail={
                "error": "source_unreachable",
                "reason": str(exc),
                "remediation": "Download the CIS XCCDF doc manually and POST again with file_path=/path/to/xccdf.xml",
            },
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid XCCDF: {exc}")
    except Exception as exc:
        _logger.exception("import_cis_benchmarks failed")
        raise HTTPException(status_code=500, detail=str(exc))

    return result


@router.get("/cis-controls", dependencies=[Depends(api_key_auth)])
def list_cis_controls(
    benchmark_id: Optional[str] = Query(default=None),
    profile: Optional[str] = Query(default=None, description="e.g. L1, L2"),
    severity: Optional[str] = Query(default=None, description="informational|low|medium|high"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=100, ge=1, le=1000),
) -> Dict[str, Any]:
    """List imported CIS Benchmark controls with optional filters."""
    try:
        importer = _get_cis_importer()
        return importer.list_controls(
            benchmark_id=benchmark_id,
            profile=profile,
            severity=severity,
            page=page,
            page_size=page_size,
        )
    except Exception as exc:
        _logger.exception("list_cis_controls failed")
        raise HTTPException(status_code=500, detail=str(exc))


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
