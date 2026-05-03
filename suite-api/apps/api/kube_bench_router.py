"""kube-bench CIS Kubernetes Benchmark Scan Router — async-queued model.

Prefix: /api/v1/kube-bench

Wraps Aqua's kube-bench (https://github.com/aquasecurity/kube-bench) — the
canonical CIS Kubernetes Benchmark runner. Same async-queue + SQLite contract
as the Semgrep / Gitleaks / Checkov / Grype routers:

    GET  /                         — capability summary (benchmarks, target
                                     node roles, status levels)
    GET  /benchmarks               — catalog with check-count per benchmark
    POST /scan                     — queue a scan; returns {scan_id,
                                     benchmark_version, target_node_role,
                                     queued_at}
    GET  /scan/{scan_id}           — fetch scan record (status_counts,
                                     total_checks, findings)

Backed by core.kube_bench_scan_engine.KubeBenchScanEngine (SQLite at
data/security/kube_bench_scans.db).

Vision pillars: V1 (APP_ID-Centric), V3 (Decision Intelligence), V9 (Air-Gapped)
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/kube-bench",
    tags=["kube-bench"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Lazy engine accessor (allows test override via monkeypatch)
# ---------------------------------------------------------------------------


def _get_engine():
    from core.kube_bench_scan_engine import get_kube_bench_scan_engine

    return get_kube_bench_scan_engine()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CapabilitySummary(BaseModel):
    service: str
    benchmarks: List[str]
    target_node_roles: List[str]
    status_levels: List[str]
    status: str  # ok | empty | unavailable
    binary_present: bool
    scan_count: int


class BenchmarkEntry(BaseModel):
    id: str
    name: str
    default_check_count: int


class BenchmarksResponse(BaseModel):
    benchmarks: List[BenchmarkEntry]
    count: int


class ScanRequest(BaseModel):
    benchmark_version: Optional[str] = Field(
        default=None,
        description="CIS benchmark version: cis-1.6 | cis-1.7 | cis-1.8 | cis-1.9 | cis-1.10 (default: latest)",
    )
    target_node_role: Optional[str] = Field(
        default=None,
        description="kube-bench --targets value: master | node | etcd | policies | controlplane | managedservices (default: node)",
    )
    asff_output: Optional[bool] = Field(
        default=False,
        description="Emit AWS Security Finding Format alongside JSON (default: False)",
    )


class ScanQueuedResponse(BaseModel):
    scan_id: str
    benchmark_version: str
    target_node_role: str
    queued_at: str


class StatusCounts(BaseModel):
    PASS: int = 0
    FAIL: int = 0
    WARN: int = 0
    INFO: int = 0


class Finding(BaseModel):
    test_number: Optional[str] = None
    test_desc: Optional[str] = None
    status: str
    remediation: Optional[str] = None
    scored: bool = False


class ScanRecordResponse(BaseModel):
    scan_id: str
    benchmark_version: str
    target_node_role: str
    status: str
    status_counts: Dict[str, int]
    total_checks: int
    findings: List[Finding] = Field(default_factory=list)
    started_at: Optional[str] = None
    completed_at: Optional[str] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/",
    response_model=CapabilitySummary,
    summary="kube-bench CIS Kubernetes Benchmark capability summary",
)
def capability_summary() -> Dict[str, Any]:
    """Return kube-bench capability descriptor — supported CIS benchmarks,
    target node roles, status vocabulary, and overall status (``ok`` if scans
    recorded, ``empty`` if none yet, or ``unavailable`` when the kube-bench
    binary is not installed)."""
    engine = _get_engine()
    return engine.capability_summary()


@router.get(
    "/benchmarks",
    response_model=BenchmarksResponse,
    summary="List supported CIS Kubernetes benchmark versions",
)
def list_benchmarks() -> Dict[str, Any]:
    """Return the catalog of CIS Kubernetes benchmark versions supported by
    this engine, with the default check-count for each (used as a air-gapped
    UI hint; real per-scan counts come from kube-bench JSON output)."""
    engine = _get_engine()
    benchmarks = engine.list_benchmarks()
    return {"benchmarks": benchmarks, "count": len(benchmarks)}


@router.post(
    "/scan",
    response_model=ScanQueuedResponse,
    status_code=202,
    summary="Queue a kube-bench CIS Kubernetes Benchmark scan",
)
def queue_scan(body: ScanRequest) -> Dict[str, Any]:
    """Queue a kube-bench scan. Returns the scan id immediately.

    The scan executes inline against the kube-bench CLI when present; otherwise
    the record is persisted with ``status=unavailable`` (NO MOCKS — no fake
    findings)."""
    engine = _get_engine()
    try:
        return engine.queue_scan(
            benchmark_version=body.benchmark_version,
            target_node_role=body.target_node_role,
            asff_output=bool(body.asff_output),
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:  # noqa: BLE001
        logger.error("kube-bench queue_scan failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get(
    "/scan/{scan_id}",
    response_model=ScanRecordResponse,
    summary="Fetch a kube-bench scan record",
)
def get_scan(scan_id: str) -> Dict[str, Any]:
    """Return a single scan record by id. Returns 404 when unknown."""
    engine = _get_engine()
    record = engine.get_scan(scan_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"scan_id {scan_id!r} not found")
    return record
