"""
Self-Scan API Router — ALDECI scans itself as its own test subject.

Exposes endpoints to trigger and retrieve self-scan results so that
ALDECI's own security posture feeds its own dashboards (dogfooding).

Endpoints:
  POST /api/v1/self-scan/run       — Trigger a full self-scan (async)
  GET  /api/v1/self-scan/results   — Latest self-scan report
  GET  /api/v1/self-scan/findings  — Findings, optionally filtered by category
  GET  /api/v1/self-scan/score     — ALDECI's own security score summary
"""

from __future__ import annotations

import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import structlog
from apps.api.auth_deps import api_key_auth
from core.self_scanner import (
    ScanCategory,
    get_self_scan_engine,
)
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/api/v1/self-scan", tags=["Self-Scan"])

# ---------------------------------------------------------------------------
# Scan-run state (in-process; a real deployment would persist to DB)
# ---------------------------------------------------------------------------

_scan_lock = threading.Lock()
_active_scan_id: Optional[str] = None
_scan_status: Dict[str, Any] = {}  # scan_id -> {status, started_at, ...}


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class ScanRunResponse(BaseModel):
    """Response returned immediately when a scan is triggered."""

    scan_id: str
    status: str = "running"
    message: str
    triggered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ScanStatusResponse(BaseModel):
    """Lightweight status for a running/completed scan."""

    scan_id: str
    status: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None


class FindingsResponse(BaseModel):
    """Paginated findings response."""

    total: int
    category_filter: Optional[str] = None
    severity_filter: Optional[str] = None
    findings: List[Dict[str, Any]]


class ScoreResponse(BaseModel):
    """Security score summary for ALDECI itself."""

    scan_id: Optional[str] = None
    score: Optional[float] = None
    grade: Optional[str] = None
    scanned_at: Optional[str] = None
    total_findings: Optional[int] = None
    findings_by_severity: Optional[Dict[str, int]] = None
    top_priorities: Optional[List[str]] = None
    message: Optional[str] = None


# ---------------------------------------------------------------------------
# Background scan runner
# ---------------------------------------------------------------------------

def _run_scan_background(scan_id: str) -> None:
    """Execute the full self-scan in a background thread."""
    global _active_scan_id

    log = logger.bind(scan_id=scan_id)
    log.info("self_scan_background_started")

    with _scan_lock:
        _scan_status[scan_id]["status"] = "running"

    try:
        engine = get_self_scan_engine()
        report = engine.run_full_scan()

        with _scan_lock:
            _scan_status[scan_id].update(
                {
                    "status": "completed",
                    "completed_at": datetime.now(timezone.utc),
                    "duration_seconds": report.duration_seconds,
                    "risk_score": report.risk_score,
                    "grade": report.grade,
                    "total_findings": len(report.findings),
                }
            )
            if _active_scan_id == scan_id:
                _active_scan_id = None

        log.info(
            "self_scan_background_completed",
            risk_score=report.risk_score,
            grade=report.grade,
            findings=len(report.findings),
        )

    except Exception as exc:  # noqa: BLE001
        log.exception("self_scan_background_failed", error=str(exc))
        with _scan_lock:
            _scan_status[scan_id].update({"status": "failed", "error": str(exc)})
            if _active_scan_id == scan_id:
                _active_scan_id = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post(
    "/run",
    response_model=ScanRunResponse,
    summary="Trigger a full ALDECI self-scan",
    description=(
        "Starts a background self-scan of ALDECI's own codebase, dependencies, "
        "containers, config, and API surface. Returns immediately with a scan_id. "
        "Only one scan runs at a time — subsequent requests while a scan is active "
        "return the existing scan_id."
    ),
    dependencies=[Depends(api_key_auth)],
)
async def trigger_self_scan(background_tasks: BackgroundTasks) -> ScanRunResponse:
    global _active_scan_id

    with _scan_lock:
        if _active_scan_id is not None:
            existing = _active_scan_id
            started = _scan_status.get(existing, {}).get("started_at")
            logger.info("self_scan_already_running", existing_scan_id=existing)
            return ScanRunResponse(
                scan_id=existing,
                status="running",
                message="A self-scan is already in progress. Poll /api/v1/self-scan/results for completion.",
                triggered_at=started or datetime.now(timezone.utc),
            )

        scan_id = str(uuid.uuid4())
        _active_scan_id = scan_id
        started_at = datetime.now(timezone.utc)
        _scan_status[scan_id] = {
            "status": "queued",
            "started_at": started_at,
            "completed_at": None,
            "duration_seconds": None,
        }

    background_tasks.add_task(_run_scan_background, scan_id)

    logger.info("self_scan_triggered", scan_id=scan_id)
    return ScanRunResponse(
        scan_id=scan_id,
        status="running",
        message="Self-scan started. GET /api/v1/self-scan/results to retrieve results when complete.",
        triggered_at=started_at,
    )


@router.get(
    "/results",
    summary="Latest self-scan report",
    description=(
        "Returns the full report from the most recently completed self-scan. "
        "If no scan has run yet, returns 404. Trigger a scan first with POST /run."
    ),
    dependencies=[Depends(api_key_auth)],
)
async def get_self_scan_results() -> Dict[str, Any]:
    engine = get_self_scan_engine()
    report = engine.get_latest_report()

    if report is None:
        raise HTTPException(
            status_code=404,
            detail=(
                "No self-scan results available. "
                "Trigger a scan first: POST /api/v1/self-scan/run"
            ),
        )

    # Serialise via model_dump to handle datetime + enum types
    data = report.model_dump(mode="json")
    # Strip the large CI YAML from the results response (available via /score)
    data.pop("ci_workflow_yaml", None)

    return {
        "scan_id": data["scan_id"],
        "scanned_at": data["scanned_at"],
        "project_root": data["project_root"],
        "duration_seconds": data["duration_seconds"],
        "risk_score": data["risk_score"],
        "grade": data["grade"],
        "files_scanned": data["files_scanned"],
        "lines_scanned": data["lines_scanned"],
        "findings_by_severity": data["findings_by_severity"],
        "findings_by_category": data["findings_by_category"],
        "compliance_gaps": data["compliance_gaps"],
        "remediation_priorities": data["remediation_priorities"],
        "total_findings": len(data["findings"]),
        "dependencies_scanned": len(data["dependencies"]),
    }


@router.get(
    "/findings",
    response_model=FindingsResponse,
    summary="Self-scan findings by category",
    description=(
        "Returns individual findings from the latest self-scan. "
        "Filter by category (sast, dependency, container, config, api_surface) "
        "and/or severity (critical, high, medium, low, info)."
    ),
    dependencies=[Depends(api_key_auth)],
)
async def get_self_scan_findings(
    category: Optional[str] = Query(
        default=None,
        description="Filter by scan category: sast, dependency, container, config, api_surface",
    ),
    severity: Optional[str] = Query(
        default=None,
        description="Filter by severity: critical, high, medium, low, info",
    ),
    limit: int = Query(default=100, ge=1, le=500, description="Maximum findings to return"),
    offset: int = Query(default=0, ge=0, description="Offset for pagination"),
) -> FindingsResponse:
    engine = get_self_scan_engine()
    report = engine.get_latest_report()

    if report is None:
        raise HTTPException(
            status_code=404,
            detail="No self-scan results available. Trigger a scan: POST /api/v1/self-scan/run",
        )

    # Validate category filter
    category_filter: Optional[ScanCategory] = None
    if category is not None:
        try:
            category_filter = ScanCategory(category)
        except ValueError:
            valid = [c.value for c in ScanCategory]
            raise HTTPException(
                status_code=422,
                detail=f"Invalid category '{category}'. Valid values: {valid}",
            )

    findings = engine.get_findings_by_category(category_filter)

    # Severity filter
    if severity is not None:
        findings = [f for f in findings if f.severity == severity]

    total = len(findings)
    page = findings[offset: offset + limit]

    return FindingsResponse(
        total=total,
        category_filter=category,
        severity_filter=severity,
        findings=[f.model_dump(mode="json") for f in page],
    )


@router.get(
    "/score",
    response_model=ScoreResponse,
    summary="ALDECI's own security score",
    description=(
        "Returns ALDECI's self-assessed security score (0–100, lower is better), "
        "letter grade (A–F), top remediation priorities, and the generated "
        "CI workflow YAML for integrating the self-scan into GitHub Actions."
    ),
    dependencies=[Depends(api_key_auth)],
)
async def get_security_score(
    include_ci_yaml: bool = Query(
        default=False,
        description="Include the generated GitHub Actions CI workflow YAML in the response",
    ),
) -> ScoreResponse:
    engine = get_self_scan_engine()
    score_data = engine.get_security_score()

    if score_data.get("score") is None:
        return ScoreResponse(message=score_data.get("message", "No scan data available."))

    report = engine.get_latest_report()
    ci_yaml: Optional[str] = None
    if include_ci_yaml and report is not None:
        ci_yaml = report.ci_workflow_yaml

    result = ScoreResponse(
        scan_id=score_data.get("scan_id"),
        score=score_data.get("score"),
        grade=score_data.get("grade"),
        scanned_at=score_data.get("scanned_at"),
        total_findings=score_data.get("total_findings"),
        findings_by_severity=score_data.get("findings_by_severity"),
        top_priorities=score_data.get("top_priorities"),
    )

    # Attach CI YAML as extra field if requested (not in schema model to keep it optional)
    if ci_yaml is not None:
        # Return raw dict so we can include the YAML without inflating the schema
        return {  # type: ignore[return-value]
            **result.model_dump(),
            "ci_workflow_yaml": ci_yaml,
        }

    return result
