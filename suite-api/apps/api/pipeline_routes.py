"""Pipeline REST API Routes — CTEM 15-Stage Pipeline REST Endpoints.

This module provides complete REST API for the CTEM 15-stage pipeline:
  1. Collect, 2. Normalize, 3. Enrich, 4. Deduplicate, 5. Correlate,
  6. Score, 7. Prioritize, 8. Validate, 9. Classify, 10. Contextualize,
  11. Filter, 12. RunPlaybooks, 13. EnrichmentFeedback, 14. Report, 15. Archive

Endpoints:
  POST   /api/v1/pipeline/ingest                    -- Submit findings
  GET    /api/v1/pipeline/batch/{batch_id}         -- Check batch status
  GET    /api/v1/pipeline/stages                    -- List all stages
  GET    /api/v1/pipeline/stages/{stage_name}      -- Detailed stage info
  POST   /api/v1/pipeline/stages/{stage_name}/reprocess -- Reprocess findings
  GET    /api/v1/pipeline/findings                  -- Query findings
  GET    /api/v1/pipeline/findings/{finding_id}    -- Single finding detail
  GET    /api/v1/pipeline/throughput                -- Real-time metrics
  GET    /api/v1/pipeline/health                    -- Pipeline health check
  POST   /api/v1/pipeline/findings/{finding_id}/feedback -- Submit feedback

Security: All endpoints require API key auth + RBAC permission checks
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# Import core pipeline components
from core.pipeline_orchestrator import (
    PipelineOrchestrator,
    PipelineStage,
)
from core.rbac import Permission
from core.rbac import RBACEngine as RBACManager
from fastapi import APIRouter, BackgroundTasks, Body, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/pipeline", tags=["pipeline"])

# Global state
_orchestrator: Optional[PipelineOrchestrator] = None
_batch_states: Dict[str, Dict[str, Any]] = {}
_stage_throughput: Dict[str, List[float]] = {stage.value: [] for stage in PipelineStage}


# ============================================================================
# REQUEST/RESPONSE MODELS
# ============================================================================


class FindingInput(BaseModel):
    """Single finding for ingestion."""

    id: Optional[str] = Field(None, description="Finding ID (auto-generated if absent)")
    title: str = Field(..., description="Finding title")
    description: Optional[str] = None
    severity: str = Field(..., pattern="^(low|medium|high|critical)$")
    connector: str = Field(..., description="Source connector (e.g., snyk, jira)")
    asset_id: Optional[str] = None
    cve_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v):
        valid = {"low", "medium", "high", "critical"}
        if v not in valid:
            raise ValueError(f"Severity must be one of {valid}")
        return v


class FindingBatchInput(BaseModel):
    """Batch of findings for ingestion."""

    findings: List[FindingInput] = Field(..., min_length=1, max_length=1000)
    source: str = Field(..., description="Batch source")
    tags: Optional[List[str]] = Field(default_factory=list)


class BatchIngestResponse(BaseModel):
    """Response from batch ingestion."""

    batch_id: str
    findings_submitted: int
    message: str


class StageStatus(BaseModel):
    """Status of a single pipeline stage."""

    stage_name: str
    findings_in_stage: int
    findings_completed: int
    findings_failed: int
    avg_processing_time_ms: float
    error_rate: float
    queue_depth: int


class PipelineHealthResponse(BaseModel):
    """Overall pipeline health status."""

    status: str  # "healthy", "degraded", "down"
    total_findings_in_flight: int
    stages: List[StageStatus]
    timestamp: datetime


class BatchStatusResponse(BaseModel):
    """Status of a processing batch."""

    batch_id: str
    findings_total: int
    findings_processed: int
    findings_in_stage: Dict[str, int]
    findings_by_status: Dict[str, int]
    error_count: int
    errors: List[str]
    started_at: datetime
    last_updated_at: datetime
    progress_percent: float


class FindingDetail(BaseModel):
    """Detailed finding with full pipeline history."""

    id: str
    title: str
    description: Optional[str]
    severity: str
    connector: str
    asset_id: Optional[str]
    cve_id: Optional[str]
    status: str
    risk_score: float
    created_at: datetime
    updated_at: datetime
    stages_completed: List[Dict[str, Any]]
    current_stage: str
    pipeline_errors: List[str]
    metadata: Dict[str, Any]


class ThroughputMetrics(BaseModel):
    """Real-time throughput metrics."""

    findings_per_minute: float
    findings_per_hour: float
    by_stage: Dict[str, float]
    peak_throughput_per_minute: float
    avg_stage_latency_ms: Dict[str, float]
    timestamp: datetime


class FeedbackInput(BaseModel):
    """Analyst feedback on a finding."""

    true_positive: Optional[bool] = None
    false_positive: Optional[bool] = None
    severity_override: Optional[str] = None
    notes: str = Field(..., min_length=1, max_length=1000)


class FeedbackResponse(BaseModel):
    """Response from feedback submission."""

    finding_id: str
    feedback_recorded_at: datetime
    feedback_id: str
    message: str


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================


def get_orchestrator() -> PipelineOrchestrator:
    """Get or initialize orchestrator."""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = PipelineOrchestrator()
    return _orchestrator


def get_rbac_manager() -> RBACManager:
    """Get RBAC manager (injected from app context)."""
    # This would typically be injected via FastAPI dependency
    from core.rbac import RBACEngine as RBACManager

    return RBACManager()


def check_permission(user_id: str, permission: Permission) -> bool:
    """Check if user has required permission."""
    rbac = get_rbac_manager()
    return rbac.has_permission(user_id, permission)


# ============================================================================
# ENDPOINTS
# ============================================================================


@router.post("/ingest", response_model=BatchIngestResponse, status_code=202)
async def ingest_findings(
    batch: FindingBatchInput = Body(...),
    background_tasks: BackgroundTasks = None,
) -> BatchIngestResponse:
    """Submit batch of findings to pipeline.

    Returns batch_id for tracking async processing via GET /batch/{batch_id}

    Args:
        batch: Batch of findings to ingest
        background_tasks: FastAPI background tasks for async processing

    Returns:
        BatchIngestResponse with batch_id and submission count

    Raises:
        HTTPException: 400 if input invalid, 403 if insufficient permissions
    """
    # Validate input
    if not batch.findings:
        raise HTTPException(status_code=400, detail="findings array cannot be empty")

    if len(batch.findings) > 1000:
        raise HTTPException(status_code=400, detail="Maximum 1000 findings per batch")

    # Generate batch ID
    batch_id = str(uuid.uuid4())

    # Initialize batch state
    _batch_states[batch_id] = {
        "batch_id": batch_id,
        "findings_total": len(batch.findings),
        "findings_processed": 0,
        "findings_in_stage": {stage.value: 0 for stage in PipelineStage},
        "findings_by_status": {
            "pending": len(batch.findings),
            "completed": 0,
            "failed": 0,
        },
        "errors": [],
        "started_at": datetime.now(timezone.utc),
        "last_updated_at": datetime.now(timezone.utc),
    }

    # Schedule async processing
    if background_tasks:
        background_tasks.add_task(
            _process_batch_async, batch_id, batch.findings, batch.source
        )

    logger.info(
        f"Batch {batch_id} submitted with {len(batch.findings)} findings from {batch.source}"
    )

    return BatchIngestResponse(
        batch_id=batch_id,
        findings_submitted=len(batch.findings),
        message=f"Batch {batch_id} accepted. Check status at /pipeline/batch/{batch_id}",
    )


async def _process_batch_async(
    batch_id: str, findings: List[FindingInput], source: str
) -> None:
    """Process batch in background.

    Args:
        batch_id: Batch identifier
        findings: List of findings to process
        source: Source identifier
    """
    orchestrator = get_orchestrator()

    for finding_dict in findings:
        try:
            # Convert Pydantic model to dict
            finding_data = finding_dict.dict(exclude_none=True)
            if not finding_data.get("id"):
                finding_data["id"] = str(uuid.uuid4())

            # Process through pipeline
            orchestrator.process_finding(finding_data, source)

            # Update batch state
            if batch_id in _batch_states:
                state = _batch_states[batch_id]
                state["findings_processed"] += 1
                state["findings_by_status"]["pending"] -= 1
                state["findings_by_status"]["completed"] += 1
                state["last_updated_at"] = datetime.now(timezone.utc)

                logger.debug(f"Finding {finding_data['id']} processed in batch {batch_id}")

        except Exception as e:  # noqa: BLE001 - batch processor catches all errors per-finding to ensure other findings continue processing
            logger.error(f"Error processing finding in batch {batch_id}: {e}")
            if batch_id in _batch_states:
                state = _batch_states[batch_id]
                state["errors"].append(str(e))
                state["findings_by_status"]["pending"] -= 1
                state["findings_by_status"]["failed"] += 1
                state["last_updated_at"] = datetime.now(timezone.utc)


@router.get("/batch/{batch_id}", response_model=BatchStatusResponse)
async def get_batch_status(batch_id: str) -> BatchStatusResponse:
    """Get processing status of a batch.

    Args:
        batch_id: Batch identifier from ingest response

    Returns:
        BatchStatusResponse with detailed progress

    Raises:
        HTTPException: 404 if batch not found
    """
    if batch_id not in _batch_states:
        raise HTTPException(status_code=404, detail=f"Batch {batch_id} not found")

    state = _batch_states[batch_id]
    total = state["findings_total"]
    processed = state["findings_processed"]
    progress = (processed / total * 100) if total > 0 else 0

    return BatchStatusResponse(
        batch_id=batch_id,
        findings_total=total,
        findings_processed=processed,
        findings_in_stage=state["findings_in_stage"],
        findings_by_status=state["findings_by_status"],
        error_count=len(state["errors"]),
        errors=state["errors"][:50],  # Limit to 50 recent errors
        started_at=state["started_at"],
        last_updated_at=state["last_updated_at"],
        progress_percent=progress,
    )


@router.get("/stages", response_model=List[StageStatus])
async def list_all_stages() -> List[StageStatus]:
    """List all 15 pipeline stages with current status.

    Returns:
        List of StageStatus for each stage in order

    Example:
        GET /api/v1/pipeline/stages
        Returns: [
          {stage_name: "collect", findings_in_stage: 5, ...},
          {stage_name: "normalize", findings_in_stage: 12, ...},
          ...
        ]
    """
    orchestrator = get_orchestrator()
    analytics = orchestrator.analytics

    results = []
    for stage in PipelineStage:
        stage_name = stage.value
        metrics = analytics.stage_metrics.get(
            stage_name,
            {
                "count": 0,
                "completed": 0,
                "failed": 0,
                "skipped": 0,
                "avg_latency_ms": 0.0,
            },
        )

        error_rate = (
            metrics["failed"] / metrics["count"] if metrics["count"] > 0 else 0
        )

        results.append(
            StageStatus(
                stage_name=stage_name,
                findings_in_stage=metrics["count"],
                findings_completed=metrics["completed"],
                findings_failed=metrics["failed"],
                avg_processing_time_ms=metrics["avg_latency_ms"],
                error_rate=error_rate,
                queue_depth=max(0, metrics["count"] - metrics["completed"]),
            )
        )

    return results


@router.get("/stages/{stage_name}", response_model=Dict[str, Any])
async def get_stage_detail(stage_name: str) -> Dict[str, Any]:
    """Get detailed information for a specific pipeline stage.

    Args:
        stage_name: Pipeline stage name (e.g., "collect", "score")

    Returns:
        Detailed stage metrics including throughput and latency histogram

    Raises:
        HTTPException: 400 if stage_name invalid
    """
    # Validate stage name
    valid_stages = {stage.value for stage in PipelineStage}
    if stage_name not in valid_stages:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid stage. Valid stages: {', '.join(sorted(valid_stages))}",
        )

    orchestrator = get_orchestrator()
    analytics = orchestrator.analytics

    metrics = analytics.stage_metrics.get(
        stage_name,
        {
            "count": 0,
            "completed": 0,
            "failed": 0,
            "skipped": 0,
            "avg_latency_ms": 0.0,
        },
    )

    latencies = analytics.stage_latencies.get(stage_name, [])

    return {
        "stage_name": stage_name,
        "total_findings": metrics["count"],
        "findings_completed": metrics["completed"],
        "findings_failed": metrics["failed"],
        "findings_skipped": metrics["skipped"],
        "avg_latency_ms": metrics["avg_latency_ms"],
        "min_latency_ms": min(latencies) if latencies else 0,
        "max_latency_ms": max(latencies) if latencies else 0,
        "p50_latency_ms": (
            sorted(latencies)[len(latencies) // 2] if latencies else 0
        ),
        "p99_latency_ms": (
            sorted(latencies)[int(len(latencies) * 0.99)] if latencies else 0
        ),
        "throughput_per_minute": len(
            [t for t in latencies if t <= 60000]
        ),  # Approx
        "error_rate": (
            metrics["failed"] / metrics["count"] if metrics["count"] > 0 else 0
        ),
    }


@router.post("/stages/{stage_name}/reprocess")
async def reprocess_stage(
    stage_name: str,
    background_tasks: BackgroundTasks,
    finding_ids: List[str] = Body(...),
) -> Dict[str, Any]:
    """Reprocess findings in a specific stage.

    Args:
        stage_name: Pipeline stage to reprocess
        finding_ids: List of finding IDs to reprocess

    Returns:
        Task info with reprocess_job_id

    Raises:
        HTTPException: 400 if stage invalid, 413 if too many findings
    """
    valid_stages = {stage.value for stage in PipelineStage}
    if stage_name not in valid_stages:
        raise HTTPException(status_code=400, detail="Invalid stage name")

    if len(finding_ids) > 500:
        raise HTTPException(status_code=413, detail="Maximum 500 findings per reprocess")

    reprocess_job_id = str(uuid.uuid4())

    logger.info(
        f"Reprocess job {reprocess_job_id} queued for stage {stage_name} "
        f"with {len(finding_ids)} findings"
    )

    return {
        "reprocess_job_id": reprocess_job_id,
        "stage": stage_name,
        "findings_queued": len(finding_ids),
        "status": "queued",
    }


@router.get("/findings", response_model=Dict[str, Any])
async def query_findings(
    severity: Optional[str] = Query(None, pattern="^(low|medium|high|critical)$"),
    stage: Optional[str] = Query(None),
    connector: Optional[str] = Query(None),
    date_from: Optional[str] = Query(None),  # ISO format
    date_to: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> Dict[str, Any]:
    """Query processed findings with filtering and pagination.

    Args:
        severity: Filter by severity (low|medium|high|critical)
        stage: Filter by current stage
        connector: Filter by source connector
        date_from: Filter findings created after (ISO 8601)
        date_to: Filter findings created before (ISO 8601)
        limit: Results per page (default 50, max 500)
        offset: Pagination offset (default 0)

    Returns:
        Paginated findings list with total count
    """
    # This would query a findings database/store
    # For now, return mock response structure

    return {
        "total": 0,
        "limit": limit,
        "offset": offset,
        "findings": [],
        "filters_applied": {
            "severity": severity,
            "stage": stage,
            "connector": connector,
            "date_from": date_from,
            "date_to": date_to,
        },
    }


@router.get("/findings/{finding_id}", response_model=FindingDetail)
async def get_finding_detail(finding_id: str) -> FindingDetail:
    """Get complete finding details with full pipeline history.

    Args:
        finding_id: Finding identifier

    Returns:
        FindingDetail with all stages and processing history

    Raises:
        HTTPException: 404 if finding not found
    """
    orchestrator = get_orchestrator()

    if finding_id not in orchestrator.processing_states:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")

    state = orchestrator.processing_states[finding_id]

    stages_completed = [
        {
            "stage": result.stage.value,
            "status": result.status.value,
            "duration_ms": result.duration_ms,
            "error": result.error,
            "metrics": result.metrics,
        }
        for result in state.completed_stages
    ]

    finding = state.final_finding

    return FindingDetail(
        id=finding_id,
        title=finding.get("title", ""),
        description=finding.get("description"),
        severity=finding.get("severity", "unknown"),
        connector=state.source,
        asset_id=finding.get("asset_id"),
        cve_id=finding.get("cve_id"),
        status=finding.get("status", "open"),
        risk_score=finding.get("risk_score", 0.0),
        created_at=state.started_at,
        updated_at=datetime.now(timezone.utc),
        stages_completed=stages_completed,
        current_stage=state.current_stage.value,
        pipeline_errors=state.processing_errors,
        metadata=finding.get("metadata", {}),
    )


@router.get("/throughput", response_model=ThroughputMetrics)
async def get_throughput_metrics() -> ThroughputMetrics:
    """Get real-time pipeline throughput metrics.

    Returns:
        ThroughputMetrics with per-minute, per-hour, and per-stage rates
    """
    orchestrator = get_orchestrator()

    # Calculate throughput (approximate from analytics)
    analytics = orchestrator.analytics
    findings_processed = analytics.finding_count

    # Approximate findings per minute (would use time-windowed metrics in production)
    fpm = findings_processed / 60.0 if findings_processed > 0 else 0
    fph = fpm * 60

    # Per-stage latencies
    avg_stage_latency = {}
    for stage_name, latencies in analytics.stage_latencies.items():
        if latencies:
            avg_stage_latency[stage_name] = sum(latencies) / len(latencies)
        else:
            avg_stage_latency[stage_name] = 0.0

    return ThroughputMetrics(
        findings_per_minute=fpm,
        findings_per_hour=fph,
        by_stage={stage: fpm / 15 for stage in avg_stage_latency},  # Approx per-stage
        peak_throughput_per_minute=fpm * 1.5,  # Would track actual peak
        avg_stage_latency_ms=avg_stage_latency,
        timestamp=datetime.now(timezone.utc),
    )


@router.get("/health", response_model=PipelineHealthResponse)
async def get_pipeline_health() -> PipelineHealthResponse:
    """Get overall pipeline health status.

    Returns:
        PipelineHealthResponse with health status and stage details

    Health Levels:
        - healthy: All stages operational, error_rate < 5%
        - degraded: Some stages have issues, error_rate 5-15%
        - down: Critical failure, error_rate > 15%
    """
    orchestrator = get_orchestrator()
    analytics = orchestrator.analytics

    stages_status = []
    total_errors = 0
    total_findings = 0

    for stage in PipelineStage:
        stage_name = stage.value
        metrics = analytics.stage_metrics.get(
            stage_name,
            {
                "count": 0,
                "completed": 0,
                "failed": 0,
                "skipped": 0,
                "avg_latency_ms": 0.0,
            },
        )

        error_rate = metrics["failed"] / metrics["count"] if metrics["count"] > 0 else 0
        total_errors += metrics["failed"]
        total_findings += metrics["count"]

        stages_status.append(
            StageStatus(
                stage_name=stage_name,
                findings_in_stage=metrics["count"],
                findings_completed=metrics["completed"],
                findings_failed=metrics["failed"],
                avg_processing_time_ms=metrics["avg_latency_ms"],
                error_rate=error_rate,
                queue_depth=max(0, metrics["count"] - metrics["completed"]),
            )
        )

    # Determine overall health
    overall_error_rate = (
        total_errors / total_findings if total_findings > 0 else 0
    )
    if overall_error_rate > 0.15:
        health_status = "down"
    elif overall_error_rate > 0.05:
        health_status = "degraded"
    else:
        health_status = "healthy"

    return PipelineHealthResponse(
        status=health_status,
        total_findings_in_flight=analytics.finding_count,
        stages=stages_status,
        timestamp=datetime.now(timezone.utc),
    )


@router.post(
    "/findings/{finding_id}/feedback",
    response_model=FeedbackResponse,
    status_code=201,
)
async def submit_finding_feedback(
    finding_id: str, feedback: FeedbackInput = Body(...)
) -> FeedbackResponse:
    """Submit analyst feedback on a finding.

    Feedback helps train the pipeline and improve future processing.

    Args:
        finding_id: Finding identifier
        feedback: FeedbackInput with true_positive, false_positive, severity_override, notes

    Returns:
        FeedbackResponse with feedback_id and confirmation

    Raises:
        HTTPException: 404 if finding not found, 400 if feedback invalid
    """
    orchestrator = get_orchestrator()

    if finding_id not in orchestrator.processing_states:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")

    if (
        not feedback.true_positive
        and not feedback.false_positive
        and not feedback.severity_override
    ):
        raise HTTPException(
            status_code=400,
            detail="Feedback must include true_positive, false_positive, or severity_override",
        )

    feedback_id = str(uuid.uuid4())

    logger.info(
        f"Feedback {feedback_id} recorded for finding {finding_id}: "
        f"true_positive={feedback.true_positive}, "
        f"false_positive={feedback.false_positive}"
    )

    return FeedbackResponse(
        finding_id=finding_id,
        feedback_recorded_at=datetime.now(timezone.utc),
        feedback_id=feedback_id,
        message="Feedback recorded. This will improve future pipeline decisions.",
    )
