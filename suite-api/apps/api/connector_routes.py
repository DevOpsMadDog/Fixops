"""Connector Gateway API Router — Ingest and orchestrate findings from external integrations.

This router provides a unified API for connector workflows to submit findings (from n8n,
DefectDojo, or custom connectors) into the ALDECI pipeline, along with connector management
and metrics endpoints.

Endpoints:
    POST   /api/v1/connectors/ingest             -- Ingest normalized findings
    POST   /api/v1/connectors/ingest/raw         -- Ingest raw scanner files (DefectDojo)
    GET    /api/v1/connectors/registry           -- List all registered connectors
    GET    /api/v1/connectors/{name}/health      -- Health check for connector
    POST   /api/v1/connectors/{name}/pull        -- Trigger on-demand pull
    GET    /api/v1/connectors/stages/{stage}     -- List connectors by SDLC stage
    GET    /api/v1/connectors/metrics            -- Aggregated metrics per connector
    GET    /api/v1/findings/pending-export       -- Findings pending export (bidirectional)

Security:
    - All endpoints require API key authentication (injected by app.py)
    - Deduplication via SHA-256 content hash prevents duplicate findings
    - Input validated with Pydantic; file uploads size-limited
    - Logging includes connector metadata but never sensitive data
"""

from __future__ import annotations

import hashlib
import logging
import re
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from apps.api.dependencies import get_org_id
from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    UploadFile,
)
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/connectors", tags=["connectors"])

# ──────────────────────────────────────────────────────────────────────────
# Enums
# ──────────────────────────────────────────────────────────────────────────


class SDLCStage(str, Enum):
    """SDLC stages for connector classification."""
    source_code = "source-code"
    build = "build"
    artifact = "artifact"
    deploy_pre = "deploy-pre"
    runtime = "runtime"
    external_supply_chain = "external-supply-chain"


class FindingSeverity(str, Enum):
    """Finding severity levels."""
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class ConnectorStatus(str, Enum):
    """Connector health status."""
    healthy = "healthy"
    degraded = "degraded"
    unhealthy = "unhealthy"
    unknown = "unknown"


# ──────────────────────────────────────────────────────────────────────────
# Request/Response Pydantic Models
# ──────────────────────────────────────────────────────────────────────────


class NormalizedFinding(BaseModel):
    """A finding normalized to ALDECI's canonical format."""

    finding_id: str = Field(..., min_length=1, max_length=256, description="Unique ID from source system")
    title: str = Field(..., min_length=1, max_length=512, description="Finding title/summary")
    description: Optional[str] = Field(None, max_length=10000, description="Detailed description")
    severity: FindingSeverity = Field(..., description="Severity level")
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0, description="CVSS v3 score")
    cvss_vector: Optional[str] = Field(None, max_length=256, description="CVSS v3 vector string")
    cve_ids: List[str] = Field(default_factory=list, description="CVE IDs (e.g. CVE-2024-1234)")
    cwe_ids: List[int] = Field(default_factory=list, description="CWE IDs (e.g. 79, 89)")
    component: Optional[str] = Field(None, max_length=512, description="Affected component/library")
    version: Optional[str] = Field(None, max_length=100, description="Component version")
    file_path: Optional[str] = Field(None, max_length=2048, description="File path in repository")
    line_number: Optional[int] = Field(None, ge=0, description="Line number (if applicable)")
    remediation: Optional[str] = Field(None, max_length=5000, description="Remediation guidance")
    remediation_effort: Optional[str] = Field(
        None,
        pattern="^(low|medium|high)$",
        description="Estimated effort to fix"
    )
    false_positive: bool = Field(default=False, description="Mark as false positive")
    tags: List[str] = Field(default_factory=list, max_length=50, description="Arbitrary tags")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

    @field_validator("cve_ids")
    @classmethod
    def validate_cve_ids(cls, v: List[str]) -> List[str]:
        """Validate CVE ID format (CVE-YYYY-NNNNN+)."""
        if not v:
            return v
        pattern = re.compile(r"^CVE-\d{4}-\d{4,}$")
        for cve in v:
            if not pattern.match(cve):
                raise ValueError(f"Invalid CVE ID format: {cve}. Expected CVE-YYYY-NNNNN...")
        return v


class ConnectorIngestMeta(BaseModel):
    """Metadata about the ingest request."""

    connector_version: str = Field(..., min_length=1, max_length=50, description="Connector version")
    pull_timestamp: datetime = Field(..., description="When findings were pulled from source")
    page_number: Optional[int] = Field(None, ge=1, description="Current page in paginated pull")
    page_size: Optional[int] = Field(None, ge=1, le=1000, description="Findings per page")
    total_pages: Optional[int] = Field(None, ge=1, description="Total pages in pull")
    api_endpoint: Optional[str] = Field(None, max_length=2048, description="Source API endpoint queried")


class IngestPayload(BaseModel):
    """Main request body for POST /api/v1/connectors/ingest."""

    source: str = Field(..., min_length=1, max_length=100, description="Connector name (e.g., 'github', 'jira')")
    findings: List[NormalizedFinding] = Field(..., description="List of normalized findings")
    metadata: ConnectorIngestMeta = Field(..., description="Ingest metadata")

    @field_validator("source")
    @classmethod
    def validate_source(cls, v: str) -> str:
        """Validate connector source name."""
        v = v.strip().lower()
        if not re.match(r"^[a-z0-9][a-z0-9_-]{0,62}$", v):
            raise ValueError(
                "source must be lowercase alphanumeric with hyphens/underscores, "
                "1-63 chars"
            )
        return v


class IngestResult(BaseModel):
    """Response for POST /api/v1/connectors/ingest."""

    ingest_id: str = Field(..., description="Unique ID for this ingest batch")
    source: str = Field(..., description="Connector source name")
    timestamp: datetime = Field(..., description="When ingest was processed")
    accepted_count: int = Field(..., ge=0, description="Number of findings accepted")
    duplicate_count: int = Field(..., ge=0, description="Number of duplicates skipped")
    error_count: int = Field(..., ge=0, description="Number of parsing errors")
    errors: List[Dict[str, Any]] = Field(default_factory=list, description="Error details")
    job_id: str = Field(..., description="Background pipeline job ID")


class RawIngestResult(BaseModel):
    """Response for POST /api/v1/connectors/ingest/raw."""

    ingest_id: str = Field(..., description="Unique ID for this raw ingest")
    scan_type: str = Field(..., description="Scanner type (e.g. 'sarif', 'json')")
    product_name: str = Field(..., description="Product/project name")
    timestamp: datetime = Field(..., description="When ingest was processed")
    parsed_findings_count: int = Field(..., ge=0, description="Number of findings parsed")
    errors: List[str] = Field(default_factory=list, description="Parsing errors")
    defectdojo_import_id: Optional[str] = Field(None, description="DefectDojo import ID (if applicable)")


class ConnectorMetadata(BaseModel):
    """Metadata for a registered connector."""

    name: str = Field(..., description="Connector name")
    display_name: str = Field(..., description="Display name")
    description: str = Field(..., description="Connector description")
    type: str = Field(..., description="Connector type (e.g. 'github', 'jira', 'defectdojo')")
    stages: List[SDLCStage] = Field(..., description="SDLC stages covered")
    status: ConnectorStatus = Field(..., description="Current health status")
    version: str = Field(..., description="Connector version")
    last_pull_time: Optional[datetime] = Field(None, description="Last successful pull timestamp")
    last_pull_findings_count: Optional[int] = Field(None, description="Findings from last pull")
    pull_interval_seconds: Optional[int] = Field(None, description="Recommended pull interval")


class ConnectorRegistryResponse(BaseModel):
    """Response for GET /api/v1/connectors/registry."""

    connectors: List[ConnectorMetadata] = Field(..., description="List of registered connectors")
    total_count: int = Field(..., description="Total number of connectors")


class ConnectorHealth(BaseModel):
    """Health status for a specific connector."""

    name: str = Field(..., description="Connector name")
    status: ConnectorStatus = Field(..., description="Health status")
    timestamp: datetime = Field(..., description="Status check timestamp")
    details: Dict[str, Any] = Field(default_factory=dict, description="Status details")
    last_error: Optional[str] = Field(None, description="Last error message (if unhealthy)")


class PullJobRequest(BaseModel):
    """Request for POST /api/v1/connectors/{name}/pull."""

    since: Optional[datetime] = Field(
        None,
        description="Pull findings modified since this timestamp (optional)"
    )


class PullJobResponse(BaseModel):
    """Response for POST /api/v1/connectors/{name}/pull."""

    job_id: str = Field(..., description="Async pull job ID")
    connector: str = Field(..., description="Connector name")
    timestamp: datetime = Field(..., description="When pull was triggered")
    expected_completion_seconds: Optional[int] = Field(
        None,
        description="Estimated seconds until completion"
    )


class FindingExportTarget(str, Enum):
    """External systems for finding export."""
    jira = "jira"
    github = "github"
    slack = "slack"


class FindingForExport(BaseModel):
    """Finding ready for export to external system."""

    finding_id: str = Field(..., description="ALDECI finding ID")
    source: str = Field(..., description="Original connector source")
    title: str = Field(..., description="Finding title")
    severity: FindingSeverity = Field(..., description="Severity level")
    description: Optional[str] = Field(None, description="Description")
    remediation: Optional[str] = Field(None, description="Remediation guidance")
    external_ids: Dict[str, str] = Field(
        default_factory=dict,
        description="IDs in external systems (e.g. {'jira': 'PROJ-123'})"
    )
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class FindingsForExportResponse(BaseModel):
    """Response for GET /api/v1/findings/pending-export."""

    target: FindingExportTarget = Field(..., description="Target system")
    findings: List[FindingForExport] = Field(..., description="Findings ready to export")
    total_count: int = Field(..., description="Total pending for target")
    since: datetime = Field(..., description="Findings modified since this time")


class ConnectorMetricsEntry(BaseModel):
    """Metrics for a single connector."""

    name: str = Field(..., description="Connector name")
    pull_count_24h: int = Field(..., description="Successful pulls in last 24h")
    pull_count_7d: int = Field(..., description="Successful pulls in last 7d")
    error_count_24h: int = Field(..., description="Errors in last 24h")
    error_count_7d: int = Field(..., description="Errors in last 7d")
    error_rate_24h: float = Field(..., ge=0.0, le=1.0, description="Error rate % (0.0-1.0)")
    findings_ingested_24h: int = Field(..., description="Findings ingested in last 24h")
    findings_ingested_7d: int = Field(..., description="Findings ingested in last 7d")
    last_pull_time: Optional[datetime] = Field(None, description="Last successful pull")
    avg_pull_duration_seconds: Optional[float] = Field(
        None,
        description="Average pull duration"
    )


class ConnectorMetricsResponse(BaseModel):
    """Response for GET /api/v1/connectors/metrics."""

    timestamp: datetime = Field(..., description="When metrics were computed")
    metrics: List[ConnectorMetricsEntry] = Field(..., description="Per-connector metrics")
    total_pulls_24h: int = Field(..., description="Total pulls across all connectors")
    total_findings_ingested_24h: int = Field(..., description="Total findings ingested")
    overall_error_rate: float = Field(..., ge=0.0, le=1.0, description="Overall error rate")


# ──────────────────────────────────────────────────────────────────────────
# In-Memory Stores (replace with persistent DB in production)
# ──────────────────────────────────────────────────────────────────────────

# Deduplication: (source, finding_id) -> sha256 hash
_dedup_cache: Dict[str, str] = {}

# Connector registry (replace with database query in production)
_connector_registry: Dict[str, ConnectorMetadata] = {
    "github": ConnectorMetadata(
        name="github",
        display_name="GitHub",
        description="GitHub repository code scanning and secret detection",
        type="github",
        stages=[SDLCStage.source_code, SDLCStage.build],
        status=ConnectorStatus.healthy,
        version="1.0.0",
        pull_interval_seconds=3600,
    ),
    "jira": ConnectorMetadata(
        name="jira",
        display_name="Jira",
        description="Jira issue tracking integration",
        type="jira",
        stages=[SDLCStage.deploy_pre, SDLCStage.runtime],
        status=ConnectorStatus.healthy,
        version="1.0.0",
    ),
    "defectdojo": ConnectorMetadata(
        name="defectdojo",
        display_name="DefectDojo",
        description="DAST, SAST, and scanner format parsing",
        type="defectdojo",
        stages=[
            SDLCStage.build,
            SDLCStage.artifact,
            SDLCStage.deploy_pre,
            SDLCStage.runtime,
        ],
        status=ConnectorStatus.healthy,
        version="1.0.0",
        pull_interval_seconds=1800,
    ),
}

# Metrics store (replace with time-series DB in production)
_metrics_store: Dict[str, Dict[str, int]] = {
    connector_name: {
        "pull_count_24h": 0,
        "pull_count_7d": 0,
        "error_count_24h": 0,
        "error_count_7d": 0,
        "findings_ingested_24h": 0,
        "findings_ingested_7d": 0,
    }
    for connector_name in _connector_registry.keys()
}


# ──────────────────────────────────────────────────────────────────────────
# Helper Functions
# ──────────────────────────────────────────────────────────────────────────


def _compute_content_hash(source: str, finding_id: str, title: str) -> str:
    """Compute SHA-256 hash for deduplication.

    Hash includes source, finding_id, and title to detect duplicate findings
    across multiple ingest cycles.
    """
    content = f"{source}#{finding_id}#{title}"
    return hashlib.sha256(content.encode()).hexdigest()


def _is_duplicate(source: str, finding: NormalizedFinding) -> bool:
    """Check if finding is a duplicate."""
    content_hash = _compute_content_hash(source, finding.finding_id, finding.title)
    cache_key = f"{source}#{finding.finding_id}"

    if cache_key in _dedup_cache:
        return _dedup_cache[cache_key] == content_hash

    _dedup_cache[cache_key] = content_hash
    return False


def _route_to_pipeline(
    source: str,
    findings: List[NormalizedFinding],
    metadata: ConnectorIngestMeta,
    org_id: str
) -> str:
    """Route findings through the ALDECI pipeline.

    This is a placeholder for the actual pipeline routing logic.
    In production, this would:
    1. Normalize and enrich findings
    2. Apply deduplication, derating, false positive detection
    3. Create/update findings in ALDECI database
    4. Trigger workflows for high-severity findings
    5. Update connector metrics

    Returns: Job ID for async tracking.
    """
    job_id = str(uuid.uuid4())
    logger.info(
        "Routed %d findings from %s to pipeline (job_id=%s, org_id=%s)",
        len(findings),
        source,
        job_id,
        org_id,
    )

    # Update metrics
    if source in _metrics_store:
        _metrics_store[source]["findings_ingested_24h"] += len(findings)
        _metrics_store[source]["findings_ingested_7d"] += len(findings)
        _metrics_store[source]["pull_count_24h"] += 1
        _metrics_store[source]["pull_count_7d"] += 1

    return job_id


async def _trigger_defectdojo_parse(
    scan_type: str,
    product_name: str,
    file_content: bytes,
    org_id: str
) -> str:
    """Trigger DefectDojo async parsing of scanner file.

    This is a placeholder that would POST to DefectDojo /api/v2/importer/
    endpoint to trigger async parsing. Returns the import ID.
    """
    import_id = str(uuid.uuid4())
    logger.info(
        "Triggered DefectDojo parse (import_id=%s, scan_type=%s, product=%s, org_id=%s)",
        import_id,
        scan_type,
        product_name,
        org_id,
    )
    return import_id


# ──────────────────────────────────────────────────────────────────────────
# Endpoints
# ──────────────────────────────────────────────────────────────────────────


@router.post("/ingest", response_model=IngestResult, status_code=202)
async def ingest_findings(
    payload: IngestPayload,
    background_tasks: BackgroundTasks,
    org_id: str = Depends(get_org_id),
) -> IngestResult:
    """Ingest normalized findings from a connector.

    This is the primary entry point for n8n workflows and custom connectors
    to submit findings in ALDECI's canonical format. Validates schema,
    performs deduplication via content hash, and routes through the pipeline
    in a background task.

    Args:
        payload: IngestPayload with source, findings list, and metadata
        background_tasks: FastAPI background task executor
        org_id: Organization ID (from API key auth)

    Returns:
        IngestResult with accepted/duplicate/error counts and job ID

    Status Codes:
        202 Accepted: Findings queued for processing
        400 Bad Request: Invalid payload
        401 Unauthorized: Invalid API key
        429 Too Many Requests: Rate limit exceeded
        500 Internal Server Error: Pipeline error
    """
    ingest_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    logger.info(
        "Received ingest from connector=%s, finding_count=%d, org_id=%s",
        payload.source,
        len(payload.findings),
        org_id,
    )

    accepted: List[NormalizedFinding] = []
    duplicate_count = 0
    errors: List[Dict[str, Any]] = []

    # Deduplication pass
    for finding in payload.findings:
        try:
            if _is_duplicate(payload.source, finding):
                duplicate_count += 1
                logger.debug(
                    "Skipped duplicate finding: source=%s, finding_id=%s",
                    payload.source,
                    finding.finding_id,
                )
            else:
                accepted.append(finding)
        except (ValueError, KeyError, AttributeError, TypeError) as e:
            error_detail = {
                "finding_id": finding.finding_id,
                "error": str(e),
                "type": type(e).__name__,
            }
            errors.append(error_detail)
            logger.warning("Error processing finding: %s", error_detail)

    # Queue background pipeline routing
    job_id = _route_to_pipeline(
        source=payload.source,
        findings=accepted,
        metadata=payload.metadata,
        org_id=org_id,
    )

    # Background task for actual pipeline processing
    background_tasks.add_task(
        _route_to_pipeline,
        payload.source,
        accepted,
        payload.metadata,
        org_id,
    )

    logger.info(
        "Ingest processed: ingest_id=%s, accepted=%d, duplicates=%d, errors=%d, job_id=%s",
        ingest_id,
        len(accepted),
        duplicate_count,
        len(errors),
        job_id,
    )

    return IngestResult(
        ingest_id=ingest_id,
        source=payload.source,
        timestamp=now,
        accepted_count=len(accepted),
        duplicate_count=duplicate_count,
        error_count=len(errors),
        errors=errors,
        job_id=job_id,
    )


@router.post("/ingest/raw", response_model=RawIngestResult, status_code=202)
async def ingest_raw(
    file: UploadFile = File(...),
    scan_type: str = Form(...),
    product_name: str = Form(...),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    org_id: str = Depends(get_org_id),
) -> RawIngestResult:
    """Ingest raw scanner output files.

    Accepts scanner files in various formats (JSON, XML, SARIF, etc.) and routes
    through DefectDojo for parsing into normalized findings. Supports multipart
    file upload.

    Args:
        file: Scanner output file (max 100MB)
        scan_type: Scanner type (e.g., 'sarif', 'json', 'nessus', 'burp')
        product_name: Product/project name for grouping
        org_id: Organization ID

    Returns:
        RawIngestResult with parsed finding count and DefectDojo import ID

    Status Codes:
        202 Accepted: File queued for parsing
        400 Bad Request: Invalid scan_type or product_name
        413 Payload Too Large: File exceeds 100MB limit
        422 Unprocessable Entity: File parsing failed
        500 Internal Server Error: DefectDojo error
    """
    ingest_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    # Validate file size (100MB limit)
    max_file_size = 100 * 1024 * 1024  # 100MB
    file_content = await file.read()
    if len(file_content) > max_file_size:
        raise HTTPException(
            status_code=413,
            detail=f"File size {len(file_content)} bytes exceeds 100MB limit"
        )

    logger.info(
        "Received raw ingest: ingest_id=%s, scan_type=%s, product=%s, "
        "file_size=%d bytes, org_id=%s",
        ingest_id,
        scan_type,
        product_name,
        len(file_content),
        org_id,
    )

    # Trigger DefectDojo parsing (background)
    import_id = await _trigger_defectdojo_parse(
        scan_type=scan_type,
        product_name=product_name,
        file_content=file_content,
        org_id=org_id,
    )

    # Update metrics
    if "defectdojo" in _metrics_store:
        _metrics_store["defectdojo"]["pull_count_24h"] += 1
        _metrics_store["defectdojo"]["pull_count_7d"] += 1

    return RawIngestResult(
        ingest_id=ingest_id,
        scan_type=scan_type,
        product_name=product_name,
        timestamp=now,
        parsed_findings_count=0,  # Will be updated when DefectDojo finishes
        defectdojo_import_id=import_id,
    )


@router.get("/registry", response_model=ConnectorRegistryResponse)
async def list_connectors(
    org_id: str = Depends(get_org_id),
) -> ConnectorRegistryResponse:
    """List all registered connectors with health status.

    Returns metadata and health status for all connectors available to the
    organization, including version, SDLC stages covered, and last pull metrics.

    Args:
        org_id: Organization ID

    Returns:
        ConnectorRegistryResponse with list of connector metadata
    """
    logger.info("Listed connectors for org_id=%s", org_id)

    return ConnectorRegistryResponse(
        connectors=list(_connector_registry.values()),
        total_count=len(_connector_registry),
    )


@router.get("/{name}/health", response_model=ConnectorHealth)
async def get_connector_health(
    name: str,
    org_id: str = Depends(get_org_id),
) -> ConnectorHealth:
    """Get health status for a specific connector.

    Performs a health check on the connector (if applicable) and returns
    current status, last error, and diagnostic details.

    Args:
        name: Connector name
        org_id: Organization ID

    Returns:
        ConnectorHealth with status and details

    Status Codes:
        200 OK: Health check succeeded
        404 Not Found: Connector not found
    """
    if name not in _connector_registry:
        raise HTTPException(
            status_code=404,
            detail=f"Connector '{name}' not found"
        )

    metadata = _connector_registry[name]

    logger.info(
        "Health check for connector=%s, status=%s, org_id=%s",
        name,
        metadata.status,
        org_id,
    )

    return ConnectorHealth(
        name=name,
        status=metadata.status,
        timestamp=datetime.now(timezone.utc),
        details={
            "version": metadata.version,
            "last_pull_time": metadata.last_pull_time,
            "last_pull_findings_count": metadata.last_pull_findings_count,
        },
    )


@router.post("/{name}/pull", response_model=PullJobResponse, status_code=202)
async def trigger_connector_pull(
    name: str,
    request: Optional[PullJobRequest] = None,
    background_tasks: BackgroundTasks = BackgroundTasks(),
    org_id: str = Depends(get_org_id),
) -> PullJobResponse:
    """Trigger an on-demand pull for a specific connector.

    Queues an async pull job for the connector. Can optionally pull only
    findings modified since a specific timestamp (for incremental pulls).

    Args:
        name: Connector name
        request: Optional PullJobRequest with since parameter
        background_tasks: FastAPI background task executor
        org_id: Organization ID

    Returns:
        PullJobResponse with job ID and estimated completion time

    Status Codes:
        202 Accepted: Pull job queued
        404 Not Found: Connector not found
        409 Conflict: Another pull already in progress
        500 Internal Server Error: Pull error
    """
    if name not in _connector_registry:
        raise HTTPException(
            status_code=404,
            detail=f"Connector '{name}' not found"
        )

    job_id = str(uuid.uuid4())
    since = request.since if request else None

    logger.info(
        "Triggered pull for connector=%s, job_id=%s, since=%s, org_id=%s",
        name,
        job_id,
        since,
        org_id,
    )

    # Update metrics
    if name in _metrics_store:
        _metrics_store[name]["pull_count_24h"] += 1
        _metrics_store[name]["pull_count_7d"] += 1

    return PullJobResponse(
        job_id=job_id,
        connector=name,
        timestamp=datetime.now(timezone.utc),
        expected_completion_seconds=300,  # Placeholder
    )


@router.get("/stages/{stage}", response_model=List[ConnectorMetadata])
async def list_connectors_by_stage(
    stage: SDLCStage,
    org_id: str = Depends(get_org_id),
) -> List[ConnectorMetadata]:
    """List connectors registered for a specific SDLC stage.

    Returns all connectors that cover the given SDLC stage (e.g., source-code,
    build, artifact, deploy-pre, runtime, external-supply-chain).

    Args:
        stage: SDLC stage
        org_id: Organization ID

    Returns:
        List of ConnectorMetadata for connectors covering the stage
    """
    matching_connectors = [
        connector for connector in _connector_registry.values()
        if stage in connector.stages
    ]

    logger.info(
        "Listed connectors for stage=%s, count=%d, org_id=%s",
        stage.value,
        len(matching_connectors),
        org_id,
    )

    return matching_connectors


@router.get("/findings/pending-export", response_model=FindingsForExportResponse)
async def get_pending_export_findings(
    target: FindingExportTarget = Query(..., description="Target system (jira, github, slack)"),
    limit: int = Query(100, ge=1, le=1000, description="Max findings to return"),
    since: Optional[datetime] = Query(None, description="Findings modified since this time"),
    org_id: str = Depends(get_org_id),
) -> FindingsForExportResponse:
    """Get findings pending export to external systems (bidirectional workflows).

    Returns findings that are ready to be exported to external systems (Jira, GitHub, Slack).
    Used by n8n bidirectional workflows to keep external systems in sync.

    Args:
        target: Target system for export (jira, github, slack)
        limit: Max findings to return
        since: Only return findings modified after this time
        org_id: Organization ID

    Returns:
        FindingsForExportResponse with list of findings ready for export
    """
    if since is None:
        since = datetime.now(timezone.utc) - timedelta(hours=24)

    logger.info(
        "Queried pending exports: target=%s, since=%s, limit=%d, org_id=%s",
        target.value,
        since,
        limit,
        org_id,
    )

    # Placeholder: in production, query findings database for those needing export
    findings_for_export: List[FindingForExport] = []

    return FindingsForExportResponse(
        target=target,
        findings=findings_for_export,
        total_count=len(findings_for_export),
        since=since,
    )


@router.get("/metrics", response_model=ConnectorMetricsResponse)
async def get_connector_metrics(
    org_id: str = Depends(get_org_id),
) -> ConnectorMetricsResponse:
    """Get aggregated connector metrics (pulls, findings, error rates).

    Returns per-connector metrics for the last 24h and 7d, including pull counts,
    error rates, findings ingested, and average pull duration. Used for
    monitoring connector health and throughput.

    Args:
        org_id: Organization ID

    Returns:
        ConnectorMetricsResponse with per-connector metrics
    """
    now = datetime.now(timezone.utc)

    metrics_entries: List[ConnectorMetricsEntry] = []
    total_pulls_24h = 0
    total_findings_24h = 0
    total_errors_24h = 0

    for connector_name, metrics in _metrics_store.items():
        pull_24h = metrics.get("pull_count_24h", 0)
        error_24h = metrics.get("error_count_24h", 0)
        findings_24h = metrics.get("findings_ingested_24h", 0)

        error_rate = (
            error_24h / (pull_24h + error_24h)
            if (pull_24h + error_24h) > 0
            else 0.0
        )

        entry = ConnectorMetricsEntry(
            name=connector_name,
            pull_count_24h=pull_24h,
            pull_count_7d=metrics.get("pull_count_7d", 0),
            error_count_24h=error_24h,
            error_count_7d=metrics.get("error_count_7d", 0),
            error_rate_24h=error_rate,
            findings_ingested_24h=findings_24h,
            findings_ingested_7d=metrics.get("findings_ingested_7d", 0),
        )
        metrics_entries.append(entry)

        total_pulls_24h += pull_24h
        total_findings_24h += findings_24h
        total_errors_24h += error_24h

    overall_error_rate = (
        total_errors_24h / (total_pulls_24h + total_errors_24h)
        if (total_pulls_24h + total_errors_24h) > 0
        else 0.0
    )

    logger.info(
        "Fetched connector metrics: timestamp=%s, connectors=%d, "
        "total_pulls_24h=%d, total_findings_24h=%d, org_id=%s",
        now,
        len(metrics_entries),
        total_pulls_24h,
        total_findings_24h,
        org_id,
    )

    return ConnectorMetricsResponse(
        timestamp=now,
        metrics=metrics_entries,
        total_pulls_24h=total_pulls_24h,
        total_findings_ingested_24h=total_findings_24h,
        overall_error_rate=overall_error_rate,
    )
