"""
Audit Log Analytics API endpoints.

8 endpoints under /api/v1/audit-analytics:
  POST   /ingest              — ingest a single log line
  POST   /ingest/batch        — ingest multiple log lines
  GET    /search              — full-text + field-based search
  GET    /anomalies           — list detected anomalies
  POST   /anomalies/detect    — trigger on-demand anomaly detection
  GET    /compliance-trail    — SOC2/HIPAA who-did-what-when trail
  GET    /retention-policy    — get current retention policy
  PUT    /retention-policy    — upsert retention policy
  POST   /retention/apply     — run retention policy (archive/delete)
  GET    /timeline            — build forensic timeline

Compliance: SOC2 CC7.2, HIPAA §164.312(b)
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from apps.api.dependencies import get_org_id
from core.audit_analytics import (
    AuditAnalyticsEngine,
    AuditAnomaly,
    AuditEntry,
    ForensicTimeline,
    LogFormat,
    RetentionPolicy,
    RetentionReport,
    SearchResult,
)
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/audit-analytics", tags=["audit-analytics"])

# Module-level engine instance (SQLite path relative to process cwd)
_engine = None  # lazy-initialised on first request


def _get_engine():
    global _engine
    if _engine is None:
        _engine = AuditAnalyticsEngine()
    return _engine


# ============================================================================
# REQUEST / RESPONSE SCHEMAS
# ============================================================================


class IngestRequest(BaseModel):
    """Single log-line ingestion request."""

    raw: str = Field(..., description="Raw log line to ingest")
    format: LogFormat = Field(LogFormat.JSON, description="Wire format of the log line")
    org_id: Optional[str] = Field(None, description="Override org_id (defaults to authenticated org)")


class IngestBatchRequest(BaseModel):
    """Batch log ingestion request."""

    lines: List[str] = Field(..., description="List of raw log lines", min_length=1)
    format: LogFormat = Field(LogFormat.JSON, description="Wire format shared by all lines")
    run_anomaly_detection: bool = Field(True, description="Run anomaly detection on the batch")
    org_id: Optional[str] = Field(None)


class IngestResponse(BaseModel):
    """Response after a single-line ingestion."""

    entry_id: str
    org_id: str
    timestamp: str
    severity: str
    actor: str
    action: str
    checksum: str


class IngestBatchResponse(BaseModel):
    """Response after batch ingestion."""

    ingested: int
    anomalies_detected: int
    anomaly_ids: List[str] = Field(default_factory=list)


class AuditEntryOut(BaseModel):
    """Serialisable audit entry."""

    id: str
    org_id: str
    timestamp: str
    source_format: str
    severity: str
    actor: str
    actor_ip: str
    action: str
    resource_type: str
    resource_id: str
    outcome: str
    status: str
    checksum: str
    details: Dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_entry(cls, e: AuditEntry) -> "AuditEntryOut":
        return cls(
            id=e.id,
            org_id=e.org_id,
            timestamp=e.timestamp.isoformat(),
            source_format=e.source_format.value,
            severity=e.severity.value,
            actor=e.actor,
            actor_ip=e.actor_ip,
            action=e.action,
            resource_type=e.resource_type,
            resource_id=e.resource_id,
            outcome=e.outcome,
            status=e.status.value,
            checksum=e.checksum,
            details=e.details,
        )


class SearchResponse(BaseModel):
    """Paginated search response."""

    items: List[AuditEntryOut]
    total: int
    limit: int
    offset: int
    query: str


class AnomalyOut(BaseModel):
    """Serialisable anomaly record."""

    id: str
    org_id: str
    kind: str
    severity: str
    actor: str
    description: str
    entry_ids: List[str]
    detected_at: str
    details: Dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_anomaly(cls, a: AuditAnomaly) -> "AnomalyOut":
        return cls(
            id=a.id,
            org_id=a.org_id,
            kind=a.kind.value,
            severity=a.severity.value,
            actor=a.actor,
            description=a.description,
            entry_ids=a.entry_ids,
            detected_at=a.detected_at.isoformat(),
            details=a.details,
        )


class AnomalyListResponse(BaseModel):
    items: List[AnomalyOut]
    total: int
    limit: int
    offset: int


class DetectAnomaliesRequest(BaseModel):
    """On-demand anomaly detection trigger."""

    start: Optional[datetime] = Field(None, description="Start of window (ISO-8601)")
    end: Optional[datetime] = Field(None, description="End of window (ISO-8601)")
    org_id: Optional[str] = None


class DetectAnomaliesResponse(BaseModel):
    anomalies: List[AnomalyOut]
    count: int


class RetentionPolicyIn(BaseModel):
    """Retention policy upsert payload."""

    archive_after_days: int = Field(90, ge=1, le=36500)
    delete_after_days: int = Field(365, ge=1, le=36500)
    legal_hold_actor_ids: List[str] = Field(default_factory=list)


class RetentionPolicyOut(BaseModel):
    org_id: str
    archive_after_days: int
    delete_after_days: int
    legal_hold_actor_ids: List[str]


class RetentionReportOut(BaseModel):
    org_id: str
    archived: int
    deleted: int
    held: int
    skipped: int
    run_at: str


class TimelineRequest(BaseModel):
    """Forensic timeline build request."""

    query: str = Field(..., description="FTS5-compatible search query")
    start: datetime
    end: datetime
    limit: int = Field(500, ge=1, le=5000)
    org_id: Optional[str] = None


class TimelineEventOut(BaseModel):
    timestamp: str
    actor: str
    action: str
    resource_type: str
    resource_id: str
    outcome: str
    severity: str
    entry_id: str
    details: Dict[str, Any] = Field(default_factory=dict)


class ForensicTimelineOut(BaseModel):
    query: str
    start: str
    end: str
    total: int
    actors: List[str]
    resources: List[str]
    events: List[TimelineEventOut]


# ============================================================================
# HELPERS
# ============================================================================


def _entry_out(e: AuditEntry) -> AuditEntryOut:
    return AuditEntryOut.from_entry(e)


def _anomaly_out(a: AuditAnomaly) -> AnomalyOut:
    return AnomalyOut.from_anomaly(a)


def _parse_dt(value: Optional[str], default: Optional[datetime] = None) -> Optional[datetime]:
    """Parse an ISO-8601 string to datetime; returns *default* on failure."""
    if value is None:
        return default
    try:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return default


# ============================================================================
# ENDPOINTS
# ============================================================================


@router.post("/ingest", response_model=IngestResponse, status_code=201)
async def ingest_log(
    body: IngestRequest,
    org_id: str = Depends(get_org_id),
) -> IngestResponse:
    """
    Ingest a single raw log line.

    Supported formats: json, syslog, cef, leef.
    The line is parsed, normalised, and persisted immediately.
    """
    effective_org = body.org_id or org_id
    try:
        entry = _get_engine().ingest(body.raw, body.format, org_id=effective_org)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Parse error: {exc}") from exc

    return IngestResponse(
        entry_id=entry.id,
        org_id=entry.org_id,
        timestamp=entry.timestamp.isoformat(),
        severity=entry.severity.value,
        actor=entry.actor,
        action=entry.action,
        checksum=entry.checksum,
    )


@router.post("/ingest/batch", response_model=IngestBatchResponse, status_code=201)
async def ingest_batch(
    body: IngestBatchRequest,
    org_id: str = Depends(get_org_id),
) -> IngestBatchResponse:
    """
    Ingest multiple raw log lines in a single call.

    Optionally runs anomaly detection over the batch after ingestion.
    All lines must share the same wire format.
    """
    effective_org = body.org_id or org_id
    try:
        entries, anomalies = _get_engine().ingest_batch(
            lines=body.lines,
            fmt=body.format,
            org_id=effective_org,
            run_anomaly_detection=body.run_anomaly_detection,
        )
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Batch ingest error: {exc}") from exc

    return IngestBatchResponse(
        ingested=len(entries),
        anomalies_detected=len(anomalies),
        anomaly_ids=[a.id for a in anomalies],
    )


@router.get("/search", response_model=SearchResponse)
async def search_logs(
    org_id: str = Depends(get_org_id),
    q: str = Query("", description="Full-text search query (FTS5)"),
    actor: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    resource_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None, description="debug|info|warning|error|critical"),
    outcome: Optional[str] = Query(None, description="success|failure"),
    status: Optional[str] = Query(None, description="active|archived|legal_hold"),
    start: Optional[str] = Query(None, description="ISO-8601 start timestamp"),
    end: Optional[str] = Query(None, description="ISO-8601 end timestamp"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> SearchResponse:
    """
    Search audit log entries.

    Combines FTS5 full-text search with structured field filters.
    All filters are ANDed together.
    """
    result: SearchResult = _get_engine().search(
        query=q,
        actor=actor,
        action=action,
        resource_type=resource_type,
        severity=severity,
        outcome=outcome,
        status=status,
        start=_parse_dt(start),
        end=_parse_dt(end),
        limit=limit,
        offset=offset,
        org_id=org_id,
    )
    return SearchResponse(
        items=[_entry_out(e) for e in result.items],
        total=result.total,
        limit=result.limit,
        offset=result.offset,
        query=result.query,
    )


@router.get("/anomalies", response_model=AnomalyListResponse)
async def list_anomalies(
    org_id: str = Depends(get_org_id),
    kind: Optional[str] = Query(None, description="off_hours_access|privilege_escalation|…"),
    severity: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> AnomalyListResponse:
    """List previously detected anomalies."""
    items, total = _get_engine().list_anomalies(
        kind=kind, severity=severity, limit=limit, offset=offset, org_id=org_id
    )
    return AnomalyListResponse(
        items=[_anomaly_out(a) for a in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post("/anomalies/detect", response_model=DetectAnomaliesResponse)
async def detect_anomalies(
    body: DetectAnomaliesRequest,
    org_id: str = Depends(get_org_id),
) -> DetectAnomaliesResponse:
    """
    Trigger on-demand anomaly detection over stored entries.

    Scans entries within the optional [start, end] window, applies all
    detection rules, persists new anomalies, and returns them.
    """
    effective_org = body.org_id or org_id
    anomalies = _get_engine().detect_anomalies(
        start=body.start, end=body.end, org_id=effective_org
    )
    return DetectAnomaliesResponse(
        anomalies=[_anomaly_out(a) for a in anomalies],
        count=len(anomalies),
    )


@router.get("/compliance-trail", response_model=SearchResponse)
async def compliance_trail(
    org_id: str = Depends(get_org_id),
    actor: Optional[str] = Query(None, description="Filter by user/service actor"),
    resource_type: Optional[str] = Query(None, description="Filter by resource type"),
    start: Optional[str] = Query(None, description="ISO-8601 start timestamp"),
    end: Optional[str] = Query(None, description="ISO-8601 end timestamp"),
    limit: int = Query(1000, ge=1, le=5000),
    offset: int = Query(0, ge=0),
) -> SearchResponse:
    """
    SOC2 / HIPAA compliance audit trail — who did what when.

    Returns a time-ordered record of all actions matching the filters,
    suitable for compliance reporting and evidence collection.
    """
    result: SearchResult = _get_engine().compliance_trail(
        actor=actor,
        resource_type=resource_type,
        start=_parse_dt(start),
        end=_parse_dt(end),
        limit=limit,
        org_id=org_id,
    )
    return SearchResponse(
        items=[_entry_out(e) for e in result.items],
        total=result.total,
        limit=result.limit,
        offset=result.offset,
        query="",
    )


@router.get("/retention-policy", response_model=RetentionPolicyOut)
async def get_retention_policy(
    org_id: str = Depends(get_org_id),
) -> RetentionPolicyOut:
    """Get the current retention policy for the authenticated org."""
    policy = _get_engine().get_retention_policy(org_id=org_id)
    return RetentionPolicyOut(
        org_id=policy.org_id,
        archive_after_days=policy.archive_after_days,
        delete_after_days=policy.delete_after_days,
        legal_hold_actor_ids=policy.legal_hold_actor_ids,
    )


@router.put("/retention-policy", response_model=RetentionPolicyOut)
async def upsert_retention_policy(
    body: RetentionPolicyIn,
    org_id: str = Depends(get_org_id),
) -> RetentionPolicyOut:
    """
    Create or update the retention policy for the authenticated org.

    - archive_after_days: entries older than this are marked archived (default 90)
    - delete_after_days:  entries older than this are permanently deleted (default 365)
    - legal_hold_actor_ids: actors whose entries are exempt from deletion
    """
    if body.delete_after_days <= body.archive_after_days:
        raise HTTPException(
            status_code=422,
            detail="delete_after_days must be greater than archive_after_days",
        )
    policy = RetentionPolicy(
        org_id=org_id,
        archive_after_days=body.archive_after_days,
        delete_after_days=body.delete_after_days,
        legal_hold_actor_ids=body.legal_hold_actor_ids,
    )
    _get_engine().set_retention_policy(policy)
    return RetentionPolicyOut(
        org_id=policy.org_id,
        archive_after_days=policy.archive_after_days,
        delete_after_days=policy.delete_after_days,
        legal_hold_actor_ids=policy.legal_hold_actor_ids,
    )


@router.post("/retention/apply", response_model=RetentionReportOut)
async def apply_retention(
    org_id: str = Depends(get_org_id),
) -> RetentionReportOut:
    """
    Apply the retention policy for the authenticated org immediately.

    Entries older than archive_after_days are archived.
    Entries older than delete_after_days are deleted.
    Entries belonging to legal-hold actors are marked as legal_hold.
    Returns a summary report.
    """
    report: RetentionReport = _get_engine().apply_retention(org_id=org_id)
    return RetentionReportOut(
        org_id=report.org_id,
        archived=report.archived,
        deleted=report.deleted,
        held=report.held,
        skipped=report.skipped,
        run_at=report.run_at.isoformat(),
    )


@router.post("/timeline", response_model=ForensicTimelineOut)
async def build_forensic_timeline(
    body: TimelineRequest,
    org_id: str = Depends(get_org_id),
) -> ForensicTimelineOut:
    """
    Build a forensic timeline of audit events matching *query* within [start, end].

    Returns events in chronological order, plus actor and resource summaries.
    Useful for incident investigation and post-mortem analysis.
    """
    effective_org = body.org_id or org_id
    timeline: ForensicTimeline = _get_engine().build_timeline(
        query=body.query,
        start=body.start,
        end=body.end,
        limit=body.limit,
        org_id=effective_org,
    )
    events_out = [
        TimelineEventOut(
            timestamp=ev.timestamp.isoformat(),
            actor=ev.actor,
            action=ev.action,
            resource_type=ev.resource_type,
            resource_id=ev.resource_id,
            outcome=ev.outcome,
            severity=ev.severity.value,
            entry_id=ev.entry_id,
            details=ev.details,
        )
        for ev in timeline.events
    ]
    return ForensicTimelineOut(
        query=timeline.query,
        start=timeline.start.isoformat(),
        end=timeline.end.isoformat(),
        total=timeline.total,
        actors=timeline.actors,
        resources=timeline.resources,
        events=events_out,
    )
