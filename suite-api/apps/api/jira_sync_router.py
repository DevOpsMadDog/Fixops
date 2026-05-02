"""
ALDECI Jira Bidirectional Sync API Router.

Provides REST endpoints for configuring and operating the Jira sync engine.

Endpoints:
  POST /api/v1/jira-sync/configure        — set Jira connection + sync config
  POST /api/v1/jira-sync/sync-all         — sync all provided findings to Jira
  POST /api/v1/jira-sync/sync-finding     — sync a single finding to Jira
  POST /api/v1/jira-sync/sync-status      — propagate a finding status to Jira
  GET  /api/v1/jira-sync/field-mapping    — retrieve field mapping config
  PUT  /api/v1/jira-sync/field-mapping    — update field mapping config
  GET  /api/v1/jira-sync/history          — paginated sync history
  GET  /api/v1/jira-sync/stats            — sync statistics
  POST /api/v1/jira-sync/webhooks         — receive Jira webhook events
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/jira-sync",
    tags=["jira-sync"],
    dependencies=[Depends(api_key_auth)],
)

# Webhook endpoint intentionally has NO auth dependency — Jira signs its own
# payloads. The engine validates the secret if configured.
webhook_router = APIRouter(
    prefix="/api/v1/jira-sync",
    tags=["jira-sync"],
)

# ---------------------------------------------------------------------------
# Lazy singleton
# ---------------------------------------------------------------------------


def _get_engine():
    from core.jira_sync import get_jira_sync_engine
    return get_jira_sync_engine()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class FieldMappingItem(BaseModel):
    finding_field: str = Field(..., description="Field name in the ALDECI finding dict")
    jira_field: str = Field(..., description="Field name in the Jira issue fields dict")
    transform: Optional[str] = Field(None, description="Optional transform key")


class ConfigureRequest(BaseModel):
    """Configure the Jira sync engine."""
    jira_url: str = Field(..., description="Jira base URL, e.g. https://example.atlassian.net")
    user_email: str = Field(..., description="Jira user email for API auth")
    api_token: str = Field(..., description="Jira API token or PAT")
    project_key: str = Field(..., description="Jira project key, e.g. SEC")
    default_issue_type: str = Field("Bug", description="Default Jira issue type")
    sync_direction: str = Field("bidirectional", description="bidirectional | finding_to_jira | jira_to_finding")
    conflict_resolution: str = Field("newest_wins", description="newest_wins | jira_wins | finding_wins | manual")
    labels: List[str] = Field(default_factory=lambda: ["aldeci", "security"])
    component_name: Optional[str] = Field(None, description="Jira component name to assign")
    webhook_secret: Optional[str] = Field(None, description="Secret for validating Jira webhook calls")
    field_mappings: List[FieldMappingItem] = Field(default_factory=list)
    jira_to_finding_status: Optional[Dict[str, str]] = Field(
        None, description="Override Jira status → finding status mapping"
    )
    finding_to_jira_transition: Optional[Dict[str, str]] = Field(
        None, description="Override finding status → Jira transition name mapping"
    )
    severity_to_priority: Optional[Dict[str, str]] = Field(
        None, description="Override severity → Jira priority mapping"
    )


class SyncFindingRequest(BaseModel):
    finding_id: str = Field(..., description="Unique finding identifier")
    finding_data: Dict[str, Any] = Field(
        ..., description="Finding fields: title, severity, description, cve_id, source, etc."
    )


class SyncAllRequest(BaseModel):
    findings: List[Dict[str, Any]] = Field(
        ..., description="List of finding dicts, each with a finding_id or id field"
    )


class SyncStatusRequest(BaseModel):
    finding_id: str = Field(..., description="Finding to update")
    new_status: str = Field(..., description="New finding status, e.g. resolved, closed, in_progress")


class FieldMappingUpdateRequest(BaseModel):
    mappings: List[FieldMappingItem] = Field(..., description="New field mapping list (replaces existing)")


class ConfigureResponse(BaseModel):
    success: bool
    configured: bool
    project_key: str
    sync_direction: str
    conflict_resolution: str


class SyncResultResponse(BaseModel):
    finding_id: str
    jira_issue_key: Optional[str]
    status: str
    direction: str
    detail: Dict[str, Any]
    synced_at: str


class SyncAllResponse(BaseModel):
    total: int
    succeeded: int
    failed: int
    skipped: int
    results: List[SyncResultResponse]


class HistoryEntry(BaseModel):
    record_id: str
    finding_id: str
    jira_issue_key: Optional[str]
    direction: str
    status: str
    detail: Dict[str, Any]
    synced_at: str


class StatsResponse(BaseModel):
    total_links: int
    total_sync_events: int
    by_status: Dict[str, int]
    by_direction: Dict[str, int]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/configure",
    response_model=ConfigureResponse,
    summary="Configure Jira sync engine",
)
def configure(req: ConfigureRequest):
    """
    Set (and persist) the Jira connection configuration and sync policy.

    The configuration is stored in the sync engine's SQLite database and
    survives process restarts.
    """
    from core.jira_sync import (
        ConflictResolution,
        FieldMapping,
        JiraSyncConfig,
        SyncDirection,
    )

    try:
        sync_dir = SyncDirection(req.sync_direction)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid sync_direction: '{req.sync_direction}'. "
                   f"Valid values: {[d.value for d in SyncDirection]}",
        )

    try:
        conflict = ConflictResolution(req.conflict_resolution)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid conflict_resolution: '{req.conflict_resolution}'. "
                   f"Valid values: {[c.value for c in ConflictResolution]}",
        )

    from core.jira_sync import (
        _DEFAULT_FINDING_TO_JIRA_TRANSITION,
        _DEFAULT_JIRA_TO_FINDING_STATUS,
        _DEFAULT_SEVERITY_TO_PRIORITY,
    )

    cfg = JiraSyncConfig(
        jira_url=req.jira_url,
        user_email=req.user_email,
        api_token=req.api_token,
        project_key=req.project_key,
        default_issue_type=req.default_issue_type,
        sync_direction=sync_dir,
        conflict_resolution=conflict,
        labels=req.labels,
        component_name=req.component_name,
        webhook_secret=req.webhook_secret,
        field_mappings=[
            FieldMapping(
                finding_field=fm.finding_field,
                jira_field=fm.jira_field,
                transform=fm.transform,
            )
            for fm in req.field_mappings
        ],
        jira_to_finding_status=req.jira_to_finding_status or dict(_DEFAULT_JIRA_TO_FINDING_STATUS),
        finding_to_jira_transition=req.finding_to_jira_transition or dict(_DEFAULT_FINDING_TO_JIRA_TRANSITION),
        severity_to_priority=req.severity_to_priority or dict(_DEFAULT_SEVERITY_TO_PRIORITY),
    )

    engine = _get_engine()
    engine.configure(cfg)

    return ConfigureResponse(
        success=True,
        configured=cfg.configured,
        project_key=cfg.project_key,
        sync_direction=cfg.sync_direction.value,
        conflict_resolution=cfg.conflict_resolution.value,
    )


@router.post(
    "/sync-all",
    response_model=SyncAllResponse,
    summary="Sync a batch of findings to Jira",
)
def sync_all(req: SyncAllRequest):
    """
    Push a list of findings to Jira, creating or updating issues as needed.

    Each finding dict must contain a ``finding_id`` or ``id`` field.
    Returns per-finding results and aggregate counters.
    """
    engine = _get_engine()
    results = engine.sync_all(req.findings)

    succeeded = sum(1 for r in results if r.status.value == "success")
    failed = sum(1 for r in results if r.status.value == "failed")
    skipped = sum(1 for r in results if r.status.value in ("skipped", "conflict"))

    return SyncAllResponse(
        total=len(results),
        succeeded=succeeded,
        failed=failed,
        skipped=skipped,
        results=[
            SyncResultResponse(**r.to_dict())
            for r in results
        ],
    )


@router.post(
    "/sync-finding",
    response_model=SyncResultResponse,
    summary="Sync a single finding to Jira",
)
def sync_finding(req: SyncFindingRequest):
    """
    Create or update the Jira issue that corresponds to the given finding.

    If a Jira link already exists for this finding the issue is updated.
    If no link exists a new Jira issue is created and the link is recorded.
    """
    engine = _get_engine()
    result = engine.sync_finding(req.finding_id, req.finding_data)
    return SyncResultResponse(**result.to_dict())


@router.post(
    "/sync-status",
    response_model=SyncResultResponse,
    summary="Propagate finding status change to Jira",
)
def sync_status(req: SyncStatusRequest):
    """
    Transition the linked Jira ticket to reflect the finding's new status.

    Requires a pre-existing link between ``finding_id`` and a Jira issue
    (established via ``sync-finding``). Uses the configured
    ``finding_to_jira_transition`` mapping to determine the Jira transition name.
    """
    engine = _get_engine()
    result = engine.sync_status(req.finding_id, req.new_status)
    return SyncResultResponse(**result.to_dict())


@router.get(
    "/field-mapping",
    response_model=List[FieldMappingItem],
    summary="Retrieve current field mapping configuration",
)
def get_field_mapping():
    """
    Return the list of custom finding-field → Jira-field mappings.

    These mappings supplement the built-in ones (title, severity, description).
    """
    engine = _get_engine()
    mappings = engine.get_field_mapping()
    return [FieldMappingItem(**m) for m in mappings]


@router.put(
    "/field-mapping",
    response_model=List[FieldMappingItem],
    summary="Replace field mapping configuration",
)
def update_field_mapping(req: FieldMappingUpdateRequest):
    """
    Replace the entire custom field mapping list.

    The new list is persisted immediately and takes effect on the next sync.
    """
    engine = _get_engine()
    try:
        engine.set_field_mapping(
            [{"finding_field": m.finding_field, "jira_field": m.jira_field, "transform": m.transform}
             for m in req.mappings]
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return req.mappings


@router.get(
    "/history",
    response_model=List[HistoryEntry],
    summary="Paginated sync history",
)
def get_history(
    finding_id: Optional[str] = Query(None, description="Filter by finding ID"),
    limit: int = Query(100, ge=1, le=1000, description="Max records to return"),
    offset: int = Query(0, ge=0, description="Number of records to skip"),
):
    """
    Return the sync audit history, newest first.

    Optionally filter to a specific ``finding_id``. Supports pagination via
    ``limit`` and ``offset``.
    """
    engine = _get_engine()
    rows = engine.get_history(finding_id=finding_id, limit=limit, offset=offset)
    return [HistoryEntry(**r) for r in rows]


@router.get(
    "/stats",
    response_model=StatsResponse,
    summary="Sync engine statistics",
)
def get_stats():
    """
    Return aggregate statistics: total links, event counts by status and direction.
    """
    engine = _get_engine()
    return StatsResponse(**engine.get_stats())


# ---------------------------------------------------------------------------
# Webhook endpoint (no API-key auth — Jira calls this directly)
# ---------------------------------------------------------------------------


@webhook_router.post(
    "/webhooks",
    response_model=SyncResultResponse,
    summary="Receive Jira webhook events",
)
async def handle_webhook(request: Request):
    """
    Receive and process Jira webhook ``POST`` callbacks.

    Jira sends a JSON payload for every issue event (created, updated, deleted).
    The engine translates the Jira status into an ALDECI finding status and
    records the event in sync history.

    If ``webhook_secret`` is configured the engine validates it against the
    ``X-Atlassian-Webhook-Identifier`` or custom header you set in Jira.
    """
    try:
        payload: Dict[str, Any] = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    engine = _get_engine()
    result = engine.handle_webhook(payload)
    return SyncResultResponse(**result.to_dict())
