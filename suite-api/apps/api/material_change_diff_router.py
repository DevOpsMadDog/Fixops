"""Material Change Diff Router — ALDECI (GAP-011).

Endpoints for computing risk-surface diffs between two scan runs, persisting
them as `material_change_events`, and associating them with pull requests.

Prefix: /api/v1/material-change
Auth:   api_key_auth dependency

Routes:
  POST /api/v1/material-change/compute       compute+persist diff
  GET  /api/v1/material-change/events        list events (optional pr_ref filter)
  GET  /api/v1/material-change/events/{id}   fetch a single event
  POST /api/v1/material-change/pr-webhook    record PR ref on an existing event
  GET  /api/v1/material-change/stats         aggregated per-org stats
"""
from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/material-change",
    tags=["Material Change (GAP-011)"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_change_management_engine import (
            SecurityChangeManagementEngine,
        )
        _engine = SecurityChangeManagementEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class ComputeRequest(BaseModel):
    prior_scan_id: str
    current_scan_id: str
    pr_ref: str = ""


class PRWebhookRequest(BaseModel):
    pr_ref: str
    event_id: Optional[str] = None
    prior_scan_id: Optional[str] = None
    current_scan_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/compute", dependencies=[Depends(api_key_auth)], status_code=201)
def compute_material_change(
    body: ComputeRequest,
    org_id: str = Query(default="default"),
):
    """Compute a PR-webhook friendly material-change diff between two scans.

    Joins findings on correlation_key (GAP-063) to emit new/unchanged/resolved
    buckets plus per-component risk-surface deltas. Idempotent on
    (org_id, prior_scan_id, current_scan_id).
    """
    try:
        return _get_engine().compute_material_change_diff(
            org_id=org_id,
            prior_scan_id=body.prior_scan_id,
            current_scan_id=body.current_scan_id,
            pr_ref=body.pr_ref or "",
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/events", dependencies=[Depends(api_key_auth)])
def list_events(
    org_id: str = Query(default="default"),
    pr_ref: Optional[str] = Query(None),
):
    """List material-change events for an org, optionally filtered by pr_ref."""
    return _get_engine().list_material_events(org_id, pr_ref=pr_ref)


@router.get("/events/{event_id}", dependencies=[Depends(api_key_auth)])
def get_event(event_id: str):
    """Fetch a single material-change event by id."""
    ev = _get_engine().get_material_event(event_id)
    if ev is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return ev


@router.post("/pr-webhook", dependencies=[Depends(api_key_auth)], status_code=201)
def pr_webhook(
    body: PRWebhookRequest,
    org_id: str = Query(default="default"),
):
    """PR webhook: associate a pr_ref with a material-change event.

    If ``event_id`` is provided, updates that event directly. Otherwise
    ``prior_scan_id`` + ``current_scan_id`` are required — the diff is
    (re-)computed and the resulting event gets the pr_ref.
    """
    if not body.pr_ref:
        raise HTTPException(status_code=400, detail="pr_ref is required")

    engine = _get_engine()

    if body.event_id:
        updated = engine.record_pr_webhook(org_id, body.pr_ref, body.event_id)
        if updated is None:
            raise HTTPException(status_code=404, detail="Event not found")
        return updated

    if not body.prior_scan_id or not body.current_scan_id:
        raise HTTPException(
            status_code=400,
            detail="Either event_id or (prior_scan_id + current_scan_id) is required",
        )
    try:
        return engine.compute_material_change_diff(
            org_id=org_id,
            prior_scan_id=body.prior_scan_id,
            current_scan_id=body.current_scan_id,
            pr_ref=body.pr_ref,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_stats(org_id: str = Query(default="default")):
    """Aggregated material-change stats for an org."""
    return _get_engine().get_material_change_stats(org_id)
