"""Data Retention API Router — ALDECI.

Endpoints (all under /api/v1/data-retention):

  Policies:
    GET  /policies              — list retention policies
    POST /policies              — create a retention policy

  Datasets:
    GET  /datasets              — list datasets (filter: policy_id, expiry_status)
    POST /datasets              — register a dataset

  Dataset Actions:
    POST /datasets/{id}/legal-hold      — apply legal hold
    POST /datasets/{id}/release-hold   — release legal hold
    POST /datasets/{id}/schedule-delete — schedule for deletion
    POST /datasets/{id}/complete-delete — mark deleted + audit

  Audit & Stats:
    GET  /deletion-audit        — full deletion audit trail
    GET  /stats                 — retention compliance statistics
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from core.data_retention_engine import DataRetentionEngine
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/data-retention",
    tags=["data-retention"],
    dependencies=[Depends(api_key_auth)],
)

_engine = None  # lazy-initialised on first request


def _get_engine():
    global _engine
    if _engine is None:
        _engine = DataRetentionEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class PolicyIn(BaseModel):
    policy_name: str = ""
    data_category: str = "logs"
    retention_days: int = 365
    action_on_expiry: str = "delete"
    legal_hold: bool = False
    regulation: str = "custom"


class DatasetIn(BaseModel):
    dataset_name: str = ""
    policy_id: str = ""
    location: str = ""
    size_bytes: int = 0
    record_count: int = 0
    created_at: Optional[str] = None
    data_owner: str = ""


class LegalHoldIn(BaseModel):
    held_by: str = ""
    reason: str = ""


class ReleaseHoldIn(BaseModel):
    released_by: str = ""


class ScheduleDeleteIn(BaseModel):
    scheduled_by: str = ""
    notes: str = ""


class CompleteDeleteIn(BaseModel):
    deleted_by: str = ""


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------


@router.get("/policies")
def list_policies(
    org_id: str = Query("default"),
    regulation: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    """List retention policies for an org."""
    try:
        return _get_engine().list_policies(org_id, regulation=regulation)
    except Exception as exc:
        logger.exception("list_policies failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/policies", status_code=201)
def create_policy(
    payload: PolicyIn,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Create a new retention policy."""
    try:
        return _get_engine().create_policy(org_id, payload.model_dump())
    except Exception as exc:
        logger.exception("create_policy failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Datasets
# ---------------------------------------------------------------------------


@router.get("/datasets")
def list_datasets(
    org_id: str = Query("default"),
    policy_id: Optional[str] = Query(None),
    expiry_status: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    """List datasets, optionally filtered by policy_id or expiry_status."""
    try:
        return _get_engine().list_datasets(
            org_id, policy_id=policy_id, expiry_status=expiry_status
        )
    except Exception as exc:
        logger.exception("list_datasets failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/datasets", status_code=201)
def register_dataset(
    payload: DatasetIn,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Register a dataset under a retention policy."""
    try:
        data = payload.model_dump()
        if data.get("created_at") is None:
            data.pop("created_at", None)
        return _get_engine().register_dataset(org_id, data)
    except Exception as exc:
        logger.exception("register_dataset failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Dataset actions
# ---------------------------------------------------------------------------


@router.post("/datasets/{dataset_id}/legal-hold")
def mark_legal_hold(
    dataset_id: str,
    payload: LegalHoldIn,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Apply a legal hold to a dataset."""
    try:
        result = _get_engine().mark_legal_hold(
            org_id, dataset_id, payload.held_by, payload.reason
        )
        if result is None:
            raise HTTPException(status_code=404, detail=f"Dataset {dataset_id} not found")
        return result
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("mark_legal_hold failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/datasets/{dataset_id}/release-hold")
def release_legal_hold(
    dataset_id: str,
    payload: ReleaseHoldIn,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Release a legal hold from a dataset."""
    try:
        result = _get_engine().release_legal_hold(org_id, dataset_id, payload.released_by)
        if result is None:
            raise HTTPException(status_code=404, detail=f"Dataset {dataset_id} not found")
        return result
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("release_legal_hold failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/datasets/{dataset_id}/schedule-delete")
def schedule_deletion(
    dataset_id: str,
    payload: ScheduleDeleteIn,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Schedule a dataset for deletion."""
    try:
        result = _get_engine().schedule_deletion(
            org_id, dataset_id, payload.scheduled_by, payload.notes
        )
        if result is None:
            raise HTTPException(status_code=404, detail=f"Dataset {dataset_id} not found")
        return result
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("schedule_deletion failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/datasets/{dataset_id}/complete-delete")
def complete_deletion(
    dataset_id: str,
    payload: CompleteDeleteIn,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Complete deletion of a dataset and record audit trail."""
    try:
        result = _get_engine().complete_deletion(org_id, dataset_id, payload.deleted_by)
        if result is None:
            raise HTTPException(status_code=404, detail=f"Dataset {dataset_id} not found")
        return result
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("complete_deletion failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Audit & Stats
# ---------------------------------------------------------------------------


@router.get("/deletion-audit")
def get_deletion_audit(
    org_id: str = Query("default"),
) -> List[Dict[str, Any]]:
    """Return the deletion audit trail for an org."""
    try:
        return _get_engine().get_deletion_audit(org_id)
    except Exception as exc:
        logger.exception("get_deletion_audit failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/stats")
def get_stats(
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Return retention compliance statistics for an org."""
    try:
        return _get_engine().get_retention_stats(org_id)
    except Exception as exc:
        logger.exception("get_retention_stats failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
