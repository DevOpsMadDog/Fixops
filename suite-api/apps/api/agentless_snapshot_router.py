"""Agentless Snapshot Scan Router — ALDECI (GAP-020).

Endpoints for the agentless snapshot scan engine. This is the P0 Wiz/Orca
moat — side-scanning cloud block-storage snapshots without installing any
agent on the workload.

Prefix: /api/v1/agentless-snapshot
Auth:   api_key_auth dependency

Routes:
  POST  /api/v1/agentless-snapshot/enqueue                    enqueue_scan
  POST  /api/v1/agentless-snapshot/{snapshot_db_id}/scan      run_scan
  GET   /api/v1/agentless-snapshot/snapshots                  list_snapshots
  GET   /api/v1/agentless-snapshot/findings                   list_findings
  GET   /api/v1/agentless-snapshot/stats                      stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/agentless-snapshot",
    tags=["Agentless Snapshot Scan"],
    dependencies=[Depends(api_key_auth)],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.agentless_snapshot_scan_engine import AgentlessSnapshotScanEngine

        _engine = AgentlessSnapshotScanEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class EnqueueRequest(BaseModel):
    org_id: str = Field(default="default", min_length=1, max_length=128)
    provider: str = Field(..., min_length=2, max_length=32)
    account_id: str = Field(..., min_length=1, max_length=128)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/enqueue")
def enqueue_scan(body: EnqueueRequest) -> Dict[str, Any]:
    """Discover snapshots for (provider, account_id) and queue them."""

    try:
        queued = _get_engine().enqueue_scan(
            org_id=body.org_id,
            provider=body.provider,
            account_id=body.account_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {
        "org_id": body.org_id,
        "provider": body.provider,
        "account_id": body.account_id,
        "queued_count": len(queued),
        "snapshots": [
            {
                "id": record["id"],
                "snapshot_id": record["snapshot_id"],
                "scan_status": record["scan_status"],
            }
            for record in queued
        ],
    }


@router.post("/{snapshot_db_id}/scan")
def run_scan(snapshot_db_id: str) -> Dict[str, Any]:
    """Synchronously execute a scan for the given snapshot row.

    For v0 this is synchronous so demos and curl flows are deterministic.
    A production build would hand this off to a background worker and return
    a job id immediately.
    """

    try:
        return _get_engine().run_scan(snapshot_db_id=snapshot_db_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/snapshots")
def list_snapshots(
    org_id: str = Query(default="default"),
    provider: Optional[str] = Query(None),
    scan_status: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    try:
        return _get_engine().list_snapshots(
            org_id=org_id, provider=provider, scan_status=scan_status
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/findings")
def list_findings(
    org_id: str = Query(default="default"),
    severity: Optional[str] = Query(None),
    min_severity: Optional[str] = Query(None),
    finding_type: Optional[str] = Query(None),
    snapshot_db_id: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    try:
        return _get_engine().list_findings(
            org_id=org_id,
            severity=severity,
            min_severity=min_severity,
            finding_type=finding_type,
            snapshot_db_id=snapshot_db_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/stats")
def stats(org_id: str = Query(default="default")) -> Dict[str, Any]:
    return _get_engine().stats(org_id=org_id)


__all__ = ["router"]


# ---------------------------------------------------------------------------
# Root — capability summary (fixes BUG-1: missing GET /)
# ---------------------------------------------------------------------------

@router.get("/")
def get_agentless_root(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Return Agentless Snapshot Scan service capabilities and live stats summary."""
    live_stats = _get_engine().stats(org_id=org_id)
    return {
        "service": "agentless-snapshot-scan",
        "version": "1.0",
        "status": "operational",
        "capabilities": [
            "snapshot_enqueue",
            "vulnerability_scanning",
            "findings_aggregation",
            "multi_cloud_support",
        ],
        "stats": live_stats,
    }
