"""Agentless Snapshot Scan Router — ALDECI (GAP-020).

Agentless side-scanning of cloud block-storage snapshots without installing
any agent on the workload. Covers EBS, Azure managed disks, GCP PD.

Prefix: /api/v1/agentless-snapshot-scan
Auth:   api_key_auth dependency

Routes:
  POST  /api/v1/agentless-snapshot-scan/snapshots              enqueue_scan
  GET   /api/v1/agentless-snapshot-scan/snapshots              list_snapshots
  POST  /api/v1/agentless-snapshot-scan/snapshots/{id}/run     run_scan
  GET   /api/v1/agentless-snapshot-scan/findings               list_findings
  GET   /api/v1/agentless-snapshot-scan/stats                  stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/agentless-snapshot-scan",
    tags=["Agentless Snapshot Scan"],
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

class EnqueueScanRequest(BaseModel):
    org_id: str = Field(default="default", description="Organisation identifier")
    provider: str = Field(
        default="aws",
        description="Cloud provider: aws | azure | gcp",
    )
    account_id: str = Field(default="", description="Cloud account/subscription ID")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/", dependencies=[Depends(api_key_auth)])
def root(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Return snapshot scan stats summary for the org."""
    return _get_engine().stats(org_id)


@router.post("/snapshots", dependencies=[Depends(api_key_auth)])
def enqueue_scan(req: EnqueueScanRequest) -> List[Dict[str, Any]]:
    """Discover and enqueue agentless snapshot scan jobs for the given provider/account."""
    try:
        return _get_engine().enqueue_scan(
            org_id=req.org_id,
            provider=req.provider,
            account_id=req.account_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("enqueue_scan failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/snapshots", dependencies=[Depends(api_key_auth)])
def list_snapshots(
    org_id: str = Query(default="default"),
    provider: Optional[str] = Query(default=None),
    scan_status: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List snapshot scan jobs for the org with optional filters."""
    try:
        return _get_engine().list_snapshots(
            org_id=org_id,
            provider=provider,
            scan_status=scan_status,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("list_snapshots failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/snapshots/{snapshot_db_id}/run", dependencies=[Depends(api_key_auth)])
def run_scan(snapshot_db_id: str) -> Dict[str, Any]:
    """Execute a queued snapshot scan synchronously and return findings summary."""
    try:
        return _get_engine().run_scan(snapshot_db_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("run_scan failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/findings", dependencies=[Depends(api_key_auth)])
def list_findings(
    org_id: str = Query(default="default"),
    snapshot_db_id: Optional[str] = Query(default=None),
    finding_type: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List scan findings with optional filters."""
    try:
        return _get_engine().list_findings(
            org_id=org_id,
            snapshot_db_id=snapshot_db_id,
            finding_type=finding_type,
            severity=severity,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("list_findings failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def stats(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Return aggregate snapshot scan statistics for the org."""
    try:
        return _get_engine().stats(org_id)
    except Exception as exc:
        _logger.exception("stats failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
