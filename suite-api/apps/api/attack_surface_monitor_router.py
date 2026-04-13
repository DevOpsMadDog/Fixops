"""Attack Surface Continuous Monitoring Router.

REST API for snapshot-based attack surface tracking — take snapshots,
diff them, score current exposure, detect shadow IT, and generate attack paths.

Mounted by app.py under read:findings scope at /api/v1/attack-surface/monitor.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

try:
    from apps.api.auth_deps import api_key_auth as _api_key_auth
    _AUTH_DEP: list = [Depends(_api_key_auth)]
except ImportError:
    logging.getLogger(__name__).warning(
        "attack_surface_monitor_router: auth_deps not available, "
        "relying on app.py mount-level auth"
    )
    _AUTH_DEP = []

from core.attack_surface_monitor import (
    AttackPath,
    AttackSurfaceDiff,
    AttackSurfaceMonitor,
    AttackSurfaceSnapshot,
    MonitorSession,
    get_attack_surface_monitor,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/attack-surface/monitor",
    tags=["Attack Surface Monitor"],
    dependencies=_AUTH_DEP,
)


# ---------------------------------------------------------------------------
# Dependency
# ---------------------------------------------------------------------------


def _get_monitor() -> AttackSurfaceMonitor:
    return get_attack_surface_monitor()


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class TakeSnapshotRequest(BaseModel):
    target: str = Field("127.0.0.1", description="Hostname or IP to snapshot")
    port_timeout: float = Field(0.1, description="Per-port socket timeout in seconds")
    endpoints: Optional[List[str]] = Field(None, description="Known endpoints to record")
    deps: Optional[List[str]] = Field(None, description="Dependency list to record")
    env_vars: Optional[Dict[str, str]] = Field(
        None, description="Environment variable key/value pairs to scan for secrets"
    )


class StartMonitorRequest(BaseModel):
    target: str = Field("127.0.0.1", description="Hostname or IP to monitor")
    interval_seconds: int = Field(300, ge=10, description="Scan interval in seconds")
    port_timeout: float = Field(0.1, description="Per-port socket timeout in seconds")


class ShadowITRequest(BaseModel):
    network_range: str = Field("127.0.0.1", description="Host to scan for shadow IT")
    port_timeout: float = Field(0.1, description="Per-port socket timeout in seconds")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/snapshot", response_model=AttackSurfaceSnapshot, summary="Take an attack surface snapshot")
def take_snapshot(
    req: TakeSnapshotRequest,
    monitor: AttackSurfaceMonitor = Depends(_get_monitor),
) -> AttackSurfaceSnapshot:
    """Capture the current attack surface state for a target.

    Performs a socket-based port scan, classifies services, infers HTTP/S
    endpoints, and scans provided env vars for exposed secrets.
    """
    try:
        return monitor.take_snapshot(
            target=req.target,
            port_timeout=req.port_timeout,
            endpoints=req.endpoints,
            deps=req.deps,
            env_vars=req.env_vars or {},
        )
    except Exception as exc:
        logger.exception("Snapshot failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Snapshot failed: {exc}") from exc


@router.get("/snapshot/{snapshot_id}", response_model=AttackSurfaceSnapshot, summary="Get a snapshot by ID")
def get_snapshot(
    snapshot_id: str,
    monitor: AttackSurfaceMonitor = Depends(_get_monitor),
) -> AttackSurfaceSnapshot:
    snap = monitor.get_snapshot(snapshot_id)
    if not snap:
        raise HTTPException(status_code=404, detail=f"Snapshot '{snapshot_id}' not found")
    return snap


@router.get("/snapshots", response_model=List[AttackSurfaceSnapshot], summary="List snapshots for a target")
def list_snapshots(
    target: str = Query("127.0.0.1", description="Target host"),
    limit: int = Query(50, ge=1, le=500),
    monitor: AttackSurfaceMonitor = Depends(_get_monitor),
) -> List[AttackSurfaceSnapshot]:
    return monitor.list_snapshots(target=target, limit=limit)


@router.get(
    "/diff/{snapshot1_id}/{snapshot2_id}",
    response_model=AttackSurfaceDiff,
    summary="Compare two snapshots",
)
def diff_snapshots(
    snapshot1_id: str,
    snapshot2_id: str,
    monitor: AttackSurfaceMonitor = Depends(_get_monitor),
) -> AttackSurfaceDiff:
    """Compare two snapshots and return the set of changes: added/removed services,
    new/closed secrets, endpoint changes, and score delta."""
    old = monitor.get_snapshot(snapshot1_id)
    if not old:
        raise HTTPException(status_code=404, detail=f"Snapshot '{snapshot1_id}' not found")
    new = monitor.get_snapshot(snapshot2_id)
    if not new:
        raise HTTPException(status_code=404, detail=f"Snapshot '{snapshot2_id}' not found")
    try:
        return monitor.diff_snapshots(old, new)
    except Exception as exc:
        logger.exception("Diff failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Diff failed: {exc}") from exc


@router.get("/score/{target}", response_model=Dict[str, Any], summary="Get current attack surface score")
def get_score(
    target: str,
    port_timeout: float = Query(0.1, description="Per-port socket timeout in seconds"),
    monitor: AttackSurfaceMonitor = Depends(_get_monitor),
) -> Dict[str, Any]:
    """Take a fresh snapshot of the target and return its 0-100 risk score
    (lower is better) along with contributing factors."""
    try:
        return monitor.get_current_score(target=target, port_timeout=port_timeout)
    except Exception as exc:
        logger.exception("Scoring failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Scoring failed: {exc}") from exc


@router.post("/shadow-it", response_model=List[Dict[str, Any]], summary="Detect shadow IT services")
def detect_shadow_it(
    req: ShadowITRequest,
    monitor: AttackSurfaceMonitor = Depends(_get_monitor),
) -> List[Dict[str, Any]]:
    """Scan the target host for unexpected open ports and flag them as
    potential shadow IT (unmanaged/unauthorized services)."""
    try:
        return monitor.detect_shadow_it(
            network_range=req.network_range,
            port_timeout=req.port_timeout,
        )
    except Exception as exc:
        logger.exception("Shadow IT scan failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Shadow IT scan failed: {exc}") from exc


@router.get("/paths", response_model=List[AttackPath], summary="Generate attack paths from shadow IT findings")
def get_attack_paths(
    target: str = Query("127.0.0.1", description="Target to derive paths for"),
    port_timeout: float = Query(0.1, description="Per-port socket timeout in seconds"),
    monitor: AttackSurfaceMonitor = Depends(_get_monitor),
) -> List[AttackPath]:
    """Detect open services on the target then generate likely attack paths
    (entry point → lateral movement → internal target)."""
    try:
        findings = monitor.detect_shadow_it(network_range=target, port_timeout=port_timeout)
        return monitor.generate_attack_paths(findings)
    except Exception as exc:
        logger.exception("Attack path generation failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Attack path generation failed: {exc}") from exc


@router.post("/start", response_model=MonitorSession, summary="Start continuous monitoring")
def start_monitoring(
    req: StartMonitorRequest,
    monitor: AttackSurfaceMonitor = Depends(_get_monitor),
) -> MonitorSession:
    """Launch a background thread that periodically snapshots the target
    and logs warnings when the attack surface risk increases."""
    try:
        return monitor.start_monitoring(
            target=req.target,
            interval_seconds=req.interval_seconds,
            port_timeout=req.port_timeout,
        )
    except Exception as exc:
        logger.exception("Failed to start monitoring: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to start monitoring: {exc}") from exc


@router.delete("/stop/{session_id}", summary="Stop a monitoring session")
def stop_monitoring(
    session_id: str,
    monitor: AttackSurfaceMonitor = Depends(_get_monitor),
) -> Dict[str, Any]:
    stopped = monitor.stop_monitoring(session_id)
    if not stopped:
        raise HTTPException(status_code=404, detail=f"Monitor session '{session_id}' not found")
    return {"stopped": True, "session_id": session_id}
