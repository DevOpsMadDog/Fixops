"""Container Security Posture Router — ALDECI.

Endpoints for the Container Security Posture engine.

Prefix: /api/v1/container-posture
Auth:   api_key_auth dependency

Routes:
  POST /api/v1/container-posture/clusters                      register_cluster
  GET  /api/v1/container-posture/clusters                      list_clusters
  GET  /api/v1/container-posture/clusters/{cluster_id}         get_cluster
  POST /api/v1/container-posture/findings                      record_finding
  GET  /api/v1/container-posture/findings                      list_findings
  POST /api/v1/container-posture/findings/{finding_id}/resolve resolve_finding
  GET  /api/v1/container-posture/stats                         get_posture_stats
"""

from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/container-posture",
    tags=["Container Security Posture"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.container_security_posture_engine import (
            ContainerSecurityPostureEngine,
        )
        _engine = ContainerSecurityPostureEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ClusterCreate(BaseModel):
    name: str
    runtime: str = "docker"
    version: str = ""
    node_count: int = 0
    namespace_count: int = 0
    last_scanned: Optional[str] = None


class FindingCreate(BaseModel):
    cluster_id: str
    namespace: str = ""
    pod_name: str = ""
    container_name: str = ""
    finding_type: str = "misconfiguration"
    severity: str = "medium"
    title: str = ""
    description: str = ""
    remediation: str = ""
    detected_at: Optional[str] = None


class FindingResolve(BaseModel):
    resolution: str


# ---------------------------------------------------------------------------
# Clusters
# ---------------------------------------------------------------------------

@router.post("/clusters", dependencies=[Depends(api_key_auth)], status_code=201)
def register_cluster(body: ClusterCreate, org_id: str = Query(default="default")):
    """Register a new container cluster."""
    try:
        return _get_engine().register_cluster(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/clusters", dependencies=[Depends(api_key_auth)])
def list_clusters(
     org_id: str = Query(default="default"),
    runtime: Optional[str] = Query(None),
):
    """List clusters with optional runtime filter."""
    return _get_engine().list_clusters(org_id, runtime=runtime)


@router.get("/clusters/{cluster_id}", dependencies=[Depends(api_key_auth)])
def get_cluster(cluster_id: str, org_id: str = Query(default="default")):
    """Get a single cluster by ID."""
    cluster = _get_engine().get_cluster(org_id, cluster_id)
    if not cluster:
        raise HTTPException(status_code=404, detail="Cluster not found")
    return cluster


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

@router.post("/findings", dependencies=[Depends(api_key_auth)], status_code=201)
def record_finding(body: FindingCreate, org_id: str = Query(default="default")):
    """Record a new security finding."""
    try:
        return _get_engine().record_finding(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/findings", dependencies=[Depends(api_key_auth)])
def list_findings(
     org_id: str = Query(default="default"),
    cluster_id: Optional[str] = Query(None),
    finding_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """List findings with optional filters."""
    return _get_engine().list_findings(
        org_id,
        cluster_id=cluster_id,
        finding_type=finding_type,
        severity=severity,
        status=status,
    )


@router.post("/findings/{finding_id}/resolve", dependencies=[Depends(api_key_auth)])
def resolve_finding(finding_id: str, body: FindingResolve, org_id: str = Query(default="default")):
    """Resolve a security finding and restore posture score."""
    try:
        return _get_engine().resolve_finding(org_id, finding_id, body.resolution)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_posture_stats(org_id: str = Query(default="default")):
    """Return aggregated container security posture statistics."""
    return _get_engine().get_posture_stats(org_id)
