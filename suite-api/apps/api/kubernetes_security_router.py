"""
Kubernetes Security Router — ALDECI.

Prefix: /api/v1/kubernetes-security
Auth:   Depends(api_key_auth)
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

_SIMULATION_WARNING = {
    "is_simulated": True,
    "engine": "kubernetes_security_engine",
    "real_integration_required": "/api/v1/connectors/kubernetes/configure",
    "do_not_use_in_demo": True,
}

router = APIRouter(prefix="/api/v1/kubernetes-security", tags=["kubernetes-security"])

# ---------------------------------------------------------------------------
# Lazy engine singleton
# ---------------------------------------------------------------------------

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.kubernetes_security_engine import KubernetesSecurityEngine
        _engine = KubernetesSecurityEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class RegisterClusterRequest(BaseModel):
    cluster_name: str = "unnamed-cluster"
    provider: str = "eks"
    k8s_version: str = "1.28"
    node_count: int = 1
    namespace_count: int = 1


class RecordFindingRequest(BaseModel):
    cluster_id: str
    finding_type: str = "no_resource_limits"
    severity: str = "medium"
    namespace: str = "default"
    resource_name: str = ""
    resource_type: str = ""
    description: str = ""
    remediation: str = ""


class ResolveFindingRequest(BaseModel):
    resolved_by: str
    resolution_notes: str = ""


# ---------------------------------------------------------------------------
# Endpoints — Posture Summary (root GET /)
# ---------------------------------------------------------------------------

@router.get("")
@router.get("/")
def get_kubernetes_posture_summary(
    org_id: str = Query(..., description="Organisation ID"),
    _auth: bool = Depends(api_key_auth),
) -> Dict[str, Any]:
    """
    Kubernetes posture summary for an org.

    Returns aggregate cluster count, open critical findings, resolved count,
    and average CIS Benchmark score.  Backed by KubernetesSecurityEngine.get_cluster_stats().
    No mocks — reads live SQLite data via the engine.
    """
    try:
        stats = _get_engine().get_cluster_stats(org_id=org_id)
        return {
            "org_id": org_id,
            "total_clusters": stats["total_clusters"],
            "total_findings": stats["total_findings"],
            "critical_open": stats["critical_count"],
            "resolved": stats["resolved_count"],
            "avg_cis_score": stats["avg_cis_score"],
            "by_severity": stats["by_severity"],
            "_simulation_warning": _SIMULATION_WARNING,
        }
    except Exception as exc:
        _logger.exception("get_kubernetes_posture_summary failed")
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Endpoints — Clusters
# ---------------------------------------------------------------------------

@router.get("/clusters")
def list_clusters(
    org_id: str = Query(..., description="Organisation ID"),
    _auth: bool = Depends(api_key_auth),
) -> List[Dict[str, Any]]:
    """List Kubernetes clusters for an org."""
    try:
        return _get_engine().list_clusters(org_id=org_id)
    except Exception as exc:
        _logger.exception("list_clusters failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/clusters", status_code=201)
def register_cluster(
    org_id: str = Query(..., description="Organisation ID"),
    body: RegisterClusterRequest = ...,
    _auth: bool = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Register a Kubernetes cluster."""
    try:
        return _get_engine().register_cluster(org_id=org_id, data=body.model_dump())
    except Exception as exc:
        _logger.exception("register_cluster failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/clusters/{cluster_id}/cis-benchmark")
def run_cis_benchmark(
    cluster_id: str,
    org_id: str = Query(..., description="Organisation ID"),
    _auth: bool = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Run CIS Kubernetes Benchmark v1.8 against a cluster."""
    try:
        result = _get_engine().run_cis_benchmark(org_id=org_id, cluster_id=cluster_id)
        return {"data": result, "_simulation_warning": _SIMULATION_WARNING}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        _logger.exception("run_cis_benchmark failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/clusters/{cluster_id}/rbac-analysis")
def get_rbac_analysis(
    cluster_id: str,
    org_id: str = Query(..., description="Organisation ID"),
    _auth: bool = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Get RBAC analysis for a cluster."""
    try:
        return _get_engine().get_rbac_analysis(org_id=org_id, cluster_id=cluster_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        _logger.exception("get_rbac_analysis failed")
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Endpoints — Findings
# ---------------------------------------------------------------------------

@router.get("/findings")
def list_findings(
    org_id: str = Query(..., description="Organisation ID"),
    cluster_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    finding_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    _auth: bool = Depends(api_key_auth),
) -> List[Dict[str, Any]]:
    """List security findings with optional filters."""
    try:
        return _get_engine().list_findings(
            org_id=org_id,
            cluster_id=cluster_id,
            severity=severity,
            finding_type=finding_type,
            status=status,
        )
    except Exception as exc:
        _logger.exception("list_findings failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/findings", status_code=201)
def record_finding(
    org_id: str = Query(..., description="Organisation ID"),
    body: RecordFindingRequest = ...,
    _auth: bool = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Record a Kubernetes security finding."""
    try:
        return _get_engine().record_finding(org_id=org_id, data=body.model_dump())
    except Exception as exc:
        _logger.exception("record_finding failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/findings/{finding_id}/resolve")
def resolve_finding(
    finding_id: str,
    org_id: str = Query(..., description="Organisation ID"),
    body: ResolveFindingRequest = ...,
    _auth: bool = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Mark a finding as resolved."""
    try:
        return _get_engine().resolve_finding(
            org_id=org_id,
            finding_id=finding_id,
            resolved_by=body.resolved_by,
            resolution_notes=body.resolution_notes,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        _logger.exception("resolve_finding failed")
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Endpoints — Stats
# ---------------------------------------------------------------------------

@router.get("/stats")
def get_stats(
    org_id: str = Query(..., description="Organisation ID"),
    _auth: bool = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Get aggregate Kubernetes security stats for an org."""
    try:
        return _get_engine().get_cluster_stats(org_id=org_id)
    except Exception as exc:
        _logger.exception("get_cluster_stats failed")
        raise HTTPException(status_code=500, detail=str(exc))
