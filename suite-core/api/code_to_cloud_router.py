"""Code-to-Cloud Tracer Router — Vulnerability tracing endpoints.

Traces vulnerabilities from source code through build, deploy, to cloud runtime.
Competitive parity: Wiz Code-to-Cloud, Orca Security, Prisma Cloud, Apiiro Risk Graph.

Endpoints:
  POST /trace              — Trace a single vulnerability from code to cloud
  POST /trace/batch        — Batch trace multiple vulnerabilities
  GET  /map/{app_id}       — Full application topology map (code→build→deploy→cloud)
  GET  /risk/{commit_sha}  — Risk assessment for a specific commit
  GET  /summary            — Aggregate code-to-cloud risk summary
  GET  /health             — Health check
  GET  /status             — Status with engine stats
"""

from __future__ import annotations

import hashlib
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query
from apps.api.dependencies import get_org_id
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/code-to-cloud", tags=["Code-to-Cloud"])

# In-memory trace store (production would use DB)
_trace_store: Dict[str, Dict[str, Any]] = {}


class TraceRequest(BaseModel):
    vulnerability_id: str
    source_file: str = ""
    source_line: int = 0
    git_commit: str = ""
    container_image: str = ""
    k8s_namespace: str = ""
    k8s_deployment: str = ""
    cloud_service: str = ""
    cloud_region: str = ""
    internet_facing: bool = False


class BatchTraceRequest(BaseModel):
    """Batch trace request for multiple vulnerabilities."""
    vulnerabilities: List[TraceRequest] = Field(
        ..., description="List of vulnerabilities to trace", max_length=100
    )


@router.post("/trace")
async def trace_vulnerability(req: TraceRequest) -> Dict[str, Any]:
    """Trace a vulnerability from code to cloud deployment."""
    from core.code_to_cloud_tracer import get_code_to_cloud_tracer

    tracer = get_code_to_cloud_tracer()
    result = tracer.trace(
        vulnerability_id=req.vulnerability_id,
        source_file=req.source_file,
        source_line=req.source_line,
        git_commit=req.git_commit,
        container_image=req.container_image,
        k8s_namespace=req.k8s_namespace,
        k8s_deployment=req.k8s_deployment,
        cloud_service=req.cloud_service,
        cloud_region=req.cloud_region,
        internet_facing=req.internet_facing,
    )
    result_dict = result.to_dict()
    # Store for later retrieval
    _trace_store[result.trace_id] = result_dict
    return result_dict


@router.post("/trace/batch")
async def batch_trace_vulnerabilities(req: BatchTraceRequest) -> Dict[str, Any]:
    """Batch trace multiple vulnerabilities from code to cloud."""
    from core.code_to_cloud_tracer import get_code_to_cloud_tracer

    tracer = get_code_to_cloud_tracer()
    t0 = time.time()
    results = []
    risk_amplifications = []

    for vuln in req.vulnerabilities:
        result = tracer.trace(
            vulnerability_id=vuln.vulnerability_id,
            source_file=vuln.source_file,
            source_line=vuln.source_line,
            git_commit=vuln.git_commit,
            container_image=vuln.container_image,
            k8s_namespace=vuln.k8s_namespace,
            k8s_deployment=vuln.k8s_deployment,
            cloud_service=vuln.cloud_service,
            cloud_region=vuln.cloud_region,
            internet_facing=vuln.internet_facing,
        )
        result_dict = result.to_dict()
        _trace_store[result.trace_id] = result_dict
        results.append(result_dict)
        risk_amplifications.append(result.risk_amplification)

    elapsed = (time.time() - t0) * 1000
    return {
        "batch_id": f"batch-{uuid.uuid4().hex[:12]}",
        "traces": results,
        "total_traced": len(results),
        "avg_risk_amplification": round(
            sum(risk_amplifications) / len(risk_amplifications), 2
        ) if risk_amplifications else 0,
        "max_risk_amplification": round(max(risk_amplifications), 2) if risk_amplifications else 0,
        "internet_facing_count": sum(
            1 for r in results if r.get("cloud_exposure") == "internet"
        ),
        "duration_ms": round(elapsed, 2),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/map/{app_id}")
async def get_application_topology(
    app_id: str,
    include_vulnerabilities: bool = Query(True, description="Include vulnerability overlay"),
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Get full application topology map from code to cloud.

    Returns a graph of all layers: source repos, build artifacts,
    container images, K8s deployments, cloud services — with
    vulnerability overlay showing risk propagation.
    """
    t0 = time.time()
    layers: Dict[str, List[Dict[str, Any]]] = {
        "source_code": [],
        "build_artifacts": [],
        "container_images": [],
        "deployments": [],
        "cloud_services": [],
    }
    connections: List[Dict[str, Any]] = []
    vuln_overlay: List[Dict[str, Any]] = []

    # Aggregate from stored traces for this app
    app_traces = [
        t for t in _trace_store.values()
        if app_id in t.get("vulnerability_id", "")
        or any(
            app_id in n.get("name", "") for n in t.get("nodes", [])
        )
    ]

    # Build topology from traces
    seen_nodes: set = set()
    for trace in app_traces:
        for node in trace.get("nodes", []):
            node_key = f"{node['node_type']}:{node['name']}"
            if node_key in seen_nodes:
                continue
            seen_nodes.add(node_key)

            layer_map = {
                "source_code": "source_code",
                "git_commit": "source_code",
                "build_artifact": "build_artifacts",
                "container_image": "container_images",
                "container_registry": "container_images",
                "k8s_pod": "deployments",
                "k8s_deployment": "deployments",
                "cloud_instance": "cloud_services",
                "cloud_service": "cloud_services",
            }
            layer = layer_map.get(node["node_type"], "source_code")
            layers[layer].append({
                "id": node["node_id"],
                "name": node["name"],
                "type": node["node_type"],
                "metadata": node.get("metadata", {}),
            })

        for edge in trace.get("edges", []):
            connections.append({
                "source": edge["source_id"],
                "target": edge["target_id"],
                "type": edge["edge_type"],
            })

        if include_vulnerabilities:
            vuln_overlay.append({
                "vulnerability_id": trace["vulnerability_id"],
                "trace_id": trace["trace_id"],
                "risk_amplification": trace["risk_amplification"],
                "cloud_exposure": trace["cloud_exposure"],
                "attack_path_length": trace["attack_path_length"],
            })

    # If no traces exist, return a scaffold topology for the app
    if not app_traces:
        app_hash = hashlib.sha256(app_id.encode()).hexdigest()[:8]
        layers["source_code"].append({
            "id": f"repo-{app_hash}",
            "name": f"{app_id}/main",
            "type": "git_repository",
            "metadata": {"branch": "main", "language": "auto-detect"},
        })
        layers["build_artifacts"].append({
            "id": f"build-{app_hash}",
            "name": f"{app_id}:latest",
            "type": "docker_build",
            "metadata": {"stage": "production"},
        })

    elapsed = (time.time() - t0) * 1000
    return {
        "app_id": app_id,
        "topology": {
            "layers": layers,
            "connections": connections,
            "total_nodes": sum(len(v) for v in layers.values()),
            "total_connections": len(connections),
        },
        "vulnerability_overlay": vuln_overlay,
        "risk_summary": {
            "total_vulnerabilities": len(vuln_overlay),
            "internet_facing": sum(
                1 for v in vuln_overlay if v["cloud_exposure"] == "internet"
            ),
            "max_risk_amplification": max(
                (v["risk_amplification"] for v in vuln_overlay), default=0
            ),
            "avg_attack_path_length": round(
                sum(v["attack_path_length"] for v in vuln_overlay) / len(vuln_overlay), 1
            ) if vuln_overlay else 0,
        },
        "duration_ms": round(elapsed, 2),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/risk/{commit_sha}")
async def get_commit_risk(
    commit_sha: str,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Assess risk for a specific git commit.

    Analyzes how a commit's changes propagate through the build/deploy
    chain and what cloud resources are affected. Used by CI/CD gates
    and developer risk profiles.
    """
    t0 = time.time()

    # Find all traces related to this commit
    commit_traces = [
        t for t in _trace_store.values()
        if any(
            commit_sha[:12] in n.get("name", "") or commit_sha[:12] in n.get("node_id", "")
            for n in t.get("nodes", [])
        )
    ]

    # Compute aggregate risk
    risk_amplifications = [t["risk_amplification"] for t in commit_traces]
    internet_count = sum(
        1 for t in commit_traces if t.get("cloud_exposure") == "internet"
    )

    # Affected services
    affected_services = set()
    affected_deployments = set()
    for trace in commit_traces:
        for node in trace.get("nodes", []):
            if node["node_type"] == "cloud_service":
                affected_services.add(node["name"])
            elif node["node_type"] == "k8s_deployment":
                affected_deployments.add(node["name"])

    elapsed = (time.time() - t0) * 1000
    return {
        "commit_sha": commit_sha,
        "risk_assessment": {
            "total_vulnerabilities": len(commit_traces),
            "max_risk_amplification": round(max(risk_amplifications), 2) if risk_amplifications else 1.0,
            "avg_risk_amplification": round(
                sum(risk_amplifications) / len(risk_amplifications), 2
            ) if risk_amplifications else 1.0,
            "internet_facing_vulns": internet_count,
            "risk_level": (
                "critical" if internet_count > 0 and len(commit_traces) > 3
                else "high" if internet_count > 0
                else "medium" if len(commit_traces) > 0
                else "low"
            ),
        },
        "blast_radius": {
            "affected_services": sorted(affected_services),
            "affected_deployments": sorted(affected_deployments),
            "total_affected": len(affected_services) + len(affected_deployments),
        },
        "traces": [
            {
                "trace_id": t["trace_id"],
                "vulnerability_id": t["vulnerability_id"],
                "risk_amplification": t["risk_amplification"],
                "cloud_exposure": t["cloud_exposure"],
            }
            for t in commit_traces
        ],
        "ci_cd_gate": {
            "should_block": internet_count > 0 or len(commit_traces) > 5,
            "reason": (
                f"{internet_count} internet-facing vulnerabilities detected"
                if internet_count > 0
                else f"{len(commit_traces)} vulnerabilities in commit"
                if commit_traces
                else "No vulnerabilities detected"
            ),
        },
        "duration_ms": round(elapsed, 2),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/summary")
async def code_to_cloud_summary(
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Aggregate code-to-cloud risk summary across all traced vulnerabilities."""
    all_traces = list(_trace_store.values())
    internet_count = sum(
        1 for t in all_traces if t.get("cloud_exposure") == "internet"
    )
    internal_count = sum(
        1 for t in all_traces if t.get("cloud_exposure") == "internal"
    )

    risk_amps = [t.get("risk_amplification", 1.0) for t in all_traces]
    return {
        "total_traces": len(all_traces),
        "exposure_breakdown": {
            "internet": internet_count,
            "internal": internal_count,
            "none": len(all_traces) - internet_count - internal_count,
        },
        "risk_metrics": {
            "max_amplification": round(max(risk_amps), 2) if risk_amps else 1.0,
            "avg_amplification": round(
                sum(risk_amps) / len(risk_amps), 2
            ) if risk_amps else 1.0,
            "p95_amplification": round(
                sorted(risk_amps)[int(len(risk_amps) * 0.95)] if risk_amps else 1.0, 2
            ),
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/health")
async def tracer_health() -> Dict[str, Any]:
    """Health check for code-to-cloud tracer."""
    return {"status": "healthy", "engine": "code_to_cloud_tracer", "version": "2.0.0"}


@router.get("/status")
async def tracer_status() -> Dict[str, Any]:
    """Status with engine statistics."""
    return {
        "status": "healthy",
        "engine": "code_to_cloud_tracer",
        "version": "2.0.0",
        "stats": {
            "total_traces": len(_trace_store),
            "internet_facing": sum(
                1 for t in _trace_store.values()
                if t.get("cloud_exposure") == "internet"
            ),
        },
    }
