"""Kubernetes Security Posture Management (KSPM) API Router.

Endpoints for cluster scanning, RBAC analysis, network policy audits,
image security, secrets management, and admission control for ALDECI.

Auth is applied centrally by app.py (Depends(_verify_api_key)).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.k8s_security import (
    AdmissionRule,
    CheckCategory,
    ClusterConfig,
    ClusterPosture,
    K8sResource,
    Severity,
    get_k8s_engine,
)
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/k8s", tags=["Kubernetes Security"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    cluster_name: str = Field("default", description="Logical cluster name")
    kubeconfig_path: Optional[str] = Field(None, description="Path to kubeconfig file")
    in_cluster: bool = Field(False, description="Use in-cluster service account credentials")
    context: Optional[str] = Field(None, description="kubeconfig context to use")
    namespaces: List[str] = Field(default_factory=list, description="Namespaces to scan (empty = all)")
    trusted_registries: List[str] = Field(
        default_factory=list,
        description="Trusted image registries (overrides engine defaults if non-empty)",
    )
    # Synthetic/offline mode: caller supplies raw resource manifests
    resources: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Raw Kubernetes resource dicts (for offline/testing mode)",
    )
    rbac_resources: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Raw RBAC resource dicts (Role, ClusterRole, RoleBinding, ClusterRoleBinding)",
    )
    network_policies: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Raw NetworkPolicy resource dicts",
    )


class PostureResponse(BaseModel):
    cluster_name: str
    overall_score: float
    grade: str
    total_checks: int
    passed_checks: int
    failed_checks: int
    warned_checks: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    scanned_at: str
    scan_duration_ms: int
    namespace_scores: List[Dict[str, Any]]
    workload_scores: List[Dict[str, Any]]


class FindingsResponse(BaseModel):
    total: int
    findings: List[Dict[str, Any]]


class AdmissionRuleRequest(BaseModel):
    name: str = Field(..., description="Unique rule name")
    description: str = Field("", description="Human-readable description")
    action: str = Field("deny", description="Action on violation: deny | warn | audit")
    enabled: bool = Field(True)
    conditions: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resources_from_dicts(raw: List[Dict[str, Any]]) -> List[K8sResource]:
    """Convert raw manifest dicts to K8sResource objects."""
    result: List[K8sResource] = []
    for r in raw:
        try:
            meta = r.get("metadata", {})
            result.append(K8sResource(
                kind=r.get("kind", "Unknown"),
                name=meta.get("name", "unnamed"),
                namespace=meta.get("namespace"),
                api_version=r.get("apiVersion", "v1"),
                labels=meta.get("labels", {}),
                annotations=meta.get("annotations", {}),
                spec=r.get("spec", {}),
                metadata=meta,
            ))
        except Exception as exc:
            logger.warning("Skipping malformed resource: %s", exc)
    return result


def _posture_to_response(posture: ClusterPosture) -> PostureResponse:
    return PostureResponse(
        cluster_name=posture.cluster_name,
        overall_score=posture.overall_score,
        grade=posture.grade,
        total_checks=posture.total_checks,
        passed_checks=posture.passed_checks,
        failed_checks=posture.failed_checks,
        warned_checks=posture.warned_checks,
        critical_findings=posture.critical_findings,
        high_findings=posture.high_findings,
        medium_findings=posture.medium_findings,
        low_findings=posture.low_findings,
        scanned_at=posture.scanned_at.isoformat(),
        scan_duration_ms=posture.scan_duration_ms,
        namespace_scores=[ns.model_dump() for ns in posture.namespace_scores],
        workload_scores=[wl.model_dump() for wl in posture.workload_scores],
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get(
    "/posture",
    summary="Overall cluster security posture",
    response_model=PostureResponse,
)
def get_posture() -> PostureResponse:
    """Return the most recently computed cluster security posture.

    Returns 404 if no scan has been run yet. Trigger a scan via POST /scan first.
    """
    engine = get_k8s_engine()
    posture = engine.get_cached_posture()
    if posture is None:
        raise HTTPException(
            status_code=404,
            detail="No cluster scan available. POST /api/v1/k8s/scan to trigger one.",
        )
    return _posture_to_response(posture)


@router.get(
    "/findings",
    summary="Security findings across clusters",
    response_model=FindingsResponse,
)
def get_findings(
    severity: Optional[str] = Query(None, description="Filter by severity: critical|high|medium|low|info"),
    category: Optional[str] = Query(None, description="Filter by category: pod_security|rbac|network_policy|image_security|secrets_management|admission_control|cluster_config"),
    namespace: Optional[str] = Query(None, description="Filter by namespace"),
    limit: int = Query(100, ge=1, le=1000, description="Max findings to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
) -> FindingsResponse:
    """Return security findings from the most recent cluster scan with optional filtering."""
    engine = get_k8s_engine()
    posture = engine.get_cached_posture()
    if posture is None:
        return FindingsResponse(total=0, findings=[])

    findings = posture.findings

    if severity:
        try:
            sev = Severity(severity.lower())
            findings = [f for f in findings if f.severity == sev]
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid severity: {severity}")

    if category:
        try:
            cat = CheckCategory(category.lower())
            findings = [f for f in findings if f.category == cat]
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid category: {category}")

    if namespace:
        findings = [f for f in findings if f.namespace == namespace]

    total = len(findings)
    page = findings[offset: offset + limit]

    return FindingsResponse(
        total=total,
        findings=[f.model_dump(mode="json") for f in page],
    )


@router.post(
    "/scan",
    summary="Trigger cluster security scan",
    response_model=PostureResponse,
)
def trigger_scan(request: ScanRequest) -> PostureResponse:
    """Trigger a full KSPM scan of the specified cluster.

    Accepts kubeconfig path for remote clusters, in_cluster flag for
    pod-based scanning, or raw resource dicts for offline/testing analysis.
    """
    engine = get_k8s_engine()

    resources = _resources_from_dicts(request.resources)

    config = ClusterConfig(
        cluster_name=request.cluster_name,
        kubeconfig_path=request.kubeconfig_path,
        in_cluster=request.in_cluster,
        context=request.context,
        namespaces=request.namespaces,
        trusted_registries=request.trusted_registries or engine._trusted_registries,
        resources=resources,
        rbac_resources=request.rbac_resources,
        network_policies=request.network_policies,
    )

    try:
        posture = engine.scan_cluster(config)
    except Exception as exc:
        logger.exception("Cluster scan failed for %s", request.cluster_name)
        raise HTTPException(status_code=500, detail=f"Scan failed: {exc}") from exc

    return _posture_to_response(posture)


@router.get(
    "/rbac",
    summary="RBAC analysis results",
    response_model=Dict[str, Any],
)
def get_rbac_analysis() -> Dict[str, Any]:
    """Return RBAC analysis from the most recent scan.

    Includes cluster-admin bindings, wildcard permissions, overprivileged
    service accounts, escalation paths, and unused roles.
    """
    engine = get_k8s_engine()
    posture = engine.get_cached_posture()
    if posture is None or posture.rbac_analysis is None:
        raise HTTPException(
            status_code=404,
            detail="No RBAC analysis available. POST /api/v1/k8s/scan first.",
        )
    return posture.rbac_analysis.model_dump()


@router.get(
    "/network-policies",
    summary="Network policy audit results",
    response_model=Dict[str, Any],
)
def get_network_policy_audit() -> Dict[str, Any]:
    """Return network policy audit results from the most recent scan.

    Shows default-deny status, coverage percentage, permissive rules,
    and namespace isolation gaps.
    """
    engine = get_k8s_engine()
    posture = engine.get_cached_posture()
    if posture is None or posture.network_policy_audit is None:
        raise HTTPException(
            status_code=404,
            detail="No network policy audit available. POST /api/v1/k8s/scan first.",
        )
    return posture.network_policy_audit.model_dump()


@router.get(
    "/images",
    summary="Image security findings",
    response_model=Dict[str, Any],
)
def get_image_security() -> Dict[str, Any]:
    """Return image security findings from the most recent scan.

    Includes latest-tag usage, untrusted registries, pull policy violations,
    and image signing status.
    """
    engine = get_k8s_engine()
    posture = engine.get_cached_posture()
    if posture is None or posture.image_security_report is None:
        raise HTTPException(
            status_code=404,
            detail="No image security report available. POST /api/v1/k8s/scan first.",
        )
    return posture.image_security_report.model_dump()


@router.get(
    "/admission-rules",
    summary="Active admission control rules",
    response_model=List[Dict[str, Any]],
)
def get_admission_rules() -> List[Dict[str, Any]]:
    """Return all active admission control rules configured in the engine."""
    engine = get_k8s_engine()
    return [r.model_dump() for r in engine.get_admission_rules()]


@router.post(
    "/admission-rules",
    summary="Add or replace an admission control rule",
    response_model=Dict[str, Any],
    status_code=201,
)
def add_admission_rule(request: AdmissionRuleRequest) -> Dict[str, Any]:
    """Add a new admission control rule or replace an existing one by name."""
    if request.action not in ("deny", "warn", "audit"):
        raise HTTPException(status_code=400, detail="action must be deny | warn | audit")

    engine = get_k8s_engine()
    rule = AdmissionRule(
        name=request.name,
        description=request.description,
        action=request.action,
        enabled=request.enabled,
        conditions=request.conditions,
    )
    engine.add_admission_rule(rule)
    logger.info("Admission rule added/updated: %s", rule.name)
    return rule.model_dump()


@router.get(
    "/secrets",
    summary="Secrets management audit results",
    response_model=Dict[str, Any],
)
def get_secrets_audit() -> Dict[str, Any]:
    """Return secrets management audit from the most recent scan.

    Shows secrets exposed as env vars, secrets in ConfigMaps, etcd
    encryption status, and External Secrets Operator presence.
    """
    engine = get_k8s_engine()
    posture = engine.get_cached_posture()
    if posture is None or posture.secrets_audit is None:
        raise HTTPException(
            status_code=404,
            detail="No secrets audit available. POST /api/v1/k8s/scan first.",
        )
    return posture.secrets_audit.model_dump()


@router.get(
    "/check-results",
    summary="Detailed check results from latest scan",
    response_model=List[Dict[str, Any]],
)
def get_check_results(
    category: Optional[str] = Query(None, description="Filter by check category"),
) -> List[Dict[str, Any]]:
    """Return per-check results from the most recent scan, optionally filtered by category."""
    engine = get_k8s_engine()
    posture = engine.get_cached_posture()
    if posture is None:
        raise HTTPException(
            status_code=404,
            detail="No scan results available. POST /api/v1/k8s/scan first.",
        )

    results = posture.check_results
    if category:
        try:
            cat = CheckCategory(category.lower())
            results = [cr for cr in results if cr.category == cat]
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid category: {category}")

    return [cr.model_dump(mode="json") for cr in results]
