"""Kubernetes Security Posture Management (KSPM) Engine.

Implements NSA/CISA Kubernetes Hardening Guide checks, RBAC analysis,
network policy audits, image security, secrets management, admission
control, and cluster scoring for ALDECI.

Usage:
    from core.k8s_security import K8sSecurityEngine, get_k8s_engine
    engine = get_k8s_engine()
    posture = engine.scan_cluster(cluster_config)
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import threading
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

import structlog
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# TrustGraph event-bus wiring (auto-added by hub-wiring wave)
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload):  # type: ignore[no-untyped-def]
    """Emit an event to the TrustGraph event bus. Never raises."""
    if _get_tg_bus is None:
        return
    try:
        bus = _get_tg_bus()
        if bus is None:
            return
        emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
        if emit is None:
            return
        result = emit(event_type, payload)
        try:
            import asyncio as _aio
            import inspect as _insp
            if _insp.iscoroutine(result):
                try:
                    loop = _aio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    result.close()
        except Exception:  # pragma: no cover
            pass
    except Exception:  # pragma: no cover
        pass


# Module-load heartbeat
try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass


logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CheckCategory(str, Enum):
    POD_SECURITY = "pod_security"
    RBAC = "rbac"
    NETWORK_POLICY = "network_policy"
    IMAGE_SECURITY = "image_security"
    SECRETS_MANAGEMENT = "secrets_management"
    ADMISSION_CONTROL = "admission_control"
    CLUSTER_CONFIG = "cluster_config"


class CheckStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"


class PodSecurityStandard(str, Enum):
    PRIVILEGED = "privileged"
    BASELINE = "baseline"
    RESTRICTED = "restricted"


class ImagePullPolicy(str, Enum):
    ALWAYS = "Always"
    IF_NOT_PRESENT = "IfNotPresent"
    NEVER = "Never"


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------

class K8sResource(BaseModel):
    """Represents a Kubernetes resource being evaluated."""
    kind: str
    name: str
    namespace: Optional[str] = None
    api_version: str = "v1"
    labels: Dict[str, str] = Field(default_factory=dict)
    annotations: Dict[str, str] = Field(default_factory=dict)
    spec: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class K8sFinding(BaseModel):
    """A single security finding from a K8s check."""
    id: str = Field(default_factory=lambda: f"k8s-{uuid.uuid4().hex[:10]}")
    check_id: str
    title: str
    description: str
    severity: Severity
    category: CheckCategory
    status: CheckStatus
    resource_kind: Optional[str] = None
    resource_name: Optional[str] = None
    namespace: Optional[str] = None
    remediation: str = ""
    references: List[str] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CheckResult(BaseModel):
    """Result of running a single hardening check."""
    check_id: str
    title: str
    category: CheckCategory
    status: CheckStatus
    severity: Severity
    findings: List[K8sFinding] = Field(default_factory=list)
    passed_resources: int = 0
    failed_resources: int = 0
    score_contribution: float = 0.0


class RBACAnalysis(BaseModel):
    """RBAC analysis results for a cluster."""
    cluster_admin_bindings: List[Dict[str, Any]] = Field(default_factory=list)
    wildcard_permissions: List[Dict[str, Any]] = Field(default_factory=list)
    overprivileged_service_accounts: List[Dict[str, Any]] = Field(default_factory=list)
    unused_roles: List[str] = Field(default_factory=list)
    escalation_paths: List[Dict[str, Any]] = Field(default_factory=list)
    total_roles: int = 0
    total_bindings: int = 0
    risk_score: float = 0.0


class NetworkPolicyAudit(BaseModel):
    """Network policy audit results."""
    has_default_deny: bool = False
    namespaces_without_policy: List[str] = Field(default_factory=list)
    pods_without_policy: List[Dict[str, str]] = Field(default_factory=list)
    overly_permissive_ingress: List[Dict[str, Any]] = Field(default_factory=list)
    overly_permissive_egress: List[Dict[str, Any]] = Field(default_factory=list)
    isolated_namespaces: List[str] = Field(default_factory=list)
    total_policies: int = 0
    coverage_percent: float = 0.0


class ImageSecurityReport(BaseModel):
    """Image security findings."""
    images_with_latest_tag: List[str] = Field(default_factory=list)
    untrusted_registry_images: List[str] = Field(default_factory=list)
    missing_pull_policy: List[Dict[str, str]] = Field(default_factory=list)
    unsigned_images: List[str] = Field(default_factory=list)
    total_images: int = 0
    trusted_registries: List[str] = Field(default_factory=list)


class SecretsAudit(BaseModel):
    """Secrets management audit results."""
    secrets_as_env_vars: List[Dict[str, str]] = Field(default_factory=list)
    secrets_in_configmaps: List[str] = Field(default_factory=list)
    unencrypted_secrets: List[str] = Field(default_factory=list)
    external_secrets_operator_present: bool = False
    etcd_encryption_enabled: bool = False
    total_secrets: int = 0


class AdmissionRule(BaseModel):
    """An admission control rule."""
    id: str = Field(default_factory=lambda: f"admission-{uuid.uuid4().hex[:8]}")
    name: str
    description: str
    action: str  # deny, warn, audit
    enabled: bool = True
    conditions: Dict[str, Any] = Field(default_factory=dict)


class AdmissionResult(BaseModel):
    """Result of evaluating a resource against admission rules."""
    resource_kind: str
    resource_name: str
    namespace: Optional[str] = None
    allowed: bool = True
    violations: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    applied_rules: List[str] = Field(default_factory=list)


class NamespaceScore(BaseModel):
    """Security score for a single namespace."""
    namespace: str
    score: float  # 0-100
    total_checks: int = 0
    passed_checks: int = 0
    failed_checks: int = 0
    critical_findings: int = 0
    high_findings: int = 0


class WorkloadScore(BaseModel):
    """Security score for a single workload."""
    name: str
    namespace: str
    kind: str
    score: float  # 0-100
    findings: List[str] = Field(default_factory=list)


class ClusterPosture(BaseModel):
    """Overall cluster security posture."""
    cluster_id: str = Field(default_factory=lambda: f"cluster-{uuid.uuid4().hex[:8]}")
    cluster_name: str = "default"
    overall_score: float = 0.0  # 0-100
    grade: str = "F"
    total_checks: int = 0
    passed_checks: int = 0
    failed_checks: int = 0
    warned_checks: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    findings: List[K8sFinding] = Field(default_factory=list)
    check_results: List[CheckResult] = Field(default_factory=list)
    rbac_analysis: Optional[RBACAnalysis] = None
    network_policy_audit: Optional[NetworkPolicyAudit] = None
    image_security_report: Optional[ImageSecurityReport] = None
    secrets_audit: Optional[SecretsAudit] = None
    namespace_scores: List[NamespaceScore] = Field(default_factory=list)
    workload_scores: List[WorkloadScore] = Field(default_factory=list)
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    scan_duration_ms: int = 0


class ClusterConfig(BaseModel):
    """Input configuration for scanning a cluster."""
    cluster_name: str = "default"
    kubeconfig_path: Optional[str] = None
    in_cluster: bool = False
    context: Optional[str] = None
    namespaces: List[str] = Field(default_factory=list)  # empty = all
    trusted_registries: List[str] = Field(
        default_factory=lambda: [
            "gcr.io", "registry.k8s.io", "quay.io",
            "docker.io/library", "ghcr.io", "mcr.microsoft.com",
        ]
    )
    # Synthetic resources for testing / offline analysis
    resources: List[K8sResource] = Field(default_factory=list)
    rbac_resources: List[Dict[str, Any]] = Field(default_factory=list)
    network_policies: List[Dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# NSA/CISA Check Definitions
# ---------------------------------------------------------------------------

# (check_id, title, severity, category, remediation, references)
_NSA_CHECKS: List[Tuple[str, str, Severity, CheckCategory, str, List[str]]] = [
    (
        "K8S-PS-001", "No privileged containers", Severity.CRITICAL, CheckCategory.POD_SECURITY,
        "Set securityContext.privileged=false on all containers.",
        ["NSA/CISA K8s Hardening Guide §3.1", "CIS Benchmark 5.2.1"],
    ),
    (
        "K8S-PS-002", "No hostNetwork usage", Severity.HIGH, CheckCategory.POD_SECURITY,
        "Set spec.hostNetwork=false to prevent pods sharing the host network namespace.",
        ["NSA/CISA K8s Hardening Guide §3.2"],
    ),
    (
        "K8S-PS-003", "No hostPID usage", Severity.HIGH, CheckCategory.POD_SECURITY,
        "Set spec.hostPID=false to prevent pods sharing the host PID namespace.",
        ["NSA/CISA K8s Hardening Guide §3.2"],
    ),
    (
        "K8S-PS-004", "No hostIPC usage", Severity.HIGH, CheckCategory.POD_SECURITY,
        "Set spec.hostIPC=false to prevent pods sharing the host IPC namespace.",
        ["NSA/CISA K8s Hardening Guide §3.2"],
    ),
    (
        "K8S-PS-005", "Read-only root filesystem", Severity.MEDIUM, CheckCategory.POD_SECURITY,
        "Set securityContext.readOnlyRootFilesystem=true on all containers.",
        ["NSA/CISA K8s Hardening Guide §3.3", "CIS Benchmark 5.2.4"],
    ),
    (
        "K8S-PS-006", "Drop ALL capabilities", Severity.HIGH, CheckCategory.POD_SECURITY,
        "Set securityContext.capabilities.drop=['ALL'] on all containers.",
        ["NSA/CISA K8s Hardening Guide §3.4", "CIS Benchmark 5.2.7"],
    ),
    (
        "K8S-PS-007", "Run as non-root user", Severity.HIGH, CheckCategory.POD_SECURITY,
        "Set securityContext.runAsNonRoot=true and runAsUser>=1000.",
        ["NSA/CISA K8s Hardening Guide §3.5", "CIS Benchmark 5.2.6"],
    ),
    (
        "K8S-PS-008", "CPU resource limits set", Severity.MEDIUM, CheckCategory.POD_SECURITY,
        "Set resources.limits.cpu on all containers to prevent CPU starvation attacks.",
        ["NSA/CISA K8s Hardening Guide §3.6"],
    ),
    (
        "K8S-PS-009", "Memory resource limits set", Severity.MEDIUM, CheckCategory.POD_SECURITY,
        "Set resources.limits.memory on all containers to prevent OOM-based DoS.",
        ["NSA/CISA K8s Hardening Guide §3.6"],
    ),
    (
        "K8S-PS-010", "No allowPrivilegeEscalation", Severity.HIGH, CheckCategory.POD_SECURITY,
        "Set securityContext.allowPrivilegeEscalation=false on all containers.",
        ["CIS Benchmark 5.2.5"],
    ),
    (
        "K8S-PS-011", "Seccomp profile set", Severity.MEDIUM, CheckCategory.POD_SECURITY,
        "Set securityContext.seccompProfile.type=RuntimeDefault or Localhost.",
        ["NSA/CISA K8s Hardening Guide §3.7"],
    ),
    (
        "K8S-PS-012", "Pod Security Standards enforced (restricted)", Severity.HIGH, CheckCategory.POD_SECURITY,
        "Apply pod-security.kubernetes.io/enforce=restricted label on namespaces.",
        ["PSS documentation: https://kubernetes.io/docs/concepts/security/pod-security-standards/"],
    ),
    (
        "K8S-PS-013", "No hostPath volume mounts", Severity.HIGH, CheckCategory.POD_SECURITY,
        "Avoid hostPath volumes; use PVCs instead to prevent host filesystem access.",
        ["NSA/CISA K8s Hardening Guide §3.8"],
    ),
    (
        "K8S-PS-014", "ServiceAccountToken automount disabled", Severity.MEDIUM, CheckCategory.POD_SECURITY,
        "Set automountServiceAccountToken=false on pods that don't need API access.",
        ["CIS Benchmark 5.1.6"],
    ),
    (
        "K8S-RBAC-001", "No cluster-admin bindings for non-admin subjects", Severity.CRITICAL, CheckCategory.RBAC,
        "Review ClusterRoleBindings with cluster-admin and remove unnecessary grants.",
        ["NSA/CISA K8s Hardening Guide §4.1", "CIS Benchmark 5.1.1"],
    ),
    (
        "K8S-RBAC-002", "No wildcard permissions in roles", Severity.HIGH, CheckCategory.RBAC,
        "Replace wildcard verbs/resources with explicit grants in Role/ClusterRole.",
        ["NSA/CISA K8s Hardening Guide §4.2", "CIS Benchmark 5.1.3"],
    ),
    (
        "K8S-RBAC-003", "No overprivileged service accounts", Severity.HIGH, CheckCategory.RBAC,
        "Apply least-privilege; avoid attaching powerful roles to default service accounts.",
        ["NSA/CISA K8s Hardening Guide §4.3"],
    ),
    (
        "K8S-RBAC-004", "No unused roles", Severity.LOW, CheckCategory.RBAC,
        "Remove Role/ClusterRole objects not referenced by any binding.",
        ["CIS Benchmark 5.1.2"],
    ),
    (
        "K8S-RBAC-005", "No role escalation paths", Severity.CRITICAL, CheckCategory.RBAC,
        "Audit roles that can create/bind roles, impersonate, or modify webhooks.",
        ["NSA/CISA K8s Hardening Guide §4.4"],
    ),
    (
        "K8S-NET-001", "Default-deny network policy in place", Severity.HIGH, CheckCategory.NETWORK_POLICY,
        "Create a default-deny NetworkPolicy in every namespace before allowing specific traffic.",
        ["NSA/CISA K8s Hardening Guide §5.1"],
    ),
    (
        "K8S-NET-002", "All pods covered by network policy", Severity.MEDIUM, CheckCategory.NETWORK_POLICY,
        "Ensure every pod is selected by at least one NetworkPolicy.",
        ["NSA/CISA K8s Hardening Guide §5.2"],
    ),
    (
        "K8S-NET-003", "No overly permissive ingress rules", Severity.HIGH, CheckCategory.NETWORK_POLICY,
        "Avoid from: [] (allow all) in NetworkPolicy ingress rules.",
        ["NSA/CISA K8s Hardening Guide §5.3"],
    ),
    (
        "K8S-NET-004", "No overly permissive egress rules", Severity.MEDIUM, CheckCategory.NETWORK_POLICY,
        "Avoid to: [] (allow all) in NetworkPolicy egress rules.",
        ["NSA/CISA K8s Hardening Guide §5.3"],
    ),
    (
        "K8S-NET-005", "Namespace isolation verified", Severity.MEDIUM, CheckCategory.NETWORK_POLICY,
        "Use namespace selectors to enforce inter-namespace traffic controls.",
        ["NSA/CISA K8s Hardening Guide §5.4"],
    ),
    (
        "K8S-IMG-001", "No 'latest' image tags in production", Severity.HIGH, CheckCategory.IMAGE_SECURITY,
        "Pin images to specific digests or immutable tags for reproducibility.",
        ["NSA/CISA K8s Hardening Guide §6.1"],
    ),
    (
        "K8S-IMG-002", "Images from trusted registries only", Severity.HIGH, CheckCategory.IMAGE_SECURITY,
        "Restrict image pulls to approved registries via admission policy.",
        ["NSA/CISA K8s Hardening Guide §6.2"],
    ),
    (
        "K8S-IMG-003", "imagePullPolicy=Always for prod workloads", Severity.MEDIUM, CheckCategory.IMAGE_SECURITY,
        "Set imagePullPolicy=Always to ensure latest image digest is pulled each time.",
        ["NSA/CISA K8s Hardening Guide §6.3"],
    ),
    (
        "K8S-IMG-004", "Image signing verified (cosign/notation)", Severity.HIGH, CheckCategory.IMAGE_SECURITY,
        "Enable image signature verification via cosign or notation admission webhook.",
        ["NSA/CISA K8s Hardening Guide §6.4", "SLSA Level 2+"],
    ),
    (
        "K8S-SEC-001", "Secrets not exposed as environment variables", Severity.HIGH, CheckCategory.SECRETS_MANAGEMENT,
        "Mount secrets as volumes instead of environment variables to limit exposure.",
        ["NSA/CISA K8s Hardening Guide §7.1"],
    ),
    (
        "K8S-SEC-002", "No sensitive data in ConfigMaps", Severity.HIGH, CheckCategory.SECRETS_MANAGEMENT,
        "Move sensitive values from ConfigMaps to Secrets with proper encryption.",
        ["NSA/CISA K8s Hardening Guide §7.2"],
    ),
    (
        "K8S-SEC-003", "etcd encryption at rest enabled", Severity.CRITICAL, CheckCategory.SECRETS_MANAGEMENT,
        "Configure EncryptionConfiguration on the API server for Secrets.",
        ["NSA/CISA K8s Hardening Guide §7.3", "CIS Benchmark 1.2.33"],
    ),
    (
        "K8S-SEC-004", "External Secrets Operator or Vault integration", Severity.MEDIUM, CheckCategory.SECRETS_MANAGEMENT,
        "Use an external secrets manager (Vault, AWS SM) via External Secrets Operator.",
        ["NSA/CISA K8s Hardening Guide §7.4"],
    ),
    (
        "K8S-ADM-001", "Admission webhooks reject privileged pods", Severity.CRITICAL, CheckCategory.ADMISSION_CONTROL,
        "Deploy OPA Gatekeeper or Kyverno with policies that deny privileged pods.",
        ["NSA/CISA K8s Hardening Guide §8.1"],
    ),
    (
        "K8S-ADM-002", "Admission webhooks enforce resource limits", Severity.MEDIUM, CheckCategory.ADMISSION_CONTROL,
        "Add admission policy that requires all containers to declare resource limits.",
        ["NSA/CISA K8s Hardening Guide §8.2"],
    ),
    (
        "K8S-ADM-003", "Image allowlist enforced via admission", Severity.HIGH, CheckCategory.ADMISSION_CONTROL,
        "Configure admission webhook to reject images from untrusted registries.",
        ["NSA/CISA K8s Hardening Guide §8.3"],
    ),
    (
        "K8S-ADM-004", "Required labels enforced", Severity.LOW, CheckCategory.ADMISSION_CONTROL,
        "Use admission policy to require team/app/version labels on all workloads.",
        ["Best Practice"],
    ),
    (
        "K8S-CLU-001", "RBAC enabled", Severity.CRITICAL, CheckCategory.CLUSTER_CONFIG,
        "Ensure --authorization-mode includes RBAC on the API server.",
        ["CIS Benchmark 1.2.8"],
    ),
    (
        "K8S-CLU-002", "Anonymous auth disabled", Severity.HIGH, CheckCategory.CLUSTER_CONFIG,
        "Set --anonymous-auth=false on API server and kubelets.",
        ["CIS Benchmark 1.2.1", "4.2.1"],
    ),
    (
        "K8S-CLU-003", "Audit logging enabled", Severity.HIGH, CheckCategory.CLUSTER_CONFIG,
        "Configure audit policy and --audit-log-path on the API server.",
        ["NSA/CISA K8s Hardening Guide §9.1", "CIS Benchmark 3.2.1"],
    ),
    (
        "K8S-CLU-004", "NodeRestriction admission plugin enabled", Severity.MEDIUM, CheckCategory.CLUSTER_CONFIG,
        "Add NodeRestriction to --enable-admission-plugins on the API server.",
        ["CIS Benchmark 1.2.17"],
    ),
]

# Severity weights for scoring
_SEVERITY_WEIGHTS: Dict[Severity, float] = {
    Severity.CRITICAL: 25.0,
    Severity.HIGH: 10.0,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 2.0,
    Severity.INFO: 0.0,
}

# Known dangerous RBAC verbs
_ESCALATION_VERBS: Set[str] = {
    "bind", "escalate", "impersonate", "create", "update", "patch",
}
_ESCALATION_RESOURCES: Set[str] = {
    "roles", "clusterroles", "rolebindings", "clusterrolebindings",
    "validatingwebhookconfigurations", "mutatingwebhookconfigurations",
}

# Sensitive key patterns for configmap secret detection
_SENSITIVE_PATTERNS: List[re.Pattern] = [
    re.compile(r"(?i)(password|passwd|secret|token|api[-_]?key|private[-_]?key|credential|auth)"),
]


# ---------------------------------------------------------------------------
# K8s Security Engine
# ---------------------------------------------------------------------------

class K8sSecurityEngine:
    """KSPM engine implementing NSA/CISA hardening checks for Kubernetes clusters."""

    def __init__(self, trusted_registries: Optional[List[str]] = None) -> None:
        self._lock = threading.Lock()
        self._admission_rules: List[AdmissionRule] = self._default_admission_rules()
        self._trusted_registries: List[str] = trusted_registries or [
            "gcr.io", "registry.k8s.io", "quay.io",
            "docker.io/library", "ghcr.io", "mcr.microsoft.com",
            "public.ecr.aws",
        ]
        self._posture_cache: Optional[ClusterPosture] = None
        logger.info("K8sSecurityEngine initialised", trusted_registries=len(self._trusted_registries))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_cluster(self, config: ClusterConfig) -> ClusterPosture:
        """Run a full KSPM scan using provided resources (offline/synthetic mode)."""
        _emit_event("asset.discovered", {"module": __name__, "action": "scan_cluster"})
        import time
        t0 = time.monotonic()
        logger.info("Starting K8s cluster scan", cluster=config.cluster_name)

        posture = ClusterPosture(cluster_name=config.cluster_name)
        all_findings: List[K8sFinding] = []
        check_results: List[CheckResult] = []

        trusted = config.trusted_registries or self._trusted_registries
        resources = config.resources

        # --- Pod Security Checks ---
        ps_results = self._run_pod_security_checks(resources)
        check_results.extend(ps_results)
        for cr in ps_results:
            all_findings.extend(cr.findings)

        # --- RBAC Analysis ---
        rbac = self._analyse_rbac(config.rbac_resources)
        rbac_check_results = self._rbac_to_check_results(rbac)
        check_results.extend(rbac_check_results)
        for cr in rbac_check_results:
            all_findings.extend(cr.findings)

        # --- Network Policy Audit ---
        net_audit = self._audit_network_policies(config.network_policies, resources)
        net_check_results = self._network_audit_to_check_results(net_audit)
        check_results.extend(net_check_results)
        for cr in net_check_results:
            all_findings.extend(cr.findings)

        # --- Image Security ---
        img_report = self._check_image_security(resources, trusted)
        img_check_results = self._image_report_to_check_results(img_report)
        check_results.extend(img_check_results)
        for cr in img_check_results:
            all_findings.extend(cr.findings)

        # --- Secrets Management ---
        secrets_audit = self._audit_secrets(resources)
        sec_check_results = self._secrets_audit_to_check_results(secrets_audit)
        check_results.extend(sec_check_results)
        for cr in sec_check_results:
            all_findings.extend(cr.findings)

        # --- Admission Control ---
        adm_check_results = self._check_admission_control(resources)
        check_results.extend(adm_check_results)
        for cr in adm_check_results:
            all_findings.extend(cr.findings)

        # --- Scoring ---
        overall_score = self._calculate_overall_score(check_results)
        ns_scores = self._calculate_namespace_scores(resources, all_findings)
        wl_scores = self._calculate_workload_scores(resources, all_findings)

        posture.findings = all_findings
        posture.check_results = check_results
        posture.overall_score = overall_score
        posture.grade = self._score_to_grade(overall_score)
        posture.total_checks = len(check_results)
        posture.passed_checks = sum(1 for c in check_results if c.status == CheckStatus.PASS)
        posture.failed_checks = sum(1 for c in check_results if c.status == CheckStatus.FAIL)
        posture.warned_checks = sum(1 for c in check_results if c.status == CheckStatus.WARN)
        posture.critical_findings = sum(1 for f in all_findings if f.severity == Severity.CRITICAL)
        posture.high_findings = sum(1 for f in all_findings if f.severity == Severity.HIGH)
        posture.medium_findings = sum(1 for f in all_findings if f.severity == Severity.MEDIUM)
        posture.low_findings = sum(1 for f in all_findings if f.severity == Severity.LOW)
        posture.rbac_analysis = rbac
        posture.network_policy_audit = net_audit
        posture.image_security_report = img_report
        posture.secrets_audit = secrets_audit
        posture.namespace_scores = ns_scores
        posture.workload_scores = wl_scores
        posture.scan_duration_ms = int((time.monotonic() - t0) * 1000)

        with self._lock:
            self._posture_cache = posture

        logger.info(
            "Cluster scan complete",
            cluster=config.cluster_name,
            score=overall_score,
            grade=posture.grade,
            findings=len(all_findings),
            duration_ms=posture.scan_duration_ms,
        )
        return posture

    def get_cached_posture(self) -> Optional[ClusterPosture]:
        """Return the most recently computed posture, or None."""
        with self._lock:
            return self._posture_cache

    def evaluate_admission(self, resource: K8sResource) -> AdmissionResult:
        """Evaluate a resource against all active admission rules."""
        _emit_event("finding.created", {"module": __name__, "action": "evaluate_admission"})
        result = AdmissionResult(
            resource_kind=resource.kind,
            resource_name=resource.name,
            namespace=resource.namespace,
        )
        for rule in self._admission_rules:
            if not rule.enabled:
                continue
            violation = self._apply_admission_rule(rule, resource)
            result.applied_rules.append(rule.name)
            if violation:
                if rule.action == "deny":
                    result.allowed = False
                    result.violations.append(violation)
                else:
                    result.warnings.append(violation)
        return result

    def get_admission_rules(self) -> List[AdmissionRule]:
        """Return all active admission rules."""
        return list(self._admission_rules)

    def add_admission_rule(self, rule: AdmissionRule) -> None:
        """Add or replace an admission rule."""
        with self._lock:
            existing = [r for r in self._admission_rules if r.id != rule.id]
            existing.append(rule)
            self._admission_rules = existing

    # ------------------------------------------------------------------
    # Pod Security Checks
    # ------------------------------------------------------------------

    def _run_pod_security_checks(self, resources: List[K8sResource]) -> List[CheckResult]:
        pods = [r for r in resources if r.kind in ("Pod", "Deployment", "DaemonSet", "StatefulSet", "Job", "CronJob")]
        results: List[CheckResult] = []

        check_fns = [
            ("K8S-PS-001", self._check_no_privileged),
            ("K8S-PS-002", self._check_no_host_network),
            ("K8S-PS-003", self._check_no_host_pid),
            ("K8S-PS-004", self._check_no_host_ipc),
            ("K8S-PS-005", self._check_read_only_rootfs),
            ("K8S-PS-006", self._check_drop_all_capabilities),
            ("K8S-PS-007", self._check_run_as_non_root),
            ("K8S-PS-008", self._check_cpu_limits),
            ("K8S-PS-009", self._check_memory_limits),
            ("K8S-PS-010", self._check_no_privilege_escalation),
            ("K8S-PS-011", self._check_seccomp_profile),
            ("K8S-PS-012", self._check_pod_security_standards),
            ("K8S-PS-013", self._check_no_host_path),
            ("K8S-PS-014", self._check_automount_sa_token),
        ]

        check_meta = {c[0]: c for c in _NSA_CHECKS}

        for check_id, fn in check_fns:
            meta = check_meta.get(check_id)
            if not meta:
                continue
            _, title, severity, category, remediation, references = meta
            findings: List[K8sFinding] = []
            passed = 0
            failed = 0
            for resource in pods:
                containers = self._get_containers(resource)
                pod_spec = self._get_pod_spec(resource)
                violations = fn(resource, pod_spec, containers)
                if violations:
                    failed += 1
                    for violation in violations:
                        findings.append(K8sFinding(
                            check_id=check_id,
                            title=title,
                            description=violation,
                            severity=severity,
                            category=category,
                            status=CheckStatus.FAIL,
                            resource_kind=resource.kind,
                            resource_name=resource.name,
                            namespace=resource.namespace,
                            remediation=remediation,
                            references=references,
                        ))
                else:
                    passed += 1

            status = CheckStatus.PASS if not findings else CheckStatus.FAIL
            if not pods:
                status = CheckStatus.NOT_APPLICABLE

            results.append(CheckResult(
                check_id=check_id,
                title=title,
                category=category,
                status=status,
                severity=severity,
                findings=findings,
                passed_resources=passed,
                failed_resources=failed,
                score_contribution=_SEVERITY_WEIGHTS[severity] if not findings else 0.0,
            ))
        return results

    def _get_pod_spec(self, resource: K8sResource) -> Dict[str, Any]:
        spec = resource.spec
        if resource.kind in ("Deployment", "StatefulSet", "DaemonSet"):
            return spec.get("template", {}).get("spec", {})
        if resource.kind == "CronJob":
            return spec.get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec", {})
        if resource.kind == "Job":
            return spec.get("template", {}).get("spec", {})
        return spec  # Pod

    def _get_containers(self, resource: K8sResource) -> List[Dict[str, Any]]:
        pod_spec = self._get_pod_spec(resource)
        containers = pod_spec.get("containers", [])
        containers += pod_spec.get("initContainers", [])
        return containers

    def _check_no_privileged(self, resource: K8sResource, pod_spec: Dict, containers: List[Dict]) -> List[str]:
        violations = []
        for c in containers:
            if c.get("securityContext", {}).get("privileged") is True:
                violations.append(f"Container '{c.get('name')}' runs as privileged")
        return violations

    def _check_no_host_network(self, resource: K8sResource, pod_spec: Dict, containers: List[Dict]) -> List[str]:
        if pod_spec.get("hostNetwork") is True:
            return [f"{resource.kind}/{resource.name} uses hostNetwork"]
        return []

    def _check_no_host_pid(self, resource: K8sResource, pod_spec: Dict, containers: List[Dict]) -> List[str]:
        if pod_spec.get("hostPID") is True:
            return [f"{resource.kind}/{resource.name} uses hostPID"]
        return []

    def _check_no_host_ipc(self, resource: K8sResource, pod_spec: Dict, containers: List[Dict]) -> List[str]:
        if pod_spec.get("hostIPC") is True:
            return [f"{resource.kind}/{resource.name} uses hostIPC"]
        return []

    def _check_read_only_rootfs(self, resource: K8sResource, pod_spec: Dict, containers: List[Dict]) -> List[str]:
        violations = []
        for c in containers:
            if not c.get("securityContext", {}).get("readOnlyRootFilesystem"):
                violations.append(f"Container '{c.get('name')}' does not set readOnlyRootFilesystem=true")
        return violations

    def _check_drop_all_capabilities(self, resource: K8sResource, pod_spec: Dict, containers: List[Dict]) -> List[str]:
        violations = []
        for c in containers:
            caps = c.get("securityContext", {}).get("capabilities", {})
            drop = caps.get("drop", [])
            if "ALL" not in [d.upper() for d in drop]:
                violations.append(f"Container '{c.get('name')}' does not drop ALL capabilities")
        return violations

    def _check_run_as_non_root(self, resource: K8sResource, pod_spec: Dict, containers: List[Dict]) -> List[str]:
        violations = []
        # Check pod-level first
        pod_sc = pod_spec.get("securityContext", {})
        pod_non_root = pod_sc.get("runAsNonRoot")
        pod_run_as_user = pod_sc.get("runAsUser", 0)

        for c in containers:
            c_sc = c.get("securityContext", {})
            non_root = c_sc.get("runAsNonRoot", pod_non_root)
            run_as_user = c_sc.get("runAsUser", pod_run_as_user)

            if non_root is False:
                violations.append(f"Container '{c.get('name')}' explicitly sets runAsNonRoot=false")
            elif non_root is not True and run_as_user == 0:
                violations.append(f"Container '{c.get('name')}' may run as root (no runAsNonRoot or runAsUser)")
        return violations

    def _check_cpu_limits(self, resource: K8sResource, pod_spec: Dict, containers: List[Dict]) -> List[str]:
        violations = []
        for c in containers:
            limits = c.get("resources", {}).get("limits", {})
            if not limits.get("cpu"):
                violations.append(f"Container '{c.get('name')}' has no CPU limit")
        return violations

    def _check_memory_limits(self, resource: K8sResource, pod_spec: Dict, containers: List[Dict]) -> List[str]:
        violations = []
        for c in containers:
            limits = c.get("resources", {}).get("limits", {})
            if not limits.get("memory"):
                violations.append(f"Container '{c.get('name')}' has no memory limit")
        return violations

    def _check_no_privilege_escalation(self, resource: K8sResource, pod_spec: Dict, containers: List[Dict]) -> List[str]:
        violations = []
        for c in containers:
            ape = c.get("securityContext", {}).get("allowPrivilegeEscalation")
            if ape is not False:
                violations.append(f"Container '{c.get('name')}' does not set allowPrivilegeEscalation=false")
        return violations

    def _check_seccomp_profile(self, resource: K8sResource, pod_spec: Dict, containers: List[Dict]) -> List[str]:
        pod_sc = pod_spec.get("securityContext", {})
        if pod_sc.get("seccompProfile"):
            return []
        violations = []
        for c in containers:
            c_sc = c.get("securityContext", {})
            if not c_sc.get("seccompProfile"):
                violations.append(f"Container '{c.get('name')}' has no seccompProfile set")
        return violations

    def _check_pod_security_standards(self, resource: K8sResource, pod_spec: Dict, containers: List[Dict]) -> List[str]:
        ns = resource.namespace or "default"
        # We check for the PSS label on the resource's namespace metadata
        # In synthetic mode we check annotations on the resource itself
        labels = resource.labels
        enforce = labels.get("pod-security.kubernetes.io/enforce", "")
        if enforce not in ("restricted", "baseline"):
            return [f"Namespace '{ns}' does not enforce pod-security standards (restricted/baseline)"]
        return []

    def _check_no_host_path(self, resource: K8sResource, pod_spec: Dict, containers: List[Dict]) -> List[str]:
        volumes = pod_spec.get("volumes", [])
        violations = []
        for vol in volumes:
            if "hostPath" in vol:
                violations.append(f"Volume '{vol.get('name')}' uses hostPath: {vol['hostPath'].get('path', '')}")
        return violations

    def _check_automount_sa_token(self, resource: K8sResource, pod_spec: Dict, containers: List[Dict]) -> List[str]:
        if pod_spec.get("automountServiceAccountToken") is True:
            return [f"{resource.kind}/{resource.name} has automountServiceAccountToken=true"]
        return []

    # ------------------------------------------------------------------
    # RBAC Analysis
    # ------------------------------------------------------------------

    def _analyse_rbac(self, rbac_resources: List[Dict[str, Any]]) -> RBACAnalysis:
        analysis = RBACAnalysis()
        roles: Dict[str, Dict] = {}
        bindings: List[Dict] = []
        cluster_role_bindings: List[Dict] = []

        for r in rbac_resources:
            kind = r.get("kind", "")
            if kind in ("Role", "ClusterRole"):
                key = f"{kind}/{r.get('metadata', {}).get('name', '')}"
                roles[key] = r
                analysis.total_roles += 1
            elif kind == "RoleBinding":
                bindings.append(r)
                analysis.total_bindings += 1
            elif kind == "ClusterRoleBinding":
                cluster_role_bindings.append(r)
                analysis.total_bindings += 1

        # Detect cluster-admin bindings
        for crb in cluster_role_bindings:
            role_ref = crb.get("roleRef", {})
            if role_ref.get("name") == "cluster-admin":
                subjects = crb.get("subjects", [])
                for subj in subjects:
                    if subj.get("name") not in ("kube-controller-manager", "kube-scheduler"):
                        analysis.cluster_admin_bindings.append({
                            "binding": crb.get("metadata", {}).get("name"),
                            "subject_kind": subj.get("kind"),
                            "subject_name": subj.get("name"),
                            "namespace": subj.get("namespace"),
                        })

        # Detect wildcard permissions
        bound_role_names: Set[str] = set()
        for b in bindings + cluster_role_bindings:
            role_ref = b.get("roleRef", {})
            bound_role_names.add(f"{role_ref.get('kind', 'ClusterRole')}/{role_ref.get('name', '')}")

        for role_key, role in roles.items():
            rules = role.get("rules", [])
            for rule in rules:
                verbs = rule.get("verbs", [])
                resources_list = rule.get("resources", [])
                if "*" in verbs or "*" in resources_list:
                    analysis.wildcard_permissions.append({
                        "role": role_key,
                        "verbs": verbs,
                        "resources": resources_list,
                    })

        # Detect overprivileged service accounts
        for b in bindings + cluster_role_bindings:
            subjects = b.get("subjects", [])
            role_ref = b.get("roleRef", {})
            role_key = f"{role_ref.get('kind', 'ClusterRole')}/{role_ref.get('name', '')}"
            role = roles.get(role_key, {})
            rules = role.get("rules", [])
            is_dangerous = any(
                "*" in rule.get("verbs", []) or "*" in rule.get("resources", [])
                for rule in rules
            )
            for subj in subjects:
                if subj.get("kind") == "ServiceAccount" and is_dangerous:
                    analysis.overprivileged_service_accounts.append({
                        "service_account": subj.get("name"),
                        "namespace": subj.get("namespace"),
                        "bound_role": role_key,
                    })

        # Unused roles
        for role_key in roles:
            if role_key not in bound_role_names:
                analysis.unused_roles.append(role_key)

        # Escalation paths
        for role_key, role in roles.items():
            rules = role.get("rules", [])
            for rule in rules:
                verbs = set(rule.get("verbs", []))
                resources_set = set(rule.get("resources", []))
                dangerous_verbs = verbs & _ESCALATION_VERBS
                dangerous_resources = resources_set & _ESCALATION_RESOURCES
                if dangerous_verbs and dangerous_resources:
                    analysis.escalation_paths.append({
                        "role": role_key,
                        "dangerous_verbs": list(dangerous_verbs),
                        "dangerous_resources": list(dangerous_resources),
                    })

        # Risk score
        risk = 0.0
        risk += len(analysis.cluster_admin_bindings) * 25.0
        risk += len(analysis.wildcard_permissions) * 10.0
        risk += len(analysis.overprivileged_service_accounts) * 10.0
        risk += len(analysis.escalation_paths) * 20.0
        analysis.risk_score = min(100.0, risk)

        return analysis

    def _rbac_to_check_results(self, rbac: RBACAnalysis) -> List[CheckResult]:
        results = []
        check_meta = {c[0]: c for c in _NSA_CHECKS}

        mapping = [
            ("K8S-RBAC-001", rbac.cluster_admin_bindings, "cluster-admin binding for non-admin subject"),
            ("K8S-RBAC-002", rbac.wildcard_permissions, "wildcard permission in role"),
            ("K8S-RBAC-003", rbac.overprivileged_service_accounts, "overprivileged service account"),
            ("K8S-RBAC-005", rbac.escalation_paths, "role escalation path detected"),
        ]

        for check_id, items, desc in mapping:
            meta = check_meta.get(check_id)
            if not meta:
                continue
            _, title, severity, category, remediation, references = meta
            findings = [
                K8sFinding(
                    check_id=check_id,
                    title=title,
                    description=f"{desc}: {json.dumps(item)}",
                    severity=severity,
                    category=category,
                    status=CheckStatus.FAIL,
                    remediation=remediation,
                    references=references,
                    details=item if isinstance(item, dict) else {},
                )
                for item in items
            ]
            status = CheckStatus.FAIL if findings else CheckStatus.PASS
            results.append(CheckResult(
                check_id=check_id,
                title=title,
                category=category,
                status=status,
                severity=severity,
                findings=findings,
                passed_resources=0 if findings else 1,
                failed_resources=len(findings),
                score_contribution=_SEVERITY_WEIGHTS[severity] if not findings else 0.0,
            ))

        # Unused roles
        meta = check_meta.get("K8S-RBAC-004")
        if meta:
            _, title, severity, category, remediation, references = meta
            findings = [
                K8sFinding(
                    check_id="K8S-RBAC-004",
                    title=title,
                    description=f"Unused role: {role}",
                    severity=severity,
                    category=category,
                    status=CheckStatus.WARN,
                    remediation=remediation,
                    references=references,
                )
                for role in rbac.unused_roles
            ]
            status = CheckStatus.WARN if findings else CheckStatus.PASS
            results.append(CheckResult(
                check_id="K8S-RBAC-004",
                title=title,
                category=category,
                status=status,
                severity=severity,
                findings=findings,
                passed_resources=0 if findings else 1,
                failed_resources=len(findings),
                score_contribution=_SEVERITY_WEIGHTS[severity] if not findings else 0.0,
            ))

        return results

    # ------------------------------------------------------------------
    # Network Policy Audit
    # ------------------------------------------------------------------

    def _audit_network_policies(
        self,
        network_policies: List[Dict[str, Any]],
        resources: List[K8sResource],
    ) -> NetworkPolicyAudit:
        audit = NetworkPolicyAudit(total_policies=len(network_policies))

        namespaces: Set[str] = {r.namespace or "default" for r in resources}
        ns_with_policy: Set[str] = set()
        has_default_deny = False

        for np in network_policies:
            spec = np.get("spec", {})
            ns = np.get("metadata", {}).get("namespace", "default")
            ns_with_policy.add(ns)

            pod_selector = spec.get("podSelector", {})
            ingress = spec.get("ingress", None)
            egress = spec.get("egress", None)
            policy_types = spec.get("policyTypes", [])

            # Default deny: empty podSelector + both Ingress+Egress types + no rules
            is_default_deny = (
                pod_selector == {} and
                ingress == [] and
                egress == [] and
                "Ingress" in policy_types and
                "Egress" in policy_types
            )
            if is_default_deny:
                has_default_deny = True
                audit.isolated_namespaces.append(ns)

            # Overly permissive ingress: from: [] allows all
            if ingress:
                for rule in ingress:
                    if rule.get("from") == [] or rule.get("from") is None and ingress:
                        audit.overly_permissive_ingress.append({
                            "policy": np.get("metadata", {}).get("name"),
                            "namespace": ns,
                        })

            # Overly permissive egress
            if egress:
                for rule in egress:
                    if rule.get("to") == [] or rule.get("to") is None and egress:
                        audit.overly_permissive_egress.append({
                            "policy": np.get("metadata", {}).get("name"),
                            "namespace": ns,
                        })

        audit.has_default_deny = has_default_deny
        audit.namespaces_without_policy = list(namespaces - ns_with_policy)

        # Pods without policy (simplified: pods in namespaces without any policy)
        for r in resources:
            if r.kind in ("Pod", "Deployment", "StatefulSet", "DaemonSet"):
                ns = r.namespace or "default"
                if ns not in ns_with_policy:
                    audit.pods_without_policy.append({"name": r.name, "namespace": ns})

        total_ns = len(namespaces) or 1
        covered = len(namespaces & ns_with_policy)
        audit.coverage_percent = round((covered / total_ns) * 100, 1)

        return audit

    def _network_audit_to_check_results(self, audit: NetworkPolicyAudit) -> List[CheckResult]:
        results = []
        check_meta = {c[0]: c for c in _NSA_CHECKS}

        # K8S-NET-001: default-deny
        meta = check_meta["K8S-NET-001"]
        _, title, severity, category, remediation, references = meta
        findings = []
        if not audit.has_default_deny:
            findings.append(K8sFinding(
                check_id="K8S-NET-001",
                title=title,
                description="No default-deny NetworkPolicy found in any namespace",
                severity=severity,
                category=category,
                status=CheckStatus.FAIL,
                remediation=remediation,
                references=references,
            ))
        results.append(CheckResult(
            check_id="K8S-NET-001",
            title=title,
            category=category,
            status=CheckStatus.FAIL if findings else CheckStatus.PASS,
            severity=severity,
            findings=findings,
            passed_resources=0 if findings else 1,
            failed_resources=len(findings),
            score_contribution=_SEVERITY_WEIGHTS[severity] if not findings else 0.0,
        ))

        # K8S-NET-002: pods without policy
        meta = check_meta["K8S-NET-002"]
        _, title, severity, category, remediation, references = meta
        findings = [
            K8sFinding(
                check_id="K8S-NET-002",
                title=title,
                description=f"Pod '{p['name']}' in namespace '{p['namespace']}' has no NetworkPolicy",
                severity=severity,
                category=category,
                status=CheckStatus.FAIL,
                remediation=remediation,
                references=references,
            )
            for p in audit.pods_without_policy
        ]
        results.append(CheckResult(
            check_id="K8S-NET-002",
            title=title,
            category=category,
            status=CheckStatus.FAIL if findings else CheckStatus.PASS,
            severity=severity,
            findings=findings,
            passed_resources=0 if findings else 1,
            failed_resources=len(findings),
            score_contribution=_SEVERITY_WEIGHTS[severity] if not findings else 0.0,
        ))

        # K8S-NET-003: overly permissive ingress
        meta = check_meta["K8S-NET-003"]
        _, title, severity, category, remediation, references = meta
        findings = [
            K8sFinding(
                check_id="K8S-NET-003",
                title=title,
                description=f"Policy '{p['policy']}' in '{p['namespace']}' has overly permissive ingress",
                severity=severity,
                category=category,
                status=CheckStatus.FAIL,
                remediation=remediation,
                references=references,
            )
            for p in audit.overly_permissive_ingress
        ]
        results.append(CheckResult(
            check_id="K8S-NET-003",
            title=title,
            category=category,
            status=CheckStatus.FAIL if findings else CheckStatus.PASS,
            severity=severity,
            findings=findings,
            passed_resources=0 if findings else 1,
            failed_resources=len(findings),
            score_contribution=_SEVERITY_WEIGHTS[severity] if not findings else 0.0,
        ))

        # K8S-NET-004: overly permissive egress
        meta = check_meta["K8S-NET-004"]
        _, title, severity, category, remediation, references = meta
        findings = [
            K8sFinding(
                check_id="K8S-NET-004",
                title=title,
                description=f"Policy '{p['policy']}' in '{p['namespace']}' has overly permissive egress",
                severity=severity,
                category=category,
                status=CheckStatus.FAIL,
                remediation=remediation,
                references=references,
            )
            for p in audit.overly_permissive_egress
        ]
        results.append(CheckResult(
            check_id="K8S-NET-004",
            title=title,
            category=category,
            status=CheckStatus.FAIL if findings else CheckStatus.PASS,
            severity=severity,
            findings=findings,
            passed_resources=0 if findings else 1,
            failed_resources=len(findings),
            score_contribution=_SEVERITY_WEIGHTS[severity] if not findings else 0.0,
        ))

        # K8S-NET-005: namespace isolation
        meta = check_meta["K8S-NET-005"]
        _, title, severity, category, remediation, references = meta
        findings = [
            K8sFinding(
                check_id="K8S-NET-005",
                title=title,
                description=f"Namespace '{ns}' has no NetworkPolicy coverage",
                severity=severity,
                category=category,
                status=CheckStatus.FAIL,
                remediation=remediation,
                references=references,
            )
            for ns in audit.namespaces_without_policy
        ]
        results.append(CheckResult(
            check_id="K8S-NET-005",
            title=title,
            category=category,
            status=CheckStatus.FAIL if findings else CheckStatus.PASS,
            severity=severity,
            findings=findings,
            passed_resources=0 if findings else 1,
            failed_resources=len(findings),
            score_contribution=_SEVERITY_WEIGHTS[severity] if not findings else 0.0,
        ))

        return results

    # ------------------------------------------------------------------
    # Image Security
    # ------------------------------------------------------------------

    def _check_image_security(
        self,
        resources: List[K8sResource],
        trusted_registries: List[str],
    ) -> ImageSecurityReport:
        report = ImageSecurityReport(trusted_registries=trusted_registries)
        seen_images: Set[str] = set()

        for resource in resources:
            containers = self._get_containers(resource)
            for c in containers:
                image = c.get("image", "")
                if not image or image in seen_images:
                    continue
                seen_images.add(image)
                report.total_images += 1

                # Latest tag
                tag = image.split(":")[-1] if ":" in image else "latest"
                if tag == "latest" or ":" not in image:
                    report.images_with_latest_tag.append(image)

                # Trusted registry
                if not self._is_trusted_registry(image, trusted_registries):
                    report.untrusted_registry_images.append(image)

                # Image signing (stub — would query cosign/notation)
                if not self._is_image_signed(image):
                    report.unsigned_images.append(image)

                # Pull policy
                pull_policy = c.get("imagePullPolicy", "")
                if pull_policy and pull_policy != ImagePullPolicy.ALWAYS:
                    report.missing_pull_policy.append({
                        "container": c.get("name", ""),
                        "image": image,
                        "pull_policy": pull_policy,
                    })

        return report

    def _is_trusted_registry(self, image: str, trusted_registries: List[str]) -> bool:
        # Strip tag/digest
        image_base = image.split(":")[0].split("@")[0]
        # Short names like "nginx" → docker.io/library
        if "/" not in image_base:
            image_base = f"docker.io/library/{image_base}"
        return any(image_base.startswith(reg) for reg in trusted_registries)

    def _is_image_signed(self, image: str) -> bool:
        """Query cosign to verify the image has a valid signature.

        Returns False (unsigned) when:
          - cosign binary is not installed (warns, degrades gracefully)
          - cosign exits non-zero (no valid signature found)
          - cosign times out (treated as unverifiable = unsigned)

        Returns True only when cosign exits 0 (valid signature confirmed).
        """
        cosign_bin = shutil.which("cosign")
        if cosign_bin is None:
            logger.warning(
                "cosign_binary_not_found",
                image=image,
                advice="install cosign for real signature verification",
            )
            return False  # conservative: treat as unsigned when cosign absent

        try:
            result = subprocess.run(
                [cosign_bin, "verify", image],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode == 0:
                logger.info("cosign_verify_ok", image=image)
                return True
            logger.debug(
                "cosign_verify_no_sig",
                image=image,
                returncode=result.returncode,
                stderr=result.stderr[:300] if result.stderr else "",
            )
            return False
        except subprocess.TimeoutExpired:
            logger.warning("cosign_verify_timeout", image=image)
            return False
        except Exception as exc:  # pragma: no cover
            logger.warning("cosign_verify_error", image=image, error=str(exc))
            return False

    def _image_report_to_check_results(self, report: ImageSecurityReport) -> List[CheckResult]:
        results = []
        check_meta = {c[0]: c for c in _NSA_CHECKS}

        checks = [
            ("K8S-IMG-001", report.images_with_latest_tag, lambda i: f"Image uses 'latest' tag or no tag: {i}"),
            ("K8S-IMG-002", report.untrusted_registry_images, lambda i: f"Image from untrusted registry: {i}"),
            ("K8S-IMG-004", report.unsigned_images, lambda i: f"Image not signed (cosign/notation): {i}"),
        ]

        for check_id, items, msg_fn in checks:
            meta = check_meta.get(check_id)
            if not meta:
                continue
            _, title, severity, category, remediation, references = meta
            findings = [
                K8sFinding(
                    check_id=check_id,
                    title=title,
                    description=msg_fn(item),
                    severity=severity,
                    category=category,
                    status=CheckStatus.FAIL,
                    remediation=remediation,
                    references=references,
                )
                for item in items
            ]
            results.append(CheckResult(
                check_id=check_id,
                title=title,
                category=category,
                status=CheckStatus.FAIL if findings else CheckStatus.PASS,
                severity=severity,
                findings=findings,
                passed_resources=report.total_images - len(findings),
                failed_resources=len(findings),
                score_contribution=_SEVERITY_WEIGHTS[severity] if not findings else 0.0,
            ))

        # K8S-IMG-003: imagePullPolicy
        meta = check_meta.get("K8S-IMG-003")
        if meta:
            _, title, severity, category, remediation, references = meta
            findings = [
                K8sFinding(
                    check_id="K8S-IMG-003",
                    title=title,
                    description=f"Container '{p['container']}' uses imagePullPolicy={p['pull_policy']} for image {p['image']}",
                    severity=severity,
                    category=category,
                    status=CheckStatus.WARN,
                    remediation=remediation,
                    references=references,
                )
                for p in report.missing_pull_policy
            ]
            results.append(CheckResult(
                check_id="K8S-IMG-003",
                title=title,
                category=category,
                status=CheckStatus.WARN if findings else CheckStatus.PASS,
                severity=severity,
                findings=findings,
                passed_resources=0 if findings else 1,
                failed_resources=len(findings),
                score_contribution=_SEVERITY_WEIGHTS[severity] if not findings else 0.0,
            ))

        return results

    # ------------------------------------------------------------------
    # Secrets Management
    # ------------------------------------------------------------------

    def _audit_secrets(self, resources: List[K8sResource]) -> SecretsAudit:
        audit = SecretsAudit()

        for resource in resources:
            containers = self._get_containers(resource)
            # Secrets as env vars
            for c in containers:
                for env in c.get("env", []):
                    if env.get("valueFrom", {}).get("secretKeyRef"):
                        audit.secrets_as_env_vars.append({
                            "resource": f"{resource.kind}/{resource.name}",
                            "container": c.get("name", ""),
                            "env_var": env.get("name", ""),
                        })

            # External Secrets Operator check (look for annotation)
            if "external-secrets.io/backend" in resource.annotations:
                audit.external_secrets_operator_present = True

        # ConfigMap secret detection
        [r for r in resources if r.kind == "ConfigMap"]
        for cm in resources:
            if cm.kind != "ConfigMap":
                continue
            data = cm.spec.get("data", {})
            for key, value in data.items():
                if any(p.search(key) for p in _SENSITIVE_PATTERNS):
                    audit.secrets_in_configmaps.append(
                        f"ConfigMap/{cm.name}: key '{key}' looks like a secret"
                    )

        # etcd encryption: check for EncryptionConfig annotation (synthetic mode)
        for r in resources:
            if r.kind == "EncryptionConfiguration":
                audit.etcd_encryption_enabled = True

        audit.total_secrets = len([r for r in resources if r.kind == "Secret"])
        return audit

    def _secrets_audit_to_check_results(self, audit: SecretsAudit) -> List[CheckResult]:
        results = []
        check_meta = {c[0]: c for c in _NSA_CHECKS}

        # K8S-SEC-001: secrets as env vars
        meta = check_meta["K8S-SEC-001"]
        _, title, severity, category, remediation, references = meta
        findings = [
            K8sFinding(
                check_id="K8S-SEC-001",
                title=title,
                description=f"Secret mounted as env var in {s['resource']} container '{s['container']}' var '{s['env_var']}'",
                severity=severity,
                category=category,
                status=CheckStatus.FAIL,
                remediation=remediation,
                references=references,
            )
            for s in audit.secrets_as_env_vars
        ]
        results.append(CheckResult(
            check_id="K8S-SEC-001",
            title=title,
            category=category,
            status=CheckStatus.FAIL if findings else CheckStatus.PASS,
            severity=severity,
            findings=findings,
            passed_resources=0 if findings else 1,
            failed_resources=len(findings),
            score_contribution=_SEVERITY_WEIGHTS[severity] if not findings else 0.0,
        ))

        # K8S-SEC-002: secrets in configmaps
        meta = check_meta["K8S-SEC-002"]
        _, title, severity, category, remediation, references = meta
        findings = [
            K8sFinding(
                check_id="K8S-SEC-002",
                title=title,
                description=s,
                severity=severity,
                category=category,
                status=CheckStatus.FAIL,
                remediation=remediation,
                references=references,
            )
            for s in audit.secrets_in_configmaps
        ]
        results.append(CheckResult(
            check_id="K8S-SEC-002",
            title=title,
            category=category,
            status=CheckStatus.FAIL if findings else CheckStatus.PASS,
            severity=severity,
            findings=findings,
            passed_resources=0 if findings else 1,
            failed_resources=len(findings),
            score_contribution=_SEVERITY_WEIGHTS[severity] if not findings else 0.0,
        ))

        # K8S-SEC-003: etcd encryption
        meta = check_meta["K8S-SEC-003"]
        _, title, severity, category, remediation, references = meta
        findings = []
        if not audit.etcd_encryption_enabled:
            findings.append(K8sFinding(
                check_id="K8S-SEC-003",
                title=title,
                description="etcd encryption at rest not detected (no EncryptionConfiguration resource)",
                severity=severity,
                category=category,
                status=CheckStatus.FAIL,
                remediation=remediation,
                references=references,
            ))
        results.append(CheckResult(
            check_id="K8S-SEC-003",
            title=title,
            category=category,
            status=CheckStatus.FAIL if findings else CheckStatus.PASS,
            severity=severity,
            findings=findings,
            passed_resources=0 if findings else 1,
            failed_resources=len(findings),
            score_contribution=_SEVERITY_WEIGHTS[severity] if not findings else 0.0,
        ))

        # K8S-SEC-004: External Secrets Operator
        meta = check_meta["K8S-SEC-004"]
        _, title, severity, category, remediation, references = meta
        findings = []
        if not audit.external_secrets_operator_present:
            findings.append(K8sFinding(
                check_id="K8S-SEC-004",
                title=title,
                description="External Secrets Operator or Vault integration not detected",
                severity=severity,
                category=category,
                status=CheckStatus.WARN,
                remediation=remediation,
                references=references,
            ))
        results.append(CheckResult(
            check_id="K8S-SEC-004",
            title=title,
            category=category,
            status=CheckStatus.WARN if findings else CheckStatus.PASS,
            severity=severity,
            findings=findings,
            passed_resources=0 if findings else 1,
            failed_resources=0,
            score_contribution=_SEVERITY_WEIGHTS[severity] if not findings else 0.0,
        ))

        return results

    # ------------------------------------------------------------------
    # Admission Control
    # ------------------------------------------------------------------

    def _default_admission_rules(self) -> List[AdmissionRule]:
        return [
            AdmissionRule(
                name="deny-privileged-containers",
                description="Deny pods with privileged containers",
                action="deny",
                conditions={"privileged": True},
            ),
            AdmissionRule(
                name="require-resource-limits",
                description="Deny containers without resource limits",
                action="deny",
                conditions={"require_limits": True},
            ),
            AdmissionRule(
                name="image-allowlist",
                description="Deny images from untrusted registries",
                action="deny",
                conditions={"enforce_registry": True},
            ),
            AdmissionRule(
                name="require-labels",
                description="Warn on workloads missing required labels",
                action="warn",
                conditions={"required_labels": ["app", "team"]},
            ),
        ]

    def _apply_admission_rule(self, rule: AdmissionRule, resource: K8sResource) -> Optional[str]:
        name = rule.name
        conditions = rule.conditions
        containers = self._get_containers(resource)
        self._get_pod_spec(resource)

        if name == "deny-privileged-containers":
            for c in containers:
                if c.get("securityContext", {}).get("privileged") is True:
                    return f"Container '{c.get('name')}' is privileged"

        elif name == "require-resource-limits":
            for c in containers:
                limits = c.get("resources", {}).get("limits", {})
                if not limits.get("cpu") or not limits.get("memory"):
                    return f"Container '{c.get('name')}' missing resource limits"

        elif name == "image-allowlist":
            for c in containers:
                image = c.get("image", "")
                if image and not self._is_trusted_registry(image, self._trusted_registries):
                    return f"Image '{image}' from untrusted registry"

        elif name == "require-labels":
            required = conditions.get("required_labels", [])
            missing = [lbl for lbl in required if lbl not in resource.labels]
            if missing:
                return f"Missing required labels: {missing}"

        return None

    def _check_admission_control(self, resources: List[K8sResource]) -> List[CheckResult]:
        results = []
        check_meta = {c[0]: c for c in _NSA_CHECKS}

        adm_checks = [
            ("K8S-ADM-001", "deny-privileged-containers", CheckStatus.FAIL, Severity.CRITICAL),
            ("K8S-ADM-002", "require-resource-limits", CheckStatus.FAIL, Severity.MEDIUM),
            ("K8S-ADM-003", "image-allowlist", CheckStatus.FAIL, Severity.HIGH),
            ("K8S-ADM-004", "require-labels", CheckStatus.WARN, Severity.LOW),
        ]

        rules_by_name = {r.name: r for r in self._admission_rules}

        for check_id, rule_name, fail_status, severity in adm_checks:
            meta = check_meta.get(check_id)
            if not meta:
                continue
            _, title, sev, category, remediation, references = meta
            rule = rules_by_name.get(rule_name)
            findings = []

            if not rule or not rule.enabled:
                findings.append(K8sFinding(
                    check_id=check_id,
                    title=title,
                    description=f"Admission rule '{rule_name}' is not active",
                    severity=sev,
                    category=category,
                    status=CheckStatus.FAIL,
                    remediation=remediation,
                    references=references,
                ))
            else:
                for resource in resources:
                    violation = self._apply_admission_rule(rule, resource)
                    if violation:
                        findings.append(K8sFinding(
                            check_id=check_id,
                            title=title,
                            description=f"{resource.kind}/{resource.name}: {violation}",
                            severity=sev,
                            category=category,
                            status=fail_status,
                            resource_kind=resource.kind,
                            resource_name=resource.name,
                            namespace=resource.namespace,
                            remediation=remediation,
                            references=references,
                        ))

            status = fail_status if findings else CheckStatus.PASS
            results.append(CheckResult(
                check_id=check_id,
                title=title,
                category=category,
                status=status,
                severity=sev,
                findings=findings,
                passed_resources=0 if findings else len(resources),
                failed_resources=len(findings),
                score_contribution=_SEVERITY_WEIGHTS[sev] if not findings else 0.0,
            ))

        return results

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def _calculate_overall_score(self, check_results: List[CheckResult]) -> float:
        if not check_results:
            return 0.0

        total_weight = sum(_SEVERITY_WEIGHTS[cr.severity] for cr in check_results)
        if total_weight == 0:
            return 100.0

        earned = sum(cr.score_contribution for cr in check_results)
        return round(min(100.0, (earned / total_weight) * 100.0), 1)

    def _calculate_namespace_scores(
        self,
        resources: List[K8sResource],
        findings: List[K8sFinding],
    ) -> List[NamespaceScore]:
        namespaces: Dict[str, NamespaceScore] = {}
        for r in resources:
            ns = r.namespace or "default"
            if ns not in namespaces:
                namespaces[ns] = NamespaceScore(namespace=ns, score=100.0)

        for f in findings:
            ns = f.namespace or "default"
            if ns not in namespaces:
                namespaces[ns] = NamespaceScore(namespace=ns, score=100.0)
            ns_score = namespaces[ns]
            ns_score.total_checks += 1
            if f.status == CheckStatus.FAIL:
                ns_score.failed_checks += 1
                deduction = _SEVERITY_WEIGHTS[f.severity]
                ns_score.score = max(0.0, ns_score.score - deduction)
                if f.severity == Severity.CRITICAL:
                    ns_score.critical_findings += 1
                elif f.severity == Severity.HIGH:
                    ns_score.high_findings += 1
            else:
                ns_score.passed_checks += 1

        return list(namespaces.values())

    def _calculate_workload_scores(
        self,
        resources: List[K8sResource],
        findings: List[K8sFinding],
    ) -> List[WorkloadScore]:
        workload_kinds = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}
        scores: Dict[str, WorkloadScore] = {}

        for r in resources:
            if r.kind not in workload_kinds:
                continue
            key = f"{r.namespace or 'default'}/{r.kind}/{r.name}"
            scores[key] = WorkloadScore(
                name=r.name,
                namespace=r.namespace or "default",
                kind=r.kind,
                score=100.0,
            )

        for f in findings:
            if not f.resource_name or not f.resource_kind:
                continue
            key = f"{f.namespace or 'default'}/{f.resource_kind}/{f.resource_name}"
            if key not in scores:
                continue
            wl = scores[key]
            deduction = _SEVERITY_WEIGHTS[f.severity]
            wl.score = max(0.0, wl.score - deduction)
            wl.findings.append(f.check_id)

        return list(scores.values())

    @staticmethod
    def _score_to_grade(score: float) -> str:
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "F"


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_engine_instance: Optional[K8sSecurityEngine] = None
_engine_lock = threading.Lock()


def get_k8s_engine() -> K8sSecurityEngine:
    """Return the singleton K8sSecurityEngine."""
    global _engine_instance
    if _engine_instance is None:
        with _engine_lock:
            if _engine_instance is None:
                _engine_instance = K8sSecurityEngine()
    return _engine_instance
