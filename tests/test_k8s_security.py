"""Tests for suite-core/core/k8s_security.py — KSPM Engine.

Covers:
- Pod security checks (NSA/CISA hardening guide)
- RBAC analysis
- Network policy audit
- Image security
- Secrets management
- Admission control
- Cluster scoring and grading
- ClusterPosture model
- Router endpoints (unit-level, no HTTP server)

Usage:
    pytest tests/test_k8s_security.py -v --timeout=10
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

# Ensure suite-core is on the path
suite_core_path = str(Path(__file__).parent.parent / "suite-core")
if suite_core_path not in sys.path:
    sys.path.insert(0, suite_core_path)

from core.k8s_security import (
    AdmissionRule,
    AdmissionResult,
    CheckCategory,
    CheckResult,
    CheckStatus,
    ClusterConfig,
    ClusterPosture,
    ImageSecurityReport,
    K8sFinding,
    K8sResource,
    K8sSecurityEngine,
    NetworkPolicyAudit,
    RBACAnalysis,
    SecretsAudit,
    Severity,
    WorkloadScore,
    NamespaceScore,
    get_k8s_engine,
)


# ============================================================================
# Fixtures
# ============================================================================

def _make_pod(
    name: str = "test-pod",
    namespace: str = "default",
    privileged: bool = False,
    host_network: bool = False,
    host_pid: bool = False,
    host_ipc: bool = False,
    read_only_rootfs: bool = True,
    drop_all: bool = True,
    run_as_non_root: bool = True,
    cpu_limit: str = "500m",
    mem_limit: str = "256Mi",
    allow_privilege_escalation: bool = False,
    image: str = "gcr.io/my-app:1.0.0",
    pull_policy: str = "Always",
    automount_sa: bool = False,
    seccomp: bool = True,
    labels: Dict[str, str] | None = None,
) -> K8sResource:
    caps = {"drop": ["ALL"]} if drop_all else {}
    seccomp_ctx = {"type": "RuntimeDefault"} if seccomp else {}
    return K8sResource(
        kind="Pod",
        name=name,
        namespace=namespace,
        labels=labels or {"pod-security.kubernetes.io/enforce": "restricted"},
        spec={
            "hostNetwork": host_network,
            "hostPID": host_pid,
            "hostIPC": host_ipc,
            "automountServiceAccountToken": automount_sa,
            "securityContext": {
                "runAsNonRoot": run_as_non_root,
                "seccompProfile": seccomp_ctx if seccomp else {},
            },
            "containers": [
                {
                    "name": "app",
                    "image": image,
                    "imagePullPolicy": pull_policy,
                    "securityContext": {
                        "privileged": privileged,
                        "readOnlyRootFilesystem": read_only_rootfs,
                        "capabilities": caps,
                        "allowPrivilegeEscalation": allow_privilege_escalation,
                        "seccompProfile": seccomp_ctx if seccomp else {},
                    },
                    "resources": {
                        "limits": {
                            "cpu": cpu_limit,
                            "memory": mem_limit,
                        }
                    },
                }
            ],
        },
    )


def _make_deployment(name: str = "test-deploy", namespace: str = "default", **kwargs) -> K8sResource:
    pod = _make_pod(name=name, namespace=namespace, **kwargs)
    return K8sResource(
        kind="Deployment",
        name=name,
        namespace=namespace,
        labels=pod.labels,
        spec={
            "template": {
                "spec": pod.spec,
            }
        },
    )


def _make_engine() -> K8sSecurityEngine:
    return K8sSecurityEngine(trusted_registries=["gcr.io", "registry.k8s.io", "quay.io"])


def _minimal_config(resources: List[K8sResource] | None = None) -> ClusterConfig:
    return ClusterConfig(
        cluster_name="test-cluster",
        resources=resources or [],
    )


# ============================================================================
# Pydantic Model Tests
# ============================================================================

class TestK8sModels:
    def test_k8s_resource_defaults(self):
        r = K8sResource(kind="Pod", name="foo")
        assert r.api_version == "v1"
        assert r.labels == {}
        assert r.spec == {}

    def test_k8s_finding_auto_id(self):
        f = K8sFinding(
            check_id="K8S-PS-001",
            title="test",
            description="desc",
            severity=Severity.HIGH,
            category=CheckCategory.POD_SECURITY,
            status=CheckStatus.FAIL,
        )
        assert f.id.startswith("k8s-")

    def test_cluster_posture_defaults(self):
        p = ClusterPosture(cluster_name="dev")
        assert p.overall_score == 0.0
        assert p.grade == "F"
        assert p.findings == []

    def test_admission_rule_defaults(self):
        r = AdmissionRule(name="test-rule", description="Test", action="deny")
        assert r.enabled is True
        assert r.id.startswith("admission-")

    def test_namespace_score_model(self):
        ns = NamespaceScore(namespace="kube-system", score=85.0)
        assert ns.score == 85.0

    def test_workload_score_model(self):
        ws = WorkloadScore(name="api", namespace="prod", kind="Deployment", score=72.0)
        assert ws.findings == []


# ============================================================================
# Pod Security Checks
# ============================================================================

class TestPodSecurityChecks:
    def test_compliant_pod_passes_all_checks(self):
        engine = _make_engine()
        pod = _make_pod()
        config = _minimal_config([pod])
        posture = engine.scan_cluster(config)
        ps_failures = [
            f for f in posture.findings
            if f.category == CheckCategory.POD_SECURITY and f.status == CheckStatus.FAIL
        ]
        assert ps_failures == [], f"Expected no pod security failures, got: {[f.check_id for f in ps_failures]}"

    def test_privileged_container_detected(self):
        engine = _make_engine()
        pod = _make_pod(privileged=True)
        config = _minimal_config([pod])
        posture = engine.scan_cluster(config)
        ids = [f.check_id for f in posture.findings]
        assert "K8S-PS-001" in ids

    def test_host_network_detected(self):
        engine = _make_engine()
        pod = _make_pod(host_network=True)
        config = _minimal_config([pod])
        posture = engine.scan_cluster(config)
        ids = [f.check_id for f in posture.findings]
        assert "K8S-PS-002" in ids

    def test_host_pid_detected(self):
        engine = _make_engine()
        pod = _make_pod(host_pid=True)
        config = _minimal_config([pod])
        posture = engine.scan_cluster(config)
        ids = [f.check_id for f in posture.findings]
        assert "K8S-PS-003" in ids

    def test_host_ipc_detected(self):
        engine = _make_engine()
        pod = _make_pod(host_ipc=True)
        config = _minimal_config([pod])
        posture = engine.scan_cluster(config)
        ids = [f.check_id for f in posture.findings]
        assert "K8S-PS-004" in ids

    def test_no_read_only_rootfs_detected(self):
        engine = _make_engine()
        pod = _make_pod(read_only_rootfs=False)
        config = _minimal_config([pod])
        posture = engine.scan_cluster(config)
        ids = [f.check_id for f in posture.findings]
        assert "K8S-PS-005" in ids

    def test_drop_all_caps_missing_detected(self):
        engine = _make_engine()
        pod = _make_pod(drop_all=False)
        config = _minimal_config([pod])
        posture = engine.scan_cluster(config)
        ids = [f.check_id for f in posture.findings]
        assert "K8S-PS-006" in ids

    def test_run_as_root_detected(self):
        engine = _make_engine()
        pod = _make_pod(run_as_non_root=False)
        config = _minimal_config([pod])
        posture = engine.scan_cluster(config)
        ids = [f.check_id for f in posture.findings]
        assert "K8S-PS-007" in ids

    def test_no_cpu_limit_detected(self):
        engine = _make_engine()
        pod = _make_pod(cpu_limit="")
        config = _minimal_config([pod])
        posture = engine.scan_cluster(config)
        ids = [f.check_id for f in posture.findings]
        assert "K8S-PS-008" in ids

    def test_no_memory_limit_detected(self):
        engine = _make_engine()
        pod = _make_pod(mem_limit="")
        config = _minimal_config([pod])
        posture = engine.scan_cluster(config)
        ids = [f.check_id for f in posture.findings]
        assert "K8S-PS-009" in ids

    def test_allow_privilege_escalation_detected(self):
        engine = _make_engine()
        pod = _make_pod(allow_privilege_escalation=True)
        config = _minimal_config([pod])
        posture = engine.scan_cluster(config)
        ids = [f.check_id for f in posture.findings]
        assert "K8S-PS-010" in ids

    def test_no_seccomp_detected(self):
        engine = _make_engine()
        pod = _make_pod(seccomp=False)
        config = _minimal_config([pod])
        posture = engine.scan_cluster(config)
        ids = [f.check_id for f in posture.findings]
        assert "K8S-PS-011" in ids

    def test_no_pss_label_detected(self):
        engine = _make_engine()
        pod = _make_pod(labels={"app": "myapp"})  # no PSS label
        config = _minimal_config([pod])
        posture = engine.scan_cluster(config)
        ids = [f.check_id for f in posture.findings]
        assert "K8S-PS-012" in ids

    def test_host_path_volume_detected(self):
        engine = _make_engine()
        pod = _make_pod()
        pod.spec["volumes"] = [{"name": "host-vol", "hostPath": {"path": "/etc"}}]
        config = _minimal_config([pod])
        posture = engine.scan_cluster(config)
        ids = [f.check_id for f in posture.findings]
        assert "K8S-PS-013" in ids

    def test_automount_sa_token_detected(self):
        engine = _make_engine()
        pod = _make_pod(automount_sa=True)
        config = _minimal_config([pod])
        posture = engine.scan_cluster(config)
        ids = [f.check_id for f in posture.findings]
        assert "K8S-PS-014" in ids

    def test_deployment_pod_spec_extracted(self):
        engine = _make_engine()
        deploy = _make_deployment(privileged=True)
        config = _minimal_config([deploy])
        posture = engine.scan_cluster(config)
        ids = [f.check_id for f in posture.findings]
        assert "K8S-PS-001" in ids


# ============================================================================
# RBAC Analysis
# ============================================================================

class TestRBACAnalysis:
    def _make_role(self, kind: str, name: str, rules: List[Dict]) -> Dict:
        return {"kind": kind, "metadata": {"name": name}, "rules": rules}

    def _make_binding(self, kind: str, name: str, role_name: str, role_kind: str, subjects: List[Dict]) -> Dict:
        return {
            "kind": kind,
            "metadata": {"name": name},
            "roleRef": {"kind": role_kind, "name": role_name},
            "subjects": subjects,
        }

    def test_cluster_admin_binding_detected(self):
        engine = _make_engine()
        crb = self._make_binding(
            "ClusterRoleBinding", "dangerous-binding", "cluster-admin", "ClusterRole",
            [{"kind": "User", "name": "dev-user"}],
        )
        config = ClusterConfig(cluster_name="test", rbac_resources=[crb])
        posture = engine.scan_cluster(config)
        assert posture.rbac_analysis is not None
        assert len(posture.rbac_analysis.cluster_admin_bindings) == 1

    def test_cluster_admin_binding_for_system_accounts_ignored(self):
        engine = _make_engine()
        crb = self._make_binding(
            "ClusterRoleBinding", "system-binding", "cluster-admin", "ClusterRole",
            [{"kind": "User", "name": "kube-controller-manager"}],
        )
        config = ClusterConfig(cluster_name="test", rbac_resources=[crb])
        posture = engine.scan_cluster(config)
        assert len(posture.rbac_analysis.cluster_admin_bindings) == 0

    def test_wildcard_verb_detected(self):
        engine = _make_engine()
        role = self._make_role("ClusterRole", "wildcard-role", [{"verbs": ["*"], "resources": ["pods"]}])
        config = ClusterConfig(cluster_name="test", rbac_resources=[role])
        posture = engine.scan_cluster(config)
        assert len(posture.rbac_analysis.wildcard_permissions) >= 1

    def test_wildcard_resource_detected(self):
        engine = _make_engine()
        role = self._make_role("ClusterRole", "wildcard-res", [{"verbs": ["get"], "resources": ["*"]}])
        config = ClusterConfig(cluster_name="test", rbac_resources=[role])
        posture = engine.scan_cluster(config)
        assert len(posture.rbac_analysis.wildcard_permissions) >= 1

    def test_overprivileged_service_account_detected(self):
        engine = _make_engine()
        role = self._make_role("ClusterRole", "admin-role", [{"verbs": ["*"], "resources": ["*"]}])
        crb = self._make_binding(
            "ClusterRoleBinding", "sa-binding", "admin-role", "ClusterRole",
            [{"kind": "ServiceAccount", "name": "my-sa", "namespace": "default"}],
        )
        config = ClusterConfig(cluster_name="test", rbac_resources=[role, crb])
        posture = engine.scan_cluster(config)
        assert len(posture.rbac_analysis.overprivileged_service_accounts) >= 1

    def test_unused_role_detected(self):
        engine = _make_engine()
        role = self._make_role("ClusterRole", "orphan-role", [{"verbs": ["get"], "resources": ["pods"]}])
        config = ClusterConfig(cluster_name="test", rbac_resources=[role])
        posture = engine.scan_cluster(config)
        assert any("orphan-role" in r for r in posture.rbac_analysis.unused_roles)

    def test_escalation_path_detected(self):
        engine = _make_engine()
        role = self._make_role("ClusterRole", "escalator", [
            {"verbs": ["create", "bind"], "resources": ["clusterroles", "clusterrolebindings"]}
        ])
        config = ClusterConfig(cluster_name="test", rbac_resources=[role])
        posture = engine.scan_cluster(config)
        assert len(posture.rbac_analysis.escalation_paths) >= 1

    def test_clean_rbac_no_findings(self):
        engine = _make_engine()
        role = self._make_role("ClusterRole", "safe-role", [{"verbs": ["get", "list"], "resources": ["pods"]}])
        crb = self._make_binding(
            "ClusterRoleBinding", "safe-binding", "safe-role", "ClusterRole",
            [{"kind": "User", "name": "reader"}],
        )
        config = ClusterConfig(cluster_name="test", rbac_resources=[role, crb])
        posture = engine.scan_cluster(config)
        assert posture.rbac_analysis.cluster_admin_bindings == []
        assert posture.rbac_analysis.escalation_paths == []

    def test_rbac_risk_score_increases_with_violations(self):
        engine = _make_engine()
        crb = self._make_binding(
            "ClusterRoleBinding", "b1", "cluster-admin", "ClusterRole",
            [{"kind": "User", "name": "user1"}],
        )
        config = ClusterConfig(cluster_name="test", rbac_resources=[crb])
        posture = engine.scan_cluster(config)
        assert posture.rbac_analysis.risk_score > 0


# ============================================================================
# Network Policy Audit
# ============================================================================

class TestNetworkPolicyAudit:
    def _make_netpol(self, name: str, namespace: str, spec: Dict) -> Dict:
        return {"metadata": {"name": name, "namespace": namespace}, "spec": spec}

    def test_no_network_policies_fails(self):
        engine = _make_engine()
        pod = _make_pod(namespace="production")
        config = ClusterConfig(cluster_name="test", resources=[pod], network_policies=[])
        posture = engine.scan_cluster(config)
        assert posture.network_policy_audit.has_default_deny is False
        assert "production" in posture.network_policy_audit.namespaces_without_policy

    def test_default_deny_detected(self):
        engine = _make_engine()
        np = self._make_netpol("default-deny", "default", {
            "podSelector": {},
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [],
            "egress": [],
        })
        config = ClusterConfig(cluster_name="test", network_policies=[np])
        posture = engine.scan_cluster(config)
        assert posture.network_policy_audit.has_default_deny is True

    def test_coverage_percent_calculated(self):
        engine = _make_engine()
        pod = _make_pod(namespace="ns1")
        np = self._make_netpol("allow-ns1", "ns1", {
            "podSelector": {},
            "policyTypes": ["Ingress"],
            "ingress": [{"from": [{"namespaceSelector": {"matchLabels": {"ns": "trusted"}}}]}],
        })
        config = ClusterConfig(cluster_name="test", resources=[pod], network_policies=[np])
        posture = engine.scan_cluster(config)
        assert posture.network_policy_audit.coverage_percent == 100.0

    def test_pods_without_policy_listed(self):
        engine = _make_engine()
        pod = _make_pod(namespace="isolated")
        config = ClusterConfig(cluster_name="test", resources=[pod], network_policies=[])
        posture = engine.scan_cluster(config)
        pods_ns = [p["namespace"] for p in posture.network_policy_audit.pods_without_policy]
        assert "isolated" in pods_ns

    def test_overly_permissive_ingress_detected(self):
        engine = _make_engine()
        np = self._make_netpol("allow-all-in", "default", {
            "podSelector": {"matchLabels": {"app": "api"}},
            "policyTypes": ["Ingress"],
            "ingress": [{"from": []}],
        })
        config = ClusterConfig(cluster_name="test", network_policies=[np])
        posture = engine.scan_cluster(config)
        assert len(posture.network_policy_audit.overly_permissive_ingress) >= 1


# ============================================================================
# Image Security
# ============================================================================

class TestImageSecurity:
    def test_latest_tag_detected(self):
        engine = _make_engine()
        pod = _make_pod(image="nginx:latest")
        config = _minimal_config([pod])
        posture = engine.scan_cluster(config)
        assert "nginx:latest" in posture.image_security_report.images_with_latest_tag

    def test_no_tag_treated_as_latest(self):
        engine = _make_engine()
        pod = _make_pod(image="nginx")
        config = _minimal_config([pod])
        posture = engine.scan_cluster(config)
        assert "nginx" in posture.image_security_report.images_with_latest_tag

    def test_trusted_registry_passes(self):
        engine = _make_engine()
        pod = _make_pod(image="gcr.io/my-project/app:1.2.3")
        config = _minimal_config([pod])
        posture = engine.scan_cluster(config)
        assert "gcr.io/my-project/app:1.2.3" not in posture.image_security_report.untrusted_registry_images

    def test_untrusted_registry_detected(self):
        engine = _make_engine()
        pod = _make_pod(image="badregistry.example.com/app:1.0")
        config = _minimal_config([pod])
        posture = engine.scan_cluster(config)
        assert "badregistry.example.com/app:1.0" in posture.image_security_report.untrusted_registry_images

    def test_docker_library_image_trusted(self):
        engine = K8sSecurityEngine(trusted_registries=["docker.io/library"])
        pod = _make_pod(image="nginx:1.25")
        config = _minimal_config([pod])
        posture = engine.scan_cluster(config)
        assert "nginx:1.25" not in posture.image_security_report.untrusted_registry_images

    def test_non_always_pull_policy_flagged(self):
        engine = _make_engine()
        pod = _make_pod(image="gcr.io/app:1.0", pull_policy="IfNotPresent")
        config = _minimal_config([pod])
        posture = engine.scan_cluster(config)
        pull_images = [p["image"] for p in posture.image_security_report.missing_pull_policy]
        assert "gcr.io/app:1.0" in pull_images

    def test_total_images_counted(self):
        engine = _make_engine()
        pod1 = _make_pod(name="p1", image="gcr.io/a:1.0")
        pod2 = _make_pod(name="p2", image="gcr.io/b:2.0")
        config = _minimal_config([pod1, pod2])
        posture = engine.scan_cluster(config)
        assert posture.image_security_report.total_images == 2

    def test_duplicate_images_not_double_counted(self):
        engine = _make_engine()
        pod1 = _make_pod(name="p1", image="gcr.io/app:1.0")
        pod2 = _make_pod(name="p2", image="gcr.io/app:1.0")
        config = _minimal_config([pod1, pod2])
        posture = engine.scan_cluster(config)
        assert posture.image_security_report.total_images == 1


# ============================================================================
# Secrets Management
# ============================================================================

class TestSecretsManagement:
    def test_secret_env_var_detected(self):
        engine = _make_engine()
        pod = K8sResource(
            kind="Pod",
            name="secret-pod",
            namespace="default",
            labels={"pod-security.kubernetes.io/enforce": "restricted"},
            spec={
                "securityContext": {"runAsNonRoot": True},
                "containers": [{
                    "name": "app",
                    "image": "gcr.io/app:1.0",
                    "env": [
                        {"name": "DB_PASSWORD", "valueFrom": {"secretKeyRef": {"name": "db-secret", "key": "password"}}}
                    ],
                    "securityContext": {
                        "readOnlyRootFilesystem": True,
                        "allowPrivilegeEscalation": False,
                        "capabilities": {"drop": ["ALL"]},
                    },
                    "resources": {"limits": {"cpu": "100m", "memory": "128Mi"}},
                }],
            },
        )
        config = _minimal_config([pod])
        posture = engine.scan_cluster(config)
        assert len(posture.secrets_audit.secrets_as_env_vars) == 1

    def test_sensitive_configmap_key_detected(self):
        engine = _make_engine()
        cm = K8sResource(
            kind="ConfigMap",
            name="app-config",
            namespace="default",
            spec={"data": {"api_key": "supersecret123", "port": "8080"}},
        )
        config = _minimal_config([cm])
        posture = engine.scan_cluster(config)
        assert len(posture.secrets_audit.secrets_in_configmaps) >= 1

    def test_non_sensitive_configmap_ignored(self):
        engine = _make_engine()
        cm = K8sResource(
            kind="ConfigMap",
            name="app-config",
            namespace="default",
            spec={"data": {"log_level": "info", "port": "8080"}},
        )
        config = _minimal_config([cm])
        posture = engine.scan_cluster(config)
        assert len(posture.secrets_audit.secrets_in_configmaps) == 0

    def test_etcd_encryption_config_detected(self):
        engine = _make_engine()
        enc = K8sResource(kind="EncryptionConfiguration", name="encryption-config")
        config = _minimal_config([enc])
        posture = engine.scan_cluster(config)
        assert posture.secrets_audit.etcd_encryption_enabled is True

    def test_etcd_encryption_missing_flagged(self):
        engine = _make_engine()
        config = _minimal_config([])
        posture = engine.scan_cluster(config)
        assert posture.secrets_audit.etcd_encryption_enabled is False
        ids = [f.check_id for f in posture.findings]
        assert "K8S-SEC-003" in ids

    def test_external_secrets_operator_detected(self):
        engine = _make_engine()
        r = K8sResource(
            kind="Pod",
            name="eso-pod",
            namespace="default",
            annotations={"external-secrets.io/backend": "vault"},
            spec={"containers": []},
        )
        config = _minimal_config([r])
        posture = engine.scan_cluster(config)
        assert posture.secrets_audit.external_secrets_operator_present is True

    def test_secret_count_tracked(self):
        engine = _make_engine()
        s1 = K8sResource(kind="Secret", name="s1", namespace="default")
        s2 = K8sResource(kind="Secret", name="s2", namespace="default")
        config = _minimal_config([s1, s2])
        posture = engine.scan_cluster(config)
        assert posture.secrets_audit.total_secrets == 2


# ============================================================================
# Admission Control
# ============================================================================

class TestAdmissionControl:
    def test_privileged_pod_denied(self):
        engine = _make_engine()
        pod = _make_pod(privileged=True)
        result = engine.evaluate_admission(pod)
        assert result.allowed is False
        assert any("privileged" in v.lower() for v in result.violations)

    def test_compliant_pod_admitted(self):
        engine = _make_engine()
        pod = _make_pod(
            cpu_limit="500m",
            mem_limit="256Mi",
            image="gcr.io/app:1.0",
        )
        result = engine.evaluate_admission(pod)
        assert result.allowed is True
        assert result.violations == []

    def test_no_resource_limits_denied(self):
        engine = _make_engine()
        pod = _make_pod(cpu_limit="", mem_limit="")
        result = engine.evaluate_admission(pod)
        assert result.allowed is False
        assert any("limit" in v.lower() for v in result.violations)

    def test_untrusted_image_denied(self):
        engine = _make_engine()
        pod = _make_pod(image="evil.registry.io/malware:latest", cpu_limit="100m", mem_limit="128Mi")
        result = engine.evaluate_admission(pod)
        assert result.allowed is False
        assert any("untrusted" in v.lower() for v in result.violations)

    def test_missing_labels_warns(self):
        engine = _make_engine()
        pod = _make_pod(labels={})  # no app/team labels
        result = engine.evaluate_admission(pod)
        assert any("label" in w.lower() for w in result.warnings)

    def test_add_custom_admission_rule(self):
        engine = _make_engine()
        rule = AdmissionRule(
            name="deny-test",
            description="Deny any resource named 'forbidden'",
            action="deny",
            conditions={},
        )
        engine.add_admission_rule(rule)
        rules = engine.get_admission_rules()
        assert any(r.name == "deny-test" for r in rules)

    def test_disabled_rule_skipped(self):
        engine = _make_engine()
        for rule in engine._admission_rules:
            rule.enabled = False
        pod = _make_pod(privileged=True, cpu_limit="", mem_limit="")
        result = engine.evaluate_admission(pod)
        assert result.allowed is True

    def test_admission_result_lists_applied_rules(self):
        engine = _make_engine()
        pod = _make_pod()
        result = engine.evaluate_admission(pod)
        assert len(result.applied_rules) > 0


# ============================================================================
# Cluster Scoring
# ============================================================================

class TestClusterScoring:
    def test_perfect_cluster_scores_high(self):
        engine = _make_engine()
        pod = _make_pod()
        np = {
            "metadata": {"name": "default-deny", "namespace": "default"},
            "spec": {
                "podSelector": {},
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [],
                "egress": [],
            },
        }
        config = ClusterConfig(
            cluster_name="test",
            resources=[pod],
            network_policies=[np],
        )
        posture = engine.scan_cluster(config)
        assert posture.overall_score > 0

    def test_many_violations_lowers_score(self):
        engine = _make_engine()
        pod = _make_pod(
            privileged=True,
            host_network=True,
            host_pid=True,
            read_only_rootfs=False,
            drop_all=False,
            run_as_non_root=False,
            cpu_limit="",
            mem_limit="",
        )
        config = _minimal_config([pod])
        posture_bad = engine.scan_cluster(config)
        engine2 = _make_engine()
        posture_good = engine2.scan_cluster(ClusterConfig(cluster_name="good", resources=[_make_pod()]))
        assert posture_bad.overall_score < posture_good.overall_score

    def test_grade_a_threshold(self):
        engine = _make_engine()
        assert engine._score_to_grade(95.0) == "A"
        assert engine._score_to_grade(90.0) == "A"

    def test_grade_b_threshold(self):
        engine = _make_engine()
        assert engine._score_to_grade(85.0) == "B"
        assert engine._score_to_grade(80.0) == "B"

    def test_grade_c_threshold(self):
        engine = _make_engine()
        assert engine._score_to_grade(75.0) == "C"

    def test_grade_d_threshold(self):
        engine = _make_engine()
        assert engine._score_to_grade(65.0) == "D"

    def test_grade_f_threshold(self):
        engine = _make_engine()
        assert engine._score_to_grade(50.0) == "F"
        assert engine._score_to_grade(0.0) == "F"

    def test_namespace_scores_populated(self):
        engine = _make_engine()
        pod = _make_pod(namespace="ns-a", privileged=True)
        config = _minimal_config([pod])
        posture = engine.scan_cluster(config)
        ns_names = [ns.namespace for ns in posture.namespace_scores]
        assert "ns-a" in ns_names

    def test_workload_scores_populated(self):
        engine = _make_engine()
        pod = _make_pod(name="my-pod", namespace="prod")
        config = _minimal_config([pod])
        posture = engine.scan_cluster(config)
        wl_names = [w.name for w in posture.workload_scores]
        assert "my-pod" in wl_names

    def test_posture_finding_counts_match(self):
        engine = _make_engine()
        pod = _make_pod(privileged=True, host_network=True)
        config = _minimal_config([pod])
        posture = engine.scan_cluster(config)
        total_by_sev = (
            posture.critical_findings
            + posture.high_findings
            + posture.medium_findings
            + posture.low_findings
        )
        actual = sum(
            1 for f in posture.findings
            if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
        )
        assert total_by_sev == actual

    def test_scan_duration_recorded(self):
        engine = _make_engine()
        config = _minimal_config([_make_pod()])
        posture = engine.scan_cluster(config)
        assert posture.scan_duration_ms >= 0

    def test_scanned_at_set(self):
        engine = _make_engine()
        config = _minimal_config([_make_pod()])
        posture = engine.scan_cluster(config)
        assert posture.scanned_at is not None


# ============================================================================
# Singleton and Caching
# ============================================================================

class TestSingletonAndCaching:
    def test_get_k8s_engine_returns_same_instance(self):
        e1 = get_k8s_engine()
        e2 = get_k8s_engine()
        assert e1 is e2

    def test_cached_posture_initially_none(self):
        engine = _make_engine()
        assert engine.get_cached_posture() is None

    def test_cached_posture_updated_after_scan(self):
        engine = _make_engine()
        config = _minimal_config([_make_pod()])
        posture = engine.scan_cluster(config)
        cached = engine.get_cached_posture()
        assert cached is not None
        assert cached.cluster_name == posture.cluster_name

    def test_posture_cluster_name_set(self):
        engine = _make_engine()
        config = ClusterConfig(cluster_name="my-cluster")
        posture = engine.scan_cluster(config)
        assert posture.cluster_name == "my-cluster"


# ============================================================================
# Edge Cases
# ============================================================================

class TestEdgeCases:
    def test_empty_cluster_scan(self):
        engine = _make_engine()
        config = _minimal_config([])
        posture = engine.scan_cluster(config)
        assert posture is not None
        assert posture.overall_score >= 0

    def test_multiple_pods_aggregated(self):
        engine = _make_engine()
        pods = [_make_pod(name=f"pod-{i}", namespace=f"ns-{i}") for i in range(5)]
        config = _minimal_config(pods)
        posture = engine.scan_cluster(config)
        assert posture.total_checks > 0

    def test_cronjob_pod_spec_extracted(self):
        engine = _make_engine()
        cj = K8sResource(
            kind="CronJob",
            name="my-job",
            namespace="default",
            labels={"pod-security.kubernetes.io/enforce": "restricted"},
            spec={
                "jobTemplate": {
                    "spec": {
                        "template": {
                            "spec": {
                                "hostPID": True,
                                "containers": [
                                    {
                                        "name": "worker",
                                        "image": "gcr.io/app:1.0",
                                        "securityContext": {"privileged": False},
                                        "resources": {"limits": {"cpu": "100m", "memory": "128Mi"}},
                                    }
                                ],
                            }
                        }
                    }
                }
            },
        )
        config = _minimal_config([cj])
        posture = engine.scan_cluster(config)
        ids = [f.check_id for f in posture.findings]
        assert "K8S-PS-003" in ids

    def test_init_containers_checked(self):
        engine = _make_engine()
        pod = K8sResource(
            kind="Pod",
            name="init-pod",
            namespace="default",
            labels={"pod-security.kubernetes.io/enforce": "restricted"},
            spec={
                "securityContext": {"runAsNonRoot": True},
                "containers": [
                    {
                        "name": "main",
                        "image": "gcr.io/app:1.0",
                        "securityContext": {
                            "readOnlyRootFilesystem": True,
                            "allowPrivilegeEscalation": False,
                            "capabilities": {"drop": ["ALL"]},
                        },
                        "resources": {"limits": {"cpu": "100m", "memory": "128Mi"}},
                    }
                ],
                "initContainers": [
                    {
                        "name": "init",
                        "image": "gcr.io/init:1.0",
                        "securityContext": {
                            "privileged": True,
                        },
                        "resources": {"limits": {"cpu": "50m", "memory": "64Mi"}},
                    }
                ],
            },
        )
        config = _minimal_config([pod])
        posture = engine.scan_cluster(config)
        ids = [f.check_id for f in posture.findings]
        assert "K8S-PS-001" in ids

    def test_check_results_include_all_categories(self):
        engine = _make_engine()
        config = _minimal_config([_make_pod()])
        posture = engine.scan_cluster(config)
        categories = {cr.category for cr in posture.check_results}
        assert CheckCategory.POD_SECURITY in categories
        assert CheckCategory.RBAC in categories

    def test_findings_have_remediation(self):
        engine = _make_engine()
        pod = _make_pod(privileged=True)
        config = _minimal_config([pod])
        posture = engine.scan_cluster(config)
        for f in posture.findings:
            assert f.remediation, f"Finding {f.check_id} missing remediation"

    def test_findings_have_references(self):
        engine = _make_engine()
        pod = _make_pod(privileged=True)
        config = _minimal_config([pod])
        posture = engine.scan_cluster(config)
        for f in posture.findings:
            assert len(f.references) > 0, f"Finding {f.check_id} missing references"
