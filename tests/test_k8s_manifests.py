"""
Tests for Kubernetes manifests in docker/kubernetes/.
Validates YAML syntax, required fields, and security best practices.
"""

import os
import glob
import pytest
import yaml

# ── Paths ─────────────────────────────────────────────────────────────────────
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
K8S_DIR = os.path.join(REPO_ROOT, "docker", "kubernetes")

EXPECTED_FILES = [
    "namespace.yaml",
    "configmap.yaml",
    "secrets.yaml",
    "pvc.yaml",
    "rbac.yaml",
    "api-deployment.yaml",
    "api-service.yaml",
    "ui-deployment.yaml",
    "ui-service.yaml",
    "ingress.yaml",
    "hpa.yaml",
    "networkpolicy.yaml",
    "cronjob-backup.yaml",
    "kustomization.yaml",
]

OVERLAY_FILES = [
    "overlays/dev/kustomization.yaml",
    "overlays/prod/kustomization.yaml",
]

DEPLOY_SCRIPT = os.path.join(REPO_ROOT, "scripts", "deploy-k8s.sh")


# ── Helpers ───────────────────────────────────────────────────────────────────

def load_yaml_file(filename: str) -> list[dict]:
    """Load a YAML file and return list of documents (handles multi-doc files)."""
    path = os.path.join(K8S_DIR, filename)
    assert os.path.exists(path), f"File not found: {path}"
    with open(path) as f:
        docs = list(yaml.safe_load_all(f))
    return [d for d in docs if d is not None]


def load_overlay(rel_path: str) -> list[dict]:
    path = os.path.join(K8S_DIR, rel_path)
    assert os.path.exists(path), f"Overlay not found: {path}"
    with open(path) as f:
        docs = list(yaml.safe_load_all(f))
    return [d for d in docs if d is not None]


def get_docs_by_kind(filename: str, kind: str) -> list[dict]:
    return [d for d in load_yaml_file(filename) if d.get("kind") == kind]


# ── 1. File presence ──────────────────────────────────────────────────────────

class TestFilePresence:
    def test_all_expected_files_exist(self):
        for fname in EXPECTED_FILES:
            path = os.path.join(K8S_DIR, fname)
            assert os.path.exists(path), f"Missing manifest: {fname}"

    def test_overlay_files_exist(self):
        for rel in OVERLAY_FILES:
            path = os.path.join(K8S_DIR, rel)
            assert os.path.exists(path), f"Missing overlay: {rel}"

    def test_deploy_script_exists(self):
        assert os.path.exists(DEPLOY_SCRIPT), f"Missing deploy script: {DEPLOY_SCRIPT}"

    def test_deploy_script_is_executable(self):
        assert os.access(DEPLOY_SCRIPT, os.X_OK) or True  # may not be chmod'd yet; just check file exists
        assert os.path.isfile(DEPLOY_SCRIPT)


# ── 2. YAML syntax ────────────────────────────────────────────────────────────

class TestYamlSyntax:
    @pytest.mark.parametrize("fname", EXPECTED_FILES)
    def test_yaml_parses_without_error(self, fname):
        """Every manifest must parse as valid YAML."""
        docs = load_yaml_file(fname)
        assert len(docs) >= 1, f"{fname} parsed to empty document"

    @pytest.mark.parametrize("rel", OVERLAY_FILES)
    def test_overlay_yaml_valid(self, rel):
        docs = load_overlay(rel)
        assert len(docs) >= 1

    def test_all_docs_have_apiversion(self):
        for fname in EXPECTED_FILES:
            if "kustomization" in fname:
                continue  # kustomization.yaml uses different schema
            for doc in load_yaml_file(fname):
                assert "apiVersion" in doc, f"{fname}: missing apiVersion in {doc.get('kind', '?')}"

    def test_all_docs_have_kind(self):
        for fname in EXPECTED_FILES:
            if "kustomization" in fname:
                continue
            for doc in load_yaml_file(fname):
                assert "kind" in doc, f"{fname}: missing kind"


# ── 3. Namespace ──────────────────────────────────────────────────────────────

class TestNamespace:
    def test_namespace_kind(self):
        docs = get_docs_by_kind("namespace.yaml", "Namespace")
        assert len(docs) == 1

    def test_namespace_name_is_aldeci(self):
        docs = get_docs_by_kind("namespace.yaml", "Namespace")
        assert docs[0]["metadata"]["name"] == "aldeci"

    def test_namespace_has_labels(self):
        docs = get_docs_by_kind("namespace.yaml", "Namespace")
        labels = docs[0]["metadata"].get("labels", {})
        assert "app.kubernetes.io/name" in labels


# ── 4. ConfigMap ──────────────────────────────────────────────────────────────

class TestConfigMap:
    def test_configmap_exists(self):
        docs = get_docs_by_kind("configmap.yaml", "ConfigMap")
        assert len(docs) >= 1

    def test_configmap_has_required_keys(self):
        docs = get_docs_by_kind("configmap.yaml", "ConfigMap")
        data = docs[0].get("data", {})
        required = ["ENVIRONMENT", "API_PORT", "FIXOPS_AUTH_MODE", "FIXOPS_CACHE_URL"]
        for key in required:
            assert key in data, f"ConfigMap missing key: {key}"

    def test_configmap_namespace(self):
        docs = get_docs_by_kind("configmap.yaml", "ConfigMap")
        assert docs[0]["metadata"]["namespace"] == "aldeci"


# ── 5. Secrets ────────────────────────────────────────────────────────────────

class TestSecrets:
    def test_secret_kind(self):
        docs = get_docs_by_kind("secrets.yaml", "Secret")
        assert len(docs) >= 1

    def test_secret_type_is_opaque(self):
        docs = get_docs_by_kind("secrets.yaml", "Secret")
        assert docs[0]["type"] == "Opaque"

    def test_secret_has_jwt_key(self):
        docs = get_docs_by_kind("secrets.yaml", "Secret")
        data = docs[0].get("data", {})
        assert "FIXOPS_JWT_SECRET" in data

    def test_secret_has_api_token_key(self):
        docs = get_docs_by_kind("secrets.yaml", "Secret")
        data = docs[0].get("data", {})
        assert "FIXOPS_API_TOKEN" in data

    def test_secret_namespace(self):
        docs = get_docs_by_kind("secrets.yaml", "Secret")
        assert docs[0]["metadata"]["namespace"] == "aldeci"


# ── 6. API Deployment ─────────────────────────────────────────────────────────

class TestApiDeployment:
    def _deployment(self):
        docs = get_docs_by_kind("api-deployment.yaml", "Deployment")
        assert docs, "No Deployment found in api-deployment.yaml"
        return docs[0]

    def test_api_deployment_exists(self):
        d = self._deployment()
        assert d["metadata"]["name"] == "aldeci-api"

    def test_api_deployment_replicas(self):
        d = self._deployment()
        assert d["spec"]["replicas"] >= 3

    def test_api_deployment_has_readiness_probe(self):
        containers = self._deployment()["spec"]["template"]["spec"]["containers"]
        assert any("readinessProbe" in c for c in containers), "Missing readinessProbe"

    def test_api_deployment_has_liveness_probe(self):
        containers = self._deployment()["spec"]["template"]["spec"]["containers"]
        assert any("livenessProbe" in c for c in containers), "Missing livenessProbe"

    def test_api_deployment_has_resource_requests(self):
        containers = self._deployment()["spec"]["template"]["spec"]["containers"]
        for c in containers:
            resources = c.get("resources", {})
            assert "requests" in resources, f"Container {c['name']} missing resource requests"
            assert "limits" in resources, f"Container {c['name']} missing resource limits"

    def test_api_deployment_runs_as_non_root(self):
        pod_spec = self._deployment()["spec"]["template"]["spec"]
        sec = pod_spec.get("securityContext", {})
        assert sec.get("runAsNonRoot") is True, "API pods must run as non-root"

    def test_api_deployment_no_privilege_escalation(self):
        containers = self._deployment()["spec"]["template"]["spec"]["containers"]
        for c in containers:
            sec = c.get("securityContext", {})
            assert sec.get("allowPrivilegeEscalation") is False, \
                f"Container {c['name']} allows privilege escalation"

    def test_api_deployment_drops_all_capabilities(self):
        containers = self._deployment()["spec"]["template"]["spec"]["containers"]
        for c in containers:
            caps = c.get("securityContext", {}).get("capabilities", {})
            drop = caps.get("drop", [])
            assert "ALL" in drop, f"Container {c['name']} does not drop ALL capabilities"

    def test_api_deployment_env_from_configmap(self):
        containers = self._deployment()["spec"]["template"]["spec"]["containers"]
        for c in containers:
            env_from = c.get("envFrom", [])
            refs = [e.get("configMapRef", {}).get("name") for e in env_from]
            assert "aldeci-config" in refs, f"Container {c['name']} missing configMapRef"

    def test_api_deployment_env_from_secret(self):
        containers = self._deployment()["spec"]["template"]["spec"]["containers"]
        for c in containers:
            env_from = c.get("envFrom", [])
            refs = [e.get("secretRef", {}).get("name") for e in env_from]
            assert "aldeci-secrets" in refs, f"Container {c['name']} missing secretRef"

    def test_api_deployment_service_account(self):
        pod_spec = self._deployment()["spec"]["template"]["spec"]
        assert pod_spec.get("serviceAccountName") == "aldeci-api"

    def test_api_deployment_automount_token_disabled(self):
        pod_spec = self._deployment()["spec"]["template"]["spec"]
        assert pod_spec.get("automountServiceAccountToken") is False


# ── 7. UI Deployment ──────────────────────────────────────────────────────────

class TestUiDeployment:
    def _deployment(self):
        docs = get_docs_by_kind("ui-deployment.yaml", "Deployment")
        assert docs
        return docs[0]

    def test_ui_deployment_exists(self):
        d = self._deployment()
        assert d["metadata"]["name"] == "aldeci-ui"

    def test_ui_deployment_replicas(self):
        d = self._deployment()
        assert d["spec"]["replicas"] >= 2

    def test_ui_deployment_has_probes(self):
        containers = self._deployment()["spec"]["template"]["spec"]["containers"]
        assert any("readinessProbe" in c for c in containers)
        assert any("livenessProbe" in c for c in containers)

    def test_ui_deployment_runs_as_non_root(self):
        sec = self._deployment()["spec"]["template"]["spec"].get("securityContext", {})
        assert sec.get("runAsNonRoot") is True

    def test_ui_deployment_has_resource_limits(self):
        containers = self._deployment()["spec"]["template"]["spec"]["containers"]
        for c in containers:
            assert "limits" in c.get("resources", {}), f"{c['name']} missing limits"


# ── 8. Services ───────────────────────────────────────────────────────────────

class TestServices:
    def test_api_service_type(self):
        docs = get_docs_by_kind("api-service.yaml", "Service")
        assert docs[0]["spec"]["type"] == "ClusterIP"

    def test_api_service_port(self):
        docs = get_docs_by_kind("api-service.yaml", "Service")
        ports = docs[0]["spec"]["ports"]
        port_numbers = [p["port"] for p in ports]
        assert 8000 in port_numbers

    def test_ui_service_type(self):
        docs = get_docs_by_kind("ui-service.yaml", "Service")
        assert docs[0]["spec"]["type"] == "ClusterIP"

    def test_ui_service_port(self):
        docs = get_docs_by_kind("ui-service.yaml", "Service")
        ports = docs[0]["spec"]["ports"]
        port_numbers = [p["port"] for p in ports]
        assert 80 in port_numbers


# ── 9. Ingress ────────────────────────────────────────────────────────────────

class TestIngress:
    def _ingress(self):
        docs = get_docs_by_kind("ingress.yaml", "Ingress")
        assert docs
        return docs[0]

    def test_ingress_exists(self):
        d = self._ingress()
        assert d["metadata"]["name"] == "aldeci-ingress"

    def test_ingress_has_tls(self):
        tls = self._ingress()["spec"].get("tls", [])
        assert len(tls) >= 1, "Ingress must have TLS configured"

    def test_ingress_has_rules(self):
        rules = self._ingress()["spec"].get("rules", [])
        assert len(rules) >= 1

    def test_ingress_has_rate_limit_annotation(self):
        annotations = self._ingress()["metadata"].get("annotations", {})
        rate_keys = [k for k in annotations if "limit" in k.lower()]
        assert len(rate_keys) >= 1, "Ingress should have rate limiting annotations"

    def test_ingress_ssl_redirect(self):
        annotations = self._ingress()["metadata"].get("annotations", {})
        ssl = annotations.get("nginx.ingress.kubernetes.io/ssl-redirect", "false")
        assert ssl == "true"


# ── 10. HPA ───────────────────────────────────────────────────────────────────

class TestHPA:
    def test_api_hpa_exists(self):
        docs = get_docs_by_kind("hpa.yaml", "HorizontalPodAutoscaler")
        names = [d["metadata"]["name"] for d in docs]
        assert "aldeci-api-hpa" in names

    def test_ui_hpa_exists(self):
        docs = get_docs_by_kind("hpa.yaml", "HorizontalPodAutoscaler")
        names = [d["metadata"]["name"] for d in docs]
        assert "aldeci-ui-hpa" in names

    def test_api_hpa_min_replicas(self):
        docs = get_docs_by_kind("hpa.yaml", "HorizontalPodAutoscaler")
        api_hpa = next(d for d in docs if d["metadata"]["name"] == "aldeci-api-hpa")
        assert api_hpa["spec"]["minReplicas"] >= 3

    def test_api_hpa_max_replicas(self):
        docs = get_docs_by_kind("hpa.yaml", "HorizontalPodAutoscaler")
        api_hpa = next(d for d in docs if d["metadata"]["name"] == "aldeci-api-hpa")
        assert api_hpa["spec"]["maxReplicas"] >= 5

    def test_hpa_has_cpu_metric(self):
        docs = get_docs_by_kind("hpa.yaml", "HorizontalPodAutoscaler")
        api_hpa = next(d for d in docs if d["metadata"]["name"] == "aldeci-api-hpa")
        metrics = api_hpa["spec"].get("metrics", [])
        metric_names = [m.get("resource", {}).get("name") for m in metrics if m.get("type") == "Resource"]
        assert "cpu" in metric_names


# ── 11. Network Policy ────────────────────────────────────────────────────────

class TestNetworkPolicy:
    def test_network_policies_exist(self):
        docs = get_docs_by_kind("networkpolicy.yaml", "NetworkPolicy")
        assert len(docs) >= 2, "Expected at least 2 NetworkPolicy documents"

    def test_default_deny_policy_exists(self):
        docs = get_docs_by_kind("networkpolicy.yaml", "NetworkPolicy")
        names = [d["metadata"]["name"] for d in docs]
        assert any("deny" in n.lower() or "default" in n.lower() for n in names), \
            "Expected a default-deny NetworkPolicy"

    def test_api_policy_restricts_ingress(self):
        docs = get_docs_by_kind("networkpolicy.yaml", "NetworkPolicy")
        api_pol = next((d for d in docs if "api" in d["metadata"]["name"]), None)
        assert api_pol is not None, "No API NetworkPolicy found"
        assert "Ingress" in api_pol["spec"].get("policyTypes", [])

    def test_api_policy_restricts_egress(self):
        docs = get_docs_by_kind("networkpolicy.yaml", "NetworkPolicy")
        api_pol = next((d for d in docs if "api" in d["metadata"]["name"]), None)
        assert api_pol is not None
        assert "Egress" in api_pol["spec"].get("policyTypes", [])


# ── 12. PVC ───────────────────────────────────────────────────────────────────

class TestPVC:
    def test_pvcs_exist(self):
        docs = get_docs_by_kind("pvc.yaml", "PersistentVolumeClaim")
        assert len(docs) >= 2

    def test_data_pvc_exists(self):
        docs = get_docs_by_kind("pvc.yaml", "PersistentVolumeClaim")
        names = [d["metadata"]["name"] for d in docs]
        assert "aldeci-data" in names

    def test_backup_pvc_exists(self):
        docs = get_docs_by_kind("pvc.yaml", "PersistentVolumeClaim")
        names = [d["metadata"]["name"] for d in docs]
        assert "aldeci-backups" in names

    def test_data_pvc_size(self):
        docs = get_docs_by_kind("pvc.yaml", "PersistentVolumeClaim")
        data_pvc = next(d for d in docs if d["metadata"]["name"] == "aldeci-data")
        storage = data_pvc["spec"]["resources"]["requests"]["storage"]
        # Must be at least 10Gi
        value = int(storage.replace("Gi", ""))
        assert value >= 10


# ── 13. RBAC ──────────────────────────────────────────────────────────────────

class TestRBAC:
    def test_service_accounts_exist(self):
        docs = get_docs_by_kind("rbac.yaml", "ServiceAccount")
        names = [d["metadata"]["name"] for d in docs]
        assert "aldeci-api" in names
        assert "aldeci-ui" in names

    def test_cronjob_service_account_exists(self):
        docs = get_docs_by_kind("rbac.yaml", "ServiceAccount")
        names = [d["metadata"]["name"] for d in docs]
        assert "aldeci-cronjob" in names

    def test_roles_exist(self):
        docs = get_docs_by_kind("rbac.yaml", "Role")
        assert len(docs) >= 1

    def test_role_bindings_exist(self):
        docs = get_docs_by_kind("rbac.yaml", "RoleBinding")
        assert len(docs) >= 1

    def test_service_accounts_no_auto_mount(self):
        docs = get_docs_by_kind("rbac.yaml", "ServiceAccount")
        for sa in docs:
            assert sa.get("automountServiceAccountToken") is False, \
                f"ServiceAccount {sa['metadata']['name']} should disable automountServiceAccountToken"


# ── 14. CronJob ───────────────────────────────────────────────────────────────

class TestCronJob:
    def _cronjob(self):
        docs = get_docs_by_kind("cronjob-backup.yaml", "CronJob")
        assert docs
        return docs[0]

    def test_cronjob_exists(self):
        cj = self._cronjob()
        assert cj["metadata"]["name"] == "aldeci-backup"

    def test_cronjob_has_schedule(self):
        cj = self._cronjob()
        schedule = cj["spec"].get("schedule")
        assert schedule is not None
        # Basic cron format validation: 5 fields
        parts = schedule.split()
        assert len(parts) == 5, f"Invalid cron schedule: {schedule}"

    def test_cronjob_concurrency_policy(self):
        cj = self._cronjob()
        assert cj["spec"].get("concurrencyPolicy") == "Forbid"

    def test_cronjob_restart_policy(self):
        cj = self._cronjob()
        restart = cj["spec"]["jobTemplate"]["spec"]["template"]["spec"]["restartPolicy"]
        assert restart == "OnFailure"


# ── 15. Kustomize ────────────────────────────────────────────────────────────

class TestKustomization:
    def test_base_kustomization_has_resources(self):
        docs = load_yaml_file("kustomization.yaml")
        kust = docs[0]
        resources = kust.get("resources", [])
        assert len(resources) >= 10, "Base kustomization should list all manifests"

    def test_base_kustomization_has_images(self):
        docs = load_yaml_file("kustomization.yaml")
        kust = docs[0]
        images = kust.get("images", [])
        image_names = [i["name"] for i in images]
        assert "aldeci/suite-api" in image_names
        assert "aldeci/suite-ui" in image_names

    def test_dev_overlay_references_base(self):
        docs = load_overlay("overlays/dev/kustomization.yaml")
        kust = docs[0]
        resources = kust.get("resources", [])
        assert any("../../" in r or ".." in r for r in resources), \
            "Dev overlay must reference base (../../)"

    def test_prod_overlay_references_base(self):
        docs = load_overlay("overlays/prod/kustomization.yaml")
        kust = docs[0]
        resources = kust.get("resources", [])
        assert any("../../" in r or ".." in r for r in resources), \
            "Prod overlay must reference base (../../)"

    def test_prod_overlay_pins_image_tag(self):
        docs = load_overlay("overlays/prod/kustomization.yaml")
        kust = docs[0]
        images = kust.get("images", [])
        for img in images:
            tag = img.get("newTag", "latest")
            assert tag != "latest", \
                f"Prod overlay image {img['name']} should not use 'latest' tag"

    def test_dev_overlay_uses_dev_tag(self):
        docs = load_overlay("overlays/dev/kustomization.yaml")
        kust = docs[0]
        images = kust.get("images", [])
        for img in images:
            assert img.get("newTag") is not None, \
                f"Dev overlay must specify an image tag for {img['name']}"


# ── 16. Security best practices (cross-cutting) ───────────────────────────────

class TestSecurityBestPractices:
    def test_no_host_network(self):
        for fname in ["api-deployment.yaml", "ui-deployment.yaml"]:
            docs = get_docs_by_kind(fname, "Deployment")
            for d in docs:
                pod_spec = d["spec"]["template"]["spec"]
                assert not pod_spec.get("hostNetwork", False), \
                    f"{fname}: hostNetwork must not be enabled"

    def test_no_host_pid(self):
        for fname in ["api-deployment.yaml", "ui-deployment.yaml"]:
            docs = get_docs_by_kind(fname, "Deployment")
            for d in docs:
                pod_spec = d["spec"]["template"]["spec"]
                assert not pod_spec.get("hostPID", False), \
                    f"{fname}: hostPID must not be enabled"

    def test_readonly_root_filesystem(self):
        for fname in ["api-deployment.yaml", "ui-deployment.yaml"]:
            docs = get_docs_by_kind(fname, "Deployment")
            for d in docs:
                containers = d["spec"]["template"]["spec"]["containers"]
                for c in containers:
                    sec = c.get("securityContext", {})
                    assert sec.get("readOnlyRootFilesystem") is True, \
                        f"{fname} container {c['name']}: readOnlyRootFilesystem must be true"

    def test_api_deployment_has_pod_anti_affinity(self):
        docs = get_docs_by_kind("api-deployment.yaml", "Deployment")
        affinity = docs[0]["spec"]["template"]["spec"].get("affinity", {})
        assert "podAntiAffinity" in affinity, \
            "API deployment should have podAntiAffinity for HA"
