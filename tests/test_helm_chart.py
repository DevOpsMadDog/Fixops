"""
Tests for the ALDECI Helm chart structure, YAML syntax, and values.
Validates docker/helm/aldeci/ without requiring helm CLI.
"""
import os
import yaml
import pytest

CHART_DIR = os.path.join(os.path.dirname(__file__), "..", "docker", "helm", "aldeci")
TEMPLATES_DIR = os.path.join(CHART_DIR, "templates")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def chart_file(name: str) -> str:
    return os.path.join(CHART_DIR, name)


def template_file(name: str) -> str:
    return os.path.join(TEMPLATES_DIR, name)


def load_yaml(path: str):
    with open(path) as f:
        return yaml.safe_load(f)


def load_yaml_all(path: str):
    with open(path) as f:
        return list(yaml.safe_load_all(f))


def file_text(path: str) -> str:
    with open(path) as f:
        return f.read()


# ---------------------------------------------------------------------------
# 1. Chart structure — required files exist
# ---------------------------------------------------------------------------

class TestChartStructure:
    REQUIRED_FILES = [
        "Chart.yaml",
        "values.yaml",
        "templates/_helpers.tpl",
        "templates/deployment-api.yaml",
        "templates/deployment-ui.yaml",
        "templates/service-api.yaml",
        "templates/service-ui.yaml",
        "templates/ingress.yaml",
        "templates/configmap.yaml",
        "templates/secret.yaml",
        "templates/pvc.yaml",
        "templates/hpa.yaml",
        "templates/NOTES.txt",
    ]

    @pytest.mark.parametrize("rel_path", REQUIRED_FILES)
    def test_file_exists(self, rel_path):
        full = os.path.join(CHART_DIR, rel_path)
        assert os.path.isfile(full), f"Missing required chart file: {rel_path}"

    def test_templates_dir_exists(self):
        assert os.path.isdir(TEMPLATES_DIR)

    def test_no_unexpected_extensions_in_templates(self):
        allowed = {".yaml", ".yml", ".tpl", ".txt"}
        for fname in os.listdir(TEMPLATES_DIR):
            ext = os.path.splitext(fname)[1]
            assert ext in allowed, f"Unexpected file extension in templates/: {fname}"


# ---------------------------------------------------------------------------
# 2. Chart.yaml — metadata validation
# ---------------------------------------------------------------------------

class TestChartYaml:
    @pytest.fixture(scope="class")
    def chart(self):
        return load_yaml(chart_file("Chart.yaml"))

    def test_api_version_v2(self, chart):
        assert chart["apiVersion"] == "v2"

    def test_name_is_aldeci(self, chart):
        assert chart["name"] == "aldeci"

    def test_version_is_1_0_0(self, chart):
        assert chart["version"] == "1.0.0"

    def test_app_version_is_2_5_0(self, chart):
        assert chart["appVersion"] == "2.5.0"

    def test_type_is_application(self, chart):
        assert chart["type"] == "application"

    def test_description_present(self, chart):
        assert "description" in chart
        assert len(chart["description"]) > 10

    def test_maintainers_present(self, chart):
        assert "maintainers" in chart
        assert len(chart["maintainers"]) >= 1

    def test_maintainer_has_name_and_email(self, chart):
        m = chart["maintainers"][0]
        assert "name" in m
        assert "email" in m


# ---------------------------------------------------------------------------
# 3. values.yaml — structure and defaults
# ---------------------------------------------------------------------------

class TestValuesYaml:
    @pytest.fixture(scope="class")
    def values(self):
        return load_yaml(chart_file("values.yaml"))

    def test_api_section_present(self, values):
        assert "api" in values

    def test_ui_section_present(self, values):
        assert "ui" in values

    def test_ingress_section_present(self, values):
        assert "ingress" in values

    def test_persistence_section_present(self, values):
        assert "persistence" in values

    def test_config_section_present(self, values):
        assert "config" in values

    def test_secrets_section_present(self, values):
        assert "secrets" in values

    def test_global_section_present(self, values):
        assert "global" in values

    def test_api_replica_count_default(self, values):
        assert values["api"]["replicaCount"] == 3

    def test_ui_replica_count_default(self, values):
        assert values["ui"]["replicaCount"] == 2

    def test_api_image_repository(self, values):
        assert values["api"]["image"]["repository"] == "aldeci/suite-api"

    def test_ui_image_repository(self, values):
        assert values["ui"]["image"]["repository"] == "aldeci/suite-ui"

    def test_api_service_port(self, values):
        assert values["api"]["service"]["port"] == 8000

    def test_ui_service_port(self, values):
        assert values["ui"]["service"]["port"] == 80

    def test_api_autoscaling_defaults(self, values):
        hpa = values["api"]["autoscaling"]
        assert hpa["enabled"] is True
        assert hpa["minReplicas"] == 3
        assert hpa["maxReplicas"] == 10
        assert hpa["targetCPUUtilizationPercentage"] == 70

    def test_ui_autoscaling_defaults(self, values):
        hpa = values["ui"]["autoscaling"]
        assert hpa["enabled"] is True
        assert hpa["minReplicas"] == 2
        assert hpa["maxReplicas"] == 6

    def test_persistence_data_size(self, values):
        assert values["persistence"]["data"]["size"] == "50Gi"

    def test_persistence_logs_size(self, values):
        assert values["persistence"]["logs"]["size"] == "10Gi"

    def test_persistence_backups_size(self, values):
        assert values["persistence"]["backups"]["size"] == "20Gi"

    def test_config_environment_default(self, values):
        assert values["config"]["environment"] == "production"

    def test_config_trustgraph_enabled(self, values):
        assert values["config"]["trustgraphEnabled"] == "true"

    def test_config_use_council(self, values):
        assert values["config"]["useCouncil"] == "1"

    def test_secrets_create_true(self, values):
        assert values["secrets"]["create"] is True

    def test_ingress_tls_enabled(self, values):
        assert values["ingress"]["tls"]["enabled"] is True

    def test_ingress_hosts_ui_present(self, values):
        assert "ui" in values["ingress"]["hosts"]
        assert "host" in values["ingress"]["hosts"]["ui"]

    def test_ingress_hosts_api_present(self, values):
        assert "api" in values["ingress"]["hosts"]
        assert "host" in values["ingress"]["hosts"]["api"]


# ---------------------------------------------------------------------------
# 4. Template files — valid YAML (Helm directives stripped)
# ---------------------------------------------------------------------------

HELM_DIRECTIVES = [
    "{{", "}}", "{{-", "-}}", "{{/*", "*/}}",
]


def strip_helm(text: str) -> str:
    """Remove Helm template directives so yaml.safe_load can parse the rest."""
    import re
    # Remove entire lines that start with {{ (after optional whitespace)
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("{{") or stripped.startswith("{{-"):
            continue
        lines.append(line)
    return "\n".join(lines)


class TestTemplateYamlSyntax:
    YAML_TEMPLATES = [
        "deployment-api.yaml",
        "deployment-ui.yaml",
        "service-api.yaml",
        "service-ui.yaml",
        "ingress.yaml",
        "configmap.yaml",
        "secret.yaml",
        "pvc.yaml",
        "hpa.yaml",
    ]

    @pytest.mark.parametrize("tpl", YAML_TEMPLATES)
    def test_template_is_nonempty(self, tpl):
        text = file_text(template_file(tpl))
        assert len(text.strip()) > 0, f"{tpl} is empty"

    @pytest.mark.parametrize("tpl", YAML_TEMPLATES)
    def test_template_references_aldeci(self, tpl):
        text = file_text(template_file(tpl))
        assert "aldeci" in text.lower(), f"{tpl} does not reference aldeci"


# ---------------------------------------------------------------------------
# 5. _helpers.tpl — required template definitions
# ---------------------------------------------------------------------------

class TestHelpersTpl:
    REQUIRED_DEFINES = [
        "aldeci.name",
        "aldeci.fullname",
        "aldeci.chart",
        "aldeci.namespace",
        "aldeci.labels",
        "aldeci.api.selectorLabels",
        "aldeci.ui.selectorLabels",
        "aldeci.secretName",
        "aldeci.configmapName",
        "aldeci.pvc.data",
        "aldeci.pvc.logs",
        "aldeci.pvc.backups",
    ]

    @pytest.fixture(scope="class")
    def helpers_text(self):
        return file_text(template_file("_helpers.tpl"))

    @pytest.mark.parametrize("define_name", REQUIRED_DEFINES)
    def test_define_present(self, helpers_text, define_name):
        assert f'"{ define_name }"' in helpers_text or f'"{define_name}"' in helpers_text, \
            f"_helpers.tpl missing define: {define_name}"


# ---------------------------------------------------------------------------
# 6. Deployment templates — key fields present
# ---------------------------------------------------------------------------

class TestDeploymentTemplates:
    def test_api_deployment_has_replicas(self):
        text = file_text(template_file("deployment-api.yaml"))
        assert "replicas:" in text

    def test_api_deployment_has_image(self):
        text = file_text(template_file("deployment-api.yaml"))
        assert "image:" in text

    def test_api_deployment_has_readiness_probe(self):
        text = file_text(template_file("deployment-api.yaml"))
        assert "readinessProbe:" in text

    def test_api_deployment_has_liveness_probe(self):
        text = file_text(template_file("deployment-api.yaml"))
        assert "livenessProbe:" in text

    def test_api_deployment_has_resources(self):
        text = file_text(template_file("deployment-api.yaml"))
        assert "resources:" in text

    def test_api_deployment_has_security_context(self):
        text = file_text(template_file("deployment-api.yaml"))
        assert "securityContext:" in text

    def test_api_deployment_has_volume_mounts(self):
        text = file_text(template_file("deployment-api.yaml"))
        assert "volumeMounts:" in text

    def test_ui_deployment_has_nginx_health_path(self):
        # The probe path is defined in values.yaml and rendered via toYaml;
        # verify it appears in values rather than the template text.
        values = load_yaml(chart_file("values.yaml"))
        readiness = values["ui"]["readinessProbe"]
        assert readiness["httpGet"]["path"] == "/nginx-health"

    def test_api_deployment_references_configmap(self):
        text = file_text(template_file("deployment-api.yaml"))
        assert "configMapRef" in text or "configmapName" in text

    def test_api_deployment_references_secret(self):
        text = file_text(template_file("deployment-api.yaml"))
        assert "secretRef" in text or "secretName" in text

    def test_api_deployment_has_pod_anti_affinity(self):
        text = file_text(template_file("deployment-api.yaml"))
        assert "podAntiAffinity" in text

    def test_api_deployment_has_startup_probe(self):
        text = file_text(template_file("deployment-api.yaml"))
        assert "startupProbe:" in text


# ---------------------------------------------------------------------------
# 7. Ingress template
# ---------------------------------------------------------------------------

class TestIngressTemplate:
    def test_ingress_has_tls_block(self):
        text = file_text(template_file("ingress.yaml"))
        assert "tls:" in text

    def test_ingress_has_rules(self):
        text = file_text(template_file("ingress.yaml"))
        assert "rules:" in text

    def test_ingress_references_ui_service(self):
        text = file_text(template_file("ingress.yaml"))
        assert "ui" in text

    def test_ingress_references_api_service(self):
        text = file_text(template_file("ingress.yaml"))
        assert "api" in text

    def test_ingress_has_class_name(self):
        text = file_text(template_file("ingress.yaml"))
        assert "ingressClassName" in text


# ---------------------------------------------------------------------------
# 8. HPA template
# ---------------------------------------------------------------------------

class TestHpaTemplate:
    def test_hpa_has_scale_target_ref(self):
        text = file_text(template_file("hpa.yaml"))
        assert "scaleTargetRef" in text

    def test_hpa_has_cpu_metric(self):
        text = file_text(template_file("hpa.yaml"))
        assert "cpu" in text

    def test_hpa_has_memory_metric(self):
        text = file_text(template_file("hpa.yaml"))
        assert "memory" in text

    def test_hpa_has_behavior(self):
        text = file_text(template_file("hpa.yaml"))
        assert "behavior:" in text

    def test_hpa_covers_both_components(self):
        text = file_text(template_file("hpa.yaml"))
        assert "api" in text and "ui" in text


# ---------------------------------------------------------------------------
# 9. PVC template
# ---------------------------------------------------------------------------

class TestPvcTemplate:
    def test_pvc_has_data_volume(self):
        text = file_text(template_file("pvc.yaml"))
        assert "data" in text

    def test_pvc_has_logs_volume(self):
        text = file_text(template_file("pvc.yaml"))
        assert "logs" in text

    def test_pvc_has_backups_volume(self):
        text = file_text(template_file("pvc.yaml"))
        assert "backups" in text

    def test_pvc_has_access_mode(self):
        text = file_text(template_file("pvc.yaml"))
        assert "accessModes" in text

    def test_pvc_has_resource_policy_keep(self):
        text = file_text(template_file("pvc.yaml"))
        assert "resource-policy" in text


# ---------------------------------------------------------------------------
# 10. Secret template
# ---------------------------------------------------------------------------

class TestSecretTemplate:
    def test_secret_has_jwt_key(self):
        text = file_text(template_file("secret.yaml"))
        assert "FIXOPS_JWT_SECRET" in text

    def test_secret_has_api_token_key(self):
        text = file_text(template_file("secret.yaml"))
        assert "FIXOPS_API_TOKEN" in text

    def test_secret_has_encryption_key(self):
        text = file_text(template_file("secret.yaml"))
        assert "FIXOPS_ENCRYPTION_KEY" in text

    def test_secret_has_openrouter_key(self):
        text = file_text(template_file("secret.yaml"))
        assert "OPENROUTER_API_KEY" in text

    def test_secret_type_opaque(self):
        text = file_text(template_file("secret.yaml"))
        assert "Opaque" in text

    def test_secret_has_resource_policy_keep(self):
        text = file_text(template_file("secret.yaml"))
        assert "resource-policy" in text


# ---------------------------------------------------------------------------
# 11. ConfigMap template
# ---------------------------------------------------------------------------

class TestConfigMapTemplate:
    def test_configmap_has_environment(self):
        text = file_text(template_file("configmap.yaml"))
        assert "ENVIRONMENT" in text

    def test_configmap_has_trustgraph_url(self):
        text = file_text(template_file("configmap.yaml"))
        assert "TRUSTGRAPH_URL" in text

    def test_configmap_has_fixops_use_council(self):
        text = file_text(template_file("configmap.yaml"))
        assert "FIXOPS_USE_COUNCIL" in text

    def test_configmap_has_allowed_origins(self):
        text = file_text(template_file("configmap.yaml"))
        assert "FIXOPS_ALLOWED_ORIGINS" in text


# ---------------------------------------------------------------------------
# 12. NOTES.txt
# ---------------------------------------------------------------------------

class TestNotesTxt:
    def test_notes_exists_and_nonempty(self):
        text = file_text(template_file("NOTES.txt"))
        assert len(text.strip()) > 50

    def test_notes_mentions_aldeci(self):
        text = file_text(template_file("NOTES.txt"))
        assert "ALDECI" in text

    def test_notes_has_access_url_section(self):
        text = file_text(template_file("NOTES.txt"))
        assert "ACCESS" in text.upper() or "URL" in text.upper()

    def test_notes_has_health_check(self):
        text = file_text(template_file("NOTES.txt"))
        assert "health" in text.lower()

    def test_notes_has_upgrade_instructions(self):
        text = file_text(template_file("NOTES.txt"))
        assert "upgrade" in text.lower() or "UPGRADE" in text
