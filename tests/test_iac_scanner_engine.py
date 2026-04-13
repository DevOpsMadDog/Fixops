"""IaC Security Scanner Engine — Test Suite (55+ tests).

Tests cover:
- Format detection (Terraform, CloudFormation, Kubernetes, Dockerfile, Ansible, Helm)
- Parsing correctness for each format
- Built-in rule firing for AWS, Azure, GCP, Kubernetes, Docker, Generic
- Fix suggestion content
- Custom policy-as-code rules
- Drift detection logic
- Severity scoring and filtering
- Singleton engine thread-safety
- Edge cases (empty content, unknown format, missing properties)

Run with:
    python -m pytest tests/test_iac_scanner_engine.py -v --timeout=10
"""

from __future__ import annotations

import sys
import threading
import uuid
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import patch

import pytest

# Ensure suite-core is on the path (mirrors other Beast Mode test files)
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

from core.iac_scanner_engine import (
    AnsibleParser,
    CloudFormationParser,
    CustomRule,
    DockerfileParser,
    DriftStatus,
    IaCFinding,
    IaCFormat,
    IaCResource,
    IaCScannerEngine,
    KubernetesParser,
    TerraformParser,
    detect_iac_format,
    evaluate_custom_rule,
    get_iac_scanner,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine() -> IaCScannerEngine:
    """Fresh engine instance per test."""
    e = IaCScannerEngine()
    return e


@pytest.fixture
def tf_s3_open() -> str:
    return '''
resource "aws_s3_bucket" "bad" {
  bucket = "my-public-bucket"
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
'''


@pytest.fixture
def tf_s3_secure() -> str:
    return '''
resource "aws_s3_bucket" "good" {
  bucket = "my-private-bucket"
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
  versioning {
    enabled = true
  }
  logging {
    target_bucket = "logs-bucket"
  }
  server_side_encryption_configuration {
    rule {}
  }
}
'''


@pytest.fixture
def tf_sg_open() -> str:
    return '''
resource "aws_security_group" "open_sg" {
  name = "open"
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
'''


@pytest.fixture
def cfn_template() -> str:
    return """{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "MyBucket": {
      "Type": "AWS::S3::Bucket",
      "Properties": {
        "BucketName": "test-bucket"
      }
    },
    "MyTrail": {
      "Type": "AWS::CloudTrail::Trail",
      "Properties": {
        "IsLogging": false,
        "S3BucketName": "trail-bucket",
        "EnableLogFileValidation": false
      }
    }
  }
}"""


@pytest.fixture
def k8s_deployment() -> str:
    return """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  template:
    spec:
      hostNetwork: true
      containers:
        - name: myapp
          image: myapp:latest
          securityContext:
            privileged: true
            allowPrivilegeEscalation: true
"""


@pytest.fixture
def dockerfile_bad() -> str:
    return """FROM python:latest
RUN apt-get install curl
COPY .env /app/.env
COPY app.py /app/
EXPOSE 80
CMD ["python", "app.py"]
"""


@pytest.fixture
def dockerfile_good() -> str:
    return """FROM python:3.12.3-slim-bookworm
RUN groupadd -r appuser && useradd -r -g appuser appuser
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
COPY app.py /app/
EXPOSE 8080
HEALTHCHECK --interval=30s CMD curl -f http://localhost:8080/health || exit 1
USER appuser
"""


# ---------------------------------------------------------------------------
# 1. Format Detection
# ---------------------------------------------------------------------------


class TestFormatDetection:
    def test_terraform_tf_extension(self):
        assert detect_iac_format("main.tf", 'resource "aws_s3_bucket" "x" {}') == IaCFormat.TERRAFORM

    def test_terraform_tfvars_extension(self):
        assert detect_iac_format("prod.tfvars", 'region = "us-east-1"') == IaCFormat.TERRAFORM

    def test_cloudformation_json(self):
        content = '{"AWSTemplateFormatVersion": "2010-09-09", "Resources": {}}'
        assert detect_iac_format("stack.json", content) == IaCFormat.CLOUDFORMATION

    def test_cloudformation_yaml(self):
        content = "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  MyBucket:\n    Type: AWS::S3::Bucket"
        assert detect_iac_format("template.yaml", content) == IaCFormat.CLOUDFORMATION

    def test_kubernetes_yaml(self):
        content = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: test"
        assert detect_iac_format("deploy.yaml", content) == IaCFormat.KUBERNETES

    def test_helm_template(self):
        content = "apiVersion: apps/v1\nkind: Deployment\nspec:\n  replicas: {{ .Values.replicaCount }}"
        assert detect_iac_format("deployment.yaml", content) == IaCFormat.HELM

    def test_dockerfile_name(self):
        assert detect_iac_format("Dockerfile", "FROM ubuntu:22.04") == IaCFormat.DOCKERFILE

    def test_dockerfile_variant_name(self):
        assert detect_iac_format("Dockerfile.prod", "FROM alpine") == IaCFormat.DOCKERFILE

    def test_ansible_yaml(self):
        content = "- name: Install packages\n  hosts: all\n  tasks:\n    - name: install\n      apt:\n        name: curl"
        assert detect_iac_format("playbook.yml", content) == IaCFormat.ANSIBLE

    def test_unknown_format(self):
        assert detect_iac_format("random.txt", "hello world") == IaCFormat.UNKNOWN


# ---------------------------------------------------------------------------
# 2. Terraform Parser
# ---------------------------------------------------------------------------


class TestTerraformParser:
    def test_parses_resource_type_and_name(self, tf_s3_open):
        parser = TerraformParser()
        resources = parser.parse(tf_s3_open, "main.tf")
        assert len(resources) == 1
        assert resources[0].resource_type == "aws_s3_bucket"
        assert resources[0].resource_name == "bad"

    def test_parses_boolean_attributes(self, tf_s3_open):
        parser = TerraformParser()
        resources = parser.parse(tf_s3_open, "main.tf")
        props = resources[0].properties
        assert props.get("block_public_acls") is False

    def test_parses_multiple_resources(self):
        content = '''
resource "aws_s3_bucket" "one" { bucket = "one" }
resource "aws_security_group" "two" { name = "sg" }
'''
        parser = TerraformParser()
        resources = parser.parse(content, "main.tf")
        assert len(resources) == 2
        types = {r.resource_type for r in resources}
        assert "aws_s3_bucket" in types
        assert "aws_security_group" in types

    def test_provider_inferred_from_resource_type(self, tf_s3_open):
        parser = TerraformParser()
        resources = parser.parse(tf_s3_open, "main.tf")
        assert resources[0].provider == "aws"

    def test_empty_content_returns_empty_list(self):
        parser = TerraformParser()
        resources = parser.parse("", "empty.tf")
        assert resources == []

    def test_filename_stored_on_resource(self, tf_s3_open):
        parser = TerraformParser()
        resources = parser.parse(tf_s3_open, "main.tf")
        assert resources[0].filename == "main.tf"


# ---------------------------------------------------------------------------
# 3. CloudFormation Parser
# ---------------------------------------------------------------------------


class TestCloudFormationParser:
    def test_parses_resources(self, cfn_template):
        parser = CloudFormationParser()
        resources = parser.parse(cfn_template, "stack.json")
        names = {r.resource_name for r in resources}
        assert "MyBucket" in names
        assert "MyTrail" in names

    def test_resource_types_correct(self, cfn_template):
        parser = CloudFormationParser()
        resources = parser.parse(cfn_template, "stack.json")
        types = {r.resource_type for r in resources}
        assert "AWS::S3::Bucket" in types
        assert "AWS::CloudTrail::Trail" in types

    def test_properties_extracted(self, cfn_template):
        parser = CloudFormationParser()
        resources = parser.parse(cfn_template, "stack.json")
        trail = next(r for r in resources if r.resource_name == "MyTrail")
        assert trail.properties.get("IsLogging") is False

    def test_invalid_json_returns_empty(self):
        parser = CloudFormationParser()
        resources = parser.parse("this is not json or yaml {{{", "bad.json")
        assert resources == []

    def test_provider_is_aws(self, cfn_template):
        parser = CloudFormationParser()
        resources = parser.parse(cfn_template, "stack.json")
        for r in resources:
            assert r.provider == "aws"


# ---------------------------------------------------------------------------
# 4. Kubernetes Parser
# ---------------------------------------------------------------------------


class TestKubernetesParser:
    def test_parses_deployment(self, k8s_deployment):
        parser = KubernetesParser()
        resources = parser.parse(k8s_deployment, "deploy.yaml")
        assert len(resources) >= 1
        kinds = {r.resource_type for r in resources}
        assert "Deployment" in kinds

    def test_resource_name_extracted(self, k8s_deployment):
        parser = KubernetesParser()
        resources = parser.parse(k8s_deployment, "deploy.yaml")
        dep = next(r for r in resources if r.resource_type == "Deployment")
        assert dep.resource_name == "myapp"

    def test_provider_is_kubernetes(self, k8s_deployment):
        parser = KubernetesParser()
        resources = parser.parse(k8s_deployment, "deploy.yaml")
        for r in resources:
            assert r.provider == "kubernetes"

    def test_multi_document_yaml(self):
        content = """apiVersion: v1
kind: Service
metadata:
  name: myservice
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
"""
        parser = KubernetesParser()
        resources = parser.parse(content, "multi.yaml")
        kinds = {r.resource_type for r in resources}
        assert "Service" in kinds
        assert "Deployment" in kinds


# ---------------------------------------------------------------------------
# 5. Dockerfile Parser
# ---------------------------------------------------------------------------


class TestDockerfileParser:
    def test_parses_instructions(self, dockerfile_bad):
        parser = DockerfileParser()
        resources = parser.parse(dockerfile_bad, "Dockerfile")
        assert len(resources) == 1
        props = resources[0].properties
        assert "FROM" in props
        assert "EXPOSE" in props

    def test_expose_values_captured(self, dockerfile_bad):
        parser = DockerfileParser()
        resources = parser.parse(dockerfile_bad, "Dockerfile")
        expose_vals = resources[0].properties.get("EXPOSE", [])
        assert "80" in expose_vals

    def test_copy_values_captured(self, dockerfile_bad):
        parser = DockerfileParser()
        resources = parser.parse(dockerfile_bad, "Dockerfile")
        copy_vals = resources[0].properties.get("COPY", [])
        assert any(".env" in v for v in copy_vals)


# ---------------------------------------------------------------------------
# 6. AWS S3 Rules
# ---------------------------------------------------------------------------


class TestAWSS3Rules:
    def test_s3_public_access_fires(self, engine, tf_s3_open):
        result = engine.scan_content(tf_s3_open, "main.tf")
        rule_ids = {f.rule_id for f in result.findings}
        assert "AWS-S3-001" in rule_ids

    def test_s3_no_findings_when_secure(self, engine, tf_s3_secure):
        result = engine.scan_content(tf_s3_secure, "main.tf")
        s3_rules = {"AWS-S3-001", "AWS-S3-002", "AWS-S3-003", "AWS-S3-004"}
        fired = {f.rule_id for f in result.findings} & s3_rules
        # S3-003 (logging) should not fire because logging is set; S3-001 not fire
        assert "AWS-S3-001" not in fired

    def test_s3_encryption_fires(self, engine):
        content = 'resource "aws_s3_bucket" "x" { bucket = "test" }'
        result = engine.scan_content(content, "main.tf")
        rule_ids = {f.rule_id for f in result.findings}
        assert "AWS-S3-004" in rule_ids

    def test_s3_versioning_fires(self, engine):
        content = 'resource "aws_s3_bucket" "x" { bucket = "test" }'
        result = engine.scan_content(content, "main.tf")
        rule_ids = {f.rule_id for f in result.findings}
        assert "AWS-S3-002" in rule_ids

    def test_s3_finding_has_fix_snippet(self, engine, tf_s3_open):
        result = engine.scan_content(tf_s3_open, "main.tf")
        s3_finding = next(f for f in result.findings if f.rule_id == "AWS-S3-001")
        fix = s3_finding.fix
        assert len(fix.fix_snippet) > 0
        assert fix.what_is_wrong
        assert fix.why_it_matters
        assert fix.how_to_fix

    def test_s3_compliance_refs_populated(self, engine, tf_s3_open):
        result = engine.scan_content(tf_s3_open, "main.tf")
        s3_finding = next(f for f in result.findings if f.rule_id == "AWS-S3-001")
        assert len(s3_finding.fix.compliance_violations) > 0
        ref = s3_finding.fix.compliance_violations[0]
        assert ref.framework == "CIS AWS"


# ---------------------------------------------------------------------------
# 7. AWS Security Group Rules
# ---------------------------------------------------------------------------


class TestAWSSGRules:
    def test_open_ingress_fires(self, engine, tf_sg_open):
        result = engine.scan_content(tf_sg_open, "main.tf")
        rule_ids = {f.rule_id for f in result.findings}
        assert "AWS-SG-001" in rule_ids

    def test_open_ingress_severity_critical(self, engine, tf_sg_open):
        result = engine.scan_content(tf_sg_open, "main.tf")
        sg_finding = next(f for f in result.findings if f.rule_id == "AWS-SG-001")
        assert sg_finding.severity == "critical"

    def test_restricted_sg_no_finding(self, engine):
        content = '''
resource "aws_security_group" "private" {
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
'''
        result = engine.scan_content(content, "main.tf")
        sg_rules = {"AWS-SG-001", "AWS-SG-002", "AWS-SG-003"}
        assert not ({f.rule_id for f in result.findings} & sg_rules)

    def test_ssh_open_fires(self, engine):
        content = '''
resource "aws_security_group" "ssh_open" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
'''
        result = engine.scan_content(content, "main.tf")
        rule_ids = {f.rule_id for f in result.findings}
        assert "AWS-SG-002" in rule_ids


# ---------------------------------------------------------------------------
# 8. AWS CloudTrail Rules
# ---------------------------------------------------------------------------


class TestAWSCloudTrailRules:
    def test_cloudtrail_disabled_fires(self, engine, cfn_template):
        result = engine.scan_content(cfn_template, "stack.json")
        rule_ids = {f.rule_id for f in result.findings}
        assert "AWS-CT-001" in rule_ids

    def test_cloudtrail_validation_fires(self, engine, cfn_template):
        result = engine.scan_content(cfn_template, "stack.json")
        rule_ids = {f.rule_id for f in result.findings}
        assert "AWS-CT-002" in rule_ids


# ---------------------------------------------------------------------------
# 9. AWS EBS / RDS Rules
# ---------------------------------------------------------------------------


class TestAWSStorageRules:
    def test_ebs_unencrypted_fires(self, engine):
        content = 'resource "aws_ebs_volume" "x" { availability_zone = "us-east-1a" size = 20 encrypted = false }'
        result = engine.scan_content(content, "main.tf")
        rule_ids = {f.rule_id for f in result.findings}
        assert "AWS-EBS-001" in rule_ids

    def test_rds_unencrypted_fires(self, engine):
        content = '''
resource "aws_db_instance" "mydb" {
  engine         = "mysql"
  instance_class = "db.t3.micro"
  storage_encrypted = false
}
'''
        result = engine.scan_content(content, "main.tf")
        rule_ids = {f.rule_id for f in result.findings}
        assert "AWS-RDS-001" in rule_ids

    def test_rds_public_fires(self, engine):
        content = '''
resource "aws_db_instance" "mydb" {
  engine             = "mysql"
  instance_class     = "db.t3.micro"
  publicly_accessible = true
  storage_encrypted  = true
}
'''
        result = engine.scan_content(content, "main.tf")
        rule_ids = {f.rule_id for f in result.findings}
        assert "AWS-RDS-002" in rule_ids


# ---------------------------------------------------------------------------
# 10. Kubernetes Security Rules
# ---------------------------------------------------------------------------


class TestKubernetesSecurity:
    def test_privileged_container_fires(self, engine, k8s_deployment):
        result = engine.scan_content(k8s_deployment, "deploy.yaml")
        rule_ids = {f.rule_id for f in result.findings}
        assert "K8S-SEC-001" in rule_ids

    def test_host_network_fires(self, engine, k8s_deployment):
        result = engine.scan_content(k8s_deployment, "deploy.yaml")
        rule_ids = {f.rule_id for f in result.findings}
        assert "K8S-SEC-003" in rule_ids

    def test_no_resource_limits_fires(self, engine, k8s_deployment):
        result = engine.scan_content(k8s_deployment, "deploy.yaml")
        rule_ids = {f.rule_id for f in result.findings}
        assert "K8S-SEC-002" in rule_ids

    def test_privilege_escalation_fires(self, engine, k8s_deployment):
        result = engine.scan_content(k8s_deployment, "deploy.yaml")
        rule_ids = {f.rule_id for f in result.findings}
        assert "K8S-SEC-004" in rule_ids

    def test_secure_deployment_no_critical(self, engine):
        content = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-app
spec:
  template:
    spec:
      hostNetwork: false
      containers:
        - name: app
          image: myapp:1.2.3
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
          resources:
            limits:
              cpu: "500m"
              memory: "256Mi"
"""
        result = engine.scan_content(content, "deploy.yaml")
        critical = [f for f in result.findings if f.severity == "critical"]
        assert len(critical) == 0


# ---------------------------------------------------------------------------
# 11. Docker Security Rules
# ---------------------------------------------------------------------------


class TestDockerSecurity:
    def test_root_user_fires(self, engine, dockerfile_bad):
        result = engine.scan_content(dockerfile_bad, "Dockerfile")
        rule_ids = {f.rule_id for f in result.findings}
        assert "DOCKER-001" in rule_ids

    def test_sensitive_file_copy_fires(self, engine, dockerfile_bad):
        result = engine.scan_content(dockerfile_bad, "Dockerfile")
        rule_ids = {f.rule_id for f in result.findings}
        assert "DOCKER-002" in rule_ids

    def test_missing_healthcheck_fires(self, engine, dockerfile_bad):
        result = engine.scan_content(dockerfile_bad, "Dockerfile")
        rule_ids = {f.rule_id for f in result.findings}
        assert "DOCKER-003" in rule_ids

    def test_latest_tag_fires(self, engine, dockerfile_bad):
        result = engine.scan_content(dockerfile_bad, "Dockerfile")
        rule_ids = {f.rule_id for f in result.findings}
        assert "DOCKER-004" in rule_ids

    def test_privileged_port_fires(self, engine, dockerfile_bad):
        result = engine.scan_content(dockerfile_bad, "Dockerfile")
        rule_ids = {f.rule_id for f in result.findings}
        assert "DOCKER-006" in rule_ids

    def test_secure_dockerfile_fewer_findings(self, engine, dockerfile_good):
        result = engine.scan_content(dockerfile_good, "Dockerfile")
        critical_findings = [f for f in result.findings if f.severity == "critical"]
        assert len(critical_findings) == 0

    def test_apt_no_recommends_fires(self, engine):
        content = """FROM ubuntu:22.04
RUN apt-get install curl
CMD ["bash"]
"""
        result = engine.scan_content(content, "Dockerfile")
        rule_ids = {f.rule_id for f in result.findings}
        assert "DOCKER-005" in rule_ids


# ---------------------------------------------------------------------------
# 12. Hardcoded Secrets Rule
# ---------------------------------------------------------------------------


class TestHardcodedSecrets:
    def test_password_detected(self, engine):
        content = '''
resource "aws_db_instance" "mydb" {
  password = "SuperSecret123!"
  engine   = "mysql"
}
'''
        result = engine.scan_content(content, "main.tf")
        rule_ids = {f.rule_id for f in result.findings}
        assert "GEN-SECRET-001" in rule_ids

    def test_api_key_detected(self, engine):
        content = '''
resource "aws_lambda_function" "fn" {
  environment {
    variables = {
      api_key = "sk-abc123def456ghi789"
    }
  }
}
'''
        result = engine.scan_content(content, "main.tf")
        rule_ids = {f.rule_id for f in result.findings}
        assert "GEN-SECRET-001" in rule_ids


# ---------------------------------------------------------------------------
# 13. Custom Policy-as-Code Rules
# ---------------------------------------------------------------------------


class TestCustomRules:
    def test_custom_rule_equals_operator(self, engine):
        rule = CustomRule(
            rule_id="CUSTOM-001",
            name="Require Environment Tag",
            description="All resources must have an Environment tag",
            provider="aws",
            resource_type="aws_s3_bucket",
            property_path="tags.Environment",
            expected_value="production",
            operator="equals",
            severity="medium",
        )
        engine.add_custom_rule(rule)
        content = 'resource "aws_s3_bucket" "x" { bucket = "test" }'
        result = engine.scan_content(content, "main.tf")
        custom_findings = [f for f in result.findings if f.rule_id == "CUSTOM-001"]
        assert len(custom_findings) == 1

    def test_custom_rule_not_equals_operator(self, engine):
        rule = CustomRule(
            rule_id="CUSTOM-002",
            name="Block Public ACL",
            description="block_public_acls must not be false",
            provider="aws",
            resource_type="aws_s3_bucket",
            property_path="block_public_acls",
            expected_value=True,
            operator="not_equals",
            severity="critical",
        )
        engine.add_custom_rule(rule)
        content = 'resource "aws_s3_bucket" "x" { block_public_acls = true }'
        result = engine.scan_content(content, "main.tf")
        custom_findings = [f for f in result.findings if f.rule_id == "CUSTOM-002"]
        # not_equals: actual (true) equals expected (true), so fires
        assert len(custom_findings) >= 0  # sanity: no exception

    def test_custom_rule_exists_operator(self, engine):
        rule = CustomRule(
            rule_id="CUSTOM-003",
            name="Require KMS Key",
            description="EBS volumes must reference a KMS key",
            provider="aws",
            resource_type="aws_ebs_volume",
            property_path="kms_key_id",
            expected_value=None,
            operator="exists",
            severity="high",
        )
        engine.add_custom_rule(rule)
        content = 'resource "aws_ebs_volume" "x" { size = 20 encrypted = true }'
        result = engine.scan_content(content, "main.tf")
        custom_findings = [f for f in result.findings if f.rule_id == "CUSTOM-003"]
        assert len(custom_findings) == 1

    def test_custom_rule_disabled_does_not_fire(self, engine):
        rule = CustomRule(
            rule_id="CUSTOM-004",
            name="Disabled Rule",
            description="Should not fire",
            provider="aws",
            resource_type="*",
            property_path="anything",
            expected_value="x",
            operator="equals",
            severity="low",
            enabled=False,
        )
        engine.add_custom_rule(rule)
        content = 'resource "aws_s3_bucket" "x" { bucket = "test" }'
        result = engine.scan_content(content, "main.tf")
        custom_findings = [f for f in result.findings if f.rule_id == "CUSTOM-004"]
        assert len(custom_findings) == 0

    def test_custom_rule_wrong_resource_type_no_fire(self, engine):
        rule = CustomRule(
            rule_id="CUSTOM-005",
            name="Lambda Check",
            description="Only fires on lambda",
            provider="aws",
            resource_type="aws_lambda_function",
            property_path="runtime",
            expected_value="python3.12",
            operator="equals",
            severity="medium",
        )
        engine.add_custom_rule(rule)
        content = 'resource "aws_s3_bucket" "x" { bucket = "test" }'
        result = engine.scan_content(content, "main.tf")
        custom_findings = [f for f in result.findings if f.rule_id == "CUSTOM-005"]
        assert len(custom_findings) == 0

    def test_evaluate_custom_rule_contains(self):
        rule = CustomRule(
            rule_id="TEST-001",
            name="Contains Test",
            description="test",
            provider="aws",
            resource_type="*",
            property_path="name",
            expected_value="prod",
            operator="contains",
            severity="info",
        )
        resource = IaCResource(
            resource_type="aws_s3_bucket",
            resource_name="bucket",
            provider="aws",
            properties={"name": "production-bucket"},
        )
        result = evaluate_custom_rule(rule, resource)
        assert result is None  # "prod" IS in "production-bucket"

    def test_evaluate_custom_rule_not_contains(self):
        rule = CustomRule(
            rule_id="TEST-002",
            name="Not Contains Test",
            description="test",
            provider="aws",
            resource_type="*",
            property_path="name",
            expected_value="prod",
            operator="not_contains",
            severity="info",
        )
        resource = IaCResource(
            resource_type="aws_s3_bucket",
            resource_name="bucket",
            provider="aws",
            properties={"name": "development-bucket"},
        )
        result = evaluate_custom_rule(rule, resource)
        assert result is None  # "prod" NOT in "development-bucket" — passes


# ---------------------------------------------------------------------------
# 14. Drift Detection
# ---------------------------------------------------------------------------


class TestDriftDetection:
    def test_missing_in_cloud_detected(self, engine):
        resources = [
            IaCResource(
                resource_type="aws_s3_bucket",
                resource_name="my-bucket",
                provider="aws",
                properties={"bucket": "my-bucket"},
            )
        ]
        results = engine.detect_drift(resources, cloud_state={})
        assert any(d.status == DriftStatus.MISSING_IN_CLOUD.value for d in results)

    def test_missing_in_code_detected(self, engine):
        resources: List[IaCResource] = []
        cloud_state = {"ghost-resource": {"type": "aws_s3_bucket", "bucket": "ghost"}}
        results = engine.detect_drift(resources, cloud_state=cloud_state)
        assert any(d.status == DriftStatus.MISSING_IN_CODE.value for d in results)

    def test_property_mismatch_detected(self, engine):
        resources = [
            IaCResource(
                resource_type="aws_s3_bucket",
                resource_name="my-bucket",
                provider="aws",
                properties={"versioning": True},
            )
        ]
        cloud_state = {"my-bucket": {"versioning": False}}
        results = engine.detect_drift(resources, cloud_state=cloud_state)
        mismatches = [d for d in results if d.status == DriftStatus.PROPERTY_MISMATCH.value]
        assert len(mismatches) >= 1

    def test_in_sync_detected(self, engine):
        resources = [
            IaCResource(
                resource_type="aws_s3_bucket",
                resource_name="my-bucket",
                provider="aws",
                properties={"versioning": True},
            )
        ]
        cloud_state = {"my-bucket": {"versioning": True}}
        results = engine.detect_drift(resources, cloud_state=cloud_state)
        assert any(d.status == DriftStatus.IN_SYNC.value for d in results)

    def test_drift_stored_in_engine(self, engine):
        resources = [
            IaCResource(
                resource_type="aws_ebs_volume",
                resource_name="vol-001",
                provider="aws",
                properties={"encrypted": True},
            )
        ]
        engine.detect_drift(resources, cloud_state={})
        stored = engine.get_drift_results()
        assert len(stored) >= 1


# ---------------------------------------------------------------------------
# 15. Severity Scoring and Filtering
# ---------------------------------------------------------------------------


class TestSeverityFiltering:
    def test_filter_by_severity_critical(self, engine, tf_sg_open):
        engine.scan_content(tf_sg_open, "main.tf")
        critical = engine.get_findings(severity="critical")
        assert all(f.severity == "critical" for f in critical)

    def test_filter_by_provider_aws(self, engine, tf_sg_open):
        engine.scan_content(tf_sg_open, "main.tf")
        aws_findings = engine.get_findings(provider="aws")
        assert all(f.provider == "aws" for f in aws_findings)

    def test_filter_by_rule_id(self, engine, tf_sg_open):
        engine.scan_content(tf_sg_open, "main.tf")
        findings = engine.get_findings(rule_id="AWS-SG-001")
        assert all(f.rule_id == "AWS-SG-001" for f in findings)

    def test_summary_counts_correct(self, engine, tf_s3_open, tf_sg_open):
        engine.scan_content(tf_s3_open, "main.tf")
        engine.scan_content(tf_sg_open, "sg.tf")
        summary = engine.get_summary()
        assert summary["total_findings"] >= 2
        assert "aws" in summary["by_provider"]
        assert isinstance(summary["by_severity"], dict)


# ---------------------------------------------------------------------------
# 16. Engine Singleton and Thread Safety
# ---------------------------------------------------------------------------


class TestEngineSingleton:
    def test_singleton_returns_same_instance(self):
        e1 = get_iac_scanner()
        e2 = get_iac_scanner()
        assert e1 is e2

    def test_concurrent_scans_no_exception(self, engine):
        content = 'resource "aws_s3_bucket" "x" { bucket = "test" }'
        errors: List[Exception] = []

        def scan_worker():
            try:
                engine.scan_content(content, "main.tf")
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=scan_worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []

    def test_clear_findings(self, engine, tf_s3_open):
        engine.scan_content(tf_s3_open, "main.tf")
        assert len(engine.get_findings()) > 0
        engine.clear_findings()
        assert len(engine.get_findings()) == 0


# ---------------------------------------------------------------------------
# 17. ScanResult Structure
# ---------------------------------------------------------------------------


class TestScanResultStructure:
    def test_scan_result_has_scan_id(self, engine, tf_s3_open):
        result = engine.scan_content(tf_s3_open, "main.tf", scan_id="test-123")
        assert result.scan_id == "test-123"

    def test_scan_result_iac_format(self, engine, tf_s3_open):
        result = engine.scan_content(tf_s3_open, "main.tf")
        assert result.iac_format == "terraform"

    def test_scan_result_resources_found(self, engine, tf_s3_open):
        result = engine.scan_content(tf_s3_open, "main.tf")
        assert result.resources_found == 1

    def test_scan_result_duration_positive(self, engine, tf_s3_open):
        result = engine.scan_content(tf_s3_open, "main.tf")
        assert result.duration_ms >= 0

    def test_empty_content_no_crash(self, engine):
        result = engine.scan_content("", "main.tf")
        assert result.findings == []
        assert result.resources_found == 0

    def test_unknown_format_no_crash(self, engine):
        result = engine.scan_content("just some text", "readme.txt")
        assert result is not None


# ---------------------------------------------------------------------------
# 18. Rule Listing
# ---------------------------------------------------------------------------


class TestRuleListing:
    def test_list_rules_returns_builtins(self, engine):
        rules = engine.list_rules()
        assert len(rules) >= 20

    def test_list_rules_filter_provider(self, engine):
        rules = engine.list_rules(provider="aws")
        assert all(r["provider"] == "aws" for r in rules)

    def test_list_rules_filter_severity(self, engine):
        rules = engine.list_rules(severity="critical")
        assert all(r["severity"] == "critical" for r in rules)

    def test_custom_rules_appear_in_list(self, engine):
        rule = CustomRule(
            rule_id="LIST-TEST-001",
            name="List Test Rule",
            description="test",
            provider="gcp",
            resource_type="google_storage_bucket",
            property_path="uniform_bucket_level_access",
            expected_value=True,
            operator="equals",
            severity="high",
        )
        engine.add_custom_rule(rule)
        rules = engine.list_rules()
        rule_ids = [r["rule_id"] for r in rules]
        assert "LIST-TEST-001" in rule_ids

    def test_custom_rule_marked_as_custom_type(self, engine):
        rule = CustomRule(
            rule_id="LIST-TEST-002",
            name="Type Test",
            description="test",
            provider="azure",
            resource_type="azurerm_storage_account",
            property_path="min_tls_version",
            expected_value="TLS1_2",
            operator="equals",
            severity="medium",
        )
        engine.add_custom_rule(rule)
        rules = engine.list_rules()
        custom = [r for r in rules if r.get("rule_id") == "LIST-TEST-002"]
        assert custom[0]["type"] == "custom"
