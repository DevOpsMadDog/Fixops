"""
ALDECI Terraform Module Validation Tests

Validates HCL syntax, required variables, security best practices, and
structural correctness of the docker/terraform/ module without requiring
AWS credentials or a live Terraform installation.

Run with:
    python -m pytest tests/test_terraform.py -x --tb=short --timeout=10 -q
"""

import re
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

TERRAFORM_DIR = Path(__file__).parent.parent / "docker" / "terraform"
EXPECTED_FILES = [
    "main.tf",
    "variables.tf",
    "outputs.tf",
    "vpc.tf",
    "ecs.tf",
    "rds.tf",
    "s3.tf",
    "iam.tf",
    "terraform.tfvars.example",
]


def _read(filename: str) -> str:
    """Read a Terraform file and return its contents."""
    path = TERRAFORM_DIR / filename
    assert path.exists(), f"Expected file not found: {path}"
    return path.read_text()


def _all_tf_content() -> str:
    """Return concatenated content of all .tf files."""
    return "\n".join(
        (TERRAFORM_DIR / f).read_text()
        for f in EXPECTED_FILES
        if f.endswith(".tf")
    )


def _extract_variable_names(variables_tf: str) -> set:
    """Return set of declared variable names from variables.tf."""
    return set(re.findall(r'^variable\s+"(\w+)"', variables_tf, re.MULTILINE))


def _extract_output_names(outputs_tf: str) -> set:
    """Return set of declared output names from outputs.tf."""
    return set(re.findall(r'^output\s+"(\w+)"', outputs_tf, re.MULTILINE))


def _extract_resource_types(content: str) -> set:
    """Return set of resource types declared across all .tf files."""
    return set(re.findall(r'^resource\s+"(\w+)"', content, re.MULTILINE))


def _curly_braces_balanced(content: str) -> bool:
    """Rough balance check for curly braces — catches unclosed blocks."""
    depth = 0
    in_string = False
    escape_next = False
    for ch in content:
        if escape_next:
            escape_next = False
            continue
        if ch == "\\" and in_string:
            escape_next = True
            continue
        if ch == '"' and not escape_next:
            in_string = not in_string
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
    return depth == 0


# ===========================================================================
# Group 1: File Existence (5 tests)
# ===========================================================================


class TestFileExistence:
    def test_terraform_directory_exists(self):
        assert TERRAFORM_DIR.exists(), f"Terraform directory missing: {TERRAFORM_DIR}"

    @pytest.mark.parametrize("filename", EXPECTED_FILES)
    def test_required_files_exist(self, filename):
        assert (TERRAFORM_DIR / filename).exists(), f"Missing: {filename}"

    def test_no_sensitive_files_checked_in(self):
        """terraform.tfvars must not exist (only the .example)."""
        assert not (TERRAFORM_DIR / "terraform.tfvars").exists(), (
            "terraform.tfvars must not be committed — it may contain secrets. "
            "Use terraform.tfvars.example instead."
        )


# ===========================================================================
# Group 2: Syntax / Structure (5 tests)
# ===========================================================================


class TestSyntax:
    def test_main_tf_curly_braces_balanced(self):
        assert _curly_braces_balanced(_read("main.tf")), "Unbalanced braces in main.tf"

    def test_vpc_tf_curly_braces_balanced(self):
        assert _curly_braces_balanced(_read("vpc.tf")), "Unbalanced braces in vpc.tf"

    def test_ecs_tf_curly_braces_balanced(self):
        assert _curly_braces_balanced(_read("ecs.tf")), "Unbalanced braces in ecs.tf"

    def test_iam_tf_curly_braces_balanced(self):
        assert _curly_braces_balanced(_read("iam.tf")), "Unbalanced braces in iam.tf"

    def test_no_hardcoded_aws_account_ids(self):
        """Account IDs must come from data sources, not be hardcoded literals."""
        content = _all_tf_content()
        # A 12-digit number that is NOT part of a variable reference, ARN template,
        # or the example tfvars file. We allow 123456789012 as an obvious placeholder.
        account_ids = re.findall(r'(?<![/\-:*"])\b([0-9]{12})\b(?![0-9])', content)
        real_ids = [a for a in account_ids if a != "123456789012"]
        assert not real_ids, f"Hardcoded AWS account IDs found: {real_ids}"


# ===========================================================================
# Group 3: Required Variables (5 tests)
# ===========================================================================


class TestRequiredVariables:
    REQUIRED_VARIABLES = [
        "aws_region",
        "environment",
        "project_name",
        "domain_name",
        "api_image",
        "ui_image",
        "vpc_cidr",
        "enable_rds",
        "log_retention_days",
        "tags",
    ]

    @pytest.fixture(scope="class")
    def var_names(self):
        return _extract_variable_names(_read("variables.tf"))

    @pytest.mark.parametrize("var_name", REQUIRED_VARIABLES)
    def test_variable_declared(self, var_name, var_names):
        assert var_name in var_names, f"Variable '{var_name}' not declared in variables.tf"

    def test_all_variables_have_descriptions(self):
        """Every variable block must include a description field."""
        content = _read("variables.tf")
        blocks = re.findall(
            r'variable\s+"(\w+)"\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}',
            content,
            re.DOTALL,
        )
        missing = [name for name, body in blocks if "description" not in body]
        assert not missing, f"Variables missing description: {missing}"

    def test_sensitive_variables_marked(self):
        """Password/secret variables must be marked sensitive = true."""
        content = _read("variables.tf")
        # Find variable blocks that contain "password" in their name
        password_blocks = re.findall(
            r'variable\s+"([^"]*(?:password|secret)[^"]*)"\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}',
            content,
            re.DOTALL | re.IGNORECASE,
        )
        not_sensitive = [
            name for name, body in password_blocks if "sensitive" not in body
        ]
        assert not not_sensitive, f"Password variables not marked sensitive: {not_sensitive}"

    def test_environment_variable_has_validation(self):
        """The environment variable must have a validation block."""
        content = _read("variables.tf")
        env_block_match = re.search(
            r'variable\s+"environment"\s*\{(.+?)^}',
            content,
            re.DOTALL | re.MULTILINE,
        )
        assert env_block_match, "environment variable block not found"
        assert "validation" in env_block_match.group(1), (
            "environment variable must include a validation block"
        )

    def test_cpu_variables_have_validation(self):
        """CPU variables must have validation blocks (only valid Fargate values)."""
        content = _read("variables.tf")
        for var in ("api_cpu", "ui_cpu"):
            pattern = rf'variable\s+"{var}"\s*\{{(.+?)^}}'
            match = re.search(pattern, content, re.DOTALL | re.MULTILINE)
            assert match, f"{var} variable block not found"
            assert "validation" in match.group(1), f"{var} must include a validation block"


# ===========================================================================
# Group 4: Required Outputs (3 tests)
# ===========================================================================


class TestRequiredOutputs:
    REQUIRED_OUTPUTS = [
        "api_url",
        "ui_url",
        "alb_dns_name",
        "vpc_id",
        "ecs_cluster_name",
        "backup_bucket_name",
        "ecs_task_execution_role_arn",
    ]

    @pytest.fixture(scope="class")
    def output_names(self):
        return _extract_output_names(_read("outputs.tf"))

    @pytest.mark.parametrize("output_name", REQUIRED_OUTPUTS)
    def test_output_declared(self, output_name, output_names):
        assert output_name in output_names, f"Output '{output_name}' not declared in outputs.tf"

    def test_all_outputs_have_descriptions(self):
        """Every output block must include a description field."""
        content = _read("outputs.tf")
        blocks = re.findall(
            r'output\s+"(\w+)"\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}',
            content,
            re.DOTALL,
        )
        missing = [name for name, body in blocks if "description" not in body]
        assert not missing, f"Outputs missing description: {missing}"

    def test_rds_outputs_are_conditional(self):
        """RDS outputs must guard on var.enable_rds to avoid errors when disabled."""
        content = _read("outputs.tf")
        rds_output_match = re.search(
            r'output\s+"rds_endpoint"\s*\{(.+?)^}',
            content,
            re.DOTALL | re.MULTILINE,
        )
        assert rds_output_match, "rds_endpoint output not found"
        assert "enable_rds" in rds_output_match.group(1), (
            "rds_endpoint output must be conditional on var.enable_rds"
        )


# ===========================================================================
# Group 5: Security Best Practices (7 tests)
# ===========================================================================


class TestSecurityBestPractices:
    def test_s3_public_access_blocked(self):
        """S3 bucket must have all public access blocked."""
        content = _read("s3.tf")
        assert "block_public_acls" in content
        assert "block_public_policy" in content
        assert "ignore_public_acls" in content
        assert "restrict_public_buckets" in content

    def test_s3_encryption_enabled(self):
        """S3 bucket must have server-side encryption configured."""
        content = _read("s3.tf")
        assert "server_side_encryption_configuration" in content
        assert re.search(r"sse_algorithm\s*=", content), "SSE algorithm not configured"

    def test_s3_tls_enforced(self):
        """S3 bucket policy must deny non-TLS access."""
        content = _read("s3.tf")
        assert "DenyNonTLS" in content or "SecureTransport" in content, (
            "S3 bucket policy must deny non-TLS (SecureTransport) requests"
        )

    def test_rds_encrypted_at_rest(self):
        """RDS instance must have storage_encrypted = true."""
        content = _read("rds.tf")
        assert "storage_encrypted" in content
        assert re.search(r"storage_encrypted\s*=\s*true", content), (
            "RDS must have storage_encrypted = true"
        )

    def test_rds_not_publicly_accessible(self):
        """RDS instance must not be publicly accessible."""
        content = _read("rds.tf")
        assert re.search(r"publicly_accessible\s*=\s*false", content), (
            "RDS must have publicly_accessible = false"
        )

    def test_alb_drops_invalid_headers(self):
        """ALB must drop invalid HTTP headers (security hardening)."""
        content = _read("main.tf")
        assert re.search(r"drop_invalid_header_fields\s*=\s*true", content), (
            "ALB must have drop_invalid_header_fields = true"
        )

    def test_alb_uses_tls13_policy(self):
        """HTTPS listener must use a TLS 1.2+ or TLS 1.3 security policy."""
        content = _read("main.tf")
        assert re.search(r"ELBSecurityPolicy-TLS", content), (
            "ALB HTTPS listener must specify a TLS security policy"
        )

    def test_ecs_tasks_not_privileged(self):
        """ECS container definitions must not run as privileged."""
        content = _read("ecs.tf")
        # privileged should be explicitly set to false
        privileged_true = re.findall(r"privileged\s*=\s*true", content)
        assert not privileged_true, "ECS tasks must not run with privileged = true"

    def test_iam_roles_use_condition_on_assume(self):
        """ECS task IAM roles must use a condition on the trust policy."""
        content = _read("iam.tf")
        assert "Condition" in content, (
            "ECS IAM role trust policies must include a Condition to limit scope"
        )

    def test_vpc_flow_logs_enabled(self):
        """VPC flow logs must be configured for network audit trail."""
        content = _read("vpc.tf")
        assert "aws_flow_log" in content, "VPC flow logs resource not found in vpc.tf"

    def test_no_wildcard_iam_actions_without_condition(self):
        """Star-action IAM policies must include a Condition."""
        content = _read("iam.tf")
        # Find Action = "*" patterns — these are dangerous without conditions
        star_actions = re.findall(
            r'"Action"\s*:\s*"\*"',
            content,
        )
        # We allow zero occurrences of unconditional Action: *
        assert not star_actions, (
            f"Found {len(star_actions)} wildcard Action: * in iam.tf — use specific actions"
        )


# ===========================================================================
# Group 6: Resource Naming and Tagging (3 tests)
# ===========================================================================


class TestNamingAndTagging:
    def test_resource_names_use_project_environment_prefix(self):
        """Resource names should reference project_name and environment variables."""
        content = _all_tf_content()
        assert 'var.project_name' in content, "Resources must use var.project_name in names"
        assert 'var.environment' in content, "Resources must use var.environment in names"

    def test_ecs_services_have_deployment_circuit_breaker(self):
        """ECS services must enable deployment circuit breaker for safe rollouts."""
        content = _read("ecs.tf")
        assert "deployment_circuit_breaker" in content, (
            "ECS services must configure deployment_circuit_breaker"
        )
        assert re.search(r"rollback\s*=\s*true", content), (
            "Deployment circuit breaker must have rollback = true"
        )

    def test_nat_gateway_per_az_for_ha(self):
        """NAT gateways should be provisioned per AZ (count = length of subnets)."""
        content = _read("vpc.tf")
        assert re.search(r"count\s*=\s*length\(var\.public_subnet_cidrs\)", content), (
            "NAT gateways must use count = length(var.public_subnet_cidrs) for per-AZ HA"
        )

    def test_s3_versioning_enabled(self):
        """S3 backup bucket must have versioning enabled."""
        content = _read("s3.tf")
        assert "aws_s3_bucket_versioning" in content
        assert re.search(r'status\s*=\s*"Enabled"', content), (
            "S3 versioning must be set to Enabled"
        )

    def test_tfvars_example_has_all_required_keys(self):
        """terraform.tfvars.example must document all required variable values."""
        example = _read("terraform.tfvars.example")
        required_keys = [
            "aws_region", "environment", "domain_name",
            "api_image", "ui_image", "enable_rds",
            "backup_bucket_name", "log_retention_days",
        ]
        missing = [k for k in required_keys if k not in example]
        assert not missing, f"terraform.tfvars.example missing keys: {missing}"
