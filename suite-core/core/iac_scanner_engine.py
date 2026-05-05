"""IaC Security Scanner Engine — Infrastructure-as-Code vulnerability detection.

Scans Terraform, CloudFormation, Kubernetes, Helm, Ansible, and Dockerfiles
for security misconfigurations. Provides fix suggestions, compliance mapping,
custom policy-as-code rules, and drift detection stubs.

Usage:
    from core.iac_scanner_engine import IaCScannerEngine, get_iac_scanner

    scanner = get_iac_scanner()
    result = scanner.scan_content(content="...", filename="main.tf")
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Optional, Tuple

import structlog

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None

# ---------------------------------------------------------------------------
# Pre-compiled regex constants (module-level, compiled once at import time)
# ---------------------------------------------------------------------------
_RE_K8S_API_VERSION = re.compile(r"apiVersion\s*:")
_RE_K8S_KIND = re.compile(r"kind\s*:")
_RE_ANSIBLE = re.compile(r"^\s*-\s+(name|hosts|tasks|roles)\s*:", re.MULTILINE)
_RE_CFN = re.compile(r'AWSTemplateFormatVersion|Resources\s*:')
_RE_CFN_JSON = re.compile(r'"AWSTemplateFormatVersion"|"Resources"\s*:')
_RE_YAML_TOPKEY = re.compile(r'^(\w[\w:]*)\s*:')
_RE_YAML_KV = re.compile(r'^(\w+)\s*:\s*(.+)$')
_RE_YAML_DOC_SEP = re.compile(r'^---\s*$', re.MULTILINE)


def _emit_event(event_type: str, payload) -> None:  # type: ignore[no-untyped-def]
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


try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class IaCFormat(str, Enum):
    TERRAFORM = "terraform"
    CLOUDFORMATION = "cloudformation"
    KUBERNETES = "kubernetes"
    HELM = "helm"
    ANSIBLE = "ansible"
    DOCKERFILE = "dockerfile"
    UNKNOWN = "unknown"


class Provider(str, Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    KUBERNETES = "kubernetes"
    DOCKER = "docker"
    GENERIC = "generic"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class DriftStatus(str, Enum):
    IN_SYNC = "in_sync"
    MISSING_IN_CLOUD = "missing_in_cloud"
    MISSING_IN_CODE = "missing_in_code"
    PROPERTY_MISMATCH = "property_mismatch"


# ---------------------------------------------------------------------------
# Pydantic v2 models
# ---------------------------------------------------------------------------

try:
    from pydantic import BaseModel, Field
    _PYDANTIC = True
except ImportError:
    _PYDANTIC = False


if _PYDANTIC:
    class ComplianceRef(BaseModel):
        framework: str
        control: str
        description: str

    class FixSuggestion(BaseModel):
        what_is_wrong: str
        why_it_matters: str
        how_to_fix: str
        fix_snippet: str
        compliance_violations: List[ComplianceRef] = Field(default_factory=list)

    class IaCFinding(BaseModel):
        finding_id: str
        rule_id: str
        title: str
        description: str
        severity: str
        provider: str
        resource_type: str
        resource_name: str
        filename: str
        line_number: int
        property_path: str
        actual_value: Any
        expected_value: Any
        fix: FixSuggestion
        tags: List[str] = Field(default_factory=list)
        scan_id: str = ""
        detected_at: str = ""

    class IaCResource(BaseModel):
        resource_type: str
        resource_name: str
        provider: str
        properties: Dict[str, Any] = Field(default_factory=dict)
        filename: str = ""
        line_number: int = 0
        raw_block: str = ""

    class CustomRule(BaseModel):
        rule_id: str
        name: str
        description: str
        provider: str
        resource_type: str
        property_path: str
        expected_value: Any
        operator: str = "equals"   # equals, not_equals, contains, not_contains, exists, not_exists
        severity: str = "medium"
        fix_description: str = ""
        fix_snippet: str = ""
        compliance: List[Dict[str, str]] = Field(default_factory=list)
        enabled: bool = True

    class DriftResult(BaseModel):
        resource_id: str
        resource_type: str
        status: str
        iac_value: Any = None
        cloud_value: Any = None
        property_path: str = ""
        detected_at: str = ""

    class ScanResult(BaseModel):
        scan_id: str
        filename: str
        iac_format: str
        provider: str
        resources_found: int
        findings: List[IaCFinding] = Field(default_factory=list)
        scanned_at: str = ""
        duration_ms: float = 0.0

else:
    # Fallback dataclasses when Pydantic is unavailable
    @dataclass
    class ComplianceRef:
        framework: str
        control: str
        description: str

    @dataclass
    class FixSuggestion:
        what_is_wrong: str
        why_it_matters: str
        how_to_fix: str
        fix_snippet: str
        compliance_violations: List = field(default_factory=list)

    @dataclass
    class IaCFinding:
        finding_id: str
        rule_id: str
        title: str
        description: str
        severity: str
        provider: str
        resource_type: str
        resource_name: str
        filename: str
        line_number: int
        property_path: str
        actual_value: Any
        expected_value: Any
        fix: Any
        tags: List[str] = field(default_factory=list)
        scan_id: str = ""
        detected_at: str = ""

    @dataclass
    class IaCResource:
        resource_type: str
        resource_name: str
        provider: str
        properties: Dict[str, Any] = field(default_factory=dict)
        filename: str = ""
        line_number: int = 0
        raw_block: str = ""

    @dataclass
    class CustomRule:
        rule_id: str
        name: str
        description: str
        provider: str
        resource_type: str
        property_path: str
        expected_value: Any
        operator: str = "equals"
        severity: str = "medium"
        fix_description: str = ""
        fix_snippet: str = ""
        compliance: List = field(default_factory=list)
        enabled: bool = True

    @dataclass
    class DriftResult:
        resource_id: str
        resource_type: str
        status: str
        iac_value: Any = None
        cloud_value: Any = None
        property_path: str = ""
        detected_at: str = ""

    @dataclass
    class ScanResult:
        scan_id: str
        filename: str
        iac_format: str
        provider: str
        resources_found: int
        findings: List = field(default_factory=list)
        scanned_at: str = ""
        duration_ms: float = 0.0


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------


def detect_iac_format(filename: str, content: str) -> IaCFormat:
    """Detect IaC format from filename and content heuristics."""
    name = Path(filename).name.lower()
    suffix = Path(filename).suffix.lower()

    if name == "dockerfile" or name.startswith("dockerfile."):
        return IaCFormat.DOCKERFILE
    if suffix in (".tf", ".tfvars"):
        return IaCFormat.TERRAFORM
    if suffix in (".yml", ".yaml"):
        # Kubernetes detection
        if _RE_K8S_API_VERSION.search(content) and _RE_K8S_KIND.search(content):
            # Check for Helm chart indicators
            if "{{ " in content or "{{-" in content or ".Values." in content:
                return IaCFormat.HELM
            return IaCFormat.KUBERNETES
        # Ansible detection
        if _RE_ANSIBLE.search(content):
            return IaCFormat.ANSIBLE
        # CloudFormation YAML
        if _RE_CFN.search(content):
            return IaCFormat.CLOUDFORMATION
    if suffix == ".json":
        if _RE_CFN_JSON.search(content):
            return IaCFormat.CLOUDFORMATION
    return IaCFormat.UNKNOWN


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------


class TerraformParser:
    """Minimal HCL-like parser for Terraform .tf and .tfvars files."""

    _RESOURCE_RE = re.compile(
        r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{', re.MULTILINE
    )
    _ATTR_RE = re.compile(r'^\s*(\w[\w.]*)\s*=\s*(.+)$', re.MULTILINE)
    _BLOCK_RE = re.compile(r'^\s*(\w+)\s*\{', re.MULTILINE)

    def parse(self, content: str, filename: str) -> List[IaCResource]:
        resources: List[IaCResource] = []
        content.splitlines()

        for m in self._RESOURCE_RE.finditer(content):
            res_type = m.group(1)
            res_name = m.group(2)
            line_no = content[: m.start()].count("\n") + 1
            block_content = self._extract_block(content, m.end())
            props = self._parse_attrs(block_content)
            provider = res_type.split("_")[0] if "_" in res_type else "generic"
            resources.append(
                IaCResource(
                    resource_type=res_type,
                    resource_name=res_name,
                    provider=provider,
                    properties=props,
                    filename=filename,
                    line_number=line_no,
                    raw_block=block_content[:500],
                )
            )
        return resources

    def _extract_block(self, content: str, start: int) -> str:
        depth = 1
        i = start
        while i < len(content) and depth > 0:
            if content[i] == "{":
                depth += 1
            elif content[i] == "}":
                depth -= 1
            i += 1
        return content[start: i - 1]

    def _parse_attrs(self, block: str) -> Dict[str, Any]:
        attrs: Dict[str, Any] = {}
        for m in self._ATTR_RE.finditer(block):
            key = m.group(1).strip()
            raw = m.group(2).strip().rstrip(",")
            attrs[key] = self._coerce(raw)
        return attrs

    def _coerce(self, raw: str) -> Any:
        raw = raw.strip('"').strip("'")
        if raw.lower() in ("true", "yes"):
            return True
        if raw.lower() in ("false", "no"):
            return False
        try:
            return int(raw)
        except ValueError:
            pass
        return raw


class CloudFormationParser:
    """Parse AWS CloudFormation templates (JSON and YAML)."""

    def parse(self, content: str, filename: str) -> List[IaCResource]:
        resources: List[IaCResource] = []
        try:
            data = self._load(content)
        except Exception:
            return resources

        cf_resources = data.get("Resources", {})
        if not isinstance(cf_resources, dict):
            return resources

        for logical_id, definition in cf_resources.items():
            if not isinstance(definition, dict):
                continue
            res_type = definition.get("Type", "AWS::Unknown")
            props = definition.get("Properties", {})
            if not isinstance(props, dict):
                props = {}
            resources.append(
                IaCResource(
                    resource_type=res_type,
                    resource_name=logical_id,
                    provider="aws",
                    properties=props,
                    filename=filename,
                    line_number=0,
                )
            )
        return resources

    def _load(self, content: str) -> Dict[str, Any]:
        # Try JSON first, then YAML-lite
        content = content.strip()
        if content.startswith("{"):
            data = json.loads(content)
            if not isinstance(data, dict):
                raise ValueError("CloudFormation JSON root must be an object")
            return data
        return self._parse_yaml_lite(content)

    def _parse_yaml_lite(self, content: str) -> Dict[str, Any]:
        """Very minimal YAML parser sufficient for CloudFormation structure."""
        try:
            import yaml  # type: ignore
            data = yaml.safe_load(content)
            if isinstance(data, dict):
                return data
            return {}
        except ImportError:
            pass
        except Exception:
            return {}
        # Fallback: regex-based extraction of top-level keys
        result: Dict[str, Any] = {}
        for line in content.splitlines():
            m = _RE_YAML_TOPKEY.match(line)
            if m and not line.startswith(" "):
                current_key = m.group(1)
                result[current_key] = {}
        return result


class KubernetesParser:
    """Parse Kubernetes YAML manifests."""

    def parse(self, content: str, filename: str) -> List[IaCResource]:
        resources: List[IaCResource] = []
        docs = self._split_docs(content)
        for doc in docs:
            try:
                data = self._load_yaml(doc)
            except Exception:
                continue
            if not isinstance(data, dict):
                continue
            kind = data.get("kind", "Unknown")
            meta = data.get("metadata", {}) or {}
            name = meta.get("name", "unnamed")
            spec = data.get("spec", {}) or {}
            resources.append(
                IaCResource(
                    resource_type=kind,
                    resource_name=name,
                    provider="kubernetes",
                    properties={"spec": spec, "metadata": meta},
                    filename=filename,
                    line_number=0,
                )
            )
        return resources

    def _split_docs(self, content: str) -> List[str]:
        return [d for d in _RE_YAML_DOC_SEP.split(content) if d.strip()]

    def _load_yaml(self, content: str) -> Any:
        try:
            import yaml  # type: ignore
            return yaml.safe_load(content)
        except ImportError:
            pass
        # Minimal fallback
        result: Dict[str, Any] = {}
        for line in content.splitlines():
            m = _RE_YAML_KV.match(line)
            if m:
                result[m.group(1)] = m.group(2).strip()
        return result


class DockerfileParser:
    """Parse Dockerfile instructions."""

    _INSTRUCTION_RE = re.compile(
        r'^(FROM|RUN|CMD|ENTRYPOINT|ENV|COPY|ADD|USER|EXPOSE|HEALTHCHECK|ARG|WORKDIR|VOLUME|LABEL|STOPSIGNAL|ONBUILD|SHELL)\s+(.*)',
        re.IGNORECASE | re.MULTILINE,
    )

    def parse(self, content: str, filename: str) -> List[IaCResource]:
        instructions: Dict[str, List[str]] = {}
        lines_map: Dict[str, int] = {}
        for i, line in enumerate(content.splitlines(), 1):
            m = self._INSTRUCTION_RE.match(line.strip())
            if m:
                instr = m.group(1).upper()
                val = m.group(2).strip()
                instructions.setdefault(instr, []).append(val)
                if instr not in lines_map:
                    lines_map[instr] = i

        return [
            IaCResource(
                resource_type="Dockerfile",
                resource_name=Path(filename).name,
                provider="docker",
                properties={k: v for k, v in instructions.items()},
                filename=filename,
                line_number=1,
            )
        ]


class AnsibleParser:
    """Parse Ansible playbooks."""

    def parse(self, content: str, filename: str) -> List[IaCResource]:
        resources: List[IaCResource] = []
        try:
            import yaml  # type: ignore

            data = yaml.safe_load(content)
        except ImportError:
            return resources
        except Exception:
            return resources

        if not isinstance(data, list):
            return resources

        for play in data:
            if not isinstance(play, dict):
                continue
            name = play.get("name", "unnamed_play")
            tasks = play.get("tasks", []) or []
            resources.append(
                IaCResource(
                    resource_type="ansible_play",
                    resource_name=name,
                    provider="generic",
                    properties={"hosts": play.get("hosts", ""), "tasks": tasks, "vars": play.get("vars", {})},
                    filename=filename,
                    line_number=0,
                )
            )
        return resources


# ---------------------------------------------------------------------------
# Built-in security rules
# ---------------------------------------------------------------------------


@dataclass
class BuiltInRule:
    rule_id: str
    title: str
    description: str
    provider: str
    resource_types: List[str]
    severity: str
    tags: List[str]
    check_fn_name: str  # method name on IaCRuleEngine
    fix_what: str
    fix_why: str
    fix_how: str
    fix_snippet: str
    compliance: List[Dict[str, str]] = field(default_factory=list)


_BUILTIN_RULES: List[BuiltInRule] = [
    # ---- AWS S3 ----
    BuiltInRule(
        rule_id="AWS-S3-001",
        title="S3 Bucket Public Access Not Blocked",
        description="S3 bucket does not have public access block enabled, risking data exposure.",
        provider="aws", resource_types=["aws_s3_bucket", "AWS::S3::Bucket"],
        severity="critical", tags=["s3", "public-access", "data-exposure"],
        check_fn_name="check_s3_public_access",
        fix_what="Public access block is not configured or set to false.",
        fix_why="Public S3 buckets expose data to the internet and are a leading cause of data breaches.",
        fix_how="Enable all four public access block settings.",
        fix_snippet='block_public_acls       = true\nblock_public_policy     = true\nignore_public_acls      = true\nrestrict_public_buckets = true',
        compliance=[{"framework": "CIS AWS", "control": "2.1.5", "description": "Ensure S3 public access block"}],
    ),
    BuiltInRule(
        rule_id="AWS-S3-002",
        title="S3 Bucket Versioning Disabled",
        description="S3 bucket versioning is not enabled, preventing recovery from accidental deletion.",
        provider="aws", resource_types=["aws_s3_bucket", "AWS::S3::Bucket"],
        severity="medium", tags=["s3", "versioning", "data-protection"],
        check_fn_name="check_s3_versioning",
        fix_what="Versioning is not enabled on the bucket.",
        fix_why="Without versioning, deleted or overwritten objects cannot be recovered.",
        fix_how="Enable versioning in the bucket configuration.",
        fix_snippet='versioning {\n  enabled = true\n}',
        compliance=[{"framework": "CIS AWS", "control": "2.1.3", "description": "Ensure S3 versioning enabled"}],
    ),
    BuiltInRule(
        rule_id="AWS-S3-003",
        title="S3 Bucket Logging Disabled",
        description="Server access logging is not enabled for the S3 bucket.",
        provider="aws", resource_types=["aws_s3_bucket"],
        severity="medium", tags=["s3", "logging", "audit"],
        check_fn_name="check_s3_logging",
        fix_what="No logging configuration block found.",
        fix_why="Without access logs, you cannot audit who accessed or modified objects.",
        fix_how="Add a logging configuration block pointing to a log bucket.",
        fix_snippet='logging {\n  target_bucket = aws_s3_bucket.logs.id\n  target_prefix = "log/"\n}',
        compliance=[{"framework": "CIS AWS", "control": "2.1.1", "description": "Ensure S3 access logging"}],
    ),
    BuiltInRule(
        rule_id="AWS-S3-004",
        title="S3 Bucket Encryption Disabled",
        description="S3 bucket does not enforce server-side encryption.",
        provider="aws", resource_types=["aws_s3_bucket", "AWS::S3::Bucket"],
        severity="high", tags=["s3", "encryption", "data-protection"],
        check_fn_name="check_s3_encryption",
        fix_what="No server_side_encryption_configuration block present.",
        fix_why="Unencrypted buckets violate data-at-rest requirements and compliance mandates.",
        fix_how="Add SSE-S3 or SSE-KMS encryption configuration.",
        fix_snippet='server_side_encryption_configuration {\n  rule {\n    apply_server_side_encryption_by_default {\n      sse_algorithm = "aws:kms"\n    }\n  }\n}',
        compliance=[{"framework": "CIS AWS", "control": "2.1.2", "description": "Ensure S3 SSE"}],
    ),
    # ---- AWS Security Groups ----
    BuiltInRule(
        rule_id="AWS-SG-001",
        title="Security Group Allows Unrestricted Ingress (0.0.0.0/0)",
        description="Security group allows inbound traffic from any IP address.",
        provider="aws", resource_types=["aws_security_group", "aws_security_group_rule", "AWS::EC2::SecurityGroup"],
        severity="critical", tags=["security-group", "network", "unrestricted-ingress"],
        check_fn_name="check_sg_open_ingress",
        fix_what="Ingress rule with cidr_blocks = [\"0.0.0.0/0\"] found.",
        fix_why="Open ingress exposes services to the entire internet, enabling scanning and exploitation.",
        fix_how="Restrict CIDR blocks to known IP ranges or use security group references.",
        fix_snippet='ingress {\n  from_port   = 443\n  to_port     = 443\n  protocol    = "tcp"\n  cidr_blocks = ["10.0.0.0/8"]  # restrict to internal\n}',
        compliance=[
            {"framework": "CIS AWS", "control": "4.1", "description": "Restrict SSH from 0.0.0.0/0"},
            {"framework": "NIST 800-53", "control": "SC-7", "description": "Boundary protection"},
        ],
    ),
    BuiltInRule(
        rule_id="AWS-SG-002",
        title="Security Group Allows Unrestricted SSH",
        description="Security group allows SSH (port 22) from 0.0.0.0/0.",
        provider="aws", resource_types=["aws_security_group", "AWS::EC2::SecurityGroup"],
        severity="critical", tags=["security-group", "ssh", "network"],
        check_fn_name="check_sg_ssh_open",
        fix_what="SSH port 22 open to 0.0.0.0/0.",
        fix_why="Open SSH enables brute force and unauthorized access to instances.",
        fix_how="Restrict SSH to bastion host IP or use AWS Systems Manager Session Manager.",
        fix_snippet='ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["10.0.0.0/8"]  # bastion only\n}',
        compliance=[{"framework": "CIS AWS", "control": "4.1", "description": "No SSH from 0.0.0.0/0"}],
    ),
    BuiltInRule(
        rule_id="AWS-SG-003",
        title="Security Group Allows Unrestricted RDP",
        description="Security group allows RDP (port 3389) from 0.0.0.0/0.",
        provider="aws", resource_types=["aws_security_group", "AWS::EC2::SecurityGroup"],
        severity="critical", tags=["security-group", "rdp", "network"],
        check_fn_name="check_sg_rdp_open",
        fix_what="RDP port 3389 open to 0.0.0.0/0.",
        fix_why="Open RDP is frequently exploited for ransomware and lateral movement.",
        fix_how="Restrict RDP to known IPs or use VPN + SSM.",
        fix_snippet='ingress {\n  from_port   = 3389\n  to_port     = 3389\n  protocol    = "tcp"\n  cidr_blocks = ["10.0.0.0/8"]\n}',
        compliance=[{"framework": "CIS AWS", "control": "4.2", "description": "No RDP from 0.0.0.0/0"}],
    ),
    # ---- AWS EBS ----
    BuiltInRule(
        rule_id="AWS-EBS-001",
        title="EBS Volume Not Encrypted",
        description="EBS volume or snapshot does not have encryption enabled.",
        provider="aws", resource_types=["aws_ebs_volume", "aws_instance", "AWS::EC2::Volume"],
        severity="high", tags=["ebs", "encryption", "storage"],
        check_fn_name="check_ebs_encryption",
        fix_what="encrypted = false or not set on EBS volume.",
        fix_why="Unencrypted EBS volumes expose data if the underlying hardware is reused.",
        fix_how="Set encrypted = true and optionally specify a KMS key.",
        fix_snippet='resource "aws_ebs_volume" "example" {\n  availability_zone = "us-east-1a"\n  size              = 20\n  encrypted         = true\n  kms_key_id        = aws_kms_key.ebs.arn\n}',
        compliance=[{"framework": "CIS AWS", "control": "2.2.1", "description": "EBS encryption at rest"}],
    ),
    # ---- AWS IAM ----
    BuiltInRule(
        rule_id="AWS-IAM-001",
        title="IAM Policy Uses Wildcard Action (*)",
        description="IAM policy grants all actions (*) which is overly permissive.",
        provider="aws", resource_types=["aws_iam_policy", "aws_iam_role_policy", "AWS::IAM::Policy"],
        severity="critical", tags=["iam", "least-privilege", "wildcard"],
        check_fn_name="check_iam_wildcard_action",
        fix_what="Action: \"*\" found in IAM policy document.",
        fix_why="Wildcard actions violate least-privilege and enable privilege escalation.",
        fix_how="Enumerate only the specific actions required by the role.",
        fix_snippet='"Action": [\n  "s3:GetObject",\n  "s3:PutObject"\n]',
        compliance=[
            {"framework": "CIS AWS", "control": "1.16", "description": "No full admin IAM policies"},
            {"framework": "SOC 2", "control": "CC6.3", "description": "Least privilege access"},
        ],
    ),
    BuiltInRule(
        rule_id="AWS-IAM-002",
        title="IAM Policy Uses Wildcard Resource (*)",
        description="IAM policy applies to all resources (*) instead of specific ARNs.",
        provider="aws", resource_types=["aws_iam_policy", "aws_iam_role_policy"],
        severity="high", tags=["iam", "least-privilege", "wildcard"],
        check_fn_name="check_iam_wildcard_resource",
        fix_what="Resource: \"*\" combined with sensitive actions.",
        fix_why="Wildcard resources allow actions on any AWS resource in the account.",
        fix_how="Specify exact resource ARNs or use ARN conditions.",
        fix_snippet='"Resource": "arn:aws:s3:::my-bucket/*"',
        compliance=[{"framework": "CIS AWS", "control": "1.16", "description": "Least privilege IAM"}],
    ),
    BuiltInRule(
        rule_id="AWS-IAM-003",
        title="IAM Root Account Access Keys Active",
        description="Root account access keys are configured, which is a critical security risk.",
        provider="aws", resource_types=["aws_iam_access_key"],
        severity="critical", tags=["iam", "root", "access-keys"],
        check_fn_name="check_iam_root_keys",
        fix_what="aws_iam_access_key resource found (suggests root or overly privileged key).",
        fix_why="Root access keys cannot be scoped and provide full account access.",
        fix_how="Delete root access keys; use IAM roles with minimal permissions instead.",
        fix_snippet="# Remove access keys entirely and use IAM roles\n# aws iam delete-access-key --access-key-id <KEY_ID>",
        compliance=[{"framework": "CIS AWS", "control": "1.4", "description": "No root access keys"}],
    ),
    # ---- AWS CloudTrail ----
    BuiltInRule(
        rule_id="AWS-CT-001",
        title="CloudTrail Not Enabled",
        description="No CloudTrail trail is configured for the account.",
        provider="aws", resource_types=["aws_cloudtrail", "AWS::CloudTrail::Trail"],
        severity="high", tags=["cloudtrail", "logging", "audit"],
        check_fn_name="check_cloudtrail_enabled",
        fix_what="CloudTrail trail has is_logging = false or does not exist.",
        fix_why="Without CloudTrail, API calls cannot be audited or investigated post-incident.",
        fix_how="Enable CloudTrail with multi-region logging and log file validation.",
        fix_snippet='resource "aws_cloudtrail" "main" {\n  name                          = "main"\n  s3_bucket_name                = aws_s3_bucket.trail.id\n  include_global_service_events = true\n  is_multi_region_trail         = true\n  enable_log_file_validation    = true\n  is_logging                    = true\n}',
        compliance=[{"framework": "CIS AWS", "control": "3.1", "description": "CloudTrail enabled all regions"}],
    ),
    BuiltInRule(
        rule_id="AWS-CT-002",
        title="CloudTrail Log File Validation Disabled",
        description="CloudTrail does not validate log file integrity.",
        provider="aws", resource_types=["aws_cloudtrail", "AWS::CloudTrail::Trail"],
        severity="medium", tags=["cloudtrail", "integrity", "logging"],
        check_fn_name="check_cloudtrail_validation",
        fix_what="enable_log_file_validation = false.",
        fix_why="Without validation, log tampering cannot be detected.",
        fix_how="Enable log file validation.",
        fix_snippet='enable_log_file_validation = true',
        compliance=[{"framework": "CIS AWS", "control": "3.2", "description": "CloudTrail log validation"}],
    ),
    # ---- AWS RDS ----
    BuiltInRule(
        rule_id="AWS-RDS-001",
        title="RDS Instance Not Encrypted",
        description="RDS database instance does not have storage encryption enabled.",
        provider="aws", resource_types=["aws_db_instance", "AWS::RDS::DBInstance"],
        severity="high", tags=["rds", "encryption", "database"],
        check_fn_name="check_rds_encryption",
        fix_what="storage_encrypted = false or not set.",
        fix_why="Unencrypted databases violate PCI-DSS, HIPAA, and other compliance frameworks.",
        fix_how="Enable storage_encrypted = true (requires snapshot restore for existing instances).",
        fix_snippet='storage_encrypted   = true\nkms_key_id          = aws_kms_key.rds.arn',
        compliance=[
            {"framework": "PCI-DSS", "control": "3.4", "description": "Encrypt cardholder data"},
            {"framework": "HIPAA", "control": "164.312(a)(2)(iv)", "description": "Encryption at rest"},
        ],
    ),
    BuiltInRule(
        rule_id="AWS-RDS-002",
        title="RDS Instance Publicly Accessible",
        description="RDS instance is configured with publicly_accessible = true.",
        provider="aws", resource_types=["aws_db_instance"],
        severity="critical", tags=["rds", "public-access", "database"],
        check_fn_name="check_rds_public",
        fix_what="publicly_accessible = true on RDS instance.",
        fix_why="Publicly accessible databases are a primary attack vector for data exfiltration.",
        fix_how="Set publicly_accessible = false and use a VPC with private subnets.",
        fix_snippet='publicly_accessible = false',
        compliance=[{"framework": "CIS AWS", "control": "2.3.2", "description": "RDS not publicly accessible"}],
    ),
    # ---- AWS Lambda ----
    BuiltInRule(
        rule_id="AWS-LAMBDA-001",
        title="Lambda Function Has No Reserved Concurrency",
        description="Lambda function has no reserved concurrency, risking denial of service.",
        provider="aws", resource_types=["aws_lambda_function"],
        severity="low", tags=["lambda", "concurrency", "availability"],
        check_fn_name="check_lambda_concurrency",
        fix_what="No reserved_concurrent_executions set.",
        fix_why="Without limits, Lambda can exhaust account concurrency and starve other functions.",
        fix_how="Set reserved_concurrent_executions to a reasonable value.",
        fix_snippet='reserved_concurrent_executions = 100',
        compliance=[],
    ),
    # ---- Azure ----
    BuiltInRule(
        rule_id="AZ-STORAGE-001",
        title="Azure Storage Account Allows Public Access",
        description="Azure Storage Account has public blob access enabled.",
        provider="azure", resource_types=["azurerm_storage_account"],
        severity="critical", tags=["azure", "storage", "public-access"],
        check_fn_name="check_azure_storage_public",
        fix_what="allow_blob_public_access = true or enable_https_traffic_only = false.",
        fix_why="Public blob access exposes storage containers to unauthenticated reads.",
        fix_how="Disable public blob access and enforce HTTPS.",
        fix_snippet='allow_blob_public_access  = false\nenable_https_traffic_only = true\nmin_tls_version           = "TLS1_2"',
        compliance=[{"framework": "CIS Azure", "control": "3.5", "description": "Disable public blob access"}],
    ),
    BuiltInRule(
        rule_id="AZ-NSG-001",
        title="Azure NSG Allows Any-Any Inbound",
        description="Network Security Group has an allow-all inbound rule (*:*).",
        provider="azure", resource_types=["azurerm_network_security_group", "azurerm_network_security_rule"],
        severity="critical", tags=["azure", "nsg", "network"],
        check_fn_name="check_azure_nsg_any_any",
        fix_what="NSG rule with source=* and destination_port_range=* (or any) found.",
        fix_why="Any-any rules negate the purpose of network segmentation.",
        fix_how="Replace with explicit port/protocol rules for required traffic only.",
        fix_snippet='security_rule {\n  access                     = "Allow"\n  direction                  = "Inbound"\n  protocol                   = "Tcp"\n  source_port_range          = "*"\n  destination_port_range     = "443"\n  source_address_prefix      = "10.0.0.0/8"\n  destination_address_prefix = "*"\n  priority                   = 100\n}',
        compliance=[{"framework": "CIS Azure", "control": "6.1", "description": "NSG restrict inbound"}],
    ),
    BuiltInRule(
        rule_id="AZ-DISK-001",
        title="Azure Managed Disk Not Encrypted with CMK",
        description="Azure managed disk uses platform-managed key instead of customer-managed key.",
        provider="azure", resource_types=["azurerm_managed_disk"],
        severity="medium", tags=["azure", "disk", "encryption", "cmk"],
        check_fn_name="check_azure_disk_cmk",
        fix_what="disk_encryption_set_id not set on managed disk.",
        fix_why="CMK encryption provides additional control over key lifecycle and access.",
        fix_how="Create a DiskEncryptionSet and reference it.",
        fix_snippet='disk_encryption_set_id = azurerm_disk_encryption_set.main.id',
        compliance=[{"framework": "CIS Azure", "control": "7.2", "description": "CMK for managed disks"}],
    ),
    # ---- GCP ----
    BuiltInRule(
        rule_id="GCP-STORAGE-001",
        title="GCP Storage Bucket is Public",
        description="GCP storage bucket has allUsers or allAuthenticatedUsers IAM binding.",
        provider="gcp", resource_types=["google_storage_bucket", "google_storage_bucket_iam_member"],
        severity="critical", tags=["gcp", "storage", "public-access"],
        check_fn_name="check_gcp_bucket_public",
        fix_what="IAM member allUsers or allAuthenticatedUsers found on bucket.",
        fix_why="Public GCP buckets expose all objects to unauthenticated internet users.",
        fix_how="Remove allUsers bindings and use signed URLs for temporary access.",
        fix_snippet='# Remove public binding\n# gcloud storage buckets remove-iam-policy-binding gs://BUCKET\\\n#   --member=allUsers --role=roles/storage.objectViewer',
        compliance=[{"framework": "CIS GCP", "control": "5.1", "description": "No public GCS buckets"}],
    ),
    BuiltInRule(
        rule_id="GCP-FW-001",
        title="GCP Firewall Rule Allows 0.0.0.0/0",
        description="GCP firewall rule allows ingress from all IPs.",
        provider="gcp", resource_types=["google_compute_firewall"],
        severity="critical", tags=["gcp", "firewall", "network"],
        check_fn_name="check_gcp_firewall_open",
        fix_what="source_ranges = [\"0.0.0.0/0\"] on firewall ingress rule.",
        fix_why="Open firewall rules expose GCE instances to internet-wide scanning.",
        fix_how="Restrict source_ranges to known CIDRs or use IAP for SSH/RDP.",
        fix_snippet='source_ranges = ["10.0.0.0/8"]  # restrict to internal',
        compliance=[{"framework": "CIS GCP", "control": "3.6", "description": "No unrestricted firewall"}],
    ),
    BuiltInRule(
        rule_id="GCP-SQL-001",
        title="GCP Cloud SQL Instance Publicly Accessible",
        description="Cloud SQL has an authorized network with 0.0.0.0/0.",
        provider="gcp", resource_types=["google_sql_database_instance"],
        severity="critical", tags=["gcp", "cloudsql", "database"],
        check_fn_name="check_gcp_sql_public",
        fix_what="authorized_networks with value=\"0.0.0.0/0\" found.",
        fix_why="Public SQL access enables brute-force and credential stuffing attacks.",
        fix_how="Remove public authorized networks; use Cloud SQL Auth Proxy.",
        fix_snippet='ip_configuration {\n  ipv4_enabled    = false\n  private_network = google_compute_network.private.id\n}',
        compliance=[{"framework": "CIS GCP", "control": "6.2", "description": "Cloud SQL not public"}],
    ),
    # ---- Kubernetes ----
    BuiltInRule(
        rule_id="K8S-SEC-001",
        title="Container Running as Privileged",
        description="Container has privileged: true in its security context.",
        provider="kubernetes", resource_types=["Pod", "Deployment", "DaemonSet", "StatefulSet"],
        severity="critical", tags=["kubernetes", "privileged", "container-security"],
        check_fn_name="check_k8s_privileged",
        fix_what="securityContext.privileged = true found.",
        fix_why="Privileged containers have full host access and can escape container isolation.",
        fix_how="Set privileged: false and use specific capabilities instead.",
        fix_snippet='securityContext:\n  privileged: false\n  capabilities:\n    drop: ["ALL"]\n    add: ["NET_BIND_SERVICE"]',
        compliance=[
            {"framework": "CIS K8s", "control": "5.2.1", "description": "No privileged containers"},
            {"framework": "NSA K8s Hardening", "control": "Pod Security", "description": "Non-privileged pods"},
        ],
    ),
    BuiltInRule(
        rule_id="K8S-SEC-002",
        title="Container Has No Resource Limits",
        description="Container is missing CPU/memory limits, risking resource exhaustion.",
        provider="kubernetes", resource_types=["Pod", "Deployment", "DaemonSet", "StatefulSet"],
        severity="high", tags=["kubernetes", "resource-limits", "availability"],
        check_fn_name="check_k8s_resource_limits",
        fix_what="No resources.limits set on container.",
        fix_why="Containers without limits can consume all node resources, causing cluster instability.",
        fix_how="Define CPU and memory limits for each container.",
        fix_snippet='resources:\n  requests:\n    cpu: "100m"\n    memory: "128Mi"\n  limits:\n    cpu: "500m"\n    memory: "256Mi"',
        compliance=[{"framework": "CIS K8s", "control": "5.2.5", "description": "Resource limits set"}],
    ),
    BuiltInRule(
        rule_id="K8S-SEC-003",
        title="Pod Uses hostNetwork",
        description="Pod has hostNetwork: true, sharing the host network namespace.",
        provider="kubernetes", resource_types=["Pod", "Deployment", "DaemonSet"],
        severity="high", tags=["kubernetes", "hostnetwork", "network-isolation"],
        check_fn_name="check_k8s_host_network",
        fix_what="spec.hostNetwork = true found.",
        fix_why="hostNetwork breaks container network isolation and exposes host services.",
        fix_how="Set hostNetwork: false unless required for system-level DaemonSets.",
        fix_snippet='spec:\n  hostNetwork: false',
        compliance=[{"framework": "CIS K8s", "control": "5.2.4", "description": "No hostNetwork"}],
    ),
    BuiltInRule(
        rule_id="K8S-SEC-004",
        title="Container Allows Privilege Escalation",
        description="Container does not set allowPrivilegeEscalation: false.",
        provider="kubernetes", resource_types=["Pod", "Deployment", "DaemonSet", "StatefulSet"],
        severity="high", tags=["kubernetes", "privilege-escalation"],
        check_fn_name="check_k8s_priv_escalation",
        fix_what="allowPrivilegeEscalation not set to false.",
        fix_why="Without this, processes can gain more privileges than their parent.",
        fix_how="Explicitly set allowPrivilegeEscalation: false in securityContext.",
        fix_snippet='securityContext:\n  allowPrivilegeEscalation: false\n  runAsNonRoot: true',
        compliance=[{"framework": "CIS K8s", "control": "5.2.5", "description": "No privilege escalation"}],
    ),
    BuiltInRule(
        rule_id="K8S-SEC-005",
        title="Pod Does Not Use ReadOnlyRootFilesystem",
        description="Container filesystem is writable, enabling persistence attacks.",
        provider="kubernetes", resource_types=["Pod", "Deployment"],
        severity="medium", tags=["kubernetes", "filesystem", "immutability"],
        check_fn_name="check_k8s_readonly_root",
        fix_what="readOnlyRootFilesystem not set to true.",
        fix_why="Writable root filesystem enables attackers to modify binaries or add backdoors.",
        fix_how="Set readOnlyRootFilesystem: true and use emptyDir for writable paths.",
        fix_snippet='securityContext:\n  readOnlyRootFilesystem: true',
        compliance=[{"framework": "CIS K8s", "control": "5.2.6", "description": "Read-only root filesystem"}],
    ),
    BuiltInRule(
        rule_id="K8S-NET-001",
        title="No NetworkPolicy Defined",
        description="Namespace has no NetworkPolicy, allowing unrestricted pod-to-pod communication.",
        provider="kubernetes", resource_types=["Deployment", "StatefulSet"],
        severity="medium", tags=["kubernetes", "network-policy", "segmentation"],
        check_fn_name="check_k8s_network_policy",
        fix_what="No NetworkPolicy resource found in the manifest.",
        fix_why="Without network policies, any pod can communicate with any other pod.",
        fix_how="Define a NetworkPolicy with ingress/egress rules matching your pods.",
        fix_snippet='apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nspec:\n  podSelector:\n    matchLabels:\n      app: myapp\n  policyTypes: [Ingress, Egress]',
        compliance=[{"framework": "CIS K8s", "control": "5.3.2", "description": "Network policies configured"}],
    ),
    # ---- Docker ----
    BuiltInRule(
        rule_id="DOCKER-001",
        title="Dockerfile Runs as Root User",
        description="No USER instruction found; container runs as root by default.",
        provider="docker", resource_types=["Dockerfile"],
        severity="high", tags=["docker", "root", "least-privilege"],
        check_fn_name="check_docker_root_user",
        fix_what="No USER instruction or USER root found in Dockerfile.",
        fix_why="Running as root inside a container increases the impact of a container escape.",
        fix_how="Create a non-root user and switch to it.",
        fix_snippet='RUN groupadd -r appgroup && useradd -r -g appgroup appuser\nUSER appuser',
        compliance=[
            {"framework": "CIS Docker", "control": "4.1", "description": "Non-root container user"},
            {"framework": "NIST 800-190", "control": "4.3.3", "description": "Least privilege containers"},
        ],
    ),
    BuiltInRule(
        rule_id="DOCKER-002",
        title="Dockerfile Copies Sensitive Files",
        description="COPY or ADD instruction copies potentially sensitive files (*.pem, *.key, .env).",
        provider="docker", resource_types=["Dockerfile"],
        severity="critical", tags=["docker", "secrets", "sensitive-files"],
        check_fn_name="check_docker_secrets",
        fix_what="COPY/ADD instruction referencing .env, *.pem, *.key, credentials, or secrets.",
        fix_why="Secrets baked into Docker images are accessible to anyone with image access.",
        fix_how="Use Docker secrets, environment variables at runtime, or a vault solution.",
        fix_snippet='# Use build secrets (Docker BuildKit)\nRUN --mount=type=secret,id=mysecret cat /run/secrets/mysecret',
        compliance=[{"framework": "CIS Docker", "control": "4.9", "description": "No secrets in images"}],
    ),
    BuiltInRule(
        rule_id="DOCKER-003",
        title="Dockerfile Missing HEALTHCHECK",
        description="No HEALTHCHECK instruction defined in Dockerfile.",
        provider="docker", resource_types=["Dockerfile"],
        severity="low", tags=["docker", "healthcheck", "reliability"],
        check_fn_name="check_docker_healthcheck",
        fix_what="No HEALTHCHECK instruction present.",
        fix_why="Without a health check, orchestrators cannot detect unhealthy containers.",
        fix_how="Add a HEALTHCHECK instruction appropriate for your application.",
        fix_snippet='HEALTHCHECK --interval=30s --timeout=10s --retries=3 \\\n  CMD curl -f http://localhost:8080/health || exit 1',
        compliance=[],
    ),
    BuiltInRule(
        rule_id="DOCKER-004",
        title="Dockerfile Uses Latest Tag",
        description="FROM instruction uses :latest tag, preventing reproducible builds.",
        provider="docker", resource_types=["Dockerfile"],
        severity="medium", tags=["docker", "image-pinning", "supply-chain"],
        check_fn_name="check_docker_latest_tag",
        fix_what="FROM <image>:latest or FROM <image> without explicit tag.",
        fix_why=":latest can change unexpectedly, introducing unvetted dependencies.",
        fix_how="Pin to a specific version digest or tag.",
        fix_snippet='FROM python:3.12.3-slim-bookworm@sha256:abc123...',
        compliance=[{"framework": "NIST 800-190", "control": "4.1.1", "description": "Pin base image versions"}],
    ),
    BuiltInRule(
        rule_id="DOCKER-005",
        title="Dockerfile Runs apt-get Without --no-install-recommends",
        description="apt-get install without --no-install-recommends adds unnecessary packages.",
        provider="docker", resource_types=["Dockerfile"],
        severity="info", tags=["docker", "image-size", "best-practice"],
        check_fn_name="check_docker_apt_recommends",
        fix_what="RUN apt-get install without --no-install-recommends flag.",
        fix_why="Unnecessary packages increase attack surface and image size.",
        fix_how="Add --no-install-recommends to apt-get install commands.",
        fix_snippet='RUN apt-get update && apt-get install -y --no-install-recommends \\\n    curl \\\n  && rm -rf /var/lib/apt/lists/*',
        compliance=[],
    ),
    BuiltInRule(
        rule_id="DOCKER-006",
        title="Dockerfile Exposes Privileged Port",
        description="EXPOSE instruction uses a port below 1024 (privileged).",
        provider="docker", resource_types=["Dockerfile"],
        severity="medium", tags=["docker", "network", "privileged-port"],
        check_fn_name="check_docker_privileged_port",
        fix_what="EXPOSE <port> where port < 1024.",
        fix_why="Binding privileged ports typically requires root, increasing risk.",
        fix_how="Use a port >= 1024 and remap at runtime if needed.",
        fix_snippet='EXPOSE 8080',
        compliance=[],
    ),
    # ---- Generic / Secrets ----
    BuiltInRule(
        rule_id="GEN-SECRET-001",
        title="Hardcoded Secret or Password Detected",
        description="A password, API key, or secret appears to be hardcoded in the IaC file.",
        provider="generic", resource_types=["*"],
        severity="critical", tags=["secrets", "credentials", "hardcoded"],
        check_fn_name="check_hardcoded_secrets",
        fix_what="Literal secret value (password, key, token) found in configuration.",
        fix_why="Hardcoded credentials in IaC files are exposed in version control.",
        fix_how="Use a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault).",
        fix_snippet='# Reference secret from AWS Secrets Manager\npassword = data.aws_secretsmanager_secret_version.db_pass.secret_string',
        compliance=[
            {"framework": "CIS", "control": "Secrets Management", "description": "No plaintext secrets"},
            {"framework": "OWASP", "control": "A07:2021", "description": "Identification failures"},
        ],
    ),
]


# ---------------------------------------------------------------------------
# Rule engine — check functions
# ---------------------------------------------------------------------------


class IaCRuleEngine:
    """Executes built-in security rules against parsed IaC resources."""

    _OPEN_CIDRS = frozenset({"0.0.0.0/0", "::/0", "*"})
    _SECRET_PATTERNS = re.compile(
        r'(?i)(password|passwd|secret|api_key|apikey|token|private_key|access_key|auth_key)\s*[=:]\s*["\']?([A-Za-z0-9+/=_\-]{8,})["\']?'
    )
    _SENSITIVE_FILE_RE = re.compile(
        r'(?i)\.(pem|key|p12|pfx|crt|cer|env|secret|credentials|passwd|htpasswd)$|\b(credentials|secret|\.env)\b'
    )

    def check_s3_public_access(self, resource: IaCResource) -> Optional[Tuple[str, Any, Any]]:
        props = resource.properties
        block_keys = ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]
        if resource.resource_type == "AWS::S3::Bucket":
            pab = props.get("PublicAccessBlockConfiguration", {})
            if not pab:
                return ("PublicAccessBlockConfiguration", "missing", "required")
            for key in ["BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets"]:
                if pab.get(key) is not True:
                    return (f"PublicAccessBlockConfiguration.{key}", pab.get(key), True)
        else:
            for key in block_keys:
                if props.get(key) is not True:
                    return (key, props.get(key), True)
        return None

    def check_s3_versioning(self, resource: IaCResource) -> Optional[Tuple[str, Any, Any]]:
        props = resource.properties
        if resource.resource_type == "AWS::S3::Bucket":
            vc = props.get("VersioningConfiguration", {})
            if not vc or vc.get("Status") != "Enabled":
                return ("VersioningConfiguration.Status", vc.get("Status") if vc else "missing", "Enabled")
        else:
            versioning = props.get("versioning", {})
            if not versioning or versioning.get("enabled") is not True:
                return ("versioning.enabled", versioning, True)
        return None

    def check_s3_logging(self, resource: IaCResource) -> Optional[Tuple[str, Any, Any]]:
        if resource.resource_type != "aws_s3_bucket":
            return None
        if not resource.properties.get("logging"):
            return ("logging", "missing", "required")
        return None

    def check_s3_encryption(self, resource: IaCResource) -> Optional[Tuple[str, Any, Any]]:
        props = resource.properties
        if resource.resource_type == "AWS::S3::Bucket":
            enc = props.get("BucketEncryption")
            if not enc:
                return ("BucketEncryption", "missing", "required")
        else:
            enc = props.get("server_side_encryption_configuration")
            if not enc:
                return ("server_side_encryption_configuration", "missing", "required")
        return None

    def check_sg_open_ingress(self, resource: IaCResource) -> Optional[Tuple[str, Any, Any]]:
        ingress = resource.properties.get("ingress", [])
        # Terraform parser may return a single dict (nested block) or a list
        if isinstance(ingress, dict):
            ingress = [ingress]
        if isinstance(ingress, list):
            for rule in ingress:
                if isinstance(rule, dict):
                    cidrs = rule.get("cidr_blocks", [])
                    if isinstance(cidrs, list):
                        for c in cidrs:
                            if c in self._OPEN_CIDRS:
                                return ("ingress[].cidr_blocks", c, "restricted CIDR")
                    elif isinstance(cidrs, str) and cidrs in self._OPEN_CIDRS:
                        return ("ingress[].cidr_blocks", cidrs, "restricted CIDR")
        # CloudFormation
        sec_rules = resource.properties.get("SecurityGroupIngress", [])
        if isinstance(sec_rules, list):
            for rule in sec_rules:
                if isinstance(rule, dict):
                    cidr = rule.get("CidrIp", "") or rule.get("CidrIpv6", "")
                    if cidr in self._OPEN_CIDRS:
                        return ("SecurityGroupIngress[].CidrIp", cidr, "restricted CIDR")
        # Raw content scan for open CIDR in security group blocks
        raw = resource.raw_block or ""
        if "0.0.0.0/0" in raw or "::/0" in raw:
            return ("ingress[].cidr_blocks", "0.0.0.0/0", "restricted CIDR")
        return None

    def check_sg_ssh_open(self, resource: IaCResource) -> Optional[Tuple[str, Any, Any]]:
        return self._check_port_open(resource, 22)

    def check_sg_rdp_open(self, resource: IaCResource) -> Optional[Tuple[str, Any, Any]]:
        return self._check_port_open(resource, 3389)

    def _check_port_open(self, resource: IaCResource, port: int) -> Optional[Tuple[str, Any, Any]]:
        ingress = resource.properties.get("ingress", [])
        # Terraform parser may return a single dict (nested block) or a list
        if isinstance(ingress, dict):
            ingress = [ingress]
        if isinstance(ingress, list):
            for rule in ingress:
                if isinstance(rule, dict):
                    cidrs = rule.get("cidr_blocks", [])
                    from_p = rule.get("from_port", -1)
                    to_p = rule.get("to_port", -1)
                    try:
                        from_p = int(from_p)
                        to_p = int(to_p)
                    except (TypeError, ValueError):
                        continue
                    if from_p <= port <= to_p:
                        if isinstance(cidrs, list) and any(c in self._OPEN_CIDRS for c in cidrs):
                            return (f"ingress[].cidr_blocks (port {port})", "0.0.0.0/0", "restricted CIDR")
        # Raw content fallback for port + open CIDR in same block
        raw = resource.raw_block or ""
        if str(port) in raw and ("0.0.0.0/0" in raw or "::/0" in raw):
            return (f"ingress[].cidr_blocks (port {port})", "0.0.0.0/0", "restricted CIDR")
        return None

    def check_ebs_encryption(self, resource: IaCResource) -> Optional[Tuple[str, Any, Any]]:
        props = resource.properties
        if resource.resource_type == "AWS::EC2::Volume":
            if props.get("Encrypted") is not True:
                return ("Encrypted", props.get("Encrypted"), True)
        else:
            if props.get("encrypted") is not True:
                return ("encrypted", props.get("encrypted"), True)
        return None

    def check_iam_wildcard_action(self, resource: IaCResource) -> Optional[Tuple[str, Any, Any]]:
        policy_doc = resource.properties.get("policy") or resource.properties.get("PolicyDocument") or ""
        if isinstance(policy_doc, str):
            if '"Action": "*"' in policy_doc or '"Action":["*"]' in policy_doc or "Action = \"*\"" in policy_doc:
                return ("policy.Action", "*", "specific actions")
        elif isinstance(policy_doc, dict):
            for stmt in policy_doc.get("Statement", []):
                action = stmt.get("Action", "")
                if action == "*" or action == ["*"]:
                    return ("policy.Statement[].Action", "*", "specific actions")
        return None

    def check_iam_wildcard_resource(self, resource: IaCResource) -> Optional[Tuple[str, Any, Any]]:
        policy_doc = resource.properties.get("policy") or resource.properties.get("PolicyDocument") or ""
        if isinstance(policy_doc, dict):
            for stmt in policy_doc.get("Statement", []):
                res_val = stmt.get("Resource", "")
                action = stmt.get("Action", "")
                if res_val == "*" and action not in ("*", ["*"]):
                    return ("policy.Statement[].Resource", "*", "specific ARN")
        return None

    def check_iam_root_keys(self, resource: IaCResource) -> Optional[Tuple[str, Any, Any]]:
        # Flag any aws_iam_access_key as potentially dangerous
        return ("aws_iam_access_key", "present", "remove root access keys")

    def check_cloudtrail_enabled(self, resource: IaCResource) -> Optional[Tuple[str, Any, Any]]:
        props = resource.properties
        if resource.resource_type == "AWS::CloudTrail::Trail":
            if props.get("IsLogging") is not True:
                return ("IsLogging", props.get("IsLogging"), True)
        else:
            if props.get("is_logging") is not True:
                return ("is_logging", props.get("is_logging"), True)
        return None

    def check_cloudtrail_validation(self, resource: IaCResource) -> Optional[Tuple[str, Any, Any]]:
        props = resource.properties
        key = "EnableLogFileValidation" if resource.resource_type == "AWS::CloudTrail::Trail" else "enable_log_file_validation"
        if props.get(key) is not True:
            return (key, props.get(key), True)
        return None

    def check_rds_encryption(self, resource: IaCResource) -> Optional[Tuple[str, Any, Any]]:
        props = resource.properties
        key = "StorageEncrypted" if resource.resource_type.startswith("AWS::RDS") else "storage_encrypted"
        if props.get(key) is not True:
            return (key, props.get(key), True)
        return None

    def check_rds_public(self, resource: IaCResource) -> Optional[Tuple[str, Any, Any]]:
        if resource.properties.get("publicly_accessible") is True:
            return ("publicly_accessible", True, False)
        return None

    def check_lambda_concurrency(self, resource: IaCResource) -> Optional[Tuple[str, Any, Any]]:
        if resource.properties.get("reserved_concurrent_executions") is None:
            return ("reserved_concurrent_executions", "not set", "integer value")
        return None

    def check_azure_storage_public(self, resource: IaCResource) -> Optional[Tuple[str, Any, Any]]:
        props = resource.properties
        if props.get("allow_blob_public_access") is True:
            return ("allow_blob_public_access", True, False)
        if props.get("enable_https_traffic_only") is False:
            return ("enable_https_traffic_only", False, True)
        return None

    def check_azure_nsg_any_any(self, resource: IaCResource) -> Optional[Tuple[str, Any, Any]]:
        rules = resource.properties.get("security_rule", [])
        if isinstance(rules, list):
            for rule in rules:
                if isinstance(rule, dict):
                    src = rule.get("source_address_prefix", "")
                    dport = rule.get("destination_port_range", "")
                    access = rule.get("access", "").lower()
                    if access == "allow" and src == "*" and dport in ("*", "Any"):
                        return ("security_rule[].source_address_prefix", "*", "specific CIDR")
        return None

    def check_azure_disk_cmk(self, resource: IaCResource) -> Optional[Tuple[str, Any, Any]]:
        if not resource.properties.get("disk_encryption_set_id"):
            return ("disk_encryption_set_id", "not set", "DiskEncryptionSet ID")
        return None

    def check_gcp_bucket_public(self, resource: IaCResource) -> Optional[Tuple[str, Any, Any]]:
        member = resource.properties.get("member", "")
        if member in ("allUsers", "allAuthenticatedUsers"):
            return ("member", member, "specific service account")
        # Also check uniform bucket-level access
        ub = resource.properties.get("uniform_bucket_level_access", None)
        if ub is False:
            return ("uniform_bucket_level_access", False, True)
        return None

    def check_gcp_firewall_open(self, resource: IaCResource) -> Optional[Tuple[str, Any, Any]]:
        source_ranges = resource.properties.get("source_ranges", [])
        if isinstance(source_ranges, list) and any(r in self._OPEN_CIDRS for r in source_ranges):
            return ("source_ranges", "0.0.0.0/0", "restricted CIDR")
        return None

    def check_gcp_sql_public(self, resource: IaCResource) -> Optional[Tuple[str, Any, Any]]:
        ip_config = resource.properties.get("ip_configuration", {}) or resource.properties.get("settings", {})
        if isinstance(ip_config, dict):
            auth_nets = ip_config.get("authorized_networks", [])
            if isinstance(auth_nets, list):
                for net in auth_nets:
                    if isinstance(net, dict) and net.get("value") in self._OPEN_CIDRS:
                        return ("ip_configuration.authorized_networks[].value", "0.0.0.0/0", "private network")
        return None

    def check_k8s_privileged(self, resource: IaCResource) -> Optional[Tuple[str, Any, Any]]:
        containers = self._get_k8s_containers(resource)
        for c in containers:
            sc = c.get("securityContext", {}) or {}
            if sc.get("privileged") is True:
                return ("spec.containers[].securityContext.privileged", True, False)
        return None

    def check_k8s_resource_limits(self, resource: IaCResource) -> Optional[Tuple[str, Any, Any]]:
        containers = self._get_k8s_containers(resource)
        for c in containers:
            resources_def = c.get("resources", {}) or {}
            if not resources_def.get("limits"):
                return ("spec.containers[].resources.limits", "not set", "cpu+memory limits required")
        return None

    def check_k8s_host_network(self, resource: IaCResource) -> Optional[Tuple[str, Any, Any]]:
        spec = resource.properties.get("spec", {}) or {}
        # For Deployment/DaemonSet, spec is nested
        pod_spec = spec.get("template", {}).get("spec", spec) if "template" in spec else spec
        if pod_spec.get("hostNetwork") is True:
            return ("spec.hostNetwork", True, False)
        return None

    def check_k8s_priv_escalation(self, resource: IaCResource) -> Optional[Tuple[str, Any, Any]]:
        containers = self._get_k8s_containers(resource)
        for c in containers:
            sc = c.get("securityContext", {}) or {}
            if sc.get("allowPrivilegeEscalation") is not False:
                return ("spec.containers[].securityContext.allowPrivilegeEscalation", sc.get("allowPrivilegeEscalation"), False)
        return None

    def check_k8s_readonly_root(self, resource: IaCResource) -> Optional[Tuple[str, Any, Any]]:
        containers = self._get_k8s_containers(resource)
        for c in containers:
            sc = c.get("securityContext", {}) or {}
            if sc.get("readOnlyRootFilesystem") is not True:
                return ("spec.containers[].securityContext.readOnlyRootFilesystem", sc.get("readOnlyRootFilesystem"), True)
        return None

    def check_k8s_network_policy(self, resource: IaCResource) -> Optional[Tuple[str, Any, Any]]:
        # This is a meta-check; we flag when no NetworkPolicy is present in the manifest
        # The scanner collects resource types and checks post-scan
        return None  # handled at scan level

    def check_docker_root_user(self, resource: IaCResource) -> Optional[Tuple[str, Any, Any]]:
        users = resource.properties.get("USER", [])
        if not users:
            return ("USER", "not set", "non-root user")
        for u in users:
            if str(u).lower() in ("root", "0"):
                return ("USER", u, "non-root user")
        return None

    def check_docker_secrets(self, resource: IaCResource) -> Optional[Tuple[str, Any, Any]]:
        for instr in ("COPY", "ADD"):
            for val in resource.properties.get(instr, []):
                if self._SENSITIVE_FILE_RE.search(str(val)):
                    return (instr, val, "use Docker secrets or runtime env vars")
        return None

    def check_docker_healthcheck(self, resource: IaCResource) -> Optional[Tuple[str, Any, Any]]:
        if not resource.properties.get("HEALTHCHECK"):
            return ("HEALTHCHECK", "not set", "HEALTHCHECK instruction required")
        return None

    def check_docker_latest_tag(self, resource: IaCResource) -> Optional[Tuple[str, Any, Any]]:
        froms = resource.properties.get("FROM", [])
        for f in froms:
            image = str(f).split(" ")[0]  # handle multi-stage aliases
            if ":" not in image or image.endswith(":latest"):
                return ("FROM", image, "pinned version tag or digest")
        return None

    def check_docker_apt_recommends(self, resource: IaCResource) -> Optional[Tuple[str, Any, Any]]:
        for run in resource.properties.get("RUN", []):
            if "apt-get install" in str(run) and "--no-install-recommends" not in str(run):
                return ("RUN", "apt-get install without --no-install-recommends", "--no-install-recommends")
        return None

    def check_docker_privileged_port(self, resource: IaCResource) -> Optional[Tuple[str, Any, Any]]:
        for port_str in resource.properties.get("EXPOSE", []):
            try:
                port = int(str(port_str).split("/")[0])
                if port < 1024:
                    return ("EXPOSE", port, ">= 1024")
            except (ValueError, TypeError):
                continue
        return None

    def check_hardcoded_secrets(self, resource: IaCResource) -> Optional[Tuple[str, Any, Any]]:
        raw = resource.raw_block or str(resource.properties)
        m = self._SECRET_PATTERNS.search(raw)
        if m:
            key_name = m.group(1)
            # Mask the value
            return (key_name, "<redacted>", "secrets manager reference")
        return None

    def _get_k8s_containers(self, resource: IaCResource) -> List[Dict[str, Any]]:
        spec = resource.properties.get("spec", {}) or {}
        # Deployment/DaemonSet/StatefulSet have template.spec.containers
        pod_spec = spec.get("template", {}).get("spec", {}) if "template" in spec else spec
        containers = pod_spec.get("containers", []) or []
        init_containers = pod_spec.get("initContainers", []) or []
        return [c for c in containers + init_containers if isinstance(c, dict)]


# ---------------------------------------------------------------------------
# Custom rule evaluator
# ---------------------------------------------------------------------------


def _get_nested(data: Any, path: str) -> Any:
    """Traverse dot-notation path into a nested dict."""
    parts = path.split(".")
    current = data
    for part in parts:
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def evaluate_custom_rule(rule: "CustomRule", resource: "IaCResource") -> Optional[Tuple[str, Any, Any]]:
    """Evaluate a custom YAML-defined rule against a resource."""
    # Check resource type match (* = any)
    if rule.resource_type != "*" and rule.resource_type != resource.resource_type:
        return None

    actual = _get_nested(resource.properties, rule.property_path)
    expected = rule.expected_value
    op = rule.operator

    if op == "exists":
        if actual is None:
            return (rule.property_path, "missing", "present")
    elif op == "not_exists":
        if actual is not None:
            return (rule.property_path, actual, "absent")
    elif op == "equals":
        if actual != expected:
            return (rule.property_path, actual, expected)
    elif op == "not_equals":
        if actual == expected:
            return (rule.property_path, actual, f"not {expected}")
    elif op == "contains":
        if expected not in str(actual or ""):
            return (rule.property_path, actual, f"contains '{expected}'")
    elif op == "not_contains":
        if expected in str(actual or ""):
            return (rule.property_path, actual, f"does not contain '{expected}'")
    return None


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------


class IaCScannerEngine:
    """Main IaC security scanner engine.

    Thread-safe. Maintains in-memory store of findings and custom rules.
    """

    def __init__(self) -> None:
        self._lock = Lock()
        self._findings: Dict[str, IaCFinding] = {}   # finding_id -> IaCFinding
        self._custom_rules: Dict[str, "CustomRule"] = {}  # rule_id -> CustomRule
        self._drift_results: Dict[str, "DriftResult"] = {}
        self._baselines: Dict[str, Dict] = {}  # baseline_id -> snapshot record
        self._rule_engine = IaCRuleEngine()
        self._tf_parser = TerraformParser()
        self._cfn_parser = CloudFormationParser()
        self._k8s_parser = KubernetesParser()
        self._docker_parser = DockerfileParser()
        self._ansible_parser = AnsibleParser()
        self._builtin_rules: Dict[str, BuiltInRule] = {r.rule_id: r for r in _BUILTIN_RULES}
        logger.info("iac_scanner_engine_initialized", builtin_rules=len(_BUILTIN_RULES))

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------

    def scan_content(self, content: str, filename: str, scan_id: Optional[str] = None) -> ScanResult:
        """Scan IaC content and return a ScanResult with all findings."""
        t0 = time.time()
        scan_id = scan_id or str(uuid.uuid4())
        fmt = detect_iac_format(filename, content)
        resources = self._parse(content, filename, fmt)

        findings: List[IaCFinding] = []
        findings.extend(self._run_builtin_rules(resources, scan_id, filename))
        findings.extend(self._run_custom_rules(resources, scan_id, filename))

        # Store findings
        with self._lock:
            for f in findings:
                self._findings[f.finding_id] = f

        provider = self._infer_provider(fmt, resources)
        duration_ms = (time.time() - t0) * 1000

        logger.info(
            "iac_scan_complete",
            scan_id=scan_id,
            filename=filename,
            fmt=fmt.value,
            resources=len(resources),
            findings=len(findings),
            duration_ms=round(duration_ms, 2),
        )

        _emit_event("iac.scan.completed", {
            "scan_id": scan_id,
            "filename": filename,
            "iac_format": fmt.value,
            "resources_found": len(resources),
            "findings_count": len(findings),
            "duration_ms": round(duration_ms, 2),
        })

        return ScanResult(
            scan_id=scan_id,
            filename=filename,
            iac_format=fmt.value,
            provider=provider,
            resources_found=len(resources),
            findings=findings,
            scanned_at=datetime.now(timezone.utc).isoformat(),
            duration_ms=round(duration_ms, 2),
        )

    def scan_path(self, path: str) -> List[ScanResult]:
        """Recursively scan all IaC files in a directory."""
        results: List[ScanResult] = []
        p = Path(path)
        if p.is_file():
            content = p.read_text(errors="replace")
            results.append(self.scan_content(content, str(p)))
            return results

        extensions = {".tf", ".tfvars", ".json", ".yml", ".yaml"}
        for fpath in p.rglob("*"):
            if fpath.is_file() and (fpath.suffix.lower() in extensions or fpath.name.lower().startswith("dockerfile")):
                try:
                    content = fpath.read_text(errors="replace")
                    results.append(self.scan_content(content, str(fpath)))
                except Exception as exc:
                    logger.warning("iac_scan_file_error", path=str(fpath), error=str(exc))
        return results

    # ------------------------------------------------------------------
    # Findings store
    # ------------------------------------------------------------------

    def get_findings(
        self,
        provider: Optional[str] = None,
        severity: Optional[str] = None,
        rule_id: Optional[str] = None,
    ) -> List[IaCFinding]:
        with self._lock:
            findings = list(self._findings.values())
        if provider:
            findings = [f for f in findings if f.provider == provider]
        if severity:
            findings = [f for f in findings if f.severity == severity]
        if rule_id:
            findings = [f for f in findings if f.rule_id == rule_id]
        return findings

    def clear_findings(self) -> None:
        with self._lock:
            self._findings.clear()

    # ------------------------------------------------------------------
    # Rules management
    # ------------------------------------------------------------------

    def list_rules(
        self,
        provider: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return builtin + custom rules as dicts."""
        rules: List[Dict[str, Any]] = []
        for r in self._builtin_rules.values():
            if provider and r.provider != provider:
                continue
            if severity and r.severity != severity:
                continue
            rules.append({
                "rule_id": r.rule_id,
                "title": r.title,
                "description": r.description,
                "provider": r.provider,
                "severity": r.severity,
                "tags": r.tags,
                "type": "builtin",
            })
        with self._lock:
            custom = list(self._custom_rules.values())
        for r in custom:
            if provider and r.provider != provider:
                continue
            if severity and r.severity != severity:
                continue
            d = r.dict() if hasattr(r, "dict") else r.__dict__
            d["type"] = "custom"
            rules.append(d)
        return rules

    def add_custom_rule(self, rule: "CustomRule") -> None:
        with self._lock:
            self._custom_rules[rule.rule_id] = rule
        logger.info("iac_custom_rule_added", rule_id=rule.rule_id)

    # ------------------------------------------------------------------
    # Drift detection (stubs — real impl would call cloud APIs)
    # ------------------------------------------------------------------

    def detect_drift(
        self,
        iac_resources: List["IaCResource"],
        cloud_state: Optional[Dict[str, Any]] = None,
    ) -> List["DriftResult"]:
        """Compare IaC definitions against cloud state (stub).

        In production, cloud_state would be fetched from AWS Config, Azure Resource Graph, etc.
        """
        results: List[DriftResult] = []
        cloud_state = cloud_state or {}
        now = datetime.now(timezone.utc).isoformat()

        iac_ids = {r.resource_name for r in iac_resources}
        cloud_ids = set(cloud_state.keys())

        # Resources in code but not in cloud
        for r in iac_resources:
            if r.resource_name not in cloud_ids:
                dr = DriftResult(
                    resource_id=r.resource_name,
                    resource_type=r.resource_type,
                    status=DriftStatus.MISSING_IN_CLOUD.value,
                    iac_value=r.properties,
                    cloud_value=None,
                    detected_at=now,
                )
                results.append(dr)
            else:
                cloud_props = cloud_state[r.resource_name]
                mismatches = self._diff_properties(r.properties, cloud_props)
                if mismatches:
                    for path, iac_val, cloud_val in mismatches:
                        dr = DriftResult(
                            resource_id=r.resource_name,
                            resource_type=r.resource_type,
                            status=DriftStatus.PROPERTY_MISMATCH.value,
                            iac_value=iac_val,
                            cloud_value=cloud_val,
                            property_path=path,
                            detected_at=now,
                )
                        results.append(dr)
                else:
                    results.append(DriftResult(
                        resource_id=r.resource_name,
                        resource_type=r.resource_type,
                        status=DriftStatus.IN_SYNC.value,
                        detected_at=now,
                    ))

        # Resources in cloud but not in code
        for cloud_id in cloud_ids - iac_ids:
            results.append(DriftResult(
                resource_id=cloud_id,
                resource_type=cloud_state[cloud_id].get("type", "unknown"),
                status=DriftStatus.MISSING_IN_CODE.value,
                cloud_value=cloud_state[cloud_id],
                detected_at=now,
            ))

        with self._lock:
            for dr in results:
                key = f"{dr.resource_id}:{dr.property_path}"
                self._drift_results[key] = dr

        return results

    def get_drift_results(self) -> List["DriftResult"]:
        with self._lock:
            return list(self._drift_results.values())

    # ------------------------------------------------------------------
    # Baseline snapshots
    # ------------------------------------------------------------------

    def create_baseline_snapshot(
        self,
        name: str,
        description: str = "",
        org_id: str = "default",
    ) -> Dict[str, Any]:
        """Snapshot current findings as a named IaC baseline.

        Captures the current set of findings (by severity / provider counts)
        plus the full finding IDs so callers can compare future scans against
        this known-good (or known-state) point in time.
        """
        import uuid as _uuid
        from datetime import datetime, timezone

        with self._lock:
            findings = list(self._findings.values())
            baseline_id = str(_uuid.uuid4())
            now = datetime.now(timezone.utc).isoformat()

            severity_counts: Dict[str, int] = {}
            provider_counts: Dict[str, int] = {}
            finding_ids: List[str] = []

            for f in findings:
                sev = getattr(f, "severity", None)
                sev_val = sev.value if hasattr(sev, "value") else str(sev)
                severity_counts[sev_val] = severity_counts.get(sev_val, 0) + 1

                prov = getattr(f, "provider", None)
                prov_val = prov.value if hasattr(prov, "value") else str(prov)
                provider_counts[prov_val] = provider_counts.get(prov_val, 0) + 1

                fid = getattr(f, "finding_id", None) or getattr(f, "id", None)
                if fid:
                    finding_ids.append(fid)

            record: Dict[str, Any] = {
                "id": baseline_id,
                "org_id": org_id,
                "name": name,
                "description": description,
                "total_findings": len(findings),
                "severity_counts": severity_counts,
                "provider_counts": provider_counts,
                "finding_ids": finding_ids,
                "created_at": now,
            }
            self._baselines[baseline_id] = record

        logger.info(
            "iac_baseline_snapshot_created",
            baseline_id=baseline_id,
            total_findings=len(findings),
        )
        return record

    def get_baseline_snapshot(self, baseline_id: str) -> Optional[Dict[str, Any]]:
        """Return a previously created baseline snapshot by ID."""
        with self._lock:
            return self._baselines.get(baseline_id)

    def list_baseline_snapshots(self, org_id: str = "default") -> List[Dict[str, Any]]:
        """List all baseline snapshots, optionally filtered by org_id."""
        with self._lock:
            return [
                b for b in self._baselines.values()
                if b.get("org_id") == org_id
            ]

    # ------------------------------------------------------------------
    # Summary stats
    # ------------------------------------------------------------------

    def get_summary(self) -> Dict[str, Any]:
        with self._lock:
            findings = list(self._findings.values())

        by_severity: Dict[str, int] = {}
        by_provider: Dict[str, int] = {}
        by_rule: Dict[str, int] = {}

        for f in findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            by_provider[f.provider] = by_provider.get(f.provider, 0) + 1
            by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1

        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("FINDING_CREATED", {"entity_type": "iac_scanner_engine", "org_id": "unknown", "source_engine": "iac_scanner_engine"})
            except Exception:
                pass
        return {
            "total_findings": len(findings),
            "by_severity": by_severity,
            "by_provider": by_provider,
            "by_rule": by_rule,
            "builtin_rules": len(self._builtin_rules),
            "custom_rules": len(self._custom_rules),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse(self, content: str, filename: str, fmt: IaCFormat) -> List[IaCResource]:
        try:
            if fmt == IaCFormat.TERRAFORM:
                return self._tf_parser.parse(content, filename)
            if fmt == IaCFormat.CLOUDFORMATION:
                return self._cfn_parser.parse(content, filename)
            if fmt in (IaCFormat.KUBERNETES, IaCFormat.HELM):
                return self._k8s_parser.parse(content, filename)
            if fmt == IaCFormat.DOCKERFILE:
                return self._docker_parser.parse(content, filename)
            if fmt == IaCFormat.ANSIBLE:
                return self._ansible_parser.parse(content, filename)
        except Exception as exc:
            logger.warning("iac_parse_error", filename=filename, fmt=fmt.value, error=str(exc))
        return []

    def _run_builtin_rules(
        self, resources: List[IaCResource], scan_id: str, filename: str
    ) -> List[IaCFinding]:
        findings: List[IaCFinding] = []
        for rule in self._builtin_rules.values():
            for resource in resources:
                # Resource type match — wildcard * or specific type
                if rule.resource_types != ["*"] and resource.resource_type not in rule.resource_types:
                    continue
                check_fn = getattr(self._rule_engine, rule.check_fn_name, None)
                if check_fn is None:
                    continue
                try:
                    result = check_fn(resource)
                except Exception as exc:
                    logger.debug("iac_rule_check_error", rule_id=rule.rule_id, error=str(exc))
                    continue
                if result is not None:
                    prop_path, actual, expected = result
                    findings.append(self._make_finding(rule, resource, prop_path, actual, expected, scan_id))
        return findings

    def _run_custom_rules(
        self, resources: List[IaCResource], scan_id: str, filename: str
    ) -> List[IaCFinding]:
        findings: List[IaCFinding] = []
        with self._lock:
            custom_rules = list(self._custom_rules.values())
        for rule in custom_rules:
            if not rule.enabled:
                continue
            for resource in resources:
                result = evaluate_custom_rule(rule, resource)
                if result is not None:
                    prop_path, actual, expected = result
                    findings.append(self._make_custom_finding(rule, resource, prop_path, actual, expected, scan_id))
        return findings

    def _make_finding(
        self,
        rule: BuiltInRule,
        resource: IaCResource,
        prop_path: str,
        actual: Any,
        expected: Any,
        scan_id: str,
    ) -> IaCFinding:
        fid = hashlib.sha256(
            f"{rule.rule_id}:{resource.filename}:{resource.resource_name}:{prop_path}".encode()
        ).hexdigest()[:16]

        compliance_refs = [
            ComplianceRef(
                framework=c["framework"],
                control=c["control"],
                description=c.get("description", ""),
            )
            for c in rule.compliance
        ]

        fix = FixSuggestion(
            what_is_wrong=rule.fix_what,
            why_it_matters=rule.fix_why,
            how_to_fix=rule.fix_how,
            fix_snippet=rule.fix_snippet,
            compliance_violations=compliance_refs,
        )

        return IaCFinding(
            finding_id=fid,
            rule_id=rule.rule_id,
            title=rule.title,
            description=rule.description,
            severity=rule.severity,
            provider=rule.provider,
            resource_type=resource.resource_type,
            resource_name=resource.resource_name,
            filename=resource.filename,
            line_number=resource.line_number,
            property_path=prop_path,
            actual_value=actual,
            expected_value=expected,
            fix=fix,
            tags=rule.tags,
            scan_id=scan_id,
            detected_at=datetime.now(timezone.utc).isoformat(),
        )

    def _make_custom_finding(
        self,
        rule: "CustomRule",
        resource: IaCResource,
        prop_path: str,
        actual: Any,
        expected: Any,
        scan_id: str,
    ) -> IaCFinding:
        fid = hashlib.sha256(
            f"{rule.rule_id}:{resource.filename}:{resource.resource_name}:{prop_path}".encode()
        ).hexdigest()[:16]

        compliance_refs = [
            ComplianceRef(
                framework=c.get("framework", ""),
                control=c.get("control", ""),
                description=c.get("description", ""),
            )
            for c in rule.compliance
        ]

        fix = FixSuggestion(
            what_is_wrong=f"{prop_path} is {actual!r}, expected {expected!r}.",
            why_it_matters=rule.description,
            how_to_fix=rule.fix_description or f"Set {prop_path} to {expected!r}.",
            fix_snippet=rule.fix_snippet or f"{prop_path} = {expected!r}",
            compliance_violations=compliance_refs,
        )

        return IaCFinding(
            finding_id=fid,
            rule_id=rule.rule_id,
            title=rule.name,
            description=rule.description,
            severity=rule.severity,
            provider=rule.provider,
            resource_type=resource.resource_type,
            resource_name=resource.resource_name,
            filename=resource.filename,
            line_number=resource.line_number,
            property_path=prop_path,
            actual_value=actual,
            expected_value=expected,
            fix=fix,
            tags=[],
            scan_id=scan_id,
            detected_at=datetime.now(timezone.utc).isoformat(),
        )

    def _infer_provider(self, fmt: IaCFormat, resources: List[IaCResource]) -> str:
        if fmt == IaCFormat.DOCKERFILE:
            return "docker"
        if fmt in (IaCFormat.KUBERNETES, IaCFormat.HELM):
            return "kubernetes"
        if fmt == IaCFormat.ANSIBLE:
            return "generic"
        providers = [r.provider for r in resources if r.provider]
        if providers:
            return max(set(providers), key=providers.count)
        return "generic"

    def _diff_properties(
        self, iac: Dict[str, Any], cloud: Dict[str, Any], prefix: str = ""
    ) -> List[Tuple[str, Any, Any]]:
        diffs: List[Tuple[str, Any, Any]] = []
        all_keys = set(iac.keys()) | set(cloud.keys())
        for k in all_keys:
            path = f"{prefix}.{k}" if prefix else k
            iac_val = iac.get(k)
            cloud_val = cloud.get(k)
            if isinstance(iac_val, dict) and isinstance(cloud_val, dict):
                diffs.extend(self._diff_properties(iac_val, cloud_val, path))
            elif iac_val != cloud_val:
                diffs.append((path, iac_val, cloud_val))
        return diffs


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_engine: Optional[IaCScannerEngine] = None
_engine_lock = Lock()


def get_iac_scanner() -> IaCScannerEngine:
    global _engine
    if _engine is None:
        with _engine_lock:
            if _engine is None:
                _engine = IaCScannerEngine()
    return _engine
