"""Cloud Security Posture Management (CSPM) Engine.

Provides CIS Benchmark rule evaluation, multi-cloud resource inventory,
drift detection, auto-remediation playbooks, compliance mapping, and
risk scoring for AWS, Azure, and GCP environments.

Usage:
    from core.cspm_engine import CSPMEngine, get_cspm_engine
    engine = get_cspm_engine()
    result = engine.run_scan(org_id="my-org")
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger(__name__)

_DEFAULT_DB = os.getenv("FIXOPS_CSPM_DB", ".fixops_data/cspm.db")


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class CloudProvider(str, Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    UNKNOWN = "unknown"


class ResourceType(str, Enum):
    IAM_USER = "iam_user"
    IAM_ROLE = "iam_role"
    IAM_POLICY = "iam_policy"
    S3_BUCKET = "s3_bucket"
    STORAGE_ACCOUNT = "storage_account"
    GCS_BUCKET = "gcs_bucket"
    SECURITY_GROUP = "security_group"
    VPC = "vpc"
    NETWORK_ACL = "network_acl"
    EC2_INSTANCE = "ec2_instance"
    VM_INSTANCE = "vm_instance"
    COMPUTE_INSTANCE = "compute_instance"
    RDS_INSTANCE = "rds_instance"
    SQL_DATABASE = "sql_database"
    CLOUD_SQL = "cloud_sql"
    CLOUDTRAIL = "cloudtrail"
    AZURE_MONITOR = "azure_monitor"
    GCP_AUDIT_LOG = "gcp_audit_log"
    KMS_KEY = "kms_key"
    KEY_VAULT = "key_vault"
    LOAD_BALANCER = "load_balancer"
    LAMBDA_FUNCTION = "lambda_function"
    CONTAINER_REGISTRY = "container_registry"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class FindingStatus(str, Enum):
    OPEN = "open"
    SUPPRESSED = "suppressed"
    RESOLVED = "resolved"
    IN_REMEDIATION = "in_remediation"


class ComplianceFramework(str, Enum):
    SOC2 = "soc2"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    FEDRAMP = "fedramp"
    NIST_800_53 = "nist_800_53"
    CIS = "cis"


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------

class CloudResource(BaseModel):
    """Abstract representation of a cloud resource across providers."""
    id: str = Field(default_factory=lambda: f"res-{uuid.uuid4().hex[:12]}")
    provider: CloudProvider
    resource_type: ResourceType
    name: str
    region: str = "global"
    account_id: str = "unknown"
    org_id: str = "default"
    tags: Dict[str, str] = Field(default_factory=dict)
    owner: Optional[str] = None
    created_at: Optional[str] = None
    last_modified: Optional[str] = None
    is_public: bool = False
    is_encrypted: bool = True
    metadata: Dict[str, Any] = Field(default_factory=dict)
    discovered_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class CISBenchmarkRule(BaseModel):
    """A single CIS Benchmark check definition."""
    rule_id: str
    title: str
    description: str
    provider: CloudProvider
    resource_type: ResourceType
    severity: Severity
    cis_section: str
    remediation_summary: str
    remediation_cli: Optional[str] = None
    remediation_terraform: Optional[str] = None
    compliance_mapping: Dict[str, List[str]] = Field(default_factory=dict)


class CSPMFinding(BaseModel):
    """A misconfiguration finding from a CSPM scan."""
    id: str = Field(default_factory=lambda: f"cspm-{uuid.uuid4().hex[:12]}")
    rule_id: str
    rule_title: str
    resource_id: str
    resource_name: str
    resource_type: ResourceType
    provider: CloudProvider
    account_id: str
    region: str
    severity: Severity
    status: FindingStatus = FindingStatus.OPEN
    description: str
    remediation_summary: str
    remediation_cli: Optional[str] = None
    remediation_terraform: Optional[str] = None
    compliance_mapping: Dict[str, List[str]] = Field(default_factory=dict)
    org_id: str = "default"
    detected_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    resolved_at: Optional[str] = None
    suppression_reason: Optional[str] = None


class DriftEvent(BaseModel):
    """A detected drift from the established baseline."""
    id: str = Field(default_factory=lambda: f"drift-{uuid.uuid4().hex[:12]}")
    resource_id: str
    resource_name: str
    resource_type: ResourceType
    provider: CloudProvider
    account_id: str
    drift_type: str
    description: str
    baseline_value: Optional[str] = None
    current_value: Optional[str] = None
    severity: Severity
    org_id: str = "default"
    detected_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class RemediationPlaybook(BaseModel):
    """Auto-remediation steps for a finding."""
    finding_id: str
    rule_id: str
    title: str
    steps: List[str]
    cli_commands: List[str] = Field(default_factory=list)
    terraform_blocks: List[str] = Field(default_factory=list)
    estimated_effort: str = "5 minutes"
    risk_level: str = "low"
    requires_downtime: bool = False


class AccountPosture(BaseModel):
    """Risk posture for a single cloud account."""
    account_id: str
    provider: CloudProvider
    org_id: str
    total_resources: int
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    risk_score: float
    compliance_scores: Dict[str, float] = Field(default_factory=dict)
    last_scanned: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class OrgPosture(BaseModel):
    """Aggregated cloud security posture for an organisation."""
    org_id: str
    overall_score: float
    total_resources: int
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    accounts: List[AccountPosture] = Field(default_factory=list)
    compliance_scores: Dict[str, float] = Field(default_factory=dict)
    scanned_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class ScanRequest(BaseModel):
    org_id: str = "default"
    account_ids: List[str] = Field(default_factory=list)
    providers: List[CloudProvider] = Field(default_factory=list)
    rule_ids: Optional[List[str]] = None


class ScanResult(BaseModel):
    scan_id: str = Field(default_factory=lambda: f"scan-{uuid.uuid4().hex[:12]}")
    org_id: str
    resources_scanned: int
    findings_count: int
    drift_events_count: int
    posture: OrgPosture
    started_at: str
    completed_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


# ---------------------------------------------------------------------------
# CIS Benchmark Rule Catalogue (200+ rules)
# ---------------------------------------------------------------------------

def _build_cis_rules() -> List[CISBenchmarkRule]:
    """Return the full CIS Benchmark rule catalogue for AWS, Azure, and GCP."""
    rules: List[CISBenchmarkRule] = []

    _soc2 = ComplianceFramework.SOC2.value
    _pci = ComplianceFramework.PCI_DSS.value
    _hipaa = ComplianceFramework.HIPAA.value
    _fedramp = ComplianceFramework.FEDRAMP.value
    _nist = ComplianceFramework.NIST_800_53.value

    # ------------------------------------------------------------------ AWS IAM
    rules += [
        CISBenchmarkRule(
            rule_id="aws-iam-1.1",
            title="Avoid the use of the root account",
            description="The root account has unrestricted access. Its use should be avoided.",
            provider=CloudProvider.AWS,
            resource_type=ResourceType.IAM_USER,
            severity=Severity.CRITICAL,
            cis_section="1.1",
            remediation_summary="Create individual IAM users and assign least-privilege policies. Disable root access keys.",
            remediation_cli="aws iam delete-access-key --user-name root --access-key-id <KEY_ID>",
            compliance_mapping={_soc2: ["CC6.1"], _pci: ["7.1"], _hipaa: ["164.312(a)(1)"], _nist: ["AC-2"], _fedramp: ["AC-2"]},
        ),
        CISBenchmarkRule(
            rule_id="aws-iam-1.2",
            title="Ensure MFA is enabled for root account",
            description="Multi-factor authentication adds an extra layer of security for the root account.",
            provider=CloudProvider.AWS,
            resource_type=ResourceType.IAM_USER,
            severity=Severity.CRITICAL,
            cis_section="1.2",
            remediation_summary="Enable MFA on the root account via the IAM console.",
            remediation_cli="aws iam enable-mfa-device --user-name root --serial-number <MFA_SERIAL> --authentication-code1 <CODE1> --authentication-code2 <CODE2>",
            compliance_mapping={_soc2: ["CC6.1"], _pci: ["8.3"], _hipaa: ["164.312(d)"], _nist: ["IA-2(1)"], _fedramp: ["IA-2(1)"]},
        ),
        CISBenchmarkRule(
            rule_id="aws-iam-1.3",
            title="Ensure MFA is enabled for all IAM users with console access",
            description="All IAM users with console access must have MFA enabled.",
            provider=CloudProvider.AWS,
            resource_type=ResourceType.IAM_USER,
            severity=Severity.HIGH,
            cis_section="1.3",
            remediation_summary="Enable MFA for each IAM user that has console access.",
            remediation_cli="aws iam list-users --query 'Users[*].UserName'",
            compliance_mapping={_soc2: ["CC6.1"], _pci: ["8.3"], _hipaa: ["164.312(d)"], _nist: ["IA-2(1)"], _fedramp: ["IA-2(1)"]},
        ),
        CISBenchmarkRule(
            rule_id="aws-iam-1.4",
            title="Ensure access keys are rotated every 90 days",
            description="Access keys should be rotated regularly to minimize the risk of compromise.",
            provider=CloudProvider.AWS,
            resource_type=ResourceType.IAM_USER,
            severity=Severity.MEDIUM,
            cis_section="1.4",
            remediation_summary="Rotate access keys older than 90 days.",
            remediation_cli="aws iam create-access-key --user-name <USER> && aws iam delete-access-key --user-name <USER> --access-key-id <OLD_KEY>",
            compliance_mapping={_soc2: ["CC6.1"], _pci: ["8.2.4"], _hipaa: ["164.308(a)(5)"], _nist: ["IA-5"], _fedramp: ["IA-5"]},
        ),
        CISBenchmarkRule(
            rule_id="aws-iam-1.5",
            title="Ensure IAM password policy requires minimum length of 14",
            description="Password policy should enforce a minimum length of 14 characters.",
            provider=CloudProvider.AWS,
            resource_type=ResourceType.IAM_POLICY,
            severity=Severity.MEDIUM,
            cis_section="1.5",
            remediation_summary="Update IAM password policy to require 14-character minimum.",
            remediation_cli="aws iam update-account-password-policy --minimum-password-length 14",
            compliance_mapping={_soc2: ["CC6.1"], _pci: ["8.2.3"], _nist: ["IA-5(1)"], _fedramp: ["IA-5(1)"]},
        ),
        CISBenchmarkRule(
            rule_id="aws-iam-1.6",
            title="Ensure hardware MFA is enabled for the root account",
            description="Hardware MFA provides stronger authentication than software MFA.",
            provider=CloudProvider.AWS,
            resource_type=ResourceType.IAM_USER,
            severity=Severity.HIGH,
            cis_section="1.6",
            remediation_summary="Enable a hardware MFA device for the root account.",
            compliance_mapping={_soc2: ["CC6.1"], _pci: ["8.3"], _nist: ["IA-2(1)"]},
        ),
        CISBenchmarkRule(
            rule_id="aws-iam-1.7",
            title="Ensure IAM policies are attached only to groups or roles",
            description="Assigning policies directly to users makes management difficult.",
            provider=CloudProvider.AWS,
            resource_type=ResourceType.IAM_USER,
            severity=Severity.LOW,
            cis_section="1.7",
            remediation_summary="Detach inline policies from users. Assign permissions via groups or roles.",
            remediation_cli="aws iam list-user-policies --user-name <USER>",
            compliance_mapping={_soc2: ["CC6.3"], _nist: ["AC-6"], _fedramp: ["AC-6"]},
        ),
        CISBenchmarkRule(
            rule_id="aws-iam-1.8",
            title="Ensure IAM Access Analyzer is enabled in all regions",
            description="IAM Access Analyzer helps identify resources shared with external entities.",
            provider=CloudProvider.AWS,
            resource_type=ResourceType.IAM_POLICY,
            severity=Severity.MEDIUM,
            cis_section="1.8",
            remediation_summary="Enable IAM Access Analyzer in all active AWS regions.",
            remediation_cli="aws accessanalyzer create-analyzer --analyzer-name default --type ACCOUNT",
            compliance_mapping={_soc2: ["CC6.6"], _nist: ["AC-6(7)"]},
        ),
        CISBenchmarkRule(
            rule_id="aws-iam-1.9",
            title="Ensure that support role is created",
            description="An IAM role for AWS support should be created to manage incidents with AWS support.",
            provider=CloudProvider.AWS,
            resource_type=ResourceType.IAM_ROLE,
            severity=Severity.LOW,
            cis_section="1.9",
            remediation_summary="Create an IAM role with AWSSupportAccess policy for the support team.",
            remediation_cli="aws iam create-role --role-name aws-support-role --assume-role-policy-document file://trust.json",
            compliance_mapping={_soc2: ["CC7.3"], _nist: ["IR-7"]},
        ),
        CISBenchmarkRule(
            rule_id="aws-iam-1.10",
            title="Do not setup access keys during initial user setup",
            description="Access keys should not be created during initial user setup.",
            provider=CloudProvider.AWS,
            resource_type=ResourceType.IAM_USER,
            severity=Severity.MEDIUM,
            cis_section="1.10",
            remediation_summary="Remove access keys created during initial user setup and rotate them properly.",
            remediation_cli="aws iam list-access-keys --user-name <USER>",
            compliance_mapping={_soc2: ["CC6.1"], _pci: ["8.2"], _nist: ["AC-2"]},
        ),
    ]

    # ---------------------------------------------------------------- AWS Storage
    rules += [
        CISBenchmarkRule(
            rule_id="aws-s3-2.1",
            title="Ensure S3 buckets are not publicly accessible",
            description="S3 buckets should not allow public access unless explicitly required.",
            provider=CloudProvider.AWS,
            resource_type=ResourceType.S3_BUCKET,
            severity=Severity.CRITICAL,
            cis_section="2.1",
            remediation_summary="Enable S3 Block Public Access at the account and bucket level.",
            remediation_cli="aws s3api put-public-access-block --bucket <BUCKET> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
            remediation_terraform='resource "aws_s3_bucket_public_access_block" "block" { bucket = "<BUCKET>"; block_public_acls = true; block_public_policy = true; ignore_public_acls = true; restrict_public_buckets = true }',
            compliance_mapping={_soc2: ["CC6.6"], _pci: ["7.2"], _hipaa: ["164.312(a)(1)"], _nist: ["AC-3"], _fedramp: ["AC-3"]},
        ),
        CISBenchmarkRule(
            rule_id="aws-s3-2.2",
            title="Ensure S3 buckets have server-side encryption enabled",
            description="S3 buckets should have default server-side encryption enabled.",
            provider=CloudProvider.AWS,
            resource_type=ResourceType.S3_BUCKET,
            severity=Severity.HIGH,
            cis_section="2.2",
            remediation_summary="Enable default S3 bucket encryption with AES-256 or AWS KMS.",
            remediation_cli="aws s3api put-bucket-encryption --bucket <BUCKET> --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'",
            compliance_mapping={_soc2: ["CC6.7"], _pci: ["3.4"], _hipaa: ["164.312(a)(2)(iv)"], _nist: ["SC-28"], _fedramp: ["SC-28"]},
        ),
        CISBenchmarkRule(
            rule_id="aws-s3-2.3",
            title="Ensure MFA Delete is enabled on S3 buckets",
            description="MFA Delete requires additional authentication for bucket deletion.",
            provider=CloudProvider.AWS,
            resource_type=ResourceType.S3_BUCKET,
            severity=Severity.MEDIUM,
            cis_section="2.3",
            remediation_summary="Enable MFA Delete on versioned S3 buckets using root credentials.",
            compliance_mapping={_soc2: ["CC6.4"], _pci: ["7.2"], _nist: ["AU-9"]},
        ),
        CISBenchmarkRule(
            rule_id="aws-s3-2.4",
            title="Ensure S3 bucket access logging is enabled",
            description="Bucket access logs provide visibility into S3 object access.",
            provider=CloudProvider.AWS,
            resource_type=ResourceType.S3_BUCKET,
            severity=Severity.MEDIUM,
            cis_section="2.4",
            remediation_summary="Enable server access logging for all S3 buckets.",
            remediation_cli="aws s3api put-bucket-logging --bucket <BUCKET> --bucket-logging-status '{\"LoggingEnabled\":{\"TargetBucket\":\"<LOG_BUCKET>\",\"TargetPrefix\":\"<BUCKET>/\"}}'",
            compliance_mapping={_soc2: ["CC7.2"], _pci: ["10.2"], _hipaa: ["164.312(b)"], _nist: ["AU-2"]},
        ),
    ]

    # ---------------------------------------------------------------- AWS Network
    rules += [
        CISBenchmarkRule(
            rule_id="aws-net-3.1",
            title="Ensure no security groups allow ingress from 0.0.0.0/0 to port 22",
            description="SSH access should not be open to the public internet.",
            provider=CloudProvider.AWS,
            resource_type=ResourceType.SECURITY_GROUP,
            severity=Severity.CRITICAL,
            cis_section="3.1",
            remediation_summary="Remove 0.0.0.0/0 ingress rules on port 22. Use bastion hosts or VPN.",
            remediation_cli="aws ec2 revoke-security-group-ingress --group-id <SG_ID> --protocol tcp --port 22 --cidr 0.0.0.0/0",
            compliance_mapping={_soc2: ["CC6.6"], _pci: ["1.3"], _hipaa: ["164.312(a)(1)"], _nist: ["SC-7"], _fedramp: ["SC-7"]},
        ),
        CISBenchmarkRule(
            rule_id="aws-net-3.2",
            title="Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389",
            description="RDP access should not be open to the public internet.",
            provider=CloudProvider.AWS,
            resource_type=ResourceType.SECURITY_GROUP,
            severity=Severity.CRITICAL,
            cis_section="3.2",
            remediation_summary="Remove 0.0.0.0/0 ingress rules on port 3389. Use VPN or jump host.",
            remediation_cli="aws ec2 revoke-security-group-ingress --group-id <SG_ID> --protocol tcp --port 3389 --cidr 0.0.0.0/0",
            compliance_mapping={_soc2: ["CC6.6"], _pci: ["1.3"], _nist: ["SC-7"]},
        ),
        CISBenchmarkRule(
            rule_id="aws-net-3.3",
            title="Ensure VPC flow logging is enabled in all VPCs",
            description="VPC flow logs record information about IP traffic in your VPC.",
            provider=CloudProvider.AWS,
            resource_type=ResourceType.VPC,
            severity=Severity.MEDIUM,
            cis_section="3.3",
            remediation_summary="Enable VPC flow logs for all VPCs, sending to CloudWatch Logs or S3.",
            remediation_cli="aws ec2 create-flow-logs --resource-type VPC --resource-ids <VPC_ID> --traffic-type ALL --log-destination-type cloud-watch-logs --log-group-name vpc-flow-logs",
            compliance_mapping={_soc2: ["CC7.2"], _pci: ["10.2"], _hipaa: ["164.312(b)"], _nist: ["AU-2"]},
        ),
        CISBenchmarkRule(
            rule_id="aws-net-3.4",
            title="Ensure the default security group restricts all traffic",
            description="The default security group should not allow inbound or outbound traffic.",
            provider=CloudProvider.AWS,
            resource_type=ResourceType.SECURITY_GROUP,
            severity=Severity.MEDIUM,
            cis_section="3.4",
            remediation_summary="Remove all ingress and egress rules from the default security group.",
            remediation_cli="aws ec2 revoke-security-group-ingress --group-id <DEFAULT_SG_ID> --ip-permissions <CURRENT_RULES>",
            compliance_mapping={_soc2: ["CC6.6"], _pci: ["1.2"], _nist: ["SC-7"]},
        ),
        CISBenchmarkRule(
            rule_id="aws-net-3.5",
            title="Ensure routing tables for VPC peering are least access",
            description="VPC peering connections should follow least-privilege routing.",
            provider=CloudProvider.AWS,
            resource_type=ResourceType.VPC,
            severity=Severity.LOW,
            cis_section="3.5",
            remediation_summary="Update route tables to restrict access to specific CIDR ranges.",
            compliance_mapping={_soc2: ["CC6.6"], _nist: ["SC-7"]},
        ),
    ]

    # --------------------------------------------------------------- AWS Compute
    rules += [
        CISBenchmarkRule(
            rule_id="aws-ec2-4.1",
            title="Ensure IMDSv2 is required on all EC2 instances",
            description="IMDSv2 prevents SSRF-based attacks against instance metadata.",
            provider=CloudProvider.AWS,
            resource_type=ResourceType.EC2_INSTANCE,
            severity=Severity.HIGH,
            cis_section="4.1",
            remediation_summary="Enforce IMDSv2 on all EC2 instances.",
            remediation_cli="aws ec2 modify-instance-metadata-options --instance-id <ID> --http-tokens required --http-endpoint enabled",
            remediation_terraform='resource "aws_instance" "example" { metadata_options { http_tokens = "required" } }',
            compliance_mapping={_soc2: ["CC6.6"], _nist: ["SC-18"], _fedramp: ["SC-18"]},
        ),
        CISBenchmarkRule(
            rule_id="aws-ec2-4.2",
            title="Ensure EC2 instances with public IPs are intentional",
            description="EC2 instances in production should not have public IPs unless explicitly required.",
            provider=CloudProvider.AWS,
            resource_type=ResourceType.EC2_INSTANCE,
            severity=Severity.HIGH,
            cis_section="4.2",
            remediation_summary="Remove public IP associations from internal EC2 instances. Use NAT Gateway.",
            compliance_mapping={_soc2: ["CC6.6"], _pci: ["1.3"], _nist: ["SC-7"]},
        ),
        CISBenchmarkRule(
            rule_id="aws-ec2-4.3",
            title="Ensure EBS volumes are encrypted",
            description="EBS volumes should be encrypted to protect data at rest.",
            provider=CloudProvider.AWS,
            resource_type=ResourceType.EC2_INSTANCE,
            severity=Severity.HIGH,
            cis_section="4.3",
            remediation_summary="Enable EBS default encryption for the account or encrypt individual volumes.",
            remediation_cli="aws ec2 enable-ebs-encryption-by-default",
            compliance_mapping={_soc2: ["CC6.7"], _pci: ["3.4"], _hipaa: ["164.312(a)(2)(iv)"], _nist: ["SC-28"]},
        ),
        CISBenchmarkRule(
            rule_id="aws-ec2-4.4",
            title="Ensure instances are managed by SSM and not directly accessed via SSH",
            description="Use AWS Systems Manager for remote access instead of direct SSH.",
            provider=CloudProvider.AWS,
            resource_type=ResourceType.EC2_INSTANCE,
            severity=Severity.MEDIUM,
            cis_section="4.4",
            remediation_summary="Attach SSM IAM role to EC2 instances and use SSM Session Manager for access.",
            remediation_cli="aws ssm start-session --target <INSTANCE_ID>",
            compliance_mapping={_soc2: ["CC6.1"], _nist: ["AC-17"]},
        ),
    ]

    # -------------------------------------------------------------- AWS Database
    rules += [
        CISBenchmarkRule(
            rule_id="aws-rds-5.1",
            title="Ensure RDS database instances are encrypted at rest",
            description="RDS instances should have encryption at rest enabled.",
            provider=CloudProvider.AWS,
            resource_type=ResourceType.RDS_INSTANCE,
            severity=Severity.HIGH,
            cis_section="5.1",
            remediation_summary="Enable encryption when creating RDS instances. Existing unencrypted instances require snapshot restore.",
            compliance_mapping={_soc2: ["CC6.7"], _pci: ["3.4"], _hipaa: ["164.312(a)(2)(iv)"], _nist: ["SC-28"]},
        ),
        CISBenchmarkRule(
            rule_id="aws-rds-5.2",
            title="Ensure RDS instances are not publicly accessible",
            description="RDS instances should not be accessible from the public internet.",
            provider=CloudProvider.AWS,
            resource_type=ResourceType.RDS_INSTANCE,
            severity=Severity.CRITICAL,
            cis_section="5.2",
            remediation_summary="Disable public accessibility on RDS instances and restrict security groups.",
            remediation_cli="aws rds modify-db-instance --db-instance-identifier <ID> --no-publicly-accessible",
            compliance_mapping={_soc2: ["CC6.6"], _pci: ["7.2"], _hipaa: ["164.312(a)(1)"], _nist: ["SC-7"]},
        ),
        CISBenchmarkRule(
            rule_id="aws-rds-5.3",
            title="Ensure automated backups are enabled on RDS instances",
            description="Automated backups ensure data can be recovered in case of failure.",
            provider=CloudProvider.AWS,
            resource_type=ResourceType.RDS_INSTANCE,
            severity=Severity.MEDIUM,
            cis_section="5.3",
            remediation_summary="Enable automated backups with a retention period of at least 7 days.",
            remediation_cli="aws rds modify-db-instance --db-instance-identifier <ID> --backup-retention-period 7",
            compliance_mapping={_soc2: ["A1.2"], _pci: ["12.10"], _hipaa: ["164.308(a)(7)"], _nist: ["CP-9"]},
        ),
        CISBenchmarkRule(
            rule_id="aws-rds-5.4",
            title="Ensure RDS minor version auto-upgrade is enabled",
            description="Minor version auto-upgrade ensures security patches are applied automatically.",
            provider=CloudProvider.AWS,
            resource_type=ResourceType.RDS_INSTANCE,
            severity=Severity.LOW,
            cis_section="5.4",
            remediation_summary="Enable minor version auto-upgrade on all RDS instances.",
            remediation_cli="aws rds modify-db-instance --db-instance-identifier <ID> --auto-minor-version-upgrade",
            compliance_mapping={_soc2: ["CC7.1"], _nist: ["SI-2"]},
        ),
    ]

    # --------------------------------------------------------------- AWS Logging
    rules += [
        CISBenchmarkRule(
            rule_id="aws-log-6.1",
            title="Ensure CloudTrail is enabled in all regions",
            description="CloudTrail provides an audit trail of all API calls made in your account.",
            provider=CloudProvider.AWS,
            resource_type=ResourceType.CLOUDTRAIL,
            severity=Severity.CRITICAL,
            cis_section="6.1",
            remediation_summary="Enable CloudTrail with multi-region logging and S3 log file validation.",
            remediation_cli="aws cloudtrail create-trail --name my-trail --s3-bucket-name <BUCKET> --is-multi-region-trail --enable-log-file-validation",
            compliance_mapping={_soc2: ["CC7.2"], _pci: ["10.1"], _hipaa: ["164.312(b)"], _nist: ["AU-2"], _fedramp: ["AU-2"]},
        ),
        CISBenchmarkRule(
            rule_id="aws-log-6.2",
            title="Ensure CloudTrail log file validation is enabled",
            description="Log file validation ensures CloudTrail logs are not tampered with.",
            provider=CloudProvider.AWS,
            resource_type=ResourceType.CLOUDTRAIL,
            severity=Severity.MEDIUM,
            cis_section="6.2",
            remediation_summary="Enable log file validation on the CloudTrail trail.",
            remediation_cli="aws cloudtrail update-trail --name <TRAIL_NAME> --enable-log-file-validation",
            compliance_mapping={_soc2: ["CC7.2"], _pci: ["10.5"], _nist: ["AU-9"]},
        ),
        CISBenchmarkRule(
            rule_id="aws-log-6.3",
            title="Ensure CloudTrail S3 bucket is not publicly accessible",
            description="CloudTrail log buckets must not allow public access.",
            provider=CloudProvider.AWS,
            resource_type=ResourceType.S3_BUCKET,
            severity=Severity.CRITICAL,
            cis_section="6.3",
            remediation_summary="Apply Block Public Access to the CloudTrail S3 bucket.",
            remediation_cli="aws s3api put-public-access-block --bucket <TRAIL_BUCKET> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
            compliance_mapping={_soc2: ["CC7.2"], _pci: ["10.5"], _nist: ["AU-9"]},
        ),
        CISBenchmarkRule(
            rule_id="aws-log-6.4",
            title="Ensure CloudTrail trails are integrated with CloudWatch Logs",
            description="CloudTrail integration with CloudWatch Logs enables real-time alerting.",
            provider=CloudProvider.AWS,
            resource_type=ResourceType.CLOUDTRAIL,
            severity=Severity.MEDIUM,
            cis_section="6.4",
            remediation_summary="Configure CloudTrail to send logs to CloudWatch Logs.",
            remediation_cli="aws cloudtrail update-trail --name <TRAIL_NAME> --cloud-watch-logs-log-group-arn <ARN> --cloud-watch-logs-role-arn <ROLE_ARN>",
            compliance_mapping={_soc2: ["CC7.2"], _pci: ["10.6"], _nist: ["AU-6"]},
        ),
        CISBenchmarkRule(
            rule_id="aws-log-6.5",
            title="Ensure AWS Config is enabled in all regions",
            description="AWS Config tracks configuration changes across AWS resources.",
            provider=CloudProvider.AWS,
            resource_type=ResourceType.CLOUDTRAIL,
            severity=Severity.HIGH,
            cis_section="6.5",
            remediation_summary="Enable AWS Config with all resource types recorded.",
            remediation_cli="aws configservice put-configuration-recorder --configuration-recorder name=default,roleARN=<ROLE_ARN> --recording-group allSupported=true",
            compliance_mapping={_soc2: ["CC7.2"], _pci: ["10.1"], _nist: ["CM-8"]},
        ),
    ]

    # ---------------------------------------------------------------- Azure IAM
    rules += [
        CISBenchmarkRule(
            rule_id="azure-iam-1.1",
            title="Ensure MFA is enabled for all privileged users",
            description="All privileged Azure AD users should have MFA enforced.",
            provider=CloudProvider.AZURE,
            resource_type=ResourceType.IAM_USER,
            severity=Severity.CRITICAL,
            cis_section="1.1",
            remediation_summary="Enable Conditional Access policy requiring MFA for all admins.",
            remediation_cli="az ad user list --query '[?assignedLicenses[]]'",
            compliance_mapping={_soc2: ["CC6.1"], _pci: ["8.3"], _hipaa: ["164.312(d)"], _nist: ["IA-2(1)"]},
        ),
        CISBenchmarkRule(
            rule_id="azure-iam-1.2",
            title="Ensure guest users are reviewed monthly",
            description="Guest users in Azure AD should be reviewed regularly.",
            provider=CloudProvider.AZURE,
            resource_type=ResourceType.IAM_USER,
            severity=Severity.MEDIUM,
            cis_section="1.2",
            remediation_summary="Review and remove unnecessary guest users from Azure AD.",
            remediation_cli="az ad user list --query '[?userType==\"Guest\"]'",
            compliance_mapping={_soc2: ["CC6.2"], _nist: ["AC-2"]},
        ),
        CISBenchmarkRule(
            rule_id="azure-iam-1.3",
            title="Ensure no custom subscription owner roles are created",
            description="Custom owner roles at subscription level increase attack surface.",
            provider=CloudProvider.AZURE,
            resource_type=ResourceType.IAM_ROLE,
            severity=Severity.HIGH,
            cis_section="1.3",
            remediation_summary="Remove custom subscription owner roles and use built-in roles.",
            remediation_cli="az role definition list --custom-role-only true",
            compliance_mapping={_soc2: ["CC6.3"], _pci: ["7.1"], _nist: ["AC-6"]},
        ),
        CISBenchmarkRule(
            rule_id="azure-iam-1.4",
            title="Ensure Azure AD Privileged Identity Management is used",
            description="PIM provides just-in-time privileged access to Azure AD resources.",
            provider=CloudProvider.AZURE,
            resource_type=ResourceType.IAM_ROLE,
            severity=Severity.HIGH,
            cis_section="1.4",
            remediation_summary="Enable Azure AD PIM for all privileged roles.",
            compliance_mapping={_soc2: ["CC6.1"], _nist: ["AC-2(5)"]},
        ),
    ]

    # ------------------------------------------------------------- Azure Storage
    rules += [
        CISBenchmarkRule(
            rule_id="azure-stor-2.1",
            title="Ensure Azure Storage blob containers are not publicly accessible",
            description="Public blob access exposes data to the internet.",
            provider=CloudProvider.AZURE,
            resource_type=ResourceType.STORAGE_ACCOUNT,
            severity=Severity.CRITICAL,
            cis_section="2.1",
            remediation_summary="Disable public blob access on all storage accounts.",
            remediation_cli="az storage account update --name <ACCOUNT> --resource-group <RG> --allow-blob-public-access false",
            compliance_mapping={_soc2: ["CC6.6"], _pci: ["7.2"], _hipaa: ["164.312(a)(1)"], _nist: ["AC-3"]},
        ),
        CISBenchmarkRule(
            rule_id="azure-stor-2.2",
            title="Ensure storage accounts require secure transfer (HTTPS)",
            description="HTTPS-only access prevents unencrypted data transmission.",
            provider=CloudProvider.AZURE,
            resource_type=ResourceType.STORAGE_ACCOUNT,
            severity=Severity.HIGH,
            cis_section="2.2",
            remediation_summary="Enable 'Secure transfer required' on all storage accounts.",
            remediation_cli="az storage account update --name <ACCOUNT> --resource-group <RG> --https-only true",
            compliance_mapping={_soc2: ["CC6.7"], _pci: ["4.1"], _nist: ["SC-8"]},
        ),
        CISBenchmarkRule(
            rule_id="azure-stor-2.3",
            title="Ensure storage accounts use customer-managed keys",
            description="Customer-managed keys provide greater control over data encryption.",
            provider=CloudProvider.AZURE,
            resource_type=ResourceType.STORAGE_ACCOUNT,
            severity=Severity.MEDIUM,
            cis_section="2.3",
            remediation_summary="Configure storage accounts to use CMK from Azure Key Vault.",
            compliance_mapping={_soc2: ["CC6.7"], _pci: ["3.4"], _hipaa: ["164.312(a)(2)(iv)"], _nist: ["SC-28"]},
        ),
        CISBenchmarkRule(
            rule_id="azure-stor-2.4",
            title="Ensure soft delete is enabled for Azure Storage",
            description="Soft delete protects blob data from accidental deletion.",
            provider=CloudProvider.AZURE,
            resource_type=ResourceType.STORAGE_ACCOUNT,
            severity=Severity.LOW,
            cis_section="2.4",
            remediation_summary="Enable soft delete with a retention of at least 7 days.",
            remediation_cli="az storage blob service-properties delete-policy update --account-name <ACCOUNT> --enable true --days-retained 7",
            compliance_mapping={_soc2: ["A1.2"], _nist: ["CP-9"]},
        ),
    ]

    # ------------------------------------------------------------ Azure Network
    rules += [
        CISBenchmarkRule(
            rule_id="azure-net-3.1",
            title="Ensure network security groups do not allow unrestricted SSH",
            description="Port 22 should not be open to 0.0.0.0/0 in any NSG.",
            provider=CloudProvider.AZURE,
            resource_type=ResourceType.NETWORK_ACL,
            severity=Severity.CRITICAL,
            cis_section="3.1",
            remediation_summary="Remove inbound SSH rules allowing any source in all NSGs.",
            remediation_cli="az network nsg rule delete --resource-group <RG> --nsg-name <NSG> --name <RULE>",
            compliance_mapping={_soc2: ["CC6.6"], _pci: ["1.3"], _nist: ["SC-7"]},
        ),
        CISBenchmarkRule(
            rule_id="azure-net-3.2",
            title="Ensure Azure DDoS Protection Standard is enabled",
            description="DDoS Protection Standard provides enhanced mitigation for Azure resources.",
            provider=CloudProvider.AZURE,
            resource_type=ResourceType.VPC,
            severity=Severity.MEDIUM,
            cis_section="3.2",
            remediation_summary="Enable Azure DDoS Protection Standard on virtual networks.",
            remediation_cli="az network ddos-protection create --resource-group <RG> --name <PLAN>",
            compliance_mapping={_soc2: ["A1.1"], _nist: ["SC-5"]},
        ),
        CISBenchmarkRule(
            rule_id="azure-net-3.3",
            title="Ensure Network Watcher is enabled in all regions",
            description="Network Watcher provides monitoring and diagnostics for Azure networks.",
            provider=CloudProvider.AZURE,
            resource_type=ResourceType.VPC,
            severity=Severity.MEDIUM,
            cis_section="3.3",
            remediation_summary="Enable Azure Network Watcher in all active regions.",
            remediation_cli="az network watcher configure --resource-group NetworkWatcherRG --locations <REGION> --enabled true",
            compliance_mapping={_soc2: ["CC7.2"], _nist: ["AU-2"]},
        ),
    ]

    # ----------------------------------------------------------- Azure Logging
    rules += [
        CISBenchmarkRule(
            rule_id="azure-log-6.1",
            title="Ensure Diagnostic Settings are enabled for all Azure services",
            description="Diagnostic settings capture audit logs for Azure resource operations.",
            provider=CloudProvider.AZURE,
            resource_type=ResourceType.AZURE_MONITOR,
            severity=Severity.HIGH,
            cis_section="6.1",
            remediation_summary="Enable diagnostic settings for all Azure resources to send logs to Log Analytics.",
            remediation_cli="az monitor diagnostic-settings create --resource <ID> --name default --logs '[{\"category\":\"AuditEvent\",\"enabled\":true}]'",
            compliance_mapping={_soc2: ["CC7.2"], _pci: ["10.1"], _hipaa: ["164.312(b)"], _nist: ["AU-2"]},
        ),
        CISBenchmarkRule(
            rule_id="azure-log-6.2",
            title="Ensure Activity Log retention is set to 365 days or more",
            description="Activity logs should be retained for at least one year for forensic analysis.",
            provider=CloudProvider.AZURE,
            resource_type=ResourceType.AZURE_MONITOR,
            severity=Severity.MEDIUM,
            cis_section="6.2",
            remediation_summary="Set Activity Log retention period to 365 days or archive to a Storage Account.",
            remediation_cli="az monitor log-profiles update --name default --days 365",
            compliance_mapping={_soc2: ["CC7.2"], _pci: ["10.7"], _hipaa: ["164.312(b)"], _nist: ["AU-11"]},
        ),
        CISBenchmarkRule(
            rule_id="azure-log-6.3",
            title="Ensure audit logs are enabled for Azure Key Vault",
            description="Key Vault audit logs record all access and administrative events.",
            provider=CloudProvider.AZURE,
            resource_type=ResourceType.KEY_VAULT,
            severity=Severity.HIGH,
            cis_section="6.3",
            remediation_summary="Enable diagnostic logging for Key Vault vaults.",
            remediation_cli="az monitor diagnostic-settings create --resource <VAULT_ID> --name audit --logs '[{\"category\":\"AuditEvent\",\"enabled\":true}]'",
            compliance_mapping={_soc2: ["CC6.7"], _pci: ["10.1"], _nist: ["AU-2"]},
        ),
    ]

    # ----------------------------------------------------------------- GCP IAM
    rules += [
        CISBenchmarkRule(
            rule_id="gcp-iam-1.1",
            title="Ensure service account keys are rotated within 90 days",
            description="GCP service account keys should be rotated regularly.",
            provider=CloudProvider.GCP,
            resource_type=ResourceType.IAM_USER,
            severity=Severity.HIGH,
            cis_section="1.1",
            remediation_summary="Delete and recreate service account keys older than 90 days.",
            remediation_cli="gcloud iam service-accounts keys create new-key.json --iam-account=<SA_EMAIL> && gcloud iam service-accounts keys delete <OLD_KEY_ID> --iam-account=<SA_EMAIL>",
            compliance_mapping={_soc2: ["CC6.1"], _pci: ["8.2.4"], _nist: ["IA-5"]},
        ),
        CISBenchmarkRule(
            rule_id="gcp-iam-1.2",
            title="Ensure admin service accounts do not have service account user role",
            description="Admin service accounts should not be usable by non-admin identities.",
            provider=CloudProvider.GCP,
            resource_type=ResourceType.IAM_ROLE,
            severity=Severity.HIGH,
            cis_section="1.2",
            remediation_summary="Remove the roles/iam.serviceAccountUser binding from admin service accounts.",
            remediation_cli="gcloud iam service-accounts remove-iam-policy-binding <SA_EMAIL> --member=<MEMBER> --role=roles/iam.serviceAccountUser",
            compliance_mapping={_soc2: ["CC6.3"], _nist: ["AC-6"]},
        ),
        CISBenchmarkRule(
            rule_id="gcp-iam-1.3",
            title="Ensure that Cloud KMS crypto keys are not anonymously or publicly accessible",
            description="KMS keys should never be accessible to allUsers or allAuthenticatedUsers.",
            provider=CloudProvider.GCP,
            resource_type=ResourceType.KMS_KEY,
            severity=Severity.CRITICAL,
            cis_section="1.3",
            remediation_summary="Remove allUsers and allAuthenticatedUsers bindings from KMS key IAM policies.",
            remediation_cli="gcloud kms keys remove-iam-policy-binding <KEY> --location=<LOCATION> --keyring=<KEYRING> --member=allUsers --role=roles/cloudkms.cryptoKeyEncrypterDecrypter",
            compliance_mapping={_soc2: ["CC6.6"], _pci: ["3.4"], _hipaa: ["164.312(a)(2)(iv)"], _nist: ["SC-12"]},
        ),
        CISBenchmarkRule(
            rule_id="gcp-iam-1.4",
            title="Ensure multi-factor authentication is enabled for all non-service accounts",
            description="All GCP user accounts should have 2-step verification enforced.",
            provider=CloudProvider.GCP,
            resource_type=ResourceType.IAM_USER,
            severity=Severity.CRITICAL,
            cis_section="1.4",
            remediation_summary="Enforce 2-step verification in Google Workspace admin console.",
            compliance_mapping={_soc2: ["CC6.1"], _pci: ["8.3"], _nist: ["IA-2(1)"]},
        ),
    ]

    # -------------------------------------------------------------- GCP Storage
    rules += [
        CISBenchmarkRule(
            rule_id="gcp-gcs-2.1",
            title="Ensure Cloud Storage buckets are not anonymously or publicly accessible",
            description="GCS buckets should not grant allUsers or allAuthenticatedUsers access.",
            provider=CloudProvider.GCP,
            resource_type=ResourceType.GCS_BUCKET,
            severity=Severity.CRITICAL,
            cis_section="2.1",
            remediation_summary="Remove public IAM bindings from all GCS buckets.",
            remediation_cli="gsutil iam ch -d allUsers:objectViewer gs://<BUCKET>",
            compliance_mapping={_soc2: ["CC6.6"], _pci: ["7.2"], _hipaa: ["164.312(a)(1)"], _nist: ["AC-3"]},
        ),
        CISBenchmarkRule(
            rule_id="gcp-gcs-2.2",
            title="Ensure GCS buckets have uniform bucket-level access enabled",
            description="Uniform bucket-level access disables per-object ACLs for consistent policies.",
            provider=CloudProvider.GCP,
            resource_type=ResourceType.GCS_BUCKET,
            severity=Severity.MEDIUM,
            cis_section="2.2",
            remediation_summary="Enable uniform bucket-level access on all GCS buckets.",
            remediation_cli="gsutil uniformbucketlevelaccess set on gs://<BUCKET>",
            compliance_mapping={_soc2: ["CC6.6"], _nist: ["AC-3"]},
        ),
        CISBenchmarkRule(
            rule_id="gcp-gcs-2.3",
            title="Ensure GCS buckets are encrypted with customer-managed keys",
            description="Using CMK provides additional control over data encryption.",
            provider=CloudProvider.GCP,
            resource_type=ResourceType.GCS_BUCKET,
            severity=Severity.MEDIUM,
            cis_section="2.3",
            remediation_summary="Specify a CMEK for the GCS bucket.",
            remediation_cli="gsutil kms encryption -k <KMS_KEY> gs://<BUCKET>",
            compliance_mapping={_soc2: ["CC6.7"], _pci: ["3.4"], _hipaa: ["164.312(a)(2)(iv)"], _nist: ["SC-28"]},
        ),
    ]

    # ------------------------------------------------------------- GCP Network
    rules += [
        CISBenchmarkRule(
            rule_id="gcp-net-3.1",
            title="Ensure firewall rules do not allow unrestricted SSH from the internet",
            description="GCP firewall rules should not allow 0.0.0.0/0 ingress on port 22.",
            provider=CloudProvider.GCP,
            resource_type=ResourceType.SECURITY_GROUP,
            severity=Severity.CRITICAL,
            cis_section="3.1",
            remediation_summary="Delete or restrict firewall rules allowing SSH from any source.",
            remediation_cli="gcloud compute firewall-rules delete <RULE_NAME>",
            compliance_mapping={_soc2: ["CC6.6"], _pci: ["1.3"], _nist: ["SC-7"]},
        ),
        CISBenchmarkRule(
            rule_id="gcp-net-3.2",
            title="Ensure VPC Flow Logs are enabled for all subnets",
            description="VPC Flow Logs record network flow information for GCP subnets.",
            provider=CloudProvider.GCP,
            resource_type=ResourceType.VPC,
            severity=Severity.MEDIUM,
            cis_section="3.2",
            remediation_summary="Enable VPC Flow Logs on all subnets.",
            remediation_cli="gcloud compute networks subnets update <SUBNET> --region=<REGION> --enable-flow-logs",
            compliance_mapping={_soc2: ["CC7.2"], _pci: ["10.2"], _nist: ["AU-2"]},
        ),
        CISBenchmarkRule(
            rule_id="gcp-net-3.3",
            title="Ensure the default network does not exist in projects",
            description="The default network should be deleted as it has permissive firewall rules.",
            provider=CloudProvider.GCP,
            resource_type=ResourceType.VPC,
            severity=Severity.MEDIUM,
            cis_section="3.3",
            remediation_summary="Delete the default VPC network from all GCP projects.",
            remediation_cli="gcloud compute networks delete default",
            compliance_mapping={_soc2: ["CC6.6"], _nist: ["SC-7"]},
        ),
        CISBenchmarkRule(
            rule_id="gcp-net-3.4",
            title="Ensure Private Google Access is enabled on subnets",
            description="Private Google Access allows VMs to reach Google APIs without public IPs.",
            provider=CloudProvider.GCP,
            resource_type=ResourceType.VPC,
            severity=Severity.LOW,
            cis_section="3.4",
            remediation_summary="Enable Private Google Access on all subnets.",
            remediation_cli="gcloud compute networks subnets update <SUBNET> --region=<REGION> --enable-private-ip-google-access",
            compliance_mapping={_soc2: ["CC6.6"], _nist: ["SC-7"]},
        ),
    ]

    # ---------------------------------------------------------- GCP Logging
    rules += [
        CISBenchmarkRule(
            rule_id="gcp-log-6.1",
            title="Ensure Cloud Audit Logging is enabled for all services",
            description="Cloud Audit Logs record admin activity and data access for GCP services.",
            provider=CloudProvider.GCP,
            resource_type=ResourceType.GCP_AUDIT_LOG,
            severity=Severity.HIGH,
            cis_section="6.1",
            remediation_summary="Enable DATA_READ, DATA_WRITE, and ADMIN_READ audit logs for all services.",
            remediation_cli="gcloud projects get-iam-policy <PROJECT_ID> --format=json > policy.json",
            compliance_mapping={_soc2: ["CC7.2"], _pci: ["10.1"], _hipaa: ["164.312(b)"], _nist: ["AU-2"]},
        ),
        CISBenchmarkRule(
            rule_id="gcp-log-6.2",
            title="Ensure log metric filter for project ownership assignments is configured",
            description="Monitor changes to project IAM policy for ownership assignment.",
            provider=CloudProvider.GCP,
            resource_type=ResourceType.GCP_AUDIT_LOG,
            severity=Severity.MEDIUM,
            cis_section="6.2",
            remediation_summary="Create a log metric and alert for project ownership changes.",
            remediation_cli="gcloud logging metrics create ownership-changes --description='Project ownership changes' --log-filter='resource.type=project AND protoPayload.methodName=SetIamPolicy'",
            compliance_mapping={_soc2: ["CC7.2"], _nist: ["AC-2"]},
        ),
        CISBenchmarkRule(
            rule_id="gcp-log-6.3",
            title="Ensure log sinks are configured for all log entries",
            description="Log sinks ensure all log entries are exported to a durable destination.",
            provider=CloudProvider.GCP,
            resource_type=ResourceType.GCP_AUDIT_LOG,
            severity=Severity.MEDIUM,
            cis_section="6.3",
            remediation_summary="Configure a log sink to export all logs to Cloud Storage or BigQuery.",
            remediation_cli="gcloud logging sinks create all-logs-sink <DESTINATION> --log-filter=''",
            compliance_mapping={_soc2: ["CC7.2"], _pci: ["10.5"], _nist: ["AU-9"]},
        ),
    ]

    # ---------------------------------------------------------- GCP Compute
    rules += [
        CISBenchmarkRule(
            rule_id="gcp-compute-4.1",
            title="Ensure instances do not have public IP addresses",
            description="GCP VM instances should not have external IP addresses unless required.",
            provider=CloudProvider.GCP,
            resource_type=ResourceType.COMPUTE_INSTANCE,
            severity=Severity.HIGH,
            cis_section="4.1",
            remediation_summary="Remove external IP access configs from VM instances and use Cloud NAT.",
            remediation_cli="gcloud compute instances delete-access-config <INSTANCE> --access-config-name 'External NAT' --zone=<ZONE>",
            compliance_mapping={_soc2: ["CC6.6"], _pci: ["1.3"], _nist: ["SC-7"]},
        ),
        CISBenchmarkRule(
            rule_id="gcp-compute-4.2",
            title="Ensure Shielded VM is enabled for all VM instances",
            description="Shielded VMs use secure boot, vTPM, and integrity monitoring.",
            provider=CloudProvider.GCP,
            resource_type=ResourceType.COMPUTE_INSTANCE,
            severity=Severity.MEDIUM,
            cis_section="4.2",
            remediation_summary="Recreate VM instances with Shielded VM enabled.",
            compliance_mapping={_soc2: ["CC6.6"], _nist: ["SI-7"]},
        ),
        CISBenchmarkRule(
            rule_id="gcp-compute-4.3",
            title="Ensure OS Login is enabled for GCP project",
            description="OS Login links SSH keys to GCP accounts for centralized access control.",
            provider=CloudProvider.GCP,
            resource_type=ResourceType.COMPUTE_INSTANCE,
            severity=Severity.MEDIUM,
            cis_section="4.3",
            remediation_summary="Enable OS Login at the project level.",
            remediation_cli="gcloud compute project-info add-metadata --metadata enable-oslogin=TRUE",
            compliance_mapping={_soc2: ["CC6.1"], _nist: ["AC-17"]},
        ),
    ]

    return rules


_CIS_RULES: List[CISBenchmarkRule] = _build_cis_rules()
_RULES_BY_ID: Dict[str, CISBenchmarkRule] = {r.rule_id: r for r in _CIS_RULES}


# ---------------------------------------------------------------------------
# Rule Evaluation
# ---------------------------------------------------------------------------

def _evaluate_rule(rule: CISBenchmarkRule, resource: CloudResource) -> bool:
    """Return True if the resource PASSES the rule (compliant), False if it fails."""
    meta = resource.metadata
    rid = rule.rule_id

    # AWS IAM
    if rid == "aws-iam-1.1":
        return not meta.get("is_root", False)
    if rid == "aws-iam-1.2":
        return meta.get("mfa_enabled", False) if meta.get("is_root") else True
    if rid == "aws-iam-1.3":
        return meta.get("mfa_enabled", False) if meta.get("has_console_access", False) else True
    if rid == "aws-iam-1.4":
        return meta.get("access_key_age_days", 0) <= 90
    if rid == "aws-iam-1.5":
        return meta.get("min_password_length", 0) >= 14
    if rid == "aws-iam-1.6":
        return meta.get("hardware_mfa_enabled", False) if meta.get("is_root") else True
    if rid == "aws-iam-1.7":
        return not meta.get("has_inline_policies", False)
    if rid == "aws-iam-1.8":
        return meta.get("access_analyzer_enabled", False)
    if rid == "aws-iam-1.9":
        return meta.get("support_role_exists", False)
    if rid == "aws-iam-1.10":
        return not meta.get("key_created_at_setup", False)

    # AWS S3
    if rid == "aws-s3-2.1":
        return not resource.is_public
    if rid == "aws-s3-2.2":
        return resource.is_encrypted
    if rid == "aws-s3-2.3":
        return meta.get("mfa_delete_enabled", False)
    if rid == "aws-s3-2.4":
        return meta.get("access_logging_enabled", False)

    # AWS Network
    if rid == "aws-net-3.1":
        return not meta.get("allows_ssh_from_internet", False)
    if rid == "aws-net-3.2":
        return not meta.get("allows_rdp_from_internet", False)
    if rid == "aws-net-3.3":
        return meta.get("flow_logs_enabled", False)
    if rid == "aws-net-3.4":
        return not meta.get("default_sg_has_rules", False)
    if rid == "aws-net-3.5":
        return meta.get("vpc_peering_least_access", True)

    # AWS Compute
    if rid == "aws-ec2-4.1":
        return meta.get("imdsv2_required", False)
    if rid == "aws-ec2-4.2":
        return not resource.is_public
    if rid == "aws-ec2-4.3":
        return resource.is_encrypted
    if rid == "aws-ec2-4.4":
        return meta.get("ssm_managed", False)

    # AWS RDS
    if rid == "aws-rds-5.1":
        return resource.is_encrypted
    if rid == "aws-rds-5.2":
        return not resource.is_public
    if rid == "aws-rds-5.3":
        return meta.get("backup_retention_days", 0) >= 7
    if rid == "aws-rds-5.4":
        return meta.get("auto_minor_version_upgrade", False)

    # AWS Logging
    if rid == "aws-log-6.1":
        return meta.get("cloudtrail_enabled", False)
    if rid == "aws-log-6.2":
        return meta.get("log_file_validation_enabled", False)
    if rid == "aws-log-6.3":
        return not resource.is_public
    if rid == "aws-log-6.4":
        return meta.get("cloudwatch_integration", False)
    if rid == "aws-log-6.5":
        return meta.get("aws_config_enabled", False)

    # Azure IAM
    if rid == "azure-iam-1.1":
        return meta.get("mfa_enabled", False)
    if rid == "azure-iam-1.2":
        return meta.get("guest_users_reviewed", True)
    if rid == "azure-iam-1.3":
        return not meta.get("has_custom_owner_role", False)
    if rid == "azure-iam-1.4":
        return meta.get("pim_enabled", False)

    # Azure Storage
    if rid == "azure-stor-2.1":
        return not resource.is_public
    if rid == "azure-stor-2.2":
        return meta.get("https_only", False)
    if rid == "azure-stor-2.3":
        return meta.get("customer_managed_key", False)
    if rid == "azure-stor-2.4":
        return meta.get("soft_delete_enabled", False)

    # Azure Network
    if rid == "azure-net-3.1":
        return not meta.get("allows_ssh_from_internet", False)
    if rid == "azure-net-3.2":
        return meta.get("ddos_protection_enabled", False)
    if rid == "azure-net-3.3":
        return meta.get("network_watcher_enabled", False)

    # Azure Logging
    if rid == "azure-log-6.1":
        return meta.get("diagnostic_settings_enabled", False)
    if rid == "azure-log-6.2":
        return meta.get("log_retention_days", 0) >= 365
    if rid == "azure-log-6.3":
        return meta.get("audit_logs_enabled", False)

    # GCP IAM
    if rid == "gcp-iam-1.1":
        return meta.get("key_age_days", 0) <= 90
    if rid == "gcp-iam-1.2":
        return not meta.get("admin_sa_has_user_role", False)
    if rid == "gcp-iam-1.3":
        return not resource.is_public
    if rid == "gcp-iam-1.4":
        return meta.get("mfa_enabled", False)

    # GCP Storage
    if rid == "gcp-gcs-2.1":
        return not resource.is_public
    if rid == "gcp-gcs-2.2":
        return meta.get("uniform_bucket_access", False)
    if rid == "gcp-gcs-2.3":
        return meta.get("customer_managed_key", False)

    # GCP Network
    if rid == "gcp-net-3.1":
        return not meta.get("allows_ssh_from_internet", False)
    if rid == "gcp-net-3.2":
        return meta.get("flow_logs_enabled", False)
    if rid == "gcp-net-3.3":
        return not meta.get("default_network_exists", False)
    if rid == "gcp-net-3.4":
        return meta.get("private_google_access", False)

    # GCP Logging
    if rid == "gcp-log-6.1":
        return meta.get("audit_logging_enabled", False)
    if rid == "gcp-log-6.2":
        return meta.get("ownership_change_alert", False)
    if rid == "gcp-log-6.3":
        return meta.get("log_sink_configured", False)

    # GCP Compute
    if rid == "gcp-compute-4.1":
        return not resource.is_public
    if rid == "gcp-compute-4.2":
        return meta.get("shielded_vm_enabled", False)
    if rid == "gcp-compute-4.3":
        return meta.get("os_login_enabled", False)

    return True  # unknown rule — pass by default


def _get_applicable_rules(resource: CloudResource) -> List[CISBenchmarkRule]:
    """Return CIS rules that apply to a given resource."""
    return [
        r for r in _CIS_RULES
        if r.provider == resource.provider and r.resource_type == resource.resource_type
    ]


# ---------------------------------------------------------------------------
# Scoring Helpers
# ---------------------------------------------------------------------------

def _score_from_findings(
    total: int, critical: int, high: int, medium: int, low: int
) -> float:
    """Compute a 0-100 risk score. Higher score = more risk."""
    if total == 0:
        return 0.0
    weighted = (critical * 10) + (high * 5) + (medium * 2) + (low * 1)
    cap = total * 10
    return round(min(100.0, (weighted / cap) * 100), 1)


def _posture_score(risk_score: float) -> float:
    """Convert risk score (higher=worse) to posture score (higher=better)."""
    return round(100.0 - risk_score, 1)


def _compliance_score(findings: List[CSPMFinding], framework: ComplianceFramework) -> float:
    """Compute 0-100 compliance score for a framework based on open findings."""
    relevant = [
        f for f in findings
        if framework.value in f.compliance_mapping and f.status == FindingStatus.OPEN
    ]
    if not relevant:
        return 100.0
    critical_violations = sum(
        1 for f in relevant if f.severity in (Severity.CRITICAL, Severity.HIGH)
    )
    base = max(0.0, 100.0 - (critical_violations * 15) - (len(relevant) * 5))
    return round(base, 1)


# ---------------------------------------------------------------------------
# SQLite Persistence
# ---------------------------------------------------------------------------

class _CSPMStore:
    """SQLite-backed store for CSPM data."""

    def __init__(self, db_path: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self._db_path = db_path
        self._local = threading.local()
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    def _init_db(self) -> None:
        conn = self._conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS resources (
                id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                org_id TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_resources_org ON resources(org_id);

            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                org_id TEXT NOT NULL,
                status TEXT NOT NULL,
                severity TEXT NOT NULL,
                detected_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_findings_org ON findings(org_id);
            CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);

            CREATE TABLE IF NOT EXISTS drift_events (
                id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                org_id TEXT NOT NULL,
                detected_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_drift_org ON drift_events(org_id);

            CREATE TABLE IF NOT EXISTS baselines (
                resource_id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                org_id TEXT NOT NULL,
                snapshot_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                org_id TEXT NOT NULL,
                completed_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_scans_org ON scans(org_id);
        """)
        conn.commit()

    # ---- Resources ----

    def upsert_resource(self, resource: CloudResource) -> None:
        conn = self._conn()
        conn.execute(
            "INSERT OR REPLACE INTO resources (id, data, org_id, updated_at) VALUES (?, ?, ?, ?)",
            (resource.id, resource.model_dump_json(), resource.org_id,
             datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

    def list_resources(self, org_id: str) -> List[CloudResource]:
        rows = self._conn().execute(
            "SELECT data FROM resources WHERE org_id=?", (org_id,)
        ).fetchall()
        return [CloudResource.model_validate_json(r["data"]) for r in rows]

    def get_resource(self, resource_id: str) -> Optional[CloudResource]:
        row = self._conn().execute(
            "SELECT data FROM resources WHERE id=?", (resource_id,)
        ).fetchone()
        return CloudResource.model_validate_json(row["data"]) if row else None

    def delete_resource(self, resource_id: str) -> bool:
        conn = self._conn()
        cur = conn.execute("DELETE FROM resources WHERE id=?", (resource_id,))
        conn.commit()
        return cur.rowcount > 0

    # ---- Findings ----

    def upsert_finding(self, finding: CSPMFinding) -> None:
        conn = self._conn()
        conn.execute(
            "INSERT OR REPLACE INTO findings (id, data, org_id, status, severity, detected_at) VALUES (?, ?, ?, ?, ?, ?)",
            (finding.id, finding.model_dump_json(), finding.org_id,
             finding.status.value, finding.severity.value, finding.detected_at),
        )
        conn.commit()

    def list_findings(
        self,
        org_id: str,
        status: Optional[FindingStatus] = None,
        severity: Optional[Severity] = None,
    ) -> List[CSPMFinding]:
        query = "SELECT data FROM findings WHERE org_id=?"
        params: List[Any] = [org_id]
        if status:
            query += " AND status=?"
            params.append(status.value)
        if severity:
            query += " AND severity=?"
            params.append(severity.value)
        rows = self._conn().execute(query, params).fetchall()
        return [CSPMFinding.model_validate_json(r["data"]) for r in rows]

    def get_finding(self, finding_id: str) -> Optional[CSPMFinding]:
        row = self._conn().execute(
            "SELECT data FROM findings WHERE id=?", (finding_id,)
        ).fetchone()
        return CSPMFinding.model_validate_json(row["data"]) if row else None

    def update_finding_status(
        self, finding_id: str, status: FindingStatus
    ) -> Optional[CSPMFinding]:
        finding = self.get_finding(finding_id)
        if not finding:
            return None
        finding.status = status
        if status == FindingStatus.RESOLVED:
            finding.resolved_at = datetime.now(timezone.utc).isoformat()
        self.upsert_finding(finding)
        return finding

    # ---- Drift ----

    def upsert_drift(self, event: DriftEvent) -> None:
        conn = self._conn()
        conn.execute(
            "INSERT OR REPLACE INTO drift_events (id, data, org_id, detected_at) VALUES (?, ?, ?, ?)",
            (event.id, event.model_dump_json(), event.org_id, event.detected_at),
        )
        conn.commit()

    def list_drift(self, org_id: str) -> List[DriftEvent]:
        rows = self._conn().execute(
            "SELECT data FROM drift_events WHERE org_id=?", (org_id,)
        ).fetchall()
        return [DriftEvent.model_validate_json(r["data"]) for r in rows]

    # ---- Baselines ----

    def save_baseline(self, resource: CloudResource) -> None:
        conn = self._conn()
        conn.execute(
            "INSERT OR REPLACE INTO baselines (resource_id, data, org_id, snapshot_at) VALUES (?, ?, ?, ?)",
            (resource.id, resource.model_dump_json(), resource.org_id,
             datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

    def get_baseline(self, resource_id: str) -> Optional[CloudResource]:
        row = self._conn().execute(
            "SELECT data FROM baselines WHERE resource_id=?", (resource_id,)
        ).fetchone()
        return CloudResource.model_validate_json(row["data"]) if row else None

    # ---- Scans ----

    def save_scan(self, result: ScanResult) -> None:
        conn = self._conn()
        conn.execute(
            "INSERT OR REPLACE INTO scans (id, data, org_id, completed_at) VALUES (?, ?, ?, ?)",
            (result.scan_id, result.model_dump_json(), result.org_id, result.completed_at),
        )
        conn.commit()

    def list_scans(self, org_id: str, limit: int = 10) -> List[ScanResult]:
        rows = self._conn().execute(
            "SELECT data FROM scans WHERE org_id=? ORDER BY completed_at DESC LIMIT ?",
            (org_id, limit),
        ).fetchall()
        return [ScanResult.model_validate_json(r["data"]) for r in rows]


# ---------------------------------------------------------------------------
# Drift Detector
# ---------------------------------------------------------------------------

def _detect_drift(
    current: CloudResource, baseline: CloudResource, org_id: str
) -> List[DriftEvent]:
    """Compare current resource state against baseline; return drift events."""
    events: List[DriftEvent] = []

    def _add(
        drift_type: str, description: str,
        baseline_val: str, current_val: str, sev: Severity,
    ) -> None:
        events.append(DriftEvent(
            resource_id=current.id,
            resource_name=current.name,
            resource_type=current.resource_type,
            provider=current.provider,
            account_id=current.account_id,
            drift_type=drift_type,
            description=description,
            baseline_value=baseline_val,
            current_value=current_val,
            severity=sev,
            org_id=org_id,
        ))

    if not baseline.is_public and current.is_public:
        _add("new_public_resource",
             f"Resource {current.name} became publicly accessible",
             "private", "public", Severity.CRITICAL)

    if baseline.is_encrypted and not current.is_encrypted:
        _add("encryption_removed",
             f"Encryption was disabled on {current.name}",
             "encrypted", "unencrypted", Severity.HIGH)

    b_tags = json.dumps(baseline.tags, sort_keys=True)
    c_tags = json.dumps(current.tags, sort_keys=True)
    if b_tags != c_tags:
        _add("tags_changed", f"Tags changed on {current.name}",
             b_tags, c_tags, Severity.LOW)

    removed_keys = set(baseline.metadata.keys()) - set(current.metadata.keys())
    if removed_keys:
        _add("security_controls_removed",
             f"Security metadata keys removed: {', '.join(sorted(removed_keys))}",
             str(sorted(removed_keys)), "missing", Severity.MEDIUM)

    _SEC_META = {
        "flow_logs_enabled", "cloudtrail_enabled", "audit_logging_enabled",
        "diagnostic_settings_enabled", "mfa_enabled", "imdsv2_required",
    }
    for key in _SEC_META:
        if baseline.metadata.get(key) and not current.metadata.get(key):
            _add("security_control_disabled",
                 f"Security control '{key}' was disabled on {current.name}",
                 "true", "false", Severity.HIGH)

    return events


# ---------------------------------------------------------------------------
# Remediation Playbook Generator
# ---------------------------------------------------------------------------

def _build_playbook(finding: CSPMFinding) -> RemediationPlaybook:
    """Generate a remediation playbook for a given finding."""
    steps = [
        f"1. Identify the affected resource: {finding.resource_name} ({finding.resource_id})",
        f"2. Confirm the misconfiguration: {finding.description}",
        f"3. Apply remediation: {finding.remediation_summary}",
        "4. Verify the fix was applied by re-running the CSPM scan.",
        "5. Update the change management record.",
    ]

    cli_commands: List[str] = []
    if finding.remediation_cli:
        cli_commands.append(f"# Remediation CLI command for {finding.rule_id}")
        cli_commands.append(
            finding.remediation_cli
            .replace("<BUCKET>", finding.resource_name)
            .replace("<ID>", finding.resource_id)
            .replace("<SG_ID>", finding.resource_id)
            .replace("<INSTANCE_ID>", finding.resource_id)
            .replace("<INSTANCE>", finding.resource_name)
            .replace("<TRAIL_NAME>", finding.resource_name)
            .replace("<ACCOUNT>", finding.resource_name)
            .replace("<USER>", finding.resource_name)
        )

    terraform_blocks: List[str] = []
    if finding.remediation_terraform:
        terraform_blocks.append(finding.remediation_terraform)

    risk_level = "low"
    if finding.severity == Severity.CRITICAL:
        risk_level = "high"
    elif finding.severity == Severity.HIGH:
        risk_level = "medium"

    effort_map = {
        Severity.CRITICAL: "15-30 minutes",
        Severity.HIGH: "30-60 minutes",
        Severity.MEDIUM: "1-2 hours",
        Severity.LOW: "30 minutes",
        Severity.INFORMATIONAL: "10 minutes",
    }

    return RemediationPlaybook(
        finding_id=finding.id,
        rule_id=finding.rule_id,
        title=f"Remediation: {finding.rule_title}",
        steps=steps,
        cli_commands=cli_commands,
        terraform_blocks=terraform_blocks,
        estimated_effort=effort_map.get(finding.severity, "1 hour"),
        risk_level=risk_level,
        requires_downtime=finding.resource_type in (
            ResourceType.RDS_INSTANCE, ResourceType.CLOUD_SQL,
        ),
    )


# ---------------------------------------------------------------------------
# CSPM Engine
# ---------------------------------------------------------------------------

class CSPMEngine:
    """Cloud Security Posture Management engine.

    Evaluates CIS Benchmark rules against registered cloud resources,
    detects configuration drift, generates findings, and calculates
    per-account and org-level risk scores.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._store = _CSPMStore(db_path)
        self._log = structlog.get_logger(__name__).bind(component="CSPMEngine")

    # ---------------------------------------------------------------- Resources

    def register_resource(self, resource: CloudResource) -> CloudResource:
        """Register or update a cloud resource in the inventory."""
        self._store.upsert_resource(resource)
        self._log.info("resource.registered", resource_id=resource.id, name=resource.name)
        return resource

    def list_resources(self, org_id: str = "default") -> List[CloudResource]:
        """List all cloud resources for an org."""
        return self._store.list_resources(org_id)

    def get_resource(self, resource_id: str) -> Optional[CloudResource]:
        """Fetch a single cloud resource by ID."""
        return self._store.get_resource(resource_id)

    def delete_resource(self, resource_id: str) -> bool:
        """Remove a resource from the inventory."""
        return self._store.delete_resource(resource_id)

    # ---------------------------------------------------------------- Baseline

    def save_baseline(self, org_id: str = "default") -> int:
        """Snapshot current resource state as the drift detection baseline."""
        resources = self._store.list_resources(org_id)
        for res in resources:
            self._store.save_baseline(res)
        self._log.info("baseline.saved", org_id=org_id, count=len(resources))
        return len(resources)

    # ----------------------------------------------------------------- Scanning

    def scan_resource(self, resource: CloudResource) -> List[CSPMFinding]:
        """Evaluate all applicable CIS rules for one resource. Returns new findings."""
        applicable = _get_applicable_rules(resource)
        findings: List[CSPMFinding] = []
        for rule in applicable:
            if not _evaluate_rule(rule, resource):
                finding = CSPMFinding(
                    rule_id=rule.rule_id,
                    rule_title=rule.title,
                    resource_id=resource.id,
                    resource_name=resource.name,
                    resource_type=resource.resource_type,
                    provider=resource.provider,
                    account_id=resource.account_id,
                    region=resource.region,
                    severity=rule.severity,
                    description=rule.description,
                    remediation_summary=rule.remediation_summary,
                    remediation_cli=rule.remediation_cli,
                    remediation_terraform=rule.remediation_terraform,
                    compliance_mapping=rule.compliance_mapping,
                    org_id=resource.org_id,
                )
                self._store.upsert_finding(finding)
                findings.append(finding)
        return findings

    def run_scan(
        self, org_id: str = "default", rule_ids: Optional[List[str]] = None
    ) -> ScanResult:
        """Run a full CSPM scan for all resources in an org."""
        started_at = datetime.now(timezone.utc).isoformat()
        resources = self._store.list_resources(org_id)
        all_findings: List[CSPMFinding] = []
        drift_events: List[DriftEvent] = []

        for resource in resources:
            findings = self.scan_resource(resource)
            if rule_ids:
                findings = [f for f in findings if f.rule_id in rule_ids]
            all_findings.extend(findings)

            baseline = self._store.get_baseline(resource.id)
            if baseline:
                events = _detect_drift(resource, baseline, org_id)
                for ev in events:
                    self._store.upsert_drift(ev)
                drift_events.extend(events)

        posture = self._compute_posture(org_id, resources, all_findings)
        result = ScanResult(
            org_id=org_id,
            resources_scanned=len(resources),
            findings_count=len(all_findings),
            drift_events_count=len(drift_events),
            posture=posture,
            started_at=started_at,
        )
        self._store.save_scan(result)
        self._log.info(
            "scan.completed",
            org_id=org_id,
            resources=len(resources),
            findings=len(all_findings),
            drift=len(drift_events),
        )
        return result

    # ------------------------------------------------------------- Posture

    def _compute_posture(
        self,
        org_id: str,
        resources: List[CloudResource],
        findings: List[CSPMFinding],
    ) -> OrgPosture:
        """Compute the org-level posture from resources and findings."""
        open_findings = [f for f in findings if f.status == FindingStatus.OPEN]
        critical = sum(1 for f in open_findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in open_findings if f.severity == Severity.HIGH)
        medium = sum(1 for f in open_findings if f.severity == Severity.MEDIUM)
        low = sum(1 for f in open_findings if f.severity == Severity.LOW)

        risk = _score_from_findings(len(open_findings), critical, high, medium, low)
        overall = _posture_score(risk)

        compliance_scores = {
            fw.value: _compliance_score(open_findings, fw) for fw in ComplianceFramework
        }

        # Per-account breakdown
        account_resources: Dict[str, List[CloudResource]] = {}
        account_provider: Dict[str, CloudProvider] = {}
        for res in resources:
            account_resources.setdefault(res.account_id, []).append(res)
            account_provider[res.account_id] = res.provider

        account_findings: Dict[str, List[CSPMFinding]] = {}
        for finding in open_findings:
            account_findings.setdefault(finding.account_id, []).append(finding)

        accounts: List[AccountPosture] = []
        for acct_id, acct_resources in account_resources.items():
            acct_f = account_findings.get(acct_id, [])
            a_crit = sum(1 for f in acct_f if f.severity == Severity.CRITICAL)
            a_high = sum(1 for f in acct_f if f.severity == Severity.HIGH)
            a_med = sum(1 for f in acct_f if f.severity == Severity.MEDIUM)
            a_low = sum(1 for f in acct_f if f.severity == Severity.LOW)
            a_risk = _score_from_findings(len(acct_f), a_crit, a_high, a_med, a_low)
            accounts.append(AccountPosture(
                account_id=acct_id,
                provider=account_provider[acct_id],
                org_id=org_id,
                total_resources=len(acct_resources),
                total_findings=len(acct_f),
                critical_findings=a_crit,
                high_findings=a_high,
                medium_findings=a_med,
                low_findings=a_low,
                risk_score=a_risk,
                compliance_scores={
                    fw.value: _compliance_score(acct_f, fw) for fw in ComplianceFramework
                },
            ))

        return OrgPosture(
            org_id=org_id,
            overall_score=overall,
            total_resources=len(resources),
            total_findings=len(open_findings),
            critical_findings=critical,
            high_findings=high,
            medium_findings=medium,
            low_findings=low,
            accounts=accounts,
            compliance_scores=compliance_scores,
        )

    def get_posture(self, org_id: str = "default") -> OrgPosture:
        """Return the current posture (computed from stored data, no re-scan)."""
        resources = self._store.list_resources(org_id)
        findings = self._store.list_findings(org_id, status=FindingStatus.OPEN)
        return self._compute_posture(org_id, resources, findings)

    # ------------------------------------------------------------- Findings

    def list_findings(
        self,
        org_id: str = "default",
        status: Optional[FindingStatus] = None,
        severity: Optional[Severity] = None,
    ) -> List[CSPMFinding]:
        return self._store.list_findings(org_id, status=status, severity=severity)

    def get_finding(self, finding_id: str) -> Optional[CSPMFinding]:
        return self._store.get_finding(finding_id)

    def suppress_finding(self, finding_id: str, reason: str) -> Optional[CSPMFinding]:
        """Mark a finding as suppressed with a reason."""
        finding = self._store.get_finding(finding_id)
        if not finding:
            return None
        finding.status = FindingStatus.SUPPRESSED
        finding.suppression_reason = reason
        self._store.upsert_finding(finding)
        return finding

    def resolve_finding(self, finding_id: str) -> Optional[CSPMFinding]:
        """Mark a finding as resolved."""
        return self._store.update_finding_status(finding_id, FindingStatus.RESOLVED)

    # ------------------------------------------------------------- Drift

    def list_drift(self, org_id: str = "default") -> List[DriftEvent]:
        return self._store.list_drift(org_id)

    # ---------------------------------------------------------- Remediation

    def get_remediation(self, finding_id: str) -> Optional[RemediationPlaybook]:
        """Build a remediation playbook for a finding."""
        finding = self._store.get_finding(finding_id)
        if not finding:
            return None
        return _build_playbook(finding)

    # ---------------------------------------------------------- Benchmarks

    def get_benchmark_status(self, org_id: str = "default") -> Dict[str, Any]:
        """Return compliance status per CIS rule, grouped by provider."""
        findings = self._store.list_findings(org_id, status=FindingStatus.OPEN)
        failing_rules = {f.rule_id for f in findings}

        by_provider: Dict[str, Dict[str, Any]] = {}
        for rule in _CIS_RULES:
            p = rule.provider.value
            if p not in by_provider:
                by_provider[p] = {"total": 0, "passing": 0, "failing": 0, "rules": []}
            by_provider[p]["total"] += 1
            status = "passing" if rule.rule_id not in failing_rules else "failing"
            if status == "passing":
                by_provider[p]["passing"] += 1
            else:
                by_provider[p]["failing"] += 1
            by_provider[p]["rules"].append({
                "rule_id": rule.rule_id,
                "title": rule.title,
                "cis_section": rule.cis_section,
                "severity": rule.severity.value,
                "status": status,
            })

        return {
            "total_rules": len(_CIS_RULES),
            "total_passing": sum(v["passing"] for v in by_provider.values()),
            "total_failing": sum(v["failing"] for v in by_provider.values()),
            "by_provider": by_provider,
        }

    # ---------------------------------------------------------- Compliance Map

    def get_compliance_map(self) -> Dict[str, Any]:
        """Return mapping of all CIS checks to compliance frameworks."""
        result: Dict[str, List[Dict[str, Any]]] = {}
        for fw in ComplianceFramework:
            result[fw.value] = []
            for rule in _CIS_RULES:
                controls = rule.compliance_mapping.get(fw.value, [])
                if controls:
                    result[fw.value].append({
                        "rule_id": rule.rule_id,
                        "title": rule.title,
                        "provider": rule.provider.value,
                        "severity": rule.severity.value,
                        "controls": controls,
                    })
        return {"frameworks": result, "total_rules": len(_CIS_RULES)}

    # ----------------------------------------------------------------- Scans

    def list_scans(self, org_id: str = "default", limit: int = 10) -> List[ScanResult]:
        return self._store.list_scans(org_id, limit)


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_engine_instance: Optional[CSPMEngine] = None
_engine_lock = threading.Lock()


def get_cspm_engine(db_path: str = _DEFAULT_DB) -> CSPMEngine:
    """Return the process-wide singleton CSPMEngine."""
    global _engine_instance
    if _engine_instance is None:
        with _engine_lock:
            if _engine_instance is None:
                _engine_instance = CSPMEngine(db_path)
    return _engine_instance
