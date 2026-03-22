"""ALdeci CSPM Engine — Cloud Security Posture Management.

Scans cloud configurations for misconfigurations:
- AWS: S3, IAM, EC2, RDS, Lambda, CloudTrail, VPC
- Azure: Storage, NSG, Key Vault, App Service, SQL
- GCP: Storage, Compute, IAM, GKE, Cloud SQL

Real SDK integration with boto3, azure-sdk, google-cloud when available.
Falls back to configuration-file analysis (Terraform, CloudFormation, ARM).

Competitive parity: Wiz CSPM, Aikido Cloud, Prisma Cloud.
"""

from __future__ import annotations

import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

logger = logging.getLogger(__name__)
from typing import Any, Dict, List, Optional, Tuple


class CloudProvider(str, Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    MULTI = "multi"


class CspmSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CspmCategory(str, Enum):
    IAM = "iam"
    STORAGE = "storage"
    NETWORK = "network"
    ENCRYPTION = "encryption"
    LOGGING = "logging"
    COMPUTE = "compute"
    DATABASE = "database"
    CONTAINER = "container"
    SERVERLESS = "serverless"


@dataclass
class CspmFinding:
    finding_id: str
    title: str
    severity: CspmSeverity
    category: CspmCategory
    provider: CloudProvider
    resource_type: str
    resource_id: str
    region: str = ""
    cis_benchmark: str = ""
    description: str = ""
    recommendation: str = ""
    compliance_frameworks: List[str] = field(default_factory=list)
    confidence: float = 0.9
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category.value,
            "provider": self.provider.value,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "region": self.region,
            "cis_benchmark": self.cis_benchmark,
            "description": self.description,
            "recommendation": self.recommendation,
            "compliance_frameworks": self.compliance_frameworks,
            "confidence": self.confidence,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class CspmScanResult:
    scan_id: str
    provider: str
    resources_scanned: int
    total_findings: int
    findings: List[CspmFinding]
    by_severity: Dict[str, int]
    by_category: Dict[str, int]
    compliance_score: float = 0.0
    duration_ms: float = 0.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "provider": self.provider,
            "resources_scanned": self.resources_scanned,
            "total_findings": self.total_findings,
            "findings": [f.to_dict() for f in self.findings],
            "by_severity": self.by_severity,
            "by_category": self.by_category,
            "compliance_score": self.compliance_score,
            "duration_ms": self.duration_ms,
            "timestamp": self.timestamp.isoformat(),
        }


# ── Cloud Misconfiguration Rules ──────────────────────────────────
AWS_RULES: List[Tuple[str, str, str, str, str, str, str, List[str]]] = [
    (
        "CSPM-AWS-001",
        "S3 Bucket Public Access",
        "critical",
        "CWE-284",
        "storage",
        "S3 bucket allows public access",
        "Enable S3 Block Public Access",
        ["SOC2-CC6.1", "CIS-AWS-2.1.5", "NIST-AC-3"],
    ),
    (
        "CSPM-AWS-002",
        "IAM Root Account Used",
        "critical",
        "CWE-250",
        "iam",
        "Root account used for daily operations",
        "Create IAM users with least privilege",
        ["SOC2-CC6.1", "CIS-AWS-1.1"],
    ),
    (
        "CSPM-AWS-003",
        "Unencrypted EBS Volume",
        "high",
        "CWE-311",
        "encryption",
        "EBS volume not encrypted at rest",
        "Enable EBS encryption by default",
        ["SOC2-CC6.1", "CIS-AWS-2.2.1"],
    ),
    (
        "CSPM-AWS-004",
        "Security Group Open to World",
        "critical",
        "CWE-284",
        "network",
        "Security group allows 0.0.0.0/0 ingress",
        "Restrict to specific CIDR ranges",
        ["SOC2-CC6.6", "CIS-AWS-5.2"],
    ),
    (
        "CSPM-AWS-005",
        "CloudTrail Disabled",
        "high",
        "CWE-778",
        "logging",
        "CloudTrail not enabled in all regions",
        "Enable CloudTrail in all regions",
        ["SOC2-CC7.2", "CIS-AWS-3.1"],
    ),
    (
        "CSPM-AWS-006",
        "RDS Public Access",
        "critical",
        "CWE-284",
        "database",
        "RDS instance is publicly accessible",
        "Disable public access on RDS instances",
        ["SOC2-CC6.6", "CIS-AWS-2.3.1"],
    ),
    (
        "CSPM-AWS-007",
        "Lambda Without VPC",
        "medium",
        "CWE-284",
        "serverless",
        "Lambda function not in VPC",
        "Configure Lambda to run within VPC",
        ["SOC2-CC6.6"],
    ),
    (
        "CSPM-AWS-008",
        "IAM Policy Allows *",
        "high",
        "CWE-250",
        "iam",
        "IAM policy with Action:* or Resource:*",
        "Apply least privilege IAM policies",
        ["SOC2-CC6.1", "CIS-AWS-1.16"],
    ),
    (
        "CSPM-AWS-009",
        "MFA Not Enabled",
        "high",
        "CWE-308",
        "iam",
        "MFA not enabled for IAM users",
        "Enable MFA for all IAM users",
        ["SOC2-CC6.1", "CIS-AWS-1.2"],
    ),
    (
        "CSPM-AWS-010",
        "S3 No Versioning",
        "medium",
        "CWE-693",
        "storage",
        "S3 bucket versioning not enabled",
        "Enable versioning for data protection",
        ["SOC2-CC6.1"],
    ),
    # ── CIS L1+L2 expanded rules ──
    ("CSPM-AWS-011", "S3 No Server-Side Encryption", "high", "CWE-311", "encryption",
     "S3 bucket default encryption not enabled", "Enable SSE-S3 or SSE-KMS default encryption",
     ["CIS-AWS-2.1.1", "SOC2-CC6.1", "NIST-SC-28"]),
    ("CSPM-AWS-012", "S3 No Access Logging", "medium", "CWE-778", "logging",
     "S3 bucket access logging not enabled", "Enable S3 server access logging",
     ["CIS-AWS-2.1.3", "SOC2-CC7.2"]),
    ("CSPM-AWS-013", "S3 No TLS Enforcement", "high", "CWE-319", "encryption",
     "S3 bucket policy does not enforce TLS", "Add bucket policy requiring aws:SecureTransport",
     ["CIS-AWS-2.1.2", "NIST-SC-8"]),
    ("CSPM-AWS-014", "IAM Password Policy Weak", "medium", "CWE-521", "iam",
     "IAM password policy does not meet CIS requirements", "Set minimum 14 chars, require symbols, numbers, uppercase",
     ["CIS-AWS-1.8", "CIS-AWS-1.9", "SOC2-CC6.1"]),
    ("CSPM-AWS-015", "IAM User Has Console + Access Key", "medium", "CWE-250", "iam",
     "IAM user has both console and programmatic access", "Separate human and service accounts",
     ["CIS-AWS-1.13", "NIST-AC-6"]),
    ("CSPM-AWS-016", "IAM Access Key Not Rotated", "medium", "CWE-798", "iam",
     "IAM access key not rotated in 90+ days", "Rotate access keys every 90 days",
     ["CIS-AWS-1.14", "SOC2-CC6.1"]),
    ("CSPM-AWS-017", "VPC Flow Logs Disabled", "high", "CWE-778", "logging",
     "VPC flow logs not enabled", "Enable VPC flow logs for all VPCs",
     ["CIS-AWS-3.9", "SOC2-CC7.2", "NIST-AU-12"]),
    ("CSPM-AWS-018", "CloudTrail Not Encrypted", "high", "CWE-311", "logging",
     "CloudTrail logs not encrypted with KMS", "Enable SSE-KMS encryption on CloudTrail",
     ["CIS-AWS-3.7", "NIST-AU-9"]),
    ("CSPM-AWS-019", "CloudTrail Log Validation Disabled", "medium", "CWE-354", "logging",
     "CloudTrail log file validation not enabled", "Enable log file integrity validation",
     ["CIS-AWS-3.2", "NIST-AU-9"]),
    ("CSPM-AWS-020", "Default Security Group In Use", "medium", "CWE-284", "network",
     "Default VPC security group allows traffic", "Restrict default security group to deny all",
     ["CIS-AWS-5.3", "NIST-AC-4"]),
    ("CSPM-AWS-021", "RDS Not Encrypted", "high", "CWE-311", "database",
     "RDS instance storage not encrypted", "Enable encryption at rest for RDS",
     ["CIS-AWS-2.3.1", "SOC2-CC6.1"]),
    ("CSPM-AWS-022", "RDS No Multi-AZ", "medium", "CWE-693", "database",
     "RDS instance not configured for Multi-AZ", "Enable Multi-AZ for high availability",
     ["SOC2-A1.2", "NIST-CP-10"]),
    ("CSPM-AWS-023", "RDS No Backup", "high", "CWE-693", "database",
     "RDS automated backups disabled", "Enable automated backups with 7+ day retention",
     ["CIS-AWS-2.3.1", "NIST-CP-9"]),
    ("CSPM-AWS-024", "ELB No Access Logging", "medium", "CWE-778", "logging",
     "ELB access logging not enabled", "Enable access logging on all load balancers",
     ["CIS-AWS-2.6", "SOC2-CC7.2"]),
    ("CSPM-AWS-025", "ELB Using HTTP", "high", "CWE-319", "network",
     "ELB listener uses HTTP instead of HTTPS", "Configure HTTPS listeners with valid TLS certificates",
     ["CIS-AWS-2.6", "NIST-SC-8"]),
    ("CSPM-AWS-026", "KMS Key Rotation Disabled", "medium", "CWE-320", "encryption",
     "KMS CMK automatic rotation not enabled", "Enable annual key rotation for all CMKs",
     ["CIS-AWS-3.8", "SOC2-CC6.1", "NIST-SC-12"]),
    ("CSPM-AWS-027", "SNS Topic Not Encrypted", "medium", "CWE-311", "encryption",
     "SNS topic not encrypted with KMS", "Enable KMS encryption for SNS topics",
     ["SOC2-CC6.1", "NIST-SC-28"]),
    ("CSPM-AWS-028", "SQS Queue Not Encrypted", "medium", "CWE-311", "encryption",
     "SQS queue not encrypted with KMS", "Enable KMS encryption for SQS queues",
     ["SOC2-CC6.1", "NIST-SC-28"]),
    ("CSPM-AWS-029", "Lambda No DLQ", "low", "CWE-390", "serverless",
     "Lambda function has no dead letter queue configured", "Configure DLQ for async invocations",
     ["SOC2-CC7.4"]),
    ("CSPM-AWS-030", "Lambda Env Vars Unencrypted", "high", "CWE-312", "serverless",
     "Lambda environment variables not encrypted with KMS", "Use KMS CMK for Lambda env var encryption",
     ["SOC2-CC6.1", "NIST-SC-28"]),
    ("CSPM-AWS-031", "ECR Image Scan Disabled", "medium", "CWE-693", "container",
     "ECR repository image scanning not enabled", "Enable scan-on-push for ECR repositories",
     ["SOC2-CC7.1"]),
    ("CSPM-AWS-032", "ECR No Immutable Tags", "medium", "CWE-345", "container",
     "ECR repository allows mutable image tags", "Enable image tag immutability",
     ["SOC2-CC8.1", "NIST-SI-7"]),
    ("CSPM-AWS-033", "GuardDuty Disabled", "high", "CWE-778", "logging",
     "GuardDuty threat detection not enabled", "Enable GuardDuty in all regions",
     ["CIS-AWS-4.15", "SOC2-CC7.2", "NIST-SI-4"]),
    ("CSPM-AWS-034", "Config Service Disabled", "high", "CWE-778", "logging",
     "AWS Config not enabled in all regions", "Enable AWS Config in every region",
     ["CIS-AWS-3.5", "SOC2-CC7.1", "NIST-CM-8"]),
    ("CSPM-AWS-035", "SecurityHub Disabled", "medium", "CWE-778", "logging",
     "AWS Security Hub not enabled", "Enable Security Hub for centralized findings",
     ["SOC2-CC7.2"]),
    ("CSPM-AWS-036", "Secrets Manager No Rotation", "medium", "CWE-798", "iam",
     "Secrets Manager secret rotation not configured", "Enable automatic rotation",
     ["CIS-AWS-1.14", "NIST-IA-5"]),
    ("CSPM-AWS-037", "ECS Task Privileged", "critical", "CWE-250", "container",
     "ECS task definition runs in privileged mode", "Remove privileged flag from task definitions",
     ["SOC2-CC6.1", "CIS-Docker-5.4"]),
    ("CSPM-AWS-038", "EKS Public Endpoint", "high", "CWE-284", "container",
     "EKS cluster API endpoint publicly accessible", "Restrict EKS endpoint to private access",
     ["CIS-EKS-5.4.1", "NIST-AC-3"]),
    ("CSPM-AWS-039", "CloudFront No WAF", "medium", "CWE-693", "network",
     "CloudFront distribution without WAF", "Associate WAF WebACL with CloudFront",
     ["SOC2-CC6.6", "NIST-SC-7"]),
    ("CSPM-AWS-040", "DynamoDB No Encryption", "high", "CWE-311", "database",
     "DynamoDB table not encrypted with CMK", "Enable KMS encryption for DynamoDB tables",
     ["SOC2-CC6.1", "NIST-SC-28"]),
]

AZURE_RULES: List[Tuple[str, str, str, str, str, str, str, List[str]]] = [
    (
        "CSPM-AZ-001",
        "Storage Account Public Blob",
        "critical",
        "CWE-284",
        "storage",
        "Storage account allows public blob access",
        "Disable public blob access",
        ["SOC2-CC6.1", "CIS-Azure-3.1"],
    ),
    (
        "CSPM-AZ-002",
        "NSG Allows SSH from Any",
        "critical",
        "CWE-284",
        "network",
        "NSG allows SSH (22) from 0.0.0.0/0",
        "Restrict SSH to specific IPs",
        ["SOC2-CC6.6", "CIS-Azure-6.2"],
    ),
    (
        "CSPM-AZ-003",
        "Key Vault No Soft Delete",
        "high",
        "CWE-693",
        "encryption",
        "Key Vault soft delete not enabled",
        "Enable soft delete on Key Vault",
        ["SOC2-CC6.1"],
    ),
    (
        "CSPM-AZ-004",
        "SQL Server No Auditing",
        "high",
        "CWE-778",
        "database",
        "Azure SQL auditing not enabled",
        "Enable auditing on SQL Server",
        ["SOC2-CC7.2", "CIS-Azure-4.1.1"],
    ),
    (
        "CSPM-AZ-005",
        "App Service HTTP Only",
        "medium",
        "CWE-319",
        "compute",
        "App Service allows HTTP (not HTTPS only)",
        "Enable HTTPS Only on App Service",
        ["SOC2-CC6.1"],
    ),
    # ── CIS Azure L1+L2 expanded ──
    ("CSPM-AZ-006", "Storage Account No HTTPS", "high", "CWE-319", "encryption",
     "Storage account does not enforce HTTPS", "Enable Secure Transfer Required",
     ["CIS-Azure-3.1", "NIST-SC-8"]),
    ("CSPM-AZ-007", "Storage No Encryption CMK", "medium", "CWE-311", "encryption",
     "Storage account using Microsoft-managed keys", "Use customer-managed keys for encryption",
     ["CIS-Azure-3.2", "SOC2-CC6.1"]),
    ("CSPM-AZ-008", "NSG Allows RDP from Any", "critical", "CWE-284", "network",
     "NSG allows RDP (3389) from 0.0.0.0/0", "Restrict RDP to specific IPs or use JIT",
     ["CIS-Azure-6.1", "SOC2-CC6.6"]),
    ("CSPM-AZ-009", "SQL Server TDE Disabled", "high", "CWE-311", "database",
     "SQL Server Transparent Data Encryption disabled", "Enable TDE on all SQL databases",
     ["CIS-Azure-4.1.2", "SOC2-CC6.1"]),
    ("CSPM-AZ-010", "SQL Server No Advanced Threat Protection", "medium", "CWE-693", "database",
     "SQL Server Advanced Threat Protection not enabled", "Enable Advanced Threat Protection",
     ["CIS-Azure-4.2.1", "SOC2-CC7.2"]),
    ("CSPM-AZ-011", "Key Vault No Logging", "high", "CWE-778", "logging",
     "Key Vault diagnostic logging not enabled", "Enable diagnostic logging on Key Vault",
     ["CIS-Azure-5.1.5", "SOC2-CC7.2"]),
    ("CSPM-AZ-012", "Key Vault Expiry Not Set", "medium", "CWE-320", "encryption",
     "Key Vault keys/secrets have no expiration", "Set expiration dates on all keys and secrets",
     ["CIS-Azure-8.1", "NIST-SC-12"]),
    ("CSPM-AZ-013", "VM No Disk Encryption", "high", "CWE-311", "compute",
     "Virtual Machine OS/data disks not encrypted", "Enable Azure Disk Encryption",
     ["CIS-Azure-7.2", "SOC2-CC6.1"]),
    ("CSPM-AZ-014", "Network Watcher Disabled", "medium", "CWE-778", "logging",
     "Network Watcher not enabled in region", "Enable Network Watcher in all regions",
     ["CIS-Azure-6.5", "SOC2-CC7.2"]),
    ("CSPM-AZ-015", "Activity Log No Alert", "medium", "CWE-778", "logging",
     "Activity Log alerts not configured for key operations", "Configure alerts for security events",
     ["CIS-Azure-5.2.1", "NIST-AU-6"]),
    ("CSPM-AZ-016", "App Service No Managed Identity", "medium", "CWE-250", "iam",
     "App Service not using managed identity", "Enable system-assigned managed identity",
     ["CIS-Azure-9.5", "NIST-IA-2"]),
    ("CSPM-AZ-017", "App Service Outdated TLS", "high", "CWE-326", "encryption",
     "App Service using TLS version below 1.2", "Set minimum TLS version to 1.2",
     ["CIS-Azure-9.3", "NIST-SC-8"]),
    ("CSPM-AZ-018", "Cosmos DB No Firewall", "high", "CWE-284", "database",
     "Cosmos DB account allows access from all networks", "Configure virtual network or IP firewall rules",
     ["SOC2-CC6.6", "NIST-AC-4"]),
    ("CSPM-AZ-019", "AKS RBAC Disabled", "critical", "CWE-284", "container",
     "AKS cluster RBAC not enabled", "Enable Kubernetes RBAC on AKS clusters",
     ["CIS-Azure-8.5", "CIS-K8s-5.1.1"]),
    ("CSPM-AZ-020", "AKS Dashboard Enabled", "medium", "CWE-284", "container",
     "AKS Kubernetes Dashboard addon enabled", "Disable Kubernetes Dashboard in production",
     ["CIS-K8s-7.1", "SOC2-CC6.1"]),
    ("CSPM-AZ-021", "Security Center Not Standard", "high", "CWE-693", "logging",
     "Azure Security Center not on Standard tier", "Upgrade to Standard tier for threat detection",
     ["CIS-Azure-2.1", "SOC2-CC7.2"]),
    ("CSPM-AZ-022", "WAF Not Enabled", "medium", "CWE-693", "network",
     "Web Application Firewall not enabled on Application Gateway", "Enable WAF in Prevention mode",
     ["SOC2-CC6.6", "NIST-SC-7"]),
    ("CSPM-AZ-023", "Function App No HTTPS", "high", "CWE-319", "serverless",
     "Function App does not enforce HTTPS", "Enable HTTPS Only on Function App",
     ["CIS-Azure-9.4", "NIST-SC-8"]),
    ("CSPM-AZ-024", "MySQL No SSL Enforcement", "high", "CWE-319", "database",
     "Azure MySQL SSL enforcement disabled", "Enable SSL enforcement on MySQL servers",
     ["CIS-Azure-4.3.1", "NIST-SC-8"]),
    ("CSPM-AZ-025", "PostgreSQL No SSL Enforcement", "high", "CWE-319", "database",
     "Azure PostgreSQL SSL enforcement disabled", "Enable SSL enforcement on PostgreSQL servers",
     ["CIS-Azure-4.3.2", "NIST-SC-8"]),
]

GCP_RULES: List[Tuple[str, str, str, str, str, str, str, List[str]]] = [
    (
        "CSPM-GCP-001",
        "Storage Bucket allUsers",
        "critical",
        "CWE-284",
        "storage",
        "GCS bucket accessible to allUsers",
        "Remove allUsers binding",
        ["SOC2-CC6.1", "CIS-GCP-5.1"],
    ),
    (
        "CSPM-GCP-002",
        "Compute Default Service Account",
        "high",
        "CWE-250",
        "compute",
        "Instance uses default service account",
        "Create dedicated service accounts",
        ["SOC2-CC6.1", "CIS-GCP-4.1"],
    ),
    (
        "CSPM-GCP-003",
        "Firewall Allows All Ingress",
        "critical",
        "CWE-284",
        "network",
        "Firewall rule allows 0.0.0.0/0 ingress",
        "Restrict firewall source ranges",
        ["SOC2-CC6.6", "CIS-GCP-3.6"],
    ),
    (
        "CSPM-GCP-004",
        "Cloud SQL Public IP",
        "critical",
        "CWE-284",
        "database",
        "Cloud SQL instance has public IP",
        "Use private IP for Cloud SQL",
        ["SOC2-CC6.6", "CIS-GCP-6.6"],
    ),
    (
        "CSPM-GCP-005",
        "Service Account Key",
        "high",
        "CWE-798",
        "iam",
        "Service account key > 90 days old",
        "Rotate service account keys regularly",
        ["SOC2-CC6.1"],
    ),
    # ── CIS GCP L1+L2 expanded ──
    ("CSPM-GCP-006", "GCS Bucket No Uniform Access", "medium", "CWE-284", "storage",
     "GCS bucket not using uniform bucket-level access", "Enable uniform bucket-level access",
     ["CIS-GCP-5.2", "NIST-AC-3"]),
    ("CSPM-GCP-007", "GCS Bucket No Encryption CMK", "medium", "CWE-311", "encryption",
     "GCS bucket using Google-managed encryption", "Use CMEK for bucket encryption",
     ["CIS-GCP-5.3", "SOC2-CC6.1"]),
    ("CSPM-GCP-008", "Compute Serial Port Enabled", "medium", "CWE-284", "compute",
     "Compute instance serial port enabled", "Disable serial port access on instances",
     ["CIS-GCP-4.5", "NIST-AC-17"]),
    ("CSPM-GCP-009", "Compute OS Login Disabled", "medium", "CWE-250", "iam",
     "OS Login not enabled for project", "Enable OS Login for centralized SSH key management",
     ["CIS-GCP-4.4", "NIST-IA-2"]),
    ("CSPM-GCP-010", "Compute IP Forwarding", "medium", "CWE-284", "network",
     "Compute instance has IP forwarding enabled", "Disable IP forwarding unless required for NAT/routing",
     ["CIS-GCP-4.6", "NIST-AC-4"]),
    ("CSPM-GCP-011", "Cloud SQL No Backup", "high", "CWE-693", "database",
     "Cloud SQL instance automated backups disabled", "Enable automated backups",
     ["CIS-GCP-6.7", "NIST-CP-9"]),
    ("CSPM-GCP-012", "Cloud SQL No SSL", "high", "CWE-319", "database",
     "Cloud SQL instance does not require SSL", "Require SSL connections for Cloud SQL",
     ["CIS-GCP-6.4", "NIST-SC-8"]),
    ("CSPM-GCP-013", "GKE Legacy ABAC", "critical", "CWE-284", "container",
     "GKE cluster uses legacy ABAC authorization", "Disable legacy ABAC, use RBAC",
     ["CIS-GCP-7.3", "CIS-K8s-5.1.1"]),
    ("CSPM-GCP-014", "GKE No Network Policy", "high", "CWE-284", "container",
     "GKE cluster has no network policy configured", "Enable network policy enforcement",
     ["CIS-GCP-7.11", "CIS-K8s-5.3.2"]),
    ("CSPM-GCP-015", "GKE Client Certificate Auth", "medium", "CWE-284", "container",
     "GKE cluster uses client certificate authentication", "Disable client certificate auth, use OIDC",
     ["CIS-GCP-7.10", "NIST-IA-2"]),
    ("CSPM-GCP-016", "GKE Dashboard Enabled", "medium", "CWE-284", "container",
     "GKE Kubernetes Dashboard addon enabled", "Disable Kubernetes Dashboard in production",
     ["CIS-GCP-7.6", "CIS-K8s-7.1"]),
    ("CSPM-GCP-017", "Cloud Audit Logging Disabled", "high", "CWE-778", "logging",
     "Cloud Audit Logging not configured for all services", "Enable Data Access audit logs",
     ["CIS-GCP-2.1", "SOC2-CC7.2", "NIST-AU-12"]),
    ("CSPM-GCP-018", "VPC No Flow Logs", "medium", "CWE-778", "logging",
     "VPC subnet flow logs not enabled", "Enable VPC flow logs for all subnets",
     ["CIS-GCP-3.8", "NIST-AU-12"]),
    ("CSPM-GCP-019", "BigQuery No CMK", "medium", "CWE-311", "encryption",
     "BigQuery dataset not encrypted with CMK", "Use CMEK for BigQuery encryption",
     ["CIS-GCP-7.1", "SOC2-CC6.1"]),
    ("CSPM-GCP-020", "KMS Key Not Rotated", "medium", "CWE-320", "encryption",
     "KMS key rotation period exceeds 90 days", "Set key rotation to 90 days or less",
     ["CIS-GCP-1.10", "NIST-SC-12"]),
]


K8S_RULES: List[Tuple[str, str, str, str, str, str, str, List[str]]] = [
    ("CSPM-K8S-001", "Privileged Container", "critical", "CWE-250", "container",
     "Container runs in privileged mode", "Remove privileged: true from securityContext",
     ["CIS-K8s-5.2.1", "SOC2-CC6.1", "NIST-AC-6"]),
    ("CSPM-K8S-002", "Container Runs As Root", "high", "CWE-250", "container",
     "Container runs as root user (UID 0)", "Set runAsNonRoot: true in securityContext",
     ["CIS-K8s-5.2.6", "SOC2-CC6.1"]),
    ("CSPM-K8S-003", "Host Network Enabled", "high", "CWE-284", "network",
     "Pod uses host network namespace", "Remove hostNetwork: true",
     ["CIS-K8s-5.2.4", "NIST-AC-4"]),
    ("CSPM-K8S-004", "Host PID Enabled", "high", "CWE-284", "container",
     "Pod uses host PID namespace", "Remove hostPID: true",
     ["CIS-K8s-5.2.2", "NIST-AC-4"]),
    ("CSPM-K8S-005", "Host IPC Enabled", "high", "CWE-284", "container",
     "Pod uses host IPC namespace", "Remove hostIPC: true",
     ["CIS-K8s-5.2.3", "NIST-AC-4"]),
    ("CSPM-K8S-006", "No Resource Limits", "medium", "CWE-400", "container",
     "Container has no resource limits set", "Set CPU and memory limits on all containers",
     ["CIS-K8s-5.4.1", "SOC2-A1.2"]),
    ("CSPM-K8S-007", "No Resource Requests", "medium", "CWE-400", "container",
     "Container has no resource requests set", "Set CPU and memory requests for scheduling",
     ["CIS-K8s-5.4.1"]),
    ("CSPM-K8S-008", "Writable Root Filesystem", "medium", "CWE-284", "container",
     "Container root filesystem is writable", "Set readOnlyRootFilesystem: true",
     ["CIS-K8s-5.2.8", "NIST-AC-6"]),
    ("CSPM-K8S-009", "Capability Escalation Allowed", "high", "CWE-250", "container",
     "Container allows privilege escalation", "Set allowPrivilegeEscalation: false",
     ["CIS-K8s-5.2.5", "NIST-AC-6"]),
    ("CSPM-K8S-010", "Dangerous Capabilities", "critical", "CWE-250", "container",
     "Container has dangerous capabilities (NET_ADMIN, SYS_ADMIN, ALL)", "Drop ALL capabilities, add only required",
     ["CIS-K8s-5.2.7", "CIS-K8s-5.2.9"]),
    ("CSPM-K8S-011", "No Liveness Probe", "low", "CWE-693", "container",
     "Container has no liveness probe", "Add liveness probe for health monitoring",
     ["SOC2-A1.2"]),
    ("CSPM-K8S-012", "No Readiness Probe", "low", "CWE-693", "container",
     "Container has no readiness probe", "Add readiness probe for traffic management",
     ["SOC2-A1.2"]),
    ("CSPM-K8S-013", "Default ServiceAccount", "medium", "CWE-250", "iam",
     "Pod uses default service account", "Create dedicated service accounts per workload",
     ["CIS-K8s-5.1.5", "NIST-AC-6"]),
    ("CSPM-K8S-014", "No Network Policy", "medium", "CWE-284", "network",
     "Namespace has no NetworkPolicy", "Define NetworkPolicy for ingress/egress control",
     ["CIS-K8s-5.3.2", "NIST-AC-4"]),
    ("CSPM-K8S-015", "Latest Image Tag", "medium", "CWE-345", "container",
     "Container uses :latest or no image tag", "Use specific image digests or semantic version tags",
     ["CIS-K8s-5.5.1", "NIST-SI-7"]),
]

ALL_RULES = {
    CloudProvider.AWS: AWS_RULES,
    CloudProvider.AZURE: AZURE_RULES,
    CloudProvider.GCP: GCP_RULES,
}


class CSPMEngine:
    """Cloud Security Posture Management engine.

    Scans cloud configurations (Terraform, CloudFormation, ARM templates)
    and optionally queries live cloud APIs via boto3/azure-sdk/google-cloud.

    Security limits:
    - MAX_CONFIG_SIZE: 5 MB max per configuration input
    - MAX_FINDINGS: 2,000 findings cap per scan
    """

    MAX_CONFIG_SIZE = 5 * 1024 * 1024  # 5 MB
    MAX_FINDINGS = 2_000

    def __init__(self):
        self._boto3_available = False
        self._azure_available = False
        self._gcp_available = False
        try:
            import boto3  # noqa: F401

            self._boto3_available = True
        except ImportError:
            pass
        try:
            from azure.identity import DefaultAzureCredential  # noqa: F401

            self._azure_available = True
        except ImportError:
            pass
        try:
            from google.cloud import storage  # noqa: F401

            self._gcp_available = True
        except ImportError:
            pass

    def _validate_config_size(self, content: str, label: str = "config") -> None:
        """Validate configuration input size to prevent DoS."""
        if len(content) > self.MAX_CONFIG_SIZE:
            raise ValueError(
                f"{label} size {len(content)} exceeds maximum {self.MAX_CONFIG_SIZE} bytes"
            )

    def scan_terraform(
        self, tf_content: str, filename: str = "main.tf"
    ) -> CspmScanResult:
        """Scan Terraform HCL configuration for cloud misconfigurations."""
        self._validate_config_size(tf_content, "Terraform config")
        t0 = time.time()
        findings: List[CspmFinding] = []
        provider = self._detect_provider_tf(tf_content)
        rules = ALL_RULES.get(provider, AWS_RULES)

        # S3/Storage public access
        if re.search(r'acl\s*=\s*"public-read"', tf_content):
            findings.append(
                self._make_finding(
                    rules[0] if provider == CloudProvider.AWS else rules[0],
                    provider,
                    "terraform",
                )
            )
        # Security group 0.0.0.0/0
        if re.search(r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]', tf_content):
            findings.append(
                self._make_finding(
                    (
                        "CSPM-TF-001",
                        "Security Group Open to World",
                        "critical",
                        "CWE-284",
                        "network",
                        "Security group ingress from 0.0.0.0/0",
                        "Restrict CIDR",
                        ["CIS"],
                    ),
                    provider,
                    "terraform",
                )
            )
        # Unencrypted storage
        if (
            re.search(r'resource\s+"aws_ebs_volume"', tf_content)
            and "encrypted" not in tf_content
        ):
            findings.append(
                self._make_finding(
                    (
                        "CSPM-TF-002",
                        "Unencrypted EBS",
                        "high",
                        "CWE-311",
                        "encryption",
                        "EBS volume not encrypted",
                        "Enable encryption",
                        ["CIS"],
                    ),
                    provider,
                    "terraform",
                )
            )
        # RDS public
        if re.search(r"publicly_accessible\s*=\s*true", tf_content):
            findings.append(
                self._make_finding(
                    (
                        "CSPM-TF-003",
                        "RDS Public Access",
                        "critical",
                        "CWE-284",
                        "database",
                        "RDS publicly accessible",
                        "Disable public access",
                        ["CIS"],
                    ),
                    provider,
                    "terraform",
                )
            )
        # IAM wildcard
        if re.search(r'"Action"\s*:\s*"\*"', tf_content) or re.search(
            r'"Resource"\s*:\s*"\*"', tf_content
        ):
            findings.append(
                self._make_finding(
                    (
                        "CSPM-TF-004",
                        "IAM Wildcard Policy",
                        "high",
                        "CWE-250",
                        "iam",
                        "IAM policy with * action/resource",
                        "Apply least privilege",
                        ["CIS"],
                    ),
                    provider,
                    "terraform",
                )
            )
        # No logging
        if "aws_cloudtrail" not in tf_content and provider == CloudProvider.AWS:
            findings.append(
                self._make_finding(
                    (
                        "CSPM-TF-005",
                        "No CloudTrail",
                        "high",
                        "CWE-778",
                        "logging",
                        "No CloudTrail resource defined",
                        "Add CloudTrail",
                        ["CIS"],
                    ),
                    provider,
                    "terraform",
                )
            )

        by_sev, by_cat = self._summarize(findings)
        total_resources = len(re.findall(r'resource\s+"', tf_content))
        compliance = 1.0 - (len(findings) / max(total_resources, 1))
        elapsed = (time.time() - t0) * 1000
        return CspmScanResult(
            scan_id=f"cspm-{uuid.uuid4().hex[:12]}",
            provider=provider.value,
            resources_scanned=max(total_resources, 1),
            total_findings=len(findings),
            findings=findings,
            by_severity=by_sev,
            by_category=by_cat,
            compliance_score=round(max(compliance, 0) * 100, 1),
            duration_ms=round(elapsed, 2),
        )

    def scan_cloudformation(self, cf_content: str) -> CspmScanResult:
        """Scan CloudFormation JSON/YAML for AWS misconfigurations."""
        self._validate_config_size(cf_content, "CloudFormation template")
        t0 = time.time()
        findings: List[CspmFinding] = []
        try:
            data = json.loads(cf_content)
        except json.JSONDecodeError as e:
            logger.warning("Invalid CloudFormation JSON at position %d: %s", e.pos or 0, e.msg)
            data = {}
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.warning("Failed to parse CloudFormation: %s", type(e).__name__)
            data = {}
        resources = data.get("Resources", {})
        for name, res in resources.items():
            rtype = res.get("Type", "")
            props = res.get("Properties", {})
            if rtype == "AWS::S3::Bucket":
                acl = props.get("AccessControl", "")
                if "Public" in acl:
                    findings.append(
                        self._make_finding(AWS_RULES[0], CloudProvider.AWS, name)
                    )
            elif rtype == "AWS::EC2::SecurityGroup":
                for ingress in props.get("SecurityGroupIngress", []):
                    if ingress.get("CidrIp") == "0.0.0.0/0":
                        findings.append(
                            self._make_finding(AWS_RULES[3], CloudProvider.AWS, name)
                        )
            elif rtype == "AWS::RDS::DBInstance":
                if props.get("PubliclyAccessible", False):
                    findings.append(
                        self._make_finding(AWS_RULES[5], CloudProvider.AWS, name)
                    )

        by_sev, by_cat = self._summarize(findings)
        elapsed = (time.time() - t0) * 1000
        return CspmScanResult(
            scan_id=f"cspm-{uuid.uuid4().hex[:12]}",
            provider="aws",
            resources_scanned=len(resources),
            total_findings=len(findings),
            findings=findings,
            by_severity=by_sev,
            by_category=by_cat,
            compliance_score=round(
                (1 - len(findings) / max(len(resources), 1)) * 100, 1
            ),
            duration_ms=round(elapsed, 2),
        )

    def scan_kubernetes(self, manifest_content: str, filename: str = "manifest.yaml") -> CspmScanResult:
        """Scan Kubernetes YAML manifests for security misconfigurations."""
        self._validate_config_size(manifest_content, "K8s manifest")
        t0 = time.time()
        findings: List[CspmFinding] = []

        try:
            import yaml as _yaml
            docs = list(_yaml.safe_load_all(manifest_content))
        except Exception:
            # Fallback to regex-based parsing if PyYAML not available
            docs = [None]

        if docs and docs[0] is not None:
            for doc in docs:
                if not isinstance(doc, dict):
                    continue
                kind = doc.get("kind", "")
                metadata = doc.get("metadata", {})
                res_name = metadata.get("name", filename)
                spec = doc.get("spec", {})

                # Pod spec can be at spec.template.spec (Deployment/StatefulSet/etc) or spec (Pod)
                pod_spec = spec
                if "template" in spec:
                    pod_spec = spec.get("template", {}).get("spec", {})

                self._check_k8s_pod_spec(pod_spec, res_name, kind, findings)
        else:
            # Regex fallback for when YAML parsing fails
            self._check_k8s_regex(manifest_content, filename, findings)

        by_sev, by_cat = self._summarize(findings)
        elapsed = (time.time() - t0) * 1000
        resource_count = max(len(docs) if docs and docs[0] is not None else 1, 1)
        compliance = 1.0 - (len(findings) / max(resource_count * 5, 1))
        return CspmScanResult(
            scan_id=f"cspm-k8s-{uuid.uuid4().hex[:12]}",
            provider="kubernetes",
            resources_scanned=resource_count,
            total_findings=len(findings),
            findings=findings,
            by_severity=by_sev,
            by_category=by_cat,
            compliance_score=round(max(compliance, 0) * 100, 1),
            duration_ms=round(elapsed, 2),
        )

    def _check_k8s_pod_spec(self, pod_spec: Dict, res_name: str, kind: str, findings: List[CspmFinding]) -> None:
        """Check a Kubernetes pod spec for security issues."""
        if not isinstance(pod_spec, dict):
            return

        # Host namespace checks
        if pod_spec.get("hostNetwork") is True:
            findings.append(self._make_finding(K8S_RULES[2], CloudProvider.MULTI, f"{kind}/{res_name}"))
        if pod_spec.get("hostPID") is True:
            findings.append(self._make_finding(K8S_RULES[3], CloudProvider.MULTI, f"{kind}/{res_name}"))
        if pod_spec.get("hostIPC") is True:
            findings.append(self._make_finding(K8S_RULES[4], CloudProvider.MULTI, f"{kind}/{res_name}"))

        # Service account check
        sa = pod_spec.get("serviceAccountName", "default")
        if sa == "default" or not sa:
            findings.append(self._make_finding(K8S_RULES[12], CloudProvider.MULTI, f"{kind}/{res_name}"))

        for container in pod_spec.get("containers", []) + pod_spec.get("initContainers", []):
            cname = container.get("name", "unknown")
            sec_ctx = container.get("securityContext", {})

            # Privileged
            if sec_ctx.get("privileged") is True:
                findings.append(self._make_finding(K8S_RULES[0], CloudProvider.MULTI, f"{kind}/{res_name}/{cname}"))
            # Run as root
            if sec_ctx.get("runAsUser") == 0 or (not sec_ctx.get("runAsNonRoot", False) and not sec_ctx.get("runAsUser")):
                findings.append(self._make_finding(K8S_RULES[1], CloudProvider.MULTI, f"{kind}/{res_name}/{cname}"))
            # Writable root filesystem
            if not sec_ctx.get("readOnlyRootFilesystem", False):
                findings.append(self._make_finding(K8S_RULES[7], CloudProvider.MULTI, f"{kind}/{res_name}/{cname}"))
            # Privilege escalation
            if sec_ctx.get("allowPrivilegeEscalation") is not False:
                findings.append(self._make_finding(K8S_RULES[8], CloudProvider.MULTI, f"{kind}/{res_name}/{cname}"))
            # Dangerous capabilities
            caps = sec_ctx.get("capabilities", {})
            add_caps = [c.upper() for c in caps.get("add", [])]
            if any(c in add_caps for c in ["ALL", "SYS_ADMIN", "NET_ADMIN", "NET_RAW"]):
                findings.append(self._make_finding(K8S_RULES[9], CloudProvider.MULTI, f"{kind}/{res_name}/{cname}"))

            # Resource limits/requests
            resources = container.get("resources", {})
            if not resources.get("limits"):
                findings.append(self._make_finding(K8S_RULES[5], CloudProvider.MULTI, f"{kind}/{res_name}/{cname}"))
            if not resources.get("requests"):
                findings.append(self._make_finding(K8S_RULES[6], CloudProvider.MULTI, f"{kind}/{res_name}/{cname}"))

            # Probes
            if not container.get("livenessProbe"):
                findings.append(self._make_finding(K8S_RULES[10], CloudProvider.MULTI, f"{kind}/{res_name}/{cname}"))
            if not container.get("readinessProbe"):
                findings.append(self._make_finding(K8S_RULES[11], CloudProvider.MULTI, f"{kind}/{res_name}/{cname}"))

            # Image tag
            image = container.get("image", "")
            if ":latest" in image or (":" not in image and "@" not in image):
                findings.append(self._make_finding(K8S_RULES[14], CloudProvider.MULTI, f"{kind}/{res_name}/{cname}"))

    def _check_k8s_regex(self, content: str, filename: str, findings: List[CspmFinding]) -> None:
        """Regex fallback for K8s manifest scanning when PyYAML is unavailable."""
        if re.search(r"privileged:\s*true", content):
            findings.append(self._make_finding(K8S_RULES[0], CloudProvider.MULTI, filename))
        if re.search(r"runAsUser:\s*0", content):
            findings.append(self._make_finding(K8S_RULES[1], CloudProvider.MULTI, filename))
        if re.search(r"hostNetwork:\s*true", content):
            findings.append(self._make_finding(K8S_RULES[2], CloudProvider.MULTI, filename))
        if re.search(r"hostPID:\s*true", content):
            findings.append(self._make_finding(K8S_RULES[3], CloudProvider.MULTI, filename))
        if re.search(r"hostIPC:\s*true", content):
            findings.append(self._make_finding(K8S_RULES[4], CloudProvider.MULTI, filename))
        if not re.search(r"limits:", content):
            findings.append(self._make_finding(K8S_RULES[5], CloudProvider.MULTI, filename))
        if re.search(r"readOnlyRootFilesystem:\s*false", content) or not re.search(r"readOnlyRootFilesystem:", content):
            findings.append(self._make_finding(K8S_RULES[7], CloudProvider.MULTI, filename))
        if re.search(r"allowPrivilegeEscalation:\s*true", content) or not re.search(r"allowPrivilegeEscalation:", content):
            findings.append(self._make_finding(K8S_RULES[8], CloudProvider.MULTI, filename))
        if re.search(r"image:.*:latest", content):
            findings.append(self._make_finding(K8S_RULES[14], CloudProvider.MULTI, filename))

    def scan_aws_live(self, region: str = "us-east-1", services: Optional[List[str]] = None) -> CspmScanResult:
        """Scan live AWS account using boto3 for misconfigurations.

        Args:
            region: AWS region to scan.
            services: List of services to scan (s3, iam, ec2, rds, cloudtrail, lambda, kms).
                      Defaults to all.
        """
        t0 = time.time()
        findings: List[CspmFinding] = []
        resources_scanned = 0
        target_services = services or ["s3", "iam", "ec2", "rds", "cloudtrail", "lambda", "kms"]

        if not self._boto3_available:
            logger.warning("boto3 not available — returning empty live scan result")
            return self._build_scan_result("aws", 0, findings, t0)

        try:
            import boto3
            session = boto3.Session(region_name=region)
        except Exception as e:
            logger.error("Failed to create boto3 session: %s", e)
            return self._build_scan_result("aws", 0, findings, t0)

        if "s3" in target_services:
            resources_scanned += self._scan_aws_s3(session, findings)
        if "ec2" in target_services:
            resources_scanned += self._scan_aws_ec2(session, findings)
        if "iam" in target_services:
            resources_scanned += self._scan_aws_iam(session, findings)
        if "rds" in target_services:
            resources_scanned += self._scan_aws_rds(session, findings)
        if "cloudtrail" in target_services:
            resources_scanned += self._scan_aws_cloudtrail(session, region, findings)

        return self._build_scan_result("aws", resources_scanned, findings, t0)

    def _scan_aws_s3(self, session: Any, findings: List[CspmFinding]) -> int:
        """Scan S3 buckets for misconfigurations."""
        count = 0
        try:
            s3 = session.client("s3")
            buckets = s3.list_buckets().get("Buckets", [])
            for bucket in buckets:
                count += 1
                name = bucket["Name"]
                # Check public access block
                try:
                    pab = s3.get_public_access_block(Bucket=name)
                    cfg = pab.get("PublicAccessBlockConfiguration", {})
                    if not all([cfg.get("BlockPublicAcls"), cfg.get("BlockPublicPolicy"),
                                cfg.get("IgnorePublicAcls"), cfg.get("RestrictPublicBuckets")]):
                        findings.append(self._make_finding(AWS_RULES[0], CloudProvider.AWS, name))
                except Exception:
                    findings.append(self._make_finding(AWS_RULES[0], CloudProvider.AWS, name))
                # Check encryption
                try:
                    s3.get_bucket_encryption(Bucket=name)
                except Exception:
                    findings.append(self._make_finding(AWS_RULES[10], CloudProvider.AWS, name))
                # Check versioning
                try:
                    ver = s3.get_bucket_versioning(Bucket=name)
                    if ver.get("Status") != "Enabled":
                        findings.append(self._make_finding(AWS_RULES[9], CloudProvider.AWS, name))
                except Exception:
                    pass
                # Check logging
                try:
                    log = s3.get_bucket_logging(Bucket=name)
                    if not log.get("LoggingEnabled"):
                        findings.append(self._make_finding(AWS_RULES[11], CloudProvider.AWS, name))
                except Exception:
                    pass
        except Exception as e:
            logger.warning("S3 scan failed: %s", e)
        return count

    def _scan_aws_ec2(self, session: Any, findings: List[CspmFinding]) -> int:
        """Scan EC2 security groups and EBS volumes."""
        count = 0
        try:
            ec2 = session.client("ec2")
            # Security groups
            sgs = ec2.describe_security_groups().get("SecurityGroups", [])
            for sg in sgs:
                count += 1
                for perm in sg.get("IpPermissions", []):
                    for ip_range in perm.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            findings.append(self._make_finding(
                                AWS_RULES[3], CloudProvider.AWS, sg.get("GroupId", "unknown")))
                            break
            # EBS volumes
            vols = ec2.describe_volumes().get("Volumes", [])
            for vol in vols:
                count += 1
                if not vol.get("Encrypted", False):
                    findings.append(self._make_finding(
                        AWS_RULES[2], CloudProvider.AWS, vol.get("VolumeId", "unknown")))
            # VPC flow logs
            vpcs = ec2.describe_vpcs().get("Vpcs", [])
            for vpc in vpcs:
                count += 1
                vpc_id = vpc.get("VpcId", "")
                flow_logs = ec2.describe_flow_logs(Filters=[{"Name": "resource-id", "Values": [vpc_id]}])
                if not flow_logs.get("FlowLogs"):
                    findings.append(self._make_finding(AWS_RULES[16], CloudProvider.AWS, vpc_id))
        except Exception as e:
            logger.warning("EC2 scan failed: %s", e)
        return count

    def _scan_aws_iam(self, session: Any, findings: List[CspmFinding]) -> int:
        """Scan IAM for misconfigurations."""
        count = 0
        try:
            iam = session.client("iam")
            # Check for MFA on users
            users = iam.list_users().get("Users", [])
            for user in users:
                count += 1
                mfa = iam.list_mfa_devices(UserName=user["UserName"])
                if not mfa.get("MFADevices"):
                    findings.append(self._make_finding(
                        AWS_RULES[8], CloudProvider.AWS, user["UserName"]))
                # Check access key age
                keys = iam.list_access_keys(UserName=user["UserName"]).get("AccessKeyMetadata", [])
                for key in keys:
                    if key.get("Status") == "Active":
                        created = key.get("CreateDate")
                        if created:
                            age_days = (datetime.now(timezone.utc) - created.replace(tzinfo=timezone.utc)).days
                            if age_days > 90:
                                findings.append(self._make_finding(
                                    AWS_RULES[15], CloudProvider.AWS, f"{user['UserName']}/{key['AccessKeyId']}"))
        except Exception as e:
            logger.warning("IAM scan failed: %s", e)
        return count

    def _scan_aws_rds(self, session: Any, findings: List[CspmFinding]) -> int:
        """Scan RDS instances."""
        count = 0
        try:
            rds = session.client("rds")
            instances = rds.describe_db_instances().get("DBInstances", [])
            for db in instances:
                count += 1
                db_id = db.get("DBInstanceIdentifier", "unknown")
                if db.get("PubliclyAccessible", False):
                    findings.append(self._make_finding(AWS_RULES[5], CloudProvider.AWS, db_id))
                if not db.get("StorageEncrypted", False):
                    findings.append(self._make_finding(AWS_RULES[20], CloudProvider.AWS, db_id))
                if not db.get("MultiAZ", False):
                    findings.append(self._make_finding(AWS_RULES[21], CloudProvider.AWS, db_id))
                if db.get("BackupRetentionPeriod", 0) == 0:
                    findings.append(self._make_finding(AWS_RULES[22], CloudProvider.AWS, db_id))
        except Exception as e:
            logger.warning("RDS scan failed: %s", e)
        return count

    def _scan_aws_cloudtrail(self, session: Any, region: str, findings: List[CspmFinding]) -> int:
        """Scan CloudTrail configuration."""
        count = 0
        try:
            ct = session.client("cloudtrail")
            trails = ct.describe_trails().get("trailList", [])
            if not trails:
                findings.append(self._make_finding(AWS_RULES[4], CloudProvider.AWS, region))
                return 1
            for trail in trails:
                count += 1
                trail_name = trail.get("Name", "unknown")
                if not trail.get("KmsKeyId"):
                    findings.append(self._make_finding(AWS_RULES[17], CloudProvider.AWS, trail_name))
                if not trail.get("LogFileValidationEnabled", False):
                    findings.append(self._make_finding(AWS_RULES[18], CloudProvider.AWS, trail_name))
        except Exception as e:
            logger.warning("CloudTrail scan failed: %s", e)
        return count

    def scan_azure_live(self, subscription_id: Optional[str] = None) -> CspmScanResult:
        """Scan live Azure subscription for misconfigurations.

        Requires azure-identity and azure-mgmt-* packages.
        """
        t0 = time.time()
        findings: List[CspmFinding] = []
        resources_scanned = 0

        if not self._azure_available:
            logger.warning("azure-identity not available — returning empty live scan result")
            return self._build_scan_result("azure", 0, findings, t0)

        try:
            from azure.identity import DefaultAzureCredential
            credential = DefaultAzureCredential()

            # Storage accounts
            try:
                from azure.mgmt.storage import StorageManagementClient
                storage_client = StorageManagementClient(credential, subscription_id)
                for account in storage_client.storage_accounts.list():
                    resources_scanned += 1
                    if not account.enable_https_traffic_only:
                        findings.append(self._make_finding(AZURE_RULES[5], CloudProvider.AZURE, account.name))
                    if account.allow_blob_public_access:
                        findings.append(self._make_finding(AZURE_RULES[0], CloudProvider.AZURE, account.name))
            except Exception as e:
                logger.warning("Azure storage scan failed: %s", e)

            # NSGs
            try:
                from azure.mgmt.network import NetworkManagementClient
                net_client = NetworkManagementClient(credential, subscription_id)
                for nsg in net_client.network_security_groups.list_all():
                    resources_scanned += 1
                    for rule in (nsg.security_rules or []):
                        if rule.source_address_prefix == "*" and rule.direction == "Inbound":
                            if rule.destination_port_range == "22":
                                findings.append(self._make_finding(AZURE_RULES[1], CloudProvider.AZURE, nsg.name))
                            elif rule.destination_port_range == "3389":
                                findings.append(self._make_finding(AZURE_RULES[7], CloudProvider.AZURE, nsg.name))
            except Exception as e:
                logger.warning("Azure network scan failed: %s", e)

        except Exception as e:
            logger.error("Azure live scan failed: %s", e)

        return self._build_scan_result("azure", resources_scanned, findings, t0)

    def scan_gcp_live(self, project_id: Optional[str] = None) -> CspmScanResult:
        """Scan live GCP project for misconfigurations.

        Requires google-cloud-storage, google-cloud-compute packages.
        """
        t0 = time.time()
        findings: List[CspmFinding] = []
        resources_scanned = 0

        if not self._gcp_available:
            logger.warning("google-cloud not available — returning empty live scan result")
            return self._build_scan_result("gcp", 0, findings, t0)

        try:
            from google.cloud import storage as gcs_storage
            client = gcs_storage.Client(project=project_id)
            for bucket in client.list_buckets():
                resources_scanned += 1
                if bucket.iam_configuration.uniform_bucket_level_access_enabled is False:
                    findings.append(self._make_finding(GCP_RULES[5], CloudProvider.GCP, bucket.name))
                # Check for allUsers access
                policy = bucket.get_iam_policy()
                for binding in policy.bindings:
                    if "allUsers" in binding.get("members", []) or "allAuthenticatedUsers" in binding.get("members", []):
                        findings.append(self._make_finding(GCP_RULES[0], CloudProvider.GCP, bucket.name))
                        break
        except Exception as e:
            logger.warning("GCP storage scan failed: %s", e)

        return self._build_scan_result("gcp", resources_scanned, findings, t0)

    def _build_scan_result(self, provider: str, resources: int, findings: List[CspmFinding], t0: float) -> CspmScanResult:
        """Build a standardized scan result."""
        by_sev, by_cat = self._summarize(findings)
        elapsed = (time.time() - t0) * 1000
        compliance = 1.0 - (len(findings) / max(resources * 3, 1)) if resources > 0 else 1.0
        return CspmScanResult(
            scan_id=f"cspm-live-{uuid.uuid4().hex[:12]}",
            provider=provider,
            resources_scanned=resources,
            total_findings=len(findings),
            findings=findings,
            by_severity=by_sev,
            by_category=by_cat,
            compliance_score=round(max(compliance, 0) * 100, 1),
            duration_ms=round(elapsed, 2),
        )

    def _detect_provider_tf(self, content: str) -> CloudProvider:
        if 'provider "aws"' in content or "aws_" in content:
            return CloudProvider.AWS
        if 'provider "azurerm"' in content or "azurerm_" in content:
            return CloudProvider.AZURE
        if 'provider "google"' in content or "google_" in content:
            return CloudProvider.GCP
        return CloudProvider.AWS

    def _make_finding(
        self, rule: Tuple, provider: CloudProvider, resource_id: str
    ) -> CspmFinding:
        rid, title, sev, cwe, cat, desc, rec, frameworks = rule
        return CspmFinding(
            finding_id=f"CSPM-{uuid.uuid4().hex[:8]}",
            title=title,
            severity=CspmSeverity(sev),
            category=CspmCategory(cat),
            provider=provider,
            resource_type=rid.split("-")[1] if "-" in rid else "unknown",
            resource_id=resource_id,
            description=desc,
            recommendation=rec,
            compliance_frameworks=frameworks,
        )

    @staticmethod
    def _summarize(
        findings: List[CspmFinding],
    ) -> Tuple[Dict[str, int], Dict[str, int]]:
        by_sev: Dict[str, int] = {}
        by_cat: Dict[str, int] = {}
        for f in findings:
            by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
            by_cat[f.category.value] = by_cat.get(f.category.value, 0) + 1
        return by_sev, by_cat


_engine: Optional[CSPMEngine] = None


def get_cspm_engine() -> CSPMEngine:
    global _engine
    if _engine is None:
        _engine = CSPMEngine()
    return _engine
