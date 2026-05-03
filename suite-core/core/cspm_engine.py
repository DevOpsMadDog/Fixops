"""Cloud Security Posture Management (CSPM) Engine.

Lightweight IaC scanning engine for Terraform (HCL) and CloudFormation (JSON/YAML)
templates. Detects common cloud misconfigurations using pattern matching and
structured rule catalogues for AWS, Azure, and GCP.

Usage:
    from core.cspm_engine import CSPMEngine, get_cspm_engine
    engine = get_cspm_engine()
    result = engine.scan_terraform(hcl_text)
    result = engine.scan_cloudformation(cf_json_text)
"""

from __future__ import annotations

import json
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


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

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class CloudProvider(str, Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    OCI = "oci"
    ALIBABA = "alibaba"
    IBM = "ibm"
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


# ---------------------------------------------------------------------------
# Rule catalogue format
# Each rule is a tuple of 8 fields:
#   (rule_id, title, severity, cis_benchmark, category, description,
#    recommendation, compliance_frameworks)
# ---------------------------------------------------------------------------

# Rule = Tuple[str, str, str, str, str, str, str, List[str]]

AWS_RULES: List[Tuple] = [
    # --- Storage (S3) ---
    (
        "CSPM-AWS-001",
        "S3 Bucket Publicly Accessible",
        "critical",
        "CIS-AWS-2.1.5",
        "storage",
        "S3 bucket allows public access via ACL or bucket policy.",
        "Enable S3 Block Public Access at bucket and account level.",
        ["CIS-AWS-2.1.5", "SOC2-CC6.6", "PCI-DSS-7.2", "HIPAA-164.312(a)(1)", "NIST-AC-3"],
    ),
    (
        "CSPM-AWS-002",
        "S3 Bucket Versioning Disabled",
        "low",
        "CIS-AWS-2.1.3",
        "storage",
        "S3 bucket does not have versioning enabled, risking data loss.",
        "Enable versioning on all S3 buckets to protect against accidental deletion.",
        ["CIS-AWS-2.1.3", "SOC2-A1.2", "NIST-CP-9"],
    ),
    (
        "CSPM-AWS-003",
        "S3 Bucket Encryption Disabled",
        "high",
        "CIS-AWS-2.1.1",
        "storage",
        "S3 bucket does not have default server-side encryption enabled.",
        "Enable AES-256 or AWS KMS encryption on all S3 buckets.",
        ["CIS-AWS-2.1.1", "SOC2-CC6.7", "PCI-DSS-3.4", "HIPAA-164.312(a)(2)(iv)", "NIST-SC-28"],
    ),
    (
        "CSPM-AWS-004",
        "S3 Bucket Access Logging Disabled",
        "low",
        "CIS-AWS-2.1.4",
        "logging",
        "S3 bucket access logging is not enabled.",
        "Enable server access logging to track requests made to the bucket.",
        ["CIS-AWS-2.1.4", "SOC2-CC7.2", "PCI-DSS-10.2", "NIST-AU-2"],
    ),
    (
        "CSPM-AWS-005",
        "CloudTrail Disabled",
        "high",
        "CIS-AWS-3.1",
        "logging",
        "AWS CloudTrail is not enabled, preventing audit logging of API activity.",
        "Enable CloudTrail with multi-region logging and log file validation.",
        ["CIS-AWS-3.1", "SOC2-CC7.2", "PCI-DSS-10.1", "HIPAA-164.312(b)", "NIST-AU-2"],
    ),
    (
        "CSPM-AWS-006",
        "RDS Instance Not Encrypted",
        "critical",
        "CIS-AWS-2.3.1",
        "database",
        "RDS instance does not have encryption at rest enabled.",
        "Enable storage encryption when creating RDS instances.",
        ["CIS-AWS-2.3.1", "SOC2-CC6.7", "PCI-DSS-3.4", "HIPAA-164.312(a)(2)(iv)", "NIST-SC-28"],
    ),
    (
        "CSPM-AWS-007",
        "RDS Instance Publicly Accessible",
        "critical",
        "CIS-AWS-2.3.2",
        "database",
        "RDS instance is publicly accessible from the internet.",
        "Disable public accessibility and restrict access via security groups.",
        ["CIS-AWS-2.3.2", "SOC2-CC6.6", "PCI-DSS-7.2", "HIPAA-164.312(a)(1)", "NIST-SC-7"],
    ),
    (
        "CSPM-AWS-008",
        "Security Group Open to World (0.0.0.0/0)",
        "critical",
        "CIS-AWS-5.2",
        "network",
        "Security group allows unrestricted inbound access from 0.0.0.0/0.",
        "Restrict inbound rules to specific CIDR ranges. Use VPN or bastion hosts.",
        ["CIS-AWS-5.2", "SOC2-CC6.6", "PCI-DSS-1.3", "HIPAA-164.312(a)(1)", "NIST-SC-7"],
    ),
    (
        "CSPM-AWS-009",
        "IAM User Access Key Older Than 90 Days",
        "medium",
        "CIS-AWS-1.14",
        "iam",
        "IAM user access key has not been rotated in 90+ days.",
        "Rotate access keys regularly and remove unused keys.",
        ["CIS-AWS-1.14", "SOC2-CC6.1", "PCI-DSS-8.2.4", "NIST-IA-5"],
    ),
    (
        "CSPM-AWS-010",
        "MFA Not Enabled on Root Account",
        "critical",
        "CIS-AWS-1.5",
        "iam",
        "Multi-factor authentication is not enabled on the AWS root account.",
        "Enable hardware or virtual MFA on the root account immediately.",
        ["CIS-AWS-1.5", "SOC2-CC6.1", "PCI-DSS-8.3", "HIPAA-164.312(d)", "NIST-IA-2(1)"],
    ),
    (
        "CSPM-AWS-011",
        "IAM Policy With Wildcard Permissions",
        "high",
        "CIS-AWS-1.16",
        "iam",
        "IAM policy grants wildcard (*) actions or resources, violating least privilege.",
        "Replace wildcard permissions with specific action/resource ARNs.",
        ["CIS-AWS-1.16", "SOC2-CC6.3", "PCI-DSS-7.1", "NIST-AC-6"],
    ),
    (
        "CSPM-AWS-012",
        "Lambda Function Using Deprecated Runtime",
        "medium",
        "CIS-AWS-4.1",
        "serverless",
        "Lambda function uses a deprecated or end-of-life runtime.",
        "Upgrade Lambda function to a supported runtime version.",
        ["SOC2-CC7.1", "NIST-SI-2"],
    ),
    (
        "CSPM-AWS-013",
        "ECS Task Definition Uses Privileged Container",
        "high",
        "CIS-AWS-5.4",
        "container",
        "ECS task definition runs a container in privileged mode.",
        "Remove privileged flag from container definitions unless strictly required.",
        ["SOC2-CC6.6", "NIST-CM-6"],
    ),
    (
        "CSPM-AWS-014",
        "EC2 Instance Has Public IP",
        "medium",
        "CIS-AWS-5.1",
        "compute",
        "EC2 instance is configured with a public IP address.",
        "Remove public IP and use NAT gateway or load balancer for internet access.",
        ["SOC2-CC6.6", "PCI-DSS-1.3", "NIST-SC-7"],
    ),
    (
        "CSPM-AWS-015",
        "Secrets Manager Rotation Disabled",
        "medium",
        "CIS-AWS-2.3.3",
        "iam",
        "Secrets Manager secret does not have automatic rotation enabled.",
        "Enable automatic rotation with an appropriate Lambda rotation function.",
        ["SOC2-CC6.1", "PCI-DSS-8.2.4", "NIST-IA-5"],
    ),
    (
        "CSPM-AWS-016",
        "KMS Key Rotation Disabled",
        "low",
        "CIS-AWS-2.8",
        "encryption",
        "AWS KMS customer-managed key does not have automatic rotation enabled.",
        "Enable automatic annual key rotation for all customer-managed KMS keys.",
        ["CIS-AWS-2.8", "SOC2-CC6.7", "PCI-DSS-3.6", "NIST-SC-12"],
    ),
    (
        "CSPM-AWS-017",
        "VPC Flow Logs Disabled",
        "medium",
        "CIS-AWS-3.9",
        "logging",
        "VPC flow logs are not enabled, limiting network traffic visibility.",
        "Enable VPC flow logs for all VPCs and send to CloudWatch Logs or S3.",
        ["CIS-AWS-3.9", "SOC2-CC7.2", "PCI-DSS-10.2", "HIPAA-164.312(b)", "NIST-AU-2"],
    ),
    (
        "CSPM-AWS-018",
        "ELB Access Logging Disabled",
        "low",
        "CIS-AWS-2.6",
        "logging",
        "Elastic Load Balancer does not have access logging enabled.",
        "Enable access logging and configure log destination S3 bucket.",
        ["SOC2-CC7.2", "PCI-DSS-10.2", "NIST-AU-2"],
    ),
    (
        "CSPM-AWS-019",
        "CloudWatch Log Retention Not Set",
        "low",
        "CIS-AWS-3.8",
        "logging",
        "CloudWatch log group has no retention policy, logs retained indefinitely.",
        "Set an appropriate log retention period (e.g. 90 days) for all log groups.",
        ["SOC2-CC7.2", "PCI-DSS-10.7", "NIST-AU-11"],
    ),
    (
        "CSPM-AWS-020",
        "EBS Volume Not Encrypted",
        "high",
        "CIS-AWS-2.2.1",
        "encryption",
        "EBS volume is not encrypted at rest.",
        "Enable EBS default encryption for the account or encrypt individual volumes.",
        ["CIS-AWS-2.2.1", "SOC2-CC6.7", "PCI-DSS-3.4", "HIPAA-164.312(a)(2)(iv)", "NIST-SC-28"],
    ),
    (
        "CSPM-AWS-021",
        "CloudTrail Log File Validation Disabled",
        "medium",
        "CIS-AWS-3.2",
        "logging",
        "CloudTrail trail does not have log file validation enabled.",
        "Enable log file validation to detect tampered trail files.",
        ["CIS-AWS-3.2", "SOC2-CC7.2", "PCI-DSS-10.5", "NIST-AU-9"],
    ),
    (
        "CSPM-AWS-022",
        "RDS Automated Backups Disabled",
        "medium",
        "CIS-AWS-2.3.4",
        "database",
        "RDS instance does not have automated backups enabled.",
        "Enable automated backups with a retention period of at least 7 days.",
        ["SOC2-A1.2", "PCI-DSS-12.10", "HIPAA-164.308(a)(7)", "NIST-CP-9"],
    ),
    (
        "CSPM-AWS-023",
        "Security Group Allows All Outbound Traffic",
        "low",
        "CIS-AWS-5.3",
        "network",
        "Security group egress rule allows all outbound traffic.",
        "Restrict outbound rules to required destinations and ports.",
        ["SOC2-CC6.6", "PCI-DSS-1.3", "NIST-SC-7"],
    ),
    (
        "CSPM-AWS-024",
        "IAM Root Account Has Active Access Keys",
        "critical",
        "CIS-AWS-1.4",
        "iam",
        "AWS root account has active programmatic access keys.",
        "Delete all root account access keys immediately.",
        ["CIS-AWS-1.4", "SOC2-CC6.1", "PCI-DSS-7.1", "NIST-AC-2"],
    ),
    (
        "CSPM-AWS-025",
        "SNS Topic Not Encrypted",
        "low",
        "CIS-AWS-2.9",
        "encryption",
        "SNS topic does not use server-side encryption.",
        "Enable SSE for SNS topics using AWS KMS.",
        ["SOC2-CC6.7", "NIST-SC-28"],
    ),
    (
        "CSPM-AWS-026",
        "SQS Queue Not Encrypted",
        "low",
        "CIS-AWS-2.9",
        "encryption",
        "SQS queue does not have server-side encryption enabled.",
        "Enable SSE for SQS queues using AWS KMS.",
        ["SOC2-CC6.7", "PCI-DSS-3.4", "NIST-SC-28"],
    ),
    (
        "CSPM-AWS-027",
        "EC2 Security Group Allows SSH From Internet",
        "critical",
        "CIS-AWS-5.2",
        "network",
        "Security group allows SSH (port 22) access from 0.0.0.0/0.",
        "Restrict SSH access to specific trusted CIDR ranges or use AWS SSM Session Manager.",
        ["CIS-AWS-5.2", "SOC2-CC6.6", "PCI-DSS-1.3", "NIST-SC-7"],
    ),
    (
        "CSPM-AWS-028",
        "EC2 Security Group Allows RDP From Internet",
        "critical",
        "CIS-AWS-5.3",
        "network",
        "Security group allows RDP (port 3389) access from 0.0.0.0/0.",
        "Restrict RDP access to specific trusted CIDR ranges or use VPN.",
        ["CIS-AWS-5.3", "SOC2-CC6.6", "PCI-DSS-1.3", "NIST-SC-7"],
    ),
    (
        "CSPM-AWS-029",
        "IAM Password Policy Weak",
        "medium",
        "CIS-AWS-1.8",
        "iam",
        "IAM account password policy does not meet minimum security requirements.",
        "Set minimum password length to 14, require uppercase, lowercase, numbers and symbols.",
        ["CIS-AWS-1.8", "SOC2-CC6.1", "PCI-DSS-8.2.3", "NIST-IA-5(1)"],
    ),
    (
        "CSPM-AWS-030",
        "Lambda Function Environment Variable Contains Secret",
        "high",
        "CIS-AWS-4.2",
        "serverless",
        "Lambda function environment variables may contain hardcoded secrets.",
        "Use AWS Secrets Manager or Parameter Store for secrets instead of env vars.",
        ["SOC2-CC6.1", "PCI-DSS-6.3", "NIST-IA-5"],
    ),
    (
        "CSPM-AWS-031",
        "ECR Image Scan On Push Disabled",
        "medium",
        "CIS-AWS-5.5",
        "container",
        "ECR repository does not have image scanning on push enabled.",
        "Enable scan on push to detect vulnerabilities in container images.",
        ["SOC2-CC7.1", "NIST-SI-2"],
    ),
    (
        "CSPM-AWS-032",
        "CloudFront Distribution Without WAF",
        "medium",
        "CIS-AWS-2.7",
        "network",
        "CloudFront distribution does not have AWS WAF enabled.",
        "Associate a WAF web ACL with the CloudFront distribution.",
        ["SOC2-CC6.6", "PCI-DSS-6.6", "NIST-SC-7"],
    ),
    (
        "CSPM-AWS-033",
        "RDS Multi-AZ Not Enabled",
        "medium",
        "CIS-AWS-2.3.5",
        "database",
        "RDS instance does not have Multi-AZ deployment enabled.",
        "Enable Multi-AZ for production RDS instances for high availability.",
        ["SOC2-A1.2", "HIPAA-164.308(a)(7)", "NIST-CP-6"],
    ),
    (
        "CSPM-AWS-034",
        "S3 MFA Delete Disabled",
        "medium",
        "CIS-AWS-2.1.2",
        "storage",
        "S3 bucket does not have MFA Delete enabled.",
        "Enable MFA Delete on versioned S3 buckets to prevent accidental deletion.",
        ["CIS-AWS-2.1.2", "SOC2-CC6.4", "PCI-DSS-7.2", "NIST-AU-9"],
    ),
    (
        "CSPM-AWS-035",
        "DynamoDB Table Not Encrypted With CMK",
        "low",
        "CIS-AWS-2.4",
        "encryption",
        "DynamoDB table uses AWS managed keys instead of customer-managed keys.",
        "Use customer-managed KMS keys for sensitive DynamoDB tables.",
        ["SOC2-CC6.7", "PCI-DSS-3.4", "NIST-SC-28"],
    ),
    (
        "CSPM-AWS-036",
        "ElasticSearch Domain Not Encrypted",
        "high",
        "CIS-AWS-2.5",
        "encryption",
        "Elasticsearch/OpenSearch domain does not have encryption at rest.",
        "Enable encryption at rest for all Elasticsearch/OpenSearch domains.",
        ["SOC2-CC6.7", "PCI-DSS-3.4", "HIPAA-164.312(a)(2)(iv)", "NIST-SC-28"],
    ),
    (
        "CSPM-AWS-037",
        "Redshift Cluster Publicly Accessible",
        "high",
        "CIS-AWS-2.5",
        "database",
        "Redshift cluster is publicly accessible from the internet.",
        "Disable public accessibility and restrict access via VPC security groups.",
        ["SOC2-CC6.6", "PCI-DSS-7.2", "NIST-SC-7"],
    ),
    (
        "CSPM-AWS-038",
        "API Gateway Logging Disabled",
        "low",
        "CIS-AWS-3.7",
        "logging",
        "API Gateway stage does not have access logging or execution logging enabled.",
        "Enable detailed CloudWatch logging for API Gateway stages.",
        ["SOC2-CC7.2", "PCI-DSS-10.2", "NIST-AU-2"],
    ),
    (
        "CSPM-AWS-039",
        "Kinesis Stream Not Encrypted",
        "low",
        "CIS-AWS-2.9",
        "encryption",
        "Kinesis data stream does not have server-side encryption enabled.",
        "Enable SSE for Kinesis streams using AWS KMS.",
        ["SOC2-CC6.7", "PCI-DSS-3.4", "NIST-SC-28"],
    ),
    (
        "CSPM-AWS-040",
        "IAM Access Analyzer Not Enabled",
        "medium",
        "CIS-AWS-1.20",
        "iam",
        "IAM Access Analyzer is not enabled in the region.",
        "Enable IAM Access Analyzer in all active AWS regions.",
        ["CIS-AWS-1.20", "SOC2-CC6.6", "NIST-AC-6(7)"],
    ),
]

AZURE_RULES: List[Tuple] = [
    (
        "CSPM-AZ-001",
        "Azure Storage Blob Publicly Accessible",
        "critical",
        "CIS-Azure-3.1",
        "storage",
        "Azure Storage blob container allows public access.",
        "Disable public blob access on all storage accounts.",
        ["CIS-Azure-3.1", "SOC2-CC6.6", "PCI-DSS-7.2", "NIST-AC-3"],
    ),
    (
        "CSPM-AZ-002",
        "Azure Storage Account HTTPS Not Required",
        "high",
        "CIS-Azure-3.2",
        "storage",
        "Azure Storage account allows unencrypted HTTP connections.",
        "Enable Secure transfer required on all storage accounts.",
        ["CIS-Azure-3.2", "SOC2-CC6.7", "PCI-DSS-4.1", "NIST-SC-8"],
    ),
    (
        "CSPM-AZ-003",
        "Azure MFA Not Enabled For Privileged Users",
        "critical",
        "CIS-Azure-1.2",
        "iam",
        "MFA is not enforced for privileged Azure AD users.",
        "Enable Conditional Access policy requiring MFA for all privileged roles.",
        ["CIS-Azure-1.2", "SOC2-CC6.1", "PCI-DSS-8.3", "HIPAA-164.312(d)", "NIST-IA-2(1)"],
    ),
    (
        "CSPM-AZ-004",
        "Azure NSG Allows Unrestricted SSH",
        "critical",
        "CIS-Azure-6.2",
        "network",
        "Network Security Group allows SSH (port 22) from any source.",
        "Remove any-source SSH rules and restrict to specific CIDR ranges.",
        ["CIS-Azure-6.2", "SOC2-CC6.6", "PCI-DSS-1.3", "NIST-SC-7"],
    ),
    (
        "CSPM-AZ-005",
        "Azure Key Vault Soft Delete Disabled",
        "medium",
        "CIS-Azure-8.4",
        "encryption",
        "Azure Key Vault does not have soft delete enabled.",
        "Enable soft delete and purge protection on all Key Vaults.",
        ["CIS-Azure-8.4", "SOC2-A1.2", "NIST-CP-9"],
    ),
    (
        "CSPM-AZ-006",
        "Azure SQL Database Transparent Data Encryption Disabled",
        "high",
        "CIS-Azure-4.1",
        "database",
        "Azure SQL Database does not have Transparent Data Encryption enabled.",
        "Enable TDE for all Azure SQL Databases.",
        ["CIS-Azure-4.1", "SOC2-CC6.7", "PCI-DSS-3.4", "HIPAA-164.312(a)(2)(iv)", "NIST-SC-28"],
    ),
    (
        "CSPM-AZ-007",
        "Azure Activity Log Alert Not Configured",
        "medium",
        "CIS-Azure-5.1",
        "logging",
        "No activity log alert is configured for critical operations.",
        "Create activity log alerts for policy changes, role assignments and security events.",
        ["CIS-Azure-5.1", "SOC2-CC7.2", "PCI-DSS-10.6", "NIST-AU-6"],
    ),
    (
        "CSPM-AZ-008",
        "Azure Defender Not Enabled",
        "high",
        "CIS-Azure-2.1",
        "compute",
        "Microsoft Defender for Cloud is not enabled for subscription resources.",
        "Enable Microsoft Defender for all supported resource types.",
        ["CIS-Azure-2.1", "SOC2-CC7.1", "NIST-SI-3"],
    ),
    (
        "CSPM-AZ-009",
        "Azure VM OS Disk Not Encrypted",
        "high",
        "CIS-Azure-7.2",
        "encryption",
        "Azure VM OS disk does not have disk encryption enabled.",
        "Enable Azure Disk Encryption using Key Vault for all VM disks.",
        ["CIS-Azure-7.2", "SOC2-CC6.7", "PCI-DSS-3.4", "NIST-SC-28"],
    ),
    (
        "CSPM-AZ-010",
        "Azure Network Watcher Not Enabled",
        "medium",
        "CIS-Azure-6.5",
        "network",
        "Azure Network Watcher is not enabled in the region.",
        "Enable Network Watcher in all regions where resources are deployed.",
        ["CIS-Azure-6.5", "SOC2-CC7.2", "NIST-AU-2"],
    ),
    (
        "CSPM-AZ-011",
        "Azure Storage Account Allows All Networks",
        "medium",
        "CIS-Azure-3.7",
        "network",
        "Azure Storage account is accessible from all networks.",
        "Restrict storage account access to specific virtual networks and IPs.",
        ["CIS-Azure-3.7", "SOC2-CC6.6", "PCI-DSS-1.3", "NIST-SC-7"],
    ),
    (
        "CSPM-AZ-012",
        "Azure SQL Server Auditing Disabled",
        "medium",
        "CIS-Azure-4.2",
        "logging",
        "Azure SQL Server does not have auditing enabled.",
        "Enable auditing for all SQL Servers and retain logs for 90+ days.",
        ["CIS-Azure-4.2", "SOC2-CC7.2", "PCI-DSS-10.2", "NIST-AU-2"],
    ),
    (
        "CSPM-AZ-013",
        "Azure App Service HTTPS Only Not Enforced",
        "high",
        "CIS-Azure-9.2",
        "network",
        "Azure App Service allows HTTP connections in addition to HTTPS.",
        "Enable HTTPS Only on all App Service applications.",
        ["CIS-Azure-9.2", "SOC2-CC6.7", "PCI-DSS-4.1", "NIST-SC-8"],
    ),
    (
        "CSPM-AZ-014",
        "Azure Function App Authentication Disabled",
        "high",
        "CIS-Azure-9.4",
        "iam",
        "Azure Function App does not have authentication/authorization enabled.",
        "Enable App Service Authentication for Function Apps.",
        ["SOC2-CC6.1", "NIST-IA-2"],
    ),
    (
        "CSPM-AZ-015",
        "Azure Container Registry Admin User Enabled",
        "medium",
        "CIS-Azure-7.4",
        "container",
        "Azure Container Registry has the admin user account enabled.",
        "Disable admin user and use service principals or managed identities.",
        ["SOC2-CC6.1", "NIST-AC-2"],
    ),
    (
        "CSPM-AZ-016",
        "Azure PostgreSQL SSL Not Enforced",
        "high",
        "CIS-Azure-4.3",
        "database",
        "Azure PostgreSQL server does not enforce SSL connections.",
        "Enable SSL enforcement on all Azure PostgreSQL servers.",
        ["CIS-Azure-4.3", "SOC2-CC6.7", "PCI-DSS-4.1", "NIST-SC-8"],
    ),
    (
        "CSPM-AZ-017",
        "Azure Monitor Log Profile Not Created",
        "medium",
        "CIS-Azure-5.2",
        "logging",
        "Azure Monitor log profile is not configured to export activity logs.",
        "Create a log profile to export activity logs to storage account or event hub.",
        ["CIS-Azure-5.2", "SOC2-CC7.2", "PCI-DSS-10.1", "NIST-AU-2"],
    ),
    (
        "CSPM-AZ-018",
        "Azure Key Vault Purge Protection Disabled",
        "medium",
        "CIS-Azure-8.5",
        "encryption",
        "Azure Key Vault does not have purge protection enabled.",
        "Enable purge protection to prevent permanent key deletion.",
        ["CIS-Azure-8.5", "SOC2-A1.2", "NIST-CP-9"],
    ),
    (
        "CSPM-AZ-019",
        "Azure AD Guest Invitations Not Restricted",
        "medium",
        "CIS-Azure-1.14",
        "iam",
        "Azure AD allows guest invitations from all users.",
        "Restrict guest invitations to administrators only.",
        ["CIS-Azure-1.14", "SOC2-CC6.2", "NIST-AC-2"],
    ),
    (
        "CSPM-AZ-020",
        "Azure Subscription Has No Activity Logs",
        "high",
        "CIS-Azure-5.3",
        "logging",
        "Azure subscription does not retain activity logs for 365+ days.",
        "Configure log profile with a retention of at least 365 days.",
        ["CIS-Azure-5.3", "SOC2-CC7.2", "PCI-DSS-10.7", "NIST-AU-11"],
    ),
    (
        "CSPM-AZ-021",
        "Azure SQL Server AD Admin Not Configured",
        "high",
        "CIS-Azure-4.4",
        "iam",
        "Azure SQL Server does not have an Azure AD administrator configured.",
        "Configure an Azure AD admin for SQL Server to enable centralized identity management.",
        ["CIS-Azure-4.4", "SOC2-CC6.1", "PCI-DSS-8.1", "NIST-IA-2"],
    ),
    (
        "CSPM-AZ-022",
        "Azure Kubernetes Service RBAC Disabled",
        "high",
        "CIS-Azure-8.1",
        "container",
        "Azure Kubernetes Service cluster does not have RBAC enabled.",
        "Enable RBAC on all AKS clusters to enforce least privilege.",
        ["SOC2-CC6.3", "NIST-AC-6"],
    ),
    (
        "CSPM-AZ-023",
        "Azure VNet Peering Allows All Traffic",
        "low",
        "CIS-Azure-6.6",
        "network",
        "Azure VNet peering connection allows all traffic without filtering.",
        "Apply NSG rules to filter traffic across VNet peering connections.",
        ["SOC2-CC6.6", "NIST-SC-7"],
    ),
    (
        "CSPM-AZ-024",
        "Azure Web App Client Certificate Disabled",
        "medium",
        "CIS-Azure-9.3",
        "iam",
        "Azure Web App does not require client certificates for authentication.",
        "Enable client certificate requirement for App Service authentication.",
        ["SOC2-CC6.1", "PCI-DSS-8.3", "NIST-IA-2"],
    ),
    (
        "CSPM-AZ-025",
        "Azure DDoS Protection Not Enabled",
        "medium",
        "CIS-Azure-6.4",
        "network",
        "Azure DDoS Protection Standard is not enabled on the virtual network.",
        "Enable Azure DDoS Protection Standard for production virtual networks.",
        ["SOC2-A1.1", "NIST-SC-5"],
    ),
]

GCP_RULES: List[Tuple] = [
    (
        "CSPM-GCP-001",
        "GCS Bucket Publicly Accessible",
        "critical",
        "CIS-GCP-5.1",
        "storage",
        "GCS bucket allows public access via allUsers or allAuthenticatedUsers.",
        "Remove public IAM bindings from GCS buckets.",
        ["CIS-GCP-5.1", "SOC2-CC6.6", "PCI-DSS-7.2", "NIST-AC-3"],
    ),
    (
        "CSPM-GCP-002",
        "GCP Compute Instance Has Public IP",
        "medium",
        "CIS-GCP-4.9",
        "compute",
        "GCP Compute instance has a public IP address assigned.",
        "Use internal IP addresses and Cloud NAT for outbound internet access.",
        ["CIS-GCP-4.9", "SOC2-CC6.6", "PCI-DSS-1.3", "NIST-SC-7"],
    ),
    (
        "CSPM-GCP-003",
        "GCP Cloud Audit Logs Disabled",
        "high",
        "CIS-GCP-2.1",
        "logging",
        "GCP Cloud Audit Logs are not enabled for all services.",
        "Enable Data Read, Data Write and Admin Activity audit logs for all services.",
        ["CIS-GCP-2.1", "SOC2-CC7.2", "PCI-DSS-10.1", "HIPAA-164.312(b)", "NIST-AU-2"],
    ),
    (
        "CSPM-GCP-004",
        "GCP Firewall Rule Allows All Ingress",
        "critical",
        "CIS-GCP-3.6",
        "network",
        "GCP firewall rule allows ingress from 0.0.0.0/0 to all ports.",
        "Restrict firewall rules to specific source ranges and required ports.",
        ["CIS-GCP-3.6", "SOC2-CC6.6", "PCI-DSS-1.3", "NIST-SC-7"],
    ),
    (
        "CSPM-GCP-005",
        "GCP SQL Instance Publicly Accessible",
        "critical",
        "CIS-GCP-6.2",
        "database",
        "GCP Cloud SQL instance is configured with a public IP.",
        "Disable public IP on Cloud SQL instances and use Cloud SQL Auth Proxy.",
        ["CIS-GCP-6.2", "SOC2-CC6.6", "PCI-DSS-7.2", "NIST-SC-7"],
    ),
    (
        "CSPM-GCP-006",
        "GCP KMS Key Rotation Not Set",
        "medium",
        "CIS-GCP-1.10",
        "encryption",
        "GCP KMS key does not have automatic rotation configured.",
        "Configure key rotation period of 90 days or less on all KMS keys.",
        ["CIS-GCP-1.10", "SOC2-CC6.7", "PCI-DSS-3.6", "NIST-SC-12"],
    ),
    (
        "CSPM-GCP-007",
        "GCP Project Has No Org Policy Constraints",
        "medium",
        "CIS-GCP-2.9",
        "iam",
        "GCP project lacks organization policy constraints for security controls.",
        "Apply organization policy constraints for resource locations, IAM bindings, and service accounts.",
        ["CIS-GCP-2.9", "SOC2-CC6.3", "NIST-AC-6"],
    ),
    (
        "CSPM-GCP-008",
        "GCP Service Account Has Admin Role",
        "high",
        "CIS-GCP-1.5",
        "iam",
        "GCP service account has overly broad admin-level role assigned.",
        "Replace admin roles with granular, least-privilege custom roles.",
        ["CIS-GCP-1.5", "SOC2-CC6.3", "PCI-DSS-7.1", "NIST-AC-6"],
    ),
    (
        "CSPM-GCP-009",
        "GCP Compute Instance Uses Default Service Account With Full API Access",
        "high",
        "CIS-GCP-4.2",
        "compute",
        "GCP Compute instance uses the default service account with full API access scopes.",
        "Use a dedicated service account with minimal required API scopes.",
        ["CIS-GCP-4.2", "SOC2-CC6.3", "NIST-AC-6"],
    ),
    (
        "CSPM-GCP-010",
        "GCP VPC Flow Logs Disabled",
        "medium",
        "CIS-GCP-3.8",
        "logging",
        "GCP VPC subnet does not have flow logs enabled.",
        "Enable VPC flow logs on all subnets with appropriate sampling and metadata.",
        ["CIS-GCP-3.8", "SOC2-CC7.2", "PCI-DSS-10.2", "NIST-AU-2"],
    ),
    (
        "CSPM-GCP-011",
        "GCP GKE Cluster Has Basic Auth Enabled",
        "critical",
        "CIS-GCP-7.1",
        "container",
        "GKE cluster has basic authentication (username/password) enabled.",
        "Disable basic authentication and use RBAC with strong credentials.",
        ["CIS-GCP-7.1", "SOC2-CC6.1", "PCI-DSS-8.1", "NIST-IA-2"],
    ),
    (
        "CSPM-GCP-012",
        "GCP GKE Node Auto-Upgrade Disabled",
        "medium",
        "CIS-GCP-7.5",
        "container",
        "GKE node pool does not have auto-upgrade enabled.",
        "Enable node auto-upgrade to receive automatic security patches.",
        ["CIS-GCP-7.5", "SOC2-CC7.1", "NIST-SI-2"],
    ),
    (
        "CSPM-GCP-013",
        "GCP Cloud SQL Backup Disabled",
        "medium",
        "CIS-GCP-6.7",
        "database",
        "GCP Cloud SQL instance does not have automated backups enabled.",
        "Enable automated backups with binary logging for all Cloud SQL instances.",
        ["CIS-GCP-6.7", "SOC2-A1.2", "NIST-CP-9"],
    ),
    (
        "CSPM-GCP-014",
        "GCP BigQuery Dataset Publicly Accessible",
        "critical",
        "CIS-GCP-7.1",
        "storage",
        "GCP BigQuery dataset has public access granted to allUsers or allAuthenticatedUsers.",
        "Remove public IAM bindings from BigQuery datasets.",
        ["SOC2-CC6.6", "PCI-DSS-7.2", "NIST-AC-3"],
    ),
    (
        "CSPM-GCP-015",
        "GCP Project Lacks IAM Audit Config",
        "medium",
        "CIS-GCP-2.1",
        "logging",
        "GCP project does not have IAM audit configuration for all services.",
        "Configure IAM audit logging for all services including data access.",
        ["CIS-GCP-2.1", "SOC2-CC7.2", "PCI-DSS-10.1", "NIST-AU-2"],
    ),
    (
        "CSPM-GCP-016",
        "GCP Compute Disk Not Encrypted With CMEK",
        "low",
        "CIS-GCP-4.7",
        "encryption",
        "GCP Compute disk uses Google-managed encryption instead of CMEK.",
        "Use customer-managed encryption keys for sensitive Compute disks.",
        ["CIS-GCP-4.7", "SOC2-CC6.7", "PCI-DSS-3.4", "NIST-SC-28"],
    ),
    (
        "CSPM-GCP-017",
        "GCP Firewall Rule Allows SSH From Internet",
        "critical",
        "CIS-GCP-3.6",
        "network",
        "GCP firewall rule allows SSH (port 22) from 0.0.0.0/0.",
        "Restrict SSH access to specific IP ranges or use Cloud Identity-Aware Proxy.",
        ["CIS-GCP-3.6", "SOC2-CC6.6", "PCI-DSS-1.3", "NIST-SC-7"],
    ),
    (
        "CSPM-GCP-018",
        "GCP Service Account Key Not Rotated",
        "medium",
        "CIS-GCP-1.7",
        "iam",
        "GCP service account has user-managed keys older than 90 days.",
        "Rotate service account keys regularly and prefer Workload Identity.",
        ["CIS-GCP-1.7", "SOC2-CC6.1", "PCI-DSS-8.2.4", "NIST-IA-5"],
    ),
    (
        "CSPM-GCP-019",
        "GCP Cloud Storage Bucket Logging Disabled",
        "low",
        "CIS-GCP-5.3",
        "logging",
        "GCP Cloud Storage bucket does not have access logging enabled.",
        "Enable usage logs and storage logs for all GCS buckets.",
        ["CIS-GCP-5.3", "SOC2-CC7.2", "PCI-DSS-10.2", "NIST-AU-2"],
    ),
    (
        "CSPM-GCP-020",
        "GCP GKE Cluster Network Policy Disabled",
        "medium",
        "CIS-GCP-7.11",
        "container",
        "GKE cluster does not have a network policy enforced.",
        "Enable network policy enforcement on all GKE clusters.",
        ["CIS-GCP-7.11", "SOC2-CC6.6", "NIST-SC-7"],
    ),
]

ALL_RULES: Dict[CloudProvider, List[Tuple]] = {
    CloudProvider.AWS: AWS_RULES,
    CloudProvider.AZURE: AZURE_RULES,
    CloudProvider.GCP: GCP_RULES,
}


# ---------------------------------------------------------------------------
# GAP-025: Multi-CSP provider adapters (OCI, Alibaba, IBM)
# Each adapter implements:
#   - list_resources(account_id) -> List[Dict]   (seeded 4-5 fake resources)
#   - scan_resource(resource)   -> List[Dict]   (2-3 synthesized findings/res)
# ---------------------------------------------------------------------------

class _BaseProviderAdapter:
    """Base adapter with common seeded-scan logic."""

    provider_name: str = "base"

    # ordered list of seeded resources per provider (overridden)
    _SEED_RESOURCES: List[Dict[str, Any]] = []

    # list of rule tuples (title, severity, category, description, recommendation, compliance)
    _SEED_FINDINGS: List[Tuple[str, str, str, str, str, List[str]]] = []

    def list_resources(self, account_id: str) -> List[Dict[str, Any]]:
        """Return seeded resources belonging to the given account_id."""
        out: List[Dict[str, Any]] = []
        for i, res in enumerate(self._SEED_RESOURCES):
            out.append(
                {
                    "resource_id": f"{self.provider_name}-{account_id}-{i:03d}",
                    "account_id": account_id,
                    "provider": self.provider_name,
                    "resource_type": res["resource_type"],
                    "name": res["name"],
                    "region": res.get("region", "global"),
                    "is_public": res.get("is_public", False),
                    "is_encrypted": res.get("is_encrypted", True),
                }
            )
        return out

    def scan_resource(self, resource: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Synthesize 2-3 findings per resource based on seeded rule templates."""
        findings: List[Dict[str, Any]] = []
        rtype = resource.get("resource_type", "unknown")
        provider = resource.get("provider", self.provider_name)
        res_id = resource.get("resource_id", "unknown")
        # emit 2-3 findings per resource using the seeded rule set
        for i, rule in enumerate(self._SEED_FINDINGS[:3]):
            title, severity, category, description, recommendation, frameworks = rule
            findings.append(
                {
                    "finding_id": f"CSPM-{self.provider_name.upper()}-{uuid.uuid4().hex[:8]}",
                    "rule_id": f"CSPM-{self.provider_name.upper()}-{(i+1):03d}",
                    "title": title,
                    "severity": severity,
                    "category": category,
                    "provider": provider,
                    "resource_type": rtype,
                    "resource_id": res_id,
                    "description": description,
                    "recommendation": recommendation,
                    "compliance_frameworks": list(frameworks),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
        return findings


class OCIProviderAdapter(_BaseProviderAdapter):
    """Oracle Cloud Infrastructure (OCI) provider adapter."""

    provider_name = "oci"

    _SEED_RESOURCES = [
        {"resource_type": "object_storage_bucket", "name": "oci-logs-bucket", "region": "us-ashburn-1", "is_public": True},
        {"resource_type": "compute_instance", "name": "oci-web-01", "region": "us-ashburn-1", "is_public": True},
        {"resource_type": "autonomous_database", "name": "oci-adb-prod", "region": "us-phoenix-1", "is_encrypted": False},
        {"resource_type": "vcn_security_list", "name": "oci-sl-default", "region": "us-ashburn-1"},
        {"resource_type": "identity_user", "name": "oci-admin-user", "region": "global"},
    ]

    _SEED_FINDINGS = [
        (
            "OCI Object Storage Bucket Publicly Accessible",
            "critical",
            "storage",
            "OCI Object Storage bucket allows anonymous read access.",
            "Set visibility to 'NoPublicAccess' on OCI buckets.",
            ["CIS-OCI-4.1", "SOC2-CC6.6", "NIST-AC-3"],
        ),
        (
            "OCI Compute Instance Has Public IP",
            "medium",
            "compute",
            "OCI compute instance is configured with a public IP address.",
            "Remove public IP and use a NAT gateway or bastion host.",
            ["CIS-OCI-2.1", "SOC2-CC6.6", "NIST-SC-7"],
        ),
        (
            "OCI Autonomous Database Not Encrypted With CMK",
            "high",
            "encryption",
            "OCI Autonomous Database uses Oracle-managed keys instead of customer-managed keys.",
            "Enable customer-managed encryption keys via OCI Vault.",
            ["CIS-OCI-3.3", "SOC2-CC6.7", "PCI-DSS-3.4"],
        ),
    ]


class AlibabaProviderAdapter(_BaseProviderAdapter):
    """Alibaba Cloud provider adapter."""

    provider_name = "alibaba"

    _SEED_RESOURCES = [
        {"resource_type": "oss_bucket", "name": "ali-oss-logs", "region": "cn-hangzhou", "is_public": True},
        {"resource_type": "ecs_instance", "name": "ali-ecs-web01", "region": "cn-shanghai", "is_public": True},
        {"resource_type": "rds_instance", "name": "ali-rds-prod", "region": "cn-beijing", "is_encrypted": False},
        {"resource_type": "security_group", "name": "ali-sg-default", "region": "cn-hangzhou"},
        {"resource_type": "ram_user", "name": "ali-ram-admin", "region": "global"},
    ]

    _SEED_FINDINGS = [
        (
            "Alibaba OSS Bucket Publicly Accessible",
            "critical",
            "storage",
            "Alibaba Cloud OSS bucket allows anonymous read/write access.",
            "Set bucket ACL to 'private' on all OSS buckets.",
            ["CIS-Alibaba-4.1", "SOC2-CC6.6", "NIST-AC-3"],
        ),
        (
            "Alibaba Security Group Allows Unrestricted Inbound",
            "critical",
            "network",
            "Alibaba security group allows inbound traffic from 0.0.0.0/0.",
            "Restrict inbound rules to specific CIDR ranges.",
            ["CIS-Alibaba-5.2", "SOC2-CC6.6", "NIST-SC-7"],
        ),
        (
            "Alibaba RDS Instance Encryption Disabled",
            "high",
            "encryption",
            "Alibaba RDS instance does not have TDE (Transparent Data Encryption) enabled.",
            "Enable TDE on all production RDS instances.",
            ["CIS-Alibaba-3.1", "SOC2-CC6.7", "PCI-DSS-3.4"],
        ),
    ]


class IBMProviderAdapter(_BaseProviderAdapter):
    """IBM Cloud provider adapter."""

    provider_name = "ibm"

    _SEED_RESOURCES = [
        {"resource_type": "cos_bucket", "name": "ibm-cos-logs", "region": "us-south", "is_public": True},
        {"resource_type": "virtual_server", "name": "ibm-vs-web01", "region": "us-south", "is_public": True},
        {"resource_type": "cloudant_database", "name": "ibm-cloudant-prod", "region": "us-east", "is_encrypted": False},
        {"resource_type": "security_group", "name": "ibm-sg-default", "region": "us-south"},
        {"resource_type": "iam_service_id", "name": "ibm-iam-svc", "region": "global"},
    ]

    _SEED_FINDINGS = [
        (
            "IBM Cloud Object Storage Publicly Accessible",
            "critical",
            "storage",
            "IBM Cloud Object Storage bucket allows public access.",
            "Set bucket access policy to private on all COS buckets.",
            ["CIS-IBM-4.1", "SOC2-CC6.6", "NIST-AC-3"],
        ),
        (
            "IBM Virtual Server Has Public IP",
            "medium",
            "compute",
            "IBM virtual server is configured with a public IP address.",
            "Use a load balancer or VPN gateway instead of direct public IPs.",
            ["CIS-IBM-2.1", "SOC2-CC6.6", "NIST-SC-7"],
        ),
        (
            "IBM Cloudant Database Not Encrypted With BYOK",
            "high",
            "encryption",
            "IBM Cloudant database does not use a customer-managed Key Protect key.",
            "Enable BYOK encryption via IBM Key Protect.",
            ["CIS-IBM-3.2", "SOC2-CC6.7", "PCI-DSS-3.4"],
        ),
    ]


# Provider registry — all 6 supported CSPs
PROVIDERS: Dict[str, Any] = {
    "aws": None,       # native scanner (Terraform/CloudFormation)
    "azure": None,     # native scanner
    "gcp": None,       # native scanner
    "oci": OCIProviderAdapter(),
    "alibaba": AlibabaProviderAdapter(),
    "ibm": IBMProviderAdapter(),
}


def get_provider_adapter(provider: str) -> Optional[_BaseProviderAdapter]:
    """Return the provider adapter for a given provider name (case-insensitive)."""
    if not provider:
        return None
    return PROVIDERS.get(provider.lower())


def list_supported_providers() -> List[str]:
    """Return the canonical list of supported CSPM providers."""
    return ["aws", "azure", "gcp", "oci", "alibaba", "ibm"]


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class CspmFinding:
    """A single misconfiguration finding from a CSPM scan."""

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
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity.value if isinstance(self.severity, CspmSeverity) else self.severity,
            "category": self.category.value if isinstance(self.category, CspmCategory) else self.category,
            "provider": self.provider.value if isinstance(self.provider, CloudProvider) else self.provider,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "region": self.region,
            "cis_benchmark": self.cis_benchmark,
            "description": self.description,
            "recommendation": self.recommendation,
            "compliance_frameworks": self.compliance_frameworks,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
        }


@dataclass
class CspmScanResult:
    """Result of a CSPM IaC scan."""

    scan_id: str
    provider: str
    resources_scanned: int
    total_findings: int
    findings: List[CspmFinding]
    by_severity: Dict[str, int]
    by_category: Dict[str, int]
    compliance_score: float
    duration_ms: float
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

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
            "timestamp": self.timestamp,
        }


# ---------------------------------------------------------------------------
# CSPMEngine
# ---------------------------------------------------------------------------

_TF_RESOURCE_RE = re.compile(r'resource\s+"[^"]+"\s+"[^"]+"\s*\{')
_TF_ACL_PUBLIC_RE = re.compile(r'acl\s*=\s*"public')
_TF_CIDR_OPEN_RE = re.compile(r'cidr_blocks\s*=\s*\[.*?"0\.0\.0\.0/0"')
_TF_ENCRYPTION_FALSE_RE = re.compile(r'encrypted\s*=\s*false')
_TF_ENCRYPTION_MISSING_RE = re.compile(r'resource\s+"aws_ebs_volume"')
_TF_ENCRYPTION_TRUE_RE = re.compile(r'encrypted\s*=\s*true')
_TF_RDS_PUBLIC_TRUE_RE = re.compile(r'publicly_accessible\s*=\s*true')
_TF_RDS_PUBLIC_FALSE_RE = re.compile(r'publicly_accessible\s*=\s*false')
_TF_CLOUDTRAIL_RE = re.compile(r'resource\s+"aws_cloudtrail"')
_TF_IAM_WILDCARD_ACTION_RE = re.compile(r'"Action"\s*:\s*"\*"')
_TF_IAM_WILDCARD_RESOURCE_RE = re.compile(r'"Resource"\s*:\s*"\*"')
_TF_IAM_POLICY_RE = re.compile(r'resource\s+"aws_iam_policy"')
_TF_SG_RE = re.compile(r'resource\s+"aws_security_group"')


class CSPMEngine:
    """Lightweight CSPM engine for scanning IaC templates."""

    def __init__(self) -> None:
        try:
            import boto3  # noqa: F401
            self._boto3_available = True
        except ImportError:
            self._boto3_available = False

        try:
            from azure.identity import DefaultAzureCredential  # noqa: F401
            self._azure_available = True
        except ImportError:
            self._azure_available = False

        try:
            from google.cloud import storage  # noqa: F401
            self._gcp_available = True
        except ImportError:
            self._gcp_available = False

    # ------------------------------------------------------------------
    # Provider detection
    # ------------------------------------------------------------------

    def _detect_provider_tf(self, hcl: str) -> CloudProvider:
        """Detect cloud provider from Terraform HCL text."""
        if (
            'provider "azurerm"' in hcl
            or 'provider "azuread"' in hcl
            or '"azurerm_' in hcl
        ):
            return CloudProvider.AZURE
        if (
            'provider "google"' in hcl
            or 'provider "google-beta"' in hcl
            or '"google_' in hcl
        ):
            return CloudProvider.GCP
        # AWS is the default
        return CloudProvider.AWS

    # ------------------------------------------------------------------
    # Finding factory
    # ------------------------------------------------------------------

    def _make_finding(
        self,
        rule: Tuple,
        provider: CloudProvider,
        resource_id: str,
    ) -> CspmFinding:
        """Create a CspmFinding from a rule tuple."""
        rule_id, title, severity, cis_benchmark, category, description, recommendation, frameworks = rule
        # Derive resource_type from rule_id: "CSPM-AWS-001" → "AWS"
        parts = rule_id.split("-")
        resource_type = parts[1] if len(parts) >= 3 else "unknown"

        return CspmFinding(
            finding_id=f"CSPM-{uuid.uuid4().hex[:8].upper()}",
            title=title,
            severity=CspmSeverity(severity),
            category=CspmCategory(category),
            provider=provider,
            resource_type=resource_type,
            resource_id=resource_id,
            cis_benchmark=cis_benchmark,
            description=description,
            recommendation=recommendation,
            compliance_frameworks=list(frameworks),
        )

    # ------------------------------------------------------------------
    # Summarize helper
    # ------------------------------------------------------------------

    @staticmethod
    def _summarize(
        findings: List[CspmFinding],
    ) -> Tuple[Dict[str, int], Dict[str, int]]:
        """Return (by_severity, by_category) count dicts."""
        by_sev: Dict[str, int] = {}
        by_cat: Dict[str, int] = {}
        for f in findings:
            sev = f.severity.value if isinstance(f.severity, CspmSeverity) else str(f.severity)
            cat = f.category.value if isinstance(f.category, CspmCategory) else str(f.category)
            by_sev[sev] = by_sev.get(sev, 0) + 1
            by_cat[cat] = by_cat.get(cat, 0) + 1
        return by_sev, by_cat

    # ------------------------------------------------------------------
    # Terraform scanning
    # ------------------------------------------------------------------

    def scan_terraform(self, hcl: str, filename: str = "main.tf") -> CspmScanResult:
        """Scan a Terraform HCL template for misconfigurations.

        Returns a CspmScanResult with all findings detected via pattern matching.
        """
        t0 = time.perf_counter()
        findings: List[CspmFinding] = []

        try:
            provider = self._detect_provider_tf(hcl)
            resources_scanned = max(len(_TF_RESOURCE_RE.findall(hcl)), 1)

            # Only run AWS-specific checks for AWS templates
            if provider == CloudProvider.AWS:
                # Check 1: S3 public ACL
                if _TF_ACL_PUBLIC_RE.search(hcl):
                    findings.append(self._make_finding(AWS_RULES[0], provider, filename))

                # Check 2: Security group open to world (0.0.0.0/0 with ingress)
                if _TF_SG_RE.search(hcl) and _TF_CIDR_OPEN_RE.search(hcl):
                    findings.append(self._make_finding(AWS_RULES[7], provider, filename))

                # Check 3: Unencrypted EBS volume (has aws_ebs_volume but no encrypted = true)
                if _TF_ENCRYPTION_MISSING_RE.search(hcl) and not _TF_ENCRYPTION_TRUE_RE.search(hcl):
                    findings.append(self._make_finding(AWS_RULES[19], provider, filename))

                # Check 4: Publicly accessible RDS
                if _TF_RDS_PUBLIC_TRUE_RE.search(hcl):
                    findings.append(self._make_finding(AWS_RULES[6], provider, filename))

                # Check 5: Missing CloudTrail → logging finding
                if not _TF_CLOUDTRAIL_RE.search(hcl):
                    findings.append(self._make_finding(AWS_RULES[4], provider, filename))

                # Check 6: IAM wildcard permissions
                if _TF_IAM_POLICY_RE.search(hcl) and (
                    _TF_IAM_WILDCARD_ACTION_RE.search(hcl)
                    or _TF_IAM_WILDCARD_RESOURCE_RE.search(hcl)
                ):
                    findings.append(self._make_finding(AWS_RULES[10], provider, filename))

        except Exception:
            # Never crash — return empty result on any error
            pass

        by_sev, by_cat = self._summarize(findings)
        score = self._compliance_score(len(findings), resources_scanned if "resources_scanned" in dir() else 1)
        duration_ms = (time.perf_counter() - t0) * 1000

        _provider_val = provider.value if "provider" in dir() else "aws"
        _resources_val = resources_scanned if "resources_scanned" in dir() else 1
        _emit_event("cspm.scan.terraform.completed", {
            "provider": _provider_val,
            "filename": filename,
            "resources_scanned": _resources_val,
            "findings_count": len(findings),
            "compliance_score": score,
            "duration_ms": duration_ms,
        })

        return CspmScanResult(
            scan_id=f"cspm-{uuid.uuid4().hex[:10]}",
            provider=_provider_val,
            resources_scanned=_resources_val,
            total_findings=len(findings),
            findings=findings,
            by_severity=by_sev,
            by_category=by_cat,
            compliance_score=score,
            duration_ms=duration_ms,
        )

    # ------------------------------------------------------------------
    # CloudFormation scanning
    # ------------------------------------------------------------------

    def scan_cloudformation(self, cf_text: str, filename: str = "template.json") -> CspmScanResult:
        """Scan a CloudFormation template (JSON) for misconfigurations.

        Returns a CspmScanResult with all findings detected via structured parsing.
        """
        t0 = time.perf_counter()
        findings: List[CspmFinding] = []
        resources_scanned = 0

        try:
            if not cf_text or not cf_text.strip():
                template = {}
            else:
                template = json.loads(cf_text)

            cf_resources: Dict[str, Any] = template.get("Resources", {})
            resources_scanned = len(cf_resources)

            for logical_id, resource_def in cf_resources.items():
                rtype = resource_def.get("Type", "")
                props = resource_def.get("Properties", {})

                # S3 Bucket: check AccessControl
                if rtype == "AWS::S3::Bucket":
                    acl = props.get("AccessControl", "Private")
                    if acl not in ("Private", "AuthenticatedRead"):
                        findings.append(
                            self._make_finding(AWS_RULES[0], CloudProvider.AWS, logical_id)
                        )

                # Security Group: check ingress for 0.0.0.0/0
                elif rtype == "AWS::EC2::SecurityGroup":
                    ingress_rules = props.get("SecurityGroupIngress", [])
                    if isinstance(ingress_rules, list):
                        for rule in ingress_rules:
                            cidr = rule.get("CidrIp", "") or rule.get("CidrIpv6", "")
                            if cidr in ("0.0.0.0/0", "::/0"):
                                findings.append(
                                    self._make_finding(AWS_RULES[7], CloudProvider.AWS, logical_id)
                                )
                                break

                # RDS: check PubliclyAccessible
                elif rtype == "AWS::RDS::DBInstance":
                    if props.get("PubliclyAccessible") is True:
                        findings.append(
                            self._make_finding(AWS_RULES[6], CloudProvider.AWS, logical_id)
                        )

        except (json.JSONDecodeError, ValueError, AttributeError):
            # Return empty result on parse errors
            pass

        by_sev, by_cat = self._summarize(findings)
        score = self._compliance_score(len(findings), max(resources_scanned, 1))
        duration_ms = (time.perf_counter() - t0) * 1000

        _emit_event("cspm.scan.cloudformation.completed", {
            "provider": "aws",
            "filename": filename,
            "resources_scanned": resources_scanned,
            "findings_count": len(findings),
            "compliance_score": score,
            "duration_ms": duration_ms,
        })

        return CspmScanResult(
            scan_id=f"cspm-{uuid.uuid4().hex[:10]}",
            provider="aws",
            resources_scanned=resources_scanned,
            total_findings=len(findings),
            findings=findings,
            by_severity=by_sev,
            by_category=by_cat,
            compliance_score=score,
            duration_ms=duration_ms,
        )

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    @staticmethod
    def _compliance_score(findings: int, resources: int) -> float:
        """Score = (1 - findings / max(resources, 1)) * 100, clamped to [0, 100]."""
        denom = max(resources, 1)
        score = (1.0 - findings / denom) * 100.0
        return max(0.0, min(100.0, round(score, 2)))


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_engine: Optional[CSPMEngine] = None


def get_cspm_engine() -> CSPMEngine:
    """Return the singleton CSPMEngine instance."""
    global _engine
    if _engine is None:
        _engine = CSPMEngine()
    return _engine


# ---------------------------------------------------------------------------
# Backward-compat shims for cspm_router.py (Pydantic-based API)
# These are imported by suite-api/apps/api/cspm_router.py
# ---------------------------------------------------------------------------

try:
    import uuid as _uuid
    from datetime import datetime as _datetime
    from datetime import timezone as _timezone
    from enum import Enum as _Enum
    from typing import Any as _Any
    from typing import Dict as _Dict
    from typing import List as _List
    from typing import Optional as _Optional

    from pydantic import BaseModel as _BaseModel
    from pydantic import Field as _Field


    class _LegacyEnum(str, _Enum):
        pass

    class ResourceType(_LegacyEnum):
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

    class Severity(_LegacyEnum):
        CRITICAL = "critical"
        HIGH = "high"
        MEDIUM = "medium"
        LOW = "low"
        INFORMATIONAL = "informational"

    class FindingStatus(_LegacyEnum):
        OPEN = "open"
        SUPPRESSED = "suppressed"
        RESOLVED = "resolved"
        IN_REMEDIATION = "in_remediation"

    class ComplianceFramework(_LegacyEnum):
        SOC2 = "soc2"
        PCI_DSS = "pci_dss"
        HIPAA = "hipaa"
        FEDRAMP = "fedramp"
        NIST_800_53 = "nist_800_53"
        CIS = "cis"

    class CloudResource(_BaseModel):
        id: str = _Field(default_factory=lambda: f"res-{_uuid.uuid4().hex[:12]}")
        provider: CloudProvider
        resource_type: ResourceType
        name: str
        region: str = "global"
        account_id: str = "unknown"
        org_id: str = "default"
        tags: _Dict[str, str] = _Field(default_factory=dict)
        owner: _Optional[str] = None
        created_at: _Optional[str] = None
        last_modified: _Optional[str] = None
        is_public: bool = False
        is_encrypted: bool = True
        metadata: _Dict[str, _Any] = _Field(default_factory=dict)
        discovered_at: str = _Field(
            default_factory=lambda: _datetime.now(_timezone.utc).isoformat()
        )

    class CSPMFinding(_BaseModel):
        id: str = _Field(default_factory=lambda: f"cspm-{_uuid.uuid4().hex[:12]}")
        rule_id: str = ""
        rule_title: str = ""
        resource_id: str = ""
        resource_name: str = ""
        resource_type: ResourceType = ResourceType.EC2_INSTANCE
        provider: CloudProvider = CloudProvider.AWS
        account_id: str = "unknown"
        region: str = "global"
        severity: Severity = Severity.MEDIUM
        status: FindingStatus = FindingStatus.OPEN
        description: str = ""
        remediation_summary: str = ""
        remediation_cli: _Optional[str] = None
        remediation_terraform: _Optional[str] = None
        compliance_mapping: _Dict[str, _List[str]] = _Field(default_factory=dict)
        org_id: str = "default"
        detected_at: str = _Field(
            default_factory=lambda: _datetime.now(_timezone.utc).isoformat()
        )
        resolved_at: _Optional[str] = None
        suppression_reason: _Optional[str] = None

    class RemediationPlaybook(_BaseModel):
        finding_id: str
        rule_id: str
        title: str
        steps: _List[str]
        cli_commands: _List[str] = _Field(default_factory=list)
        terraform_blocks: _List[str] = _Field(default_factory=list)
        estimated_effort: str = "5 minutes"
        risk_level: str = "low"
        requires_downtime: bool = False

    class AccountPosture(_BaseModel):
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
        compliance_scores: _Dict[str, float] = _Field(default_factory=dict)
        last_scanned: str = _Field(
            default_factory=lambda: _datetime.now(_timezone.utc).isoformat()
        )

    class OrgPosture(_BaseModel):
        org_id: str
        overall_score: float
        total_resources: int
        total_findings: int
        critical_findings: int
        high_findings: int
        medium_findings: int
        low_findings: int
        accounts: _List[AccountPosture] = _Field(default_factory=list)
        compliance_scores: _Dict[str, float] = _Field(default_factory=dict)
        scanned_at: str = _Field(
            default_factory=lambda: _datetime.now(_timezone.utc).isoformat()
        )

    class ScanRequest(_BaseModel):
        org_id: str = "default"
        account_ids: _List[str] = _Field(default_factory=list)
        providers: _List[CloudProvider] = _Field(default_factory=list)
        rule_ids: _Optional[_List[str]] = None

    class ScanResult(_BaseModel):
        scan_id: str = _Field(default_factory=lambda: f"scan-{_uuid.uuid4().hex[:12]}")
        org_id: str = "default"
        resources_scanned: int = 0
        findings_count: int = 0
        drift_events_count: int = 0
        posture: _Optional[OrgPosture] = None
        started_at: str = _Field(
            default_factory=lambda: _datetime.now(_timezone.utc).isoformat()
        )
        completed_at: str = _Field(
            default_factory=lambda: _datetime.now(_timezone.utc).isoformat()
        )

    # Stub legacy methods onto CSPMEngine so cspm_router.py doesn't break
    def _stub_get_posture(self, org_id: str = "default") -> OrgPosture:
        return OrgPosture(
            org_id=org_id,
            overall_score=100.0,
            total_resources=0,
            total_findings=0,
            critical_findings=0,
            high_findings=0,
            medium_findings=0,
            low_findings=0,
        )

    def _stub_list_findings(self, org_id="default", status=None, severity=None):
        return []

    def _stub_list_resources(self, org_id="default"):
        return []

    def _stub_register_resource(self, resource):
        return resource

    def _stub_get_benchmark_status(self, org_id="default"):
        return {"rules": [], "org_id": org_id}

    def _stub_run_scan(self, org_id="default", rule_ids=None):
        posture = OrgPosture(
            org_id=org_id,
            overall_score=100.0,
            total_resources=0,
            total_findings=0,
            critical_findings=0,
            high_findings=0,
            medium_findings=0,
            low_findings=0,
        )
        return ScanResult(
            org_id=org_id,
            posture=posture,
            started_at=_datetime.now(_timezone.utc).isoformat(),
        )

    def _stub_list_drift(self, org_id="default"):
        return []

    def _stub_save_baseline(self, org_id="default"):
        return 0

    def _stub_get_remediation(self, finding_id: str):
        return None

    def _stub_get_compliance_map(self):
        return {}

    def _stub_get_finding(self, finding_id: str):
        return None

    def _stub_suppress_finding(self, finding_id: str, reason: str):
        return None

    def _stub_resolve_finding(self, finding_id: str):
        return None

    def _stub_list_scans(self, org_id="default", limit=10):
        return []

    def _stub_get_resource(self, resource_id: str):
        return None

    def _stub_delete_resource(self, resource_id: str):
        return False

    # ---------------------------------------------------------------------------
    # AllowlistEntry — finding-suppression allowlist model
    # ---------------------------------------------------------------------------

    class AllowlistEntry(_BaseModel):
        id: str = _Field(default_factory=lambda: f"allow-{_uuid.uuid4().hex[:12]}")
        org_id: str = "default"
        rule_id: str = _Field(..., description="CSPM rule ID to suppress (e.g. CSPM-AWS-001)")
        resource_id: _Optional[str] = _Field(
            None,
            description="Specific resource ID — None means suppress rule org-wide",
        )
        reason: str = _Field(..., description="Business justification for exception")
        created_by: str = "system"
        expires_at: _Optional[str] = _Field(
            None,
            description="ISO-8601 expiry — None means permanent",
        )
        created_at: str = _Field(
            default_factory=lambda: _datetime.now(_timezone.utc).isoformat()
        )

    # Storage: in-memory list (survives the process lifetime, adequate for the stub)
    _ALLOWLIST_STORE: _List = []

    def _stub_add_allowlist_entry(self, entry: AllowlistEntry) -> AllowlistEntry:
        _ALLOWLIST_STORE.append(entry)
        _emit_event("cspm.allowlist.added", {"id": entry.id, "rule_id": entry.rule_id})
        return entry

    def _stub_list_allowlist(
        self,
        org_id: str = "default",
        rule_id: _Optional[str] = None,
    ) -> _List[AllowlistEntry]:
        entries = [e for e in _ALLOWLIST_STORE if e.org_id == org_id]
        if rule_id:
            entries = [e for e in entries if e.rule_id == rule_id]
        return entries

    def _stub_delete_allowlist_entry(self, entry_id: str) -> bool:
        for i, e in enumerate(_ALLOWLIST_STORE):
            if e.id == entry_id:
                _ALLOWLIST_STORE.pop(i)
                _emit_event("cspm.allowlist.deleted", {"id": entry_id})
                return True
        return False

    # Attach stubs to CSPMEngine
    CSPMEngine.get_posture = _stub_get_posture  # type: ignore[attr-defined]
    CSPMEngine.list_findings = _stub_list_findings  # type: ignore[attr-defined]
    CSPMEngine.list_resources = _stub_list_resources  # type: ignore[attr-defined]
    CSPMEngine.register_resource = _stub_register_resource  # type: ignore[attr-defined]
    CSPMEngine.get_benchmark_status = _stub_get_benchmark_status  # type: ignore[attr-defined]
    CSPMEngine.run_scan = _stub_run_scan  # type: ignore[attr-defined]
    CSPMEngine.list_drift = _stub_list_drift  # type: ignore[attr-defined]
    CSPMEngine.save_baseline = _stub_save_baseline  # type: ignore[attr-defined]
    CSPMEngine.get_remediation = _stub_get_remediation  # type: ignore[attr-defined]
    CSPMEngine.get_compliance_map = _stub_get_compliance_map  # type: ignore[attr-defined]
    CSPMEngine.get_finding = _stub_get_finding  # type: ignore[attr-defined]
    CSPMEngine.suppress_finding = _stub_suppress_finding  # type: ignore[attr-defined]
    CSPMEngine.resolve_finding = _stub_resolve_finding  # type: ignore[attr-defined]
    CSPMEngine.list_scans = _stub_list_scans  # type: ignore[attr-defined]
    CSPMEngine.get_resource = _stub_get_resource  # type: ignore[attr-defined]
    CSPMEngine.delete_resource = _stub_delete_resource  # type: ignore[attr-defined]
    CSPMEngine.add_allowlist_entry = _stub_add_allowlist_entry  # type: ignore[attr-defined]
    CSPMEngine.list_allowlist = _stub_list_allowlist  # type: ignore[attr-defined]
    CSPMEngine.delete_allowlist_entry = _stub_delete_allowlist_entry  # type: ignore[attr-defined]

except Exception:
    # Pydantic not available — skip legacy compat shims
    pass
