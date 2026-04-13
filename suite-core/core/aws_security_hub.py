"""
ALdeci AWS Security Hub Integration — Pull findings from AWS Security Hub.

Connects to AWS Security Hub via a mocked boto3 interface, normalizes findings
from AWS Security Finding Format (ASFF), and stores them for ingestion into
the Brain Pipeline.

Usage:
    client = AWSSecurityHubClient(region="us-east-1")
    if client.is_configured():
        result = client.import_findings(org_id="acme")

Vision Pillars: V1 (APP_ID-Centric), V3 (Decision Intelligence), V9 (Air-Gapped)
"""

from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-memory import history store (keyed by org_id)
# ---------------------------------------------------------------------------
_import_history: Dict[str, List[Dict[str, Any]]] = {}
_history_lock = None  # lazy-init threading.Lock


def _get_lock():
    global _history_lock
    if _history_lock is None:
        import threading
        _history_lock = threading.Lock()
    return _history_lock


# ---------------------------------------------------------------------------
# ASFF severity → normalized severity mapping
# ---------------------------------------------------------------------------
_ASFF_SEVERITY_MAP: Dict[str, str] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFORMATIONAL": "info",
}

# ---------------------------------------------------------------------------
# Mock AWS Security Hub findings (realistic ASFF format)
# ---------------------------------------------------------------------------
_MOCK_FINDINGS: List[Dict[str, Any]] = [
    {
        "SchemaVersion": "2018-10-08",
        "Id": "arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/IAM.1/finding/mock-001",
        "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
        "ProductName": "Security Hub",
        "CompanyName": "AWS",
        "Region": "us-east-1",
        "GeneratorId": "aws-foundational-security-best-practices/v/1.0.0/IAM.1",
        "AwsAccountId": "123456789012",
        "Types": ["Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices"],
        "FirstObservedAt": "2026-01-01T00:00:00.000Z",
        "LastObservedAt": "2026-01-10T00:00:00.000Z",
        "CreatedAt": "2026-01-01T00:00:00.000Z",
        "UpdatedAt": "2026-01-10T00:00:00.000Z",
        "Severity": {"Label": "HIGH", "Normalized": 70},
        "Title": "IAM root user access key should not exist",
        "Description": "The root user is the most privileged user in an AWS account. AWS strongly recommends that you do not use root user credentials for daily tasks.",
        "Remediation": {
            "Recommendation": {
                "Text": "Delete the root user access keys. For more information see: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#lock-away-credentials",
                "Url": "https://docs.aws.amazon.com/console/securityhub/IAM.1/remediation",
            }
        },
        "ProductFields": {"StandardsArn": "arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0"},
        "Resources": [
            {
                "Type": "AwsAccount",
                "Id": "AWS::::Account:123456789012",
                "Partition": "aws",
                "Region": "us-east-1",
            }
        ],
        "Compliance": {"Status": "FAILED"},
        "WorkflowState": "NEW",
        "Workflow": {"Status": "NEW"},
        "RecordState": "ACTIVE",
        "FindingProviderFields": {"Severity": {"Label": "HIGH"}},
    },
    {
        "SchemaVersion": "2018-10-08",
        "Id": "arn:aws:securityhub:us-east-1:123456789012:subscription/cis-aws-foundations-benchmark/v/1.2.0/1.3/finding/mock-002",
        "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
        "ProductName": "Security Hub",
        "CompanyName": "AWS",
        "Region": "us-east-1",
        "GeneratorId": "cis-aws-foundations-benchmark/v/1.2.0/1.3",
        "AwsAccountId": "123456789012",
        "Types": ["Software and Configuration Checks/Industry and Regulatory Standards/CIS-AWS-Foundations-Benchmark"],
        "FirstObservedAt": "2026-01-02T00:00:00.000Z",
        "LastObservedAt": "2026-01-10T00:00:00.000Z",
        "CreatedAt": "2026-01-02T00:00:00.000Z",
        "UpdatedAt": "2026-01-10T00:00:00.000Z",
        "Severity": {"Label": "MEDIUM", "Normalized": 40},
        "Title": "Ensure credentials unused for 90 days or greater are disabled",
        "Description": "AWS IAM users can access AWS resources using different types of credentials, such as passwords or access keys. It is recommended that all credentials that have been unused in 90 or greater days be removed or deactivated.",
        "Remediation": {
            "Recommendation": {
                "Text": "Disable or remove unused IAM credentials.",
                "Url": "https://docs.aws.amazon.com/console/securityhub/standards-cis-1.3/remediation",
            }
        },
        "ProductFields": {"StandardsArn": "arn:aws:securityhub:::standards/cis-aws-foundations-benchmark/v/1.2.0"},
        "Resources": [
            {
                "Type": "AwsIamUser",
                "Id": "arn:aws:iam::123456789012:user/stale-user",
                "Partition": "aws",
                "Region": "us-east-1",
                "Details": {"AwsIamUser": {"UserName": "stale-user"}},
            }
        ],
        "Compliance": {"Status": "FAILED"},
        "WorkflowState": "NEW",
        "Workflow": {"Status": "NEW"},
        "RecordState": "ACTIVE",
        "FindingProviderFields": {"Severity": {"Label": "MEDIUM"}},
    },
    {
        "SchemaVersion": "2018-10-08",
        "Id": "arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/mock-003",
        "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
        "ProductName": "Security Hub",
        "CompanyName": "AWS",
        "Region": "us-east-1",
        "GeneratorId": "aws-foundational-security-best-practices/v/1.0.0/S3.1",
        "AwsAccountId": "123456789012",
        "Types": ["Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices"],
        "FirstObservedAt": "2026-01-03T00:00:00.000Z",
        "LastObservedAt": "2026-01-10T00:00:00.000Z",
        "CreatedAt": "2026-01-03T00:00:00.000Z",
        "UpdatedAt": "2026-01-10T00:00:00.000Z",
        "Severity": {"Label": "CRITICAL", "Normalized": 90},
        "Title": "S3 Block Public Access setting should be enabled",
        "Description": "This control checks whether the following Amazon S3 public access block settings are configured at the account level. The control fails if any of the following settings are not enabled.",
        "Remediation": {
            "Recommendation": {
                "Text": "Enable Amazon S3 Block Public Access at the account level.",
                "Url": "https://docs.aws.amazon.com/console/securityhub/S3.1/remediation",
            }
        },
        "ProductFields": {"StandardsArn": "arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0"},
        "Resources": [
            {
                "Type": "AwsS3Bucket",
                "Id": "arn:aws:s3:::my-public-bucket",
                "Partition": "aws",
                "Region": "us-east-1",
                "Details": {"AwsS3Bucket": {"BucketName": "my-public-bucket"}},
            }
        ],
        "Compliance": {"Status": "FAILED"},
        "WorkflowState": "NEW",
        "Workflow": {"Status": "NEW"},
        "RecordState": "ACTIVE",
        "FindingProviderFields": {"Severity": {"Label": "CRITICAL"}},
    },
    {
        "SchemaVersion": "2018-10-08",
        "Id": "arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/EC2.6/finding/mock-004",
        "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
        "ProductName": "Security Hub",
        "CompanyName": "AWS",
        "Region": "us-east-1",
        "GeneratorId": "aws-foundational-security-best-practices/v/1.0.0/EC2.6",
        "AwsAccountId": "123456789012",
        "Types": ["Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices"],
        "FirstObservedAt": "2026-01-04T00:00:00.000Z",
        "LastObservedAt": "2026-01-10T00:00:00.000Z",
        "CreatedAt": "2026-01-04T00:00:00.000Z",
        "UpdatedAt": "2026-01-10T00:00:00.000Z",
        "Severity": {"Label": "HIGH", "Normalized": 70},
        "Title": "VPC flow logging should be enabled in all VPCs",
        "Description": "VPC Flow Logs is a feature that enables you to capture information about the IP traffic going to and from network interfaces in your VPC.",
        "Remediation": {
            "Recommendation": {
                "Text": "Enable VPC flow logging for all VPCs.",
                "Url": "https://docs.aws.amazon.com/console/securityhub/EC2.6/remediation",
            }
        },
        "ProductFields": {},
        "Resources": [
            {
                "Type": "AwsEc2Vpc",
                "Id": "arn:aws:ec2:us-east-1:123456789012:vpc/vpc-12345678",
                "Partition": "aws",
                "Region": "us-east-1",
            }
        ],
        "Compliance": {"Status": "FAILED"},
        "WorkflowState": "NEW",
        "Workflow": {"Status": "NEW"},
        "RecordState": "ACTIVE",
        "FindingProviderFields": {"Severity": {"Label": "HIGH"}},
    },
]

_MOCK_INSIGHTS: List[Dict[str, Any]] = [
    {
        "InsightArn": "arn:aws:securityhub:us-east-1:123456789012:insight/mock-insight-001",
        "Name": "Top products by counts of failed findings",
        "Filters": {
            "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
            "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
        },
        "GroupByAttribute": "ProductName",
        "ResultType": "mock",
    },
    {
        "InsightArn": "arn:aws:securityhub:us-east-1:123456789012:insight/mock-insight-002",
        "Name": "Severity by resource type",
        "Filters": {
            "SeverityLabel": [{"Value": "CRITICAL", "Comparison": "EQUALS"}],
        },
        "GroupByAttribute": "ResourceType",
        "ResultType": "mock",
    },
]

_MOCK_STANDARDS_STATUS: Dict[str, Any] = {
    "standards": [
        {
            "StandardsArn": "arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0",
            "Name": "AWS Foundational Security Best Practices v1.0.0",
            "Status": "READY",
            "EnabledAt": "2026-01-01T00:00:00.000Z",
            "ControlsCount": 67,
            "PassedControlsCount": 52,
            "FailedControlsCount": 15,
            "ComplianceScore": 77.6,
        },
        {
            "StandardsArn": "arn:aws:securityhub:::standards/cis-aws-foundations-benchmark/v/1.2.0",
            "Name": "CIS AWS Foundations Benchmark v1.2.0",
            "Status": "READY",
            "EnabledAt": "2026-01-01T00:00:00.000Z",
            "ControlsCount": 43,
            "PassedControlsCount": 38,
            "FailedControlsCount": 5,
            "ComplianceScore": 88.4,
        },
        {
            "StandardsArn": "arn:aws:securityhub:::standards/pci-dss/v/3.2.1",
            "Name": "PCI DSS v3.2.1",
            "Status": "READY",
            "EnabledAt": "2026-01-02T00:00:00.000Z",
            "ControlsCount": 34,
            "PassedControlsCount": 30,
            "FailedControlsCount": 4,
            "ComplianceScore": 88.2,
        },
    ],
    "is_mock": True,
}


# ---------------------------------------------------------------------------
# AWSSecurityHubClient
# ---------------------------------------------------------------------------


class AWSSecurityHubClient:
    """
    Client for AWS Security Hub findings ingestion.

    Uses a mocked boto3 interface — no real boto3 dependency required.
    Falls back to realistic mock data when no credentials are configured
    so that the rest of the pipeline can be exercised without AWS access.
    """

    #: Default AWS region
    DEFAULT_REGION = "us-east-1"

    def __init__(
        self,
        region: Optional[str] = None,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
    ) -> None:
        self._region: str = (
            region
            or os.environ.get("AWS_DEFAULT_REGION", "")
            or os.environ.get("AWS_REGION", "")
            or self.DEFAULT_REGION
        ).strip()
        self._access_key: str = (
            access_key
            or os.environ.get("AWS_ACCESS_KEY_ID", "")
            or ""
        ).strip()
        self._secret_key: str = (
            secret_key
            or os.environ.get("AWS_SECRET_ACCESS_KEY", "")
            or ""
        ).strip()

    # ------------------------------------------------------------------
    # Configuration check
    # ------------------------------------------------------------------

    def is_configured(self) -> bool:
        """Return True if AWS credentials are set."""
        return bool(self._access_key and self._secret_key)

    # ------------------------------------------------------------------
    # Public API methods (mock-safe)
    # ------------------------------------------------------------------

    def get_findings(self, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Pull findings from AWS Security Hub.

        Args:
            filters: ASFF filter dict (e.g. SeverityLabel, WorkflowStatus).
                     Passed through to GetFindings when credentials are real.

        Returns:
            List of raw ASFF finding dicts. Returns mock data when unconfigured.
        """
        if not self.is_configured():
            logger.warning(
                "AWS credentials not configured — returning mock Security Hub findings. "
                "Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY for real data."
            )
            return list(_MOCK_FINDINGS)

        try:
            client = self._make_boto3_client()
            paginator = client.get_paginator("get_findings")
            kwargs: Dict[str, Any] = {}
            if filters:
                kwargs["Filters"] = filters
            findings: List[Dict[str, Any]] = []
            for page in paginator.paginate(**kwargs):
                findings.extend(page.get("Findings", []))
            return findings
        except Exception as exc:
            logger.error("get_findings failed: %s", exc, exc_info=True)
            raise RuntimeError(f"AWS Security Hub get_findings failed: {exc}") from exc

    def get_insights(self) -> List[Dict[str, Any]]:
        """
        Retrieve Security Hub insights.

        Returns:
            List of insight dicts. Returns mock data when unconfigured.
        """
        if not self.is_configured():
            logger.warning(
                "AWS credentials not configured — returning mock Security Hub insights."
            )
            return list(_MOCK_INSIGHTS)

        try:
            client = self._make_boto3_client()
            paginator = client.get_paginator("get_insights")
            insights: List[Dict[str, Any]] = []
            for page in paginator.paginate():
                insights.extend(page.get("Insights", []))
            return insights
        except Exception as exc:
            logger.error("get_insights failed: %s", exc, exc_info=True)
            raise RuntimeError(f"AWS Security Hub get_insights failed: {exc}") from exc

    def get_standards_status(self) -> Dict[str, Any]:
        """
        Retrieve enabled compliance standards and their pass/fail status.

        Returns:
            Dict with standards list and summary. Returns mock data when unconfigured.
        """
        if not self.is_configured():
            logger.warning(
                "AWS credentials not configured — returning mock standards status."
            )
            return dict(_MOCK_STANDARDS_STATUS)

        try:
            client = self._make_boto3_client()
            paginator = client.get_paginator("get_enabled_standards")
            raw_standards: List[Dict[str, Any]] = []
            for page in paginator.paginate():
                raw_standards.extend(page.get("StandardsSubscriptions", []))

            standards = []
            for sub in raw_standards:
                standards.append({
                    "StandardsArn": sub.get("StandardsArn", ""),
                    "Name": sub.get("StandardsArn", "").rsplit("/", 2)[-2].replace("-", " ").title()
                    if sub.get("StandardsArn") else "Unknown Standard",
                    "Status": sub.get("StandardsStatus", "UNKNOWN"),
                    "EnabledAt": sub.get("StandardsInput", {}).get("EnabledAt", ""),
                })

            return {"standards": standards, "is_mock": False}
        except Exception as exc:
            logger.error("get_standards_status failed: %s", exc, exc_info=True)
            raise RuntimeError(f"AWS Security Hub get_standards_status failed: {exc}") from exc

    def import_findings(self, org_id: str = "default") -> Dict[str, Any]:
        """
        Pull findings from Security Hub, normalize to UnifiedFinding format,
        store in history, and optionally push into the Brain Pipeline.

        Args:
            org_id: Organisation identifier for multi-tenancy.

        Returns:
            Summary dict with import_id, findings_count, severity breakdown, etc.
        """
        import_id = str(uuid.uuid4())
        started_at = datetime.now(timezone.utc).isoformat()
        is_mock = not self.is_configured()

        try:
            raw_findings = self.get_findings()
            findings = self.normalize_asff(raw_findings)

            sev_counts: Dict[str, int] = {
                "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
            }
            for f in findings:
                sev = (f.get("severity") or "info").lower()
                sev_counts[sev] = sev_counts.get(sev, 0) + 1

            entry: Dict[str, Any] = {
                "import_id": import_id,
                "org_id": org_id,
                "started_at": started_at,
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "status": "completed",
                "is_mock": is_mock,
                "findings_count": len(findings),
                "severity_breakdown": sev_counts,
                "findings": findings,
            }

            self._try_ingest_to_pipeline(findings, org_id, import_id)

        except Exception as exc:
            logger.error(
                "Security Hub import failed for org=%s: %s", org_id, exc, exc_info=True
            )
            entry = {
                "import_id": import_id,
                "org_id": org_id,
                "started_at": started_at,
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "status": "failed",
                "error": str(exc),
                "is_mock": is_mock,
                "findings_count": 0,
                "severity_breakdown": {},
                "findings": [],
            }

        with _get_lock():
            _import_history.setdefault(org_id, []).append(entry)

        return entry

    def normalize_asff(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Normalize AWS Security Finding Format (ASFF) findings to UnifiedFinding dicts.

        Tries SecurityHubNormalizer from scanner_parsers when available;
        falls back to inline normalization so this module works standalone.

        Args:
            findings: List of raw ASFF finding dicts.

        Returns:
            List of normalized finding dicts.
        """
        if not findings:
            return []

        try:
            import json
            from core.scanner_parsers import SecurityHubNormalizer
            normalizer = SecurityHubNormalizer()
            raw_bytes = json.dumps({"findings": findings}).encode()
            findings_raw = normalizer.normalize(raw_bytes)
            result = []
            for f in findings_raw:
                if isinstance(f, dict):
                    result.append(f)
                elif hasattr(f, "model_dump"):
                    result.append(f.model_dump())
                elif hasattr(f, "__dict__"):
                    result.append(
                        {k: v for k, v in f.__dict__.items() if not k.startswith("_")}
                    )
                else:
                    result.append({"raw": str(f)})
            return result
        except Exception as exc:
            logger.warning(
                "SecurityHubNormalizer unavailable (%s) — using inline normalization", exc
            )
            return self._inline_normalize_asff(findings)

    def _inline_normalize_asff(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Minimal inline ASFF normalizer used when scanner_parsers is unavailable."""
        normalized = []
        for finding in findings:
            severity_label = (
                finding.get("Severity", {}).get("Label", "INFORMATIONAL").upper()
            )
            sev = _ASFF_SEVERITY_MAP.get(severity_label, "info")

            # Extract resource info
            resources = finding.get("Resources", [])
            primary_resource = resources[0] if resources else {}
            resource_type = primary_resource.get("Type", "")
            resource_id = primary_resource.get("Id", "")

            # Remediation
            remediation = finding.get("Remediation", {}).get("Recommendation", {})
            recommendation = remediation.get("Text", "")
            remediation_url = remediation.get("Url", "")

            # Compliance status
            compliance_status = finding.get("Compliance", {}).get("Status", "")

            # Types / categories
            types = finding.get("Types", [])
            category = types[0].split("/")[1] if types and "/" in types[0] else "security"

            normalized.append({
                "id": str(uuid.uuid4()),
                "source_tool": "aws_security_hub",
                "source_id": finding.get("Id", ""),
                "severity": sev,
                "title": finding.get("Title", "AWS Security Hub Finding"),
                "description": finding.get("Description", ""),
                "recommendation": f"{recommendation} {remediation_url}".strip(),
                "aws_account_id": finding.get("AwsAccountId", ""),
                "aws_region": finding.get("Region", ""),
                "generator_id": finding.get("GeneratorId", ""),
                "product_name": finding.get("ProductName", "Security Hub"),
                "resource_type": resource_type,
                "resource_id": resource_id,
                "compliance_status": compliance_status,
                "workflow_status": finding.get("Workflow", {}).get("Status", ""),
                "record_state": finding.get("RecordState", ""),
                "category": category,
                "created_at": finding.get("CreatedAt", ""),
                "updated_at": finding.get("UpdatedAt", ""),
                "tags": types,
            })
        return normalized

    def get_import_history(self, org_id: str = "default") -> List[Dict[str, Any]]:
        """
        Return import history for the given org, most recent first.

        The findings list is stripped to keep the response lightweight.

        Args:
            org_id: Organisation identifier.

        Returns:
            List of import summary dicts (without full findings).
        """
        with _get_lock():
            entries = list(_import_history.get(org_id, []))

        summaries = []
        for e in reversed(entries):
            summary = {k: v for k, v in e.items() if k != "findings"}
            summaries.append(summary)
        return summaries

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _make_boto3_client(self):
        """
        Build a boto3 securityhub client.

        Raises ImportError if boto3 is not installed (expected in test environments).
        """
        try:
            import boto3
        except ImportError as exc:
            raise RuntimeError(
                "boto3 is not installed. Install it with: pip install boto3. "
                "Without boto3, only mock data is available."
            ) from exc

        kwargs: Dict[str, Any] = {"region_name": self._region}
        if self._access_key and self._secret_key:
            kwargs["aws_access_key_id"] = self._access_key
            kwargs["aws_secret_access_key"] = self._secret_key

        return boto3.client("securityhub", **kwargs)

    def _try_ingest_to_pipeline(
        self,
        findings: List[Dict[str, Any]],
        org_id: str,
        import_id: str,
    ) -> None:
        """Push normalized findings into BrainPipeline if available."""
        if not findings:
            return
        try:
            from core.brain_pipeline import BrainPipeline, PipelineInput
            pipeline = BrainPipeline()
            pipeline_input = PipelineInput(
                org_id=org_id,
                findings=findings,
                metadata={"source": "aws_security_hub", "import_id": import_id},
            )
            pipeline.run(pipeline_input)
            logger.info(
                "Ingested %d Security Hub findings into BrainPipeline for org=%s import=%s",
                len(findings), org_id, import_id,
            )
        except Exception as exc:
            # Non-fatal: pipeline ingestion is best-effort
            logger.warning("BrainPipeline ingestion skipped: %s", exc)
