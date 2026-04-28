"""
ALDECI AWS Integration — Real boto3 calls against LocalStack (or live AWS).

Provides four integration areas:
1. S3EvidenceStore      — Upload scan reports, SBOM files, compliance evidence
2. SecurityHubPusher    — Convert ALDECI findings to ASFF and push to Security Hub
3. IAMAuditor           — Audit IAM users, MFA enforcement, overprivileged policies
4. CloudWatchMetrics    — Push ALDECI metrics (finding counts, risk scores, scan durations)

All clients accept an optional ``endpoint_url`` that defaults to
``http://localhost:4566`` (LocalStack). For real AWS, pass ``endpoint_url=None``.

Environment variables (mirrors docker-compose.e2e.yml):
    AWS_ENDPOINT_URL        — override LocalStack endpoint (default: http://localhost:4566)
    AWS_DEFAULT_REGION      — region (default: us-east-1)
    AWS_ACCESS_KEY_ID       — credentials (default: test)
    AWS_SECRET_ACCESS_KEY   — credentials (default: test)

Usage:
    from core.aws_integration import S3EvidenceStore, SecurityHubPusher, IAMAuditor, CloudWatchMetrics

    store = S3EvidenceStore(org_id="acme")
    store.ensure_bucket()
    store.upload_scan_report("trivy", b"...", metadata={"scanner": "trivy"})

Vision Pillars: V1 (APP_ID-Centric), V3 (Decision Intelligence), V9 (Air-Gapped)
"""

from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import structlog

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_ENDPOINT = "http://localhost:4566"
_DEFAULT_REGION = "us-east-1"
_DEFAULT_AWS_KEY = "test"
_DEFAULT_AWS_SECRET = "test"

_CLOUDWATCH_NAMESPACE = "ALDECI/SecurityMetrics"

# Severity label → numeric score for ASFF
_SEVERITY_LABEL_MAP: Dict[str, Tuple[str, int]] = {
    "critical": ("CRITICAL", 90),
    "high": ("HIGH", 70),
    "medium": ("MEDIUM", 50),
    "low": ("LOW", 25),
    "info": ("INFORMATIONAL", 0),
    "informational": ("INFORMATIONAL", 0),
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _boto3_client(service: str, endpoint_url: Optional[str], region: str) -> Any:
    """Create a boto3 client pointing at LocalStack or real AWS."""
    import boto3  # type: ignore[import-untyped]

    effective_endpoint = endpoint_url if endpoint_url is not None else os.environ.get("AWS_ENDPOINT_URL")
    kwargs: Dict[str, Any] = {
        "region_name": region,
    }
    if effective_endpoint:
        kwargs["endpoint_url"] = effective_endpoint
        # LocalStack uses static credentials; real AWS will use profile/IAM role
        kwargs.setdefault("aws_access_key_id", os.environ.get("AWS_ACCESS_KEY_ID", _DEFAULT_AWS_KEY))
        kwargs.setdefault("aws_secret_access_key", os.environ.get("AWS_SECRET_ACCESS_KEY", _DEFAULT_AWS_SECRET))

    return boto3.client(service, **kwargs)


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


# ---------------------------------------------------------------------------
# 1. S3 Evidence Store
# ---------------------------------------------------------------------------


@dataclass
class S3UploadResult:
    """Result of an S3 upload operation."""

    bucket: str
    key: str
    etag: str
    version_id: Optional[str] = None
    presigned_url: Optional[str] = None


class S3EvidenceStore:
    """
    Upload and manage compliance evidence in S3.

    Bucket name: ``aldeci-evidence-{org_id}``

    Features:
    - Server-side AES256 encryption on every PUT
    - Object tagging for scanner type and org
    - Lifecycle rule: transition to GLACIER after 90 days
    - Presigned download URLs (1-hour expiry by default)
    """

    LIFECYCLE_DAYS_TO_GLACIER = 90
    PRESIGNED_URL_EXPIRY_SECONDS = 3600

    def __init__(
        self,
        org_id: str,
        *,
        endpoint_url: Optional[str] = _DEFAULT_ENDPOINT,
        region: str = _DEFAULT_REGION,
    ) -> None:
        self.org_id = org_id
        self.bucket = f"aldeci-evidence-{org_id}"
        self._client = _boto3_client("s3", endpoint_url, region)
        self._region = region
        self._endpoint_url = endpoint_url

    # ------------------------------------------------------------------
    # Bucket lifecycle
    # ------------------------------------------------------------------

    def ensure_bucket(self) -> bool:
        """
        Create the evidence bucket if it does not exist.

        Returns True if the bucket was created, False if it already existed.
        """
        try:
            self._client.head_bucket(Bucket=self.bucket)
            logger.info("s3_evidence_store.bucket_exists", bucket=self.bucket)
            return False
        except Exception:
            pass

        # Bucket does not exist — create it
        if self._region == "us-east-1":
            self._client.create_bucket(Bucket=self.bucket)
        else:
            self._client.create_bucket(
                Bucket=self.bucket,
                CreateBucketConfiguration={"LocationConstraint": self._region},
            )

        # Enable versioning
        self._client.put_bucket_versioning(
            Bucket=self.bucket,
            VersioningConfiguration={"Status": "Enabled"},
        )

        # Server-side encryption default
        self._client.put_bucket_encryption(
            Bucket=self.bucket,
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "AES256",
                        },
                        "BucketKeyEnabled": False,
                    }
                ]
            },
        )

        # Lifecycle: move to GLACIER after 90 days
        self._apply_lifecycle_policy()

        logger.info("s3_evidence_store.bucket_created", bucket=self.bucket)
        return True

    def _apply_lifecycle_policy(self) -> None:
        self._client.put_bucket_lifecycle_configuration(
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "aldeci-glacier-transition",
                        "Status": "Enabled",
                        "Filter": {"Prefix": ""},
                        "Transitions": [
                            {
                                "Days": self.LIFECYCLE_DAYS_TO_GLACIER,
                                "StorageClass": "GLACIER",
                            }
                        ],
                        "NoncurrentVersionTransitions": [
                            {
                                "NoncurrentDays": self.LIFECYCLE_DAYS_TO_GLACIER,
                                "StorageClass": "GLACIER",
                            }
                        ],
                    }
                ]
            },
        )

    # ------------------------------------------------------------------
    # Upload helpers
    # ------------------------------------------------------------------

    def _upload(
        self,
        key: str,
        body: bytes,
        content_type: str,
        metadata: Optional[Dict[str, str]] = None,
        tags: Optional[Dict[str, str]] = None,
    ) -> S3UploadResult:
        put_kwargs: Dict[str, Any] = {
            "Bucket": self.bucket,
            "Key": key,
            "Body": body,
            "ContentType": content_type,
            "ServerSideEncryption": "AES256",
        }
        if metadata:
            put_kwargs["Metadata"] = {k: str(v) for k, v in metadata.items()}
        if tags:
            tag_str = "&".join(f"{k}={v}" for k, v in tags.items())
            put_kwargs["Tagging"] = tag_str

        response = self._client.put_object(**put_kwargs)
        etag = response.get("ETag", "").strip('"')
        version_id = response.get("VersionId")
        logger.info("s3_evidence_store.uploaded", bucket=self.bucket, key=key, etag=etag)  # nosemgrep: python-logger-credential-disclosure
        return S3UploadResult(bucket=self.bucket, key=key, etag=etag, version_id=version_id)

    def upload_scan_report(
        self,
        scanner: str,
        content: bytes,
        *,
        metadata: Optional[Dict[str, str]] = None,
        filename: Optional[str] = None,
    ) -> S3UploadResult:
        """
        Upload a scanner report (JSON, XML, etc.) to S3.

        Key pattern: ``reports/{scanner}/{YYYY-MM-DD}/{uuid}.json``
        """
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        report_id = str(uuid.uuid4())
        fname = filename or f"{report_id}.json"
        key = f"reports/{scanner}/{date_str}/{fname}"
        meta = {"scanner": scanner, "org_id": self.org_id, "upload_timestamp": _utcnow_iso()}
        if metadata:
            meta.update(metadata)
        tags = {"scanner": scanner, "org": self.org_id, "type": "scan-report"}
        return self._upload(key, content, "application/json", meta, tags)

    def upload_sbom(
        self,
        app_id: str,
        sbom_content: bytes,
        *,
        format: str = "cyclonedx",
        metadata: Optional[Dict[str, str]] = None,
    ) -> S3UploadResult:
        """
        Upload an SBOM file (CycloneDX or SPDX).

        Key pattern: ``sboms/{app_id}/{YYYY-MM-DD}/{uuid}.json``
        """
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        key = f"sboms/{app_id}/{date_str}/{uuid.uuid4()}.json"
        meta = {
            "app_id": app_id,
            "org_id": self.org_id,
            "sbom_format": format,
            "upload_timestamp": _utcnow_iso(),
        }
        if metadata:
            meta.update(metadata)
        tags = {"app_id": app_id, "org": self.org_id, "type": "sbom", "format": format}
        return self._upload(key, sbom_content, "application/json", meta, tags)

    def upload_compliance_evidence(
        self,
        framework: str,
        control_id: str,
        content: bytes,
        *,
        content_type: str = "application/pdf",
        metadata: Optional[Dict[str, str]] = None,
    ) -> S3UploadResult:
        """
        Upload compliance evidence document (PDF, JSON, etc.).

        Key pattern: ``compliance/{framework}/{control_id}/{YYYY-MM-DD}/{uuid}``
        """
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        ext = "pdf" if "pdf" in content_type else "json"
        key = f"compliance/{framework}/{control_id}/{date_str}/{uuid.uuid4()}.{ext}"
        meta = {
            "framework": framework,
            "control_id": control_id,
            "org_id": self.org_id,
            "upload_timestamp": _utcnow_iso(),
        }
        if metadata:
            meta.update(metadata)
        tags = {"framework": framework, "control": control_id, "org": self.org_id, "type": "compliance"}
        return self._upload(key, content, content_type, meta, tags)

    # ------------------------------------------------------------------
    # List / query
    # ------------------------------------------------------------------

    def list_objects(
        self,
        prefix: str = "",
        max_keys: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        List objects in the evidence bucket with optional prefix filter.

        Returns a list of dicts with ``key``, ``size``, ``last_modified``,
        ``etag``, and ``storage_class``.
        """
        response = self._client.list_objects_v2(
            Bucket=self.bucket,
            Prefix=prefix,
            MaxKeys=max_keys,
        )
        objects = []
        for obj in response.get("Contents", []):
            objects.append(
                {
                    "key": obj["Key"],
                    "size": obj["Size"],
                    "last_modified": obj["LastModified"].isoformat() if hasattr(obj["LastModified"], "isoformat") else str(obj["LastModified"]),
                    "etag": obj.get("ETag", "").strip('"'),
                    "storage_class": obj.get("StorageClass", "STANDARD"),
                }
            )
        return objects

    def generate_presigned_url(
        self,
        key: str,
        expiry_seconds: int = PRESIGNED_URL_EXPIRY_SECONDS,
    ) -> str:
        """
        Generate a presigned GET URL for downloading an object.

        URL is valid for ``expiry_seconds`` seconds (default 1 hour).
        """
        url = self._client.generate_presigned_url(
            "get_object",
            Params={"Bucket": self.bucket, "Key": key},
            ExpiresIn=expiry_seconds,
        )
        return url

    def delete_object(self, key: str) -> None:
        """Delete an object by key (used in test cleanup)."""
        self._client.delete_object(Bucket=self.bucket, Key=key)
        logger.info("s3_evidence_store.deleted", bucket=self.bucket, key=key)  # nosemgrep: python-logger-credential-disclosure

    def delete_bucket(self) -> None:
        """
        Empty and delete the evidence bucket.

        Used for test teardown — removes all versions then deletes the bucket.
        """
        try:
            paginator = self._client.get_paginator("list_object_versions")
            for page in paginator.paginate(Bucket=self.bucket):
                for version in page.get("Versions", []):
                    self._client.delete_object(
                        Bucket=self.bucket,
                        Key=version["Key"],
                        VersionId=version["VersionId"],
                    )
                for marker in page.get("DeleteMarkers", []):
                    self._client.delete_object(
                        Bucket=self.bucket,
                        Key=marker["Key"],
                        VersionId=marker["VersionId"],
                    )
        except Exception:
            # Bucket may not have versioning or may already be empty
            pass
        try:
            # Delete any remaining unversioned objects
            paginator = self._client.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=self.bucket):
                for obj in page.get("Contents", []):
                    self._client.delete_object(Bucket=self.bucket, Key=obj["Key"])
        except Exception:
            pass
        self._client.delete_bucket(Bucket=self.bucket)
        logger.info("s3_evidence_store.bucket_deleted", bucket=self.bucket)


# ---------------------------------------------------------------------------
# 2. Security Hub Pusher
# ---------------------------------------------------------------------------


@dataclass
class ALDECIFinding:
    """
    Normalised ALDECI finding to push to AWS Security Hub.

    All fields map to the ASFF (AWS Security Finding Format) schema.
    """

    finding_id: str
    title: str
    description: str
    severity: str  # "critical" | "high" | "medium" | "low" | "info"
    resource_id: str
    resource_type: str = "AwsEc2Instance"
    generator_id: str = "aldeci-security-scanner"
    types: List[str] = field(default_factory=lambda: ["Software and Configuration Checks/Vulnerabilities/CVE"])
    remediation_text: str = ""
    remediation_url: str = ""
    compliance_status: str = "FAILED"
    workflow_status: str = "NEW"
    account_id: str = "000000000000"
    region: str = "us-east-1"
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    def __post_init__(self) -> None:
        now = _utcnow_iso()
        if self.created_at is None:
            self.created_at = now
        if self.updated_at is None:
            self.updated_at = now


@dataclass
class SecurityHubImportResult:
    """Result of a BatchImportFindings call."""

    success_count: int
    failed_count: int
    failed_ids: List[str] = field(default_factory=list)
    raw_response: Optional[Dict[str, Any]] = None


class SecurityHubPusher:
    """
    Push ALDECI findings to AWS Security Hub in ASFF format.

    Converts ALDECI's internal finding schema to ASFF and calls
    BatchImportFindings. Also supports querying existing findings and
    updating workflow status when resolved.
    """

    BATCH_SIZE = 100  # Security Hub maximum per BatchImportFindings call

    def __init__(
        self,
        *,
        account_id: str = "000000000000",
        region: str = _DEFAULT_REGION,
        endpoint_url: Optional[str] = _DEFAULT_ENDPOINT,
        product_arn_suffix: Optional[str] = None,
    ) -> None:
        self._client = _boto3_client("securityhub", endpoint_url, region)
        self._region = region
        self._account_id = account_id
        self._product_arn = (
            product_arn_suffix
            or f"arn:aws:securityhub:{region}:{account_id}:product/{account_id}/default"
        )

    # ------------------------------------------------------------------
    # Hub lifecycle
    # ------------------------------------------------------------------

    def enable_security_hub(self) -> bool:
        """
        Enable Security Hub for the account.

        Returns True if newly enabled, False if already active.
        """
        try:
            self._client.enable_security_hub(EnableDefaultStandards=False)
            logger.info("securityhub.enabled", account=self._account_id)
            return True
        except Exception as exc:
            if "already" in str(exc).lower() or "subscribed" in str(exc).lower():
                return False
            raise

    # ------------------------------------------------------------------
    # ASFF conversion
    # ------------------------------------------------------------------

    def _to_asff(self, finding: ALDECIFinding) -> Dict[str, Any]:
        """Convert an ALDECIFinding to ASFF dict."""
        sev_label, sev_norm = _SEVERITY_LABEL_MAP.get(
            finding.severity.lower(), ("MEDIUM", 50)
        )
        asff: Dict[str, Any] = {
            "SchemaVersion": "2018-10-08",
            "Id": finding.finding_id,
            "ProductArn": self._product_arn,
            "GeneratorId": finding.generator_id,
            "AwsAccountId": finding.account_id,
            "Types": finding.types,
            "CreatedAt": finding.created_at,
            "UpdatedAt": finding.updated_at,
            "Severity": {
                "Label": sev_label,
                "Normalized": sev_norm,
            },
            "Title": finding.title,
            "Description": finding.description,
            "Resources": [
                {
                    "Type": finding.resource_type,
                    "Id": finding.resource_id,
                    "Partition": "aws",
                    "Region": finding.region,
                }
            ],
            "Compliance": {"Status": finding.compliance_status},
            "WorkflowState": finding.workflow_status,
            "Workflow": {"Status": finding.workflow_status},
            "RecordState": "ACTIVE",
        }
        if finding.remediation_text or finding.remediation_url:
            asff["Remediation"] = {
                "Recommendation": {
                    "Text": finding.remediation_text,
                    "Url": finding.remediation_url,
                }
            }
        return asff

    # ------------------------------------------------------------------
    # Import / query / update
    # ------------------------------------------------------------------

    def push_findings(self, findings: List[ALDECIFinding]) -> SecurityHubImportResult:
        """
        Push a list of ALDECI findings to Security Hub.

        Automatically batches into chunks of 100 (API limit).
        Returns aggregated success/failure counts.
        """
        if not findings:
            return SecurityHubImportResult(success_count=0, failed_count=0)

        asff_findings = [self._to_asff(f) for f in findings]
        total_success = 0
        total_failed = 0
        all_failed_ids: List[str] = []

        for i in range(0, len(asff_findings), self.BATCH_SIZE):
            batch = asff_findings[i : i + self.BATCH_SIZE]
            response = self._client.batch_import_findings(Findings=batch)
            total_success += response.get("SuccessCount", 0)
            total_failed += response.get("FailedCount", 0)
            for failed in response.get("FailedFindings", []):
                all_failed_ids.append(failed.get("Id", "unknown"))

        logger.info(
            "securityhub.findings_pushed",
            success=total_success,
            failed=total_failed,
        )
        return SecurityHubImportResult(
            success_count=total_success,
            failed_count=total_failed,
            failed_ids=all_failed_ids,
        )

    def get_findings(
        self,
        filters: Optional[Dict[str, Any]] = None,
        max_results: int = 20,
    ) -> List[Dict[str, Any]]:
        """
        Query Security Hub findings with optional ASFF filters.

        Returns raw ASFF finding dicts.
        """
        kwargs: Dict[str, Any] = {"MaxResults": max_results}
        if filters:
            kwargs["Filters"] = filters
        response = self._client.get_findings(**kwargs)
        return response.get("Findings", [])

    def update_finding_workflow(
        self,
        finding_id: str,
        new_status: str = "RESOLVED",
        note: str = "Resolved by ALDECI",
    ) -> bool:
        """
        Update the workflow status of a finding (e.g., mark as RESOLVED).

        ``new_status`` should be one of: NEW, NOTIFIED, RESOLVED, SUPPRESSED.
        Returns True on success.
        """
        self._client.batch_update_findings(
            FindingIdentifiers=[
                {"Id": finding_id, "ProductArn": self._product_arn}
            ],
            Workflow={"Status": new_status},
            Note={"Text": note, "UpdatedBy": "aldeci-automation"},
        )
        logger.info("securityhub.finding_updated", id=finding_id, status=new_status)
        return True


# ---------------------------------------------------------------------------
# 3. IAM Auditor
# ---------------------------------------------------------------------------


@dataclass
class IAMUserAuditResult:
    """Audit result for a single IAM user."""

    username: str
    user_id: str
    arn: str
    has_access_keys: bool
    access_key_count: int
    mfa_enabled: bool
    is_root: bool
    password_last_used: Optional[str]
    access_key_ages: List[int] = field(default_factory=list)  # days since creation
    attached_policy_arns: List[str] = field(default_factory=list)
    inline_policy_names: List[str] = field(default_factory=list)
    risk_flags: List[str] = field(default_factory=list)


@dataclass
class IAMAuditSummary:
    """Aggregate summary of IAM audit findings."""

    total_users: int
    users_without_mfa: int
    users_with_old_keys: int  # keys > 90 days
    users_with_multiple_keys: int
    root_activity_detected: bool
    overprivileged_users: List[str] = field(default_factory=list)
    audit_timestamp: str = field(default_factory=_utcnow_iso)
    user_details: List[IAMUserAuditResult] = field(default_factory=list)


class IAMAuditor:
    """
    Audit IAM configuration for security issues.

    Checks:
    - Users with active access keys (and key age)
    - MFA enforcement per user
    - Root account usage detection (via credential report)
    - Overprivileged policies (admin policy attachments)
    """

    OLD_KEY_DAYS = 90
    ADMIN_POLICY_ARNS = {
        "arn:aws:iam::aws:policy/AdministratorAccess",
        "arn:aws:iam::aws:policy/IAMFullAccess",
    }

    def __init__(
        self,
        *,
        endpoint_url: Optional[str] = _DEFAULT_ENDPOINT,
        region: str = _DEFAULT_REGION,
    ) -> None:
        self._client = _boto3_client("iam", endpoint_url, region)

    def list_users_with_access_keys(self) -> List[Dict[str, Any]]:
        """
        List all IAM users with their access key metadata.

        Returns a list of dicts with ``username``, ``user_id``, ``arn``,
        and ``access_keys`` (list of key metadata dicts).
        """
        paginator = self._client.get_paginator("list_users")
        results = []
        for page in paginator.paginate():
            for user in page.get("Users", []):
                username = user["UserName"]
                keys_response = self._client.list_access_keys(UserName=username)
                access_keys = keys_response.get("AccessKeyMetadata", [])
                results.append(
                    {
                        "username": username,
                        "user_id": user["UserId"],
                        "arn": user["Arn"],
                        "access_keys": [
                            {
                                "access_key_id": k["AccessKeyId"],
                                "status": k["Status"],
                                "create_date": k["CreateDate"].isoformat() if hasattr(k["CreateDate"], "isoformat") else str(k["CreateDate"]),
                            }
                            for k in access_keys
                        ],
                    }
                )
        return results

    def check_mfa_enforcement(self) -> Dict[str, bool]:
        """
        Check which IAM users have MFA devices enrolled.

        Returns ``{username: mfa_enabled}`` mapping.
        """
        paginator = self._client.get_paginator("list_users")
        mfa_status: Dict[str, bool] = {}
        for page in paginator.paginate():
            for user in page.get("Users", []):
                username = user["UserName"]
                devices = self._client.list_mfa_devices(UserName=username)
                mfa_status[username] = len(devices.get("MFADevices", [])) > 0
        return mfa_status

    def check_root_account_usage(self) -> Dict[str, Any]:
        """
        Check for root account activity via the credential report.

        Returns a dict with ``root_has_access_keys``, ``root_mfa_active``,
        ``root_last_used``, and ``risk_level``.
        """
        try:
            self._client.generate_credential_report()
        except Exception:
            pass  # Report may already be fresh


        for _ in range(5):
            try:
                resp = self._client.get_credential_report()
                break
            except Exception:
                time.sleep(1)
        else:
            return {"root_has_access_keys": False, "root_mfa_active": False, "root_last_used": None, "risk_level": "unknown"}

        content = resp.get("Content", b"")
        if isinstance(content, bytes):
            text = content.decode("utf-8")
        else:
            text = str(content)

        root_info: Dict[str, Any] = {
            "root_has_access_keys": False,
            "root_mfa_active": False,
            "root_last_used": None,
            "risk_level": "low",
        }

        lines = text.strip().split("\n")
        if len(lines) < 2:
            return root_info

        headers = lines[0].split(",")
        for line in lines[1:]:
            values = line.split(",")
            row = dict(zip(headers, values))
            if row.get("user") == "<root_account>":
                root_info["root_has_access_keys"] = row.get("access_key_1_active", "false").lower() == "true"
                root_info["root_mfa_active"] = row.get("mfa_active", "false").lower() == "true"
                root_info["root_last_used"] = row.get("password_last_used", "N/A")
                if root_info["root_has_access_keys"]:
                    root_info["risk_level"] = "critical"
                elif not root_info["root_mfa_active"]:
                    root_info["risk_level"] = "high"
                break

        return root_info

    def detect_overprivileged_policies(self) -> List[Dict[str, Any]]:
        """
        Detect IAM users with overprivileged managed policies attached.

        Returns a list of ``{username, policy_arn}`` dicts for admin-level policies.
        """
        paginator = self._client.get_paginator("list_users")
        overprivileged: List[Dict[str, Any]] = []
        for page in paginator.paginate():
            for user in page.get("Users", []):
                username = user["UserName"]
                attached = self._client.list_attached_user_policies(UserName=username)
                for policy in attached.get("AttachedPolicies", []):
                    arn = policy.get("PolicyArn", "")
                    if arn in self.ADMIN_POLICY_ARNS:
                        overprivileged.append({"username": username, "policy_arn": arn})
                        logger.warning(
                            "iam_audit.overprivileged",
                            username=username,
                            policy_arn=arn,
                        )
        return overprivileged

    def full_audit(self) -> IAMAuditSummary:
        """
        Run a comprehensive IAM audit.

        Combines user listing, MFA check, key age analysis, and
        overprivileged policy detection into a single IAMAuditSummary.
        """
        users_with_keys = self.list_users_with_access_keys()
        mfa_status = self.check_mfa_enforcement()
        overprivileged = self.detect_overprivileged_policies()
        overprivileged_usernames = {entry["username"] for entry in overprivileged}

        now = datetime.now(timezone.utc)
        user_details: List[IAMUserAuditResult] = []
        users_without_mfa = 0
        users_with_old_keys = 0
        users_with_multiple_keys = 0

        for user in users_with_keys:
            username = user["username"]
            keys = user["access_keys"]
            mfa_enabled = mfa_status.get(username, False)
            if not mfa_enabled:
                users_without_mfa += 1

            key_ages: List[int] = []
            for k in keys:
                try:
                    create_str = k["create_date"]
                    create_dt = datetime.fromisoformat(create_str.replace("Z", "+00:00"))
                    age_days = (now - create_dt).days
                    key_ages.append(age_days)
                except Exception:
                    key_ages.append(0)

            has_old_keys = any(a >= self.OLD_KEY_DAYS for a in key_ages)
            if has_old_keys:
                users_with_old_keys += 1
            if len(keys) > 1:
                users_with_multiple_keys += 1

            risk_flags: List[str] = []
            if not mfa_enabled:
                risk_flags.append("no_mfa")
            if has_old_keys:
                risk_flags.append("old_access_keys")
            if len(keys) > 1:
                risk_flags.append("multiple_access_keys")
            if username in overprivileged_usernames:
                risk_flags.append("overprivileged")

            user_details.append(
                IAMUserAuditResult(
                    username=username,
                    user_id=user["user_id"],
                    arn=user["arn"],
                    has_access_keys=len(keys) > 0,
                    access_key_count=len(keys),
                    mfa_enabled=mfa_enabled,
                    is_root=False,
                    password_last_used=None,
                    access_key_ages=key_ages,
                    risk_flags=risk_flags,
                )
            )

        root_info = self.check_root_account_usage()

        return IAMAuditSummary(
            total_users=len(users_with_keys),
            users_without_mfa=users_without_mfa,
            users_with_old_keys=users_with_old_keys,
            users_with_multiple_keys=users_with_multiple_keys,
            root_activity_detected=root_info.get("root_has_access_keys", False),
            overprivileged_users=list(overprivileged_usernames),
            user_details=user_details,
        )


# ---------------------------------------------------------------------------
# 4. CloudWatch Metrics Pusher
# ---------------------------------------------------------------------------


@dataclass
class MetricDatum:
    """Single CloudWatch metric datum."""

    name: str
    value: float
    unit: str = "Count"  # Count | Seconds | Percent | Bytes | None
    dimensions: Dict[str, str] = field(default_factory=dict)
    timestamp: Optional[datetime] = None


class CloudWatchMetrics:
    """
    Push ALDECI operational metrics to AWS CloudWatch.

    Namespace: ``ALDECI/SecurityMetrics``

    Metrics pushed:
    - FindingCount (by severity dimension)
    - ScanDurationSeconds
    - RiskScore
    - CouncilConsensusRate
    """

    NAMESPACE = _CLOUDWATCH_NAMESPACE
    MAX_METRICS_PER_CALL = 20  # CloudWatch API limit

    def __init__(
        self,
        *,
        endpoint_url: Optional[str] = _DEFAULT_ENDPOINT,
        region: str = _DEFAULT_REGION,
        org_id: str = "default",
    ) -> None:
        self._client = _boto3_client("cloudwatch", endpoint_url, region)
        self._org_id = org_id

    def _build_metric_data(self, metrics: List[MetricDatum]) -> List[Dict[str, Any]]:
        data = []
        for m in metrics:
            datum: Dict[str, Any] = {
                "MetricName": m.name,
                "Value": m.value,
                "Unit": m.unit,
                "Dimensions": [
                    {"Name": k, "Value": v} for k, v in m.dimensions.items()
                ],
            }
            if m.timestamp:
                datum["Timestamp"] = m.timestamp
            data.append(datum)
        return data

    def put_metrics(self, metrics: List[MetricDatum]) -> int:
        """
        Push a list of MetricDatum to CloudWatch.

        Automatically batches into chunks of 20 (API limit).
        Returns total number of metrics pushed.
        """
        total = 0
        for i in range(0, len(metrics), self.MAX_METRICS_PER_CALL):
            batch = metrics[i : i + self.MAX_METRICS_PER_CALL]
            metric_data = self._build_metric_data(batch)
            self._client.put_metric_data(
                Namespace=self.NAMESPACE,
                MetricData=metric_data,
            )
            total += len(batch)
        logger.info("cloudwatch.metrics_pushed", count=total, namespace=self.NAMESPACE)
        return total

    def push_finding_counts(self, counts_by_severity: Dict[str, int]) -> int:
        """
        Push finding count metrics broken down by severity.

        ``counts_by_severity``: e.g. ``{"critical": 3, "high": 12, "medium": 45}``
        """
        metrics = [
            MetricDatum(
                name="FindingCount",
                value=float(count),
                unit="Count",
                dimensions={"Severity": severity.upper(), "OrgId": self._org_id},
            )
            for severity, count in counts_by_severity.items()
        ]
        return self.put_metrics(metrics)

    def push_scan_duration(self, scanner: str, duration_seconds: float) -> int:
        """Push scan duration metric for a specific scanner."""
        return self.put_metrics(
            [
                MetricDatum(
                    name="ScanDurationSeconds",
                    value=duration_seconds,
                    unit="Seconds",
                    dimensions={"Scanner": scanner, "OrgId": self._org_id},
                )
            ]
        )

    def push_risk_score(self, app_id: str, risk_score: float) -> int:
        """Push risk score (0-100) for a specific application."""
        return self.put_metrics(
            [
                MetricDatum(
                    name="RiskScore",
                    value=risk_score,
                    unit="None",
                    dimensions={"AppId": app_id, "OrgId": self._org_id},
                )
            ]
        )

    def push_council_consensus_rate(self, rate: float) -> int:
        """Push LLM Council consensus rate (0.0 – 1.0 as percentage)."""
        return self.put_metrics(
            [
                MetricDatum(
                    name="CouncilConsensusRate",
                    value=rate * 100.0,
                    unit="Percent",
                    dimensions={"OrgId": self._org_id},
                )
            ]
        )

    def get_metric_statistics(
        self,
        metric_name: str,
        start_time: datetime,
        end_time: datetime,
        period_seconds: int = 3600,
        stat: str = "Sum",
        dimensions: Optional[Dict[str, str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve CloudWatch metric statistics for a given time range.

        Returns list of datapoints with ``Timestamp``, ``Sum``/``Average``/etc.,
        and ``Unit``.
        """
        kwargs: Dict[str, Any] = {
            "Namespace": self.NAMESPACE,
            "MetricName": metric_name,
            "StartTime": start_time,
            "EndTime": end_time,
            "Period": period_seconds,
            "Statistics": [stat],
        }
        if dimensions:
            kwargs["Dimensions"] = [{"Name": k, "Value": v} for k, v in dimensions.items()]
        response = self._client.get_metric_statistics(**kwargs)
        return response.get("Datapoints", [])
