"""FixOps Cloud Runtime Security Analyzer

Proprietary cloud runtime analysis for AWS, Azure, GCP.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class CloudThreatType(Enum):
    """Cloud threat types."""

    PUBLIC_ACCESS = "public_access"
    INSECURE_STORAGE = "insecure_storage"
    WEAK_ENCRYPTION = "weak_encryption"
    MISSING_IAM_POLICY = "missing_iam_policy"
    OVERLY_PERMISSIVE_IAM = "overly_permissive_iam"
    UNENCRYPTED_DATABASE = "unencrypted_database"
    PUBLIC_DATABASE = "public_database"
    MISSING_LOGGING = "missing_logging"
    INSECURE_NETWORK = "insecure_network"


@dataclass
class CloudFinding:
    """Cloud security finding."""

    threat_type: CloudThreatType
    severity: str  # critical, high, medium, low
    cloud_provider: str  # aws, azure, gcp
    resource_type: str  # s3, ec2, rds, etc.
    resource_id: str
    region: Optional[str] = None
    description: str = ""
    recommendation: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class CloudSecurityResult:
    """Cloud security analysis result."""

    findings: List[CloudFinding]
    total_findings: int
    findings_by_type: Dict[str, int]
    findings_by_severity: Dict[str, int]
    resources_analyzed: int
    cloud_provider: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class CloudRuntimeAnalyzer:
    """FixOps Cloud Runtime Analyzer - Proprietary cloud security."""

    def __init__(self, cloud_provider: str, config: Optional[Dict[str, Any]] = None):
        """Initialize cloud runtime analyzer."""
        self.cloud_provider = cloud_provider.lower()
        self.config = config or {}

    def analyze_aws_resources(self) -> CloudSecurityResult:
        """Analyze AWS resources for security issues."""
        findings = []

        # Analyze S3 buckets
        s3_findings = self._analyze_aws_s3()
        findings.extend(s3_findings)

        # Analyze RDS instances
        rds_findings = self._analyze_aws_rds()
        findings.extend(rds_findings)

        # Analyze EC2 instances
        ec2_findings = self._analyze_aws_ec2()
        findings.extend(ec2_findings)

        # Analyze IAM policies
        iam_findings = self._analyze_aws_iam()
        findings.extend(iam_findings)

        return self._build_result(findings, "aws")

    def analyze_azure_resources(self) -> CloudSecurityResult:
        """Analyze Azure resources for security issues."""
        findings = []

        # Analyze Storage Accounts
        storage_findings = self._analyze_azure_storage()
        findings.extend(storage_findings)

        # Analyze SQL Databases
        sql_findings = self._analyze_azure_sql()
        findings.extend(sql_findings)

        # Analyze Virtual Machines
        vm_findings = self._analyze_azure_vm()
        findings.extend(vm_findings)

        return self._build_result(findings, "azure")

    def analyze_gcp_resources(self) -> CloudSecurityResult:
        """Analyze GCP resources for security issues."""
        findings = []

        # Analyze Cloud Storage
        storage_findings = self._analyze_gcp_storage()
        findings.extend(storage_findings)

        # Analyze Cloud SQL
        sql_findings = self._analyze_gcp_sql()
        findings.extend(sql_findings)

        # Analyze Compute Engine
        compute_findings = self._analyze_gcp_compute()
        findings.extend(compute_findings)

        return self._build_result(findings, "gcp")

    def _check_sdk(self, sdk_name: str) -> bool:
        """Check if a cloud SDK is importable."""
        import importlib

        try:
            importlib.import_module(sdk_name)
            return True
        except ImportError:
            return False

    def _analyze_aws_s3(self) -> List[CloudFinding]:
        """Analyze AWS S3 buckets for public access, encryption, versioning."""
        if not self._check_sdk("boto3"):
            logger.warning("boto3 not installed — skipping AWS S3 analysis")
            return []
        import boto3  # type: ignore[import-untyped]

        findings: List[CloudFinding] = []
        region = self.config.get("aws_region", "us-east-1")
        try:
            s3 = boto3.client("s3", region_name=region)
            buckets = s3.list_buckets().get("Buckets", [])
            for bucket in buckets:
                name = bucket["Name"]
                # Check public access block
                try:
                    pa = s3.get_public_access_block(Bucket=name)[
                        "PublicAccessBlockConfiguration"
                    ]
                    if not all(
                        [
                            pa.get("BlockPublicAcls"),
                            pa.get("BlockPublicPolicy"),
                            pa.get("IgnorePublicAcls"),
                            pa.get("RestrictPublicBuckets"),
                        ]
                    ):
                        findings.append(
                            CloudFinding(
                                threat_type=CloudThreatType.PUBLIC_ACCESS,
                                severity="high",
                                cloud_provider="aws",
                                resource_type="s3",
                                resource_id=name,
                                region=region,
                                description=f"S3 bucket '{name}' has incomplete public access block",
                                recommendation="Enable all four PublicAccessBlock settings",
                            )
                        )
                except (ValueError, KeyError, RuntimeError, TypeError, AttributeError):
                    findings.append(
                        CloudFinding(
                            threat_type=CloudThreatType.PUBLIC_ACCESS,
                            severity="high",
                            cloud_provider="aws",
                            resource_type="s3",
                            resource_id=name,
                            region=region,
                            description=f"S3 bucket '{name}' has no public access block configured",
                            recommendation="Configure PublicAccessBlock on bucket",
                        )
                    )
                # Check encryption
                try:
                    s3.get_bucket_encryption(Bucket=name)
                except s3.exceptions.ClientError:
                    findings.append(
                        CloudFinding(
                            threat_type=CloudThreatType.WEAK_ENCRYPTION,
                            severity="medium",
                            cloud_provider="aws",
                            resource_type="s3",
                            resource_id=name,
                            region=region,
                            description=f"S3 bucket '{name}' has no default encryption",
                            recommendation="Enable SSE-S3 or SSE-KMS default encryption",
                        )
                    )
                # Check versioning
                try:
                    vs = s3.get_bucket_versioning(Bucket=name)
                    if vs.get("Status") != "Enabled":
                        findings.append(
                            CloudFinding(
                                threat_type=CloudThreatType.INSECURE_STORAGE,
                                severity="low",
                                cloud_provider="aws",
                                resource_type="s3",
                                resource_id=name,
                                region=region,
                                description=f"S3 bucket '{name}' does not have versioning enabled",
                                recommendation="Enable versioning for data protection",
                            )
                        )
                except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
                    pass
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            logger.error("AWS S3 analysis failed: %s", exc)
        return findings

    def _analyze_aws_rds(self) -> List[CloudFinding]:
        """Analyze AWS RDS instances for public access, encryption, backups."""
        if not self._check_sdk("boto3"):
            logger.warning("boto3 not installed — skipping AWS RDS analysis")
            return []
        import boto3  # type: ignore[import-untyped]

        findings: List[CloudFinding] = []
        region = self.config.get("aws_region", "us-east-1")
        try:
            rds = boto3.client("rds", region_name=region)
            instances = rds.describe_db_instances().get("DBInstances", [])
            for db in instances:
                db_id = db["DBInstanceIdentifier"]
                # Public access check
                if db.get("PubliclyAccessible"):
                    findings.append(
                        CloudFinding(
                            threat_type=CloudThreatType.PUBLIC_DATABASE,
                            severity="critical",
                            cloud_provider="aws",
                            resource_type="rds",
                            resource_id=db_id,
                            region=region,
                            description=f"RDS instance '{db_id}' is publicly accessible",
                            recommendation="Disable public accessibility and use VPC security groups",
                        )
                    )
                # Encryption check
                if not db.get("StorageEncrypted"):
                    findings.append(
                        CloudFinding(
                            threat_type=CloudThreatType.UNENCRYPTED_DATABASE,
                            severity="high",
                            cloud_provider="aws",
                            resource_type="rds",
                            resource_id=db_id,
                            region=region,
                            description=f"RDS instance '{db_id}' storage is not encrypted",
                            recommendation="Enable storage encryption with KMS",
                        )
                    )
                # Backup check
                if db.get("BackupRetentionPeriod", 0) < 7:
                    findings.append(
                        CloudFinding(
                            threat_type=CloudThreatType.INSECURE_STORAGE,
                            severity="medium",
                            cloud_provider="aws",
                            resource_type="rds",
                            resource_id=db_id,
                            region=region,
                            description=f"RDS instance '{db_id}' backup retention < 7 days",
                            recommendation="Set backup retention period to at least 7 days",
                        )
                    )
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            logger.error("AWS RDS analysis failed: %s", exc)
        return findings

    def _analyze_aws_ec2(self) -> List[CloudFinding]:
        """Analyze AWS EC2 instances for security groups, IAM roles, EBS encryption."""
        if not self._check_sdk("boto3"):
            logger.warning("boto3 not installed — skipping AWS EC2 analysis")
            return []
        import boto3  # type: ignore[import-untyped]

        findings: List[CloudFinding] = []
        region = self.config.get("aws_region", "us-east-1")
        try:
            ec2 = boto3.client("ec2", region_name=region)
            reservations = ec2.describe_instances().get("Reservations", [])
            for res in reservations:
                for inst in res.get("Instances", []):
                    iid = inst["InstanceId"]
                    # Check for overly permissive security groups (0.0.0.0/0 on sensitive ports)
                    for sg in inst.get("SecurityGroups", []):
                        try:
                            sg_detail = ec2.describe_security_groups(
                                GroupIds=[sg["GroupId"]]
                            )
                            for rule in sg_detail["SecurityGroups"][0].get(
                                "IpPermissions", []
                            ):
                                for ip_range in rule.get("IpRanges", []):
                                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                                        port = rule.get("FromPort", 0)
                                        if port in (
                                            22,
                                            3389,
                                            3306,
                                            5432,
                                            1433,
                                            6379,
                                            27017,
                                        ):
                                            findings.append(
                                                CloudFinding(
                                                    threat_type=CloudThreatType.INSECURE_NETWORK,
                                                    severity="critical",
                                                    cloud_provider="aws",
                                                    resource_type="ec2",
                                                    resource_id=iid,
                                                    region=region,
                                                    description=f"EC2 '{iid}' SG allows 0.0.0.0/0 on port {port}",
                                                    recommendation=f"Restrict port {port} to specific CIDR ranges",
                                                )
                                            )
                        except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
                            pass
                    # Check IAM role
                    if not inst.get("IamInstanceProfile"):
                        findings.append(
                            CloudFinding(
                                threat_type=CloudThreatType.MISSING_IAM_POLICY,
                                severity="medium",
                                cloud_provider="aws",
                                resource_type="ec2",
                                resource_id=iid,
                                region=region,
                                description=f"EC2 '{iid}' has no IAM instance profile",
                                recommendation="Attach an IAM role with least-privilege permissions",
                            )
                        )
                    # Check EBS encryption
                    for bd in inst.get("BlockDeviceMappings", []):
                        ebs = bd.get("Ebs", {})
                        vol_id = ebs.get("VolumeId", "")
                        if vol_id:
                            try:
                                vols = ec2.describe_volumes(VolumeIds=[vol_id])
                                for v in vols.get("Volumes", []):
                                    if not v.get("Encrypted"):
                                        findings.append(
                                            CloudFinding(
                                                threat_type=CloudThreatType.WEAK_ENCRYPTION,
                                                severity="high",
                                                cloud_provider="aws",
                                                resource_type="ec2",
                                                resource_id=iid,
                                                region=region,
                                                description=f"EC2 '{iid}' EBS volume '{vol_id}' is not encrypted",
                                                recommendation="Enable EBS encryption at rest",
                                            )
                                        )
                            except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
                                pass
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            logger.error("AWS EC2 analysis failed: %s", exc)
        return findings

    def _analyze_aws_iam(self) -> List[CloudFinding]:
        """Analyze AWS IAM for overly permissive policies, MFA, unused credentials."""
        if not self._check_sdk("boto3"):
            logger.warning("boto3 not installed — skipping AWS IAM analysis")
            return []
        import boto3  # type: ignore[import-untyped]

        findings: List[CloudFinding] = []
        try:
            iam = boto3.client("iam")
            # Check for overly permissive policies
            policies = iam.list_policies(Scope="Local", OnlyAttached=True).get(
                "Policies", []
            )
            for pol in policies:
                arn = pol["Arn"]
                try:
                    ver = iam.get_policy_version(
                        PolicyArn=arn, VersionId=pol["DefaultVersionId"]
                    )
                    doc = ver["PolicyVersion"]["Document"]
                    stmts = doc.get("Statement", []) if isinstance(doc, dict) else []
                    for stmt in stmts:
                        if stmt.get("Effect") == "Allow":
                            action = stmt.get("Action", "")
                            resource = stmt.get("Resource", "")
                            if action == "*" and resource == "*":
                                findings.append(
                                    CloudFinding(
                                        threat_type=CloudThreatType.OVERLY_PERMISSIVE_IAM,
                                        severity="critical",
                                        cloud_provider="aws",
                                        resource_type="iam_policy",
                                        resource_id=arn,
                                        description=f"IAM policy '{pol['PolicyName']}' grants full admin (Action:*, Resource:*)",
                                        recommendation="Apply least-privilege principle — restrict actions and resources",
                                    )
                                )
                except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
                    pass
            # Check users for MFA
            users = iam.list_users().get("Users", [])
            for user in users:
                uname = user["UserName"]
                mfa = iam.list_mfa_devices(UserName=uname).get("MFADevices", [])
                if not mfa:
                    # Only flag if user has console access
                    try:
                        iam.get_login_profile(UserName=uname)
                        findings.append(
                            CloudFinding(
                                threat_type=CloudThreatType.MISSING_IAM_POLICY,
                                severity="high",
                                cloud_provider="aws",
                                resource_type="iam_user",
                                resource_id=uname,
                                description=f"IAM user '{uname}' has console access without MFA",
                                recommendation="Enable MFA for all console users",
                            )
                        )
                    except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
                        pass  # No login profile = service account, MFA not applicable
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            logger.error("AWS IAM analysis failed: %s", exc)
        return findings

    def _analyze_azure_storage(self) -> List[CloudFinding]:
        """Analyze Azure Storage Accounts for HTTPS-only, encryption, public access."""
        if not self._check_sdk("azure.mgmt.storage"):
            logger.warning(
                "azure-mgmt-storage not installed — skipping Azure Storage analysis"
            )
            return []
        from azure.identity import (
            DefaultAzureCredential,  # type: ignore[import-untyped]
        )
        from azure.mgmt.storage import (
            StorageManagementClient,  # type: ignore[import-untyped]
        )

        findings: List[CloudFinding] = []
        sub_id = self.config.get("azure_subscription_id", "")
        if not sub_id:
            logger.warning(
                "azure_subscription_id not configured — skipping Azure Storage"
            )
            return []
        try:
            cred = DefaultAzureCredential()
            client = StorageManagementClient(cred, sub_id)
            for acct in client.storage_accounts.list():
                name = acct.name
                # HTTPS-only enforcement
                if not acct.enable_https_traffic_only:
                    findings.append(
                        CloudFinding(
                            threat_type=CloudThreatType.INSECURE_STORAGE,
                            severity="high",
                            cloud_provider="azure",
                            resource_type="storage_account",
                            resource_id=name,
                            description=f"Storage account '{name}' allows non-HTTPS traffic",
                            recommendation="Enable HTTPS-only traffic on the storage account",
                        )
                    )
                # Blob public access
                if acct.allow_blob_public_access:
                    findings.append(
                        CloudFinding(
                            threat_type=CloudThreatType.PUBLIC_ACCESS,
                            severity="high",
                            cloud_provider="azure",
                            resource_type="storage_account",
                            resource_id=name,
                            description=f"Storage account '{name}' allows public blob access",
                            recommendation="Disable public blob access at the account level",
                        )
                    )
                # Encryption at rest (Azure defaults to SSE, check for CMK)
                enc = acct.encryption
                if enc and enc.key_source == "Microsoft.Storage":
                    findings.append(
                        CloudFinding(
                            threat_type=CloudThreatType.WEAK_ENCRYPTION,
                            severity="low",
                            cloud_provider="azure",
                            resource_type="storage_account",
                            resource_id=name,
                            description=f"Storage account '{name}' uses Microsoft-managed keys (not CMK)",
                            recommendation="Consider using Customer-Managed Keys (CMK) for enhanced control",
                        )
                    )
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            logger.error("Azure Storage analysis failed: %s", exc)
        return findings

    def _analyze_azure_sql(self) -> List[CloudFinding]:
        """Analyze Azure SQL Databases for TDE, firewall rules, auditing."""
        if not self._check_sdk("azure.mgmt.sql"):
            logger.warning("azure-mgmt-sql not installed — skipping Azure SQL analysis")
            return []
        from azure.identity import (
            DefaultAzureCredential,  # type: ignore[import-untyped]
        )
        from azure.mgmt.sql import SqlManagementClient  # type: ignore[import-untyped]

        findings: List[CloudFinding] = []
        sub_id = self.config.get("azure_subscription_id", "")
        if not sub_id:
            logger.warning("azure_subscription_id not configured — skipping Azure SQL")
            return []
        try:
            cred = DefaultAzureCredential()
            client = SqlManagementClient(cred, sub_id)
            for server in client.servers.list():
                rg = server.id.split("/")[4] if server.id else ""
                srv_name = server.name
                # Check firewall rules for 0.0.0.0 (allow all Azure services)
                for rule in client.firewall_rules.list_by_server(rg, srv_name):
                    if (
                        rule.start_ip_address == "0.0.0.0"
                        and rule.end_ip_address == "255.255.255.255"
                    ):
                        findings.append(
                            CloudFinding(
                                threat_type=CloudThreatType.PUBLIC_DATABASE,
                                severity="critical",
                                cloud_provider="azure",
                                resource_type="sql_server",
                                resource_id=srv_name,
                                description=f"SQL server '{srv_name}' firewall allows all IP addresses",
                                recommendation="Restrict firewall rules to specific IP ranges or VNets",
                            )
                        )
                # Check TDE on databases
                for db in client.databases.list_by_server(rg, srv_name):
                    if db.name == "master":
                        continue
                    try:
                        tde = client.transparent_data_encryptions.get(
                            rg, srv_name, db.name, "current"
                        )
                        if tde.status != "Enabled":
                            findings.append(
                                CloudFinding(
                                    threat_type=CloudThreatType.UNENCRYPTED_DATABASE,
                                    severity="high",
                                    cloud_provider="azure",
                                    resource_type="sql_database",
                                    resource_id=f"{srv_name}/{db.name}",
                                    description=f"SQL database '{db.name}' on '{srv_name}' has TDE disabled",
                                    recommendation="Enable Transparent Data Encryption (TDE)",
                                )
                            )
                    except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
                        pass
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            logger.error("Azure SQL analysis failed: %s", exc)
        return findings

    def _analyze_azure_vm(self) -> List[CloudFinding]:
        """Analyze Azure VMs for disk encryption, managed identity, NSG rules."""
        if not self._check_sdk("azure.mgmt.compute"):
            logger.warning(
                "azure-mgmt-compute not installed — skipping Azure VM analysis"
            )
            return []
        from azure.identity import (
            DefaultAzureCredential,  # type: ignore[import-untyped]
        )
        from azure.mgmt.compute import (
            ComputeManagementClient,  # type: ignore[import-untyped]
        )

        findings: List[CloudFinding] = []
        sub_id = self.config.get("azure_subscription_id", "")
        if not sub_id:
            logger.warning("azure_subscription_id not configured — skipping Azure VM")
            return []
        try:
            cred = DefaultAzureCredential()
            client = ComputeManagementClient(cred, sub_id)
            for vm in client.virtual_machines.list_all():
                vm_name = vm.name
                # Check managed identity
                if not vm.identity:
                    findings.append(
                        CloudFinding(
                            threat_type=CloudThreatType.MISSING_IAM_POLICY,
                            severity="medium",
                            cloud_provider="azure",
                            resource_type="virtual_machine",
                            resource_id=vm_name,
                            description=f"VM '{vm_name}' has no managed identity assigned",
                            recommendation="Assign a system or user-assigned managed identity",
                        )
                    )
                # Check OS disk encryption
                os_disk = vm.storage_profile.os_disk if vm.storage_profile else None
                if os_disk and os_disk.managed_disk:
                    enc = os_disk.managed_disk.disk_encryption_set
                    if not enc:
                        findings.append(
                            CloudFinding(
                                threat_type=CloudThreatType.WEAK_ENCRYPTION,
                                severity="high",
                                cloud_provider="azure",
                                resource_type="virtual_machine",
                                resource_id=vm_name,
                                description=f"VM '{vm_name}' OS disk not using disk encryption set",
                                recommendation="Enable Azure Disk Encryption or server-side encryption with CMK",
                            )
                        )
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            logger.error("Azure VM analysis failed: %s", exc)
        return findings

    def _analyze_gcp_storage(self) -> List[CloudFinding]:
        """Analyze GCP Cloud Storage buckets for public access, encryption, IAM."""
        if not self._check_sdk("google.cloud.storage"):
            logger.warning("GCP SDK not installed — skipping GCP Storage analysis")
            return []
        from google.cloud import storage as gcs  # type: ignore[import-untyped]

        findings: List[CloudFinding] = []
        project_id = self.config.get("gcp_project_id", "")
        try:
            client = gcs.Client(project=project_id) if project_id else gcs.Client()
            for bucket in client.list_buckets():
                name = bucket.name
                # Check for uniform bucket-level access
                if not bucket.iam_configuration.uniform_bucket_level_access_enabled:
                    findings.append(
                        CloudFinding(
                            threat_type=CloudThreatType.PUBLIC_ACCESS,
                            severity="medium",
                            cloud_provider="gcp",
                            resource_type="gcs_bucket",
                            resource_id=name,
                            description=f"GCS bucket '{name}' does not enforce uniform bucket-level access",
                            recommendation="Enable uniform bucket-level access to prevent ACL-based access",
                        )
                    )
                # Check for public IAM members
                policy = bucket.get_iam_policy()
                for binding in policy.bindings:
                    members = binding.get("members", [])
                    if "allUsers" in members or "allAuthenticatedUsers" in members:
                        findings.append(
                            CloudFinding(
                                threat_type=CloudThreatType.PUBLIC_ACCESS,
                                severity="critical",
                                cloud_provider="gcp",
                                resource_type="gcs_bucket",
                                resource_id=name,
                                description=f"GCS bucket '{name}' is publicly accessible via IAM ({binding['role']})",
                                recommendation="Remove allUsers/allAuthenticatedUsers from bucket IAM policy",
                            )
                        )
                # Check default encryption (CMEK)
                if not bucket.default_kms_key_name:
                    findings.append(
                        CloudFinding(
                            threat_type=CloudThreatType.WEAK_ENCRYPTION,
                            severity="low",
                            cloud_provider="gcp",
                            resource_type="gcs_bucket",
                            resource_id=name,
                            description=f"GCS bucket '{name}' uses Google-managed encryption (not CMEK)",
                            recommendation="Configure Customer-Managed Encryption Key (CMEK) for enhanced control",
                        )
                    )
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            logger.error("GCP Storage analysis failed: %s", exc)
        return findings

    def _analyze_gcp_sql(self) -> List[CloudFinding]:
        """Analyze GCP Cloud SQL instances for public IP, SSL, backups."""
        if not self._check_sdk("googleapiclient"):
            logger.warning(
                "google-api-python-client not installed — skipping GCP SQL analysis"
            )
            return []
        from google.auth import default as gauth_default  # type: ignore[import-untyped]
        from googleapiclient import discovery  # type: ignore[import-untyped]

        findings: List[CloudFinding] = []
        project_id = self.config.get("gcp_project_id", "")
        if not project_id:
            logger.warning("gcp_project_id not configured — skipping GCP SQL")
            return []
        try:
            creds, _ = gauth_default()
            service = discovery.build("sqladmin", "v1beta4", credentials=creds)
            result = service.instances().list(project=project_id).execute()
            for inst in result.get("items", []):
                name = inst["name"]
                settings = inst.get("settings", {})
                ip_config = settings.get("ipConfiguration", {})
                # Public IP check
                if ip_config.get("ipv4Enabled"):
                    findings.append(
                        CloudFinding(
                            threat_type=CloudThreatType.PUBLIC_DATABASE,
                            severity="high",
                            cloud_provider="gcp",
                            resource_type="cloud_sql",
                            resource_id=name,
                            description=f"Cloud SQL '{name}' has a public IPv4 address",
                            recommendation="Use private IP only with VPC peering",
                        )
                    )
                # SSL enforcement
                if not ip_config.get("requireSsl"):
                    findings.append(
                        CloudFinding(
                            threat_type=CloudThreatType.WEAK_ENCRYPTION,
                            severity="high",
                            cloud_provider="gcp",
                            resource_type="cloud_sql",
                            resource_id=name,
                            description=f"Cloud SQL '{name}' does not require SSL connections",
                            recommendation="Enable requireSsl in IP configuration",
                        )
                    )
                # Backup check
                backup_config = settings.get("backupConfiguration", {})
                if not backup_config.get("enabled"):
                    findings.append(
                        CloudFinding(
                            threat_type=CloudThreatType.INSECURE_STORAGE,
                            severity="medium",
                            cloud_provider="gcp",
                            resource_type="cloud_sql",
                            resource_id=name,
                            description=f"Cloud SQL '{name}' has automated backups disabled",
                            recommendation="Enable automated backups with point-in-time recovery",
                        )
                    )
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            logger.error("GCP SQL analysis failed: %s", exc)
        return findings

    def _analyze_gcp_compute(self) -> List[CloudFinding]:
        """Analyze GCP Compute Engine instances for service accounts, firewall, disks."""
        if not self._check_sdk("googleapiclient"):
            logger.warning(
                "google-api-python-client not installed — skipping GCP Compute analysis"
            )
            return []
        from google.auth import default as gauth_default  # type: ignore[import-untyped]
        from googleapiclient import discovery  # type: ignore[import-untyped]

        findings: List[CloudFinding] = []
        project_id = self.config.get("gcp_project_id", "")
        if not project_id:
            logger.warning("gcp_project_id not configured — skipping GCP Compute")
            return []
        try:
            creds, _ = gauth_default()
            compute = discovery.build("compute", "v1", credentials=creds)
            # List all instances across all zones
            agg = compute.instances().aggregatedList(project=project_id).execute()
            for zone_data in agg.get("items", {}).values():
                for inst in zone_data.get("instances", []):
                    name = inst["name"]
                    zone = inst.get("zone", "").rsplit("/", 1)[-1]
                    # Default service account check
                    for sa in inst.get("serviceAccounts", []):
                        if sa.get("email", "").endswith(
                            "-compute@developer.gserviceaccount.com"
                        ):
                            scopes = sa.get("scopes", [])
                            if (
                                "https://www.googleapis.com/auth/cloud-platform"
                                in scopes
                            ):
                                findings.append(
                                    CloudFinding(
                                        threat_type=CloudThreatType.OVERLY_PERMISSIVE_IAM,
                                        severity="high",
                                        cloud_provider="gcp",
                                        resource_type="compute_instance",
                                        resource_id=name,
                                        region=zone,
                                        description=f"GCE '{name}' uses default SA with full cloud-platform scope",
                                        recommendation="Use a custom service account with minimal scopes",
                                    )
                                )
                    # External IP check
                    for iface in inst.get("networkInterfaces", []):
                        for ac in iface.get("accessConfigs", []):
                            if ac.get("natIP"):
                                findings.append(
                                    CloudFinding(
                                        threat_type=CloudThreatType.INSECURE_NETWORK,
                                        severity="medium",
                                        cloud_provider="gcp",
                                        resource_type="compute_instance",
                                        resource_id=name,
                                        region=zone,
                                        description=f"GCE '{name}' has an external IP address",
                                        recommendation="Remove external IP and use Cloud NAT or IAP for access",
                                    )
                                )
                    # Disk encryption (check for CMEK)
                    for disk in inst.get("disks", []):
                        enc = disk.get("diskEncryptionKey")
                        if not enc or not enc.get("kmsKeyName"):
                            # Google default encryption, no CMEK
                            findings.append(
                                CloudFinding(
                                    threat_type=CloudThreatType.WEAK_ENCRYPTION,
                                    severity="low",
                                    cloud_provider="gcp",
                                    resource_type="compute_instance",
                                    resource_id=name,
                                    region=zone,
                                    description=f"GCE '{name}' disk uses Google-managed keys (not CMEK)",
                                    recommendation="Use Customer-Managed Encryption Key (CMEK) for disk encryption",
                                )
                            )
                            break  # Only report once per instance
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            logger.error("GCP Compute analysis failed: %s", exc)
        return findings

    def _build_result(
        self, findings: List[CloudFinding], cloud_provider: str
    ) -> CloudSecurityResult:
        """Build cloud security result."""
        findings_by_type: Dict[str, int] = {}
        findings_by_severity: Dict[str, int] = {}

        for finding in findings:
            threat_type = finding.threat_type.value
            findings_by_type[threat_type] = findings_by_type.get(threat_type, 0) + 1

            severity = finding.severity
            findings_by_severity[severity] = findings_by_severity.get(severity, 0) + 1

        return CloudSecurityResult(
            findings=findings,
            total_findings=len(findings),
            findings_by_type=findings_by_type,
            findings_by_severity=findings_by_severity,
            resources_analyzed=len(set(f.resource_id for f in findings)),
            cloud_provider=cloud_provider,
        )
