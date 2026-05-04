"""
Cloud Security Posture Management (CSPM) engine.

Provides cloud resource inventory, security analysis, and CIS benchmark
compliance for AWS, Azure, and GCP. SQLite-backed persistence.
"""

from __future__ import annotations

import json
import logging as _logging
import sqlite3
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from pydantic import BaseModel, Field

_logger = _logging.getLogger(__name__)

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:
    _get_tg_bus = None  # type: ignore[assignment]


def _tg_emit(event_type: str, payload: dict) -> None:
    try:
        if _get_tg_bus is None:
            return
        bus = _get_tg_bus()
        if bus is not None:
            bus.emit(event_type, payload)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class CloudProvider(str, Enum):
    AWS = "AWS"
    AZURE = "AZURE"
    GCP = "GCP"


class ResourceCategory(str, Enum):
    COMPUTE = "COMPUTE"
    STORAGE = "STORAGE"
    NETWORK = "NETWORK"
    IAM = "IAM"
    DATABASE = "DATABASE"
    ENCRYPTION = "ENCRYPTION"
    LOGGING = "LOGGING"
    CONTAINER = "CONTAINER"


class ComplianceStatus(str, Enum):
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    NOT_ASSESSED = "NOT_ASSESSED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class CheckSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class CloudResource(BaseModel):
    """A cloud resource discovered during inventory sync."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    provider: CloudProvider
    category: ResourceCategory
    resource_type: str  # e.g. "s3_bucket", "security_group"
    resource_id: str
    name: str
    region: str
    account_id: str
    config: Dict[str, Any] = Field(default_factory=dict)
    tags: Dict[str, str] = Field(default_factory=dict)
    public_exposure: bool = False
    encryption_enabled: bool = True
    last_synced: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    org_id: str


class SecurityCheck(BaseModel):
    """A security check definition (maps to a check method)."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    provider: CloudProvider
    category: ResourceCategory
    cis_benchmark: Optional[str] = None
    severity: CheckSeverity
    check_function: str  # name of the method on CSPMEngine


class CheckResult(BaseModel):
    """Result of running a SecurityCheck against a CloudResource."""

    resource_id: str
    check_id: str
    status: ComplianceStatus
    details: str
    remediation: str
    checked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Built-in security checks catalogue
# ---------------------------------------------------------------------------

_BUILTIN_CHECKS: List[SecurityCheck] = [
    # ------- AWS -------
    SecurityCheck(
        name="AWS S3 Block Public Access",
        description="S3 bucket should block all public access",
        provider=CloudProvider.AWS,
        category=ResourceCategory.STORAGE,
        cis_benchmark="CIS AWS 2.1.5",
        severity=CheckSeverity.CRITICAL,
        check_function="check_aws_s3_public_access",
    ),
    SecurityCheck(
        name="AWS S3 Server-Side Encryption",
        description="S3 bucket should have default encryption enabled",
        provider=CloudProvider.AWS,
        category=ResourceCategory.STORAGE,
        cis_benchmark="CIS AWS 2.1.1",
        severity=CheckSeverity.HIGH,
        check_function="check_aws_s3_encryption",
    ),
    SecurityCheck(
        name="AWS VPC Flow Logs Enabled",
        description="VPC flow logs should be enabled for all VPCs",
        provider=CloudProvider.AWS,
        category=ResourceCategory.LOGGING,
        cis_benchmark="CIS AWS 3.9",
        severity=CheckSeverity.MEDIUM,
        check_function="check_aws_vpc_flow_logs",
    ),
    SecurityCheck(
        name="AWS CloudTrail Enabled",
        description="CloudTrail should be enabled and logging to all regions",
        provider=CloudProvider.AWS,
        category=ResourceCategory.LOGGING,
        cis_benchmark="CIS AWS 3.1",
        severity=CheckSeverity.HIGH,
        check_function="check_aws_cloudtrail",
    ),
    SecurityCheck(
        name="AWS IAM MFA Enabled",
        description="IAM users with console access should have MFA enabled",
        provider=CloudProvider.AWS,
        category=ResourceCategory.IAM,
        cis_benchmark="CIS AWS 1.10",
        severity=CheckSeverity.CRITICAL,
        check_function="check_aws_iam_mfa",
    ),
    SecurityCheck(
        name="AWS Security Group No Unrestricted SSH",
        description="Security groups should not allow unrestricted inbound SSH (port 22)",
        provider=CloudProvider.AWS,
        category=ResourceCategory.NETWORK,
        cis_benchmark="CIS AWS 5.2",
        severity=CheckSeverity.HIGH,
        check_function="check_aws_sg_open_ssh",
    ),
    SecurityCheck(
        name="AWS Security Group No Unrestricted RDP",
        description="Security groups should not allow unrestricted inbound RDP (port 3389)",
        provider=CloudProvider.AWS,
        category=ResourceCategory.NETWORK,
        cis_benchmark="CIS AWS 5.3",
        severity=CheckSeverity.HIGH,
        check_function="check_aws_sg_open_rdp",
    ),
    SecurityCheck(
        name="AWS RDS No Public Accessibility",
        description="RDS instances should not be publicly accessible",
        provider=CloudProvider.AWS,
        category=ResourceCategory.DATABASE,
        cis_benchmark="CIS AWS 2.3.2",
        severity=CheckSeverity.CRITICAL,
        check_function="check_aws_rds_public",
    ),
    SecurityCheck(
        name="AWS EBS Volumes Encrypted",
        description="EBS volumes should be encrypted at rest",
        provider=CloudProvider.AWS,
        category=ResourceCategory.ENCRYPTION,
        cis_benchmark="CIS AWS 2.2.1",
        severity=CheckSeverity.HIGH,
        check_function="check_aws_ebs_encryption",
    ),
    # ------- Azure -------
    SecurityCheck(
        name="Azure Storage Account Encryption",
        description="Azure storage accounts should use customer-managed or Microsoft-managed keys",
        provider=CloudProvider.AZURE,
        category=ResourceCategory.STORAGE,
        cis_benchmark="CIS Azure 3.2",
        severity=CheckSeverity.HIGH,
        check_function="check_azure_storage_encryption",
    ),
    SecurityCheck(
        name="Azure NSG No Unrestricted SSH",
        description="Azure NSGs should not allow unrestricted inbound SSH access",
        provider=CloudProvider.AZURE,
        category=ResourceCategory.NETWORK,
        cis_benchmark="CIS Azure 6.2",
        severity=CheckSeverity.HIGH,
        check_function="check_azure_nsg_ssh",
    ),
    SecurityCheck(
        name="Azure NSG No Unrestricted RDP",
        description="Azure NSGs should not allow unrestricted inbound RDP access",
        provider=CloudProvider.AZURE,
        category=ResourceCategory.NETWORK,
        cis_benchmark="CIS Azure 6.1",
        severity=CheckSeverity.HIGH,
        check_function="check_azure_nsg_rdp",
    ),
    SecurityCheck(
        name="Azure Key Vault Diagnostic Logs",
        description="Azure Key Vault should have diagnostic logs enabled",
        provider=CloudProvider.AZURE,
        category=ResourceCategory.LOGGING,
        cis_benchmark="CIS Azure 5.1.6",
        severity=CheckSeverity.MEDIUM,
        check_function="check_azure_keyvault_logs",
    ),
    SecurityCheck(
        name="Azure SQL Transparent Data Encryption",
        description="Azure SQL databases should have TDE enabled",
        provider=CloudProvider.AZURE,
        category=ResourceCategory.DATABASE,
        cis_benchmark="CIS Azure 4.1.2",
        severity=CheckSeverity.HIGH,
        check_function="check_azure_sql_tde",
    ),
    SecurityCheck(
        name="Azure AKS RBAC Enabled",
        description="Azure Kubernetes Service clusters should have RBAC enabled",
        provider=CloudProvider.AZURE,
        category=ResourceCategory.CONTAINER,
        cis_benchmark="CIS Azure 8.5",
        severity=CheckSeverity.HIGH,
        check_function="check_azure_aks_rbac",
    ),
    # ------- GCP -------
    SecurityCheck(
        name="GCP Storage Bucket No Public ACL",
        description="GCP storage buckets should not allow public (allUsers/allAuthenticatedUsers) ACLs",
        provider=CloudProvider.GCP,
        category=ResourceCategory.STORAGE,
        cis_benchmark="CIS GCP 5.1",
        severity=CheckSeverity.CRITICAL,
        check_function="check_gcp_bucket_public_acl",
    ),
    SecurityCheck(
        name="GCP Firewall No Unrestricted SSH",
        description="GCP firewall rules should not allow unrestricted SSH from 0.0.0.0/0",
        provider=CloudProvider.GCP,
        category=ResourceCategory.NETWORK,
        cis_benchmark="CIS GCP 3.6",
        severity=CheckSeverity.HIGH,
        check_function="check_gcp_firewall_ssh",
    ),
    SecurityCheck(
        name="GCP Cloud Audit Logging Enabled",
        description="GCP audit logging should be enabled for all services",
        provider=CloudProvider.GCP,
        category=ResourceCategory.LOGGING,
        cis_benchmark="CIS GCP 2.1",
        severity=CheckSeverity.HIGH,
        check_function="check_gcp_audit_logging",
    ),
    SecurityCheck(
        name="GCP KMS Key Rotation",
        description="GCP KMS keys should have rotation enabled (≤90 days)",
        provider=CloudProvider.GCP,
        category=ResourceCategory.ENCRYPTION,
        cis_benchmark="CIS GCP 1.10",
        severity=CheckSeverity.MEDIUM,
        check_function="check_gcp_kms_rotation",
    ),
    SecurityCheck(
        name="GCP GKE RBAC Enabled",
        description="GCP GKE clusters should have legacy ABAC disabled and RBAC enabled",
        provider=CloudProvider.GCP,
        category=ResourceCategory.CONTAINER,
        cis_benchmark="CIS GCP 7.3",
        severity=CheckSeverity.HIGH,
        check_function="check_gcp_gke_rbac",
    ),
    SecurityCheck(
        name="GCP Cloud SQL SSL Required",
        description="GCP Cloud SQL instances should require SSL for all connections",
        provider=CloudProvider.GCP,
        category=ResourceCategory.DATABASE,
        cis_benchmark="CIS GCP 6.1",
        severity=CheckSeverity.HIGH,
        check_function="check_gcp_sql_ssl",
    ),
]


# ---------------------------------------------------------------------------
# CSPM Engine
# ---------------------------------------------------------------------------


class CSPMEngine:
    """SQLite-backed CSPM engine for cloud resource inventory and security analysis."""

    def __init__(self, db_path: str = "data/cspm.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        # FEATURE-5: route through DBAdapter so DATABASE_URL switches to postgres.
        from core.db_adapter import get_adapter
        self._db = get_adapter(str(self.db_path))
        self._init_tables()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_conn(self):  # type: ignore[no-untyped-def]
        """Return a fresh per-call connection.

        FEATURE-5: this no longer hard-binds to sqlite3 — when DATABASE_URL is
        set the adapter returns a psycopg2.connection instead. Callers MUST close
        it (existing code already does so via try/finally).
        """
        if self._db.is_postgres:
            return self._db._psycopg2.connect(self._db.dsn)  # type: ignore[union-attr]
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_tables(self) -> None:
        conn = self._get_conn()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS cloud_resources (
                    id TEXT PRIMARY KEY,
                    provider TEXT NOT NULL,
                    category TEXT NOT NULL,
                    resource_type TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    region TEXT NOT NULL,
                    account_id TEXT NOT NULL,
                    config TEXT NOT NULL,
                    tags TEXT NOT NULL,
                    public_exposure INTEGER NOT NULL DEFAULT 0,
                    encryption_enabled INTEGER NOT NULL DEFAULT 1,
                    last_synced TEXT NOT NULL,
                    org_id TEXT NOT NULL
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_resources_unique
                    ON cloud_resources(org_id, provider, resource_id);
                CREATE INDEX IF NOT EXISTS idx_resources_org ON cloud_resources(org_id);
                CREATE INDEX IF NOT EXISTS idx_resources_provider ON cloud_resources(provider);
                CREATE INDEX IF NOT EXISTS idx_resources_category ON cloud_resources(category);

                CREATE TABLE IF NOT EXISTS check_results (
                    id TEXT PRIMARY KEY,
                    resource_id TEXT NOT NULL,
                    check_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    details TEXT NOT NULL,
                    remediation TEXT NOT NULL,
                    checked_at TEXT NOT NULL,
                    org_id TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_results_org ON check_results(org_id);
                CREATE INDEX IF NOT EXISTS idx_results_resource ON check_results(resource_id);
                CREATE INDEX IF NOT EXISTS idx_results_check ON check_results(check_id);
                CREATE INDEX IF NOT EXISTS idx_results_status ON check_results(status);
                """
            )
            conn.commit()
        finally:
            conn.close()

    def _row_to_resource(self, row: sqlite3.Row) -> CloudResource:
        return CloudResource(
            id=row["id"],
            provider=CloudProvider(row["provider"]),
            category=ResourceCategory(row["category"]),
            resource_type=row["resource_type"],
            resource_id=row["resource_id"],
            name=row["name"],
            region=row["region"],
            account_id=row["account_id"],
            config=json.loads(row["config"]),
            tags=json.loads(row["tags"]),
            public_exposure=bool(row["public_exposure"]),
            encryption_enabled=bool(row["encryption_enabled"]),
            last_synced=datetime.fromisoformat(row["last_synced"]),
            org_id=row["org_id"],
        )

    def _row_to_result(self, row: sqlite3.Row) -> CheckResult:
        return CheckResult(
            resource_id=row["resource_id"],
            check_id=row["check_id"],
            status=ComplianceStatus(row["status"]),
            details=row["details"],
            remediation=row["remediation"],
            checked_at=datetime.fromisoformat(row["checked_at"]),
        )

    # ------------------------------------------------------------------
    # Resource management
    # ------------------------------------------------------------------

    def sync_resources(
        self,
        resources: List[CloudResource],
        provider: CloudProvider,
        org_id: str,
    ) -> int:
        """Bulk-import cloud resources. Returns count of upserted records."""
        conn = self._get_conn()
        try:
            count = 0
            for r in resources:
                conn.execute(
                    """
                    INSERT INTO cloud_resources
                        (id, provider, category, resource_type, resource_id,
                         name, region, account_id, config, tags,
                         public_exposure, encryption_enabled, last_synced, org_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(org_id, provider, resource_id) DO UPDATE SET
                        category=excluded.category,
                        resource_type=excluded.resource_type,
                        name=excluded.name,
                        region=excluded.region,
                        account_id=excluded.account_id,
                        config=excluded.config,
                        tags=excluded.tags,
                        public_exposure=excluded.public_exposure,
                        encryption_enabled=excluded.encryption_enabled,
                        last_synced=excluded.last_synced
                    """,
                    (
                        r.id,
                        provider.value,
                        r.category.value,
                        r.resource_type,
                        r.resource_id,
                        r.name,
                        r.region,
                        r.account_id,
                        json.dumps(r.config),
                        json.dumps(r.tags),
                        int(r.public_exposure),
                        int(r.encryption_enabled),
                        r.last_synced.isoformat(),
                        org_id,
                    ),
                )
                count += 1
            conn.commit()
            _tg_emit("cspm.sync_resources", {"provider": provider.value, "org_id": org_id, "resource_count": count})
            return count
        finally:
            conn.close()

    def get_resource(self, resource_id: str) -> Optional[CloudResource]:
        """Retrieve a resource by its internal UUID."""
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM cloud_resources WHERE id = ?", (resource_id,)
            ).fetchone()
            return self._row_to_resource(row) if row else None
        finally:
            conn.close()

    def list_resources(
        self,
        org_id: str,
        provider: Optional[CloudProvider] = None,
        category: Optional[ResourceCategory] = None,
        public_only: bool = False,
    ) -> List[CloudResource]:
        """List cloud resources with optional filters."""
        conn = self._get_conn()
        try:
            query = "SELECT * FROM cloud_resources WHERE org_id = ?"
            params: List[Any] = [org_id]
            if provider:
                query += " AND provider = ?"
                params.append(provider.value)
            if category:
                query += " AND category = ?"
                params.append(category.value)
            if public_only:
                query += " AND public_exposure = 1"
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_resource(r) for r in rows]
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Security checks — orchestration
    # ------------------------------------------------------------------

    def run_security_checks(
        self,
        org_id: str,
        provider: Optional[CloudProvider] = None,
    ) -> List[CheckResult]:
        """Run all applicable security checks for an org, optionally filtered by provider.

        Perf fix: accumulate all results in memory, then persist in a single
        batched executemany call (one connection, one transaction) instead of
        opening+closing a SQLite connection per result.
        """
        resources = self.list_resources(org_id=org_id, provider=provider)
        results: List[CheckResult] = []
        checks = [c for c in _BUILTIN_CHECKS if provider is None or c.provider == provider]
        for resource in resources:
            for check in checks:
                if check.provider != resource.provider:
                    continue
                result = self.run_check(resource, check)
                results.append(result)
        # Batch persist — single connection, single transaction
        self._persist_results_bulk(results, org_id)
        _tg_emit("cspm.run_security_checks", {"org_id": org_id, "provider": provider.value if provider else "all", "results_count": len(results)})
        return results

    def run_check(self, resource: CloudResource, check: SecurityCheck) -> CheckResult:
        """Execute a single security check against a resource."""
        fn: Optional[Callable] = getattr(self, check.check_function, None)
        if fn is None:
            return CheckResult(
                resource_id=resource.id,
                check_id=check.id,
                status=ComplianceStatus.NOT_ASSESSED,
                details=f"Check function '{check.check_function}' not implemented.",
                remediation="",
            )
        return fn(resource, check)

    def _persist_results_bulk(self, results: List[CheckResult], org_id: str) -> None:
        """Batch-insert check results — one connection, one executemany, one commit."""
        if not results:
            return
        rows = [
            (
                str(uuid.uuid4()),
                r.resource_id,
                r.check_id,
                r.status.value,
                r.details,
                r.remediation,
                r.checked_at.isoformat(),
                org_id,
            )
            for r in results
        ]
        conn = self._get_conn()
        try:
            conn.executemany(
                """
                INSERT OR REPLACE INTO check_results
                    (id, resource_id, check_id, status, details, remediation, checked_at, org_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
            conn.commit()
        finally:
            conn.close()

    def _persist_result(self, result: CheckResult, org_id: str) -> None:
        """Single-result persist — kept for external callers; delegates to bulk helper."""
        self._persist_results_bulk([result], org_id)

    def get_check_results(
        self,
        org_id: str,
        provider: Optional[CloudProvider] = None,
        status_filter: Optional[ComplianceStatus] = None,
    ) -> List[CheckResult]:
        """Retrieve stored check results with optional filters."""
        conn = self._get_conn()
        try:
            query = "SELECT cr.* FROM check_results cr WHERE cr.org_id = ?"
            params: List[Any] = [org_id]
            if status_filter:
                query += " AND cr.status = ?"
                params.append(status_filter.value)
            if provider:
                query += (
                    " AND cr.resource_id IN "
                    "(SELECT id FROM cloud_resources WHERE org_id = ? AND provider = ?)"
                )
                params.extend([org_id, provider.value])
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_result(r) for r in rows]
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Aggregated views
    # ------------------------------------------------------------------

    def get_compliance_summary(
        self,
        org_id: str,
        provider: Optional[CloudProvider] = None,
    ) -> Dict[str, Any]:
        """Return pass/fail/na counts overall and by category."""
        results = self.get_check_results(org_id=org_id, provider=provider)
        total = len(results)
        if total == 0:
            return {
                "total": 0,
                "compliant": 0,
                "non_compliant": 0,
                "not_assessed": 0,
                "not_applicable": 0,
                "compliance_rate": 0.0,
                "by_category": {},
            }

        by_status: Dict[str, int] = {s.value: 0 for s in ComplianceStatus}
        by_category: Dict[str, Dict[str, int]] = {}

        # Build a lookup: check_id -> category
        check_map: Dict[str, str] = {c.id: c.category.value for c in _BUILTIN_CHECKS}

        # Resource id -> category mapping from DB
        conn = self._get_conn()
        try:
            query = "SELECT id, category FROM cloud_resources WHERE org_id = ?"
            params: List[Any] = [org_id]
            if provider:
                query += " AND provider = ?"
                params.append(provider.value)
            res_rows = conn.execute(query, params).fetchall()
            resource_category: Dict[str, str] = {r["id"]: r["category"] for r in res_rows}
        finally:
            conn.close()

        for r in results:
            by_status[r.status.value] = by_status.get(r.status.value, 0) + 1
            cat = resource_category.get(r.resource_id, check_map.get(r.check_id, "UNKNOWN"))
            if cat not in by_category:
                by_category[cat] = {s.value: 0 for s in ComplianceStatus}
            by_category[cat][r.status.value] = by_category[cat].get(r.status.value, 0) + 1

        compliant = by_status.get(ComplianceStatus.COMPLIANT.value, 0)
        non_compliant = by_status.get(ComplianceStatus.NON_COMPLIANT.value, 0)
        assessed = compliant + non_compliant
        compliance_rate = (compliant / assessed * 100) if assessed > 0 else 0.0

        return {
            "total": total,
            "compliant": compliant,
            "non_compliant": non_compliant,
            "not_assessed": by_status.get(ComplianceStatus.NOT_ASSESSED.value, 0),
            "not_applicable": by_status.get(ComplianceStatus.NOT_APPLICABLE.value, 0),
            "compliance_rate": round(compliance_rate, 2),
            "by_category": by_category,
        }

    def get_public_resources(self, org_id: str) -> List[CloudResource]:
        """Return internet-exposed resources."""
        return self.list_resources(org_id=org_id, public_only=True)

    def get_unencrypted_resources(self, org_id: str) -> List[CloudResource]:
        """Return resources with encryption disabled."""
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM cloud_resources WHERE org_id = ? AND encryption_enabled = 0",
                (org_id,),
            ).fetchall()
            return [self._row_to_resource(r) for r in rows]
        finally:
            conn.close()

    def get_iam_findings(
        self,
        org_id: str,
        provider: Optional[CloudProvider] = None,
    ) -> List[Dict[str, Any]]:
        """Return IAM resources with overly permissive policies."""
        resources = self.list_resources(
            org_id=org_id, provider=provider, category=ResourceCategory.IAM
        )
        findings: List[Dict[str, Any]] = []
        for r in resources:
            cfg = r.config
            issues: List[str] = []
            # Admin / wildcard permissions
            if cfg.get("admin_access") or cfg.get("AdministratorAccess"):
                issues.append("Has AdministratorAccess policy attached")
            if cfg.get("wildcard_permissions"):
                issues.append("Has wildcard (*) permissions in policy")
            if not cfg.get("mfa_enabled") and cfg.get("console_access", False):
                issues.append("Console access enabled without MFA")
            if cfg.get("access_keys_age_days", 0) > 90:
                issues.append(
                    f"Access key older than 90 days ({cfg['access_keys_age_days']} days)"
                )
            if cfg.get("last_used_days") is not None and cfg.get("last_used_days", 0) > 90:
                issues.append(f"User inactive for {cfg.get('last_used_days')} days")
            if issues:
                findings.append(
                    {
                        "resource_id": r.id,
                        "resource_name": r.name,
                        "provider": r.provider.value,
                        "region": r.region,
                        "issues": issues,
                        "severity": "HIGH" if len(issues) >= 2 else "MEDIUM",
                    }
                )
        return findings

    def get_security_group_findings(self, org_id: str) -> List[Dict[str, Any]]:
        """Return security group / firewall resources with risky open rules."""
        resources = self.list_resources(
            org_id=org_id, category=ResourceCategory.NETWORK
        )
        findings: List[Dict[str, Any]] = []
        dangerous_ports = {22: "SSH", 3389: "RDP", 23: "Telnet", 21: "FTP", 5900: "VNC"}
        for r in resources:
            cfg = r.config
            inbound_rules: List[Dict[str, Any]] = cfg.get("inbound_rules", [])
            issues: List[str] = []
            for rule in inbound_rules:
                cidr = rule.get("cidr", "")
                if cidr in ("0.0.0.0/0", "::/0"):
                    port = rule.get("port") or rule.get("from_port")
                    if port in dangerous_ports:
                        issues.append(
                            f"Open {dangerous_ports[port]} (port {port}) from {cidr}"
                        )
                    elif rule.get("protocol") == "-1":
                        issues.append(f"Allow-all rule from {cidr}")
            if cfg.get("allow_all_outbound") and cfg.get("allow_all_inbound"):
                issues.append("All inbound and outbound traffic allowed")
            if issues:
                findings.append(
                    {
                        "resource_id": r.id,
                        "resource_name": r.name,
                        "provider": r.provider.value,
                        "region": r.region,
                        "resource_type": r.resource_type,
                        "issues": issues,
                        "severity": "HIGH" if any("SSH" in i or "RDP" in i for i in issues) else "MEDIUM",
                    }
                )
        return findings

    def get_cspm_score(self, org_id: str) -> float:
        """Return a 0-100 cloud security posture score.

        Perf fix: replaced 3 separate list_resources() calls (3 full table
        scans) with a single SQL aggregate query that returns public_count,
        unencrypted_count, and total_count in one round-trip.
        """
        summary = self.get_compliance_summary(org_id=org_id)
        total = summary["total"]
        if total == 0:
            return 100.0  # no resources → nothing failing

        compliant = summary["compliant"]
        non_compliant = summary["non_compliant"]
        assessed = compliant + non_compliant
        if assessed == 0:
            return 50.0  # nothing assessed yet

        # Single-query aggregate: public_count, unencrypted_count, total in one pass
        conn = self._get_conn()
        try:
            row = conn.execute(
                """
                SELECT
                    COUNT(*)                                      AS total_count,
                    SUM(CASE WHEN public_exposure = 1 THEN 1 ELSE 0 END) AS public_count,
                    SUM(CASE WHEN encryption_enabled = 0 THEN 1 ELSE 0 END) AS unenc_count
                FROM cloud_resources
                WHERE org_id = ?
                """,
                (org_id,),
            ).fetchone()
        finally:
            conn.close()

        resource_count = row["total_count"] or 0
        public_count = row["public_count"] or 0
        unencrypted_count = row["unenc_count"] or 0

        # Base score from pass rate, then penalise for public/unencrypted resources
        base_score = (compliant / assessed) * 100

        if resource_count > 0:
            public_penalty = (public_count / resource_count) * 10
            encrypt_penalty = (unencrypted_count / resource_count) * 10
        else:
            public_penalty = 0.0
            encrypt_penalty = 0.0

        score = max(0.0, min(100.0, base_score - public_penalty - encrypt_penalty))
        return round(score, 2)

    # ------------------------------------------------------------------
    # AWS check implementations
    # ------------------------------------------------------------------

    def check_aws_s3_public_access(self, resource: CloudResource, check: SecurityCheck) -> CheckResult:
        if resource.resource_type != "s3_bucket":
            return CheckResult(
                resource_id=resource.id, check_id=check.id,
                status=ComplianceStatus.NOT_APPLICABLE,
                details="Not an S3 bucket.", remediation="",
            )
        cfg = resource.config
        block_public = cfg.get("block_public_access", False)
        if resource.public_exposure or not block_public:
            return CheckResult(
                resource_id=resource.id, check_id=check.id,
                status=ComplianceStatus.NON_COMPLIANT,
                details="S3 bucket allows public access.",
                remediation="Enable S3 Block Public Access settings on the bucket and account level.",
            )
        return CheckResult(
            resource_id=resource.id, check_id=check.id,
            status=ComplianceStatus.COMPLIANT,
            details="S3 bucket blocks public access.", remediation="",
        )

    def check_aws_s3_encryption(self, resource: CloudResource, check: SecurityCheck) -> CheckResult:
        if resource.resource_type != "s3_bucket":
            return CheckResult(
                resource_id=resource.id, check_id=check.id,
                status=ComplianceStatus.NOT_APPLICABLE,
                details="Not an S3 bucket.", remediation="",
            )
        if not resource.encryption_enabled:
            return CheckResult(
                resource_id=resource.id, check_id=check.id,
                status=ComplianceStatus.NON_COMPLIANT,
                details="S3 bucket does not have default encryption enabled.",
                remediation="Enable default server-side encryption (SSE-S3 or SSE-KMS) on the bucket.",
            )
        return CheckResult(
            resource_id=resource.id, check_id=check.id,
            status=ComplianceStatus.COMPLIANT,
            details="S3 bucket has encryption enabled.", remediation="",
        )

    def check_aws_vpc_flow_logs(self, resource: CloudResource, check: SecurityCheck) -> CheckResult:
        if resource.resource_type != "vpc":
            return CheckResult(
                resource_id=resource.id, check_id=check.id,
                status=ComplianceStatus.NOT_APPLICABLE,
                details="Not a VPC.", remediation="",
            )
        flow_logs = resource.config.get("flow_logs_enabled", False)
        if not flow_logs:
            return CheckResult(
                resource_id=resource.id, check_id=check.id,
                status=ComplianceStatus.NON_COMPLIANT,
                details="VPC flow logs are not enabled.",
                remediation="Enable VPC flow logs and send to CloudWatch Logs or S3.",
            )
        return CheckResult(
            resource_id=resource.id, check_id=check.id,
            status=ComplianceStatus.COMPLIANT,
            details="VPC flow logs are enabled.", remediation="",
        )

    def check_aws_cloudtrail(self, resource: CloudResource, check: SecurityCheck) -> CheckResult:
        if resource.resource_type != "cloudtrail":
            return CheckResult(
                resource_id=resource.id, check_id=check.id,
                status=ComplianceStatus.NOT_APPLICABLE,
                details="Not a CloudTrail resource.", remediation="",
            )
        cfg = resource.config
        enabled = cfg.get("enabled", False)
        multi_region = cfg.get("is_multi_region_trail", False)
        if not enabled or not multi_region:
            return CheckResult(
                resource_id=resource.id, check_id=check.id,
                status=ComplianceStatus.NON_COMPLIANT,
                details="CloudTrail is not enabled or not covering all regions.",
                remediation="Enable CloudTrail with multi-region support and log file validation.",
            )
        return CheckResult(
            resource_id=resource.id, check_id=check.id,
            status=ComplianceStatus.COMPLIANT,
            details="CloudTrail is enabled for all regions.", remediation="",
        )

    def check_aws_iam_mfa(self, resource: CloudResource, check: SecurityCheck) -> CheckResult:
        if resource.resource_type != "iam_user":
            return CheckResult(
                resource_id=resource.id, check_id=check.id,
                status=ComplianceStatus.NOT_APPLICABLE,
                details="Not an IAM user.", remediation="",
            )
        cfg = resource.config
        console_access = cfg.get("console_access", False)
        mfa_enabled = cfg.get("mfa_enabled", False)
        if console_access and not mfa_enabled:
            return CheckResult(
                resource_id=resource.id, check_id=check.id,
                status=ComplianceStatus.NON_COMPLIANT,
                details="IAM user has console access but no MFA device.",
                remediation="Enable MFA for all IAM users with console access.",
            )
        return CheckResult(
            resource_id=resource.id, check_id=check.id,
            status=ComplianceStatus.COMPLIANT,
            details="IAM user MFA is properly configured.", remediation="",
        )

    def check_aws_sg_open_ssh(self, resource: CloudResource, check: SecurityCheck) -> CheckResult:
        if resource.resource_type != "security_group":
            return CheckResult(
                resource_id=resource.id, check_id=check.id,
                status=ComplianceStatus.NOT_APPLICABLE,
                details="Not a security group.", remediation="",
            )
        inbound = resource.config.get("inbound_rules", [])
        for rule in inbound:
            port = rule.get("port") or rule.get("from_port")
            cidr = rule.get("cidr", "")
            if port == 22 and cidr in ("0.0.0.0/0", "::/0"):
                return CheckResult(
                    resource_id=resource.id, check_id=check.id,
                    status=ComplianceStatus.NON_COMPLIANT,
                    details=f"Security group allows SSH from {cidr}.",
                    remediation="Restrict SSH access to specific IP ranges or use AWS Systems Manager Session Manager.",
                )
        return CheckResult(
            resource_id=resource.id, check_id=check.id,
            status=ComplianceStatus.COMPLIANT,
            details="No unrestricted SSH access found.", remediation="",
        )

    def check_aws_sg_open_rdp(self, resource: CloudResource, check: SecurityCheck) -> CheckResult:
        if resource.resource_type != "security_group":
            return CheckResult(
                resource_id=resource.id, check_id=check.id,
                status=ComplianceStatus.NOT_APPLICABLE,
                details="Not a security group.", remediation="",
            )
        inbound = resource.config.get("inbound_rules", [])
        for rule in inbound:
            port = rule.get("port") or rule.get("from_port")
            cidr = rule.get("cidr", "")
            if port == 3389 and cidr in ("0.0.0.0/0", "::/0"):
                return CheckResult(
                    resource_id=resource.id, check_id=check.id,
                    status=ComplianceStatus.NON_COMPLIANT,
                    details=f"Security group allows RDP from {cidr}.",
                    remediation="Restrict RDP access to specific IP ranges or use a VPN/bastion host.",
                )
        return CheckResult(
            resource_id=resource.id, check_id=check.id,
            status=ComplianceStatus.COMPLIANT,
            details="No unrestricted RDP access found.", remediation="",
        )

    def check_aws_rds_public(self, resource: CloudResource, check: SecurityCheck) -> CheckResult:
        if resource.resource_type != "rds_instance":
            return CheckResult(
                resource_id=resource.id, check_id=check.id,
                status=ComplianceStatus.NOT_APPLICABLE,
                details="Not an RDS instance.", remediation="",
            )
        if resource.public_exposure or resource.config.get("publicly_accessible", False):
            return CheckResult(
                resource_id=resource.id, check_id=check.id,
                status=ComplianceStatus.NON_COMPLIANT,
                details="RDS instance is publicly accessible.",
                remediation="Disable public accessibility on the RDS instance and place it in a private subnet.",
            )
        return CheckResult(
            resource_id=resource.id, check_id=check.id,
            status=ComplianceStatus.COMPLIANT,
            details="RDS instance is not publicly accessible.", remediation="",
        )

    def check_aws_ebs_encryption(self, resource: CloudResource, check: SecurityCheck) -> CheckResult:
        if resource.resource_type != "ebs_volume":
            return CheckResult(
                resource_id=resource.id, check_id=check.id,
                status=ComplianceStatus.NOT_APPLICABLE,
                details="Not an EBS volume.", remediation="",
            )
        if not resource.encryption_enabled:
            return CheckResult(
                resource_id=resource.id, check_id=check.id,
                status=ComplianceStatus.NON_COMPLIANT,
                details="EBS volume is not encrypted.",
                remediation="Enable EBS encryption. Use AWS KMS to manage encryption keys.",
            )
        return CheckResult(
            resource_id=resource.id, check_id=check.id,
            status=ComplianceStatus.COMPLIANT,
            details="EBS volume is encrypted.", remediation="",
        )

    # ------------------------------------------------------------------
    # Azure check implementations
    # ------------------------------------------------------------------

    def check_azure_storage_encryption(self, resource: CloudResource, check: SecurityCheck) -> CheckResult:
        if resource.resource_type != "storage_account":
            return CheckResult(
                resource_id=resource.id, check_id=check.id,
                status=ComplianceStatus.NOT_APPLICABLE,
                details="Not a storage account.", remediation="",
            )
        if not resource.encryption_enabled:
            return CheckResult(
                resource_id=resource.id, check_id=check.id,
                status=ComplianceStatus.NON_COMPLIANT,
                details="Azure storage account does not have encryption enabled.",
                remediation="Enable encryption at rest for the storage account using Microsoft-managed or customer-managed keys.",
            )
        return CheckResult(
            resource_id=resource.id, check_id=check.id,
            status=ComplianceStatus.COMPLIANT,
            details="Storage account encryption is enabled.", remediation="",
        )

    def _azure_nsg_port_open(self, resource: CloudResource, port: int) -> bool:
        inbound = resource.config.get("security_rules", [])
        for rule in inbound:
            dest_port = rule.get("destination_port_range", "")
            src = rule.get("source_address_prefix", "")
            access = rule.get("access", "")
            if access.upper() == "ALLOW" and src in ("*", "Internet", "0.0.0.0/0"):
                if str(port) == str(dest_port) or dest_port == "*":
                    return True
        return False

    def check_azure_nsg_ssh(self, resource: CloudResource, check: SecurityCheck) -> CheckResult:
        if resource.resource_type != "network_security_group":
            return CheckResult(
                resource_id=resource.id, check_id=check.id,
                status=ComplianceStatus.NOT_APPLICABLE,
                details="Not an NSG.", remediation="",
            )
        if self._azure_nsg_port_open(resource, 22):
            return CheckResult(
                resource_id=resource.id, check_id=check.id,
                status=ComplianceStatus.NON_COMPLIANT,
                details="NSG allows unrestricted inbound SSH.",
                remediation="Remove or restrict the NSG rule allowing SSH from any source.",
            )
        return CheckResult(
            resource_id=resource.id, check_id=check.id,
            status=ComplianceStatus.COMPLIANT,
            details="NSG does not allow unrestricted SSH.", remediation="",
        )

    def check_azure_nsg_rdp(self, resource: CloudResource, check: SecurityCheck) -> CheckResult:
        if resource.resource_type != "network_security_group":
            return CheckResult(
                resource_id=resource.id, check_id=check.id,
                status=ComplianceStatus.NOT_APPLICABLE,
                details="Not an NSG.", remediation="",
            )
        if self._azure_nsg_port_open(resource, 3389):
            return CheckResult(
                resource_id=resource.id, check_id=check.id,
                status=ComplianceStatus.NON_COMPLIANT,
                details="NSG allows unrestricted inbound RDP.",
                remediation="Remove or restrict the NSG rule allowing RDP from any source.",
            )
        return CheckResult(
            resource_id=resource.id, check_id=check.id,
            status=ComplianceStatus.COMPLIANT,
            details="NSG does not allow unrestricted RDP.", remediation="",
        )

    def check_azure_keyvault_logs(self, resource: CloudResource, check: SecurityCheck) -> CheckResult:
        if resource.resource_type != "key_vault":
            return CheckResult(
                resource_id=resource.id, check_id=check.id,
                status=ComplianceStatus.NOT_APPLICABLE,
                details="Not a Key Vault.", remediation="",
            )
        logs_enabled = resource.config.get("diagnostic_logs_enabled", False)
        if not logs_enabled:
            return CheckResult(
                resource_id=resource.id, check_id=check.id,
                status=ComplianceStatus.NON_COMPLIANT,
                details="Key Vault does not have diagnostic logs enabled.",
                remediation="Enable diagnostic settings for the Key Vault and send logs to a Log Analytics workspace.",
            )
        return CheckResult(
            resource_id=resource.id, check_id=check.id,
            status=ComplianceStatus.COMPLIANT,
            details="Key Vault diagnostic logs are enabled.", remediation="",
        )

    def check_azure_sql_tde(self, resource: CloudResource, check: SecurityCheck) -> CheckResult:
        if resource.resource_type != "sql_database":
            return CheckResult(
                resource_id=resource.id, check_id=check.id,
                status=ComplianceStatus.NOT_APPLICABLE,
                details="Not a SQL Database.", remediation="",
            )
        tde = resource.config.get("transparent_data_encryption", False)
        if not tde or not resource.encryption_enabled:
            return CheckResult(
                resource_id=resource.id, check_id=check.id,
                status=ComplianceStatus.NON_COMPLIANT,
                details="SQL Database does not have Transparent Data Encryption enabled.",
                remediation="Enable TDE on the Azure SQL database.",
            )
        return CheckResult(
            resource_id=resource.id, check_id=check.id,
            status=ComplianceStatus.COMPLIANT,
            details="SQL Database TDE is enabled.", remediation="",
        )

    def check_azure_aks_rbac(self, resource: CloudResource, check: SecurityCheck) -> CheckResult:
        if resource.resource_type != "aks_cluster":
            return CheckResult(
                resource_id=resource.id, check_id=check.id,
                status=ComplianceStatus.NOT_APPLICABLE,
                details="Not an AKS cluster.", remediation="",
            )
        rbac = resource.config.get("rbac_enabled", False)
        if not rbac:
            return CheckResult(
                resource_id=resource.id, check_id=check.id,
                status=ComplianceStatus.NON_COMPLIANT,
                details="AKS cluster does not have RBAC enabled.",
                remediation="Enable RBAC on the AKS cluster and disable legacy ABAC.",
            )
        return CheckResult(
            resource_id=resource.id, check_id=check.id,
            status=ComplianceStatus.COMPLIANT,
            details="AKS cluster RBAC is enabled.", remediation="",
        )

    # ------------------------------------------------------------------
    # GCP check implementations
    # ------------------------------------------------------------------

    def check_gcp_bucket_public_acl(self, resource: CloudResource, check: SecurityCheck) -> CheckResult:
        if resource.resource_type != "gcs_bucket":
            return CheckResult(
                resource_id=resource.id, check_id=check.id,
                status=ComplianceStatus.NOT_APPLICABLE,
                details="Not a GCS bucket.", remediation="",
            )
        acl = resource.config.get("acl", [])
        public_entities = {"allUsers", "allAuthenticatedUsers"}
        exposed = any(e.get("entity", "") in public_entities for e in acl)
        if exposed or resource.public_exposure:
            return CheckResult(
                resource_id=resource.id, check_id=check.id,
                status=ComplianceStatus.NON_COMPLIANT,
                details="GCS bucket has public ACL (allUsers or allAuthenticatedUsers).",
                remediation="Remove public ACL entries and enable uniform bucket-level access.",
            )
        return CheckResult(
            resource_id=resource.id, check_id=check.id,
            status=ComplianceStatus.COMPLIANT,
            details="GCS bucket does not have public ACL.", remediation="",
        )

    def check_gcp_firewall_ssh(self, resource: CloudResource, check: SecurityCheck) -> CheckResult:
        if resource.resource_type != "firewall_rule":
            return CheckResult(
                resource_id=resource.id, check_id=check.id,
                status=ComplianceStatus.NOT_APPLICABLE,
                details="Not a firewall rule.", remediation="",
            )
        cfg = resource.config
        source_ranges = cfg.get("source_ranges", [])
        allowed = cfg.get("allowed", [])
        open_to_world = "0.0.0.0/0" in source_ranges or "::/0" in source_ranges
        allows_ssh = any(
            str(rule.get("ports", [""])[0]) == "22" or "22" in rule.get("ports", [])
            for rule in allowed
            if rule.get("IPProtocol") in ("tcp", "all")
        )
        if open_to_world and allows_ssh:
            return CheckResult(
                resource_id=resource.id, check_id=check.id,
                status=ComplianceStatus.NON_COMPLIANT,
                details="GCP firewall rule allows SSH from 0.0.0.0/0.",
                remediation="Restrict SSH firewall rule to specific source IP ranges.",
            )
        return CheckResult(
            resource_id=resource.id, check_id=check.id,
            status=ComplianceStatus.COMPLIANT,
            details="No unrestricted SSH firewall rule found.", remediation="",
        )

    def check_gcp_audit_logging(self, resource: CloudResource, check: SecurityCheck) -> CheckResult:
        if resource.resource_type != "project":
            return CheckResult(
                resource_id=resource.id, check_id=check.id,
                status=ComplianceStatus.NOT_APPLICABLE,
                details="Not a GCP project resource.", remediation="",
            )
        audit_enabled = resource.config.get("audit_logging_enabled", False)
        if not audit_enabled:
            return CheckResult(
                resource_id=resource.id, check_id=check.id,
                status=ComplianceStatus.NON_COMPLIANT,
                details="GCP audit logging is not enabled for this project.",
                remediation="Enable Cloud Audit Logs for all services in the project IAM policy.",
            )
        return CheckResult(
            resource_id=resource.id, check_id=check.id,
            status=ComplianceStatus.COMPLIANT,
            details="GCP audit logging is enabled.", remediation="",
        )

    def check_gcp_kms_rotation(self, resource: CloudResource, check: SecurityCheck) -> CheckResult:
        if resource.resource_type != "kms_key":
            return CheckResult(
                resource_id=resource.id, check_id=check.id,
                status=ComplianceStatus.NOT_APPLICABLE,
                details="Not a KMS key.", remediation="",
            )
        rotation_days = resource.config.get("rotation_period_days")
        if rotation_days is None or rotation_days > 90:
            return CheckResult(
                resource_id=resource.id, check_id=check.id,
                status=ComplianceStatus.NON_COMPLIANT,
                details=f"KMS key rotation period is {rotation_days} days (should be ≤90).",
                remediation="Set key rotation period to 90 days or fewer in Cloud KMS.",
            )
        return CheckResult(
            resource_id=resource.id, check_id=check.id,
            status=ComplianceStatus.COMPLIANT,
            details=f"KMS key rotation period is {rotation_days} days.", remediation="",
        )

    def check_gcp_gke_rbac(self, resource: CloudResource, check: SecurityCheck) -> CheckResult:
        if resource.resource_type != "gke_cluster":
            return CheckResult(
                resource_id=resource.id, check_id=check.id,
                status=ComplianceStatus.NOT_APPLICABLE,
                details="Not a GKE cluster.", remediation="",
            )
        legacy_abac = resource.config.get("legacy_abac_enabled", True)
        if legacy_abac:
            return CheckResult(
                resource_id=resource.id, check_id=check.id,
                status=ComplianceStatus.NON_COMPLIANT,
                details="GKE cluster has legacy ABAC enabled (RBAC not enforced).",
                remediation="Disable legacy ABAC on the GKE cluster to enforce RBAC.",
            )
        return CheckResult(
            resource_id=resource.id, check_id=check.id,
            status=ComplianceStatus.COMPLIANT,
            details="GKE cluster uses RBAC (legacy ABAC disabled).", remediation="",
        )

    def check_gcp_sql_ssl(self, resource: CloudResource, check: SecurityCheck) -> CheckResult:
        if resource.resource_type != "cloud_sql":
            return CheckResult(
                resource_id=resource.id, check_id=check.id,
                status=ComplianceStatus.NOT_APPLICABLE,
                details="Not a Cloud SQL instance.", remediation="",
            )
        ssl_required = resource.config.get("require_ssl", False)
        if not ssl_required:
            return CheckResult(
                resource_id=resource.id, check_id=check.id,
                status=ComplianceStatus.NON_COMPLIANT,
                details="Cloud SQL instance does not require SSL connections.",
                remediation="Enable 'require SSL' on the Cloud SQL instance settings.",
            )
        return CheckResult(
            resource_id=resource.id, check_id=check.id,
            status=ComplianceStatus.COMPLIANT,
            details="Cloud SQL instance requires SSL.", remediation="",
        )
