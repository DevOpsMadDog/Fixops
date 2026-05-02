"""
Configuration drift detection against security baselines (CIS benchmarks).

Detects infrastructure config drift by comparing actual resource configurations
against expected baselines (AWS, Azure, GCP, on-prem). SQLite-backed persistence.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class DriftSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class CloudProvider(str, Enum):
    AWS = "AWS"
    AZURE = "AZURE"
    GCP = "GCP"
    ON_PREM = "ON_PREM"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class BaselineRule(BaseModel):
    """A security baseline rule to compare resources against."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    provider: CloudProvider
    resource_type: str
    expected_config: Dict[str, Any]
    severity: DriftSeverity
    cis_benchmark: Optional[str] = None
    remediation: str


class DriftResult(BaseModel):
    """A detected configuration drift for a specific resource."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    rule_id: str
    resource_id: str
    provider: CloudProvider
    resource_type: str
    expected: Dict[str, Any]
    actual: Dict[str, Any]
    drifted_fields: List[str]
    severity: DriftSeverity
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at: Optional[datetime] = None
    org_id: str


class DriftSummary(BaseModel):
    """Aggregated drift summary for an organisation."""

    total_resources: int
    compliant: int
    drifted: int
    compliance_rate: float
    by_severity: Dict[str, int]
    by_provider: Dict[str, int]
    top_drifts: List[Dict[str, Any]]


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


class ConfigDriftDetector:
    """SQLite-backed config drift detector against security baselines."""

    def __init__(self, db_path: str = "data/config_drift.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_tables(self) -> None:
        conn = self._get_conn()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS baseline_rules (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    resource_type TEXT NOT NULL,
                    expected_config TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    cis_benchmark TEXT,
                    remediation TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS drift_results (
                    id TEXT PRIMARY KEY,
                    rule_id TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    resource_type TEXT NOT NULL,
                    expected TEXT NOT NULL,
                    actual TEXT NOT NULL,
                    drifted_fields TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    detected_at TEXT NOT NULL,
                    resolved_at TEXT,
                    org_id TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_drift_org ON drift_results(org_id);
                CREATE INDEX IF NOT EXISTS idx_drift_resource ON drift_results(resource_id);
                CREATE INDEX IF NOT EXISTS idx_drift_resolved ON drift_results(resolved_at);
                CREATE INDEX IF NOT EXISTS idx_drift_detected ON drift_results(detected_at);
                CREATE INDEX IF NOT EXISTS idx_baseline_provider ON baseline_rules(provider);
                CREATE INDEX IF NOT EXISTS idx_baseline_resource_type ON baseline_rules(resource_type);
                """
            )
            conn.commit()
        finally:
            conn.close()

    def _row_to_rule(self, row: sqlite3.Row) -> BaselineRule:
        return BaselineRule(
            id=row["id"],
            name=row["name"],
            description=row["description"],
            provider=CloudProvider(row["provider"]),
            resource_type=row["resource_type"],
            expected_config=json.loads(row["expected_config"]),
            severity=DriftSeverity(row["severity"]),
            cis_benchmark=row["cis_benchmark"],
            remediation=row["remediation"],
        )

    def _row_to_drift(self, row: sqlite3.Row) -> DriftResult:
        return DriftResult(
            id=row["id"],
            rule_id=row["rule_id"],
            resource_id=row["resource_id"],
            provider=CloudProvider(row["provider"]),
            resource_type=row["resource_type"],
            expected=json.loads(row["expected"]),
            actual=json.loads(row["actual"]),
            drifted_fields=json.loads(row["drifted_fields"]),
            severity=DriftSeverity(row["severity"]),
            detected_at=datetime.fromisoformat(row["detected_at"]),
            resolved_at=datetime.fromisoformat(row["resolved_at"]) if row["resolved_at"] else None,
            org_id=row["org_id"],
        )

    # ------------------------------------------------------------------
    # Baseline rule management
    # ------------------------------------------------------------------

    def add_baseline_rule(self, rule: BaselineRule) -> BaselineRule:
        """Persist a baseline rule and return it."""
        conn = self._get_conn()
        try:
            conn.execute(
                """
                INSERT OR REPLACE INTO baseline_rules
                    (id, name, description, provider, resource_type,
                     expected_config, severity, cis_benchmark, remediation)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    rule.id,
                    rule.name,
                    rule.description,
                    rule.provider.value,
                    rule.resource_type,
                    json.dumps(rule.expected_config),
                    rule.severity.value,
                    rule.cis_benchmark,
                    rule.remediation,
                ),
            )
            conn.commit()
        finally:
            conn.close()
        return rule

    def list_baseline_rules(
        self,
        provider: Optional[CloudProvider] = None,
        resource_type: Optional[str] = None,
    ) -> List[BaselineRule]:
        """List baseline rules with optional filters."""
        conn = self._get_conn()
        try:
            query = "SELECT * FROM baseline_rules WHERE 1=1"
            params: List[Any] = []
            if provider:
                query += " AND provider = ?"
                params.append(provider.value)
            if resource_type:
                query += " AND resource_type = ?"
                params.append(resource_type)
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_rule(r) for r in rows]
        finally:
            conn.close()

    def delete_baseline_rule(self, rule_id: str) -> None:
        """Remove a baseline rule by ID."""
        conn = self._get_conn()
        try:
            conn.execute("DELETE FROM baseline_rules WHERE id = ?", (rule_id,))
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Config comparison
    # ------------------------------------------------------------------

    def _compare_configs(
        self,
        expected: Dict[str, Any],
        actual: Dict[str, Any],
        prefix: str = "",
    ) -> List[str]:
        """Deep-compare two config dicts and return drifted field paths."""
        drifted: List[str] = []
        for key, exp_val in expected.items():
            path = f"{prefix}{key}" if not prefix else f"{prefix}.{key}"
            if key not in actual:
                drifted.append(path)
            elif isinstance(exp_val, dict) and isinstance(actual[key], dict):
                drifted.extend(self._compare_configs(exp_val, actual[key], prefix=path))
            elif actual[key] != exp_val:
                drifted.append(path)
        return drifted

    # ------------------------------------------------------------------
    # Resource checking
    # ------------------------------------------------------------------

    def check_resource(
        self,
        resource_id: str,
        resource_type: str,
        actual_config: Dict[str, Any],
        provider: CloudProvider,
        org_id: str,
    ) -> List[DriftResult]:
        """Check a single resource against all matching baselines."""
        rules = self.list_baseline_rules(provider=provider, resource_type=resource_type)
        results: List[DriftResult] = []
        conn = self._get_conn()
        try:
            for rule in rules:
                drifted_fields = self._compare_configs(rule.expected_config, actual_config)
                if not drifted_fields:
                    continue
                drift = DriftResult(
                    rule_id=rule.id,
                    resource_id=resource_id,
                    provider=provider,
                    resource_type=resource_type,
                    expected=rule.expected_config,
                    actual=actual_config,
                    drifted_fields=drifted_fields,
                    severity=rule.severity,
                    org_id=org_id,
                )
                conn.execute(
                    """
                    INSERT INTO drift_results
                        (id, rule_id, resource_id, provider, resource_type,
                         expected, actual, drifted_fields, severity,
                         detected_at, resolved_at, org_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        drift.id,
                        drift.rule_id,
                        drift.resource_id,
                        drift.provider.value,
                        drift.resource_type,
                        json.dumps(drift.expected),
                        json.dumps(drift.actual),
                        json.dumps(drift.drifted_fields),
                        drift.severity.value,
                        drift.detected_at.isoformat(),
                        drift.resolved_at.isoformat() if drift.resolved_at else None,
                        drift.org_id,
                    ),
                )
                results.append(drift)
            conn.commit()
        finally:
            conn.close()
        return results

    def check_batch(
        self,
        resources: List[Dict[str, Any]],
        org_id: str,
    ) -> List[DriftResult]:
        """Batch-check multiple resources.

        Each resource dict must contain:
            resource_id, resource_type, actual_config, provider
        """
        all_results: List[DriftResult] = []
        for res in resources:
            results = self.check_resource(
                resource_id=res["resource_id"],
                resource_type=res["resource_type"],
                actual_config=res["actual_config"],
                provider=CloudProvider(res["provider"]),
                org_id=org_id,
            )
            all_results.extend(results)
        return all_results

    # ------------------------------------------------------------------
    # Drift queries
    # ------------------------------------------------------------------

    def get_drift_history(
        self,
        org_id: str,
        resource_id: Optional[str] = None,
        days: int = 30,
    ) -> List[DriftResult]:
        """Return drift results for an org within the last N days."""
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        conn = self._get_conn()
        try:
            query = "SELECT * FROM drift_results WHERE org_id = ? AND detected_at >= ?"
            params: List[Any] = [org_id, since]
            if resource_id:
                query += " AND resource_id = ?"
                params.append(resource_id)
            query += " ORDER BY detected_at DESC"
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_drift(r) for r in rows]
        finally:
            conn.close()

    def get_active_drifts(
        self,
        org_id: str,
        severity_filter: Optional[DriftSeverity] = None,
    ) -> List[DriftResult]:
        """Return unresolved drift results for an org."""
        conn = self._get_conn()
        try:
            query = "SELECT * FROM drift_results WHERE org_id = ? AND resolved_at IS NULL"
            params: List[Any] = [org_id]
            if severity_filter:
                query += " AND severity = ?"
                params.append(severity_filter.value)
            query += " ORDER BY detected_at DESC"
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_drift(r) for r in rows]
        finally:
            conn.close()

    def resolve_drift(self, drift_id: str) -> None:
        """Mark a drift result as resolved."""
        conn = self._get_conn()
        try:
            conn.execute(
                "UPDATE drift_results SET resolved_at = ? WHERE id = ?",
                (datetime.now(timezone.utc).isoformat(), drift_id),
            )
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Summary and trend
    # ------------------------------------------------------------------

    def get_drift_summary(self, org_id: str) -> DriftSummary:
        """Compute drift summary for an org."""
        conn = self._get_conn()
        try:
            active_rows = conn.execute(
                "SELECT * FROM drift_results WHERE org_id = ? AND resolved_at IS NULL",
                (org_id,),
            ).fetchall()

            # Count unique resources checked (all drifts, resolved or not)
            all_resource_rows = conn.execute(
                "SELECT DISTINCT resource_id FROM drift_results WHERE org_id = ?",
                (org_id,),
            ).fetchall()
            drifted_resource_ids = {r["resource_id"] for r in active_rows}
            total_resources = len(all_resource_rows)
            drifted = len(drifted_resource_ids)
            compliant = max(0, total_resources - drifted)
            compliance_rate = (compliant / total_resources * 100) if total_resources > 0 else 100.0

            by_severity: Dict[str, int] = {s.value: 0 for s in DriftSeverity}
            by_provider: Dict[str, int] = {p.value: 0 for p in CloudProvider}
            for row in active_rows:
                by_severity[row["severity"]] = by_severity.get(row["severity"], 0) + 1
                by_provider[row["provider"]] = by_provider.get(row["provider"], 0) + 1

            # Top 5 most-drifted resources
            resource_counts: Dict[str, int] = {}
            for row in active_rows:
                resource_counts[row["resource_id"]] = resource_counts.get(row["resource_id"], 0) + 1
            top_drifts = [
                {"resource_id": rid, "drift_count": cnt}
                for rid, cnt in sorted(resource_counts.items(), key=lambda x: -x[1])[:5]
            ]

            return DriftSummary(
                total_resources=total_resources,
                compliant=compliant,
                drifted=drifted,
                compliance_rate=round(compliance_rate, 2),
                by_severity=by_severity,
                by_provider=by_provider,
                top_drifts=top_drifts,
            )
        finally:
            conn.close()

    def get_drift_trend(self, org_id: str, days: int = 30) -> List[Dict[str, Any]]:
        """Return daily drift counts over the last N days."""
        conn = self._get_conn()
        try:
            since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
            rows = conn.execute(
                """
                SELECT substr(detected_at, 1, 10) AS day, COUNT(*) AS count
                FROM drift_results
                WHERE org_id = ? AND detected_at >= ?
                GROUP BY day
                ORDER BY day ASC
                """,
                (org_id, since),
            ).fetchall()
            return [{"date": r["day"], "count": r["count"]} for r in rows]
        finally:
            conn.close()

    def get_remediation(self, drift_id: str) -> str:
        """Return remediation steps for a drift result."""
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT rule_id FROM drift_results WHERE id = ?", (drift_id,)
            ).fetchone()
            if not row:
                return "Drift not found."
            rule_row = conn.execute(
                "SELECT remediation FROM baseline_rules WHERE id = ?", (row["rule_id"],)
            ).fetchone()
            if not rule_row:
                return "Baseline rule not found."
            return rule_row["remediation"]
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Default CIS baselines
    # ------------------------------------------------------------------

    def get_default_baselines(self) -> List[BaselineRule]:
        """Return built-in CIS baseline rules for AWS, Azure, and GCP."""
        return [
            # ── AWS ──────────────────────────────────────────────────────────
            BaselineRule(
                id="aws-s3-public-access",
                name="AWS S3 Block Public Access",
                description="S3 bucket must block all public access.",
                provider=CloudProvider.AWS,
                resource_type="s3_bucket",
                expected_config={
                    "block_public_acls": True,
                    "block_public_policy": True,
                    "ignore_public_acls": True,
                    "restrict_public_buckets": True,
                },
                severity=DriftSeverity.CRITICAL,
                cis_benchmark="CIS AWS 2.1.5",
                remediation=(
                    "Enable S3 Block Public Access settings at the bucket and account level. "
                    "Run: aws s3api put-public-access-block --bucket <name> "
                    "--public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,"
                    "BlockPublicPolicy=true,RestrictPublicBuckets=true"
                ),
            ),
            BaselineRule(
                id="aws-s3-encryption",
                name="AWS S3 Encryption at Rest",
                description="S3 bucket must have server-side encryption enabled.",
                provider=CloudProvider.AWS,
                resource_type="s3_bucket",
                expected_config={"encryption_enabled": True},
                severity=DriftSeverity.HIGH,
                cis_benchmark="CIS AWS 2.1.1",
                remediation=(
                    "Enable default encryption on the S3 bucket using AES-256 or AWS-KMS. "
                    "Run: aws s3api put-bucket-encryption --bucket <name> ..."
                ),
            ),
            BaselineRule(
                id="aws-sg-no-unrestricted-ssh",
                name="AWS Security Group No Unrestricted SSH",
                description="Security groups must not allow unrestricted SSH (port 22) from 0.0.0.0/0.",
                provider=CloudProvider.AWS,
                resource_type="security_group",
                expected_config={"allow_ssh_from_any": False},
                severity=DriftSeverity.CRITICAL,
                cis_benchmark="CIS AWS 5.2",
                remediation=(
                    "Remove inbound rules allowing SSH from 0.0.0.0/0 or ::/0. "
                    "Restrict to specific IP ranges or use AWS SSM Session Manager."
                ),
            ),
            BaselineRule(
                id="aws-iam-mfa-enabled",
                name="AWS IAM MFA for Console Users",
                description="All IAM users with console access must have MFA enabled.",
                provider=CloudProvider.AWS,
                resource_type="iam_user",
                expected_config={"mfa_enabled": True},
                severity=DriftSeverity.HIGH,
                cis_benchmark="CIS AWS 1.10",
                remediation=(
                    "Enable MFA for the IAM user via AWS Console or CLI. "
                    "Run: aws iam enable-mfa-device --user-name <user> ..."
                ),
            ),
            BaselineRule(
                id="aws-cloudtrail-enabled",
                name="AWS CloudTrail Enabled",
                description="CloudTrail must be enabled and logging to an S3 bucket.",
                provider=CloudProvider.AWS,
                resource_type="cloudtrail",
                expected_config={"is_logging": True, "multi_region_trail": True},
                severity=DriftSeverity.HIGH,
                cis_benchmark="CIS AWS 3.1",
                remediation=(
                    "Enable CloudTrail and configure it to log to an S3 bucket. "
                    "Run: aws cloudtrail create-trail --name <name> --s3-bucket-name <bucket> ..."
                ),
            ),
            # ── Azure ─────────────────────────────────────────────────────────
            BaselineRule(
                id="azure-storage-encryption",
                name="Azure Storage Encryption at Rest",
                description="Azure Storage accounts must have encryption at rest enabled.",
                provider=CloudProvider.AZURE,
                resource_type="storage_account",
                expected_config={"encryption_enabled": True, "require_infrastructure_encryption": True},
                severity=DriftSeverity.HIGH,
                cis_benchmark="CIS Azure 3.2",
                remediation=(
                    "Enable encryption at rest for the Azure Storage account. "
                    "Navigate to Storage account > Encryption in the Azure Portal."
                ),
            ),
            BaselineRule(
                id="azure-nsg-no-unrestricted-rdp",
                name="Azure NSG No Unrestricted RDP",
                description="Network Security Groups must not allow RDP (port 3389) from any source.",
                provider=CloudProvider.AZURE,
                resource_type="network_security_group",
                expected_config={"allow_rdp_from_any": False},
                severity=DriftSeverity.CRITICAL,
                cis_benchmark="CIS Azure 6.2",
                remediation=(
                    "Remove NSG inbound rules allowing RDP (port 3389) from 0.0.0.0/0. "
                    "Use Azure Bastion or restrict to specific IP ranges."
                ),
            ),
            BaselineRule(
                id="azure-key-vault-soft-delete",
                name="Azure Key Vault Soft Delete",
                description="Azure Key Vault must have soft delete and purge protection enabled.",
                provider=CloudProvider.AZURE,
                resource_type="key_vault",
                expected_config={"soft_delete_enabled": True, "purge_protection_enabled": True},
                severity=DriftSeverity.MEDIUM,
                cis_benchmark="CIS Azure 8.5",
                remediation=(
                    "Enable soft delete and purge protection on the Key Vault. "
                    "Run: az keyvault update --name <vault> --enable-soft-delete true "
                    "--enable-purge-protection true"
                ),
            ),
            BaselineRule(
                id="azure-diagnostic-settings",
                name="Azure Diagnostic Settings Enabled",
                description="Azure resources must have diagnostic settings configured.",
                provider=CloudProvider.AZURE,
                resource_type="azure_resource",
                expected_config={"diagnostic_settings_enabled": True},
                severity=DriftSeverity.MEDIUM,
                cis_benchmark="CIS Azure 5.1",
                remediation=(
                    "Enable diagnostic settings for the Azure resource and route logs to "
                    "a Log Analytics workspace or Storage account."
                ),
            ),
            # ── GCP ───────────────────────────────────────────────────────────
            BaselineRule(
                id="gcp-bucket-no-public-acl",
                name="GCP Cloud Storage No Public ACL",
                description="GCP Cloud Storage buckets must not have allUsers or allAuthenticatedUsers ACL.",
                provider=CloudProvider.GCP,
                resource_type="gcs_bucket",
                expected_config={"public_access": False},
                severity=DriftSeverity.CRITICAL,
                cis_benchmark="CIS GCP 5.1",
                remediation=(
                    "Remove public ACL entries from the GCS bucket. "
                    "Run: gsutil iam ch -d allUsers gs://<bucket>"
                ),
            ),
            BaselineRule(
                id="gcp-firewall-no-unrestricted-ssh",
                name="GCP Firewall No Unrestricted SSH",
                description="GCP firewall rules must not allow SSH (port 22) from 0.0.0.0/0.",
                provider=CloudProvider.GCP,
                resource_type="firewall_rule",
                expected_config={"allow_ssh_from_any": False},
                severity=DriftSeverity.CRITICAL,
                cis_benchmark="CIS GCP 3.6",
                remediation=(
                    "Delete or restrict the firewall rule allowing SSH from 0.0.0.0/0. "
                    "Run: gcloud compute firewall-rules update <rule> --source-ranges=<ip_range>"
                ),
            ),
            BaselineRule(
                id="gcp-audit-logging-enabled",
                name="GCP Audit Logging Enabled",
                description="GCP project must have audit logging enabled for all services.",
                provider=CloudProvider.GCP,
                resource_type="gcp_project",
                expected_config={"audit_logging_enabled": True, "data_access_logs_enabled": True},
                severity=DriftSeverity.HIGH,
                cis_benchmark="CIS GCP 2.1",
                remediation=(
                    "Enable audit logging in the GCP project IAM policy. "
                    "Run: gcloud projects get-iam-policy <project> ..."
                ),
            ),
            BaselineRule(
                id="gcp-kms-key-rotation",
                name="GCP KMS Key Rotation",
                description="GCP KMS encryption keys must have automatic rotation enabled (max 90 days).",
                provider=CloudProvider.GCP,
                resource_type="kms_key",
                expected_config={"rotation_enabled": True, "rotation_period_days_max": 90},
                severity=DriftSeverity.MEDIUM,
                cis_benchmark="CIS GCP 1.10",
                remediation=(
                    "Enable automatic key rotation on the KMS key ring. "
                    "Run: gcloud kms keys update <key> --rotation-period=90d ..."
                ),
            ),
        ]
