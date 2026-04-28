"""
CloudNativeSecurityEngine — ALDECI.

Cloud service misconfiguration detection across AWS/Azure/GCP services.
Tracks cloud accounts, misconfigurations, and runs posture checks.

Multi-tenant via org_id.  Thread-safe via RLock.  SQLite WAL for concurrency.
"""
from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "cloud_native.db"
)

_VALID_PROVIDERS = {"aws", "azure", "gcp"}
_VALID_ENVIRONMENTS = {"prod", "staging", "dev"}
_VALID_SERVICES = {"s3", "ec2", "iam", "rds", "lambda", "aks", "cosmos", "pubsub"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}

# Posture check catalogue: (check_name, service, severity, description, remediation)
_POSTURE_CHECKS = [
    ("S3 Public Access Block Disabled", "s3", "critical",
     "S3 bucket has public access block disabled", "Enable S3 Block Public Access at account level"),
    ("S3 Bucket Logging Disabled", "s3", "medium",
     "S3 bucket access logging is not enabled", "Enable server access logging on all S3 buckets"),
    ("EC2 IMDSv1 Enabled", "ec2", "high",
     "Instance metadata service v1 is enabled", "Require IMDSv2 for all EC2 instances"),
    ("EC2 Security Group Unrestricted SSH", "ec2", "critical",
     "Security group allows SSH from 0.0.0.0/0", "Restrict SSH access to known IP ranges"),
    ("IAM Root Account MFA Disabled", "iam", "critical",
     "Root account does not have MFA enabled", "Enable MFA for root account immediately"),
    ("IAM Password Policy Weak", "iam", "high",
     "Account password policy does not meet minimum requirements", "Enforce strong password policy"),
    ("IAM Access Keys Unrotated", "iam", "medium",
     "IAM access keys older than 90 days found", "Rotate IAM access keys every 90 days"),
    ("RDS Encryption Disabled", "rds", "critical",
     "RDS instance does not have encryption at rest", "Enable encryption for all RDS instances"),
    ("RDS Public Access Enabled", "rds", "high",
     "RDS instance is publicly accessible", "Disable public accessibility for RDS instances"),
    ("Lambda Function Excessive Permissions", "lambda", "high",
     "Lambda function has overly broad IAM permissions", "Apply principle of least privilege to Lambda roles"),
    ("AKS RBAC Disabled", "aks", "high",
     "Azure Kubernetes Service cluster has RBAC disabled", "Enable RBAC for AKS clusters"),
    ("Cosmos DB Firewall Disabled", "cosmos", "high",
     "Cosmos DB account has no firewall rules", "Configure Cosmos DB firewall to restrict access"),
    ("PubSub Topic Unencrypted", "pubsub", "medium",
     "GCP PubSub topic does not use CMEK", "Enable customer-managed encryption for PubSub topics"),
]

_SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class CloudNativeSecurityEngine:
    """SQLite WAL-backed cloud native security engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    Tables: cloud_accounts, cloud_misconfigurations.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cloud_accounts (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    provider TEXT NOT NULL DEFAULT 'aws',
                    account_id TEXT NOT NULL DEFAULT '',
                    account_name TEXT NOT NULL DEFAULT '',
                    region TEXT NOT NULL DEFAULT 'us-east-1',
                    environment TEXT NOT NULL DEFAULT 'prod',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cloud_misconfigurations (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    account_id TEXT NOT NULL,
                    provider TEXT NOT NULL DEFAULT 'aws',
                    service TEXT NOT NULL,
                    check_name TEXT NOT NULL,
                    severity TEXT NOT NULL DEFAULT 'medium',
                    resource_id TEXT NOT NULL DEFAULT '',
                    resource_name TEXT NOT NULL DEFAULT '',
                    description TEXT NOT NULL DEFAULT '',
                    remediation TEXT NOT NULL DEFAULT '',
                    compliant INTEGER NOT NULL DEFAULT 0,
                    fixed_by TEXT,
                    created_at TEXT NOT NULL,
                    fixed_at TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cloud_accts_org ON cloud_accounts(org_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cloud_misc_org ON cloud_misconfigurations(org_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cloud_misc_acct ON cloud_misconfigurations(account_id)")
            conn.commit()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Accounts
    # ------------------------------------------------------------------

    def register_cloud_account(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a cloud account for an org."""
        acct_uuid = str(uuid.uuid4())
        provider = data.get("provider", "aws")
        if provider not in _VALID_PROVIDERS:
            provider = "aws"
        environment = data.get("environment", "prod")
        if environment not in _VALID_ENVIRONMENTS:
            environment = "prod"
        row = {
            "id": acct_uuid,
            "org_id": org_id,
            "provider": provider,
            "account_id": data.get("account_id", ""),
            "account_name": data.get("account_name", ""),
            "region": data.get("region", "us-east-1"),
            "environment": environment,
            "created_at": _now(),
            "updated_at": _now(),
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO cloud_accounts
                       (id, org_id, provider, account_id, account_name, region, environment, created_at, updated_at)
                       VALUES (:id, :org_id, :provider, :account_id, :account_name, :region, :environment, :created_at, :updated_at)""",
                    row,
                )
                conn.commit()
        _logger.info("Registered cloud account %s (%s) for org %s", acct_uuid, provider, org_id)
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ASSET_DISCOVERED", {"entity_type": "cloud_native_security", "org_id": org_id, "source_engine": "cloud_native_security"})
            except Exception:
                pass

        return dict(row)

    def list_accounts(self, org_id: str, provider: Optional[str] = None) -> List[Dict[str, Any]]:
        """List cloud accounts for an org, optionally filtered by provider."""
        query = "SELECT * FROM cloud_accounts WHERE org_id = ?"
        params: List[Any] = [org_id]
        if provider:
            query += " AND provider = ?"
            params.append(provider)
        query += " ORDER BY created_at DESC"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Misconfigurations
    # ------------------------------------------------------------------

    def record_misconfiguration(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a cloud misconfiguration finding."""
        finding_id = str(uuid.uuid4())

        # Resolve provider from account if not provided
        account_id = data.get("account_id", "")
        provider = data.get("provider", "aws")

        service = data.get("service", "s3")
        if service not in _VALID_SERVICES:
            service = "s3"
        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            severity = "medium"
        compliant = bool(data.get("compliant", False))
        row = {
            "id": finding_id,
            "org_id": org_id,
            "account_id": account_id,
            "provider": provider,
            "service": service,
            "check_name": data.get("check_name", ""),
            "severity": severity,
            "resource_id": data.get("resource_id", ""),
            "resource_name": data.get("resource_name", ""),
            "description": data.get("description", ""),
            "remediation": data.get("remediation", ""),
            "compliant": int(compliant),
            "fixed_by": None,
            "created_at": _now(),
            "fixed_at": None,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO cloud_misconfigurations
                       (id, org_id, account_id, provider, service, check_name, severity,
                        resource_id, resource_name, description, remediation,
                        compliant, fixed_by, created_at, fixed_at)
                       VALUES (:id, :org_id, :account_id, :provider, :service, :check_name, :severity,
                               :resource_id, :resource_name, :description, :remediation,
                               :compliant, :fixed_by, :created_at, :fixed_at)""",
                    row,
                )
                conn.commit()
        result = dict(row)
        result["compliant"] = bool(result["compliant"])
        _logger.info("Recorded cloud misconfiguration %s (service=%s, sev=%s)", finding_id, service, severity)
        return result

    def list_misconfigurations(
        self,
        org_id: str,
        provider: Optional[str] = None,
        service: Optional[str] = None,
        severity: Optional[str] = None,
        compliant: bool = False,
    ) -> List[Dict[str, Any]]:
        """List misconfigurations with optional filters.

        By default returns non-compliant findings only (compliant=False).
        Pass compliant=True to include all findings regardless of compliance state.
        """
        query = "SELECT * FROM cloud_misconfigurations WHERE org_id = ?"
        params: List[Any] = [org_id]
        if not compliant:
            query += " AND compliant = 0"
        if provider:
            query += " AND provider = ?"
            params.append(provider)
        if service:
            query += " AND service = ?"
            params.append(service)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        query += " ORDER BY created_at DESC"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        results = []
        for r in rows:
            d = dict(r)
            d["compliant"] = bool(d["compliant"])
            results.append(d)
        return results

    def mark_compliant(self, org_id: str, finding_id: str, fixed_by: str) -> Dict[str, Any]:
        """Mark a misconfiguration as compliant (remediated)."""
        now = _now()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM cloud_misconfigurations WHERE id = ? AND org_id = ?",
                    (finding_id, org_id),
                ).fetchone()
                if not row:
                    raise ValueError(f"Misconfiguration {finding_id} not found for org {org_id}")
                conn.execute(
                    """UPDATE cloud_misconfigurations
                       SET compliant = 1, fixed_by = ?, fixed_at = ?
                       WHERE id = ? AND org_id = ?""",
                    (fixed_by, now, finding_id, org_id),
                )
                conn.commit()
                updated = conn.execute(
                    "SELECT * FROM cloud_misconfigurations WHERE id = ?", (finding_id,)
                ).fetchone()
        result = dict(updated)
        result["compliant"] = bool(result["compliant"])
        return result

    # ------------------------------------------------------------------
    # Posture Check
    # ------------------------------------------------------------------

    def run_posture_check(self, org_id: str, account_id: str) -> Dict[str, Any]:
        """Run a posture check against a registered cloud account.

        Simulates running all applicable checks for the account's provider,
        influenced by existing recorded misconfigurations.
        """
        with self._lock:
            with self._conn() as conn:
                account = conn.execute(
                    "SELECT * FROM cloud_accounts WHERE id = ? AND org_id = ?",
                    (account_id, org_id),
                ).fetchone()
                if not account:
                    raise ValueError(f"Account {account_id} not found for org {org_id}")
                # Count open (non-compliant) findings for this account
                open_findings = conn.execute(
                    "SELECT check_name, severity FROM cloud_misconfigurations "
                    "WHERE account_id = ? AND org_id = ? AND compliant = 0",
                    (account_id, org_id),
                ).fetchall()

        provider = account["provider"]
        open_check_names = {r["check_name"] for r in open_findings}

        # Run all checks — treat recorded non-compliant ones as failed
        passed = 0
        failed = 0
        top_risks = []

        for check_name, service, severity, description, remediation in _POSTURE_CHECKS:
            if check_name in open_check_names:
                failed += 1
                top_risks.append({
                    "check_name": check_name,
                    "service": service,
                    "severity": severity,
                    "description": description,
                })
            else:
                passed += 1

        total = passed + failed
        score_pct = round((passed / total * 100) if total > 0 else 100.0, 1)

        # Sort top_risks by severity weight descending
        top_risks.sort(key=lambda x: _SEVERITY_WEIGHT.get(x["severity"], 0), reverse=True)

        return {
            "account_id": account_id,
            "provider": provider,
            "total_checks": total,
            "passed": passed,
            "failed": failed,
            "score_pct": score_pct,
            "top_risks": top_risks[:5],
            "run_at": _now(),
        }

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_cloud_stats(self, org_id: str) -> Dict[str, Any]:
        """Aggregate stats across all cloud accounts for an org."""
        with self._lock:
            with self._conn() as conn:
                total_accounts = conn.execute(
                    "SELECT COUNT(*) as cnt FROM cloud_accounts WHERE org_id = ?", (org_id,)
                ).fetchone()["cnt"]
                by_provider_rows = conn.execute(
                    "SELECT provider, COUNT(*) as cnt FROM cloud_accounts WHERE org_id = ? GROUP BY provider",
                    (org_id,),
                ).fetchall()
                total_checks = conn.execute(
                    "SELECT COUNT(*) as cnt FROM cloud_misconfigurations WHERE org_id = ?", (org_id,)
                ).fetchone()["cnt"]
                passed_count = conn.execute(
                    "SELECT COUNT(*) as cnt FROM cloud_misconfigurations WHERE org_id = ? AND compliant = 1",
                    (org_id,),
                ).fetchone()["cnt"]
                failed_count = conn.execute(
                    "SELECT COUNT(*) as cnt FROM cloud_misconfigurations WHERE org_id = ? AND compliant = 0",
                    (org_id,),
                ).fetchone()["cnt"]
                critical_findings = conn.execute(
                    "SELECT COUNT(*) as cnt FROM cloud_misconfigurations "
                    "WHERE org_id = ? AND severity = 'critical' AND compliant = 0",
                    (org_id,),
                ).fetchone()["cnt"]

        by_provider = {r["provider"]: r["cnt"] for r in by_provider_rows}
        compliance_pct = round((passed_count / total_checks * 100) if total_checks > 0 else 100.0, 1)

        return {
            "org_id": org_id,
            "total_accounts": total_accounts,
            "by_provider": by_provider,
            "total_checks": total_checks,
            "passed_count": passed_count,
            "failed_count": failed_count,
            "compliance_pct": compliance_pct,
            "critical_findings": critical_findings,
        }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_engine: Optional[CloudNativeSecurityEngine] = None
_engine_lock = threading.Lock()


def get_engine() -> CloudNativeSecurityEngine:
    global _engine
    with _engine_lock:
        if _engine is None:
            _engine = CloudNativeSecurityEngine()
    return _engine
