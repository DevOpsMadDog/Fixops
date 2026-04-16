"""IAM Policy Analyzer Engine — ALDECI.

Analyzes cloud IAM policies for least-privilege violations and toxic combinations.
Supports AWS IAM, Azure RBAC, and GCP IAM policy types.

Compliance: NIST SP 800-53 AC-2/AC-6, CIS Benchmark IAM controls, SOC 2 CC6.3
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "iam_policy_analyzer.db"
)

_VALID_POLICY_TYPES = {"aws_iam", "azure_rbac", "gcp_iam"}
_VALID_PRINCIPAL_TYPES = {"user", "group", "service_account", "role"}
_VALID_REVIEW_OUTCOMES = {"approved", "revoked", "modified"}

# Permissions that indicate admin / overly broad access
_ADMIN_PATTERNS = {
    "*", "iam:*", "s3:*", "ec2:*", "rds:*", "lambda:*",
    "sts:*", "cloudformation:*", "organizations:*",
    "Microsoft.Authorization/*", "*/write", "*/delete",
    "resourcemanager.projects.setIamPolicy",
}

# Combinations that represent toxic pairs
_TOXIC_COMBINATIONS = [
    ({"iam:CreateUser", "iam:AttachUserPolicy"}, "Privilege escalation via user creation"),
    ({"iam:CreateRole", "iam:AttachRolePolicy"}, "Privilege escalation via role creation"),
    ({"iam:PutUserPolicy", "iam:CreateAccessKey"}, "Credential theft via inline policy"),
    ({"s3:GetObject", "s3:PutBucketPolicy"}, "Data exfiltration via bucket policy manipulation"),
    ({"ec2:RunInstances", "iam:PassRole"}, "Privilege escalation via EC2 instance launch"),
]

_DATA_EXFIL_PERMISSIONS = {
    "s3:GetObject", "s3:ListBucket", "rds:DescribeDBSnapshots",
    "ec2:CreateSnapshot", "dynamodb:Scan", "dynamodb:Query",
    "secretsmanager:GetSecretValue", "ssm:GetParameter",
}


class IAMPolicyAnalyzerEngine:
    """SQLite WAL-backed IAM Policy Analyzer engine.

    Thread-safe via RLock. Multi-tenant via org_id.
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
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS iam_policies (
                    policy_id        TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    policy_name      TEXT NOT NULL DEFAULT '',
                    policy_type      TEXT NOT NULL DEFAULT 'aws_iam',
                    principal_type   TEXT NOT NULL DEFAULT 'user',
                    principal_id     TEXT NOT NULL DEFAULT '',
                    permissions      TEXT NOT NULL DEFAULT '[]',
                    resources        TEXT NOT NULL DEFAULT '[]',
                    conditions       TEXT NOT NULL DEFAULT '{}',
                    is_managed       INTEGER NOT NULL DEFAULT 1,
                    created_at       TEXT NOT NULL,
                    updated_at       TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_iam_pol_org
                    ON iam_policies (org_id, policy_type);

                CREATE TABLE IF NOT EXISTS policy_findings (
                    finding_id           TEXT PRIMARY KEY,
                    org_id               TEXT NOT NULL,
                    policy_id            TEXT NOT NULL,
                    finding_type         TEXT NOT NULL,
                    severity             TEXT NOT NULL DEFAULT 'medium',
                    description          TEXT NOT NULL DEFAULT '',
                    affected_permissions TEXT NOT NULL DEFAULT '[]',
                    recommendation       TEXT NOT NULL DEFAULT '',
                    risk_score           REAL NOT NULL DEFAULT 0,
                    created_at           TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_findings_pol
                    ON policy_findings (org_id, policy_id);

                CREATE TABLE IF NOT EXISTS access_reviews (
                    review_id      TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    policy_id      TEXT NOT NULL,
                    reviewer       TEXT NOT NULL DEFAULT '',
                    outcome        TEXT NOT NULL DEFAULT 'approved',
                    action_taken   TEXT NOT NULL DEFAULT '',
                    review_date    TEXT NOT NULL,
                    created_at     TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_reviews_org
                    ON access_reviews (org_id, policy_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # Policy CRUD
    # ------------------------------------------------------------------

    def add_policy(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add an IAM policy for analysis."""
        policy_id = str(uuid.uuid4())
        now = self._now()
        policy_type = data.get("policy_type", "aws_iam")
        if policy_type not in _VALID_POLICY_TYPES:
            policy_type = "aws_iam"
        principal_type = data.get("principal_type", "user")
        if principal_type not in _VALID_PRINCIPAL_TYPES:
            principal_type = "user"

        row = {
            "policy_id": policy_id,
            "org_id": org_id,
            "policy_name": data.get("policy_name", ""),
            "policy_type": policy_type,
            "principal_type": principal_type,
            "principal_id": data.get("principal_id", ""),
            "permissions": json.dumps(data.get("permissions", [])),
            "resources": json.dumps(data.get("resources", [])),
            "conditions": json.dumps(data.get("conditions", {})),
            "is_managed": 1 if data.get("is_managed", True) else 0,
            "created_at": now,
            "updated_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO iam_policies VALUES
                       (:policy_id,:org_id,:policy_name,:policy_type,:principal_type,
                        :principal_id,:permissions,:resources,:conditions,:is_managed,
                        :created_at,:updated_at)""",
                    row,
                )
        return {**row, "permissions": data.get("permissions", []),
                "resources": data.get("resources", []),
                "conditions": data.get("conditions", {}),
                "is_managed": data.get("is_managed", True)}

    def list_policies(
        self,
        org_id: str,
        policy_type: Optional[str] = None,
        principal_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List policies with optional filters."""
        clauses = ["org_id = ?"]
        params: List[Any] = [org_id]
        if policy_type:
            clauses.append("policy_type = ?")
            params.append(policy_type)
        if principal_type:
            clauses.append("principal_type = ?")
            params.append(principal_type)
        sql = f"SELECT * FROM iam_policies WHERE {' AND '.join(clauses)} ORDER BY created_at DESC"  # nosec B608
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(sql, params).fetchall()
        return [self._deserialize_policy(dict(r)) for r in rows]

    def _deserialize_policy(self, row: Dict[str, Any]) -> Dict[str, Any]:
        row["permissions"] = json.loads(row.get("permissions", "[]"))
        row["resources"] = json.loads(row.get("resources", "[]"))
        row["conditions"] = json.loads(row.get("conditions", "{}"))
        row["is_managed"] = bool(row.get("is_managed", 1))
        return row

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    def analyze_policy(self, org_id: str, policy_id: str) -> Dict[str, Any]:
        """Analyze a single policy for violations and risk."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM iam_policies WHERE policy_id = ? AND org_id = ?",
                    (policy_id, org_id),
                ).fetchone()
        if not row:
            return {"policy_id": policy_id, "findings": [], "risk_score": 0}

        policy = self._deserialize_policy(dict(row))
        permissions: List[str] = policy.get("permissions", [])
        perms_set = set(permissions)
        findings: List[Dict[str, Any]] = []

        # --- wildcard_action ---
        wildcards = [p for p in permissions if "*" in p]
        if wildcards:
            findings.append({
                "finding_type": "wildcard_action",
                "severity": "critical",
                "description": f"Policy grants wildcard permissions: {wildcards}",
                "affected_permissions": wildcards,
                "recommendation": "Replace wildcards with specific actions following least-privilege principle.",
            })

        # --- admin_access ---
        admin_perms = [p for p in permissions if p in _ADMIN_PATTERNS]
        if admin_perms:
            findings.append({
                "finding_type": "admin_access",
                "severity": "high",
                "description": f"Policy grants administrative permissions: {admin_perms}",
                "affected_permissions": admin_perms,
                "recommendation": "Restrict administrative access to break-glass accounts with MFA conditions.",
            })

        # --- cross_account ---
        resources: List[str] = policy.get("resources", [])
        cross_account = [r for r in resources if "arn:aws" in r and "::" not in r and r.count(":") >= 5]
        if cross_account:
            findings.append({
                "finding_type": "cross_account",
                "severity": "medium",
                "description": "Policy grants access to cross-account resources.",
                "affected_permissions": permissions,
                "recommendation": "Verify cross-account trust relationships and add external ID conditions.",
            })

        # --- data_exfil_risk ---
        exfil_perms = [p for p in permissions if p in _DATA_EXFIL_PERMISSIONS]
        if len(exfil_perms) >= 2:
            findings.append({
                "finding_type": "data_exfil_risk",
                "severity": "high",
                "description": f"Policy combines data read permissions that may enable exfiltration: {exfil_perms}",
                "affected_permissions": exfil_perms,
                "recommendation": "Add resource-level constraints and enable CloudTrail data events for monitoring.",
            })

        # --- toxic_combination ---
        for toxic_pair, description in _TOXIC_COMBINATIONS:
            if toxic_pair.issubset(perms_set):
                matched = list(toxic_pair)
                findings.append({
                    "finding_type": "toxic_combination",
                    "severity": "critical",
                    "description": description,
                    "affected_permissions": matched,
                    "recommendation": "Separate these permissions into distinct roles with different trust boundaries.",
                })

        # Compute risk score
        severity_weights = {"critical": 30, "high": 20, "medium": 10, "low": 5}
        raw_score = sum(severity_weights.get(f["severity"], 5) for f in findings)
        risk_score = min(100.0, raw_score)

        # Persist findings
        now = self._now()
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    "DELETE FROM policy_findings WHERE policy_id = ? AND org_id = ?",
                    (policy_id, org_id),
                )
                for f in findings:
                    conn.execute(
                        """INSERT INTO policy_findings VALUES
                           (:finding_id,:org_id,:policy_id,:finding_type,:severity,
                            :description,:affected_permissions,:recommendation,:risk_score,:created_at)""",
                        {
                            "finding_id": str(uuid.uuid4()),
                            "org_id": org_id,
                            "policy_id": policy_id,
                            "finding_type": f["finding_type"],
                            "severity": f["severity"],
                            "description": f["description"],
                            "affected_permissions": json.dumps(f["affected_permissions"]),
                            "recommendation": f["recommendation"],
                            "risk_score": risk_score,
                            "created_at": now,
                        },
                    )
        return {"policy_id": policy_id, "findings": findings, "risk_score": risk_score}

    def analyze_all(self, org_id: str) -> Dict[str, Any]:
        """Run analysis on all policies for an org."""
        policies = self.list_policies(org_id)
        results = []
        total_risk = 0.0
        high_risk_count = 0
        for p in policies:
            result = self.analyze_policy(org_id, p["policy_id"])
            results.append(result)
            total_risk += result["risk_score"]
            if result["risk_score"] >= 60:
                high_risk_count += 1
        avg_risk = total_risk / len(policies) if policies else 0.0
        return {
            "policies_analyzed": len(policies),
            "total_findings": sum(len(r["findings"]) for r in results),
            "high_risk_policies": high_risk_count,
            "avg_risk_score": round(avg_risk, 1),
            "results": results,
        }

    # ------------------------------------------------------------------
    # Access Reviews
    # ------------------------------------------------------------------

    def record_access_review(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record an access review outcome for a policy."""
        review_id = str(uuid.uuid4())
        now = self._now()
        outcome = data.get("outcome", "approved")
        if outcome not in _VALID_REVIEW_OUTCOMES:
            outcome = "approved"
        row = {
            "review_id": review_id,
            "org_id": org_id,
            "policy_id": data.get("policy_id", ""),
            "reviewer": data.get("reviewer", ""),
            "outcome": outcome,
            "action_taken": data.get("action_taken", ""),
            "review_date": data.get("review_date", now),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO access_reviews VALUES
                       (:review_id,:org_id,:policy_id,:reviewer,:outcome,
                        :action_taken,:review_date,:created_at)""",
                    row,
                )
        return row

    def list_access_reviews(self, org_id: str) -> List[Dict[str, Any]]:
        """List all access reviews for an org."""
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM access_reviews WHERE org_id = ? ORDER BY created_at DESC",
                    (org_id,),
                ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_iam_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated IAM stats for an org."""
        with self._lock:
            with self._conn() as conn:
                total = conn.execute(
                    "SELECT COUNT(*) FROM iam_policies WHERE org_id = ?", (org_id,)
                ).fetchone()[0]

                by_type_rows = conn.execute(
                    """SELECT policy_type, COUNT(*) as cnt
                       FROM iam_policies WHERE org_id = ?
                       GROUP BY policy_type""",
                    (org_id,),
                ).fetchall()

                admin_count = conn.execute(
                    """SELECT COUNT(DISTINCT p.policy_id)
                       FROM iam_policies p
                       JOIN policy_findings f ON p.policy_id = f.policy_id
                       WHERE p.org_id = ? AND f.finding_type = 'admin_access'""",
                    (org_id,),
                ).fetchone()[0]

                wildcard_count = conn.execute(
                    """SELECT COUNT(DISTINCT p.policy_id)
                       FROM iam_policies p
                       JOIN policy_findings f ON p.policy_id = f.policy_id
                       WHERE p.org_id = ? AND f.finding_type = 'wildcard_action'""",
                    (org_id,),
                ).fetchone()[0]

                avg_risk_row = conn.execute(
                    """SELECT AVG(risk_score) FROM policy_findings WHERE org_id = ?""",
                    (org_id,),
                ).fetchone()
                avg_risk = avg_risk_row[0] or 0.0

                high_risk = conn.execute(
                    """SELECT COUNT(DISTINCT policy_id)
                       FROM policy_findings
                       WHERE org_id = ? AND risk_score >= 60""",
                    (org_id,),
                ).fetchone()[0]

                last_review = conn.execute(
                    """SELECT MAX(review_date) FROM access_reviews WHERE org_id = ?""",
                    (org_id,),
                ).fetchone()[0]

        return {
            "total_policies": total,
            "by_type": {r["policy_type"]: r["cnt"] for r in by_type_rows},
            "admin_access_count": admin_count,
            "wildcard_count": wildcard_count,
            "avg_risk_score": round(avg_risk, 1),
            "high_risk_policies": high_risk,
            "last_review_date": last_review,
        }
