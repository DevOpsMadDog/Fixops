"""Service Account Auditor Engine — ALDECI.

Audits service accounts across k8s, aws, gcp, azure, and linux for:
- Unused accounts (not used in N days)
- Overprivileged accounts (excessive permissions)
- Stale credential rotation
- Misconfiguration findings

SQLite-backed, thread-safe, multi-tenant (per org_id).
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

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = ".fixops_data/service_account_auditor.db"

_SUPPORTED_SYSTEMS = {"k8s", "aws", "gcp", "azure", "linux"}

# Permissions considered high-risk per system
_HIGH_RISK_PERMISSIONS: Dict[str, set] = {
    "k8s": {"cluster-admin", "admin", "*"},
    "aws": {"AdministratorAccess", "*", "iam:*", "s3:*"},
    "gcp": {"roles/owner", "roles/editor", "roles/iam.admin"},
    "azure": {"Owner", "Contributor", "User Access Administrator"},
    "linux": {"root", "sudo", "wheel"},
}

# Max days before credentials are considered overdue for rotation
_ROTATION_DAYS_THRESHOLD = 90


class ServiceAccountAuditorEngine:
    """
    Service Account Auditor Engine.

    All public methods are thread-safe via RLock.
    Multi-tenant: every query is scoped to org_id.

    Args:
        db_path: Path to SQLite database.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.executescript(
                """
                PRAGMA journal_mode=WAL;

                CREATE TABLE IF NOT EXISTS service_accounts (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    name             TEXT NOT NULL,
                    system           TEXT NOT NULL,
                    permissions      TEXT NOT NULL,
                    last_used_days   INTEGER NOT NULL DEFAULT 0,
                    risk_score       REAL NOT NULL DEFAULT 0,
                    registered_at    TEXT NOT NULL,
                    updated_at       TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_sa_org ON service_accounts(org_id);
                CREATE INDEX IF NOT EXISTS idx_sa_system ON service_accounts(system);
                CREATE INDEX IF NOT EXISTS idx_sa_risk ON service_accounts(risk_score);

                CREATE TABLE IF NOT EXISTS audit_findings (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    account_id      TEXT NOT NULL,
                    finding_type    TEXT NOT NULL,
                    severity        TEXT NOT NULL,
                    description     TEXT NOT NULL,
                    audited_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_af_org ON audit_findings(org_id);
                CREATE INDEX IF NOT EXISTS idx_af_account ON audit_findings(account_id);

                CREATE TABLE IF NOT EXISTS rotation_history (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    account_id      TEXT NOT NULL,
                    rotated_at      TEXT NOT NULL,
                    rotated_by      TEXT NOT NULL DEFAULT 'system'
                );

                CREATE INDEX IF NOT EXISTS idx_rh_org ON rotation_history(org_id);
                CREATE INDEX IF NOT EXISTS idx_rh_account ON rotation_history(account_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Risk scoring helpers
    # ------------------------------------------------------------------

    def _compute_risk_score(self, system: str, permissions: List[str], last_used_days: int) -> float:
        """Compute a 0-100 risk score for a service account."""
        score = 0.0

        high_risk = _HIGH_RISK_PERMISSIONS.get(system, set())
        matched = [p for p in permissions if p in high_risk]
        wildcard_count = sum(1 for p in permissions if "*" in p or p in high_risk)

        # High-risk permission hits
        score += min(40.0, wildcard_count * 15.0)
        score += min(20.0, len(matched) * 10.0)

        # Permission count factor (too many permissions)
        if len(permissions) > 10:
            score += 15.0
        elif len(permissions) > 5:
            score += 8.0

        # Unused account factor
        if last_used_days > 180:
            score += 20.0
        elif last_used_days > 90:
            score += 10.0

        # Stale credentials factor
        if last_used_days > _ROTATION_DAYS_THRESHOLD:
            score += 5.0

        return min(100.0, score)

    def _build_findings(
        self, system: str, permissions: List[str], last_used_days: int, name: str
    ) -> List[Dict[str, Any]]:
        """Generate audit findings for a service account."""
        findings: List[Dict[str, Any]] = []
        high_risk = _HIGH_RISK_PERMISSIONS.get(system, set())

        # Check for high-risk permissions
        matched_high_risk = [p for p in permissions if p in high_risk]
        if matched_high_risk:
            findings.append({
                "finding_type": "overprivileged",
                "severity": "critical",
                "description": (
                    f"Service account '{name}' has high-risk {system} permissions: "
                    f"{', '.join(matched_high_risk)}. Apply least-privilege."
                ),
            })

        # Wildcard permissions
        wildcards = [p for p in permissions if "*" in p]
        if wildcards:
            findings.append({
                "finding_type": "wildcard_permission",
                "severity": "high",
                "description": (
                    f"Service account '{name}' has wildcard permissions: "
                    f"{', '.join(wildcards)}. Scope to explicit resources."
                ),
            })

        # Unused account
        if last_used_days > 180:
            findings.append({
                "finding_type": "unused_account",
                "severity": "high",
                "description": (
                    f"Service account '{name}' has not been used in {last_used_days} days "
                    f"(threshold: 180). Consider disabling or deleting."
                ),
            })
        elif last_used_days > 90:
            findings.append({
                "finding_type": "unused_account",
                "severity": "medium",
                "description": (
                    f"Service account '{name}' has not been used in {last_used_days} days "
                    f"(threshold: 90). Review whether this account is still needed."
                ),
            })

        # Stale credentials
        if last_used_days > _ROTATION_DAYS_THRESHOLD:
            findings.append({
                "finding_type": "stale_credentials",
                "severity": "medium",
                "description": (
                    f"Service account '{name}' credentials have not been rotated in "
                    f"{last_used_days} days (policy: {_ROTATION_DAYS_THRESHOLD} days). "
                    f"Rotate credentials immediately."
                ),
            })

        # Excessive permission count
        if len(permissions) > 10:
            findings.append({
                "finding_type": "excessive_permissions",
                "severity": "medium",
                "description": (
                    f"Service account '{name}' has {len(permissions)} permissions assigned. "
                    f"Review and reduce to minimum required."
                ),
            })

        if not findings:
            findings.append({
                "finding_type": "clean",
                "severity": "info",
                "description": f"No issues found for service account '{name}'.",
            })

        return findings

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register_service_account(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a service account for auditing.

        Args:
            org_id: Organization identifier.
            data: dict with keys:
                - name (str): Account name/identifier.
                - system (str): One of k8s/aws/gcp/azure/linux.
                - permissions (list[str]): List of permissions/roles.
                - last_used_days_ago (int): Days since last use.

        Returns:
            Registered account record with computed risk_score.
        """
        name = data.get("name", "")
        system = data.get("system", "").lower()
        permissions = data.get("permissions", [])
        last_used_days = int(data.get("last_used_days_ago", 0))

        if not name:
            raise ValueError("name is required")
        if system not in _SUPPORTED_SYSTEMS:
            raise ValueError(f"system must be one of {sorted(_SUPPORTED_SYSTEMS)}")

        account_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        risk_score = self._compute_risk_score(system, permissions, last_used_days)

        record = {
            "id": account_id,
            "org_id": org_id,
            "name": name,
            "system": system,
            "permissions": permissions,
            "last_used_days": last_used_days,
            "risk_score": risk_score,
            "registered_at": now,
            "updated_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO service_accounts
                        (id, org_id, name, system, permissions, last_used_days, risk_score, registered_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        account_id, org_id, name, system,
                        json.dumps(permissions), last_used_days, risk_score, now, now,
                    ),
                )

        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("CONTROL_ASSESSED", {"entity_type": "service_account_auditor", "org_id": org_id, "source_engine": "service_account_auditor"})
            except Exception:
                pass

        return record

    def list_service_accounts(
        self, org_id: str, system: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List all service accounts for an org, optionally filtered by system."""
        with self._lock:
            with self._conn() as conn:
                if system:
                    rows = conn.execute(
                        "SELECT * FROM service_accounts WHERE org_id=? AND system=? ORDER BY risk_score DESC",
                        (org_id, system.lower()),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM service_accounts WHERE org_id=? ORDER BY risk_score DESC",
                        (org_id,),
                    ).fetchall()

        result = []
        for row in rows:
            r = dict(row)
            r["permissions"] = json.loads(r["permissions"])
            result.append(r)
        return result

    def run_audit(self, org_id: str, account_id: str) -> Dict[str, Any]:
        """Run a security audit for a specific service account.

        Returns:
            dict with keys: account_id, findings (list), risk_score, audited_at
        """
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM service_accounts WHERE id=? AND org_id=?",
                    (account_id, org_id),
                ).fetchone()

        if not row:
            raise ValueError(f"Account {account_id} not found for org {org_id}")

        account = dict(row)
        permissions = json.loads(account["permissions"])
        findings = self._build_findings(
            account["system"],
            permissions,
            account["last_used_days"],
            account["name"],
        )

        risk_score = self._compute_risk_score(
            account["system"], permissions, account["last_used_days"]
        )
        now = datetime.now(timezone.utc).isoformat()

        # Persist findings
        with self._lock:
            with self._conn() as conn:
                for f in findings:
                    conn.execute(
                        """
                        INSERT INTO audit_findings
                            (id, org_id, account_id, finding_type, severity, description, audited_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            str(uuid.uuid4()), org_id, account_id,
                            f["finding_type"], f["severity"], f["description"], now,
                        ),
                    )
                conn.execute(
                    "UPDATE service_accounts SET risk_score=?, updated_at=? WHERE id=? AND org_id=?",
                    (risk_score, now, account_id, org_id),
                )

        return {
            "account_id": account_id,
            "name": account["name"],
            "system": account["system"],
            "findings": findings,
            "risk_score": risk_score,
            "audited_at": now,
        }

    def get_unused_accounts(self, org_id: str, days_threshold: int = 90) -> List[Dict[str, Any]]:
        """Return accounts not used in the last N days."""
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    """
                    SELECT * FROM service_accounts
                    WHERE org_id=? AND last_used_days >= ?
                    ORDER BY last_used_days DESC
                    """,
                    (org_id, days_threshold),
                ).fetchall()

        result = []
        for row in rows:
            r = dict(row)
            r["permissions"] = json.loads(r["permissions"])
            result.append(r)
        return result

    def get_overprivileged_accounts(self, org_id: str) -> List[Dict[str, Any]]:
        """Return accounts with risk_score > 70."""
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    """
                    SELECT * FROM service_accounts
                    WHERE org_id=? AND risk_score > 70
                    ORDER BY risk_score DESC
                    """,
                    (org_id,),
                ).fetchall()

        result = []
        for row in rows:
            r = dict(row)
            r["permissions"] = json.loads(r["permissions"])
            result.append(r)
        return result

    def rotate_credentials(self, org_id: str, account_id: str) -> Dict[str, Any]:
        """Record a credential rotation event for a service account.

        Returns:
            dict with rotation_id, account_id, rotated_at, message.
        """
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT id, name FROM service_accounts WHERE id=? AND org_id=?",
                    (account_id, org_id),
                ).fetchone()

        if not row:
            raise ValueError(f"Account {account_id} not found for org {org_id}")

        rotation_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO rotation_history (id, org_id, account_id, rotated_at, rotated_by)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (rotation_id, org_id, account_id, now, "api"),
                )
                # Reset last_used_days to 0 after rotation (credentials refreshed)
                conn.execute(
                    "UPDATE service_accounts SET last_used_days=0, updated_at=? WHERE id=? AND org_id=?",
                    (now, account_id, org_id),
                )

        return {
            "rotation_id": rotation_id,
            "account_id": account_id,
            "name": dict(row)["name"],
            "rotated_at": now,
            "message": "Credentials rotation recorded successfully.",
        }

    def list_rotation_history(self, org_id: str, account_id: str) -> List[Dict[str, Any]]:
        """Return all rotation events for a service account."""
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    """
                    SELECT * FROM rotation_history
                    WHERE org_id=? AND account_id=?
                    ORDER BY rotated_at DESC
                    """,
                    (org_id, account_id),
                ).fetchall()

        return [dict(row) for row in rows]

    def get_audit_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate statistics for an org's service accounts."""
        with self._lock:
            with self._conn() as conn:
                total = conn.execute(
                    "SELECT COUNT(*) FROM service_accounts WHERE org_id=?", (org_id,)
                ).fetchone()[0]

                high_risk = conn.execute(
                    "SELECT COUNT(*) FROM service_accounts WHERE org_id=? AND risk_score > 70",
                    (org_id,),
                ).fetchone()[0]

                unused = conn.execute(
                    "SELECT COUNT(*) FROM service_accounts WHERE org_id=? AND last_used_days >= ?",
                    (org_id, _ROTATION_DAYS_THRESHOLD),
                ).fetchone()[0]

                # Overdue rotations: accounts with no rotation in threshold period
                # Approximated by last_used_days > threshold and no recent rotation
                overdue_query = conn.execute(
                    """
                    SELECT COUNT(DISTINCT sa.id)
                    FROM service_accounts sa
                    LEFT JOIN (
                        SELECT account_id, MAX(rotated_at) AS last_rotation
                        FROM rotation_history
                        WHERE org_id=?
                        GROUP BY account_id
                    ) rh ON sa.id = rh.account_id
                    WHERE sa.org_id=?
                      AND (rh.last_rotation IS NULL OR sa.last_used_days > ?)
                    """,
                    (org_id, org_id, _ROTATION_DAYS_THRESHOLD),
                ).fetchone()[0]

                by_system = conn.execute(
                    """
                    SELECT system, COUNT(*) as count
                    FROM service_accounts WHERE org_id=?
                    GROUP BY system
                    """,
                    (org_id,),
                ).fetchall()

        return {
            "org_id": org_id,
            "total_accounts": total,
            "high_risk_count": high_risk,
            "unused_count": unused,
            "overdue_rotations": overdue_query,
            "by_system": {row["system"]: row["count"] for row in by_system},
        }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_engine_instance: Optional[ServiceAccountAuditorEngine] = None


def get_service_account_auditor() -> ServiceAccountAuditorEngine:
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = ServiceAccountAuditorEngine()
    return _engine_instance
