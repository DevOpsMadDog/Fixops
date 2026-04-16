"""Cloud Posture Engine — ALDECI. SQLite WAL + RLock + org_id isolation."""
from __future__ import annotations

import logging
import sqlite3

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "cloud_posture.db"
)

VALID_PROVIDERS = frozenset({"aws", "azure", "gcp", "alibaba", "oracle", "ibm"})
VALID_RESOURCE_TYPES = frozenset(
    {"iam", "storage", "compute", "network", "database", "serverless", "container"}
)
VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
VALID_FINDING_STATUSES = frozenset({"open", "suppressed", "resolved", "false_positive"})

_SEVERITY_SCORE_IMPACT = {
    "critical": 10,
    "high": 5,
    "medium": 2,
    "low": 1,
    "info": 0,
}


class CloudPostureEngine:
    """SQLite-backed Cloud Security Posture Management engine.

    All public methods are thread-safe via RLock.
    Multi-tenant via org_id isolation.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS cp_accounts (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    account_id TEXT NOT NULL DEFAULT '',
                    account_name TEXT NOT NULL DEFAULT '',
                    provider TEXT NOT NULL DEFAULT 'aws',
                    region TEXT NOT NULL DEFAULT '',
                    resource_count INTEGER NOT NULL DEFAULT 0,
                    posture_score REAL NOT NULL DEFAULT 100.0,
                    last_scanned DATETIME,
                    status TEXT NOT NULL DEFAULT 'active',
                    created_at DATETIME
                );
                CREATE TABLE IF NOT EXISTS cp_findings (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    cloud_account_id TEXT NOT NULL DEFAULT '',
                    resource_id TEXT NOT NULL DEFAULT '',
                    resource_type TEXT NOT NULL DEFAULT 'compute',
                    provider TEXT NOT NULL DEFAULT 'aws',
                    severity TEXT NOT NULL DEFAULT 'medium',
                    title TEXT NOT NULL DEFAULT '',
                    description TEXT NOT NULL DEFAULT '',
                    remediation TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'open',
                    detected_at DATETIME,
                    resolved_at DATETIME,
                    notes TEXT NOT NULL DEFAULT ''
                );
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Accounts
    # ------------------------------------------------------------------

    def register_account(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a cloud account for posture tracking."""
        account_id = data.get("account_id", "").strip()
        if not account_id:
            raise ValueError("account_id is required")
        provider = data.get("provider", "aws")
        if provider not in VALID_PROVIDERS:
            raise ValueError(f"provider must be one of {sorted(VALID_PROVIDERS)}")

        now = datetime.now(timezone.utc).isoformat()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "account_id": account_id,
            "account_name": data.get("account_name", ""),
            "provider": provider,
            "region": data.get("region", ""),
            "resource_count": int(data.get("resource_count", 0)),
            "posture_score": float(data.get("posture_score", 100.0)),
            "last_scanned": data.get("last_scanned"),
            "status": data.get("status", "active"),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO cp_accounts
                       (id, org_id, account_id, account_name, provider, region,
                        resource_count, posture_score, last_scanned, status, created_at)
                       VALUES (:id, :org_id, :account_id, :account_name, :provider, :region,
                               :resource_count, :posture_score, :last_scanned, :status, :created_at)""",
                    record,
                )
        if _get_tg_bus is not None:
            try:
                _get_tg_bus().emit("ASSET_DISCOVERED", {
                    "org_id": org_id,
                    "entity": "cloud_account",
                    "asset_id": record["id"],
                    "account_id": account_id,
                    "provider": provider,
                })
            except Exception:
                pass
        return record

    def list_accounts(
        self, org_id: str, provider: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List cloud accounts for the org, optionally filtered by provider."""
        query = "SELECT * FROM cp_accounts WHERE org_id = ?"
        params: List[Any] = [org_id]
        if provider:
            query += " AND provider = ?"
            params.append(provider)
        query += " ORDER BY created_at DESC"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def get_account(self, org_id: str, account_id_param: str) -> Optional[Dict[str, Any]]:
        """Get a single cloud account by internal id, org-isolated."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM cp_accounts WHERE id = ? AND org_id = ?",
                    (account_id_param, org_id),
                ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def record_finding(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a cloud posture finding and adjust account posture score."""
        cloud_account_id = data.get("cloud_account_id", data.get("account_id", "")).strip()
        if not cloud_account_id:
            raise ValueError("cloud_account_id is required")
        resource_type = data.get("resource_type", "compute")
        if resource_type not in VALID_RESOURCE_TYPES:
            raise ValueError(f"resource_type must be one of {sorted(VALID_RESOURCE_TYPES)}")
        severity = data.get("severity", "medium")
        if severity not in VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(VALID_SEVERITIES)}")

        now = datetime.now(timezone.utc).isoformat()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "cloud_account_id": cloud_account_id,
            "resource_id": data.get("resource_id", ""),
            "resource_type": resource_type,
            "provider": data.get("provider", "aws"),
            "severity": severity,
            "title": data.get("title", ""),
            "description": data.get("description", ""),
            "remediation": data.get("remediation", ""),
            "status": "open",
            "detected_at": now,
            "resolved_at": None,
            "notes": data.get("notes", ""),
        }
        impact = _SEVERITY_SCORE_IMPACT.get(severity, 0)
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO cp_findings
                       (id, org_id, cloud_account_id, resource_id, resource_type, provider,
                        severity, title, description, remediation, status, detected_at, resolved_at, notes)
                       VALUES (:id, :org_id, :cloud_account_id, :resource_id, :resource_type, :provider,
                               :severity, :title, :description, :remediation, :status, :detected_at,
                               :resolved_at, :notes)""",
                    record,
                )
                # Decrement posture score for the matching account (by internal id or account_id field)
                if impact > 0:
                    conn.execute(
                        """UPDATE cp_accounts
                           SET posture_score = MAX(0.0, posture_score - ?)
                           WHERE org_id = ? AND (id = ? OR account_id = ?)""",
                        (impact, org_id, cloud_account_id, cloud_account_id),
                    )
        return record

    def list_findings(
        self,
        org_id: str,
        provider: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        resource_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List findings with optional filters."""
        query = "SELECT * FROM cp_findings WHERE org_id = ?"
        params: List[Any] = [org_id]
        if provider:
            query += " AND provider = ?"
            params.append(provider)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if status:
            query += " AND status = ?"
            params.append(status)
        if resource_type:
            query += " AND resource_type = ?"
            params.append(resource_type)
        query += " ORDER BY detected_at DESC"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def update_finding_status(
        self, org_id: str, finding_id: str, status: str, notes: str = ""
    ) -> Dict[str, Any]:
        """Update a finding's status. Restores posture score when resolved."""
        if status not in VALID_FINDING_STATUSES:
            raise ValueError(f"status must be one of {sorted(VALID_FINDING_STATUSES)}")
        now = datetime.now(timezone.utc).isoformat()
        resolved_at = now if status == "resolved" else None
        with self._lock:
            with self._conn() as conn:
                # Fetch current finding
                row = conn.execute(
                    "SELECT * FROM cp_findings WHERE id = ? AND org_id = ?",
                    (finding_id, org_id),
                ).fetchone()
                if not row:
                    raise ValueError(f"Finding {finding_id} not found")
                finding = self._row(row)
                old_status = finding["status"]

                conn.execute(
                    """UPDATE cp_findings
                       SET status = ?, resolved_at = ?, notes = ?
                       WHERE id = ? AND org_id = ?""",
                    (status, resolved_at, notes, finding_id, org_id),
                )

                # Restore posture score when transitioning to resolved
                if status == "resolved" and old_status != "resolved":
                    impact = _SEVERITY_SCORE_IMPACT.get(finding["severity"], 0)
                    if impact > 0:
                        cloud_account_id = finding["cloud_account_id"]
                        conn.execute(
                            """UPDATE cp_accounts
                               SET posture_score = MIN(100.0, posture_score + ?)
                               WHERE org_id = ? AND (id = ? OR account_id = ?)""",
                            (impact, org_id, cloud_account_id, cloud_account_id),
                        )

        finding["status"] = status
        finding["resolved_at"] = resolved_at
        finding["notes"] = notes
        return finding

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_posture_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate posture statistics for the org."""
        with self._lock:
            with self._conn() as conn:
                acc_row = conn.execute(
                    "SELECT COUNT(*) AS cnt, AVG(posture_score) AS avg_score FROM cp_accounts WHERE org_id = ?",
                    (org_id,),
                ).fetchone()
                total_accounts = acc_row["cnt"] or 0
                avg_posture_score = round(acc_row["avg_score"] or 100.0, 2)

                total_findings = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM cp_findings WHERE org_id = ?",
                    (org_id,),
                ).fetchone()["cnt"]

                open_findings = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM cp_findings WHERE org_id = ? AND status = 'open'",
                    (org_id,),
                ).fetchone()["cnt"]

                critical_findings = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM cp_findings WHERE org_id = ? AND severity = 'critical'",
                    (org_id,),
                ).fetchone()["cnt"]

                provider_rows = conn.execute(
                    "SELECT provider, COUNT(*) AS cnt FROM cp_accounts WHERE org_id = ? GROUP BY provider",
                    (org_id,),
                ).fetchall()
                by_provider = {r["provider"]: r["cnt"] for r in provider_rows}

                sev_rows = conn.execute(
                    "SELECT severity, COUNT(*) AS cnt FROM cp_findings WHERE org_id = ? GROUP BY severity",
                    (org_id,),
                ).fetchall()
                by_severity = {r["severity"]: r["cnt"] for r in sev_rows}

        return {
            "total_accounts": total_accounts,
            "avg_posture_score": avg_posture_score,
            "total_findings": total_findings,
            "open_findings": open_findings,
            "critical_findings": critical_findings,
            "by_provider": by_provider,
            "by_severity": by_severity,
        }
