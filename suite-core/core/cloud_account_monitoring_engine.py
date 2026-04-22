"""Cloud Account Monitoring Engine — ALDECI.

Tracks cloud account health and security posture across AWS/Azure/GCP/etc.

Capabilities:
  - Cloud account registration with provider/region tracking
  - Scan results updating risk_score and findings_count
  - Security event recording and resolution
  - Policy creation and violation tracking
  - Risk summary per provider
  - Unresolved event querying

Compliance: CSA CCM, CIS Benchmarks, NIST SP 800-144
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

_DEFAULT_DB_DIR = str(Path(__file__).resolve().parents[2] / ".fixops_data")

_VALID_PROVIDERS = {
    "aws", "azure", "gcp", "alibaba", "oracle", "oci", "ibm", "digitalocean",
}
_VALID_EVENT_TYPES = {
    "config-change", "login-anomaly", "resource-creation", "policy-violation",
    "cost-spike", "data-access", "privilege-escalation", "compliance-breach",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_POLICY_TYPES = {"security", "compliance", "cost", "governance", "data-protection"}
_VALID_ACCOUNT_STATUSES = {"healthy", "warning", "critical"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _risk_to_status(risk_score: float) -> str:
    if risk_score < 30:
        return "healthy"
    if risk_score <= 70:
        return "warning"
    return "critical"


class CloudAccountMonitoringEngine:
    """SQLite WAL-backed Cloud Account Monitoring engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/cloud_account_monitoring.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(Path(_DEFAULT_DB_DIR) / "cloud_account_monitoring.db")
        self._db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS cloud_accounts (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    account_id      TEXT NOT NULL,
                    account_name    TEXT NOT NULL,
                    provider        TEXT NOT NULL,
                    region          TEXT NOT NULL DEFAULT '',
                    status          TEXT NOT NULL DEFAULT 'healthy',
                    risk_score      REAL NOT NULL DEFAULT 0.0,
                    findings_count  INTEGER NOT NULL DEFAULT 0,
                    last_scanned    TEXT,
                    created_at      TEXT NOT NULL,
                    UNIQUE(org_id, account_id)
                );

                CREATE INDEX IF NOT EXISTS idx_ca_org
                    ON cloud_accounts (org_id, provider, status);

                CREATE TABLE IF NOT EXISTS account_events (
                    id           TEXT PRIMARY KEY,
                    account_id   TEXT NOT NULL,
                    org_id       TEXT NOT NULL,
                    event_type   TEXT NOT NULL,
                    severity     TEXT NOT NULL,
                    resource     TEXT NOT NULL DEFAULT '',
                    description  TEXT NOT NULL DEFAULT '',
                    detected_at  TEXT NOT NULL,
                    resolved_at  TEXT,
                    status       TEXT NOT NULL DEFAULT 'open'
                );

                CREATE INDEX IF NOT EXISTS idx_ae_account
                    ON account_events (account_id, org_id, status, detected_at DESC);

                CREATE INDEX IF NOT EXISTS idx_ae_org
                    ON account_events (org_id, status, severity);

                CREATE TABLE IF NOT EXISTS account_policies (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    policy_name      TEXT NOT NULL,
                    policy_type      TEXT NOT NULL,
                    scope            TEXT NOT NULL DEFAULT '',
                    enabled          INTEGER NOT NULL DEFAULT 1,
                    violation_count  INTEGER NOT NULL DEFAULT 0,
                    last_evaluated   TEXT,
                    created_at       TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ap_org
                    ON account_policies (org_id, policy_type);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Accounts
    # ------------------------------------------------------------------

    def register_account(
        self,
        org_id: str,
        account_id: str,
        account_name: str,
        provider: str,
        region: str = "",
    ) -> Dict[str, Any]:
        """Register a new cloud account."""
        if not account_id.strip():
            raise ValueError("account_id is required.")
        if not account_name.strip():
            raise ValueError("account_name is required.")
        if provider not in _VALID_PROVIDERS:
            raise ValueError(
                f"Invalid provider: {provider!r}. "
                f"Must be one of {sorted(_VALID_PROVIDERS)}"
            )
        now = _now()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "account_id": account_id.strip(),
            "account_name": account_name.strip(),
            "provider": provider,
            "region": region or "",
            "status": "healthy",
            "risk_score": 0.0,
            "findings_count": 0,
            "last_scanned": None,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO cloud_accounts
                       (id, org_id, account_id, account_name, provider, region,
                        status, risk_score, findings_count, last_scanned, created_at)
                       VALUES (:id, :org_id, :account_id, :account_name, :provider, :region,
                               :status, :risk_score, :findings_count, :last_scanned, :created_at)""",
                    record,
                )
        return record

    def update_account_scan(
        self,
        account_id: str,
        org_id: str,
        findings_count: int,
        risk_score: float,
    ) -> Dict[str, Any]:
        """Update scan results and recompute account status."""
        risk_score = max(0.0, min(100.0, float(risk_score)))
        findings_count = max(0, int(findings_count))
        new_status = _risk_to_status(risk_score)
        now = _now()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT id FROM cloud_accounts WHERE account_id=? AND org_id=?",
                    (account_id, org_id),
                ).fetchone()
                if not row:
                    raise KeyError(f"Account {account_id!r} not found.")
                conn.execute(
                    """UPDATE cloud_accounts
                       SET findings_count=?, risk_score=?, status=?, last_scanned=?
                       WHERE account_id=? AND org_id=?""",
                    (findings_count, risk_score, new_status, now, account_id, org_id),
                )
                updated = conn.execute(
                    "SELECT * FROM cloud_accounts WHERE account_id=? AND org_id=?",
                    (account_id, org_id),
                ).fetchone()
        return self._row(updated)

    def get_account(self, account_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        """Get account with its 20 most recent events."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM cloud_accounts WHERE account_id=? AND org_id=?",
                (account_id, org_id),
            ).fetchone()
            if not row:
                return None
            account = self._row(row)
            event_rows = conn.execute(
                """SELECT * FROM account_events
                   WHERE account_id=? AND org_id=?
                   ORDER BY detected_at DESC LIMIT 20""",
                (account_id, org_id),
            ).fetchall()
        account["recent_events"] = [self._row(r) for r in event_rows]
        return account

    def list_accounts(
        self,
        org_id: str,
        provider: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List accounts with optional provider/status filters."""
        query = "SELECT * FROM cloud_accounts WHERE org_id=?"
        params: List[Any] = [org_id]
        if provider:
            query += " AND provider=?"
            params.append(provider)
        if status:
            query += " AND status=?"
            params.append(status)
        query += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    def record_event(
        self,
        account_id: str,
        org_id: str,
        event_type: str,
        severity: str,
        resource: str,
        description: str,
    ) -> Dict[str, Any]:
        """Record a security event for an account."""
        if event_type not in _VALID_EVENT_TYPES:
            raise ValueError(
                f"Invalid event_type: {event_type!r}. "
                f"Must be one of {sorted(_VALID_EVENT_TYPES)}"
            )
        if severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity: {severity!r}. "
                f"Must be one of {sorted(_VALID_SEVERITIES)}"
            )
        now = _now()
        record = {
            "id": str(uuid.uuid4()),
            "account_id": account_id,
            "org_id": org_id,
            "event_type": event_type,
            "severity": severity,
            "resource": resource or "",
            "description": description or "",
            "detected_at": now,
            "resolved_at": None,
            "status": "open",
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO account_events
                       (id, account_id, org_id, event_type, severity, resource,
                        description, detected_at, resolved_at, status)
                       VALUES (:id, :account_id, :org_id, :event_type, :severity, :resource,
                               :description, :detected_at, :resolved_at, :status)""",
                    record,
                )
        return record

    def resolve_event(
        self, account_id: str, event_id: str, org_id: str
    ) -> Dict[str, Any]:
        """Mark an event as resolved."""
        now = _now()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT id FROM account_events WHERE id=? AND account_id=? AND org_id=?",
                    (event_id, account_id, org_id),
                ).fetchone()
                if not row:
                    raise KeyError(f"Event {event_id!r} not found.")
                conn.execute(
                    """UPDATE account_events SET status='resolved', resolved_at=?
                       WHERE id=? AND account_id=? AND org_id=?""",
                    (now, event_id, account_id, org_id),
                )
                updated = conn.execute(
                    "SELECT * FROM account_events WHERE id=?", (event_id,)
                ).fetchone()
        return self._row(updated)

    def get_unresolved_events(
        self, org_id: str, severity: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Return events with status != 'resolved', optionally filtered by severity."""
        query = "SELECT * FROM account_events WHERE org_id=? AND status != 'resolved'"
        params: List[Any] = [org_id]
        if severity:
            query += " AND severity=?"
            params.append(severity)
        query += " ORDER BY detected_at DESC"
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Policies
    # ------------------------------------------------------------------

    def create_policy(
        self,
        org_id: str,
        policy_name: str,
        policy_type: str,
        scope: str = "",
    ) -> Dict[str, Any]:
        """Create an account security policy."""
        if not policy_name.strip():
            raise ValueError("policy_name is required.")
        if policy_type not in _VALID_POLICY_TYPES:
            raise ValueError(
                f"Invalid policy_type: {policy_type!r}. "
                f"Must be one of {sorted(_VALID_POLICY_TYPES)}"
            )
        now = _now()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "policy_name": policy_name.strip(),
            "policy_type": policy_type,
            "scope": scope or "",
            "enabled": 1,
            "violation_count": 0,
            "last_evaluated": None,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO account_policies
                       (id, org_id, policy_name, policy_type, scope, enabled,
                        violation_count, last_evaluated, created_at)
                       VALUES (:id, :org_id, :policy_name, :policy_type, :scope, :enabled,
                               :violation_count, :last_evaluated, :created_at)""",
                    record,
                )
        return record

    def evaluate_policy(
        self, policy_id: str, org_id: str, violation_count: int
    ) -> Dict[str, Any]:
        """Update policy violation_count and last_evaluated timestamp."""
        violation_count = max(0, int(violation_count))
        now = _now()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT id FROM account_policies WHERE id=? AND org_id=?",
                    (policy_id, org_id),
                ).fetchone()
                if not row:
                    raise KeyError(f"Policy {policy_id!r} not found.")
                conn.execute(
                    """UPDATE account_policies SET violation_count=?, last_evaluated=?
                       WHERE id=? AND org_id=?""",
                    (violation_count, now, policy_id, org_id),
                )
                updated = conn.execute(
                    "SELECT * FROM account_policies WHERE id=?", (policy_id,)
                ).fetchone()
        return self._row(updated)

    # ------------------------------------------------------------------
    # Risk Summary
    # ------------------------------------------------------------------

    def get_account_risk_summary(self, org_id: str) -> Dict[str, Any]:
        """Return per-provider avg risk_score, total findings, and critical_accounts count."""
        with self._conn() as conn:
            provider_rows = conn.execute(
                """SELECT provider,
                          AVG(risk_score) as avg_risk,
                          SUM(findings_count) as total_findings,
                          COUNT(*) as account_count
                   FROM cloud_accounts WHERE org_id=?
                   GROUP BY provider""",
                (org_id,),
            ).fetchall()
            critical_count = conn.execute(
                "SELECT COUNT(*) FROM cloud_accounts WHERE org_id=? AND status='critical'",
                (org_id,),
            ).fetchone()[0]
            total_accounts = conn.execute(
                "SELECT COUNT(*) FROM cloud_accounts WHERE org_id=?", (org_id,)
            ).fetchone()[0]
            total_findings = conn.execute(
                "SELECT COALESCE(SUM(findings_count), 0) FROM cloud_accounts WHERE org_id=?",
                (org_id,),
            ).fetchone()[0]

        by_provider = {}
        for r in provider_rows:
            by_provider[r["provider"]] = {
                "avg_risk_score": round(r["avg_risk"] or 0.0, 2),
                "total_findings": r["total_findings"] or 0,
                "account_count": r["account_count"],
            }

        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("FINDING_CREATED", {"entity_type": "cloud_account_monitoring_engine", "org_id": org_id, "source_engine": "cloud_account_monitoring_engine"})
            except Exception:
                pass
        return {
            "total_accounts": total_accounts,
            "critical_accounts": critical_count,
            "total_findings": total_findings,
            "by_provider": by_provider,
        }
