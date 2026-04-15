"""Cloud Cost Security Engine — ALDECI.

Detects cloud cost anomalies, abandoned/zombie resources, and budget overruns
with a security lens (publicly exposed idle resources = security_exposure).

Capabilities:
  - Cost snapshot recording with automatic anomaly detection
  - Abandoned/zombie/orphaned resource tracking
  - Budget management with threshold alerting
  - Cost anomaly lifecycle (open → investigating → resolved)
  - Cross-org stats aggregation

Compliance: CIS Cloud Foundations, AWS Well-Architected, FinOps Foundation
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

_DATA_DIR = Path(__file__).resolve().parents[2] / ".fixops_data"

_VALID_PROVIDERS = {"aws", "azure", "gcp"}
_VALID_ANOMALY_TYPES = {
    None, "", "spike", "abandoned", "zombie", "orphaned", "security_exposure",
}
_VALID_RESOURCE_STATUSES = {"active", "marked_for_cleanup", "terminated"}
_VALID_BUDGET_PERIODS = {"monthly", "quarterly", "annual"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_INVESTIGATION_STATUSES = {
    "open", "investigating", "resolved", "false_positive",
}

_SPIKE_THRESHOLD_PCT = 200.0   # >200% change → spike
_ABANDONED_DAYS = 30           # last_used older than 30 days → abandoned


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _today_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


class CloudCostSecurityEngine:
    """SQLite WAL-backed cloud cost security engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(_DATA_DIR / "cloud_cost_security.db")
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
                CREATE TABLE IF NOT EXISTS cost_snapshots (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    account_id          TEXT NOT NULL DEFAULT '',
                    provider            TEXT NOT NULL DEFAULT 'aws',
                    service_name        TEXT NOT NULL DEFAULT '',
                    region              TEXT NOT NULL DEFAULT '',
                    cost_usd            REAL NOT NULL DEFAULT 0.0,
                    previous_cost_usd   REAL NOT NULL DEFAULT 0.0,
                    change_pct          REAL NOT NULL DEFAULT 0.0,
                    snapshot_date       TEXT NOT NULL,
                    anomaly             INTEGER NOT NULL DEFAULT 0,
                    anomaly_type        TEXT,
                    created_at          TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_cs_org_account
                    ON cost_snapshots (org_id, account_id, snapshot_date DESC);
                CREATE INDEX IF NOT EXISTS idx_cs_org_anomaly
                    ON cost_snapshots (org_id, anomaly);

                CREATE TABLE IF NOT EXISTS abandoned_resources (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    account_id      TEXT NOT NULL DEFAULT '',
                    resource_id     TEXT NOT NULL DEFAULT '',
                    resource_type   TEXT NOT NULL DEFAULT '',
                    resource_name   TEXT NOT NULL DEFAULT '',
                    region          TEXT NOT NULL DEFAULT '',
                    provider        TEXT NOT NULL DEFAULT 'aws',
                    last_used       TEXT,
                    monthly_cost_usd REAL NOT NULL DEFAULT 0.0,
                    status          TEXT NOT NULL DEFAULT 'active',
                    security_risk   INTEGER NOT NULL DEFAULT 0,
                    risk_reason     TEXT NOT NULL DEFAULT '',
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ar_org_provider
                    ON abandoned_resources (org_id, provider, status);

                CREATE TABLE IF NOT EXISTS cost_budgets (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    account_id          TEXT NOT NULL DEFAULT '',
                    budget_name         TEXT NOT NULL,
                    period              TEXT NOT NULL DEFAULT 'monthly',
                    limit_usd           REAL NOT NULL DEFAULT 0.0,
                    current_spend_usd   REAL NOT NULL DEFAULT 0.0,
                    alert_threshold_pct INTEGER NOT NULL DEFAULT 80,
                    status              TEXT NOT NULL DEFAULT 'ok',
                    created_at          TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_cb_org
                    ON cost_budgets (org_id, status);

                CREATE TABLE IF NOT EXISTS cost_anomalies (
                    id                      TEXT PRIMARY KEY,
                    org_id                  TEXT NOT NULL,
                    account_id              TEXT NOT NULL DEFAULT '',
                    service_name            TEXT NOT NULL DEFAULT '',
                    cost_usd                REAL NOT NULL DEFAULT 0.0,
                    expected_usd            REAL NOT NULL DEFAULT 0.0,
                    deviation_pct           REAL NOT NULL DEFAULT 0.0,
                    anomaly_type            TEXT NOT NULL DEFAULT 'spike',
                    severity                TEXT NOT NULL DEFAULT 'medium',
                    investigation_status    TEXT NOT NULL DEFAULT 'open',
                    created_at              TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ca_org_status
                    ON cost_anomalies (org_id, investigation_status, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_ca_org_severity
                    ON cost_anomalies (org_id, severity);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        if "anomaly" in d:
            d["anomaly"] = bool(d["anomaly"])
        if "security_risk" in d:
            d["security_risk"] = bool(d["security_risk"])
        return d

    # ------------------------------------------------------------------
    # Cost Snapshots
    # ------------------------------------------------------------------

    def record_snapshot(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Save a cost snapshot and auto-detect anomalies.

        Anomaly detection rules:
          - change_pct > 200%          → spike
          - last_used older than 30d   → abandoned
          - public_ip=True AND idle    → security_exposure
        """
        provider = data.get("provider", "aws")
        if provider not in _VALID_PROVIDERS:
            raise ValueError(f"Invalid provider: {provider}. Must be one of {_VALID_PROVIDERS}")

        cost_usd = float(data.get("cost_usd", 0.0))
        previous_cost_usd = float(data.get("previous_cost_usd", 0.0))
        change_pct = float(data.get("change_pct", 0.0))
        if previous_cost_usd > 0 and change_pct == 0.0:
            change_pct = ((cost_usd - previous_cost_usd) / previous_cost_usd) * 100.0

        # Anomaly detection
        anomaly = False
        anomaly_type: Optional[str] = None

        if change_pct > _SPIKE_THRESHOLD_PCT:
            anomaly = True
            anomaly_type = "spike"

        last_used = data.get("last_used")
        if last_used and not anomaly:
            try:
                last_used_dt = datetime.fromisoformat(last_used.replace("Z", "+00:00"))
                now_dt = datetime.now(timezone.utc)
                days_idle = (now_dt - last_used_dt).days
                if days_idle >= _ABANDONED_DAYS:
                    anomaly = True
                    anomaly_type = "abandoned"
            except (ValueError, AttributeError):
                pass

        has_public_ip = bool(data.get("has_public_ip", False))
        is_idle = bool(data.get("is_idle", False))
        if has_public_ip and is_idle and not anomaly:
            anomaly = True
            anomaly_type = "security_exposure"

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "account_id": data.get("account_id", ""),
            "provider": provider,
            "service_name": data.get("service_name", ""),
            "region": data.get("region", ""),
            "cost_usd": cost_usd,
            "previous_cost_usd": previous_cost_usd,
            "change_pct": round(change_pct, 4),
            "snapshot_date": data.get("snapshot_date", _today_str()),
            "anomaly": anomaly,
            "anomaly_type": anomaly_type,
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO cost_snapshots
                       (id, org_id, account_id, provider, service_name, region,
                        cost_usd, previous_cost_usd, change_pct, snapshot_date,
                        anomaly, anomaly_type, created_at)
                       VALUES (:id, :org_id, :account_id, :provider, :service_name, :region,
                               :cost_usd, :previous_cost_usd, :change_pct, :snapshot_date,
                               :anomaly, :anomaly_type, :created_at)""",
                    {**record, "anomaly": 1 if anomaly else 0},
                )

        # Auto-create anomaly record if detected
        if anomaly and anomaly_type:
            severity = "critical" if anomaly_type == "security_exposure" else (
                "high" if change_pct > 500 else "medium"
            )
            self.record_anomaly(org_id, {
                "account_id": record["account_id"],
                "service_name": record["service_name"],
                "cost_usd": cost_usd,
                "expected_usd": previous_cost_usd,
                "deviation_pct": change_pct,
                "anomaly_type": anomaly_type,
                "severity": severity,
            })

        return record

    def list_snapshots(
        self,
        org_id: str,
        account_id: Optional[str] = None,
        anomaly: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        """List cost snapshots with optional filters."""
        sql = "SELECT * FROM cost_snapshots WHERE org_id = ?"
        params: list = [org_id]
        if account_id is not None:
            sql += " AND account_id = ?"
            params.append(account_id)
        if anomaly is not None:
            sql += " AND anomaly = ?"
            params.append(1 if anomaly else 0)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    # ------------------------------------------------------------------
    # Abandoned Resources
    # ------------------------------------------------------------------

    def add_abandoned_resource(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register an abandoned/zombie/orphaned resource."""
        provider = data.get("provider", "aws")
        if provider not in _VALID_PROVIDERS:
            raise ValueError(f"Invalid provider: {provider}")

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "account_id": data.get("account_id", ""),
            "resource_id": data.get("resource_id", ""),
            "resource_type": data.get("resource_type", ""),
            "resource_name": data.get("resource_name", ""),
            "region": data.get("region", ""),
            "provider": provider,
            "last_used": data.get("last_used"),
            "monthly_cost_usd": float(data.get("monthly_cost_usd", 0.0)),
            "status": data.get("status", "active"),
            "security_risk": bool(data.get("security_risk", False)),
            "risk_reason": data.get("risk_reason", ""),
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO abandoned_resources
                       (id, org_id, account_id, resource_id, resource_type,
                        resource_name, region, provider, last_used, monthly_cost_usd,
                        status, security_risk, risk_reason, created_at)
                       VALUES (:id, :org_id, :account_id, :resource_id, :resource_type,
                               :resource_name, :region, :provider, :last_used, :monthly_cost_usd,
                               :status, :security_risk, :risk_reason, :created_at)""",
                    {**record, "security_risk": 1 if record["security_risk"] else 0},
                )
        return record

    def list_abandoned_resources(
        self,
        org_id: str,
        provider: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List abandoned resources with optional filters."""
        sql = "SELECT * FROM abandoned_resources WHERE org_id = ?"
        params: list = [org_id]
        if provider:
            sql += " AND provider = ?"
            params.append(provider)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY monthly_cost_usd DESC"
        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    def terminate_resource(self, org_id: str, resource_id: str) -> bool:
        """Mark a resource as terminated. Returns True if found."""
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    """UPDATE abandoned_resources SET status = 'terminated'
                       WHERE org_id = ? AND id = ?""",
                    (org_id, resource_id),
                )
                return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Budgets
    # ------------------------------------------------------------------

    def create_budget(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a cloud cost budget."""
        budget_name = (data.get("budget_name") or "").strip()
        if not budget_name:
            raise ValueError("budget_name is required.")

        period = data.get("period", "monthly")
        if period not in _VALID_BUDGET_PERIODS:
            raise ValueError(f"Invalid period: {period}")

        limit_usd = float(data.get("limit_usd", 0.0))
        current_spend_usd = float(data.get("current_spend_usd", 0.0))
        alert_threshold_pct = int(data.get("alert_threshold_pct", 80))

        # Compute status
        if limit_usd > 0:
            spend_pct = (current_spend_usd / limit_usd) * 100.0
            if spend_pct >= 100:
                status = "exceeded"
            elif spend_pct >= alert_threshold_pct:
                status = "warning"
            else:
                status = "ok"
        else:
            status = "ok"

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "account_id": data.get("account_id", ""),
            "budget_name": budget_name,
            "period": period,
            "limit_usd": limit_usd,
            "current_spend_usd": current_spend_usd,
            "alert_threshold_pct": alert_threshold_pct,
            "status": status,
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO cost_budgets
                       (id, org_id, account_id, budget_name, period, limit_usd,
                        current_spend_usd, alert_threshold_pct, status, created_at)
                       VALUES (:id, :org_id, :account_id, :budget_name, :period, :limit_usd,
                               :current_spend_usd, :alert_threshold_pct, :status, :created_at)""",
                    record,
                )
        return record

    def list_budgets(self, org_id: str) -> List[Dict[str, Any]]:
        """List all budgets for an org with computed status."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM cost_budgets WHERE org_id = ? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()

        result = []
        for row in rows:
            d = self._row(row)
            # Recompute status in case spend was updated externally
            limit = d.get("limit_usd", 0.0)
            spend = d.get("current_spend_usd", 0.0)
            threshold = d.get("alert_threshold_pct", 80)
            if limit > 0:
                spend_pct = (spend / limit) * 100.0
                if spend_pct >= 100:
                    d["status"] = "exceeded"
                elif spend_pct >= threshold:
                    d["status"] = "warning"
                else:
                    d["status"] = "ok"
            result.append(d)
        return result

    # ------------------------------------------------------------------
    # Cost Anomalies
    # ------------------------------------------------------------------

    def record_anomaly(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Save a cost anomaly record."""
        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            severity = "medium"

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "account_id": data.get("account_id", ""),
            "service_name": data.get("service_name", ""),
            "cost_usd": float(data.get("cost_usd", 0.0)),
            "expected_usd": float(data.get("expected_usd", 0.0)),
            "deviation_pct": float(data.get("deviation_pct", 0.0)),
            "anomaly_type": data.get("anomaly_type", "spike"),
            "severity": severity,
            "investigation_status": "open",
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO cost_anomalies
                       (id, org_id, account_id, service_name, cost_usd, expected_usd,
                        deviation_pct, anomaly_type, severity, investigation_status, created_at)
                       VALUES (:id, :org_id, :account_id, :service_name, :cost_usd, :expected_usd,
                               :deviation_pct, :anomaly_type, :severity, :investigation_status,
                               :created_at)""",
                    record,
                )
        return record

    def list_anomalies(
        self,
        org_id: str,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List anomalies with optional filters."""
        sql = "SELECT * FROM cost_anomalies WHERE org_id = ?"
        params: list = [org_id]
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        if status:
            sql += " AND investigation_status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    def resolve_anomaly(self, org_id: str, anomaly_id: str) -> bool:
        """Mark anomaly as resolved. Returns True if found."""
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    """UPDATE cost_anomalies SET investigation_status = 'resolved'
                       WHERE org_id = ? AND id = ?""",
                    (org_id, anomaly_id),
                )
                return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_cost_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated cost security stats for org."""
        today = _today_str()
        month_start = datetime.now(timezone.utc).strftime("%Y-%m-01")

        with self._conn() as conn:
            # Total spend this month (from snapshots)
            total_spend = conn.execute(
                """SELECT COALESCE(SUM(cost_usd), 0) FROM cost_snapshots
                   WHERE org_id = ? AND snapshot_date >= ?""",
                (org_id, month_start),
            ).fetchone()[0]

            # By provider
            prov_rows = conn.execute(
                """SELECT provider, COALESCE(SUM(cost_usd), 0) as spend
                   FROM cost_snapshots WHERE org_id = ? AND snapshot_date >= ?
                   GROUP BY provider""",
                (org_id, month_start),
            ).fetchall()
            by_provider = {r["provider"]: r["spend"] for r in prov_rows}

            # By service (top 10)
            svc_rows = conn.execute(
                """SELECT service_name, COALESCE(SUM(cost_usd), 0) as spend
                   FROM cost_snapshots WHERE org_id = ? AND snapshot_date >= ?
                   GROUP BY service_name ORDER BY spend DESC LIMIT 10""",
                (org_id, month_start),
            ).fetchall()
            by_service = {r["service_name"]: r["spend"] for r in svc_rows}

            # Anomalies this month
            anomalies_month = conn.execute(
                """SELECT COUNT(*) FROM cost_anomalies
                   WHERE org_id = ? AND created_at >= ?""",
                (org_id, month_start),
            ).fetchone()[0]

            # Abandoned resources count
            abandoned_count = conn.execute(
                """SELECT COUNT(*) FROM abandoned_resources
                   WHERE org_id = ? AND status = 'active'""",
                (org_id,),
            ).fetchone()[0]

            # Potential savings (sum of active abandoned resource monthly costs)
            potential_savings = conn.execute(
                """SELECT COALESCE(SUM(monthly_cost_usd), 0) FROM abandoned_resources
                   WHERE org_id = ? AND status = 'active'""",
                (org_id,),
            ).fetchone()[0]

            # Budgets exceeded
            budgets_exceeded = conn.execute(
                """SELECT COUNT(*) FROM cost_budgets
                   WHERE org_id = ? AND status = 'exceeded'""",
                (org_id,),
            ).fetchone()[0]

        return {
            "total_spend_this_month": round(total_spend, 2),
            "by_provider": by_provider,
            "by_service": by_service,
            "anomalies_this_month": anomalies_month,
            "abandoned_resources": abandoned_count,
            "potential_savings_usd": round(potential_savings, 2),
            "budgets_exceeded": budgets_exceeded,
        }
