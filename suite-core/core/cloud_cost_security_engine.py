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

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


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

                CREATE TABLE IF NOT EXISTS cost_items (
                    item_id              TEXT PRIMARY KEY,
                    org_id               TEXT NOT NULL,
                    cloud_provider       TEXT NOT NULL DEFAULT 'aws',
                    service              TEXT NOT NULL DEFAULT '',
                    resource_id          TEXT NOT NULL DEFAULT '',
                    monthly_cost_usd     REAL NOT NULL DEFAULT 0.0,
                    security_relevance   TEXT NOT NULL DEFAULT 'low',
                    tags                 TEXT NOT NULL DEFAULT '{}',
                    flagged              INTEGER NOT NULL DEFAULT 0,
                    flag_reason          TEXT NOT NULL DEFAULT '',
                    recorded_at          TEXT NOT NULL,
                    prev_monthly_cost    REAL NOT NULL DEFAULT 0.0
                );

                CREATE INDEX IF NOT EXISTS idx_ci_org_provider
                    ON cost_items (org_id, cloud_provider);
                CREATE INDEX IF NOT EXISTS idx_ci_org_resource
                    ON cost_items (org_id, resource_id);

                CREATE TABLE IF NOT EXISTS cost_policies (
                    policy_id        TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    name             TEXT NOT NULL DEFAULT '',
                    max_monthly_usd  REAL NOT NULL DEFAULT 0.0,
                    resource_type    TEXT NOT NULL DEFAULT '',
                    action           TEXT NOT NULL DEFAULT 'alert',
                    created_at       TEXT NOT NULL,
                    updated_at       TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_cp_org
                    ON cost_policies (org_id);
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

        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ASSET_DISCOVERED", {"entity_type": "cloud_cost_security", "org_id": org_id, "source_engine": "cloud_cost_security"})
            except Exception:
                pass

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
    # COST EXPLORER CONNECTOR FALLBACK (AWS Cost Explorer)
    # ------------------------------------------------------------------

    def list_snapshots_with_cost_explorer_fallback(
        self,
        org_id: str,
        account_id: Optional[str] = None,
        anomaly: Optional[bool] = None,
        cost_connector: Any = None,
    ) -> Dict[str, Any]:
        """List cost snapshots; fall back to AWS Cost Explorer live data.

        Behaviour (ranked):

        1. Org has recorded snapshots → ``source="org_registered"``.
        2. Else if AWS Cost Explorer connector is available *and* its env
           creds are present, call ``fetch_snapshots()`` and project each
           per-service row → ``source="aws_cost_explorer"``.
        3. Else if creds *or* boto3 are missing → ``source="needs_credentials"``
           with a structured hint. NEVER mocks.
        4. Connector returned ``status != "ok"`` → ``source="connector_error"``.
        5. Connector OK but returned zero rows → ``source="needs_data"``.

        Filters apply against the projected rows in modes 2/4/5 too. The
        ``anomaly`` filter against derived rows uses the spike threshold
        (>200% MoM change) defined at module scope.
        """
        if not isinstance(org_id, str) or not org_id.strip():
            raise ValueError("org_id is required")

        org_rows = self.list_snapshots(
            org_id, account_id=account_id, anomaly=anomaly,
        )
        if org_rows:
            return {
                "snapshots": org_rows,
                "total": len(org_rows),
                "source": "org_registered",
            }

        creds_present = False
        connector_unavailable_reason: Optional[str] = None
        if cost_connector is None:
            try:
                from connectors.aws_cost_explorer_connector import (  # type: ignore
                    _creds_present,
                    get_aws_cost_explorer_connector,
                )
                creds_present = bool(_creds_present())
                if creds_present:
                    cost_connector = get_aws_cost_explorer_connector()
            except (ImportError, RuntimeError) as exc:
                connector_unavailable_reason = f"connector_import_failed: {exc}"
        else:
            creds_present = True

        if not creds_present or cost_connector is None:
            return {
                "snapshots": [],
                "total": 0,
                "source": "needs_credentials",
                "hint": (
                    "Set AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY (or "
                    "AWS_PROFILE / IAM instance role / EKS pod identity) to "
                    "enable AWS Cost Explorer ingestion, or POST "
                    "/api/v1/cloud-cost/snapshots to record a snapshot manually."
                ),
                **({"reason": connector_unavailable_reason}
                   if connector_unavailable_reason else {}),
            }

        try:
            payload = cost_connector.fetch_snapshots(org_id)
        except Exception as exc:  # noqa: BLE001
            _logger.warning(
                "AWSCostExplorer fetch failed for org=%s: %s", org_id, exc,
            )
            return {
                "snapshots": [],
                "total": 0,
                "source": "connector_error",
                "error": str(exc)[:500],
            }

        connector_status = (payload or {}).get("status", "")
        if connector_status == "needs_credentials":
            return {
                "snapshots": [],
                "total": 0,
                "source": "needs_credentials",
                "hint": payload.get("hint", "AWS credentials missing."),
                **({"reason": payload["reason"]}
                   if payload.get("reason") else {}),
            }
        if connector_status != "ok":
            return {
                "snapshots": [],
                "total": 0,
                "source": "connector_error",
                "error": str(payload.get("error") or connector_status)[:500],
            }

        derived: List[Dict[str, Any]] = []
        for snap in payload.get("snapshots") or []:
            change_pct = float(snap.get("change_pct") or 0.0)
            is_spike = change_pct > _SPIKE_THRESHOLD_PCT
            row = {
                "id": (
                    f"awsce:{snap.get('account_id', '')}:"
                    f"{snap.get('service_name', '')}:"
                    f"{snap.get('region', '')}:"
                    f"{snap.get('snapshot_date', '')}"
                ),
                "org_id": org_id,
                "account_id": snap.get("account_id", ""),
                "provider": "aws",
                "service_name": snap.get("service_name", ""),
                "region": snap.get("region", ""),
                "cost_usd": float(snap.get("cost_usd", 0.0)),
                "previous_cost_usd": float(snap.get("previous_cost_usd", 0.0)),
                "change_pct": change_pct,
                "snapshot_date": snap.get("snapshot_date", ""),
                "anomaly": 1 if is_spike else 0,
                "anomaly_type": "spike" if is_spike else None,
                "created_at": payload.get("ingested_at"),
                "source": "aws_cost_explorer",
            }
            derived.append(row)

        if account_id is not None:
            derived = [d for d in derived if d["account_id"] == account_id]
        if anomaly is not None:
            wanted = 1 if anomaly else 0
            derived = [d for d in derived if d["anomaly"] == wanted]

        if not derived:
            return {
                "snapshots": [],
                "total": 0,
                "source": "needs_data",
                "hint": (
                    "AWS Cost Explorer reachable but returned no snapshots "
                    "matching the requested filters."
                ),
            }

        return {
            "snapshots": derived,
            "total": len(derived),
            "source": "aws_cost_explorer",
        }

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
        _today_str()
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

    # ------------------------------------------------------------------
    # Cost Items (security-lens resource tracking)
    # ------------------------------------------------------------------

    def record_cost_item(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a cloud resource cost item with security relevance tagging.

        Fields: cloud_provider(aws/azure/gcp), service, resource_id,
                monthly_cost_usd, security_relevance(high/medium/low), tags.
        """
        provider = data.get("cloud_provider", "aws")
        if provider not in _VALID_PROVIDERS:
            provider = "aws"
        relevance = data.get("security_relevance", "low")
        if relevance not in {"high", "medium", "low"}:
            relevance = "low"
        monthly_cost = float(data.get("monthly_cost_usd", 0.0))
        resource_id = str(data.get("resource_id", ""))
        tags = data.get("tags", {})
        if not isinstance(tags, dict):
            tags = {}

        # Look up previous cost for the resource to enable MoM anomaly detection
        prev_cost = 0.0
        with self._lock:
            with self._conn() as conn:
                prev_row = conn.execute(
                    "SELECT monthly_cost_usd FROM cost_items "
                    "WHERE org_id=? AND resource_id=? ORDER BY recorded_at DESC LIMIT 1",
                    (org_id, resource_id),
                ).fetchone()
                if prev_row:
                    prev_cost = float(prev_row["monthly_cost_usd"])

            item_id = str(uuid.uuid4())
            now = _now_iso()
            record: Dict[str, Any] = {
                "item_id": item_id,
                "org_id": org_id,
                "cloud_provider": provider,
                "service": str(data.get("service", "")),
                "resource_id": resource_id,
                "monthly_cost_usd": monthly_cost,
                "security_relevance": relevance,
                "tags": json.dumps(tags),
                "flagged": 0,
                "flag_reason": "",
                "recorded_at": now,
                "prev_monthly_cost": prev_cost,
            }
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO cost_items
                       (item_id, org_id, cloud_provider, service, resource_id,
                        monthly_cost_usd, security_relevance, tags, flagged,
                        flag_reason, recorded_at, prev_monthly_cost)
                       VALUES
                       (:item_id,:org_id,:cloud_provider,:service,:resource_id,
                        :monthly_cost_usd,:security_relevance,:tags,:flagged,
                        :flag_reason,:recorded_at,:prev_monthly_cost)""",
                    record,
                )
        return self._fmt_cost_item(record)

    def list_cost_items(
        self,
        org_id: str,
        cloud_provider: Optional[str] = None,
        security_relevance: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List cost items with optional provider/relevance filters."""
        sql = "SELECT * FROM cost_items WHERE org_id=?"
        params: list = [org_id]
        if cloud_provider:
            sql += " AND cloud_provider=?"
            params.append(cloud_provider)
        if security_relevance:
            sql += " AND security_relevance=?"
            params.append(security_relevance)
        sql += " ORDER BY recorded_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._fmt_cost_item(dict(r)) for r in rows]

    def flag_unused_resource(self, org_id: str, resource_id: str, reason: str) -> dict:
        """Flag a resource for decommission review."""
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    "UPDATE cost_items SET flagged=1, flag_reason=? "
                    "WHERE org_id=? AND resource_id=?",
                    (reason, org_id, resource_id),
                )
                row = conn.execute(
                    "SELECT * FROM cost_items WHERE org_id=? AND resource_id=? "
                    "ORDER BY recorded_at DESC LIMIT 1",
                    (org_id, resource_id),
                ).fetchone()
        if not row:
            return {"flagged": False, "resource_id": resource_id, "reason": reason}
        return {**self._fmt_cost_item(dict(row)), "flagged": True, "flag_reason": reason}

    def get_security_spend_breakdown(self, org_id: str) -> Dict[str, Any]:
        """Break down cloud spend by provider and service with security tool %."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT cloud_provider, service, security_relevance, "
                "SUM(monthly_cost_usd) as total "
                "FROM cost_items WHERE org_id=? "
                "GROUP BY cloud_provider, service, security_relevance",
                (org_id,),
            ).fetchall()

        by_provider: Dict[str, float] = {}
        by_service: Dict[str, float] = {}
        total = 0.0
        security_tool_spend = 0.0

        for r in rows:
            prov = r["cloud_provider"]
            svc = r["service"]
            amt = float(r["total"])
            rel = r["security_relevance"]
            by_provider[prov] = by_provider.get(prov, 0.0) + amt
            by_service[svc] = by_service.get(svc, 0.0) + amt
            total += amt
            if rel == "high":
                security_tool_spend += amt

        security_tool_pct = round((security_tool_spend / total * 100) if total > 0 else 0.0, 2)
        return {
            "org_id": org_id,
            "total_monthly_usd": round(total, 2),
            "by_provider": {k: round(v, 2) for k, v in by_provider.items()},
            "by_service": {k: round(v, 2) for k, v in by_service.items()},
            "security_tool_spend_usd": round(security_tool_spend, 2),
            "security_tool_pct": security_tool_pct,
        }

    def detect_cost_anomalies(self, org_id: str) -> List[Dict[str, Any]]:
        """Return resources with cost spike >50% month-over-month."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM cost_items WHERE org_id=? AND prev_monthly_cost > 0",
                (org_id,),
            ).fetchall()

        anomalies = []
        for r in rows:
            prev = float(r["prev_monthly_cost"])
            curr = float(r["monthly_cost_usd"])
            if prev > 0 and curr > 0:
                pct_change = (curr - prev) / prev * 100
                if pct_change > 50:
                    anomalies.append({
                        **self._fmt_cost_item(dict(r)),
                        "prev_monthly_cost_usd": round(prev, 2),
                        "pct_increase": round(pct_change, 2),
                    })
        return anomalies

    # ------------------------------------------------------------------
    # Cost Policies
    # ------------------------------------------------------------------

    def create_cost_policy(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a cost enforcement policy (alert/block/flag)."""
        action = data.get("action", "alert")
        if action not in {"alert", "block", "flag"}:
            action = "alert"
        policy_id = str(uuid.uuid4())
        now = _now_iso()
        record: Dict[str, Any] = {
            "policy_id": policy_id,
            "org_id": org_id,
            "name": str(data.get("name", "")),
            "max_monthly_usd": float(data.get("max_monthly_usd", 0.0)),
            "resource_type": str(data.get("resource_type", "")),
            "action": action,
            "created_at": now,
            "updated_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO cost_policies
                       (policy_id, org_id, name, max_monthly_usd, resource_type,
                        action, created_at, updated_at)
                       VALUES
                       (:policy_id,:org_id,:name,:max_monthly_usd,:resource_type,
                        :action,:created_at,:updated_at)""",
                    record,
                )
        return record

    def list_cost_policies(self, org_id: str) -> List[Dict[str, Any]]:
        """List all cost policies for the org."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM cost_policies WHERE org_id=? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _fmt_cost_item(row: Dict[str, Any]) -> Dict[str, Any]:
        tags = row.get("tags", "{}")
        if isinstance(tags, str):
            try:
                tags = json.loads(tags)
            except (json.JSONDecodeError, TypeError):
                tags = {}
        return {
            "item_id": row.get("item_id", ""),
            "org_id": row.get("org_id", ""),
            "cloud_provider": row.get("cloud_provider", ""),
            "service": row.get("service", ""),
            "resource_id": row.get("resource_id", ""),
            "monthly_cost_usd": float(row.get("monthly_cost_usd", 0.0)),
            "security_relevance": row.get("security_relevance", "low"),
            "tags": tags,
            "flagged": bool(row.get("flagged", 0)),
            "flag_reason": row.get("flag_reason", ""),
            "recorded_at": row.get("recorded_at", ""),
            "prev_monthly_cost_usd": float(row.get("prev_monthly_cost", 0.0)),
        }
