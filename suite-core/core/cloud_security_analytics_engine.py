"""Cloud Security Analytics Engine — ALDECI.

Ingests cloud security events, detects anomalies, and manages detection rules.
Multi-tenant via org_id. SQLite WAL + threading.RLock for concurrency safety.
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

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "cloud_security_analytics.db"
)

_VALID_EVENT_SOURCES = {
    "cloudtrail", "azure_monitor", "gcp_audit", "kubernetes", "lambda",
    "container", "vpc_flow", "config_rule", "guardduty", "defender",
}
_VALID_EVENT_TYPES = {
    "api_call", "resource_change", "auth_event", "network_event",
    "data_access", "policy_change", "anomaly", "threat_detection",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_ANOMALY_TYPES = {
    "unusual_api", "impossible_travel", "privilege_abuse", "data_exfil_attempt",
    "crypto_mining", "lateral_movement", "resource_creation_spike", "time_anomaly",
}
_VALID_ANOMALY_STATUSES = {"open", "investigating", "confirmed", "false_positive"}
_VALID_RULE_TYPES = {"detection", "compliance", "baseline", "anomaly"}


class CloudSecurityAnalyticsEngine:
    """SQLite WAL-backed Cloud Security Analytics engine.

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
                CREATE TABLE IF NOT EXISTS csa_events (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    event_source   TEXT NOT NULL DEFAULT 'cloudtrail',
                    event_type     TEXT NOT NULL DEFAULT 'api_call',
                    severity       TEXT NOT NULL DEFAULT 'low',
                    account_id     TEXT NOT NULL DEFAULT '',
                    region         TEXT NOT NULL DEFAULT '',
                    resource_type  TEXT NOT NULL DEFAULT '',
                    resource_id    TEXT NOT NULL DEFAULT '',
                    actor          TEXT NOT NULL DEFAULT '',
                    risk_score     REAL NOT NULL DEFAULT 0.0,
                    details        TEXT NOT NULL DEFAULT '',
                    event_at       DATETIME,
                    created_at     DATETIME NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_csa_events_org
                    ON csa_events (org_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS csa_anomalies (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    anomaly_type        TEXT NOT NULL DEFAULT 'unusual_api',
                    severity            TEXT NOT NULL DEFAULT 'medium',
                    account_id          TEXT NOT NULL DEFAULT '',
                    confidence_score    REAL NOT NULL DEFAULT 0.0,
                    affected_resources  TEXT NOT NULL DEFAULT '[]',
                    status              TEXT NOT NULL DEFAULT 'open',
                    detected_at         DATETIME,
                    created_at          DATETIME NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_csa_anomalies_org
                    ON csa_anomalies (org_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS csa_rules (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    rule_name      TEXT NOT NULL DEFAULT '',
                    rule_type      TEXT NOT NULL DEFAULT 'detection',
                    condition      TEXT NOT NULL DEFAULT '',
                    severity       TEXT NOT NULL DEFAULT 'medium',
                    event_sources  TEXT NOT NULL DEFAULT '[]',
                    enabled        INTEGER NOT NULL DEFAULT 1,
                    match_count    INTEGER NOT NULL DEFAULT 0,
                    created_at     DATETIME NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_csa_rules_org
                    ON csa_rules (org_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _deserialize_anomaly(row: Dict[str, Any]) -> Dict[str, Any]:
        try:
            row["affected_resources"] = json.loads(row.get("affected_resources") or "[]")
        except (json.JSONDecodeError, TypeError):
            row["affected_resources"] = []
        return row

    @staticmethod
    def _deserialize_rule(row: Dict[str, Any]) -> Dict[str, Any]:
        try:
            row["event_sources"] = json.loads(row.get("event_sources") or "[]")
        except (json.JSONDecodeError, TypeError):
            row["event_sources"] = []
        row["enabled"] = bool(row.get("enabled", 1))
        return row

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    def record_event(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a cloud security event."""
        event_source = data.get("event_source", "cloudtrail")
        if event_source not in _VALID_EVENT_SOURCES:
            raise ValueError(f"Invalid event_source: {event_source}")
        event_type = data.get("event_type", "api_call")
        if event_type not in _VALID_EVENT_TYPES:
            raise ValueError(f"Invalid event_type: {event_type}")
        severity = data.get("severity", "low")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {severity}")

        risk_score = float(data.get("risk_score", 0.0))
        risk_score = max(0.0, min(100.0, risk_score))

        event_id = str(uuid.uuid4())
        now = self._now()

        row = {
            "id": event_id,
            "org_id": org_id,
            "event_source": event_source,
            "event_type": event_type,
            "severity": severity,
            "account_id": data.get("account_id", ""),
            "region": data.get("region", ""),
            "resource_type": data.get("resource_type", ""),
            "resource_id": data.get("resource_id", ""),
            "actor": data.get("actor", ""),
            "risk_score": risk_score,
            "details": data.get("details", ""),
            "event_at": data.get("event_at", now),
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO csa_events
                       (id, org_id, event_source, event_type, severity, account_id, region,
                        resource_type, resource_id, actor, risk_score, details, event_at, created_at)
                       VALUES (:id, :org_id, :event_source, :event_type, :severity, :account_id,
                               :region, :resource_type, :resource_id, :actor, :risk_score,
                               :details, :event_at, :created_at)""",
                    row,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ASSET_DISCOVERED", {"entity_type": "cloud_security_analytics", "org_id": org_id, "source_engine": "cloud_security_analytics"})
            except Exception:
                pass

        return dict(row)

    def list_events(
        self,
        org_id: str,
        event_source: Optional[str] = None,
        severity: Optional[str] = None,
        event_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List events with optional filters."""
        sql = "SELECT * FROM csa_events WHERE org_id=?"
        params: list = [org_id]
        if event_source:
            sql += " AND event_source=?"
            params.append(event_source)
        if severity:
            sql += " AND severity=?"
            params.append(severity)
        if event_type:
            sql += " AND event_type=?"
            params.append(event_type)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Anomalies
    # ------------------------------------------------------------------

    def record_anomaly(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a detected cloud security anomaly."""
        anomaly_type = data.get("anomaly_type", "unusual_api")
        if anomaly_type not in _VALID_ANOMALY_TYPES:
            raise ValueError(f"Invalid anomaly_type: {anomaly_type}")
        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {severity}")

        confidence = float(data.get("confidence_score", 0.0))
        confidence = max(0.0, min(100.0, confidence))

        anomaly_id = str(uuid.uuid4())
        now = self._now()
        affected_resources = json.dumps(data.get("affected_resources", []))

        row = {
            "id": anomaly_id,
            "org_id": org_id,
            "anomaly_type": anomaly_type,
            "severity": severity,
            "account_id": data.get("account_id", ""),
            "confidence_score": confidence,
            "affected_resources": affected_resources,
            "status": data.get("status", "open"),
            "detected_at": data.get("detected_at", now),
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO csa_anomalies
                       (id, org_id, anomaly_type, severity, account_id, confidence_score,
                        affected_resources, status, detected_at, created_at)
                       VALUES (:id, :org_id, :anomaly_type, :severity, :account_id,
                               :confidence_score, :affected_resources, :status,
                               :detected_at, :created_at)""",
                    row,
                )
        result = dict(row)
        result["affected_resources"] = data.get("affected_resources", [])
        return result

    def list_anomalies(
        self,
        org_id: str,
        anomaly_type: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List anomalies with optional filters; deserializes affected_resources."""
        sql = "SELECT * FROM csa_anomalies WHERE org_id=?"
        params: list = [org_id]
        if anomaly_type:
            sql += " AND anomaly_type=?"
            params.append(anomaly_type)
        if severity:
            sql += " AND severity=?"
            params.append(severity)
        if status:
            sql += " AND status=?"
            params.append(status)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._deserialize_anomaly(self._row(r)) for r in rows]

    def update_anomaly_status(self, org_id: str, anomaly_id: str, status: str) -> Dict[str, Any]:
        """Update anomaly status."""
        if status not in _VALID_ANOMALY_STATUSES:
            raise ValueError(f"Invalid status: {status}")
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    "UPDATE csa_anomalies SET status=? WHERE id=? AND org_id=?",
                    (status, anomaly_id, org_id),
                )
                row = conn.execute(
                    "SELECT * FROM csa_anomalies WHERE id=? AND org_id=?", (anomaly_id, org_id)
                ).fetchone()
        if row is None:
            raise KeyError(f"Anomaly {anomaly_id} not found for org {org_id}")
        return self._deserialize_anomaly(self._row(row))

    # ------------------------------------------------------------------
    # Rules
    # ------------------------------------------------------------------

    def create_rule(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a detection/compliance/baseline/anomaly rule."""
        rule_type = data.get("rule_type", "detection")
        if rule_type not in _VALID_RULE_TYPES:
            raise ValueError(f"Invalid rule_type: {rule_type}")
        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {severity}")

        rule_id = str(uuid.uuid4())
        now = self._now()
        event_sources = json.dumps(data.get("event_sources", []))
        enabled = 1 if data.get("enabled", True) else 0

        row = {
            "id": rule_id,
            "org_id": org_id,
            "rule_name": data.get("rule_name", ""),
            "rule_type": rule_type,
            "condition": data.get("condition", ""),
            "severity": severity,
            "event_sources": event_sources,
            "enabled": enabled,
            "match_count": 0,
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO csa_rules
                       (id, org_id, rule_name, rule_type, condition, severity,
                        event_sources, enabled, match_count, created_at)
                       VALUES (:id, :org_id, :rule_name, :rule_type, :condition, :severity,
                               :event_sources, :enabled, :match_count, :created_at)""",
                    row,
                )
        result = dict(row)
        result["event_sources"] = data.get("event_sources", [])
        result["enabled"] = bool(enabled)
        return result

    def trigger_rule(self, org_id: str, rule_id: str) -> Dict[str, Any]:
        """Increment match_count for a rule."""
        with self._lock:
            with self._conn() as conn:
                existing = conn.execute(
                    "SELECT * FROM csa_rules WHERE id=? AND org_id=?", (rule_id, org_id)
                ).fetchone()
                if existing is None:
                    raise KeyError(f"Rule {rule_id} not found for org {org_id}")
                conn.execute(
                    "UPDATE csa_rules SET match_count = match_count + 1 WHERE id=? AND org_id=?",
                    (rule_id, org_id),
                )
                updated = conn.execute(
                    "SELECT * FROM csa_rules WHERE id=? AND org_id=?", (rule_id, org_id)
                ).fetchone()
                return self._deserialize_rule(self._row(updated))

    def list_rules(
        self,
        org_id: str,
        rule_type: Optional[str] = None,
        enabled: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        """List rules with optional filters; deserializes event_sources."""
        sql = "SELECT * FROM csa_rules WHERE org_id=?"
        params: list = [org_id]
        if rule_type:
            sql += " AND rule_type=?"
            params.append(rule_type)
        if enabled is not None:
            sql += " AND enabled=?"
            params.append(1 if enabled else 0)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._deserialize_rule(self._row(r)) for r in rows]

    # ------------------------------------------------------------------
    # CloudTrail Replay
    # ------------------------------------------------------------------

    def replay_cloudtrail(
        self,
        org_id: str,
        events: List[Dict[str, Any]],
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """Replay a batch of CloudTrail-format events into the analytics store.

        Each item in *events* must be a dict that maps to the csa_events schema.
        If ``dry_run`` is True, events are validated but not persisted.

        Returns a summary: total, ingested, skipped, errors.
        """
        ingested: List[str] = []
        skipped: int = 0
        errors: List[Dict[str, Any]] = []

        for idx, raw in enumerate(events):
            # Normalise: cloudtrail JSON uses camelCase — map common keys
            normalised: Dict[str, Any] = {
                "event_source": raw.get("event_source") or raw.get("eventSource", "cloudtrail"),
                "event_type": raw.get("event_type") or raw.get("eventType", "api_call"),
                "severity": raw.get("severity", "low"),
                "account_id": raw.get("account_id") or raw.get("userIdentity", {}).get("accountId", ""),
                "region": raw.get("region") or raw.get("awsRegion", ""),
                "resource_type": raw.get("resource_type") or raw.get("resourceType", ""),
                "resource_id": raw.get("resource_id") or raw.get("resourceId", ""),
                "actor": raw.get("actor") or raw.get("userIdentity", {}).get("arn", ""),
                "risk_score": float(raw.get("risk_score", 0.0)),
                "details": raw.get("details") or raw.get("requestParameters", ""),
                "event_at": raw.get("event_at") or raw.get("eventTime"),
            }

            # Validate event_source
            if normalised["event_source"] not in _VALID_EVENT_SOURCES:
                errors.append({"index": idx, "reason": f"invalid event_source: {normalised['event_source']}"})
                continue
            # Validate event_type
            if normalised["event_type"] not in _VALID_EVENT_TYPES:
                errors.append({"index": idx, "reason": f"invalid event_type: {normalised['event_type']}"})
                continue
            # Validate severity
            if normalised["severity"] not in _VALID_SEVERITIES:
                errors.append({"index": idx, "reason": f"invalid severity: {normalised['severity']}"})
                continue

            if dry_run:
                ingested.append(f"<dry-run-{idx}>")
                continue

            try:
                result = self.record_event(org_id, normalised)
                ingested.append(result["id"])
            except Exception as exc:  # pragma: no cover
                errors.append({"index": idx, "reason": str(exc)})

        return {
            "org_id": org_id,
            "dry_run": dry_run,
            "total": len(events),
            "ingested": len(ingested),
            "skipped": skipped,
            "errors": errors,
            "event_ids": ingested,
        }

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_analytics_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate analytics statistics for an org."""
        with self._conn() as conn:
            total_events = conn.execute(
                "SELECT COUNT(*) FROM csa_events WHERE org_id=?", (org_id,)
            ).fetchone()[0]
            critical_events = conn.execute(
                "SELECT COUNT(*) FROM csa_events WHERE org_id=? AND severity='critical'",
                (org_id,),
            ).fetchone()[0]
            avg_risk = conn.execute(
                "SELECT AVG(risk_score) FROM csa_events WHERE org_id=?", (org_id,)
            ).fetchone()[0]
            total_anomalies = conn.execute(
                "SELECT COUNT(*) FROM csa_anomalies WHERE org_id=?", (org_id,)
            ).fetchone()[0]
            open_anomalies = conn.execute(
                "SELECT COUNT(*) FROM csa_anomalies WHERE org_id=? AND status='open'",
                (org_id,),
            ).fetchone()[0]
            total_rules = conn.execute(
                "SELECT COUNT(*) FROM csa_rules WHERE org_id=?", (org_id,)
            ).fetchone()[0]
            enabled_rules = conn.execute(
                "SELECT COUNT(*) FROM csa_rules WHERE org_id=? AND enabled=1", (org_id,)
            ).fetchone()[0]

            by_event_source_rows = conn.execute(
                "SELECT event_source, COUNT(*) AS cnt FROM csa_events WHERE org_id=? GROUP BY event_source",
                (org_id,),
            ).fetchall()
            by_anomaly_type_rows = conn.execute(
                "SELECT anomaly_type, COUNT(*) AS cnt FROM csa_anomalies WHERE org_id=? GROUP BY anomaly_type",
                (org_id,),
            ).fetchall()
            by_severity_rows = conn.execute(
                "SELECT severity, COUNT(*) AS cnt FROM csa_events WHERE org_id=? GROUP BY severity",
                (org_id,),
            ).fetchall()

        return {
            "total_events": total_events,
            "critical_events": critical_events,
            "total_anomalies": total_anomalies,
            "open_anomalies": open_anomalies,
            "total_rules": total_rules,
            "enabled_rules": enabled_rules,
            "avg_risk_score": round(avg_risk or 0.0, 2),
            "by_event_source": {r["event_source"]: r["cnt"] for r in by_event_source_rows},
            "by_anomaly_type": {r["anomaly_type"]: r["cnt"] for r in by_anomaly_type_rows},
            "by_severity": {r["severity"]: r["cnt"] for r in by_severity_rows},
        }
