"""APIAbuseDetectionEngine — ALDECI.

Detects and manages API abuse patterns including credential stuffing, scraping,
DoS, parameter tampering, BOLA, and bot traffic.

Features:
- Endpoint registration and monitoring
- Abuse incident recording with source IP and request counts
- Rule-based detection (rate limit, IP block, geo block, pattern match, anomaly)
- Stats: abuse score trends, incident breakdown, endpoint health

SQLite WAL + threading.RLock + multi-tenant org_id isolation.
DB at .fixops_data/api_abuse_detection.db.

Compliance: OWASP API Security Top 10, NIST SP 800-95.
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "api_abuse_detection.db"
)

VALID_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})
VALID_ENDPOINT_STATUSES = frozenset({"monitored", "unmonitored", "blocked"})

VALID_ABUSE_TYPES = frozenset({
    "credential_stuffing", "scraping", "dos", "parameter_tampering",
    "bola", "broken_auth", "rate_limit_abuse", "bot_traffic", "data_harvesting",
})
VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low"})
VALID_INCIDENT_STATUSES = frozenset({"open", "investigating", "resolved", "false_positive"})

VALID_RULE_TYPES = frozenset({"rate_limit", "ip_block", "geo_block", "user_agent", "pattern_match", "anomaly"})
VALID_ACTIONS = frozenset({"block", "alert", "throttle", "log"})


class APIAbuseDetectionEngine:
    """SQLite-backed API abuse detection engine. Thread-safe, multi-tenant."""

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db_path = db_path
        self._lock = threading.RLock()
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ------------------------------------------------------------------
    # DB INIT
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript("""
                PRAGMA journal_mode=WAL;

                CREATE TABLE IF NOT EXISTS aad_endpoints (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    path         TEXT NOT NULL,
                    method       TEXT NOT NULL,
                    service_name TEXT NOT NULL DEFAULT '',
                    rate_limit   INTEGER NOT NULL DEFAULT 1000,
                    abuse_score  REAL NOT NULL DEFAULT 0.0,
                    status       TEXT NOT NULL DEFAULT 'monitored',
                    created_at   TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_aad_endpoints_org ON aad_endpoints(org_id);

                CREATE TABLE IF NOT EXISTS aad_incidents (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    endpoint_id         TEXT NOT NULL,
                    abuse_type          TEXT NOT NULL,
                    severity            TEXT NOT NULL,
                    source_ip           TEXT,
                    request_count       INTEGER NOT NULL DEFAULT 0,
                    time_window_seconds INTEGER NOT NULL DEFAULT 60,
                    blocked             INTEGER NOT NULL DEFAULT 0,
                    status              TEXT NOT NULL DEFAULT 'open',
                    detected_at         TEXT NOT NULL,
                    created_at          TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_aad_incidents_org ON aad_incidents(org_id);
                CREATE INDEX IF NOT EXISTS idx_aad_incidents_ep  ON aad_incidents(endpoint_id);

                CREATE TABLE IF NOT EXISTS aad_rules (
                    id         TEXT PRIMARY KEY,
                    org_id     TEXT NOT NULL,
                    rule_name  TEXT NOT NULL,
                    rule_type  TEXT NOT NULL,
                    threshold  REAL NOT NULL DEFAULT 0.0,
                    action     TEXT NOT NULL,
                    enabled    INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_aad_rules_org ON aad_rules(org_id);
            """)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # ENDPOINTS
    # ------------------------------------------------------------------

    def register_endpoint(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register an API endpoint for monitoring. Returns the endpoint record."""
        path = data.get("path", "").strip()
        if not path:
            raise ValueError("path is required")

        method = data.get("method", "").upper()
        if method not in VALID_METHODS:
            raise ValueError(f"method must be one of {sorted(VALID_METHODS)}, got '{method}'")

        status = data.get("status", "monitored").lower()
        if status not in VALID_ENDPOINT_STATUSES:
            raise ValueError(f"status must be one of {sorted(VALID_ENDPOINT_STATUSES)}, got '{status}'")

        endpoint_id = str(uuid.uuid4())
        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO aad_endpoints
                   (id, org_id, path, method, service_name, rate_limit, abuse_score, status, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    endpoint_id, org_id, path, method,
                    data.get("service_name", ""),
                    int(data.get("rate_limit", 1000)),
                    float(data.get("abuse_score", 0.0)),
                    status, now,
                ),
            )
        _logger.info("aad.endpoint_registered org=%s endpoint_id=%s path=%s", org_id, endpoint_id, path)
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("THREAT_DETECTED", {"entity_type": "api_abuse_detection", "org_id": org_id, "source_engine": "api_abuse_detection"})
            except Exception:
                pass

        return self.get_endpoint(org_id, endpoint_id)

    def list_endpoints(
        self,
        org_id: str,
        service_name: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List endpoints for org, optionally filtered."""
        query = "SELECT * FROM aad_endpoints WHERE org_id=?"
        params: List[Any] = [org_id]
        if service_name:
            query += " AND service_name=?"
            params.append(service_name)
        if status:
            query += " AND status=?"
            params.append(status)
        query += " ORDER BY created_at DESC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_endpoint(self, org_id: str, endpoint_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single endpoint scoped to org_id. Returns None if not found."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM aad_endpoints WHERE org_id=? AND id=?",
                (org_id, endpoint_id),
            ).fetchone()
        return dict(row) if row else None

    # ------------------------------------------------------------------
    # INCIDENTS
    # ------------------------------------------------------------------

    def record_incident(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record an abuse incident. Returns the incident record."""
        endpoint_id = data.get("endpoint_id", "").strip()
        if not endpoint_id:
            raise ValueError("endpoint_id is required")

        # Verify endpoint belongs to org
        endpoint = self.get_endpoint(org_id, endpoint_id)
        if not endpoint:
            raise ValueError(f"Endpoint {endpoint_id} not found for org {org_id}")

        abuse_type = data.get("abuse_type", "").lower()
        if abuse_type not in VALID_ABUSE_TYPES:
            raise ValueError(f"abuse_type must be one of {sorted(VALID_ABUSE_TYPES)}, got '{abuse_type}'")

        severity = data.get("severity", "").lower()
        if severity not in VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(VALID_SEVERITIES)}, got '{severity}'")

        incident_id = str(uuid.uuid4())
        now = self._now()
        blocked_val = 1 if data.get("blocked", False) else 0
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO aad_incidents
                   (id, org_id, endpoint_id, abuse_type, severity, source_ip,
                    request_count, time_window_seconds, blocked, status, detected_at, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    incident_id, org_id, endpoint_id, abuse_type, severity,
                    data.get("source_ip"),
                    int(data.get("request_count", 0)),
                    int(data.get("time_window_seconds", 60)),
                    blocked_val,
                    data.get("status", "open"),
                    data.get("detected_at", now), now,
                ),
            )
        _logger.info("aad.incident_recorded org=%s incident_id=%s type=%s", org_id, incident_id, abuse_type)
        return self._get_incident(org_id, incident_id)

    def list_incidents(
        self,
        org_id: str,
        endpoint_id: Optional[str] = None,
        abuse_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List incidents for org, optionally filtered."""
        query = "SELECT * FROM aad_incidents WHERE org_id=?"
        params: List[Any] = [org_id]
        if endpoint_id:
            query += " AND endpoint_id=?"
            params.append(endpoint_id)
        if abuse_type:
            query += " AND abuse_type=?"
            params.append(abuse_type)
        if status:
            query += " AND status=?"
            params.append(status)
        query += " ORDER BY created_at DESC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def update_incident_status(
        self,
        org_id: str,
        incident_id: str,
        status: str,
    ) -> Dict[str, Any]:
        """Update incident status. Returns updated record."""
        if status not in VALID_INCIDENT_STATUSES:
            raise ValueError(f"status must be one of {sorted(VALID_INCIDENT_STATUSES)}, got '{status}'")
        existing = self._get_incident(org_id, incident_id)
        if not existing:
            raise ValueError(f"Incident {incident_id} not found for org {org_id}")
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE aad_incidents SET status=? WHERE org_id=? AND id=?",
                (status, org_id, incident_id),
            )
        _logger.info("aad.incident_status_updated org=%s incident_id=%s status=%s", org_id, incident_id, status)
        return self._get_incident(org_id, incident_id)

    def _get_incident(self, org_id: str, incident_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM aad_incidents WHERE org_id=? AND id=?",
                (org_id, incident_id),
            ).fetchone()
        return dict(row) if row else None

    # ------------------------------------------------------------------
    # RULES
    # ------------------------------------------------------------------

    def create_rule(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a detection rule. Returns the rule record."""
        rule_name = data.get("rule_name", "").strip()
        if not rule_name:
            raise ValueError("rule_name is required")

        rule_type = data.get("rule_type", "").lower()
        if rule_type not in VALID_RULE_TYPES:
            raise ValueError(f"rule_type must be one of {sorted(VALID_RULE_TYPES)}, got '{rule_type}'")

        action = data.get("action", "").lower()
        if action not in VALID_ACTIONS:
            raise ValueError(f"action must be one of {sorted(VALID_ACTIONS)}, got '{action}'")

        rule_id = str(uuid.uuid4())
        now = self._now()
        enabled_val = 0 if data.get("enabled", True) is False else 1
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO aad_rules
                   (id, org_id, rule_name, rule_type, threshold, action, enabled, created_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    rule_id, org_id, rule_name, rule_type,
                    float(data.get("threshold", 0.0)),
                    action, enabled_val, now,
                ),
            )
        _logger.info("aad.rule_created org=%s rule_id=%s type=%s", org_id, rule_id, rule_type)
        return self._get_rule(org_id, rule_id)

    def list_rules(
        self,
        org_id: str,
        rule_type: Optional[str] = None,
        enabled: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        """List rules for org, optionally filtered."""
        query = "SELECT * FROM aad_rules WHERE org_id=?"
        params: List[Any] = [org_id]
        if rule_type:
            query += " AND rule_type=?"
            params.append(rule_type)
        if enabled is not None:
            query += " AND enabled=?"
            params.append(1 if enabled else 0)
        query += " ORDER BY created_at DESC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        results = []
        for r in rows:
            d = dict(r)
            d["enabled"] = bool(d["enabled"])
            results.append(d)
        return results

    def _get_rule(self, org_id: str, rule_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM aad_rules WHERE org_id=? AND id=?",
                (org_id, rule_id),
            ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["enabled"] = bool(d["enabled"])
        return d

    # ------------------------------------------------------------------
    # STATS
    # ------------------------------------------------------------------

    def get_abuse_stats(self, org_id: str) -> Dict[str, Any]:
        """Return API abuse detection overview stats for org_id."""
        with self._connect() as conn:
            total_endpoints = conn.execute(
                "SELECT COUNT(*) FROM aad_endpoints WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            monitored_endpoints = conn.execute(
                "SELECT COUNT(*) FROM aad_endpoints WHERE org_id=? AND status='monitored'", (org_id,)
            ).fetchone()[0]

            blocked_endpoints = conn.execute(
                "SELECT COUNT(*) FROM aad_endpoints WHERE org_id=? AND status='blocked'", (org_id,)
            ).fetchone()[0]

            avg_abuse_row = conn.execute(
                "SELECT AVG(abuse_score) FROM aad_endpoints WHERE org_id=?", (org_id,)
            ).fetchone()[0]
            avg_abuse_score = round(avg_abuse_row, 2) if avg_abuse_row is not None else 0.0

            total_incidents = conn.execute(
                "SELECT COUNT(*) FROM aad_incidents WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            open_incidents = conn.execute(
                "SELECT COUNT(*) FROM aad_incidents WHERE org_id=? AND status='open'", (org_id,)
            ).fetchone()[0]

            critical_incidents = conn.execute(
                "SELECT COUNT(*) FROM aad_incidents WHERE org_id=? AND severity='critical'", (org_id,)
            ).fetchone()[0]

            type_rows = conn.execute(
                "SELECT abuse_type, COUNT(*) as cnt FROM aad_incidents WHERE org_id=? GROUP BY abuse_type",
                (org_id,),
            ).fetchall()
            by_abuse_type = {r["abuse_type"]: r["cnt"] for r in type_rows}

            sev_rows = conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM aad_incidents WHERE org_id=? GROUP BY severity",
                (org_id,),
            ).fetchall()
            by_severity = {r["severity"]: r["cnt"] for r in sev_rows}

        return {
            "total_endpoints": total_endpoints,
            "monitored_endpoints": monitored_endpoints,
            "blocked_endpoints": blocked_endpoints,
            "total_incidents": total_incidents,
            "open_incidents": open_incidents,
            "critical_incidents": critical_incidents,
            "by_abuse_type": by_abuse_type,
            "by_severity": by_severity,
            "avg_abuse_score": avg_abuse_score,
        }
