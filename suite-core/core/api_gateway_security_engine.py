"""API Gateway Security Engine — Gateway Registration, API Tracking, and Threat Events.

Manages API gateways, their registered APIs, and security events such as
auth failures, rate exceeded, injection attempts, schema violations, and bot traffic.

Compliance: OWASP API Security Top 10, NIST SP 800-95 (Guide to Secure Web Services)
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "api_gateway_security.db"
)

_VALID_GATEWAY_TYPES = {"kong", "apigee", "aws_api_gw", "nginx", "custom"}
_VALID_ENVIRONMENTS = {"prod", "staging", "dev"}
_VALID_AUTH_TYPES = {"api_key", "oauth2", "jwt", "none"}
_VALID_EVENT_TYPES = {"auth_failure", "rate_exceeded", "injection", "schema_violation", "bot"}
_VALID_SEVERITIES = {"low", "medium", "high", "critical"}


class APIGatewaySecurityEngine:
    """SQLite-backed API gateway security engine.

    Thread-safe via RLock. Multi-tenant via org_id.

    Args:
        db_path: Path to SQLite database file.
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
            conn.executescript(
                """
                PRAGMA journal_mode=WAL;

                CREATE TABLE IF NOT EXISTS gateways (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    name         TEXT NOT NULL,
                    base_url     TEXT NOT NULL,
                    gateway_type TEXT NOT NULL,
                    environment  TEXT NOT NULL,
                    created_at   DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_gw_org
                    ON gateways (org_id);

                CREATE TABLE IF NOT EXISTS apis (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    gateway_id      TEXT NOT NULL,
                    name            TEXT NOT NULL,
                    version         TEXT NOT NULL DEFAULT 'v1',
                    path_prefix     TEXT NOT NULL,
                    auth_type       TEXT NOT NULL DEFAULT 'api_key',
                    rate_limit_rps  INTEGER NOT NULL DEFAULT 100,
                    created_at      DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_api_org
                    ON apis (org_id);

                CREATE INDEX IF NOT EXISTS idx_api_gateway
                    ON apis (gateway_id);

                CREATE TABLE IF NOT EXISTS security_events (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    api_id       TEXT NOT NULL,
                    event_type   TEXT NOT NULL,
                    source_ip    TEXT NOT NULL,
                    request_path TEXT NOT NULL DEFAULT '',
                    severity     TEXT NOT NULL DEFAULT 'medium',
                    recorded_at  DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_se_org
                    ON security_events (org_id, recorded_at DESC);

                CREATE INDEX IF NOT EXISTS idx_se_api
                    ON security_events (api_id);

                CREATE INDEX IF NOT EXISTS idx_se_type
                    ON security_events (org_id, event_type);

                CREATE INDEX IF NOT EXISTS idx_se_severity
                    ON security_events (org_id, severity);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Gateways
    # ------------------------------------------------------------------

    def register_gateway(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register an API gateway for security monitoring.

        Args:
            org_id: Organisation identifier.
            data: name, base_url, gateway_type, environment.

        Returns:
            Persisted gateway record.

        Raises:
            ValueError: If required fields are missing or invalid.
        """
        name = data.get("name", "").strip()
        base_url = data.get("base_url", "").strip()
        gateway_type = data.get("gateway_type", "").strip()
        environment = data.get("environment", "prod").strip()

        if not name:
            raise ValueError("name is required")
        if not base_url:
            raise ValueError("base_url is required")
        if gateway_type not in _VALID_GATEWAY_TYPES:
            raise ValueError(f"gateway_type must be one of {_VALID_GATEWAY_TYPES}")
        if environment not in _VALID_ENVIRONMENTS:
            raise ValueError(f"environment must be one of {_VALID_ENVIRONMENTS}")

        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "name": name,
            "base_url": base_url,
            "gateway_type": gateway_type,
            "environment": environment,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO gateways
                        (id, org_id, name, base_url, gateway_type, environment, created_at)
                    VALUES (:id, :org_id, :name, :base_url, :gateway_type, :environment, :created_at)
                    """,
                    record,
                )

        _logger.info("registered_gateway id=%s type=%s org=%s", record["id"], gateway_type, org_id)
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "api_gateway_security", "org_id": org_id, "source_engine": "api_gateway_security"})
            except Exception:
                pass

        return record

    def list_gateways(self, org_id: str) -> List[Dict[str, Any]]:
        """Return all gateways for an org."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM gateways WHERE org_id = ? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # APIs
    # ------------------------------------------------------------------

    def register_api(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register an API on a gateway for security tracking.

        Args:
            org_id: Organisation identifier.
            data: gateway_id, name, version, path_prefix, auth_type, rate_limit_rps.

        Returns:
            Persisted API record.

        Raises:
            ValueError: If required fields are missing or invalid.
        """
        gateway_id = data.get("gateway_id", "").strip()
        name = data.get("name", "").strip()
        version = data.get("version", "v1").strip()
        path_prefix = data.get("path_prefix", "").strip()
        auth_type = data.get("auth_type", "api_key").strip()
        rate_limit_rps = int(data.get("rate_limit_rps", 100))

        if not gateway_id:
            raise ValueError("gateway_id is required")
        if not name:
            raise ValueError("name is required")
        if not path_prefix:
            raise ValueError("path_prefix is required")
        if auth_type not in _VALID_AUTH_TYPES:
            raise ValueError(f"auth_type must be one of {_VALID_AUTH_TYPES}")
        if rate_limit_rps <= 0:
            raise ValueError("rate_limit_rps must be positive")

        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "gateway_id": gateway_id,
            "name": name,
            "version": version,
            "path_prefix": path_prefix,
            "auth_type": auth_type,
            "rate_limit_rps": rate_limit_rps,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO apis
                        (id, org_id, gateway_id, name, version, path_prefix,
                         auth_type, rate_limit_rps, created_at)
                    VALUES (:id, :org_id, :gateway_id, :name, :version, :path_prefix,
                            :auth_type, :rate_limit_rps, :created_at)
                    """,
                    record,
                )

        _logger.info("registered_api id=%s name=%s org=%s", record["id"], name, org_id)
        return record

    def list_apis(self, org_id: str, gateway_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Return APIs for an org, optionally filtered by gateway."""
        query = "SELECT * FROM apis WHERE org_id = ?"
        params: List[Any] = [org_id]

        if gateway_id:
            query += " AND gateway_id = ?"
            params.append(gateway_id)

        query += " ORDER BY created_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Security Events
    # ------------------------------------------------------------------

    def record_security_event(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a security event against an API.

        Args:
            org_id: Organisation identifier.
            data: api_id, event_type, source_ip, request_path, severity.

        Returns:
            Persisted security event record.

        Raises:
            ValueError: If required fields are missing or invalid.
        """
        api_id = data.get("api_id", "").strip()
        event_type = data.get("event_type", "").strip()
        source_ip = data.get("source_ip", "").strip()
        request_path = data.get("request_path", "").strip()
        severity = data.get("severity", "medium").strip()

        if not api_id:
            raise ValueError("api_id is required")
        if event_type not in _VALID_EVENT_TYPES:
            raise ValueError(f"event_type must be one of {_VALID_EVENT_TYPES}")
        if not source_ip:
            raise ValueError("source_ip is required")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {_VALID_SEVERITIES}")

        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "api_id": api_id,
            "event_type": event_type,
            "source_ip": source_ip,
            "request_path": request_path,
            "severity": severity,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO security_events
                        (id, org_id, api_id, event_type, source_ip, request_path,
                         severity, recorded_at)
                    VALUES (:id, :org_id, :api_id, :event_type, :source_ip, :request_path,
                            :severity, :recorded_at)
                    """,
                    record,
                )

        _logger.info(
            "recorded_security_event id=%s type=%s severity=%s org=%s",
            record["id"], event_type, severity, org_id,
        )
        return record

    def list_security_events(
        self,
        org_id: str,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Return security events filtered by org, event_type, and/or severity."""
        query = "SELECT * FROM security_events WHERE org_id = ?"
        params: List[Any] = [org_id]

        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        if severity:
            query += " AND severity = ?"
            params.append(severity)

        query += " ORDER BY recorded_at DESC LIMIT ?"
        params.append(limit)

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Threat Summary
    # ------------------------------------------------------------------

    def get_api_threat_summary(self, org_id: str, api_id: str) -> Dict[str, Any]:
        """Return a threat summary for a specific API.

        Returns:
            events_by_type: count per event_type
            top_attacking_ips: top 5 source IPs by event count
            violation_rate: events per hour (last 24h)
            total_events: all-time event count for this API
        """
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()

        with self._conn() as conn:
            type_rows = conn.execute(
                """
                SELECT event_type, COUNT(*) as cnt
                FROM security_events
                WHERE org_id = ? AND api_id = ?
                GROUP BY event_type
                """,
                (org_id, api_id),
            ).fetchall()

            ip_rows = conn.execute(
                """
                SELECT source_ip, COUNT(*) as cnt
                FROM security_events
                WHERE org_id = ? AND api_id = ?
                GROUP BY source_ip
                ORDER BY cnt DESC
                LIMIT 5
                """,
                (org_id, api_id),
            ).fetchall()

            recent_count = conn.execute(
                """
                SELECT COUNT(*) FROM security_events
                WHERE org_id = ? AND api_id = ? AND recorded_at >= ?
                """,
                (org_id, api_id, cutoff),
            ).fetchone()[0]

            total_events = conn.execute(
                "SELECT COUNT(*) FROM security_events WHERE org_id = ? AND api_id = ?",
                (org_id, api_id),
            ).fetchone()[0]

        events_by_type = {row["event_type"]: row["cnt"] for row in type_rows}
        top_attacking_ips = [
            {"ip": row["source_ip"], "count": row["cnt"]} for row in ip_rows
        ]
        violation_rate = round(recent_count / 24.0, 2)

        return {
            "api_id": api_id,
            "events_by_type": events_by_type,
            "top_attacking_ips": top_attacking_ips,
            "violation_rate": violation_rate,
            "total_events": total_events,
        }

    # ------------------------------------------------------------------
    # Gateway Stats
    # ------------------------------------------------------------------

    def get_gateway_stats(self, org_id: str) -> Dict[str, Any]:
        """Return a summary of gateway security posture for an org.

        Returns:
            gateways: total registered gateways
            apis: total registered APIs
            events_24h: security events in last 24 hours
            by_severity: event counts grouped by severity
        """
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()

        with self._conn() as conn:
            gateways = conn.execute(
                "SELECT COUNT(*) FROM gateways WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            apis = conn.execute(
                "SELECT COUNT(*) FROM apis WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            events_24h = conn.execute(
                "SELECT COUNT(*) FROM security_events WHERE org_id = ? AND recorded_at >= ?",
                (org_id, cutoff),
            ).fetchone()[0]

            severity_rows = conn.execute(
                """
                SELECT severity, COUNT(*) as cnt
                FROM security_events
                WHERE org_id = ?
                GROUP BY severity
                """,
                (org_id,),
            ).fetchall()

        by_severity = {row["severity"]: row["cnt"] for row in severity_rows}

        return {
            "gateways": gateways,
            "apis": apis,
            "events_24h": events_24h,
            "by_severity": by_severity,
        }
