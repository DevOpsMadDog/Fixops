"""API Security Management Engine — ALDECI.

Manages API endpoint registry, API key lifecycle, abuse event detection,
and OWASP API Top 10 scanning jobs for multi-tenant organisations.

Different from api_security_engine.py (HTTP-based OWASP scanner):
this module provides persistent SQLite-backed management of API assets.

Capabilities:
  - API endpoint registration with sensitivity classification
  - API key creation, revocation, and usage tracking
  - Abuse event recording (BOLA, injection, rate-limit breach, etc.)
  - API scan job lifecycle (OWASP API Top 10, fuzz, auth, rate-limit)
  - Aggregated stats per org

Compliance: OWASP API Security Top 10 2023, CIS Controls v8, NIST SP 800-53
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
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

_DEFAULT_DB_DIR = Path(__file__).resolve().parents[2] / ".fixops_data"

_VALID_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
_VALID_SENSITIVITY_LEVELS = {"public", "internal", "sensitive", "critical"}
_VALID_ENDPOINT_STATUSES = {"active", "deprecated", "retired"}
_VALID_KEY_STATUSES = {"active", "revoked", "expired"}
_VALID_ABUSE_EVENT_TYPES = {
    "rate_limit_breach",
    "injection_attempt",
    "auth_bypass",
    "mass_assignment",
    "broken_object_level_auth",
    "sensitive_data_exposure",
    "excessive_data_exposure",
    "bola_attempt",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_ABUSE_STATUSES = {"detected", "investigating", "blocked", "false_positive"}
_VALID_SCAN_TYPES = {"owasp_api_top10", "fuzz", "auth_test", "rate_limit_test"}
_VALID_SCAN_STATUSES = {"running", "completed", "failed"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class APISecurityEngine:
    """SQLite WAL-backed API Security Management engine.

    Thread-safe via per-org RLock. Multi-tenant via org_id.
    Database path: .fixops_data/{org_id}_api_security.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        self._single_db_path = db_path
        self._org_locks: Dict[str, threading.RLock] = {}
        self._org_lock_meta = threading.Lock()
        if db_path:
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
            self._init_db(db_path)
        else:
            _DEFAULT_DB_DIR.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _org_db_path(self, org_id: str) -> str:
        if self._single_db_path:
            return self._single_db_path
        safe = org_id.replace("/", "_").replace("..", "__")
        return str(_DEFAULT_DB_DIR / f"{safe}_api_security.db")

    def _get_org_lock(self, org_id: str) -> threading.RLock:
        with self._org_lock_meta:
            if org_id not in self._org_locks:
                self._org_locks[org_id] = threading.RLock()
            return self._org_locks[org_id]

    def _conn(self, org_id: str) -> sqlite3.Connection:
        path = self._org_db_path(org_id)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db(path)
        conn = sqlite3.connect(path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self, path: str) -> None:
        conn = sqlite3.connect(path, timeout=10)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS api_endpoints (
                    id                      TEXT PRIMARY KEY,
                    org_id                  TEXT NOT NULL,
                    endpoint_path           TEXT NOT NULL,
                    http_method             TEXT NOT NULL DEFAULT 'GET',
                    service_name            TEXT NOT NULL DEFAULT '',
                    authentication_required INTEGER NOT NULL DEFAULT 1,
                    rate_limit_per_minute   INTEGER NOT NULL DEFAULT 60,
                    is_public               INTEGER NOT NULL DEFAULT 0,
                    sensitivity_level       TEXT NOT NULL DEFAULT 'internal',
                    status                  TEXT NOT NULL DEFAULT 'active',
                    risk_score              REAL NOT NULL DEFAULT 0.0,
                    created_at              DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ep_org_service
                    ON api_endpoints (org_id, service_name, status);

                CREATE TABLE IF NOT EXISTS api_keys (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    key_name            TEXT NOT NULL,
                    key_prefix          TEXT NOT NULL DEFAULT '',
                    hashed_key          TEXT NOT NULL DEFAULT '',
                    owner_id            TEXT NOT NULL DEFAULT '',
                    scopes              TEXT NOT NULL DEFAULT '[]',
                    rate_limit_per_hour INTEGER NOT NULL DEFAULT 1000,
                    status              TEXT NOT NULL DEFAULT 'active',
                    expires_at          DATETIME,
                    last_used           DATETIME,
                    usage_count         INTEGER NOT NULL DEFAULT 0,
                    created_at          DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_keys_org_status
                    ON api_keys (org_id, status);

                CREATE TABLE IF NOT EXISTS api_abuse_events (
                    id                      TEXT PRIMARY KEY,
                    org_id                  TEXT NOT NULL,
                    event_type              TEXT NOT NULL,
                    api_key_id              TEXT NOT NULL DEFAULT '',
                    endpoint_id             TEXT NOT NULL DEFAULT '',
                    source_ip               TEXT NOT NULL DEFAULT '',
                    request_payload_preview TEXT NOT NULL DEFAULT '',
                    severity                TEXT NOT NULL DEFAULT 'medium',
                    status                  TEXT NOT NULL DEFAULT 'detected',
                    detected_at             DATETIME NOT NULL,
                    created_at              DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_abuse_org_type
                    ON api_abuse_events (org_id, event_type, detected_at DESC);

                CREATE INDEX IF NOT EXISTS idx_abuse_org_severity
                    ON api_abuse_events (org_id, severity);

                CREATE TABLE IF NOT EXISTS api_scans (
                    id                    TEXT PRIMARY KEY,
                    org_id                TEXT NOT NULL,
                    scan_type             TEXT NOT NULL DEFAULT 'owasp_api_top10',
                    target_service        TEXT NOT NULL DEFAULT '',
                    status                TEXT NOT NULL DEFAULT 'running',
                    endpoints_scanned     INTEGER NOT NULL DEFAULT 0,
                    vulnerabilities_found INTEGER NOT NULL DEFAULT 0,
                    critical_count        INTEGER NOT NULL DEFAULT 0,
                    created_at            DATETIME NOT NULL,
                    completed_at          DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_scans_org_status
                    ON api_scans (org_id, status, created_at DESC);
                """
            )
            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def _bool_row(d: dict) -> dict:
        for field in ("authentication_required", "is_public"):
            if field in d:
                d[field] = bool(d[field])
        for field in ("scopes",):
            if field in d and isinstance(d[field], str):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, TypeError):
                    d[field] = []
        return d

    # ------------------------------------------------------------------
    # API Endpoints
    # ------------------------------------------------------------------

    def register_endpoint(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new API endpoint. Returns the created record."""
        endpoint_path = (data.get("endpoint_path") or "").strip()
        if not endpoint_path:
            raise ValueError("endpoint_path is required.")

        http_method = (data.get("http_method") or "GET").upper()
        if http_method not in _VALID_HTTP_METHODS:
            raise ValueError(f"Invalid http_method: {http_method}")

        sensitivity_level = data.get("sensitivity_level", "internal")
        if sensitivity_level not in _VALID_SENSITIVITY_LEVELS:
            raise ValueError(f"Invalid sensitivity_level: {sensitivity_level}")

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "endpoint_path": endpoint_path,
            "http_method": http_method,
            "service_name": data.get("service_name", ""),
            "authentication_required": 1 if data.get("authentication_required", True) else 0,
            "rate_limit_per_minute": int(data.get("rate_limit_per_minute", 60)),
            "is_public": 1 if data.get("is_public", False) else 0,
            "sensitivity_level": sensitivity_level,
            "status": "active",
            "risk_score": float(data.get("risk_score", 0.0)),
            "created_at": now,
        }
        with self._get_org_lock(org_id):
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO api_endpoints
                       (id, org_id, endpoint_path, http_method, service_name,
                        authentication_required, rate_limit_per_minute, is_public,
                        sensitivity_level, status, risk_score, created_at)
                       VALUES (:id, :org_id, :endpoint_path, :http_method, :service_name,
                               :authentication_required, :rate_limit_per_minute, :is_public,
                               :sensitivity_level, :status, :risk_score, :created_at)""",
                    record,
                )
        out = dict(record)
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "api_security_mgmt", "org_id": org_id, "source_engine": "api_security_mgmt"})
            except Exception:
                pass

        return self._bool_row(out)

    def list_endpoints(
        self,
        org_id: str,
        service_name: Optional[str] = None,
        is_public: Optional[bool] = None,
        sensitivity_level: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List API endpoints with optional filters."""
        sql = "SELECT * FROM api_endpoints WHERE org_id = ?"
        params: list = [org_id]
        if service_name is not None:
            sql += " AND service_name = ?"
            params.append(service_name)
        if is_public is not None:
            sql += " AND is_public = ?"
            params.append(1 if is_public else 0)
        if sensitivity_level is not None:
            sql += " AND sensitivity_level = ?"
            params.append(sensitivity_level)
        sql += " ORDER BY created_at DESC"
        with self._conn(org_id) as conn:
            return [self._bool_row(dict(r)) for r in conn.execute(sql, params).fetchall()]

    # ------------------------------------------------------------------
    # API Keys
    # ------------------------------------------------------------------

    def create_api_key(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create an API key record. Does NOT store or return the raw key."""
        key_name = (data.get("key_name") or "").strip()
        if not key_name:
            raise ValueError("key_name is required.")

        raw_key = secrets.token_hex(32)
        key_prefix = raw_key[:8]
        hashed_key = hashlib.sha256(raw_key.encode()).hexdigest()

        scopes = data.get("scopes", [])
        if not isinstance(scopes, list):
            scopes = [scopes]

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "key_name": key_name,
            "key_prefix": key_prefix,
            "hashed_key": hashed_key,
            "owner_id": data.get("owner_id", ""),
            "scopes": json.dumps(scopes),
            "rate_limit_per_hour": int(data.get("rate_limit_per_hour", 1000)),
            "status": "active",
            "expires_at": data.get("expires_at"),
            "last_used": None,
            "usage_count": 0,
            "created_at": now,
        }
        with self._get_org_lock(org_id):
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO api_keys
                       (id, org_id, key_name, key_prefix, hashed_key, owner_id,
                        scopes, rate_limit_per_hour, status, expires_at, last_used,
                        usage_count, created_at)
                       VALUES (:id, :org_id, :key_name, :key_prefix, :hashed_key, :owner_id,
                               :scopes, :rate_limit_per_hour, :status, :expires_at, :last_used,
                               :usage_count, :created_at)""",
                    record,
                )
        out = {k: v for k, v in record.items() if k != "hashed_key"}
        out["scopes"] = scopes
        out["key_hint"] = f"{key_prefix}..."
        return out

    def list_api_keys(
        self, org_id: str, status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List API keys. hashed_key is never returned."""
        sql = (
            "SELECT id, org_id, key_name, key_prefix, owner_id, scopes, "
            "rate_limit_per_hour, status, expires_at, last_used, usage_count, created_at "
            "FROM api_keys WHERE org_id = ?"
        )
        params: list = [org_id]
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC"
        with self._conn(org_id) as conn:
            rows = conn.execute(sql, params).fetchall()
        results = []
        for row in rows:
            d = dict(row)
            try:
                d["scopes"] = json.loads(d.get("scopes") or "[]")
            except (json.JSONDecodeError, TypeError):
                d["scopes"] = []
            results.append(d)
        return results

    def revoke_api_key(self, org_id: str, key_id: str) -> bool:
        """Revoke an API key. Returns True if found and updated."""
        with self._get_org_lock(org_id):
            with self._conn(org_id) as conn:
                cur = conn.execute(
                    "UPDATE api_keys SET status = 'revoked' WHERE org_id = ? AND id = ?",
                    (org_id, key_id),
                )
                return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Abuse Events
    # ------------------------------------------------------------------

    def record_abuse_event(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record an API abuse event."""
        event_type = data.get("event_type", "rate_limit_breach")
        if event_type not in _VALID_ABUSE_EVENT_TYPES:
            raise ValueError(
                f"Invalid event_type: {event_type}. Must be one of {_VALID_ABUSE_EVENT_TYPES}"
            )

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {severity}")

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "event_type": event_type,
            "api_key_id": data.get("api_key_id", ""),
            "endpoint_id": data.get("endpoint_id", ""),
            "source_ip": data.get("source_ip", ""),
            "request_payload_preview": data.get("request_payload_preview", ""),
            "severity": severity,
            "status": data.get("status", "detected"),
            "detected_at": data.get("detected_at", now),
            "created_at": now,
        }
        if record["status"] not in _VALID_ABUSE_STATUSES:
            record["status"] = "detected"

        with self._get_org_lock(org_id):
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO api_abuse_events
                       (id, org_id, event_type, api_key_id, endpoint_id, source_ip,
                        request_payload_preview, severity, status, detected_at, created_at)
                       VALUES (:id, :org_id, :event_type, :api_key_id, :endpoint_id, :source_ip,
                               :request_payload_preview, :severity, :status, :detected_at,
                               :created_at)""",
                    record,
                )
        return record

    def list_abuse_events(
        self,
        org_id: str,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """List abuse events with optional filters."""
        sql = "SELECT * FROM api_abuse_events WHERE org_id = ?"
        params: list = [org_id]
        if event_type:
            sql += " AND event_type = ?"
            params.append(event_type)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY detected_at DESC LIMIT ?"
        params.append(limit)
        with self._conn(org_id) as conn:
            return [dict(r) for r in conn.execute(sql, params).fetchall()]

    # ------------------------------------------------------------------
    # Scans
    # ------------------------------------------------------------------

    def create_scan(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create an API scan job."""
        scan_type = data.get("scan_type", "owasp_api_top10")
        if scan_type not in _VALID_SCAN_TYPES:
            raise ValueError(f"Invalid scan_type: {scan_type}")

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "scan_type": scan_type,
            "target_service": data.get("target_service", ""),
            "status": "running",
            "endpoints_scanned": 0,
            "vulnerabilities_found": 0,
            "critical_count": 0,
            "created_at": now,
            "completed_at": None,
        }
        with self._get_org_lock(org_id):
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO api_scans
                       (id, org_id, scan_type, target_service, status,
                        endpoints_scanned, vulnerabilities_found, critical_count,
                        created_at, completed_at)
                       VALUES (:id, :org_id, :scan_type, :target_service, :status,
                               :endpoints_scanned, :vulnerabilities_found, :critical_count,
                               :created_at, :completed_at)""",
                    record,
                )
        return record

    def complete_scan(
        self, org_id: str, scan_id: str, results: Dict[str, Any]
    ) -> bool:
        """Mark a scan as completed with finding counts. Returns True if found."""
        now = _now_iso()
        with self._get_org_lock(org_id):
            with self._conn(org_id) as conn:
                cur = conn.execute(
                    """UPDATE api_scans SET status = 'completed',
                       endpoints_scanned = ?, vulnerabilities_found = ?,
                       critical_count = ?, completed_at = ?
                       WHERE org_id = ? AND id = ?""",
                    (
                        int(results.get("endpoints_scanned", 0)),
                        int(results.get("vulnerabilities_found", 0)),
                        int(results.get("critical_count", 0)),
                        now,
                        org_id,
                        scan_id,
                    ),
                )
                return cur.rowcount > 0

    def list_scans(
        self, org_id: str, status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List scans with optional status filter."""
        sql = "SELECT * FROM api_scans WHERE org_id = ?"
        params: list = [org_id]
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC"
        with self._conn(org_id) as conn:
            return [dict(r) for r in conn.execute(sql, params).fetchall()]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_api_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated API security stats for org."""
        cutoff_24h = (
            datetime.now(timezone.utc) - timedelta(hours=24)
        ).isoformat()

        with self._conn(org_id) as conn:
            total_ep = conn.execute(
                "SELECT COUNT(*) FROM api_endpoints WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            public_ep = conn.execute(
                "SELECT COUNT(*) FROM api_endpoints WHERE org_id = ? AND is_public = 1",
                (org_id,),
            ).fetchone()[0]
            sensitive_ep = conn.execute(
                "SELECT COUNT(*) FROM api_endpoints WHERE org_id = ? "
                "AND sensitivity_level IN ('sensitive','critical')",
                (org_id,),
            ).fetchone()[0]
            active_keys = conn.execute(
                "SELECT COUNT(*) FROM api_keys WHERE org_id = ? AND status = 'active'",
                (org_id,),
            ).fetchone()[0]
            abuse_24h = conn.execute(
                "SELECT COUNT(*) FROM api_abuse_events "
                "WHERE org_id = ? AND detected_at >= ?",
                (org_id, cutoff_24h),
            ).fetchone()[0]

            by_event_type = {
                r["event_type"]: r["cnt"]
                for r in conn.execute(
                    "SELECT event_type, COUNT(*) as cnt FROM api_abuse_events "
                    "WHERE org_id = ? GROUP BY event_type",
                    (org_id,),
                ).fetchall()
            }

            by_severity = {
                r["severity"]: r["cnt"]
                for r in conn.execute(
                    "SELECT severity, COUNT(*) as cnt FROM api_abuse_events "
                    "WHERE org_id = ? GROUP BY severity",
                    (org_id,),
                ).fetchall()
            }

            critical_vulns = conn.execute(
                "SELECT COALESCE(SUM(critical_count), 0) FROM api_scans "
                "WHERE org_id = ? AND status = 'completed'",
                (org_id,),
            ).fetchone()[0]

            total_scans = conn.execute(
                "SELECT COUNT(*) FROM api_scans "
                "WHERE org_id = ? AND status = 'completed'",
                (org_id,),
            ).fetchone()[0]
            clean_scans = conn.execute(
                "SELECT COUNT(*) FROM api_scans "
                "WHERE org_id = ? AND status = 'completed' AND vulnerabilities_found = 0",
                (org_id,),
            ).fetchone()[0]

        scan_pass_rate = (
            (clean_scans / total_scans * 100) if total_scans > 0 else 100.0
        )

        return {
            "total_endpoints": total_ep,
            "public_endpoints": public_ep,
            "sensitive_endpoints": sensitive_ep,
            "active_api_keys": active_keys,
            "abuse_events_24h": abuse_24h,
            "by_event_type": by_event_type,
            "by_severity": by_severity,
            "critical_vulnerabilities": int(critical_vulns),
            "scan_pass_rate": round(scan_pass_rate, 1),
        }
