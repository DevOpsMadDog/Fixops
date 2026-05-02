"""WAF Engine — Web Application Firewall management for ALDECI.

Manages WAF rules, blocked request logs, OWASP protections, virtual patching,
and rate limiting rules.

Capabilities:
  - Rule CRUD (block/allow/rate_limit/challenge) targeting uri/header/body/ip
  - Blocked request recording with attack type classification
  - Virtual patch lifecycle (CVE-linked temporary rules with expiry)
  - Rate limit rule management per endpoint pattern
  - Stats aggregation: 24h/7d blocked counts, by attack type, top source IPs

Compliance: OWASP Top 10, CWE/NVD taxonomy, PCI-DSS 6.6
"""

from __future__ import annotations

import json
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "waf.db"
)

_VALID_RULE_TYPES = {"block", "allow", "rate_limit", "challenge"}
_VALID_TARGETS = {"uri", "header", "body", "ip"}
_VALID_ACTIONS = {"block", "log", "challenge", "redirect"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_ATTACK_TYPES = {"sqli", "xss", "lfi", "rfi", "rce", "csrf", "xxe", "ssrf"}
_VALID_RATE_ACTIONS = {"block", "throttle"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _now_ts() -> float:
    return datetime.now(timezone.utc).timestamp()


class WAFEngine:
    """SQLite WAL-backed WAF management engine.

    Thread-safe via RLock. Multi-tenant via org_id filtering on a shared DB.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS waf_rules (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    rule_name       TEXT NOT NULL,
                    rule_type       TEXT NOT NULL DEFAULT 'block',
                    pattern         TEXT NOT NULL DEFAULT '',
                    target          TEXT NOT NULL DEFAULT 'uri',
                    action          TEXT NOT NULL DEFAULT 'block',
                    severity        TEXT NOT NULL DEFAULT 'high',
                    enabled         INTEGER NOT NULL DEFAULT 1,
                    description     TEXT NOT NULL DEFAULT '',
                    created_at      TEXT NOT NULL,
                    updated_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_waf_rules_org
                    ON waf_rules (org_id, rule_type, enabled);

                CREATE TABLE IF NOT EXISTS blocked_requests (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    rule_id         TEXT NOT NULL DEFAULT '',
                    source_ip       TEXT NOT NULL DEFAULT '',
                    uri             TEXT NOT NULL DEFAULT '',
                    method          TEXT NOT NULL DEFAULT 'GET',
                    user_agent      TEXT NOT NULL DEFAULT '',
                    attack_type     TEXT NOT NULL DEFAULT 'xss',
                    severity        TEXT NOT NULL DEFAULT 'high',
                    request_headers TEXT NOT NULL DEFAULT '{}',
                    blocked_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_blocked_org_time
                    ON blocked_requests (org_id, blocked_at);

                CREATE INDEX IF NOT EXISTS idx_blocked_attack
                    ON blocked_requests (org_id, attack_type);

                CREATE TABLE IF NOT EXISTS virtual_patches (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    cve_id          TEXT NOT NULL,
                    title           TEXT NOT NULL,
                    rule_pattern    TEXT NOT NULL DEFAULT '',
                    expires_at      TEXT NOT NULL,
                    created_at      TEXT NOT NULL,
                    active          INTEGER NOT NULL DEFAULT 1
                );

                CREATE INDEX IF NOT EXISTS idx_vp_org_active
                    ON virtual_patches (org_id, active);

                CREATE TABLE IF NOT EXISTS rate_limit_rules (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    endpoint_pattern    TEXT NOT NULL,
                    requests_per_minute INTEGER NOT NULL DEFAULT 60,
                    burst_size          INTEGER NOT NULL DEFAULT 10,
                    action              TEXT NOT NULL DEFAULT 'block',
                    created_at          TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_rl_org
                    ON rate_limit_rules (org_id);
                """
            )

    # ------------------------------------------------------------------
    # WAF Rules
    # ------------------------------------------------------------------

    def create_rule(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a WAF rule for the given org."""
        rule_id = str(uuid.uuid4())
        now = _now_iso()
        rule_type = data.get("rule_type", "block")
        if rule_type not in _VALID_RULE_TYPES:
            raise ValueError(f"Invalid rule_type: {rule_type!r}. Valid: {_VALID_RULE_TYPES}")
        target = data.get("target", "uri")
        if target not in _VALID_TARGETS:
            raise ValueError(f"Invalid target: {target!r}. Valid: {_VALID_TARGETS}")
        action = data.get("action", "block")
        if action not in _VALID_ACTIONS:
            raise ValueError(f"Invalid action: {action!r}. Valid: {_VALID_ACTIONS}")
        severity = data.get("severity", "high")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {severity!r}. Valid: {_VALID_SEVERITIES}")

        row = {
            "id": rule_id,
            "org_id": org_id,
            "rule_name": data.get("rule_name", "unnamed"),
            "rule_type": rule_type,
            "pattern": data.get("pattern", ""),
            "target": target,
            "action": action,
            "severity": severity,
            "enabled": 1 if data.get("enabled", True) else 0,
            "description": data.get("description", ""),
            "created_at": now,
            "updated_at": now,
        }
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO waf_rules
                   (id, org_id, rule_name, rule_type, pattern, target, action,
                    severity, enabled, description, created_at, updated_at)
                   VALUES (:id, :org_id, :rule_name, :rule_type, :pattern, :target,
                           :action, :severity, :enabled, :description, :created_at, :updated_at)""",
                row,
            )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "waf", "org_id": org_id, "source_engine": "waf"})
            except Exception:
                pass

        return self._row_to_rule(row)

    def list_rules(
        self,
        org_id: str,
        rule_type: Optional[str] = None,
        enabled: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        """List WAF rules for the org, optionally filtered by rule_type and enabled."""
        query = "SELECT * FROM waf_rules WHERE org_id = ?"
        params: List[Any] = [org_id]
        if rule_type is not None:
            query += " AND rule_type = ?"
            params.append(rule_type)
        if enabled is not None:
            query += " AND enabled = ?"
            params.append(1 if enabled else 0)
        query += " ORDER BY severity, rule_name"
        with self._lock, self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_rule(dict(r)) for r in rows]

    def update_rule(self, org_id: str, rule_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Update fields of an existing WAF rule. Returns updated rule or None."""
        allowed = {"rule_name", "rule_type", "pattern", "target", "action", "severity", "enabled", "description"}
        filtered = {k: v for k, v in updates.items() if k in allowed}
        if not filtered:
            return None

        # Validate enum fields
        for field, valid_set in [
            ("rule_type", _VALID_RULE_TYPES),
            ("target", _VALID_TARGETS),
            ("action", _VALID_ACTIONS),
            ("severity", _VALID_SEVERITIES),
        ]:
            if field in filtered and filtered[field] not in valid_set:
                raise ValueError(f"Invalid {field}: {filtered[field]!r}")

        if "enabled" in filtered:
            filtered["enabled"] = 1 if filtered["enabled"] else 0

        filtered["updated_at"] = _now_iso()
        set_clause = ", ".join(f"{k} = :{k}" for k in filtered)
        filtered["_id"] = rule_id
        filtered["_org"] = org_id

        with self._lock, self._conn() as conn:
            conn.execute(
                f"UPDATE waf_rules SET {set_clause} WHERE id = :_id AND org_id = :_org",  # nosec B608
                filtered,
            )
            row = conn.execute(
                "SELECT * FROM waf_rules WHERE id = ? AND org_id = ?", (rule_id, org_id)
            ).fetchone()

        if row is None:
            return None
        return self._row_to_rule(dict(row))

    def delete_rule(self, org_id: str, rule_id: str) -> bool:
        """Delete a WAF rule. Returns True if deleted, False if not found."""
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                "DELETE FROM waf_rules WHERE id = ? AND org_id = ?", (rule_id, org_id)
            )
        return cur.rowcount > 0

    def _row_to_rule(self, row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "org_id": row["org_id"],
            "rule_name": row["rule_name"],
            "rule_type": row["rule_type"],
            "pattern": row["pattern"],
            "target": row["target"],
            "action": row["action"],
            "severity": row["severity"],
            "enabled": bool(row["enabled"]),
            "description": row["description"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    # ------------------------------------------------------------------
    # Blocked Requests
    # ------------------------------------------------------------------

    def record_blocked_request(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a blocked request event."""
        req_id = str(uuid.uuid4())
        attack_type = data.get("attack_type", "xss")
        if attack_type not in _VALID_ATTACK_TYPES:
            raise ValueError(f"Invalid attack_type: {attack_type!r}. Valid: {_VALID_ATTACK_TYPES}")
        severity = data.get("severity", "high")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {severity!r}. Valid: {_VALID_SEVERITIES}")

        headers = data.get("request_headers", {})
        row = {
            "id": req_id,
            "org_id": org_id,
            "rule_id": data.get("rule_id", ""),
            "source_ip": data.get("source_ip", ""),
            "uri": data.get("uri", ""),
            "method": data.get("method", "GET"),
            "user_agent": data.get("user_agent", ""),
            "attack_type": attack_type,
            "severity": severity,
            "request_headers": json.dumps(headers) if isinstance(headers, dict) else headers,
            "blocked_at": data.get("blocked_at", _now_iso()),
        }
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO blocked_requests
                   (id, org_id, rule_id, source_ip, uri, method, user_agent,
                    attack_type, severity, request_headers, blocked_at)
                   VALUES (:id, :org_id, :rule_id, :source_ip, :uri, :method,
                           :user_agent, :attack_type, :severity, :request_headers, :blocked_at)""",
                row,
            )
        return self._row_to_blocked(row)

    def list_blocked_requests(
        self,
        org_id: str,
        attack_type: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
        hours: int = 24,
    ) -> List[Dict[str, Any]]:
        """List blocked requests within the past `hours`, optionally filtered."""
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        query = "SELECT * FROM blocked_requests WHERE org_id = ? AND blocked_at >= ?"
        params: List[Any] = [org_id, cutoff]
        if attack_type is not None:
            query += " AND attack_type = ?"
            params.append(attack_type)
        if severity is not None:
            query += " AND severity = ?"
            params.append(severity)
        query += " ORDER BY blocked_at DESC LIMIT ?"
        params.append(limit)
        with self._lock, self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_blocked(dict(r)) for r in rows]

    def _row_to_blocked(self, row: Dict[str, Any]) -> Dict[str, Any]:
        headers = row.get("request_headers", "{}")
        if isinstance(headers, str):
            try:
                headers = json.loads(headers)
            except (json.JSONDecodeError, ValueError):
                headers = {}
        return {
            "id": row["id"],
            "org_id": row["org_id"],
            "rule_id": row["rule_id"],
            "source_ip": row["source_ip"],
            "uri": row["uri"],
            "method": row["method"],
            "user_agent": row["user_agent"],
            "attack_type": row["attack_type"],
            "severity": row["severity"],
            "request_headers": headers,
            "blocked_at": row["blocked_at"],
        }

    # ------------------------------------------------------------------
    # Virtual Patches
    # ------------------------------------------------------------------

    def add_virtual_patch(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a virtual patch (temporary CVE mitigation rule)."""
        patch_id = str(uuid.uuid4())
        now = _now_iso()
        expires_at = data.get("expires_at", "")
        if not expires_at:
            # Default: 30 days
            expires_at = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()

        row = {
            "id": patch_id,
            "org_id": org_id,
            "cve_id": data.get("cve_id", ""),
            "title": data.get("title", ""),
            "rule_pattern": data.get("rule_pattern", ""),
            "expires_at": expires_at,
            "created_at": now,
            "active": 1,
        }
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO virtual_patches
                   (id, org_id, cve_id, title, rule_pattern, expires_at, created_at, active)
                   VALUES (:id, :org_id, :cve_id, :title, :rule_pattern, :expires_at, :created_at, :active)""",
                row,
            )
        return self._row_to_patch(row)

    def list_virtual_patches(self, org_id: str, active_only: bool = True) -> List[Dict[str, Any]]:
        """List virtual patches for the org."""
        query = "SELECT * FROM virtual_patches WHERE org_id = ?"
        params: List[Any] = [org_id]
        if active_only:
            now = _now_iso()
            query += " AND active = 1 AND expires_at > ?"
            params.append(now)
        query += " ORDER BY created_at DESC"
        with self._lock, self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_patch(dict(r)) for r in rows]

    def _row_to_patch(self, row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "org_id": row["org_id"],
            "cve_id": row["cve_id"],
            "title": row["title"],
            "rule_pattern": row["rule_pattern"],
            "expires_at": row["expires_at"],
            "created_at": row["created_at"],
            "active": bool(row["active"]),
        }

    # ------------------------------------------------------------------
    # Rate Limit Rules
    # ------------------------------------------------------------------

    def create_rate_limit_rule(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a rate limiting rule for an endpoint pattern."""
        rl_id = str(uuid.uuid4())
        action = data.get("action", "block")
        if action not in _VALID_RATE_ACTIONS:
            raise ValueError(f"Invalid action: {action!r}. Valid: {_VALID_RATE_ACTIONS}")

        row = {
            "id": rl_id,
            "org_id": org_id,
            "endpoint_pattern": data.get("endpoint_pattern", "/*"),
            "requests_per_minute": int(data.get("requests_per_minute", 60)),
            "burst_size": int(data.get("burst_size", 10)),
            "action": action,
            "created_at": _now_iso(),
        }
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO rate_limit_rules
                   (id, org_id, endpoint_pattern, requests_per_minute, burst_size, action, created_at)
                   VALUES (:id, :org_id, :endpoint_pattern, :requests_per_minute, :burst_size, :action, :created_at)""",
                row,
            )
        return self._row_to_rl(row)

    def list_rate_limit_rules(self, org_id: str) -> List[Dict[str, Any]]:
        """List all rate limit rules for the org."""
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM rate_limit_rules WHERE org_id = ? ORDER BY endpoint_pattern",
                (org_id,),
            ).fetchall()
        return [self._row_to_rl(dict(r)) for r in rows]

    def _row_to_rl(self, row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "org_id": row["org_id"],
            "endpoint_pattern": row["endpoint_pattern"],
            "requests_per_minute": row["requests_per_minute"],
            "burst_size": row["burst_size"],
            "action": row["action"],
            "created_at": row["created_at"],
        }

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_waf_stats(self, org_id: str) -> Dict[str, Any]:
        """Return WAF statistics for the org."""
        now = datetime.now(timezone.utc)
        cutoff_24h = (now - timedelta(hours=24)).isoformat()
        cutoff_7d = (now - timedelta(days=7)).isoformat()

        with self._lock, self._conn() as conn:
            total_rules = conn.execute(
                "SELECT COUNT(*) FROM waf_rules WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            enabled_rules = conn.execute(
                "SELECT COUNT(*) FROM waf_rules WHERE org_id = ? AND enabled = 1", (org_id,)
            ).fetchone()[0]

            blocked_24h = conn.execute(
                "SELECT COUNT(*) FROM blocked_requests WHERE org_id = ? AND blocked_at >= ?",
                (org_id, cutoff_24h),
            ).fetchone()[0]

            blocked_7d = conn.execute(
                "SELECT COUNT(*) FROM blocked_requests WHERE org_id = ? AND blocked_at >= ?",
                (org_id, cutoff_7d),
            ).fetchone()[0]

            attack_rows = conn.execute(
                """SELECT attack_type, COUNT(*) AS cnt
                   FROM blocked_requests
                   WHERE org_id = ? AND blocked_at >= ?
                   GROUP BY attack_type
                   ORDER BY cnt DESC""",
                (org_id, cutoff_7d),
            ).fetchall()

            ip_rows = conn.execute(
                """SELECT source_ip, COUNT(*) AS cnt
                   FROM blocked_requests
                   WHERE org_id = ? AND blocked_at >= ?
                   GROUP BY source_ip
                   ORDER BY cnt DESC
                   LIMIT 10""",
                (org_id, cutoff_7d),
            ).fetchall()

            virtual_patches_active = conn.execute(
                "SELECT COUNT(*) FROM virtual_patches WHERE org_id = ? AND active = 1 AND expires_at > ?",
                (org_id, now.isoformat()),
            ).fetchone()[0]

            # False positive rate: blocked requests with 'allow' rules (approximation)
            max(blocked_7d, 1)
            # We approximate FP rate as 0 unless overridden — production would track confirmed FPs
            false_positive_rate = 0.0

        return {
            "total_rules": total_rules,
            "enabled_rules": enabled_rules,
            "blocked_requests_24h": blocked_24h,
            "blocked_requests_7d": blocked_7d,
            "by_attack_type": {r["attack_type"]: r["cnt"] for r in attack_rows},
            "top_source_ips": [
                {"ip": r["source_ip"], "count": r["cnt"]} for r in ip_rows
            ],
            "virtual_patches_active": virtual_patches_active,
            "false_positive_rate": false_positive_rate,
        }
