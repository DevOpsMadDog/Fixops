"""DDoS Protection Engine — Attack Detection, Mitigation, and Resource Management.

Tracks protected resources, records DDoS attack events, and manages mitigation
rules across volumetric, protocol, application, and amplification attack vectors.

Compliance: NIST SP 800-53 SC-5 (Denial of Service Protection), CIS Control 13
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "ddos_protection.db"
)

_VALID_RESOURCE_TYPES = {"web", "api", "dns", "network"}
_VALID_PROTECTION_TIERS = {"basic", "standard", "premium"}
_VALID_ATTACK_TYPES = {"volumetric", "protocol", "application", "slowloris", "amplification"}
_VALID_ATTACK_STATUSES = {"detected", "mitigating", "mitigated"}
_VALID_RULE_TYPES = {"rate_limit", "geo_block", "ip_block", "challenge"}


class DDoSProtectionEngine:
    """SQLite-backed DDoS protection engine.

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

                CREATE TABLE IF NOT EXISTS protected_resources (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    name             TEXT NOT NULL,
                    ip_or_fqdn       TEXT NOT NULL,
                    resource_type    TEXT NOT NULL,
                    protection_tier  TEXT NOT NULL,
                    created_at       DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_pr_org
                    ON protected_resources (org_id);

                CREATE TABLE IF NOT EXISTS attack_events (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    resource_id      TEXT NOT NULL,
                    attack_type      TEXT NOT NULL,
                    source_ips       TEXT NOT NULL,
                    peak_gbps        REAL NOT NULL DEFAULT 0.0,
                    duration_seconds INTEGER NOT NULL DEFAULT 0,
                    status           TEXT NOT NULL DEFAULT 'detected',
                    recorded_at      DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ae_org
                    ON attack_events (org_id, recorded_at DESC);

                CREATE INDEX IF NOT EXISTS idx_ae_resource
                    ON attack_events (resource_id);

                CREATE INDEX IF NOT EXISTS idx_ae_status
                    ON attack_events (org_id, status);

                CREATE TABLE IF NOT EXISTS mitigation_rules (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    name        TEXT NOT NULL,
                    rule_type   TEXT NOT NULL,
                    threshold   TEXT NOT NULL,
                    action      TEXT NOT NULL,
                    created_at  DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_mr_org
                    ON mitigation_rules (org_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Protected Resources
    # ------------------------------------------------------------------

    def register_protected_resource(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a resource for DDoS protection.

        Args:
            org_id: Organisation identifier.
            data: name, ip_or_fqdn, resource_type, protection_tier.

        Returns:
            Persisted resource record.

        Raises:
            ValueError: If required fields are missing or invalid.
        """
        name = data.get("name", "").strip()
        ip_or_fqdn = data.get("ip_or_fqdn", "").strip()
        resource_type = data.get("resource_type", "").strip()
        protection_tier = data.get("protection_tier", "basic").strip()

        if not name:
            raise ValueError("name is required")
        if not ip_or_fqdn:
            raise ValueError("ip_or_fqdn is required")
        if resource_type not in _VALID_RESOURCE_TYPES:
            raise ValueError(f"resource_type must be one of {_VALID_RESOURCE_TYPES}")
        if protection_tier not in _VALID_PROTECTION_TIERS:
            raise ValueError(f"protection_tier must be one of {_VALID_PROTECTION_TIERS}")

        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "name": name,
            "ip_or_fqdn": ip_or_fqdn,
            "resource_type": resource_type,
            "protection_tier": protection_tier,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO protected_resources
                        (id, org_id, name, ip_or_fqdn, resource_type, protection_tier, created_at)
                    VALUES (:id, :org_id, :name, :ip_or_fqdn, :resource_type, :protection_tier, :created_at)
                    """,
                    record,
                )

        _logger.info("registered_protected_resource id=%s org=%s", record["id"], org_id)
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "ddos_protection", "org_id": org_id, "source_engine": "ddos_protection"})
            except Exception:
                pass

        return record

    def list_protected_resources(self, org_id: str) -> List[Dict[str, Any]]:
        """Return all protected resources for an org."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM protected_resources WHERE org_id = ? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Attack Events
    # ------------------------------------------------------------------

    def record_attack_event(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a DDoS attack event against a protected resource.

        Args:
            org_id: Organisation identifier.
            data: resource_id, attack_type, source_ips, peak_gbps, duration_seconds, status.

        Returns:
            Persisted attack event record.

        Raises:
            ValueError: If required fields are missing or invalid.
        """
        resource_id = data.get("resource_id", "").strip()
        attack_type = data.get("attack_type", "").strip()
        source_ips = data.get("source_ips", [])
        peak_gbps = float(data.get("peak_gbps", 0.0))
        duration_seconds = int(data.get("duration_seconds", 0))
        status = data.get("status", "detected").strip()

        if not resource_id:
            raise ValueError("resource_id is required")
        if attack_type not in _VALID_ATTACK_TYPES:
            raise ValueError(f"attack_type must be one of {_VALID_ATTACK_TYPES}")
        if not isinstance(source_ips, list):
            raise ValueError("source_ips must be a list")
        if status not in _VALID_ATTACK_STATUSES:
            raise ValueError(f"status must be one of {_VALID_ATTACK_STATUSES}")

        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "resource_id": resource_id,
            "attack_type": attack_type,
            "source_ips": json.dumps(source_ips),
            "peak_gbps": peak_gbps,
            "duration_seconds": duration_seconds,
            "status": status,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO attack_events
                        (id, org_id, resource_id, attack_type, source_ips,
                         peak_gbps, duration_seconds, status, recorded_at)
                    VALUES (:id, :org_id, :resource_id, :attack_type, :source_ips,
                            :peak_gbps, :duration_seconds, :status, :recorded_at)
                    """,
                    record,
                )

        result = dict(record)
        result["source_ips"] = source_ips
        _logger.info("recorded_attack_event id=%s type=%s org=%s", record["id"], attack_type, org_id)
        return result

    def list_attack_events(
        self,
        org_id: str,
        resource_id: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Return attack events filtered by org, resource, and/or status."""
        query = "SELECT * FROM attack_events WHERE org_id = ?"
        params: List[Any] = [org_id]

        if resource_id:
            query += " AND resource_id = ?"
            params.append(resource_id)
        if status:
            query += " AND status = ?"
            params.append(status)

        query += " ORDER BY recorded_at DESC LIMIT ?"
        params.append(limit)

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()

        results = []
        for row in rows:
            r = dict(row)
            try:
                r["source_ips"] = json.loads(r["source_ips"])
            except (json.JSONDecodeError, TypeError):
                r["source_ips"] = []
            results.append(r)
        return results

    def update_attack_status(self, org_id: str, attack_id: str, status: str) -> Dict[str, Any]:
        """Update the status of an attack event.

        Args:
            org_id: Organisation identifier (enforces tenant isolation).
            attack_id: Attack event UUID.
            status: New status — detected / mitigating / mitigated.

        Returns:
            Updated attack event record.

        Raises:
            ValueError: If status is invalid or attack not found.
        """
        if status not in _VALID_ATTACK_STATUSES:
            raise ValueError(f"status must be one of {_VALID_ATTACK_STATUSES}")

        with self._lock:
            with self._conn() as conn:
                result = conn.execute(
                    "UPDATE attack_events SET status = ? WHERE id = ? AND org_id = ?",
                    (status, attack_id, org_id),
                )
                if result.rowcount == 0:
                    raise ValueError(f"attack_event {attack_id} not found for org {org_id}")

                row = conn.execute(
                    "SELECT * FROM attack_events WHERE id = ?", (attack_id,)
                ).fetchone()

        r = dict(row)
        try:
            r["source_ips"] = json.loads(r["source_ips"])
        except (json.JSONDecodeError, TypeError):
            r["source_ips"] = []
        _logger.info("updated_attack_status id=%s status=%s org=%s", attack_id, status, org_id)
        return r

    # ------------------------------------------------------------------
    # Mitigation Rules
    # ------------------------------------------------------------------

    def create_mitigation_rule(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a DDoS mitigation rule.

        Args:
            org_id: Organisation identifier.
            data: name, rule_type, threshold, action.

        Returns:
            Persisted mitigation rule record.

        Raises:
            ValueError: If required fields are missing or invalid.
        """
        name = data.get("name", "").strip()
        rule_type = data.get("rule_type", "").strip()
        threshold = str(data.get("threshold", "")).strip()
        action = data.get("action", "").strip()

        if not name:
            raise ValueError("name is required")
        if rule_type not in _VALID_RULE_TYPES:
            raise ValueError(f"rule_type must be one of {_VALID_RULE_TYPES}")
        if not threshold:
            raise ValueError("threshold is required")
        if not action:
            raise ValueError("action is required")

        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "name": name,
            "rule_type": rule_type,
            "threshold": threshold,
            "action": action,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO mitigation_rules
                        (id, org_id, name, rule_type, threshold, action, created_at)
                    VALUES (:id, :org_id, :name, :rule_type, :threshold, :action, :created_at)
                    """,
                    record,
                )

        _logger.info("created_mitigation_rule id=%s type=%s org=%s", record["id"], rule_type, org_id)
        return record

    def list_mitigation_rules(self, org_id: str) -> List[Dict[str, Any]]:
        """Return all mitigation rules for an org."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM mitigation_rules WHERE org_id = ? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_ddos_stats(self, org_id: str) -> Dict[str, Any]:
        """Return a summary of DDoS activity for an org.

        Returns:
            resources: total protected resource count
            attacks_24h: attacks recorded in last 24 hours
            mitigated_pct: percentage of all-time attacks with status=mitigated
            peak_gbps_today: maximum peak_gbps from the last 24 hours
        """
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()

        with self._conn() as conn:
            resources = conn.execute(
                "SELECT COUNT(*) FROM protected_resources WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            attacks_24h = conn.execute(
                "SELECT COUNT(*) FROM attack_events WHERE org_id = ? AND recorded_at >= ?",
                (org_id, cutoff),
            ).fetchone()[0]

            total_attacks = conn.execute(
                "SELECT COUNT(*) FROM attack_events WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            mitigated_count = conn.execute(
                "SELECT COUNT(*) FROM attack_events WHERE org_id = ? AND status = 'mitigated'",
                (org_id,),
            ).fetchone()[0]

            peak_row = conn.execute(
                "SELECT MAX(peak_gbps) FROM attack_events WHERE org_id = ? AND recorded_at >= ?",
                (org_id, cutoff),
            ).fetchone()

        mitigated_pct = (mitigated_count / total_attacks * 100) if total_attacks > 0 else 0.0
        peak_gbps_today = peak_row[0] if peak_row[0] is not None else 0.0

        return {
            "resources": resources,
            "attacks_24h": attacks_24h,
            "mitigated_pct": round(mitigated_pct, 1),
            "peak_gbps_today": peak_gbps_today,
        }
