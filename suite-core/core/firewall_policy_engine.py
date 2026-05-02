"""Firewall Policy Engine — ALDECI.

Manages firewall registrations, rules, conflict detection, and coverage analysis.

Capabilities:
  - Firewall device registry (palo_alto, checkpoint, fortinet, aws_sg, azure_nsg, iptables)
  - Rule management with ordering, zones, IPs, ports, and protocol
  - Conflicting rule detection (shadowing — earlier allow/deny hides later rules)
  - Unused rule detection (hit_count=0 beyond threshold days)
  - Coverage gap analysis (risky allow-all rules, uncovered sensitive ports)
  - Stats aggregation per org

Compliance: NIST SP 800-41, CIS Controls v8 (Control 13), PCI DSS 1.x
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB_DIR = Path(__file__).resolve().parents[2] / ".fixops_data"

_VALID_FW_TYPES = {
    "palo_alto", "checkpoint", "fortinet", "aws_sg", "azure_nsg", "iptables",
}
_VALID_ACTIONS = {"allow", "deny", "drop"}
_VALID_PROTOCOLS = {"tcp", "udp", "icmp", "any"}

# Ports considered sensitive for gap analysis
_SENSITIVE_PORTS = {21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 1521, 3306, 3389, 5432}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class FirewallPolicyEngine:
    """SQLite WAL-backed Firewall Policy engine.

    Thread-safe via per-org RLock. Multi-tenant via org_id.
    Database stored at .fixops_data/firewall_policy.db (shared, org_id-scoped rows).
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        db_dir = _DEFAULT_DB_DIR
        db_dir.mkdir(parents=True, exist_ok=True)
        self._db_path = db_path or str(db_dir / "firewall_policy.db")
        self._lock = threading.RLock()
        self._initialized = False
        self._ensure_init()

    # ------------------------------------------------------------------
    # DB bootstrap
    # ------------------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_init(self) -> None:
        if self._initialized:
            return
        with self._lock:
            if self._initialized:
                return
            with self._conn() as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.executescript("""
                    CREATE TABLE IF NOT EXISTS firewalls (
                        id              TEXT PRIMARY KEY,
                        org_id          TEXT NOT NULL,
                        name            TEXT NOT NULL,
                        fw_type         TEXT NOT NULL,
                        management_ip   TEXT NOT NULL DEFAULT '',
                        description     TEXT NOT NULL DEFAULT '',
                        created_at      DATETIME NOT NULL,
                        updated_at      DATETIME NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS idx_firewalls_org
                        ON firewalls(org_id);

                    CREATE TABLE IF NOT EXISTS firewall_rules (
                        id              TEXT PRIMARY KEY,
                        org_id          TEXT NOT NULL,
                        firewall_id     TEXT NOT NULL,
                        name            TEXT NOT NULL,
                        action          TEXT NOT NULL,
                        src_zones       TEXT NOT NULL DEFAULT '[]',
                        dst_zones       TEXT NOT NULL DEFAULT '[]',
                        src_ips         TEXT NOT NULL DEFAULT '[]',
                        dst_ips         TEXT NOT NULL DEFAULT '[]',
                        ports           TEXT NOT NULL DEFAULT '[]',
                        protocol        TEXT NOT NULL DEFAULT 'any',
                        enabled         INTEGER NOT NULL DEFAULT 1,
                        order_num       INTEGER NOT NULL DEFAULT 0,
                        hit_count       INTEGER NOT NULL DEFAULT 0,
                        last_hit_at     DATETIME,
                        created_at      DATETIME NOT NULL,
                        updated_at      DATETIME NOT NULL,
                        FOREIGN KEY (firewall_id) REFERENCES firewalls(id)
                    );

                    CREATE INDEX IF NOT EXISTS idx_rules_org_fw
                        ON firewall_rules(org_id, firewall_id, order_num);
                """)
            self._initialized = True

    # ------------------------------------------------------------------
    # Firewall CRUD
    # ------------------------------------------------------------------

    def register_firewall(self, org_id: str, data: dict) -> dict:
        """Register a new firewall device."""
        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("name is required")
        fw_type = (data.get("fw_type") or "").strip().lower()
        if fw_type not in _VALID_FW_TYPES:
            raise ValueError(f"fw_type must be one of {sorted(_VALID_FW_TYPES)}")
        fw_id = str(uuid.uuid4())
        now = _now_iso()
        row = {
            "id": fw_id,
            "org_id": org_id,
            "name": name,
            "fw_type": fw_type,
            "management_ip": (data.get("management_ip") or "").strip(),
            "description": (data.get("description") or "").strip(),
            "created_at": now,
            "updated_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO firewalls
                       (id, org_id, name, fw_type, management_ip, description, created_at, updated_at)
                       VALUES (:id, :org_id, :name, :fw_type, :management_ip, :description, :created_at, :updated_at)""",
                    row,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("CONTROL_ASSESSED", {"entity_type": "firewall_policy", "org_id": org_id, "source_engine": "firewall_policy"})
            except Exception:
                pass

        return row

    def list_firewalls(self, org_id: str) -> list:
        """List all firewalls for the org."""
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM firewalls WHERE org_id=? ORDER BY name", (org_id,)
                ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Rule CRUD
    # ------------------------------------------------------------------

    def add_rule(self, org_id: str, firewall_id: str, data: dict) -> dict:
        """Add a firewall rule."""
        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("name is required")
        action = (data.get("action") or "").strip().lower()
        if action not in _VALID_ACTIONS:
            raise ValueError(f"action must be one of {sorted(_VALID_ACTIONS)}")
        protocol = (data.get("protocol") or "any").strip().lower()
        if protocol not in _VALID_PROTOCOLS:
            raise ValueError(f"protocol must be one of {sorted(_VALID_PROTOCOLS)}")

        # Verify firewall belongs to org
        with self._lock:
            with self._conn() as conn:
                fw = conn.execute(
                    "SELECT id FROM firewalls WHERE id=? AND org_id=?",
                    (firewall_id, org_id),
                ).fetchone()
                if not fw:
                    raise ValueError(f"Firewall {firewall_id!r} not found for org {org_id!r}")

        rule_id = str(uuid.uuid4())
        now = _now_iso()
        src_zones = data.get("src_zones") or []
        dst_zones = data.get("dst_zones") or []
        src_ips = data.get("src_ips") or []
        dst_ips = data.get("dst_ips") or []
        ports = data.get("ports") or []
        enabled = bool(data.get("enabled", True))
        order_num = int(data.get("order_num", 0))

        row = {
            "id": rule_id,
            "org_id": org_id,
            "firewall_id": firewall_id,
            "name": name,
            "action": action,
            "src_zones": json.dumps(src_zones),
            "dst_zones": json.dumps(dst_zones),
            "src_ips": json.dumps(src_ips),
            "dst_ips": json.dumps(dst_ips),
            "ports": json.dumps([str(p) for p in ports]),
            "protocol": protocol,
            "enabled": 1 if enabled else 0,
            "order_num": order_num,
            "hit_count": int(data.get("hit_count", 0)),
            "last_hit_at": data.get("last_hit_at"),
            "created_at": now,
            "updated_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO firewall_rules
                       (id, org_id, firewall_id, name, action, src_zones, dst_zones,
                        src_ips, dst_ips, ports, protocol, enabled, order_num,
                        hit_count, last_hit_at, created_at, updated_at)
                       VALUES
                       (:id, :org_id, :firewall_id, :name, :action, :src_zones, :dst_zones,
                        :src_ips, :dst_ips, :ports, :protocol, :enabled, :order_num,
                        :hit_count, :last_hit_at, :created_at, :updated_at)""",
                    row,
                )
        return self._rule_to_dict(row)

    def list_rules(
        self,
        org_id: str,
        firewall_id: str,
        action: Optional[str] = None,
    ) -> list:
        """List rules for a firewall, optionally filtered by action."""
        sql = "SELECT * FROM firewall_rules WHERE org_id=? AND firewall_id=?"
        params: list = [org_id, firewall_id]
        if action:
            sql += " AND action=?"
            params.append(action)
        sql += " ORDER BY order_num, created_at"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(sql, params).fetchall()
        return [self._rule_to_dict(dict(r)) for r in rows]

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    def find_conflicting_rules(self, org_id: str, firewall_id: str) -> list:
        """Detect rules that shadow or conflict with earlier rules.

        A rule at position N is shadowed if an earlier rule (lower order_num)
        has overlapping or broader src_ips/dst_ips/ports and the same or
        broader action coverage.  We flag pairs where an allow-all or
        deny-all at a lower order hides a more specific rule later.
        """
        rules = self.list_rules(org_id, firewall_id)
        conflicts = []

        def _is_any(lst: list) -> bool:
            return not lst or lst == ["any"] or lst == ["0.0.0.0/0"]

        def _ports_overlap(ports_a: list, ports_b: list) -> bool:
            if _is_any(ports_a) or _is_any(ports_b):
                return True
            set_a = {str(p) for p in ports_a}
            set_b = {str(p) for p in ports_b}
            return bool(set_a & set_b)

        for i, rule_a in enumerate(rules):
            if not rule_a["enabled"]:
                continue
            for rule_b in rules[i + 1:]:
                if not rule_b["enabled"]:
                    continue
                # Check if rule_a could shadow rule_b
                src_shadow = _is_any(rule_a["src_ips"]) or _is_any(rule_b["src_ips"])
                dst_shadow = _is_any(rule_a["dst_ips"]) or _is_any(rule_b["dst_ips"])
                port_overlap = _ports_overlap(rule_a["ports"], rule_b["ports"])
                proto_match = (
                    rule_a["protocol"] == "any"
                    or rule_b["protocol"] == "any"
                    or rule_a["protocol"] == rule_b["protocol"]
                )
                zone_match = (
                    _is_any(rule_a["src_zones"]) or _is_any(rule_b["src_zones"])
                    or bool(set(rule_a["src_zones"]) & set(rule_b["src_zones"]))
                )
                if src_shadow and dst_shadow and port_overlap and proto_match and zone_match:
                    conflicts.append({
                        "shadowing_rule_id": rule_a["id"],
                        "shadowing_rule_name": rule_a["name"],
                        "shadowing_rule_order": rule_a["order_num"],
                        "shadowed_rule_id": rule_b["id"],
                        "shadowed_rule_name": rule_b["name"],
                        "shadowed_rule_order": rule_b["order_num"],
                        "conflict_type": "shadow",
                        "reason": (
                            f"Rule '{rule_a['name']}' (order {rule_a['order_num']}) "
                            f"may shadow '{rule_b['name']}' (order {rule_b['order_num']}) "
                            "due to broad match criteria"
                        ),
                    })
        return conflicts

    def find_unused_rules(
        self,
        org_id: str,
        firewall_id: str,
        days_threshold: int = 90,
    ) -> list:
        """Return enabled rules with hit_count=0."""
        rules = self.list_rules(org_id, firewall_id)
        cutoff = datetime.now(timezone.utc) - timedelta(days=days_threshold)
        unused = []
        for rule in rules:
            if not rule["enabled"]:
                continue
            if rule["hit_count"] == 0:
                unused.append({
                    **rule,
                    "unused_reason": "hit_count is zero — rule has never been matched",
                    "days_threshold": days_threshold,
                })
            elif rule.get("last_hit_at"):
                try:
                    last_hit = datetime.fromisoformat(rule["last_hit_at"].replace("Z", "+00:00"))
                    if last_hit < cutoff:
                        unused.append({
                            **rule,
                            "unused_reason": f"Last hit was more than {days_threshold} days ago",
                            "days_threshold": days_threshold,
                        })
                except (ValueError, AttributeError):
                    pass
        return unused

    def analyze_coverage_gaps(self, org_id: str, firewall_id: str) -> dict:
        """Identify coverage gaps and risky configurations.

        Returns:
          - risky_allow_all: rules that allow any src/dst/port
          - uncovered_sensitive_ports: sensitive ports with no explicit deny
          - overly_permissive_rules: allow rules with wildcard IPs
        """
        rules = self.list_rules(org_id, firewall_id)
        enabled_rules = [r for r in rules if r["enabled"]]

        def _is_any(lst: list) -> bool:
            return not lst or lst == ["any"] or lst == ["0.0.0.0/0"]

        risky_allow_all = []
        overly_permissive = []
        denied_ports: set = set()
        allowed_ports: set = set()

        for rule in enabled_rules:
            src_any = _is_any(rule["src_ips"])
            dst_any = _is_any(rule["dst_ips"])
            port_any = _is_any(rule["ports"])

            if rule["action"] == "allow" and src_any and dst_any and port_any:
                risky_allow_all.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "order_num": rule["order_num"],
                    "risk": "critical",
                    "description": "Allow-all rule with no src/dst/port restrictions",
                })
            elif rule["action"] == "allow" and (src_any or dst_any):
                overly_permissive.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "order_num": rule["order_num"],
                    "risk": "high",
                    "description": "Allow rule with wildcard src or dst IPs",
                })

            for port in rule["ports"]:
                try:
                    p = int(port)
                    if rule["action"] in ("deny", "drop"):
                        denied_ports.add(p)
                    else:
                        allowed_ports.add(p)
                except (ValueError, TypeError):
                    pass

        # Sensitive ports that are allowed but never explicitly denied
        uncovered = []
        for port in sorted(_SENSITIVE_PORTS):
            if port in allowed_ports and port not in denied_ports:
                uncovered.append({
                    "port": port,
                    "description": f"Port {port} is allowed but has no explicit deny rule",
                    "risk": "high",
                })

        return {
            "firewall_id": firewall_id,
            "risky_allow_all": risky_allow_all,
            "overly_permissive_rules": overly_permissive,
            "uncovered_sensitive_ports": uncovered,
            "total_enabled_rules": len(enabled_rules),
            "total_rules": len(rules),
        }

    def get_firewall_stats(self, org_id: str) -> dict:
        """Return aggregated stats for all firewalls in the org."""
        firewalls = self.list_firewalls(org_id)
        total_rules = 0
        deny_rules = 0
        unused_rules = 0
        for fw in firewalls:
            rules = self.list_rules(org_id, fw["id"])
            total_rules += len(rules)
            deny_rules += sum(1 for r in rules if r["action"] in ("deny", "drop"))
            unused_rules += len(self.find_unused_rules(org_id, fw["id"]))
        return {
            "org_id": org_id,
            "firewalls": len(firewalls),
            "total_rules": total_rules,
            "deny_rules": deny_rules,
            "unused_rules": unused_rules,
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _rule_to_dict(row: dict) -> dict:
        result = dict(row)
        for field in ("src_zones", "dst_zones", "src_ips", "dst_ips", "ports"):
            if isinstance(result.get(field), str):
                try:
                    result[field] = json.loads(result[field])
                except (json.JSONDecodeError, TypeError):
                    result[field] = []
        if "enabled" in result:
            result["enabled"] = bool(result["enabled"])
        return result
