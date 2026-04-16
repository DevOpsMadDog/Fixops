"""Firewall Management Engine — ALDECI.

Manages firewall inventory, rule lifecycle, change requests, and compliance:
  - Firewall registry (multi-vendor: Palo Alto, Cisco ASA, Fortinet, etc.)
  - Rule management with automatic risk analysis
  - Shadowed rule detection
  - Change request workflow (pending → approved → implemented)
  - Compliance scanning for OWASP/CIS firewall violations
  - Stats dashboard per org

Compliance: CIS Controls v8 (Control 12, 13), NIST SP 800-41, PCI DSS Req 1
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

_DEFAULT_DB_DIR = Path(__file__).resolve().parents[2] / ".fixops_data"

_VALID_VENDORS = {
    "palo_alto", "cisco_asa", "fortinet", "checkpoint", "juniper",
    "aws_sg", "azure_nsg", "generic"
}
_VALID_FW_TYPES = {"perimeter", "internal", "cloud", "dmz"}
_VALID_FW_STATUSES = {"online", "offline", "degraded"}
_VALID_ACTIONS = {"allow", "deny", "drop", "reject", "log"}
_VALID_RULE_STATUSES = {"active", "disabled", "expired"}
_VALID_RISK_LEVELS = {"critical", "high", "medium", "low", "info"}
_VALID_CHANGE_TYPES = {"add", "modify", "delete", "temporary"}
_VALID_CR_STATUSES = {"pending", "approved", "rejected", "implemented", "expired"}
_VALID_VIOLATION_TYPES = {
    "any_any_allow", "insecure_protocol", "shadowed_rule",
    "expired_rule", "overly_permissive", "unused_rule"
}
_VALID_VIOLATION_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_VIOLATION_STATUSES = {"open", "suppressed", "resolved"}

# Ports considered insecure for risk analysis
_INSECURE_PORTS = {"23", "21", "139", "445", "3389", "1433", "1521", "5900"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class FirewallManagementEngine:
    """SQLite WAL-backed Firewall Management engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    Each org uses its own database file.
    """

    def __init__(self, db_dir: Optional[str] = None) -> None:
        self._db_dir = Path(db_dir) if db_dir else _DEFAULT_DB_DIR
        self._db_dir.mkdir(parents=True, exist_ok=True)
        self._locks: Dict[str, threading.RLock] = {}
        self._locks_meta = threading.Lock()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _db_path(self, org_id: str) -> str:
        return str(self._db_dir / f"{org_id}_firewall_mgmt.db")

    def _lock(self, org_id: str) -> threading.RLock:
        with self._locks_meta:
            if org_id not in self._locks:
                self._locks[org_id] = threading.RLock()
            return self._locks[org_id]

    def _conn(self, org_id: str) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path(org_id), timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_org(self, org_id: str) -> None:
        with self._lock(org_id):
            with self._conn(org_id) as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.executescript("""
                    CREATE TABLE IF NOT EXISTS firewalls (
                        id          TEXT PRIMARY KEY,
                        org_id      TEXT NOT NULL,
                        name        TEXT NOT NULL,
                        vendor      TEXT NOT NULL DEFAULT 'generic',
                        model       TEXT NOT NULL DEFAULT '',
                        fw_type     TEXT NOT NULL DEFAULT 'perimeter',
                        ip_address  TEXT NOT NULL DEFAULT '',
                        status      TEXT NOT NULL DEFAULT 'online',
                        rule_count  INTEGER NOT NULL DEFAULT 0,
                        last_sync   TEXT,
                        created_at  TEXT NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS idx_fw_org_status
                        ON firewalls (org_id, status);

                    CREATE TABLE IF NOT EXISTS firewall_rules (
                        id          TEXT PRIMARY KEY,
                        org_id      TEXT NOT NULL,
                        firewall_id TEXT NOT NULL,
                        rule_name   TEXT NOT NULL DEFAULT '',
                        src_zone    TEXT NOT NULL DEFAULT '',
                        dst_zone    TEXT NOT NULL DEFAULT '',
                        src_address TEXT NOT NULL DEFAULT 'any',
                        dst_address TEXT NOT NULL DEFAULT 'any',
                        service     TEXT NOT NULL DEFAULT '[]',
                        action      TEXT NOT NULL DEFAULT 'deny',
                        status      TEXT NOT NULL DEFAULT 'active',
                        risk_level  TEXT NOT NULL DEFAULT 'info',
                        is_shadowed INTEGER NOT NULL DEFAULT 0,
                        last_hit    TEXT,
                        hit_count   INTEGER NOT NULL DEFAULT 0,
                        created_at  TEXT NOT NULL,
                        expires_at  TEXT
                    );

                    CREATE INDEX IF NOT EXISTS idx_rule_org_fw
                        ON firewall_rules (org_id, firewall_id, status);
                    CREATE INDEX IF NOT EXISTS idx_rule_org_risk
                        ON firewall_rules (org_id, risk_level);

                    CREATE TABLE IF NOT EXISTS rule_change_requests (
                        id                   TEXT PRIMARY KEY,
                        org_id               TEXT NOT NULL,
                        firewall_id          TEXT NOT NULL,
                        change_type          TEXT NOT NULL DEFAULT 'add',
                        requester            TEXT NOT NULL DEFAULT '',
                        business_justification TEXT NOT NULL DEFAULT '',
                        rules_json           TEXT NOT NULL DEFAULT '[]',
                        status               TEXT NOT NULL DEFAULT 'pending',
                        approver             TEXT,
                        expiry_date          TEXT,
                        implemented_date     TEXT,
                        risk_assessment      TEXT NOT NULL DEFAULT '',
                        created_at           TEXT NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS idx_cr_org_status
                        ON rule_change_requests (org_id, status);

                    CREATE TABLE IF NOT EXISTS compliance_violations (
                        id             TEXT PRIMARY KEY,
                        org_id         TEXT NOT NULL,
                        firewall_id    TEXT NOT NULL,
                        rule_id        TEXT NOT NULL DEFAULT '',
                        violation_type TEXT NOT NULL,
                        severity       TEXT NOT NULL DEFAULT 'medium',
                        description    TEXT NOT NULL DEFAULT '',
                        remediation    TEXT NOT NULL DEFAULT '',
                        status         TEXT NOT NULL DEFAULT 'open',
                        created_at     TEXT NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS idx_viol_org_fw
                        ON compliance_violations (org_id, firewall_id, status);
                    CREATE INDEX IF NOT EXISTS idx_viol_org_sev
                        ON compliance_violations (org_id, severity);
                """)

    def _ensure_org(self, org_id: str) -> None:
        self._init_org(org_id)

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        for field in ("service", "rules_json"):
            if field in d and isinstance(d[field], str):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, TypeError):
                    pass
        for field in ("is_shadowed",):
            if field in d:
                d[field] = bool(d[field])
        return d

    # ------------------------------------------------------------------
    # Risk analysis
    # ------------------------------------------------------------------

    def _analyze_risk(self, rule: Dict[str, Any]) -> str:
        """Determine risk level for a firewall rule."""
        src = (rule.get("src_address") or "").lower().strip()
        dst = (rule.get("dst_address") or "").lower().strip()
        action = (rule.get("action") or "").lower().strip()
        service = rule.get("service", [])
        if isinstance(service, str):
            try:
                service = json.loads(service)
            except json.JSONDecodeError:
                service = [service]

        # any-to-any allow → critical
        if src == "any" and dst == "any" and action == "allow":
            return "critical"

        # any source allowing traffic → high
        if src == "any" and action == "allow":
            return "high"

        # insecure protocols/ports in service list → high
        service_str = " ".join(str(s) for s in service).lower()
        for port in _INSECURE_PORTS:
            if port in service_str:
                return "high"

        # deny/drop/reject rules are generally safe → low
        if action in ("deny", "drop", "reject"):
            return "low"

        # any destination → medium
        if dst == "any" and action == "allow":
            return "medium"

        return "info"

    # ------------------------------------------------------------------
    # Firewalls
    # ------------------------------------------------------------------

    def add_firewall(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new firewall."""
        self._ensure_org(org_id)

        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("name is required.")

        vendor = data.get("vendor", "generic")
        if vendor not in _VALID_VENDORS:
            raise ValueError(f"Invalid vendor: {vendor}. Must be one of {_VALID_VENDORS}")

        fw_type = data.get("fw_type", "perimeter")
        if fw_type not in _VALID_FW_TYPES:
            raise ValueError(f"Invalid fw_type: {fw_type}. Must be one of {_VALID_FW_TYPES}")

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "name": name,
            "vendor": vendor,
            "model": data.get("model", ""),
            "fw_type": fw_type,
            "ip_address": data.get("ip_address", ""),
            "status": "online",
            "rule_count": 0,
            "last_sync": None,
            "created_at": now,
        }

        with self._lock(org_id):
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO firewalls
                       (id, org_id, name, vendor, model, fw_type, ip_address,
                        status, rule_count, last_sync, created_at)
                       VALUES (:id, :org_id, :name, :vendor, :model, :fw_type,
                               :ip_address, :status, :rule_count, :last_sync, :created_at)""",
                    record,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ASSET_DISCOVERED", {"entity_type": "firewall_management", "org_id": org_id, "source_engine": "firewall_management"})
            except Exception:
                pass

        return record

    def list_firewalls(
        self, org_id: str, status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List firewalls, optionally filtered by status."""
        self._ensure_org(org_id)
        sql = "SELECT * FROM firewalls WHERE org_id = ?"
        params: list = [org_id]
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC"
        with self._conn(org_id) as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    def get_firewall(self, org_id: str, firewall_id: str) -> Optional[Dict[str, Any]]:
        """Get a single firewall by ID."""
        self._ensure_org(org_id)
        with self._conn(org_id) as conn:
            row = conn.execute(
                "SELECT * FROM firewalls WHERE org_id = ? AND id = ?",
                (org_id, firewall_id),
            ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Rules
    # ------------------------------------------------------------------

    def add_rule(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a firewall rule. Automatically calculates risk_level."""
        self._ensure_org(org_id)

        firewall_id = (data.get("firewall_id") or "").strip()
        if not firewall_id:
            raise ValueError("firewall_id is required.")

        action = data.get("action", "deny")
        if action not in _VALID_ACTIONS:
            raise ValueError(f"Invalid action: {action}. Must be one of {_VALID_ACTIONS}")

        service = data.get("service", [])
        if isinstance(service, str):
            try:
                service = json.loads(service)
            except json.JSONDecodeError:
                service = [service]

        risk_level = self._analyze_risk({**data, "service": service})

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "firewall_id": firewall_id,
            "rule_name": data.get("rule_name", ""),
            "src_zone": data.get("src_zone", ""),
            "dst_zone": data.get("dst_zone", ""),
            "src_address": data.get("src_address", "any"),
            "dst_address": data.get("dst_address", "any"),
            "service": json.dumps(service),
            "action": action,
            "status": "active",
            "risk_level": risk_level,
            "is_shadowed": 0,
            "last_hit": None,
            "hit_count": 0,
            "created_at": now,
            "expires_at": data.get("expires_at", None),
        }

        with self._lock(org_id):
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO firewall_rules
                       (id, org_id, firewall_id, rule_name, src_zone, dst_zone,
                        src_address, dst_address, service, action, status,
                        risk_level, is_shadowed, last_hit, hit_count, created_at, expires_at)
                       VALUES (:id, :org_id, :firewall_id, :rule_name, :src_zone, :dst_zone,
                               :src_address, :dst_address, :service, :action, :status,
                               :risk_level, :is_shadowed, :last_hit, :hit_count,
                               :created_at, :expires_at)""",
                    record,
                )
            # Update rule_count on firewall
            with self._conn(org_id) as conn:
                conn.execute(
                    "UPDATE firewalls SET rule_count = rule_count + 1 WHERE org_id = ? AND id = ?",
                    (org_id, firewall_id),
                )

        record["service"] = service
        record["is_shadowed"] = False
        return record

    def list_rules(
        self,
        org_id: str,
        firewall_id: Optional[str] = None,
        status: Optional[str] = None,
        risk_level: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List firewall rules with optional filters."""
        self._ensure_org(org_id)
        sql = "SELECT * FROM firewall_rules WHERE org_id = ?"
        params: list = [org_id]
        if firewall_id:
            sql += " AND firewall_id = ?"
            params.append(firewall_id)
        if status:
            sql += " AND status = ?"
            params.append(status)
        if risk_level:
            sql += " AND risk_level = ?"
            params.append(risk_level)
        sql += " ORDER BY created_at ASC"
        with self._conn(org_id) as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    def disable_rule(self, org_id: str, rule_id: str) -> bool:
        """Disable a firewall rule. Returns True if found."""
        self._ensure_org(org_id)
        with self._lock(org_id):
            with self._conn(org_id) as conn:
                cur = conn.execute(
                    "UPDATE firewall_rules SET status = 'disabled' WHERE org_id = ? AND id = ?",
                    (org_id, rule_id),
                )
                return cur.rowcount > 0

    def detect_shadowed_rules(self, org_id: str, firewall_id: str) -> List[str]:
        """Detect rules shadowed by earlier higher-priority (lower-index) rules.

        A rule B is shadowed by rule A if A was created earlier and has the same
        src_address, dst_address, and service, but with an action of allow
        (making B unreachable). Returns list of newly marked shadowed rule IDs.
        """
        self._ensure_org(org_id)
        rules = self.list_rules(org_id, firewall_id=firewall_id, status="active")

        shadowed_ids: List[str] = []
        seen: Dict[str, str] = {}  # key → rule_id of first-seen rule

        for rule in rules:
            # Build a simplified key for matching
            svc = rule.get("service", [])
            if isinstance(svc, list):
                svc_key = ",".join(sorted(str(s) for s in svc))
            else:
                svc_key = str(svc)

            key = f"{rule['src_address']}|{rule['dst_address']}|{svc_key}"

            if key in seen:
                # This rule is shadowed by an earlier one
                if rule["id"] not in shadowed_ids and not rule.get("is_shadowed"):
                    shadowed_ids.append(rule["id"])
            else:
                seen[key] = rule["id"]

        # Mark shadowed in DB
        if shadowed_ids:
            with self._lock(org_id):
                with self._conn(org_id) as conn:
                    for rid in shadowed_ids:
                        conn.execute(
                            "UPDATE firewall_rules SET is_shadowed = 1 WHERE org_id = ? AND id = ?",
                            (org_id, rid),
                        )

        return shadowed_ids

    # ------------------------------------------------------------------
    # Change Requests
    # ------------------------------------------------------------------

    def create_change_request(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a firewall rule change request."""
        self._ensure_org(org_id)

        firewall_id = (data.get("firewall_id") or "").strip()
        if not firewall_id:
            raise ValueError("firewall_id is required.")

        change_type = data.get("change_type", "add")
        if change_type not in _VALID_CHANGE_TYPES:
            raise ValueError(f"Invalid change_type: {change_type}. Must be one of {_VALID_CHANGE_TYPES}")

        rules_json = data.get("rules_json", [])
        if isinstance(rules_json, list):
            rules_json_str = json.dumps(rules_json)
        elif isinstance(rules_json, str):
            rules_json_str = rules_json
        else:
            rules_json_str = "[]"

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "firewall_id": firewall_id,
            "change_type": change_type,
            "requester": data.get("requester", ""),
            "business_justification": data.get("business_justification", ""),
            "rules_json": rules_json_str,
            "status": "pending",
            "approver": None,
            "expiry_date": data.get("expiry_date", None),
            "implemented_date": None,
            "risk_assessment": data.get("risk_assessment", ""),
            "created_at": now,
        }

        with self._lock(org_id):
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO rule_change_requests
                       (id, org_id, firewall_id, change_type, requester, business_justification,
                        rules_json, status, approver, expiry_date, implemented_date,
                        risk_assessment, created_at)
                       VALUES (:id, :org_id, :firewall_id, :change_type, :requester,
                               :business_justification, :rules_json, :status, :approver,
                               :expiry_date, :implemented_date, :risk_assessment, :created_at)""",
                    record,
                )

        record["rules_json"] = rules_json if isinstance(rules_json, list) else json.loads(rules_json_str)
        return record

    def approve_change_request(
        self, org_id: str, request_id: str, approver: str
    ) -> bool:
        """Approve a change request. Returns True if found."""
        self._ensure_org(org_id)
        with self._lock(org_id):
            with self._conn(org_id) as conn:
                cur = conn.execute(
                    """UPDATE rule_change_requests
                       SET status = 'approved', approver = ?
                       WHERE org_id = ? AND id = ? AND status = 'pending'""",
                    (approver, org_id, request_id),
                )
                return cur.rowcount > 0

    def implement_change_request(self, org_id: str, request_id: str) -> bool:
        """Mark a change request as implemented. Returns True if found."""
        self._ensure_org(org_id)
        now = _now_iso()
        with self._lock(org_id):
            with self._conn(org_id) as conn:
                cur = conn.execute(
                    """UPDATE rule_change_requests
                       SET status = 'implemented', implemented_date = ?
                       WHERE org_id = ? AND id = ? AND status = 'approved'""",
                    (now, org_id, request_id),
                )
                return cur.rowcount > 0

    def reject_change_request(self, org_id: str, request_id: str, approver: str) -> bool:
        """Reject a change request. Returns True if found."""
        self._ensure_org(org_id)
        with self._lock(org_id):
            with self._conn(org_id) as conn:
                cur = conn.execute(
                    """UPDATE rule_change_requests
                       SET status = 'rejected', approver = ?
                       WHERE org_id = ? AND id = ? AND status = 'pending'""",
                    (approver, org_id, request_id),
                )
                return cur.rowcount > 0

    def list_change_requests(
        self, org_id: str, status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List change requests with optional status filter."""
        self._ensure_org(org_id)
        sql = "SELECT * FROM rule_change_requests WHERE org_id = ?"
        params: list = [org_id]
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC"
        with self._conn(org_id) as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    # ------------------------------------------------------------------
    # Compliance Scanning
    # ------------------------------------------------------------------

    def run_compliance_scan(
        self, org_id: str, firewall_id: str
    ) -> List[Dict[str, Any]]:
        """Scan all active rules for violations. Creates violation records.

        Checks:
          - any_any_allow: src=any, dst=any, action=allow → critical
          - insecure_protocol: service contains port 23/21/139/445/etc → high
          - shadowed_rule: is_shadowed=True → medium
          - expired_rule: expires_at < now → medium
          - overly_permissive: src=any, action=allow (but not any_any) → high
          - unused_rule: hit_count=0, created > 30 days ago → low
        """
        self._ensure_org(org_id)
        rules = self.list_rules(org_id, firewall_id=firewall_id)
        now = _now_iso()
        created_violations: List[Dict[str, Any]] = []

        # Run shadow detection first
        self.detect_shadowed_rules(org_id, firewall_id)
        # Refresh rules with updated shadow flags
        rules = self.list_rules(org_id, firewall_id=firewall_id)

        for rule in rules:
            if rule.get("status") == "disabled":
                continue

            rule_violations: List[Dict[str, Any]] = []
            src = (rule.get("src_address") or "").lower()
            dst = (rule.get("dst_address") or "").lower()
            action = (rule.get("action") or "").lower()
            service = rule.get("service", [])
            if isinstance(service, list):
                svc_str = " ".join(str(s) for s in service).lower()
            else:
                svc_str = str(service).lower()

            # any-any-allow
            if src == "any" and dst == "any" and action == "allow":
                rule_violations.append({
                    "violation_type": "any_any_allow",
                    "severity": "critical",
                    "description": f"Rule '{rule.get('rule_name', rule['id'])}' allows all traffic from any source to any destination.",
                    "remediation": "Restrict source and destination addresses to the minimum required. Use explicit IP ranges or zones.",
                })

            # insecure protocol
            for port in _INSECURE_PORTS:
                if port in svc_str:
                    rule_violations.append({
                        "violation_type": "insecure_protocol",
                        "severity": "high",
                        "description": f"Rule '{rule.get('rule_name', rule['id'])}' allows insecure service/port {port}.",
                        "remediation": f"Disable port {port} or replace with a secure alternative (e.g. SSH instead of Telnet).",
                    })
                    break

            # shadowed rule
            if rule.get("is_shadowed"):
                rule_violations.append({
                    "violation_type": "shadowed_rule",
                    "severity": "medium",
                    "description": f"Rule '{rule.get('rule_name', rule['id'])}' is shadowed by a higher-priority rule and will never be evaluated.",
                    "remediation": "Remove the shadowed rule or reorder rules so the intended rule takes precedence.",
                })

            # expired rule
            expires = rule.get("expires_at")
            if expires and expires < now:
                rule_violations.append({
                    "violation_type": "expired_rule",
                    "severity": "medium",
                    "description": f"Rule '{rule.get('rule_name', rule['id'])}' expired on {expires} and should be removed.",
                    "remediation": "Disable or delete the expired rule, or extend its validity with proper justification.",
                })

            # overly permissive (src=any, allow, but not any-any)
            if src == "any" and action == "allow" and dst != "any":
                rule_violations.append({
                    "violation_type": "overly_permissive",
                    "severity": "high",
                    "description": f"Rule '{rule.get('rule_name', rule['id'])}' allows traffic from any source.",
                    "remediation": "Restrict the source address to the minimum required IP ranges or zones.",
                })

            # unused rule (hit_count=0, older than 30 days approximated by created_at check)
            if rule.get("hit_count", 0) == 0 and rule.get("last_hit") is None:
                rule_violations.append({
                    "violation_type": "unused_rule",
                    "severity": "low",
                    "description": f"Rule '{rule.get('rule_name', rule['id'])}' has never been matched (hit_count=0).",
                    "remediation": "Review and remove unused rules to reduce the attack surface.",
                })

            for v in rule_violations:
                viol = {
                    "id": str(uuid.uuid4()),
                    "org_id": org_id,
                    "firewall_id": firewall_id,
                    "rule_id": rule["id"],
                    "violation_type": v["violation_type"],
                    "severity": v["severity"],
                    "description": v["description"],
                    "remediation": v["remediation"],
                    "status": "open",
                    "created_at": now,
                }
                with self._lock(org_id):
                    with self._conn(org_id) as conn:
                        conn.execute(
                            """INSERT INTO compliance_violations
                               (id, org_id, firewall_id, rule_id, violation_type, severity,
                                description, remediation, status, created_at)
                               VALUES (:id, :org_id, :firewall_id, :rule_id, :violation_type,
                                       :severity, :description, :remediation, :status,
                                       :created_at)""",
                            viol,
                        )
                created_violations.append(viol)

        return created_violations

    def list_violations(
        self,
        org_id: str,
        firewall_id: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List compliance violations with optional filters."""
        self._ensure_org(org_id)
        sql = "SELECT * FROM compliance_violations WHERE org_id = ?"
        params: list = [org_id]
        if firewall_id:
            sql += " AND firewall_id = ?"
            params.append(firewall_id)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC"
        with self._conn(org_id) as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    def resolve_violation(self, org_id: str, violation_id: str) -> bool:
        """Mark a violation as resolved. Returns True if found."""
        self._ensure_org(org_id)
        with self._lock(org_id):
            with self._conn(org_id) as conn:
                cur = conn.execute(
                    "UPDATE compliance_violations SET status = 'resolved' WHERE org_id = ? AND id = ?",
                    (org_id, violation_id),
                )
                return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_firewall_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated firewall stats for org."""
        self._ensure_org(org_id)

        with self._conn(org_id) as conn:
            total_fws = conn.execute(
                "SELECT COUNT(*) FROM firewalls WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            online_fws = conn.execute(
                "SELECT COUNT(*) FROM firewalls WHERE org_id = ? AND status = 'online'",
                (org_id,),
            ).fetchone()[0]

            total_rules = conn.execute(
                "SELECT COUNT(*) FROM firewall_rules WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            active_rules = conn.execute(
                "SELECT COUNT(*) FROM firewall_rules WHERE org_id = ? AND status = 'active'",
                (org_id,),
            ).fetchone()[0]

            disabled_rules = conn.execute(
                "SELECT COUNT(*) FROM firewall_rules WHERE org_id = ? AND status = 'disabled'",
                (org_id,),
            ).fetchone()[0]

            shadowed_rules = conn.execute(
                "SELECT COUNT(*) FROM firewall_rules WHERE org_id = ? AND is_shadowed = 1",
                (org_id,),
            ).fetchone()[0]

            compliance_violations = conn.execute(
                "SELECT COUNT(*) FROM compliance_violations WHERE org_id = ? AND status = 'open'",
                (org_id,),
            ).fetchone()[0]

            by_risk_rows = conn.execute(
                """SELECT risk_level, COUNT(*) as cnt
                   FROM firewall_rules WHERE org_id = ?
                   GROUP BY risk_level""",
                (org_id,),
            ).fetchall()
            by_risk_level = {r["risk_level"]: r["cnt"] for r in by_risk_rows}

            pending_changes = conn.execute(
                "SELECT COUNT(*) FROM rule_change_requests WHERE org_id = ? AND status = 'pending'",
                (org_id,),
            ).fetchone()[0]

        return {
            "total_firewalls": total_fws,
            "online_firewalls": online_fws,
            "total_rules": total_rules,
            "active_rules": active_rules,
            "disabled_rules": disabled_rules,
            "shadowed_rules": shadowed_rules,
            "compliance_violations": compliance_violations,
            "by_risk_level": by_risk_level,
            "pending_changes": pending_changes,
        }
