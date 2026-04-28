"""Firewall Rule Analysis Engine — ALDECI.

Inventory firewall devices and their rules, then detect common misconfigurations:
  - Shadowed rules (earlier rule makes a later one unreachable)
  - Overly permissive rules (any/any source + destination)
  - Any-to-any port rules
  - Duplicate rules
  - Unused rules (not hit in 90 days, flagged by hit-count metadata)

Compliance: NIST SP 800-41r1, CIS Controls v8 12.x, PCI DSS 4.0 req 1.3
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "firewall_rules.db"
)

# Wildcard / any-match tokens used across vendors
_ANY_TOKENS = {"any", "0.0.0.0/0", "::/0", "*", "0.0.0.0", "all"}  # nosec B104 — firewall wildcard tokens, not a bind call

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class FirewallRuleEngine:
    """SQLite WAL-backed firewall inventory and rule analysis engine.

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
                CREATE TABLE IF NOT EXISTS firewalls (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    name          TEXT NOT NULL,
                    vendor        TEXT NOT NULL DEFAULT 'unknown',
                    ip_address    TEXT NOT NULL DEFAULT '',
                    status        TEXT NOT NULL DEFAULT 'active',
                    rule_count    INTEGER NOT NULL DEFAULT 0,
                    last_audited  DATETIME,
                    created_at    DATETIME NOT NULL,
                    updated_at    DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_fw_org
                    ON firewalls (org_id);

                CREATE TABLE IF NOT EXISTS firewall_rules (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    firewall_id   TEXT NOT NULL,
                    rule_number   INTEGER NOT NULL DEFAULT 0,
                    src_zone      TEXT NOT NULL DEFAULT '',
                    dst_zone      TEXT NOT NULL DEFAULT '',
                    src_ip        TEXT NOT NULL DEFAULT 'any',
                    dst_ip        TEXT NOT NULL DEFAULT 'any',
                    port          TEXT NOT NULL DEFAULT 'any',
                    protocol      TEXT NOT NULL DEFAULT 'any',
                    action        TEXT NOT NULL DEFAULT 'allow',
                    enabled       INTEGER NOT NULL DEFAULT 1,
                    hit_count     INTEGER NOT NULL DEFAULT 0,
                    last_hit      DATETIME,
                    created_at    DATETIME NOT NULL,
                    FOREIGN KEY (firewall_id) REFERENCES firewalls(id)
                );

                CREATE INDEX IF NOT EXISTS idx_rule_org_fw
                    ON firewall_rules (org_id, firewall_id, rule_number);

                CREATE TABLE IF NOT EXISTS rule_findings (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    firewall_id   TEXT NOT NULL,
                    rule_id       TEXT,
                    finding_type  TEXT NOT NULL,
                    severity      TEXT NOT NULL DEFAULT 'medium',
                    description   TEXT NOT NULL DEFAULT '',
                    status        TEXT NOT NULL DEFAULT 'open',
                    resolved_at   DATETIME,
                    created_at    DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_finding_org_fw
                    ON rule_findings (org_id, firewall_id);

                CREATE INDEX IF NOT EXISTS idx_finding_severity
                    ON rule_findings (org_id, severity, status);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    @staticmethod
    def _bool_row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        if "enabled" in d:
            d["enabled"] = bool(d["enabled"])
        return d

    @staticmethod
    def _is_any(value: str) -> bool:
        return (value or "").strip().lower() in _ANY_TOKENS

    def _rules_match(self, a: Dict[str, Any], b: Dict[str, Any]) -> bool:
        """Return True if two rules have identical traffic selectors."""
        for field in ("src_zone", "dst_zone", "src_ip", "dst_ip", "port", "protocol", "action"):
            if str(a.get(field, "")).lower() != str(b.get(field, "")).lower():
                return False
        return True

    def _rule_is_shadowed_by(self, candidate: Dict[str, Any], earlier: Dict[str, Any]) -> bool:
        """Return True if *earlier* fully shadows *candidate*.

        A rule is shadowed when an earlier rule with the same action matches
        a superset of the traffic that the candidate matches.  For simplicity
        we treat 'any' as a wildcard that matches everything; equal values
        also match.
        """
        for field in ("src_zone", "dst_zone", "src_ip", "dst_ip", "port", "protocol"):
            ev = str(earlier.get(field, "")).lower()
            cv = str(candidate.get(field, "")).lower()
            # earlier value must be "any" (matches all) OR equal to candidate value
            if ev not in _ANY_TOKENS and ev != cv:
                return False
        # Same action required for the shadow to be effective
        return str(earlier.get("action", "")).lower() == str(candidate.get("action", "")).lower()

    # ------------------------------------------------------------------
    # Firewall CRUD
    # ------------------------------------------------------------------

    def add_firewall(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a firewall to inventory and return the record."""
        fw_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        vendor = data.get("vendor", "unknown")
        status = data.get("status", "active")

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO firewalls
                        (id, org_id, name, vendor, ip_address, status,
                         rule_count, last_audited, created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        fw_id,
                        org_id,
                        data.get("name", "Unnamed"),
                        vendor,
                        data.get("ip_address", ""),
                        status,
                        int(data.get("rule_count", 0)),
                        data.get("last_audited"),
                        now,
                        now,
                    ),
                )

        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ASSET_DISCOVERED", {"entity_type": "firewall_rule", "org_id": org_id, "source_engine": "firewall_rule"})
            except Exception:
                pass

        return {
            "firewall_id": fw_id,
            "org_id": org_id,
            "name": data.get("name", "Unnamed"),
            "vendor": vendor,
            "ip_address": data.get("ip_address", ""),
            "status": status,
            "rule_count": int(data.get("rule_count", 0)),
            "last_audited": data.get("last_audited"),
            "created_at": now,
            "updated_at": now,
        }

    def list_firewalls(self, org_id: str) -> List[Dict[str, Any]]:
        """Return all firewalls for an org."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM firewalls WHERE org_id=? ORDER BY name ASC",
                (org_id,),
            ).fetchall()
        result = []
        for row in rows:
            d = self._row(row)
            d["firewall_id"] = d.pop("id", d.get("id"))
            result.append(d)
        return result

    def get_firewall(self, org_id: str, firewall_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single firewall scoped to org."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM firewalls WHERE id=? AND org_id=?",
                (firewall_id, org_id),
            ).fetchone()
        if row is None:
            return None
        d = self._row(row)
        d["firewall_id"] = d.pop("id", firewall_id)
        return d

    # ------------------------------------------------------------------
    # Rule CRUD
    # ------------------------------------------------------------------

    def add_rule(self, org_id: str, firewall_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a firewall rule and return the record."""
        rule_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        enabled = data.get("enabled", True)

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO firewall_rules
                        (id, org_id, firewall_id, rule_number,
                         src_zone, dst_zone, src_ip, dst_ip,
                         port, protocol, action, enabled,
                         hit_count, last_hit, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        rule_id,
                        org_id,
                        firewall_id,
                        int(data.get("rule_number", 0)),
                        data.get("src_zone", ""),
                        data.get("dst_zone", ""),
                        data.get("src_ip", "any"),
                        data.get("dst_ip", "any"),
                        data.get("port", "any"),
                        data.get("protocol", "any"),
                        data.get("action", "allow"),
                        1 if enabled else 0,
                        int(data.get("hit_count", 0)),
                        data.get("last_hit"),
                        now,
                    ),
                )
                # Update rule_count on parent firewall
                conn.execute(
                    "UPDATE firewalls SET rule_count = rule_count + 1, updated_at=? "
                    "WHERE id=? AND org_id=?",
                    (now, firewall_id, org_id),
                )

        return {
            "rule_id": rule_id,
            "org_id": org_id,
            "firewall_id": firewall_id,
            "rule_number": int(data.get("rule_number", 0)),
            "src_zone": data.get("src_zone", ""),
            "dst_zone": data.get("dst_zone", ""),
            "src_ip": data.get("src_ip", "any"),
            "dst_ip": data.get("dst_ip", "any"),
            "port": data.get("port", "any"),
            "protocol": data.get("protocol", "any"),
            "action": data.get("action", "allow"),
            "enabled": bool(enabled),
            "hit_count": int(data.get("hit_count", 0)),
            "last_hit": data.get("last_hit"),
            "created_at": now,
        }

    def list_rules(
        self,
        org_id: str,
        firewall_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return rules for an org, optionally filtered by firewall."""
        if firewall_id:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM firewall_rules WHERE org_id=? AND firewall_id=? "
                    "ORDER BY rule_number ASC",
                    (org_id, firewall_id),
                ).fetchall()
        else:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM firewall_rules WHERE org_id=? ORDER BY firewall_id, rule_number ASC",
                    (org_id,),
                ).fetchall()

        result = []
        for row in rows:
            d = self._bool_row(row)
            d["rule_id"] = d.pop("id", d.get("id"))
            result.append(d)
        return result

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    def analyze_rules(self, org_id: str, firewall_id: str) -> Dict[str, Any]:
        """Analyze all rules for a firewall and return findings.

        Detects:
          - shadowed_rule: earlier rule makes later one unreachable
          - overly_permissive: src_ip=any AND dst_ip=any
          - any_port: port=any (wildcard port)
          - duplicate_rule: identical traffic selector as another rule
          - unused_rule: hit_count=0 and created >90 days ago (or last_hit >90 days ago)

        Returns:
            {
                "findings": [...],
                "rule_count": N,
                "issues_found": N,
                "risk_score": 0-100,
            }
        """
        rules = self.list_rules(org_id, firewall_id)
        now = datetime.now(timezone.utc)
        cutoff_unused = (now - timedelta(days=90)).isoformat()

        findings: List[Dict[str, Any]] = []
        seen_signatures: Dict[str, str] = {}  # signature -> first rule_id

        for i, rule in enumerate(rules):
            if not rule.get("enabled", True):
                continue  # skip disabled rules

            rule_id = rule["rule_id"]
            src_ip = str(rule.get("src_ip", "any"))
            dst_ip = str(rule.get("dst_ip", "any"))
            port = str(rule.get("port", "any"))

            # --- Overly permissive: any source AND any destination ---
            if self._is_any(src_ip) and self._is_any(dst_ip):
                findings.append({
                    "rule_id": rule_id,
                    "finding_type": "overly_permissive",
                    "severity": "high",
                    "description": (
                        f"Rule #{rule.get('rule_number')} allows any source to any destination "
                        f"(src_ip={src_ip}, dst_ip={dst_ip}). This is an open-door policy."
                    ),
                })

            # --- Any-to-any port ---
            if self._is_any(port):
                findings.append({
                    "rule_id": rule_id,
                    "finding_type": "any_port",
                    "severity": "medium",
                    "description": (
                        f"Rule #{rule.get('rule_number')} allows any port. "
                        "Restrict to required ports to reduce attack surface."
                    ),
                })

            # --- Duplicate rules ---
            sig = "|".join([
                src_ip.lower(),
                dst_ip.lower(),
                str(rule.get("src_zone", "")).lower(),
                str(rule.get("dst_zone", "")).lower(),
                port.lower(),
                str(rule.get("protocol", "any")).lower(),
                str(rule.get("action", "allow")).lower(),
            ])
            if sig in seen_signatures:
                findings.append({
                    "rule_id": rule_id,
                    "finding_type": "duplicate_rule",
                    "severity": "low",
                    "description": (
                        f"Rule #{rule.get('rule_number')} is a duplicate of rule "
                        f"#{rules[[r['rule_id'] for r in rules].index(seen_signatures[sig])].get('rule_number', '?')}. "
                        "Remove redundant rules to simplify policy."
                    ),
                })
            else:
                seen_signatures[sig] = rule_id

            # --- Shadowed rules: check all earlier rules ---
            for earlier in rules[:i]:
                if not earlier.get("enabled", True):
                    continue
                if self._rule_is_shadowed_by(rule, earlier):
                    findings.append({
                        "rule_id": rule_id,
                        "finding_type": "shadowed_rule",
                        "severity": "medium",
                        "description": (
                            f"Rule #{rule.get('rule_number')} is shadowed by earlier "
                            f"rule #{earlier.get('rule_number')} and will never be reached."
                        ),
                    })
                    break  # one shadow finding per rule is enough

            # --- Unused rules ---
            hit_count = int(rule.get("hit_count", 0))
            last_hit = rule.get("last_hit")
            created_at = rule.get("created_at", "")

            is_unused = False
            if hit_count == 0 and created_at and created_at < cutoff_unused:
                is_unused = True
            elif last_hit and last_hit < cutoff_unused:
                is_unused = True

            if is_unused:
                findings.append({
                    "rule_id": rule_id,
                    "finding_type": "unused_rule",
                    "severity": "low",
                    "description": (
                        f"Rule #{rule.get('rule_number')} has not been hit in over 90 days "
                        f"(hit_count={hit_count}). Consider removing to reduce policy bloat."
                    ),
                })

        # Persist findings to DB
        now_iso = now.isoformat()
        with self._lock:
            with self._conn() as conn:
                for f in findings:
                    finding_id = str(uuid.uuid4())
                    conn.execute(
                        """
                        INSERT INTO rule_findings
                            (id, org_id, firewall_id, rule_id, finding_type,
                             severity, description, status, created_at)
                        VALUES (?,?,?,?,?,?,?,?,?)
                        """,
                        (
                            finding_id,
                            org_id,
                            firewall_id,
                            f.get("rule_id"),
                            f["finding_type"],
                            f["severity"],
                            f["description"],
                            "open",
                            now_iso,
                        ),
                    )
                    f["finding_id"] = finding_id

                # Update last_audited on the firewall
                conn.execute(
                    "UPDATE firewalls SET last_audited=?, updated_at=? WHERE id=? AND org_id=?",
                    (now_iso, now_iso, firewall_id, org_id),
                )

        # Risk score: weighted by severity counts
        severity_weights = {"high": 20, "medium": 10, "low": 3, "info": 1}
        raw_score = sum(severity_weights.get(f["severity"], 5) for f in findings)
        risk_score = min(100, raw_score)

        return {
            "findings": findings,
            "rule_count": len(rules),
            "issues_found": len(findings),
            "risk_score": risk_score,
        }

    # ------------------------------------------------------------------
    # Findings CRUD
    # ------------------------------------------------------------------

    def create_finding(
        self,
        org_id: str,
        firewall_id: str,
        rule_id: Optional[str],
        finding_type: str,
        severity: str,
        description: str,
    ) -> Dict[str, Any]:
        """Manually create a finding and return the record."""
        finding_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO rule_findings
                        (id, org_id, firewall_id, rule_id, finding_type,
                         severity, description, status, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        finding_id,
                        org_id,
                        firewall_id,
                        rule_id,
                        finding_type,
                        severity,
                        description,
                        "open",
                        now,
                    ),
                )

        return {
            "finding_id": finding_id,
            "org_id": org_id,
            "firewall_id": firewall_id,
            "rule_id": rule_id,
            "finding_type": finding_type,
            "severity": severity,
            "description": description,
            "status": "open",
            "resolved_at": None,
            "created_at": now,
        }

    def list_findings(
        self,
        org_id: str,
        firewall_id: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return findings for an org with optional filters."""
        query = "SELECT * FROM rule_findings WHERE org_id=?"
        params: List[Any] = [org_id]

        if firewall_id:
            query += " AND firewall_id=?"
            params.append(firewall_id)
        if severity:
            query += " AND severity=?"
            params.append(severity)

        query += " ORDER BY created_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()

        result = []
        for row in rows:
            d = self._row(row)
            d["finding_id"] = d.pop("id", d.get("id"))
            result.append(d)
        return result

    def resolve_finding(self, org_id: str, finding_id: str) -> bool:
        """Mark a finding as resolved. Returns True if updated."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    "UPDATE rule_findings SET status='resolved', resolved_at=? "
                    "WHERE id=? AND org_id=? AND status='open'",
                    (now, finding_id, org_id),
                )
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_firewall_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate statistics for an org's firewall posture."""
        with self._conn() as conn:
            total_firewalls = conn.execute(
                "SELECT COUNT(*) FROM firewalls WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            total_rules = conn.execute(
                "SELECT COUNT(*) FROM firewall_rules WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            open_findings = conn.execute(
                "SELECT COUNT(*) FROM rule_findings WHERE org_id=? AND status='open'",
                (org_id,),
            ).fetchone()[0]

            severity_rows = conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM rule_findings "
                "WHERE org_id=? AND status='open' GROUP BY severity",
                (org_id,),
            ).fetchall()

            # Average risk score — approximate from finding counts per firewall
            fw_rows = conn.execute(
                "SELECT id FROM firewalls WHERE org_id=?", (org_id,)
            ).fetchall()

        findings_by_severity = {r["severity"]: r["cnt"] for r in severity_rows}

        # Compute avg risk score across firewalls
        severity_weights = {"high": 20, "medium": 10, "low": 3, "info": 1}
        total_score = 0
        for fw_row in fw_rows:
            fw_id = fw_row["id"]
            with self._conn() as conn:
                fw_findings = conn.execute(
                    "SELECT severity FROM rule_findings WHERE org_id=? AND firewall_id=? AND status='open'",
                    (org_id, fw_id),
                ).fetchall()
            raw = sum(severity_weights.get(f["severity"], 5) for f in fw_findings)
            total_score += min(100, raw)

        avg_risk_score = round(total_score / len(fw_rows), 1) if fw_rows else 0.0

        return {
            "total_firewalls": total_firewalls,
            "total_rules": total_rules,
            "open_findings": open_findings,
            "findings_by_severity": findings_by_severity,
            "avg_risk_score": avg_risk_score,
            "last_audit": datetime.now(timezone.utc).isoformat(),
        }
