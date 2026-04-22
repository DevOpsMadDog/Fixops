"""Privilege Escalation Detector Engine — ALDECI.

Detects and analyzes privilege escalation events across systems:
- Records privilege escalation events (sudo, setuid, token, exploit)
- Anomaly scoring based on method, frequency, and timing
- Detection rules (regex-based) with configurable actions
- Escalation heatmap (top users, methods, hourly distribution)

SQLite-backed, thread-safe, multi-tenant (per org_id).
"""

from __future__ import annotations

import json
import logging
import re
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

_DEFAULT_DB = ".fixops_data/privilege_escalation_detector.db"

_VALID_METHODS = {"sudo", "setuid", "token", "exploit", "impersonation", "suid", "other"}

# Base anomaly scores by escalation method
_METHOD_SCORES: Dict[str, float] = {
    "exploit": 80.0,
    "setuid": 60.0,
    "suid": 60.0,
    "token": 45.0,
    "impersonation": 50.0,
    "sudo": 25.0,
    "other": 30.0,
}

_RISK_LEVELS = {
    (0, 30): "low",
    (30, 60): "medium",
    (60, 80): "high",
    (80, 101): "critical",
}


def _risk_level(score: float) -> str:
    for (lo, hi), level in _RISK_LEVELS.items():
        if lo <= score < hi:
            return level
    return "critical"


class PrivilegeEscalationDetectorEngine:
    """
    Privilege Escalation Detector Engine.

    All public methods are thread-safe via RLock.
    Multi-tenant: every query is scoped to org_id.

    Args:
        db_path: Path to SQLite database.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.executescript(
                """
                PRAGMA journal_mode=WAL;

                CREATE TABLE IF NOT EXISTS privilege_events (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    user_id         TEXT NOT NULL,
                    from_role       TEXT NOT NULL,
                    to_role         TEXT NOT NULL,
                    method          TEXT NOT NULL,
                    source_ip       TEXT NOT NULL DEFAULT '',
                    anomaly_score   REAL NOT NULL DEFAULT 0,
                    risk_level      TEXT NOT NULL DEFAULT 'low',
                    indicators      TEXT NOT NULL DEFAULT '[]',
                    recorded_at     TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_pe_org ON privilege_events(org_id);
                CREATE INDEX IF NOT EXISTS idx_pe_user ON privilege_events(user_id);
                CREATE INDEX IF NOT EXISTS idx_pe_method ON privilege_events(method);
                CREATE INDEX IF NOT EXISTS idx_pe_recorded ON privilege_events(recorded_at);

                CREATE TABLE IF NOT EXISTS detection_rules (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    name        TEXT NOT NULL,
                    pattern     TEXT NOT NULL,
                    severity    TEXT NOT NULL DEFAULT 'medium',
                    action      TEXT NOT NULL DEFAULT 'alert',
                    created_at  TEXT NOT NULL,
                    updated_at  TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_dr_org ON detection_rules(org_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Anomaly scoring helpers
    # ------------------------------------------------------------------

    def _compute_anomaly(
        self,
        org_id: str,
        user_id: str,
        method: str,
        from_role: str,
        to_role: str,
        source_ip: str,
    ) -> tuple[float, List[str]]:
        """Compute anomaly score and indicators for an escalation event."""
        indicators: List[str] = []
        score = _METHOD_SCORES.get(method.lower(), 30.0)

        # Exploit-based escalation is always high anomaly
        if method.lower() == "exploit":
            indicators.append("exploit_based_escalation")

        # Escalation to root/admin
        high_priv_targets = {"root", "admin", "system", "administrator", "sudo", "wheel"}
        if to_role.lower() in high_priv_targets:
            score = min(100.0, score + 20.0)
            indicators.append("escalation_to_privileged_role")

        # From unprivileged to admin
        low_priv_sources = {"user", "guest", "nobody", "anonymous", "www-data"}
        if from_role.lower() in low_priv_sources and to_role.lower() in high_priv_targets:
            score = min(100.0, score + 15.0)
            indicators.append("unprivileged_to_privileged_jump")

        # Check frequency: >3 events from same user in last hour = anomaly
        with self._conn() as conn:
            recent_count = conn.execute(
                """
                SELECT COUNT(*) FROM privilege_events
                WHERE org_id=? AND user_id=?
                  AND recorded_at >= datetime('now', '-1 hour')
                """,
                (org_id, user_id),
            ).fetchone()[0]

        if recent_count >= 3:
            score = min(100.0, score + 25.0)
            indicators.append(f"repeated_escalation_attempts_{recent_count}_in_1h")

        # External/suspicious source IP check (non-RFC1918)
        if source_ip and source_ip not in ("", "localhost", "127.0.0.1", "::1"):
            # Simple heuristic: if not a private range, flag it
            is_private = (
                source_ip.startswith("10.")
                or source_ip.startswith("192.168.")
                or source_ip.startswith("172.")
            )
            if not is_private:
                score = min(100.0, score + 15.0)
                indicators.append(f"external_source_ip_{source_ip}")

        # Check matching detection rules
        event_str = f"{user_id} {from_role} {to_role} {method} {source_ip}"
        matched_rules = self._match_rules(org_id, event_str)
        for rule in matched_rules:
            indicators.append(f"rule_match:{rule['name']}")
            rule_severity_boost = {"critical": 20.0, "high": 15.0, "medium": 10.0, "low": 5.0}
            score = min(100.0, score + rule_severity_boost.get(rule["severity"], 5.0))

        return round(score, 1), indicators

    def _match_rules(self, org_id: str, event_str: str) -> List[Dict[str, Any]]:
        """Return all detection rules whose pattern matches the event string."""
        with self._lock:
            with self._conn() as conn:
                rules = conn.execute(
                    "SELECT * FROM detection_rules WHERE org_id=?", (org_id,)
                ).fetchall()

        matched = []
        for rule in rules:
            r = dict(rule)
            try:
                if re.search(r["pattern"], event_str, re.IGNORECASE):
                    matched.append(r)
            except re.error:
                _logger.warning("Invalid regex pattern in rule %s: %s", r["id"], r["pattern"])
        return matched

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record_privilege_event(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a privilege escalation event.

        Args:
            org_id: Organization identifier.
            data: dict with keys:
                - user_id (str): User or service account identifier.
                - from_role (str): Role/permission level before escalation.
                - to_role (str): Role/permission level after escalation.
                - method (str): One of sudo/setuid/token/exploit/impersonation/suid/other.
                - source_ip (str, optional): Source IP address.

        Returns:
            Recorded event dict including anomaly_score, risk_level, indicators.
        """
        user_id = data.get("user_id", "")
        from_role = data.get("from_role", "")
        to_role = data.get("to_role", "")
        method = data.get("method", "other").lower()
        source_ip = data.get("source_ip", "")

        if not user_id:
            raise ValueError("user_id is required")
        if not from_role or not to_role:
            raise ValueError("from_role and to_role are required")

        event_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        anomaly_score, indicators = self._compute_anomaly(
            org_id, user_id, method, from_role, to_role, source_ip
        )
        risk_level = _risk_level(anomaly_score)

        record = {
            "id": event_id,
            "org_id": org_id,
            "user_id": user_id,
            "from_role": from_role,
            "to_role": to_role,
            "method": method,
            "source_ip": source_ip,
            "anomaly_score": anomaly_score,
            "risk_level": risk_level,
            "indicators": indicators,
            "recorded_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO privilege_events
                        (id, org_id, user_id, from_role, to_role, method, source_ip,
                         anomaly_score, risk_level, indicators, recorded_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_id, org_id, user_id, from_role, to_role, method, source_ip,
                        anomaly_score, risk_level, json.dumps(indicators), now,
                    ),
                )

        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("FINDING_CREATED", {"entity_type": "privilege_escalation_detector", "org_id": org_id, "source_engine": "privilege_escalation_detector"})
            except Exception:
                pass

        return record

    def list_privilege_events(
        self,
        org_id: str,
        user_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """List privilege escalation events, optionally filtered by user."""
        with self._lock:
            with self._conn() as conn:
                if user_id:
                    rows = conn.execute(
                        """
                        SELECT * FROM privilege_events
                        WHERE org_id=? AND user_id=?
                        ORDER BY recorded_at DESC LIMIT ?
                        """,
                        (org_id, user_id, limit),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        """
                        SELECT * FROM privilege_events
                        WHERE org_id=?
                        ORDER BY recorded_at DESC LIMIT ?
                        """,
                        (org_id, limit),
                    ).fetchall()

        result = []
        for row in rows:
            r = dict(row)
            r["indicators"] = json.loads(r["indicators"])
            result.append(r)
        return result

    def detect_anomalous_escalation(self, org_id: str, event_id: str) -> Dict[str, Any]:
        """Analyze a specific event and return anomaly assessment.

        Returns:
            dict with event_id, anomaly_score (0-100), risk_level, indicators.
        """
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM privilege_events WHERE id=? AND org_id=?",
                    (event_id, org_id),
                ).fetchone()

        if not row:
            raise ValueError(f"Event {event_id} not found for org {org_id}")

        event = dict(row)
        indicators = json.loads(event["indicators"])

        return {
            "event_id": event_id,
            "user_id": event["user_id"],
            "method": event["method"],
            "from_role": event["from_role"],
            "to_role": event["to_role"],
            "anomaly_score": event["anomaly_score"],
            "risk_level": event["risk_level"],
            "indicators": indicators,
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
        }

    def create_detection_rule(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a detection rule for privilege escalation patterns.

        Args:
            org_id: Organization identifier.
            data: dict with keys:
                - name (str): Rule name.
                - pattern (str): Regex pattern to match against event strings.
                - severity (str): critical/high/medium/low.
                - action (str): alert/block/log.

        Returns:
            Created rule record.
        """
        name = data.get("name", "")
        pattern = data.get("pattern", "")
        severity = data.get("severity", "medium").lower()
        action = data.get("action", "alert").lower()

        if not name:
            raise ValueError("name is required")
        if not pattern:
            raise ValueError("pattern is required")

        # Validate regex
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ValueError(f"Invalid regex pattern: {exc}") from exc

        rule_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        record = {
            "id": rule_id,
            "org_id": org_id,
            "name": name,
            "pattern": pattern,
            "severity": severity,
            "action": action,
            "created_at": now,
            "updated_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO detection_rules
                        (id, org_id, name, pattern, severity, action, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (rule_id, org_id, name, pattern, severity, action, now, now),
                )

        return record

    def list_detection_rules(self, org_id: str) -> List[Dict[str, Any]]:
        """List all detection rules for an org."""
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM detection_rules WHERE org_id=? ORDER BY created_at DESC",
                    (org_id,),
                ).fetchall()

        return [dict(row) for row in rows]

    def get_escalation_heatmap(self, org_id: str, hours: int = 24) -> Dict[str, Any]:
        """Return escalation activity heatmap for the past N hours.

        Returns:
            dict with top_users, top_methods, events_by_hour, total_events.
        """
        with self._lock:
            with self._conn() as conn:
                # Events in time window
                events = conn.execute(
                    """
                    SELECT user_id, method, recorded_at, anomaly_score
                    FROM privilege_events
                    WHERE org_id=?
                      AND recorded_at >= datetime('now', ? || ' hours')
                    ORDER BY recorded_at DESC
                    """,
                    (org_id, f"-{hours}"),
                ).fetchall()

        events_list = [dict(e) for e in events]
        total = len(events_list)

        # Top users by event count
        user_counts: Dict[str, int] = {}
        method_counts: Dict[str, int] = {}
        hour_counts: Dict[str, int] = {}

        for e in events_list:
            user_counts[e["user_id"]] = user_counts.get(e["user_id"], 0) + 1
            method_counts[e["method"]] = method_counts.get(e["method"], 0) + 1

            # Bucket by hour
            try:
                dt = datetime.fromisoformat(e["recorded_at"].replace("Z", "+00:00"))
                hour_key = dt.strftime("%Y-%m-%dT%H:00")
                hour_counts[hour_key] = hour_counts.get(hour_key, 0) + 1
            except (ValueError, AttributeError):
                pass

        top_users = sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        top_methods = sorted(method_counts.items(), key=lambda x: x[1], reverse=True)

        return {
            "org_id": org_id,
            "hours": hours,
            "total_events": total,
            "top_users": [{"user_id": u, "count": c} for u, c in top_users],
            "top_methods": [{"method": m, "count": c} for m, c in top_methods],
            "events_by_hour": [{"hour": h, "count": c} for h, c in sorted(hour_counts.items())],
        }

    # ------------------------------------------------------------------
    # AD attack-chain detector (GAP-033 MERGE)
    # ------------------------------------------------------------------

    # Edge types we know how to chain together, in canonical order
    _AD_EDGE_PRIORITY: Dict[str, int] = {
        "kerberoastable": 10,
        "cracked_password": 20,
        "memberof_admincount": 30,
        "dcsync": 40,
        "unconstrained_delegation": 45,
        "esc1_enroll": 50,
        "domain_admin": 100,
    }

    def build_ad_attack_path(
        self,
        org_id: str,
        start_identity: str,
        target: str = "domain_admin",
        graph: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        max_hops: int = 8,
    ) -> Dict[str, Any]:
        """Build an Active Directory attack path from start_identity to a target.

        Accepts an optional `graph` adjacency dict where:
          graph[node] = [ { "to": <node>, "edge": <edge_type>,
                            "weight": <int>, "technique": <mitre> }, ... ]

        If no graph is supplied, a canonical template chain is emitted:
          kerberoastable → cracked_password → memberof_admincount → domain_admin

        Uses BFS (shortest path). Returns the chosen path, edge types,
        MITRE techniques, total weight, and a narrative.
        """
        if not start_identity or not target:
            raise ValueError("start_identity and target are required")

        if graph is None:
            # Canonical kill-chain if caller didn't give us a real graph
            graph = {
                start_identity: [
                    {
                        "to": f"{start_identity}_tgs_ticket",
                        "edge": "kerberoastable",
                        "weight": 10,
                        "technique": "T1558.003",
                        "note": "Request TGS for SPN and crack offline",
                    }
                ],
                f"{start_identity}_tgs_ticket": [
                    {
                        "to": f"{start_identity}_plaintext",
                        "edge": "cracked_password",
                        "weight": 15,
                        "technique": "T1110.002",
                        "note": "Offline crack of RC4 TGS hash",
                    }
                ],
                f"{start_identity}_plaintext": [
                    {
                        "to": "shadow_admin",
                        "edge": "memberof_admincount",
                        "weight": 20,
                        "technique": "T1078.002",
                        "note": "Account has stale adminCount=1 with retained ACLs",
                    }
                ],
                "shadow_admin": [
                    {
                        "to": "domain_admin",
                        "edge": "dcsync",
                        "weight": 40,
                        "technique": "T1003.006",
                        "note": "DCSync to dump krbtgt hash",
                    }
                ],
            }

        # BFS shortest path
        from collections import deque

        q = deque([(start_identity, [start_identity], [])])
        visited = {start_identity}
        best: Optional[Dict[str, Any]] = None

        hops = 0
        while q and hops <= max_hops * len(graph):
            hops += 1
            node, path, edges = q.popleft()
            if node == target:
                best = {"path": path, "edges": edges}
                break
            for edge in graph.get(node, []):
                nxt = edge.get("to")
                if not nxt or nxt in visited:
                    continue
                if len(path) > max_hops:
                    continue
                visited.add(nxt)
                q.append(
                    (
                        nxt,
                        path + [nxt],
                        edges
                        + [
                            {
                                "from": node,
                                "to": nxt,
                                "edge": edge.get("edge", "unknown"),
                                "weight": int(edge.get("weight", 1)),
                                "technique": edge.get("technique", ""),
                                "note": edge.get("note", ""),
                            }
                        ],
                    )
                )

        if not best:
            # Emit a "no path" result but still record the analysis
            result = {
                "org_id": org_id,
                "start_identity": start_identity,
                "target": target,
                "path_found": False,
                "path": [],
                "edges": [],
                "hop_count": 0,
                "total_weight": 0,
                "mitre_techniques": [],
                "risk_level": "low",
                "narrative": (
                    f"No attack path discovered from '{start_identity}' to "
                    f"'{target}' within {max_hops} hops."
                ),
                "analysed_at": datetime.now(timezone.utc).isoformat(),
            }
            return result

        edges = best["edges"]
        total_weight = sum(e["weight"] for e in edges)
        techniques = sorted({e["technique"] for e in edges if e.get("technique")})
        hop_count = len(edges)

        # Risk level based on total path "difficulty" and presence of DCSync
        has_dcsync = any(e.get("edge") == "dcsync" for e in edges)
        if has_dcsync or total_weight >= 60:
            risk_level = "critical"
        elif total_weight >= 30:
            risk_level = "high"
        elif total_weight >= 15:
            risk_level = "medium"
        else:
            risk_level = "low"

        narrative_parts: List[str] = []
        for e in edges:
            narrative_parts.append(
                f"{e['from']} --[{e['edge']}]--> {e['to']}"
                + (f" ({e['technique']})" if e["technique"] else "")
            )
        narrative = (
            f"{start_identity} → {target} in {hop_count} hops: "
            + " ; ".join(narrative_parts)
        )

        result = {
            "org_id": org_id,
            "start_identity": start_identity,
            "target": target,
            "path_found": True,
            "path": best["path"],
            "edges": edges,
            "hop_count": hop_count,
            "total_weight": total_weight,
            "mitre_techniques": techniques,
            "risk_level": risk_level,
            "narrative": narrative,
            "analysed_at": datetime.now(timezone.utc).isoformat(),
        }

        # Optional: persist to TrustGraph for cross-engine visibility
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit(
                        "FINDING_CREATED",
                        {
                            "entity_type": "ad_attack_path",
                            "entity_id": f"{start_identity}->{target}",
                            "org_id": org_id,
                            "source_engine": "privilege_escalation_detector",
                            "risk_level": risk_level,
                        },
                    )
            except Exception:
                pass

        return result

    def get_detection_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate detection statistics for an org."""
        with self._lock:
            with self._conn() as conn:
                total = conn.execute(
                    "SELECT COUNT(*) FROM privilege_events WHERE org_id=?", (org_id,)
                ).fetchone()[0]

                anomalies = conn.execute(
                    "SELECT COUNT(*) FROM privilege_events WHERE org_id=? AND anomaly_score >= 60",
                    (org_id,),
                ).fetchone()[0]

                # Blocked attempts: events matching rules with action='block'
                blocked = conn.execute(
                    """
                    SELECT COUNT(DISTINCT pe.id)
                    FROM privilege_events pe
                    WHERE pe.org_id=?
                      AND EXISTS (
                          SELECT 1 FROM detection_rules dr
                          WHERE dr.org_id=? AND dr.action='block'
                      )
                      AND pe.anomaly_score >= 60
                    """,
                    (org_id, org_id),
                ).fetchone()[0]

                by_method = conn.execute(
                    """
                    SELECT method, COUNT(*) as count
                    FROM privilege_events WHERE org_id=?
                    GROUP BY method
                    """,
                    (org_id,),
                ).fetchall()

                by_risk = conn.execute(
                    """
                    SELECT risk_level, COUNT(*) as count
                    FROM privilege_events WHERE org_id=?
                    GROUP BY risk_level
                    """,
                    (org_id,),
                ).fetchall()

                rule_count = conn.execute(
                    "SELECT COUNT(*) FROM detection_rules WHERE org_id=?", (org_id,)
                ).fetchone()[0]

        return {
            "org_id": org_id,
            "total_events": total,
            "anomalous_events": anomalies,
            "blocked_attempts": blocked,
            "detection_rules": rule_count,
            "by_method": {row["method"]: row["count"] for row in by_method},
            "by_risk_level": {row["risk_level"]: row["count"] for row in by_risk},
        }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_engine_instance: Optional[PrivilegeEscalationDetectorEngine] = None


def get_privilege_escalation_detector() -> PrivilegeEscalationDetectorEngine:
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = PrivilegeEscalationDetectorEngine()
    return _engine_instance
