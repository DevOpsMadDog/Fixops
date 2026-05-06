"""Alert Triage Engine — ALDECI.

Centralized alert ingestion and triage workflow across all security sources
(SIEM, EDR, NDR, Cloud, WAF, IDS, Firewall). Supports bulk triage, priority
auto-assignment, escalation, and queue management.

Compliance: NIST CSF DE.AE-2, ISO/IEC 27001 A.16.1.5, SOC 2 CC7.3
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "alert_triage.db"
)

_VALID_SOURCE_SYSTEMS = {"siem", "edr", "ndr", "cloud", "waf", "ids", "firewall", "custom"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_VALID_TRIAGE_STATUSES = {
    "new", "triaging", "escalated", "investigating",
    "resolved", "false_positive", "duplicate",
}
_VALID_PRIORITIES = {"p1", "p2", "p3", "p4"}

_SEVERITY_TO_PRIORITY = {
    "critical": "p1",
    "high": "p2",
    "medium": "p3",
    "low": "p4",
    "info": "p4",
}

_PRIORITY_ORDER = {"p1": 1, "p2": 2, "p3": 3, "p4": 4}


class AlertTriageEngine:
    """SQLite WAL-backed Alert Triage engine.

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
                CREATE TABLE IF NOT EXISTS at_alerts (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    title             TEXT NOT NULL DEFAULT '',
                    source_system     TEXT NOT NULL DEFAULT 'siem',
                    severity          TEXT NOT NULL DEFAULT 'medium',
                    priority          TEXT NOT NULL DEFAULT 'p3',
                    raw_alert_json    TEXT NOT NULL DEFAULT '{}',
                    status            TEXT NOT NULL DEFAULT 'new',
                    assigned_to       TEXT NOT NULL DEFAULT '',
                    triage_notes      TEXT NOT NULL DEFAULT '',
                    escalation_reason TEXT NOT NULL DEFAULT '',
                    ingested_at       DATETIME,
                    triaged_at        DATETIME,
                    resolved_at       DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_at_org_status
                    ON at_alerts (org_id, status);

                CREATE INDEX IF NOT EXISTS idx_at_org_priority
                    ON at_alerts (org_id, priority, ingested_at);
                """
            )

    _local = threading.local()

    def _conn(self) -> sqlite3.Connection:
        """Return a per-thread cached connection (avoids repeated connect overhead)."""
        cache = self._local.__dict__
        key = f"conn_{self.db_path}"
        conn = cache.get(key)
        if conn is None:
            conn = sqlite3.connect(self.db_path, timeout=10, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            cache[key] = conn
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ingest_alert(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Ingest a new alert with auto-priority assignment."""
        source_system = data.get("source_system", "siem")
        if source_system not in _VALID_SOURCE_SYSTEMS:
            raise ValueError(
                f"Invalid source_system '{source_system}'. "
                f"Valid: {sorted(_VALID_SOURCE_SYSTEMS)}"
            )
        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity '{severity}'. Valid: {sorted(_VALID_SEVERITIES)}"
            )

        priority = _SEVERITY_TO_PRIORITY[severity]
        raw = data.get("raw_alert_json", data.get("raw_alert", {}))
        if isinstance(raw, dict):
            raw = json.dumps(raw)

        alert_id = str(uuid.uuid4())
        now = self._now()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO at_alerts
                        (id, org_id, title, source_system, severity, priority,
                         raw_alert_json, status, assigned_to, triage_notes,
                         escalation_reason, ingested_at, triaged_at, resolved_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        alert_id,
                        org_id,
                        data.get("title", ""),
                        source_system,
                        severity,
                        priority,
                        raw,
                        "new",
                        "",
                        "",
                        "",
                        now,
                        None,
                        None,
                    ),
                )

        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus:
                    bus.emit("ALERT_CREATED", {"entity_type": "alert", "entity_id": str(alert_id), "org_id": org_id, "source_engine": "alert_triage_engine"})
            except Exception:
                pass  # Event emission should never break the main operation
        return self.get_alert(org_id, alert_id)  # type: ignore[return-value]

    def list_alerts(
        self,
        org_id: str,
        source_system: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        priority: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List alerts with optional filters, newest first."""
        query = "SELECT * FROM at_alerts WHERE org_id = ?"
        params: List[Any] = [org_id]

        if source_system:
            query += " AND source_system = ?"
            params.append(source_system)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if status:
            query += " AND status = ?"
            params.append(status)
        if priority:
            query += " AND priority = ?"
            params.append(priority)

        query += " ORDER BY ingested_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def get_alert(self, org_id: str, alert_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single alert by ID (org-scoped)."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM at_alerts WHERE id = ? AND org_id = ?",
                (alert_id, org_id),
            ).fetchone()
        return self._row(row) if row else None

    def alert_exists_anywhere(self, alert_id: str) -> bool:
        """Return True if an alert with this ID exists in any org.

        Used by the bulk-triage router to distinguish "missing entirely"
        (404) from "exists but in a different tenant" (403). The router
        deliberately never reveals which tenant owns the foreign ID — only
        that it isn't in the caller's org.
        """
        if not alert_id:
            return False
        with self._conn() as conn:
            row = conn.execute(
                "SELECT 1 FROM at_alerts WHERE id = ? LIMIT 1",
                (alert_id,),
            ).fetchone()
        return row is not None

    def triage_alert(
        self, org_id: str, alert_id: str, triage_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update alert triage status and metadata."""
        triage_status = triage_data.get("triage_status") or triage_data.get("status")
        if triage_status not in _VALID_TRIAGE_STATUSES:
            raise ValueError(
                f"Invalid triage_status '{triage_status}'. "
                f"Valid: {sorted(_VALID_TRIAGE_STATUSES)}"
            )

        alert = self.get_alert(org_id, alert_id)
        if alert is None:
            raise KeyError(f"Alert '{alert_id}' not found for org '{org_id}'")

        now = self._now()
        assigned_to = triage_data.get("assigned_to", alert["assigned_to"])
        triage_notes = triage_data.get("triage_notes", alert["triage_notes"])
        escalation_reason = alert["escalation_reason"]
        triaged_at = now
        resolved_at = alert["resolved_at"]

        if triage_status == "escalated":
            escalation_reason = triage_data.get("escalation_reason", escalation_reason)
        if triage_status == "resolved":
            resolved_at = now

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    UPDATE at_alerts
                    SET status = ?, assigned_to = ?, triage_notes = ?,
                        escalation_reason = ?, triaged_at = ?, resolved_at = ?
                    WHERE id = ? AND org_id = ?
                    """,
                    (
                        triage_status,
                        assigned_to,
                        triage_notes,
                        escalation_reason,
                        triaged_at,
                        resolved_at,
                        alert_id,
                        org_id,
                    ),
                )

        return self.get_alert(org_id, alert_id)  # type: ignore[return-value]

    def bulk_triage(
        self, org_id: str, alert_ids: List[str], action: str
    ) -> Dict[str, Any]:
        """Apply the same triage action to multiple alerts.

        action: "resolve" | "false_positive" | "escalate"
        Returns count of updated alerts.

        Raises ValueError on empty alert_ids or invalid action — the router
        layer turns these into HTTP 422.
        """
        if not org_id or not isinstance(org_id, str):
            raise ValueError("org_id is required and must be a non-empty string")
        if not alert_ids:
            raise ValueError("alert_ids must contain at least one ID")
        # Defensive: drop empty/whitespace IDs the caller might pass directly.
        cleaned_ids = [aid.strip() for aid in alert_ids if isinstance(aid, str) and aid.strip()]
        if not cleaned_ids:
            raise ValueError("alert_ids must contain at least one non-empty ID")
        alert_ids = cleaned_ids

        _valid_actions = {"resolve", "false_positive", "escalate"}
        if action not in _valid_actions:
            raise ValueError(
                f"Invalid action '{action}'. Valid: {sorted(_valid_actions)}"
            )

        status_map = {
            "resolve": "resolved",
            "false_positive": "false_positive",
            "escalate": "escalated",
        }
        new_status = status_map[action]
        now = self._now()

        updated = 0
        with self._lock:
            with self._conn() as conn:
                for alert_id in alert_ids:
                    extra: tuple
                    if new_status == "resolved":
                        extra = (now,)
                        sql = (
                            "UPDATE at_alerts SET status = ?, triaged_at = ?, resolved_at = ? "
                            "WHERE id = ? AND org_id = ?"
                        )
                        params_t = (new_status, now) + extra + (alert_id, org_id)
                    else:
                        sql = (
                            "UPDATE at_alerts SET status = ?, triaged_at = ? "
                            "WHERE id = ? AND org_id = ?"
                        )
                        params_t = (new_status, now, alert_id, org_id)

                    cur = conn.execute(sql, params_t)
                    updated += cur.rowcount

        return {"updated": updated, "action": action, "alert_ids": alert_ids}

    def get_triage_queue(self, org_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Return new + triaging alerts ordered by priority (p1 first) then ingested_at."""
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM at_alerts
                WHERE org_id = ? AND status IN ('new', 'triaging')
                ORDER BY
                    CASE priority
                        WHEN 'p1' THEN 1
                        WHEN 'p2' THEN 2
                        WHEN 'p3' THEN 3
                        WHEN 'p4' THEN 4
                        ELSE 5
                    END,
                    ingested_at ASC
                LIMIT ?
                """,
                (org_id, limit),
            ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # TrustGraph context
    # ------------------------------------------------------------------

    def get_alert_context(self, org_id: str, alert_id: str) -> Dict[str, Any]:
        """Query TrustGraph for cross-domain context about an alert.

        Returns historical alerts from same source, related findings, and asset criticality.
        Degrades gracefully when TrustGraph is unavailable.
        """
        context: Dict[str, Any] = {
            "related_assets": [],
            "related_findings": [],
            "related_incidents": [],
            "trustgraph_available": False,
        }
        try:
            from trustgraph.knowledge_store import KnowledgeStore
            store = KnowledgeStore()
            context["trustgraph_available"] = True

            alert = self.get_alert(org_id, alert_id)
            search_term = alert.get("title", alert_id) if alert else alert_id

            for core_id in (1, 2, 3):
                try:
                    results = store.search(core_id=core_id, query_text=search_term, limit=10)
                    for entity in results:
                        if entity.org_id not in ("default", org_id):
                            continue
                        entry = {"id": entity.entity_id, "name": entity.name, "type": entity.entity_type}
                        etype = entity.entity_type.lower()
                        if etype in ("asset", "service", "host"):
                            context["related_assets"].append(entry)
                        elif etype in ("finding", "vulnerability", "cve"):
                            context["related_findings"].append(entry)
                        elif etype in ("incident", "breach", "alert"):
                            context["related_incidents"].append(entry)
                except Exception:
                    pass

            neighbors = store.get_neighbors(entity_id=alert_id, depth=1)
            for n in neighbors:
                if n.org_id not in ("default", org_id):
                    continue
                entry = {"id": n.entity_id, "name": n.name, "type": n.entity_type}
                etype = n.entity_type.lower()
                if etype in ("asset", "service", "host"):
                    if entry not in context["related_assets"]:
                        context["related_assets"].append(entry)
                elif etype in ("finding", "vulnerability", "cve"):
                    if entry not in context["related_findings"]:
                        context["related_findings"].append(entry)
                elif etype in ("incident", "breach", "alert"):
                    if entry not in context["related_incidents"]:
                        context["related_incidents"].append(entry)
        except Exception:
            pass
        return context

    def investigate(self, org_id: str, alert_id: str) -> Dict[str, Any]:
        """SOC analyst investigation: correlate the alert across all security domains.

        Returns:
          - alert: the alert record itself
          - related_alerts: same source_system or severity in last 24 h (excluding this alert)
          - affected_assets: assets extracted from raw_alert_json (host, ip)
          - incident_history: past incidents on those assets from incident_orchestration DB
          - ioc_summary: IOCs parsed from raw_alert_json (ips, hashes, domains)
          - graphrag_context: TrustGraph cross-domain context (degrades gracefully)
          - recommended_playbook: heuristic playbook name based on source/severity
        """
        alert = self.get_alert(org_id, alert_id)
        if alert is None:
            raise KeyError(f"Alert '{alert_id}' not found for org '{org_id}'")

        # ── 1. Related alerts: same source_system in last 24 h ──────────────
        related_alerts: List[Dict[str, Any]] = []
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT id, title, severity, priority, status, source_system, ingested_at
                FROM at_alerts
                WHERE org_id = ?
                  AND id != ?
                  AND (source_system = ? OR severity = ?)
                  AND ingested_at >= datetime('now', '-24 hours')
                ORDER BY ingested_at DESC
                LIMIT 10
                """,
                (org_id, alert_id, alert["source_system"], alert["severity"]),
            ).fetchall()
        related_alerts = [self._row(r) for r in rows]

        # ── 2. Extract affected assets from raw_alert_json ──────────────────
        affected_assets: List[Dict[str, str]] = []
        try:
            raw = alert.get("raw_alert_json") or "{}"
            if isinstance(raw, str):
                import json as _json
                raw_data = _json.loads(raw)
            else:
                raw_data = raw
            host = raw_data.get("host") or raw_data.get("hostname") or raw_data.get("asset")
            ip   = raw_data.get("ip") or raw_data.get("src_ip") or raw_data.get("dest_ip")
            user = raw_data.get("user") or raw_data.get("username")
            if host:
                affected_assets.append({"type": "host", "value": str(host)})
            if ip:
                affected_assets.append({"type": "ip", "value": str(ip)})
            if user:
                affected_assets.append({"type": "user", "value": str(user)})
        except Exception:
            pass

        # ── 3. Incident history for affected assets ──────────────────────────
        incident_history: List[Dict[str, Any]] = []
        try:
            from pathlib import Path as _Path
            _inc_db = str(_Path(self.db_path).parent / "incident_orchestration.db")
            if _Path(_inc_db).exists():
                inc_conn = sqlite3.connect(_inc_db, timeout=5)
                inc_conn.row_factory = sqlite3.Row
                asset_values = [a["value"] for a in affected_assets]
                if asset_values:
                    ",".join("?" * len(asset_values))
                    like_clauses = " OR ".join(
                        "title LIKE ? OR source LIKE ?" for _ in asset_values
                    )
                    params: List[Any] = []
                    for v in asset_values:
                        params.extend([f"%{v}%", f"%{v}%"])
                    params.append(org_id)
                    rows = inc_conn.execute(
                        f"""
                        SELECT id, title, severity, status, created_at
                        FROM incidents
                        WHERE ({like_clauses}) AND org_id = ?
                        ORDER BY created_at DESC
                        LIMIT 5
                        """,
                        params,
                    ).fetchall()
                    incident_history = [dict(r) for r in rows]
                inc_conn.close()
        except Exception:
            pass

        # ── 4. IOC summary from raw payload ─────────────────────────────────
        import re as _re
        ioc_summary: Dict[str, List[str]] = {"ips": [], "domains": [], "hashes": []}
        try:
            raw_str = alert.get("raw_alert_json") or ""
            if not isinstance(raw_str, str):
                import json as _json2
                raw_str = _json2.dumps(raw_str)
            ip_pattern     = _re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
            domain_pattern = _re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|ru|cn|xyz|club)\b", _re.I)
            hash_pattern   = _re.compile(r"\b[0-9a-f]{32,64}\b", _re.I)
            ioc_summary["ips"]     = list(set(ip_pattern.findall(raw_str)))[:10]
            ioc_summary["domains"] = list(set(domain_pattern.findall(raw_str)))[:10]
            ioc_summary["hashes"]  = list(set(hash_pattern.findall(raw_str)))[:5]
        except Exception:
            pass

        # ── 5. TrustGraph GraphRAG context (graceful degradation) ───────────
        graphrag_context = self.get_alert_context(org_id, alert_id)

        # ── 6. Heuristic playbook recommendation ────────────────────────────
        _playbook_map = {
            ("siem",    "critical"): "IR-P1: SIEM Critical Incident Response",
            ("edr",     "critical"): "IR-P2: Endpoint Compromise Containment",
            ("edr",     "high"):     "IR-P3: Endpoint Threat Hunting",
            ("ndr",     "high"):     "IR-P4: Network Threat Containment",
            ("cloud",   "critical"): "IR-P5: Cloud Breach Response",
            ("waf",     "high"):     "IR-P6: Application Attack Response",
            ("ids",     "high"):     "IR-P7: Intrusion Detection Response",
            ("firewall","high"):     "IR-P8: Perimeter Breach Response",
        }
        src = (alert.get("source_system") or "").lower()
        sev = (alert.get("severity") or "").lower()
        recommended_playbook = (
            _playbook_map.get((src, sev))
            or _playbook_map.get((src, "high"))
            or "IR-P0: General Security Incident Response"
        )

        return {
            "alert": alert,
            "related_alerts": related_alerts,
            "affected_assets": affected_assets,
            "incident_history": incident_history,
            "ioc_summary": ioc_summary,
            "graphrag_context": graphrag_context,
            "recommended_playbook": recommended_playbook,
        }

    def get_triage_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate triage statistics for the org."""
        with self._conn() as conn:
            # Single-pass conditional aggregation replaces 4 separate COUNT queries
            agg = conn.execute(
                """
                SELECT
                    COUNT(*) AS total,
                    COUNT(CASE WHEN status = 'new' THEN 1 END) AS new_alerts,
                    COUNT(CASE WHEN status = 'escalated' THEN 1 END) AS escalated,
                    COUNT(CASE WHEN status = 'false_positive' THEN 1 END) AS fp_count
                FROM at_alerts WHERE org_id = ?
                """,
                (org_id,),
            ).fetchone()
            total      = agg["total"]
            new_alerts = agg["new_alerts"]
            escalated  = agg["escalated"]
            fp_count   = agg["fp_count"]

            false_positive_rate = (fp_count / total * 100.0) if total else 0.0

            # avg triage time: minutes from ingested_at to triaged_at
            triage_rows = conn.execute(
                """
                SELECT ingested_at, triaged_at FROM at_alerts
                WHERE org_id = ? AND triaged_at IS NOT NULL AND ingested_at IS NOT NULL
                """,
                (org_id,),
            ).fetchall()

            avg_triage_time_minutes = 0.0
            if triage_rows:
                total_minutes = 0.0
                valid = 0
                for r in triage_rows:
                    try:
                        ingested = datetime.fromisoformat(r["ingested_at"])
                        triaged = datetime.fromisoformat(r["triaged_at"])
                        diff = (triaged - ingested).total_seconds() / 60.0
                        total_minutes += diff
                        valid += 1
                    except Exception:
                        pass
                avg_triage_time_minutes = total_minutes / valid if valid else 0.0

            # by source_system
            src_rows = conn.execute(
                """
                SELECT source_system, COUNT(*) as cnt
                FROM at_alerts WHERE org_id = ?
                GROUP BY source_system
                """,
                (org_id,),
            ).fetchall()
            by_source_system = {r["source_system"]: r["cnt"] for r in src_rows}

            # by severity
            sev_rows = conn.execute(
                """
                SELECT severity, COUNT(*) as cnt
                FROM at_alerts WHERE org_id = ?
                GROUP BY severity
                """,
                (org_id,),
            ).fetchall()
            by_severity = {r["severity"]: r["cnt"] for r in sev_rows}

        return {
            "total_alerts": total,
            "new_alerts": new_alerts,
            "escalated_alerts": escalated,
            "false_positive_rate": round(false_positive_rate, 2),
            "avg_triage_time_minutes": round(avg_triage_time_minutes, 2),
            "by_source_system": by_source_system,
            "by_severity": by_severity,
        }
