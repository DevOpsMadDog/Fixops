"""SOC Alert Triage AI Engine — ALDECI.

ML-powered alert classification for Security Operations Centers.

Capabilities:
  - Deterministic ML-simulation scoring (no external LLM needed)
  - MITRE ATT&CK technique + tactic mapping
  - Analyst verdict workflow (confirm / dispute)
  - Rule-based override engine
  - Triage session tracking
  - Daily metrics + KPI aggregation

Compliance: MITRE ATT&CK, NIST SP 800-61 (IR), SOC 2 Type II
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

_DATA_DIR = Path(__file__).resolve().parents[2] / ".fixops_data"

_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_VALID_SOURCES = {"siem", "edr", "ndr", "xdr", "manual"}
_VALID_CLASSIFICATIONS = {
    "true_positive", "false_positive", "benign_true_positive", "undetermined"
}
_VALID_ACTIONS = {"escalate", "investigate", "monitor", "close", "block"}
_VALID_STATUSES = {"new", "triaging", "escalated", "investigating", "closed"}
_VALID_VERDICTS = {"confirmed", "disputed", "closed"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


# ---------------------------------------------------------------------------
# ML Scoring Rules — deterministic keyword-based ML simulation
# ---------------------------------------------------------------------------

_SCORING_RULES = [
    # (keywords, score_delta, mitre_technique, mitre_tactic)
    (["brute force", "credential"], 0.3, "T1110", "credential_access"),
    (["lateral movement"], 0.4, "T1021", "lateral_movement"),
    (["exfiltration", "data transfer"], 0.4, "T1041", "exfiltration"),
    (["privilege", "escalation"], 0.35, "T1068", "privilege_escalation"),
    (["ransomware", "encryption"], 0.5, "T1486", "impact"),
    (["phishing", "malicious email"], 0.3, "T1566", "initial_access"),
    (["port scan", "reconnaissance"], 0.2, "T1046", "discovery"),
]


class SOCTriageEngine:
    """SQLite WAL-backed SOC Alert Triage engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    Each org gets its own database file.
    """

    _instances: Dict[str, "SOCTriageEngine"] = {}
    _instances_lock = threading.Lock()

    def __init__(self, org_id: str) -> None:
        self.org_id = org_id
        db_name = f"{org_id}_soc_triage.db"
        self.db_path = str(_DATA_DIR / db_name)
        self._lock = threading.RLock()
        self._init_db()

    @classmethod
    def for_org(cls, org_id: str) -> "SOCTriageEngine":
        """Return (or create) the singleton engine for org_id."""
        with cls._instances_lock:
            if org_id not in cls._instances:
                cls._instances[org_id] = cls(org_id)
            return cls._instances[org_id]

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        _DATA_DIR.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS triage_alerts (
                    id                    TEXT PRIMARY KEY,
                    org_id                TEXT NOT NULL,
                    alert_source          TEXT NOT NULL DEFAULT 'siem',
                    alert_type            TEXT NOT NULL DEFAULT '',
                    title                 TEXT NOT NULL DEFAULT '',
                    raw_description       TEXT NOT NULL DEFAULT '',
                    severity_original     TEXT NOT NULL DEFAULT 'medium',
                    severity_ai           TEXT NOT NULL DEFAULT 'medium',
                    confidence_score      REAL NOT NULL DEFAULT 0.0,
                    classification        TEXT NOT NULL DEFAULT 'undetermined',
                    mitre_technique_id    TEXT NOT NULL DEFAULT '',
                    mitre_tactic          TEXT NOT NULL DEFAULT '',
                    threat_actor_hypothesis TEXT NOT NULL DEFAULT '',
                    recommended_action    TEXT NOT NULL DEFAULT 'monitor',
                    reasoning             TEXT NOT NULL DEFAULT '',
                    analyst_id            TEXT NOT NULL DEFAULT '',
                    analyst_verdict       TEXT,
                    created_at            TEXT NOT NULL,
                    triaged_at            TEXT,
                    closed_at             TEXT,
                    status                TEXT NOT NULL DEFAULT 'new',
                    priority_rank         INTEGER NOT NULL DEFAULT 50
                );

                CREATE INDEX IF NOT EXISTS idx_ta_org_status
                    ON triage_alerts (org_id, status);
                CREATE INDEX IF NOT EXISTS idx_ta_org_severity
                    ON triage_alerts (org_id, severity_original);
                CREATE INDEX IF NOT EXISTS idx_ta_org_classification
                    ON triage_alerts (org_id, classification);
                CREATE INDEX IF NOT EXISTS idx_ta_org_created
                    ON triage_alerts (org_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS triage_rules (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    rule_name       TEXT NOT NULL DEFAULT '',
                    conditions      TEXT NOT NULL DEFAULT '{}',
                    action          TEXT NOT NULL DEFAULT 'monitor',
                    override_severity TEXT NOT NULL DEFAULT '',
                    tag             TEXT NOT NULL DEFAULT '',
                    enabled         INTEGER NOT NULL DEFAULT 1,
                    hit_count       INTEGER NOT NULL DEFAULT 0,
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_tr_org_enabled
                    ON triage_rules (org_id, enabled);

                CREATE TABLE IF NOT EXISTS triage_sessions (
                    id                   TEXT PRIMARY KEY,
                    org_id               TEXT NOT NULL,
                    analyst_id           TEXT NOT NULL,
                    alerts_reviewed      INTEGER NOT NULL DEFAULT 0,
                    alerts_confirmed_tp  INTEGER NOT NULL DEFAULT 0,
                    alerts_closed_fp     INTEGER NOT NULL DEFAULT 0,
                    session_start        TEXT NOT NULL,
                    session_end          TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_ts_org_analyst
                    ON triage_sessions (org_id, analyst_id);

                CREATE TABLE IF NOT EXISTS triage_metrics (
                    id                        TEXT PRIMARY KEY,
                    org_id                    TEXT NOT NULL,
                    date                      TEXT NOT NULL,
                    total_alerts              INTEGER NOT NULL DEFAULT 0,
                    true_positives            INTEGER NOT NULL DEFAULT 0,
                    false_positives           INTEGER NOT NULL DEFAULT 0,
                    escalated                 INTEGER NOT NULL DEFAULT 0,
                    avg_triage_time_minutes   REAL NOT NULL DEFAULT 0.0,
                    analyst_efficiency_score  REAL NOT NULL DEFAULT 0.0,
                    created_at                TEXT NOT NULL,
                    UNIQUE (org_id, date)
                );

                CREATE INDEX IF NOT EXISTS idx_tm_org_date
                    ON triage_metrics (org_id, date DESC);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # AI Triage (deterministic ML simulation)
    # ------------------------------------------------------------------

    def _ai_triage(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Deterministic ML scoring. No external LLM required.

        Returns a dict with: severity_ai, confidence_score, classification,
        recommended_action, mitre_technique_id, mitre_tactic, reasoning,
        threat_actor_hypothesis, priority_rank.
        """
        title_lower = (alert.get("title") or "").lower()
        severity_orig = alert.get("severity_original", "medium")

        score = 0.0
        mitre_technique_id = ""
        mitre_tactic = ""
        matched_keywords: List[str] = []

        for keywords, delta, technique, tactic in _SCORING_RULES:
            for kw in keywords:
                if kw in title_lower:
                    score += delta
                    matched_keywords.append(kw)
                    if not mitre_technique_id:
                        mitre_technique_id = technique
                        mitre_tactic = tactic
                    break  # only one keyword match per rule

        # Severity amplifiers / dampeners
        if severity_orig == "critical":
            score = min(0.95, score * 1.5)
        elif severity_orig == "high":
            score = min(0.95, score * 1.2)
        elif severity_orig == "low":
            score *= 0.7

        # Derive classification + recommended_action
        if score > 0.7:
            classification = "true_positive"
            recommended_action = "escalate"
            severity_ai = "critical" if severity_orig == "critical" else "high"
            priority_rank = 10
        elif score > 0.4:
            classification = "undetermined"
            recommended_action = "investigate"
            severity_ai = severity_orig
            priority_rank = 30
        elif score < 0.15:
            classification = "false_positive"
            recommended_action = "close"
            severity_ai = "info"
            priority_rank = 90
        else:
            classification = "undetermined"
            recommended_action = "monitor"
            severity_ai = severity_orig
            priority_rank = 60

        confidence_score = min(0.95, score + 0.1)

        # Build reasoning string
        if matched_keywords:
            kw_str = ", ".join(f'"{k}"' for k in matched_keywords)
            reasoning = (
                f"Matched keywords: {kw_str}. "
                f"Raw score: {score:.2f} after severity multiplier. "
                f"Classification: {classification} (threshold: TP>0.7, FP<0.15)."
            )
        else:
            reasoning = (
                f"No keyword patterns matched. Raw score: {score:.2f}. "
                f"Classified as {classification} by default."
            )

        # Simple threat actor hypothesis based on tactic
        tactic_actor_map = {
            "credential_access": "APT group or opportunistic threat actor targeting credential stores",
            "lateral_movement": "Advanced persistent threat actor conducting post-exploitation movement",
            "exfiltration": "Data-motivated threat actor (espionage or financial); possible APT",
            "privilege_escalation": "Insider threat or post-compromise actor seeking elevated access",
            "impact": "Ransomware operator or destructive threat actor (possibly state-sponsored)",
            "initial_access": "Phishing campaign operator; likely commodity malware distribution",
            "discovery": "Reconnaissance actor; possible prelude to targeted attack",
        }
        threat_actor_hypothesis = tactic_actor_map.get(mitre_tactic, "Unknown or generic threat actor")

        return {
            "severity_ai": severity_ai,
            "confidence_score": round(confidence_score, 4),
            "classification": classification,
            "recommended_action": recommended_action,
            "mitre_technique_id": mitre_technique_id,
            "mitre_tactic": mitre_tactic,
            "threat_actor_hypothesis": threat_actor_hypothesis,
            "reasoning": reasoning,
            "priority_rank": priority_rank,
        }

    # ------------------------------------------------------------------
    # Alert ingestion
    # ------------------------------------------------------------------

    def ingest_alert(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Ingest an alert, run AI triage, persist, and return the alert dict."""
        alert_source = data.get("alert_source", "siem")
        severity_original = data.get("severity_original", "medium")
        if severity_original not in _VALID_SEVERITIES:
            severity_original = "medium"

        now = _now_iso()
        alert: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "alert_source": alert_source if alert_source in _VALID_SOURCES else "manual",
            "alert_type": data.get("alert_type", ""),
            "title": data.get("title", ""),
            "raw_description": data.get("raw_description", ""),
            "severity_original": severity_original,
            "severity_ai": severity_original,
            "confidence_score": 0.0,
            "classification": "undetermined",
            "mitre_technique_id": "",
            "mitre_tactic": "",
            "threat_actor_hypothesis": "",
            "recommended_action": "monitor",
            "reasoning": "",
            "analyst_id": data.get("analyst_id", ""),
            "analyst_verdict": None,
            "created_at": now,
            "triaged_at": None,
            "closed_at": None,
            "status": "new",
            "priority_rank": 50,
        }

        # AI triage
        triage = self._ai_triage(alert)
        alert.update(triage)
        alert["triaged_at"] = now
        alert["status"] = "new"

        # Auto-escalate if needed
        if triage["recommended_action"] == "escalate":
            alert["status"] = "escalated"

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO triage_alerts
                       (id, org_id, alert_source, alert_type, title, raw_description,
                        severity_original, severity_ai, confidence_score, classification,
                        mitre_technique_id, mitre_tactic, threat_actor_hypothesis,
                        recommended_action, reasoning, analyst_id, analyst_verdict,
                        created_at, triaged_at, closed_at, status, priority_rank)
                       VALUES
                       (:id, :org_id, :alert_source, :alert_type, :title, :raw_description,
                        :severity_original, :severity_ai, :confidence_score, :classification,
                        :mitre_technique_id, :mitre_tactic, :threat_actor_hypothesis,
                        :recommended_action, :reasoning, :analyst_id, :analyst_verdict,
                        :created_at, :triaged_at, :closed_at, :status, :priority_rank)""",
                    alert,
                )

        # Update daily metrics
        self._bump_daily_metrics(org_id, alert)

        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ALERT_CREATED", {"entity_type": "soc_triage", "org_id": org_id, "source_engine": "soc_triage"})
            except Exception:
                pass

        return alert

    def _bump_daily_metrics(self, org_id: str, alert: Dict[str, Any]) -> None:
        """Upsert the daily metrics row for today."""
        today = _today()
        now = _now_iso()
        classification = alert.get("classification", "undetermined")
        is_tp = 1 if classification == "true_positive" else 0
        is_fp = 1 if classification == "false_positive" else 0
        is_esc = 1 if alert.get("recommended_action") == "escalate" else 0

        with self._lock:
            with self._conn() as conn:
                existing = conn.execute(
                    "SELECT id FROM triage_metrics WHERE org_id = ? AND date = ?",
                    (org_id, today),
                ).fetchone()
                if existing:
                    conn.execute(
                        """UPDATE triage_metrics
                           SET total_alerts = total_alerts + 1,
                               true_positives = true_positives + ?,
                               false_positives = false_positives + ?,
                               escalated = escalated + ?
                           WHERE org_id = ? AND date = ?""",
                        (is_tp, is_fp, is_esc, org_id, today),
                    )
                else:
                    conn.execute(
                        """INSERT INTO triage_metrics
                           (id, org_id, date, total_alerts, true_positives, false_positives,
                            escalated, avg_triage_time_minutes, analyst_efficiency_score, created_at)
                           VALUES (?, ?, ?, 1, ?, ?, ?, 0.0, 0.0, ?)""",
                        (str(uuid.uuid4()), org_id, today, is_tp, is_fp, is_esc, now),
                    )

    # ------------------------------------------------------------------
    # Alert listing + retrieval
    # ------------------------------------------------------------------

    def list_alerts(
        self,
        org_id: str,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        classification: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Return filtered alerts ordered by priority_rank ASC, created_at DESC."""
        sql = "SELECT * FROM triage_alerts WHERE org_id = ?"
        params: list = [org_id]
        if status:
            sql += " AND status = ?"
            params.append(status)
        if severity:
            sql += " AND severity_original = ?"
            params.append(severity)
        if classification:
            sql += " AND classification = ?"
            params.append(classification)
        sql += " ORDER BY priority_rank ASC, created_at DESC LIMIT ?"
        params.append(limit)
        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    def get_alert(self, org_id: str, alert_id: str) -> Optional[Dict[str, Any]]:
        """Return a single alert with full context."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM triage_alerts WHERE org_id = ? AND id = ?",
                (org_id, alert_id),
            ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Analyst verdict
    # ------------------------------------------------------------------

    def update_verdict(
        self,
        org_id: str,
        alert_id: str,
        analyst_id: str,
        verdict: str,
        notes: str = "",
    ) -> Optional[Dict[str, Any]]:
        """Analyst confirms or disputes the AI verdict."""
        if verdict not in _VALID_VERDICTS:
            raise ValueError(f"Invalid verdict: {verdict}. Must be one of {_VALID_VERDICTS}")

        now = _now_iso()
        new_status = "closed" if verdict == "closed" else "investigating"
        closed_at = now if verdict == "closed" else None

        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    """UPDATE triage_alerts
                       SET analyst_verdict = ?, analyst_id = ?, status = ?,
                           closed_at = ?,
                           reasoning = reasoning || CASE WHEN ? != '' THEN char(10) || 'Analyst note: ' || ? ELSE '' END
                       WHERE org_id = ? AND id = ?""",
                    (verdict, analyst_id, new_status, closed_at, notes, notes, org_id, alert_id),
                )
                if cur.rowcount == 0:
                    return None
        return self.get_alert(org_id, alert_id)

    # ------------------------------------------------------------------
    # Rules
    # ------------------------------------------------------------------

    def create_rule(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a triage rule."""
        rule_name = (data.get("rule_name") or "").strip()
        if not rule_name:
            raise ValueError("rule_name is required.")
        conditions = data.get("conditions", {})
        if not isinstance(conditions, dict):
            conditions = {}

        now = _now_iso()
        rule = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "rule_name": rule_name,
            "conditions": json.dumps(conditions),
            "action": data.get("action", "monitor"),
            "override_severity": data.get("override_severity", ""),
            "tag": data.get("tag", ""),
            "enabled": 1 if data.get("enabled", True) else 0,
            "hit_count": 0,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO triage_rules
                       (id, org_id, rule_name, conditions, action, override_severity,
                        tag, enabled, hit_count, created_at)
                       VALUES (:id, :org_id, :rule_name, :conditions, :action,
                               :override_severity, :tag, :enabled, :hit_count, :created_at)""",
                    rule,
                )
        # Return with parsed conditions
        rule["conditions"] = conditions
        rule["enabled"] = bool(rule["enabled"])
        return rule

    def list_rules(self, org_id: str) -> List[Dict[str, Any]]:
        """List all rules for org_id."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM triage_rules WHERE org_id = ? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        result = []
        for row in rows:
            d = self._row(row)
            try:
                d["conditions"] = json.loads(d["conditions"])
            except Exception:
                d["conditions"] = {}
            d["enabled"] = bool(d["enabled"])
            result.append(d)
        return result

    def apply_rules(self, org_id: str, alert_id: str) -> List[Dict[str, Any]]:
        """Evaluate all enabled rules against the alert. Returns matching rules."""
        alert = self.get_alert(org_id, alert_id)
        if not alert:
            return []

        rules = self.list_rules(org_id)
        matched: List[Dict[str, Any]] = []

        for rule in rules:
            if not rule.get("enabled"):
                continue
            conditions = rule.get("conditions", {})
            if not isinstance(conditions, dict):
                continue

            hit = self._evaluate_rule_conditions(alert, conditions)
            if hit:
                matched.append(rule)
                # Increment hit_count
                with self._lock:
                    with self._conn() as conn:
                        conn.execute(
                            "UPDATE triage_rules SET hit_count = hit_count + 1 WHERE org_id = ? AND id = ?",
                            (org_id, rule["id"]),
                        )

        return matched

    @staticmethod
    def _evaluate_rule_conditions(alert: Dict[str, Any], conditions: Dict[str, Any]) -> bool:
        """Evaluate conditions dict against alert. Each key=field, value=expected value or list."""
        if not conditions:
            return False
        for field, expected in conditions.items():
            actual = alert.get(field)
            if isinstance(expected, list):
                if actual not in expected:
                    return False
            else:
                if actual != expected:
                    return False
        return True

    # ------------------------------------------------------------------
    # Sessions
    # ------------------------------------------------------------------

    def start_session(self, org_id: str, analyst_id: str) -> Dict[str, Any]:
        """Create a new triage session for an analyst."""
        if not analyst_id:
            raise ValueError("analyst_id is required.")
        now = _now_iso()
        session = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "analyst_id": analyst_id,
            "alerts_reviewed": 0,
            "alerts_confirmed_tp": 0,
            "alerts_closed_fp": 0,
            "session_start": now,
            "session_end": None,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO triage_sessions
                       (id, org_id, analyst_id, alerts_reviewed, alerts_confirmed_tp,
                        alerts_closed_fp, session_start, session_end)
                       VALUES (:id, :org_id, :analyst_id, :alerts_reviewed,
                               :alerts_confirmed_tp, :alerts_closed_fp, :session_start, :session_end)""",
                    session,
                )
        return session

    def close_session(self, org_id: str, session_id: str) -> Optional[Dict[str, Any]]:
        """Close the session and compute metrics from analyst verdicts during session."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM triage_sessions WHERE org_id = ? AND id = ?",
                (org_id, session_id),
            ).fetchone()
        if not row:
            return None

        session = self._row(row)
        session_start = session["session_start"]
        analyst_id = session["analyst_id"]

        # Count alerts with analyst_verdict set after session_start
        with self._conn() as conn:
            reviewed = conn.execute(
                """SELECT COUNT(*) FROM triage_alerts
                   WHERE org_id = ? AND analyst_id = ? AND triaged_at >= ?""",
                (org_id, analyst_id, session_start),
            ).fetchone()[0]
            confirmed_tp = conn.execute(
                """SELECT COUNT(*) FROM triage_alerts
                   WHERE org_id = ? AND analyst_id = ? AND analyst_verdict = 'confirmed'
                   AND classification = 'true_positive' AND triaged_at >= ?""",
                (org_id, analyst_id, session_start),
            ).fetchone()[0]
            closed_fp = conn.execute(
                """SELECT COUNT(*) FROM triage_alerts
                   WHERE org_id = ? AND analyst_id = ? AND analyst_verdict = 'closed'
                   AND classification = 'false_positive' AND triaged_at >= ?""",
                (org_id, analyst_id, session_start),
            ).fetchone()[0]

        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """UPDATE triage_sessions
                       SET session_end = ?, alerts_reviewed = ?,
                           alerts_confirmed_tp = ?, alerts_closed_fp = ?
                       WHERE org_id = ? AND id = ?""",
                    (now, reviewed, confirmed_tp, closed_fp, org_id, session_id),
                )

        session["session_end"] = now
        session["alerts_reviewed"] = reviewed
        session["alerts_confirmed_tp"] = confirmed_tp
        session["alerts_closed_fp"] = closed_fp
        return session

    # ------------------------------------------------------------------
    # Stats + Metrics
    # ------------------------------------------------------------------

    def get_triage_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated triage statistics."""
        with self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM triage_alerts WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            # By classification
            clf_rows = conn.execute(
                """SELECT classification, COUNT(*) as cnt
                   FROM triage_alerts WHERE org_id = ?
                   GROUP BY classification""",
                (org_id,),
            ).fetchall()
            by_classification = {r["classification"]: r["cnt"] for r in clf_rows}

            # By severity
            sev_rows = conn.execute(
                """SELECT severity_original, COUNT(*) as cnt
                   FROM triage_alerts WHERE org_id = ?
                   GROUP BY severity_original""",
                (org_id,),
            ).fetchall()
            by_severity = {r["severity_original"]: r["cnt"] for r in sev_rows}

            # By source
            src_rows = conn.execute(
                """SELECT alert_source, COUNT(*) as cnt
                   FROM triage_alerts WHERE org_id = ?
                   GROUP BY alert_source""",
                (org_id,),
            ).fetchall()
            by_source = {r["alert_source"]: r["cnt"] for r in src_rows}

            # Avg confidence
            avg_conf_row = conn.execute(
                "SELECT AVG(confidence_score) FROM triage_alerts WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]
            avg_confidence = round(float(avg_conf_row or 0.0), 4)

            # Escalation rate
            escalated = conn.execute(
                "SELECT COUNT(*) FROM triage_alerts WHERE org_id = ? AND status = 'escalated'",
                (org_id,),
            ).fetchone()[0]

            # False positive rate
            fp_count = by_classification.get("false_positive", 0)

        escalation_rate = round(escalated / total, 4) if total > 0 else 0.0
        false_positive_rate = round(fp_count / total, 4) if total > 0 else 0.0

        return {
            "total": total,
            "by_classification": by_classification,
            "by_severity": by_severity,
            "by_source": by_source,
            "avg_confidence": avg_confidence,
            "escalation_rate": escalation_rate,
            "false_positive_rate": false_positive_rate,
        }

    def get_daily_metrics(self, org_id: str, days: int = 30) -> List[Dict[str, Any]]:
        """Return daily metrics for the past N days."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM triage_metrics WHERE org_id = ?
                   ORDER BY date DESC LIMIT ?""",
                (org_id, days),
            ).fetchall()
        return [self._row(r) for r in rows]
