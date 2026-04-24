"""Access Anomaly Engine — ALDECI.

Detects anomalous access patterns including impossible travel,
unusual countries/hours/resources, and brute force indicators.

Capabilities:
  - Access event recording with risk_score and anomaly_flags
  - User baseline management (INSERT OR REPLACE)
  - Anomaly detection: unusual_country, unusual_time, unusual_resource
  - Impossible travel detection across configurable time windows
  - Anomaly resolution lifecycle
  - High-risk user identification by open anomaly count
  - Summary: totals, by_type, by_severity, impossible_travel_count

Compliance: NIST CSF DE.AE-3, ISO 27001 A.9.4 (Access Control)
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

_DEFAULT_DB_DIR = str(
    Path(__file__).resolve().parents[2] / ".fixops_data"
)

_VALID_ANOMALY_TYPES = {
    "unusual_country",
    "unusual_time",
    "unusual_resource",
    "impossible_travel",
    "brute_force",
    "privilege_escalation",
    "data_exfiltration",
    "after_hours",
}

_VALID_SEVERITIES = {"critical", "high", "medium", "low"}

_SEVERITY_WEIGHTS: Dict[str, float] = {
    "critical": 4.0,
    "high": 3.0,
    "medium": 2.0,
    "low": 1.0,
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AccessAnomalyEngine:
    """SQLite WAL-backed Access Anomaly Detection engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/access_anomaly.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(Path(_DEFAULT_DB_DIR) / "access_anomaly.db")
        self._db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS access_events (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    username        TEXT NOT NULL,
                    source_ip       TEXT NOT NULL DEFAULT '',
                    country         TEXT NOT NULL DEFAULT '',
                    city            TEXT NOT NULL DEFAULT '',
                    access_time     TEXT NOT NULL,
                    resource        TEXT NOT NULL DEFAULT '',
                    action          TEXT NOT NULL DEFAULT '',
                    success         INTEGER NOT NULL DEFAULT 1,
                    risk_score      REAL NOT NULL DEFAULT 0.0,
                    anomaly_flags   TEXT NOT NULL DEFAULT '[]',
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ae_org_user
                    ON access_events (org_id, username, access_time DESC);

                CREATE TABLE IF NOT EXISTS user_baselines (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    username            TEXT NOT NULL,
                    typical_countries   TEXT NOT NULL DEFAULT '[]',
                    typical_hours       TEXT NOT NULL DEFAULT '[]',
                    typical_resources   TEXT NOT NULL DEFAULT '[]',
                    avg_daily_events    REAL NOT NULL DEFAULT 0.0,
                    last_updated        TEXT NOT NULL,
                    created_at          TEXT NOT NULL,
                    UNIQUE(org_id, username)
                );

                CREATE INDEX IF NOT EXISTS idx_ub_org
                    ON user_baselines (org_id, username);

                CREATE TABLE IF NOT EXISTS access_anomalies (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    username        TEXT NOT NULL,
                    anomaly_type    TEXT NOT NULL,
                    description     TEXT NOT NULL DEFAULT '',
                    severity        TEXT NOT NULL DEFAULT 'medium',
                    source_event_id TEXT NOT NULL DEFAULT '',
                    risk_score      REAL NOT NULL DEFAULT 0.0,
                    status          TEXT NOT NULL DEFAULT 'open',
                    detected_at     TEXT NOT NULL,
                    resolved_at     TEXT,
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_aa_org
                    ON access_anomalies (org_id, username, status, anomaly_type, detected_at DESC);

                CREATE TABLE IF NOT EXISTS scm_anomaly_signals (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    author_email  TEXT NOT NULL,
                    anomaly_type  TEXT NOT NULL,
                    evidence_json TEXT NOT NULL DEFAULT '{}',
                    detected_at   TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_scm_anom_org_author
                    ON scm_anomaly_signals (org_id, author_email, detected_at DESC);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Event recording
    # ------------------------------------------------------------------

    def record_event(
        self,
        org_id: str,
        username: str,
        source_ip: str = "",
        country: str = "",
        city: str = "",
        access_time: Optional[str] = None,
        resource: str = "",
        action: str = "",
        success: int = 1,
    ) -> Dict[str, Any]:
        """Record an access event with default risk_score=0 and anomaly_flags=[]."""
        if access_time is None:
            access_time = _now_iso()
        now = _now_iso()
        rec_id = str(uuid.uuid4())
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO access_events
                        (id, org_id, username, source_ip, country, city, access_time,
                         resource, action, success, risk_score, anomaly_flags, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0.0, '[]', ?)
                    """,
                    (rec_id, org_id, username, source_ip, country, city,
                     access_time, resource, action, success, now),
                )
        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus:
                    bus.emit("ANOMALY_DETECTED", {"entity_type": "access_event", "entity_id": str(rec_id), "org_id": org_id, "source_engine": "access_anomaly_engine"})
            except Exception:
                pass  # Event emission should never break the main operation
        return self._get_event(rec_id, org_id)

    def _get_event(self, event_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM access_events WHERE id=? AND org_id=?",
                (event_id, org_id),
            ).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["anomaly_flags"] = json.loads(d.get("anomaly_flags", "[]"))
        return d

    # ------------------------------------------------------------------
    # Baseline
    # ------------------------------------------------------------------

    def upsert_baseline(
        self,
        org_id: str,
        username: str,
        typical_countries: Optional[List[str]] = None,
        typical_hours: Optional[List[int]] = None,
        typical_resources: Optional[List[str]] = None,
        avg_daily_events: float = 0.0,
    ) -> Dict[str, Any]:
        """Insert or replace user baseline."""
        now = _now_iso()
        rec_id = str(uuid.uuid4())
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO user_baselines
                        (id, org_id, username, typical_countries, typical_hours,
                         typical_resources, avg_daily_events, last_updated, created_at)
                    VALUES (
                        COALESCE(
                            (SELECT id FROM user_baselines WHERE org_id=? AND username=?),
                            ?
                        ),
                        ?, ?, ?, ?, ?, ?, ?, ?
                    )
                    """,
                    (
                        org_id, username, rec_id,
                        org_id, username,
                        json.dumps(typical_countries or []),
                        json.dumps(typical_hours or []),
                        json.dumps(typical_resources or []),
                        avg_daily_events,
                        now, now,
                    ),
                )
            row = conn.execute(
                "SELECT * FROM user_baselines WHERE org_id=? AND username=?",
                (org_id, username),
            ).fetchone()
        return self._baseline_row(row)

    @staticmethod
    def _baseline_row(row: sqlite3.Row) -> Dict[str, Any]:
        if row is None:
            return {}
        d = dict(row)
        for f in ("typical_countries", "typical_hours", "typical_resources"):
            d[f] = json.loads(d.get(f, "[]"))
        return d

    def _get_baseline(self, org_id: str, username: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM user_baselines WHERE org_id=? AND username=?",
                (org_id, username),
            ).fetchone()
        if row is None:
            return None
        return self._baseline_row(row)

    # ------------------------------------------------------------------
    # Anomaly detection
    # ------------------------------------------------------------------

    def detect_anomalies(
        self, org_id: str, username: str, event_id: str
    ) -> List[Dict[str, Any]]:
        """Check event against baseline and create anomaly records."""
        with self._lock:
            event = self._get_event(event_id, org_id)
            if event is None:
                raise ValueError(f"Event {event_id} not found")
            baseline = self._get_baseline(org_id, username)

            flags: List[str] = []
            anomaly_records: List[Dict[str, Any]] = []
            total_risk = 0.0

            if baseline:
                # (1) Unusual country
                if event["country"] and event["country"] not in baseline["typical_countries"]:
                    flags.append("unusual_country")
                    weight = _SEVERITY_WEIGHTS["medium"]
                    total_risk += weight
                    anom = self._insert_anomaly(
                        org_id=org_id,
                        username=username,
                        anomaly_type="unusual_country",
                        description=f"Access from unusual country: {event['country']}",
                        severity="medium",
                        source_event_id=event_id,
                        risk_score=weight,
                    )
                    anomaly_records.append(anom)

                # (2) Unusual time
                try:
                    hour = datetime.fromisoformat(event["access_time"]).hour
                except Exception:
                    hour = None
                if hour is not None and baseline["typical_hours"] and hour not in baseline["typical_hours"]:
                    flags.append("unusual_time")
                    weight = _SEVERITY_WEIGHTS["low"]
                    total_risk += weight
                    anom = self._insert_anomaly(
                        org_id=org_id,
                        username=username,
                        anomaly_type="unusual_time",
                        description=f"Access at unusual hour: {hour}",
                        severity="low",
                        source_event_id=event_id,
                        risk_score=weight,
                    )
                    anomaly_records.append(anom)

                # (3) Unusual resource
                if event["resource"] and event["resource"] not in baseline["typical_resources"]:
                    flags.append("unusual_resource")
                    weight = _SEVERITY_WEIGHTS["low"]
                    total_risk += weight
                    anom = self._insert_anomaly(
                        org_id=org_id,
                        username=username,
                        anomaly_type="unusual_resource",
                        description=f"Access to unusual resource: {event['resource']}",
                        severity="low",
                        source_event_id=event_id,
                        risk_score=weight,
                    )
                    anomaly_records.append(anom)

            # Update event with flags and risk_score
            with self._conn() as conn:
                conn.execute(
                    "UPDATE access_events SET anomaly_flags=?, risk_score=? WHERE id=? AND org_id=?",
                    (json.dumps(flags), total_risk, event_id, org_id),
                )

        return anomaly_records

    def _insert_anomaly(
        self,
        org_id: str,
        username: str,
        anomaly_type: str,
        description: str,
        severity: str,
        source_event_id: str,
        risk_score: float,
    ) -> Dict[str, Any]:
        now = _now_iso()
        rec_id = str(uuid.uuid4())
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO access_anomalies
                    (id, org_id, username, anomaly_type, description, severity,
                     source_event_id, risk_score, status, detected_at, resolved_at, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, NULL, ?)
                """,
                (rec_id, org_id, username, anomaly_type, description, severity,
                 source_event_id, risk_score, now, now),
            )
        return self._get_anomaly(rec_id, org_id)

    def _get_anomaly(self, anomaly_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM access_anomalies WHERE id=? AND org_id=?",
                (anomaly_id, org_id),
            ).fetchone()
        if row is None:
            return None
        return dict(row)

    def detect_impossible_travel(
        self, org_id: str, username: str, hours_window: float = 4.0
    ) -> List[Dict[str, Any]]:
        """Detect impossible travel: same user, different country, within hours_window."""
        anomalies: List[Dict[str, Any]] = []
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    """
                    SELECT id, country, access_time FROM access_events
                    WHERE org_id=? AND username=? AND country != ''
                    ORDER BY access_time ASC
                    """,
                    (org_id, username),
                ).fetchall()

            events = [dict(r) for r in rows]
            for i in range(len(events)):
                for j in range(i + 1, len(events)):
                    e1, e2 = events[i], events[j]
                    if e1["country"] == e2["country"]:
                        continue
                    try:
                        t1 = datetime.fromisoformat(e1["access_time"])
                        t2 = datetime.fromisoformat(e2["access_time"])
                        diff_hours = abs((t2 - t1).total_seconds()) / 3600.0
                    except Exception:
                        continue
                    if diff_hours < hours_window:
                        anom = self._insert_anomaly(
                            org_id=org_id,
                            username=username,
                            anomaly_type="impossible_travel",
                            description=(
                                f"Impossible travel: {e1['country']} → {e2['country']} "
                                f"in {diff_hours:.2f}h"
                            ),
                            severity="critical",
                            source_event_id=e1["id"],
                            risk_score=4.0,
                        )
                        anomalies.append(anom)
        return anomalies

    # ------------------------------------------------------------------
    # Anomaly management
    # ------------------------------------------------------------------

    def resolve_anomaly(self, anomaly_id: str, org_id: str) -> Dict[str, Any]:
        """Set anomaly status=resolved and resolved_at=now."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT id FROM access_anomalies WHERE id=? AND org_id=?",
                    (anomaly_id, org_id),
                ).fetchone()
                if row is None:
                    raise ValueError(f"Anomaly {anomaly_id} not found")
                conn.execute(
                    "UPDATE access_anomalies SET status='resolved', resolved_at=? WHERE id=? AND org_id=?",
                    (now, anomaly_id, org_id),
                )
            return self._get_anomaly(anomaly_id, org_id)

    def list_anomalies(
        self,
        org_id: str,
        status: Optional[str] = None,
        anomaly_type: Optional[str] = None,
        username: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        clauses = ["org_id=?"]
        params: List[Any] = [org_id]
        if status:
            clauses.append("status=?")
            params.append(status)
        if anomaly_type:
            clauses.append("anomaly_type=?")
            params.append(anomaly_type)
        if username:
            clauses.append("username=?")
            params.append(username)
        sql = f"SELECT * FROM access_anomalies WHERE {' AND '.join(clauses)} ORDER BY detected_at DESC"  # nosec B608
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Risk profiling
    # ------------------------------------------------------------------

    def get_user_risk_profile(self, org_id: str, username: str) -> Dict[str, Any]:
        """Baseline + open anomalies + recent 50 events + avg risk_score."""
        with self._lock:
            baseline = self._get_baseline(org_id, username) or {}
            with self._conn() as conn:
                anomaly_rows = conn.execute(
                    """
                    SELECT * FROM access_anomalies
                    WHERE org_id=? AND username=? AND status='open'
                    ORDER BY detected_at DESC
                    """,
                    (org_id, username),
                ).fetchall()
                event_rows = conn.execute(
                    """
                    SELECT * FROM access_events
                    WHERE org_id=? AND username=?
                    ORDER BY access_time DESC LIMIT 50
                    """,
                    (org_id, username),
                ).fetchall()
                avg_row = conn.execute(
                    """
                    SELECT AVG(risk_score) AS avg_risk FROM access_anomalies
                    WHERE org_id=? AND username=? AND status='open'
                    """,
                    (org_id, username),
                ).fetchone()

        open_anomalies = [dict(r) for r in anomaly_rows]
        recent_events = []
        for r in event_rows:
            d = dict(r)
            d["anomaly_flags"] = json.loads(d.get("anomaly_flags", "[]"))
            recent_events.append(d)

        return {
            "baseline": baseline,
            "open_anomalies": open_anomalies,
            "recent_events": recent_events,
            "risk_score": round(avg_row["avg_risk"] or 0.0, 4),
        }

    def get_high_risk_users(
        self, org_id: str, min_anomaly_count: int = 3
    ) -> List[Dict[str, Any]]:
        """Users with >= min_anomaly_count open anomalies, ordered by count DESC."""
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    """
                    SELECT username, COUNT(*) AS anomaly_count
                    FROM access_anomalies
                    WHERE org_id=? AND status='open'
                    GROUP BY username
                    HAVING COUNT(*) >= ?
                    ORDER BY anomaly_count DESC
                    """,
                    (org_id, min_anomaly_count),
                ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # SCM Anomaly Signals (GAP-016: dev-identity behavioral MERGE)
    # ------------------------------------------------------------------

    def record_scm_anomaly(
        self,
        org_id: str,
        author_email: str,
        anomaly_type: str,
        evidence_json: Any = None,
    ) -> Dict[str, Any]:
        """Record an SCM commit-derived anomaly for a developer identity.

        Writes to scm_anomaly_signals. Accepts dict or string for evidence_json;
        always persists as JSON string.

        Args:
            org_id: tenant id
            author_email: developer identity
            anomaly_type: e.g. 'off_hours','privilege_escalation','secret_file',
                'bulk_rename','force_push', or 'scm_commit_anomaly' (generic).
            evidence_json: dict or JSON string. Coerced to string for storage.

        Returns:
            Full inserted row dict (evidence decoded back to dict).
        """
        if not author_email:
            raise ValueError("author_email is required")
        if not anomaly_type:
            raise ValueError("anomaly_type is required")

        # Normalize evidence
        if evidence_json is None:
            evidence_str = "{}"
        elif isinstance(evidence_json, str):
            # Accept pre-serialized JSON string
            evidence_str = evidence_json
        else:
            try:
                evidence_str = json.dumps(evidence_json)
            except (TypeError, ValueError):
                evidence_str = json.dumps({"raw": str(evidence_json)})

        rec_id = str(uuid.uuid4())
        now = _now_iso()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO scm_anomaly_signals
                       (id, org_id, author_email, anomaly_type, evidence_json, detected_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (rec_id, org_id, author_email, anomaly_type, evidence_str, now),
                )

        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus:
                    bus.emit("ANOMALY_DETECTED", {
                        "entity_type": "scm_commit_anomaly",
                        "entity_id": rec_id,
                        "org_id": org_id,
                        "source_engine": "access_anomaly_engine",
                        "anomaly_type": anomaly_type,
                        "author_email": author_email,
                    })
            except Exception:
                pass

        try:
            evidence_decoded = json.loads(evidence_str) if evidence_str else {}
        except (TypeError, ValueError):
            evidence_decoded = {}

        return {
            "id": rec_id,
            "org_id": org_id,
            "author_email": author_email,
            "anomaly_type": anomaly_type,
            "evidence_json": evidence_decoded,
            "detected_at": now,
        }

    def list_scm_anomalies(
        self,
        org_id: str,
        author_email: Optional[str] = None,
        anomaly_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List SCM anomaly signals with optional filters."""
        sql = "SELECT * FROM scm_anomaly_signals WHERE org_id=?"
        params: List[Any] = [org_id]
        if author_email:
            sql += " AND author_email=?"
            params.append(author_email)
        if anomaly_type:
            sql += " AND anomaly_type=?"
            params.append(anomaly_type)
        sql += " ORDER BY detected_at DESC"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(sql, params).fetchall()
        out: List[Dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            try:
                d["evidence_json"] = json.loads(d.get("evidence_json") or "{}")
            except (TypeError, ValueError):
                d["evidence_json"] = {}
            out.append(d)
        return out

    def get_summary(self, org_id: str) -> Dict[str, Any]:
        """Aggregate summary of events and anomalies."""
        with self._lock:
            with self._conn() as conn:
                total_events = conn.execute(
                    "SELECT COUNT(*) FROM access_events WHERE org_id=?", (org_id,)
                ).fetchone()[0]
                anomaly_rows = conn.execute(
                    "SELECT anomaly_type, severity, status, username FROM access_anomalies WHERE org_id=?",
                    (org_id,),
                ).fetchall()
                impossible_travel_count = conn.execute(
                    """
                    SELECT COUNT(*) FROM access_anomalies
                    WHERE org_id=? AND anomaly_type='impossible_travel'
                    """,
                    (org_id,),
                ).fetchone()[0]
                high_risk_users = conn.execute(
                    """
                    SELECT COUNT(DISTINCT username) FROM access_anomalies
                    WHERE org_id=? AND status='open'
                    """,
                    (org_id,),
                ).fetchone()[0]

        by_type: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        open_anomalies = 0
        for row in anomaly_rows:
            by_type[row["anomaly_type"]] = by_type.get(row["anomaly_type"], 0) + 1
            by_severity[row["severity"]] = by_severity.get(row["severity"], 0) + 1
            if row["status"] == "open":
                open_anomalies += 1

        return {
            "total_events": total_events,
            "total_anomalies": len(anomaly_rows),
            "open_anomalies": open_anomalies,
            "by_type": by_type,
            "by_severity": by_severity,
            "high_risk_users": high_risk_users,
            "impossible_travel_count": impossible_travel_count,
        }
