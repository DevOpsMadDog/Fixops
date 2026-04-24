"""
Insider Threat Detection Engine — ALDECI.

Detects insider threat patterns via behavioral analytics:
- after_hours_access: login between 22:00–06:00
- bulk_data_download: >50 file downloads in 1 day
- multiple_failed_auth: >5 failed auth in 1 hour
- sensitive_data_access_spike: >20 unique sensitive resources in 1 day
- unusual_geo_location: login from >2 geolocations in 1 day

SQLite-backed, thread-safe, multi-tenant (per org_id).

Compliance: SOC2 CC6.8, NIST SP 800-53 AU-6 (audit review).
"""

from __future__ import annotations

import json
import logging
import sqlite3

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(Path(__file__).resolve().parents[2] / "data" / "insider_threat.db")

THREAT_INDICATORS = [
    "after_hours_access",
    "bulk_data_download",
    "privilege_escalation_attempt",
    "unusual_geo_location",
    "multiple_failed_auth",
    "data_staging",
    "policy_violation",
    "account_sharing",
    "sensitive_data_access_spike",
]

RISK_LEVELS = ["baseline", "low", "medium", "high", "critical"]

# Risk score contribution per indicator severity
_SEVERITY_SCORES: Dict[str, float] = {
    "low": 10.0,
    "medium": 20.0,
    "high": 35.0,
    "critical": 50.0,
}


class InsiderThreatEngine:
    """
    SQLite-backed insider threat detection engine.

    All public methods are thread-safe via RLock.

    Args:
        db_path: Path to SQLite database. Defaults to data/insider_threat.db.
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
        with self._get_conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS user_events (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    user_id     TEXT NOT NULL,
                    event_type  TEXT NOT NULL,
                    resource    TEXT NOT NULL,
                    details     TEXT DEFAULT '{}',
                    timestamp   DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ue_org_user_ts
                    ON user_events (org_id, user_id, timestamp DESC);

                CREATE TABLE IF NOT EXISTS threat_alerts (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    user_id     TEXT NOT NULL,
                    indicator   TEXT NOT NULL,
                    severity    TEXT NOT NULL,
                    evidence    TEXT DEFAULT '{}',
                    created_at  DATETIME NOT NULL,
                    status      TEXT DEFAULT 'open',
                    resolution  TEXT,
                    resolved_by TEXT,
                    resolved_at DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_ta_org_user
                    ON threat_alerts (org_id, user_id, created_at DESC);

                CREATE INDEX IF NOT EXISTS idx_ta_status
                    ON threat_alerts (org_id, status, severity);

                CREATE TABLE IF NOT EXISTS watched_developers (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    author_email  TEXT NOT NULL,
                    reason        TEXT NOT NULL DEFAULT '',
                    watched_by    TEXT NOT NULL DEFAULT '',
                    watched_at    DATETIME NOT NULL,
                    unwatched_at  DATETIME,
                    unwatched_by  TEXT
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_watched_dev_active
                    ON watched_developers (org_id, author_email)
                    WHERE unwatched_at IS NULL;

                CREATE INDEX IF NOT EXISTS idx_watched_dev_org
                    ON watched_developers (org_id, author_email, watched_at DESC);
                """
            )

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record_user_event(
        self,
        user_id: str,
        event_type: str,
        resource: str,
        details: Optional[Dict[str, Any]] = None,
        timestamp: Optional[str] = None,
        org_id: str = "default",
    ) -> str:
        """Log a user activity event. Returns event_id."""
        event_id = str(uuid.uuid4())
        if timestamp is None:
            timestamp = datetime.now(timezone.utc).isoformat()
        details_json = json.dumps(details or {})

        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO user_events (id, org_id, user_id, event_type, resource, details, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (event_id, org_id, user_id, event_type, resource, details_json, timestamp),
                )
        return event_id

    def analyze_user_risk(
        self,
        user_id: str,
        window_days: int = 30,
        org_id: str = "default",
    ) -> Dict[str, Any]:
        """
        Analyze a user's recent activity for insider threat indicators.

        Returns a dict with: user_id, risk_level, risk_score (0–100),
        indicators, event_count, recommendation.
        """
        since = (datetime.now(timezone.utc) - timedelta(days=window_days)).isoformat()

        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(
                    """
                    SELECT id, event_type, resource, details, timestamp
                    FROM user_events
                    WHERE org_id = ? AND user_id = ? AND timestamp >= ?
                    ORDER BY timestamp DESC
                    """,
                    (org_id, user_id, since),
                ).fetchall()

        events = [dict(r) for r in rows]
        indicators: List[Dict[str, Any]] = []

        # --- Rule: bulk_data_download (>50 downloads in 1 day) ---
        download_events = [
            e for e in events
            if e["event_type"] in ("download", "data_export", "file_access")
        ]
        # Group by calendar day
        daily_downloads: Dict[str, int] = {}
        for e in download_events:
            day = e["timestamp"][:10]
            daily_downloads[day] = daily_downloads.get(day, 0) + 1
        max_daily_dl = max(daily_downloads.values(), default=0)
        if max_daily_dl > 50:
            peak_day = max(daily_downloads, key=lambda d: daily_downloads[d])
            indicators.append({
                "indicator": "bulk_data_download",
                "severity": "high",
                "evidence": {"max_daily_downloads": max_daily_dl, "peak_day": peak_day},
                "detected_at": datetime.now(timezone.utc).isoformat(),
            })

        # --- Rule: after_hours_access (login between 22:00–06:00) ---
        login_events = [e for e in events if e["event_type"] == "login"]
        after_hours = []
        for e in login_events:
            try:
                ts = e["timestamp"]
                # Parse hour from ISO string (handles both naive and aware)
                hour = int(ts[11:13])
                if hour >= 22 or hour < 6:
                    after_hours.append(ts)
            except (ValueError, IndexError):
                pass
        if after_hours:
            indicators.append({
                "indicator": "after_hours_access",
                "severity": "medium",
                "evidence": {"after_hours_logins": len(after_hours), "examples": after_hours[:3]},
                "detected_at": datetime.now(timezone.utc).isoformat(),
            })

        # --- Rule: multiple_failed_auth (>5 failed auth in 1 hour) ---
        failed_auth = [e for e in events if e["event_type"] == "login" and
                       "failed" in json.loads(e.get("details", "{}")).get("status", "").lower()]
        # Bucket by hour
        hourly_fails: Dict[str, int] = {}
        for e in failed_auth:
            hour_key = e["timestamp"][:13]  # YYYY-MM-DDTHH
            hourly_fails[hour_key] = hourly_fails.get(hour_key, 0) + 1
        max_hourly_fails = max(hourly_fails.values(), default=0)
        if max_hourly_fails > 5:
            peak_hour = max(hourly_fails, key=lambda h: hourly_fails[h])
            indicators.append({
                "indicator": "multiple_failed_auth",
                "severity": "medium",
                "evidence": {"max_fails_in_hour": max_hourly_fails, "peak_hour": peak_hour},
                "detected_at": datetime.now(timezone.utc).isoformat(),
            })

        # --- Rule: sensitive_data_access_spike (>20 unique sensitive resources in 1 day) ---
        sensitive_events = [
            e for e in events
            if any(kw in e["resource"].lower() for kw in
                   ("secret", "key", "password", "credential", "pii", "sensitive", "confidential", "private"))
        ]
        daily_unique_resources: Dict[str, set] = {}
        for e in sensitive_events:
            day = e["timestamp"][:10]
            daily_unique_resources.setdefault(day, set()).add(e["resource"])
        max_unique_sensitive = max((len(v) for v in daily_unique_resources.values()), default=0)
        if max_unique_sensitive > 20:
            peak_day = max(daily_unique_resources, key=lambda d: len(daily_unique_resources[d]))
            indicators.append({
                "indicator": "sensitive_data_access_spike",
                "severity": "high",
                "evidence": {"max_unique_sensitive_resources": max_unique_sensitive, "peak_day": peak_day},
                "detected_at": datetime.now(timezone.utc).isoformat(),
            })

        # --- Rule: unusual_geo_location (>2 geolocations in 1 day) ---
        geo_by_day: Dict[str, set] = {}
        for e in login_events:
            details = json.loads(e.get("details", "{}"))
            geo = details.get("geo_location") or details.get("location") or details.get("ip")
            if geo:
                day = e["timestamp"][:10]
                geo_by_day.setdefault(day, set()).add(geo)
        max_geos = max((len(v) for v in geo_by_day.values()), default=0)
        if max_geos > 2:
            peak_day = max(geo_by_day, key=lambda d: len(geo_by_day[d]))
            indicators.append({
                "indicator": "unusual_geo_location",
                "severity": "high",
                "evidence": {"max_geolocations_in_day": max_geos, "peak_day": peak_day},
                "detected_at": datetime.now(timezone.utc).isoformat(),
            })

        # --- Compute aggregate risk score (capped at 100) ---
        raw_score = sum(_SEVERITY_SCORES.get(ind["severity"], 0.0) for ind in indicators)
        risk_score = min(raw_score, 100.0)

        # --- Map score to risk level ---
        if risk_score == 0:
            risk_level = "baseline"
        elif risk_score < 20:
            risk_level = "low"
        elif risk_score < 40:
            risk_level = "medium"
        elif risk_score < 70:
            risk_level = "high"
        else:
            risk_level = "critical"

        # --- Recommendation ---
        if risk_level == "baseline":
            recommendation = "No action required. Continue routine monitoring."
        elif risk_level == "low":
            recommendation = "Review user activity logs for anomalies. No immediate action required."
        elif risk_level == "medium":
            recommendation = "Notify user's manager and security team. Increase monitoring frequency."
        elif risk_level == "high":
            recommendation = "Escalate to security team immediately. Consider temporary access restriction."
        else:
            recommendation = "Suspend user access pending investigation. Engage incident response team."

        result = {
            "user_id": user_id,
            "org_id": org_id,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "indicators": indicators,
            "event_count": len(events),
            "window_days": window_days,
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "recommendation": recommendation,
        }
        if indicators and _get_tg_bus is not None:
            try:
                _get_tg_bus().emit("THREAT_DETECTED", {
                    "org_id": org_id,
                    "entity": "insider_threat",
                    "user_id": user_id,
                    "risk_level": risk_level,
                    "risk_score": risk_score,
                    "indicator_count": len(indicators),
                })
            except Exception:
                pass
        return result

    def get_high_risk_users(
        self,
        org_id: str = "default",
        min_risk_score: float = 60.0,
    ) -> List[Dict[str, Any]]:
        """List users above risk threshold, ordered by risk score descending."""
        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(
                    """
                    SELECT DISTINCT user_id
                    FROM user_events
                    WHERE org_id = ?
                    """,
                    (org_id,),
                ).fetchall()

        results = []
        for row in rows:
            uid = row["user_id"]
            analysis = self.analyze_user_risk(uid, org_id=org_id)
            if analysis["risk_score"] >= min_risk_score:
                results.append(analysis)

        results.sort(key=lambda x: x["risk_score"], reverse=True)
        return results

    def create_alert(
        self,
        user_id: str,
        indicator: str,
        evidence: Dict[str, Any],
        severity: str = "medium",
        org_id: str = "default",
    ) -> Dict[str, Any]:
        """Create an insider threat alert for a user. Returns alert record."""
        alert_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        evidence_json = json.dumps(evidence)

        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO threat_alerts
                        (id, org_id, user_id, indicator, severity, evidence, created_at, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'open')
                    """,
                    (alert_id, org_id, user_id, indicator, severity, evidence_json, now),
                )

        return {
            "alert_id": alert_id,
            "org_id": org_id,
            "user_id": user_id,
            "indicator": indicator,
            "severity": severity,
            "evidence": evidence,
            "created_at": now,
            "status": "open",
        }

    def get_alerts(
        self,
        user_id: Optional[str] = None,
        org_id: str = "default",
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return alerts, optionally filtered by user_id and/or severity."""
        query = "SELECT * FROM threat_alerts WHERE org_id = ?"
        params: list = [org_id]
        if user_id:
            query += " AND user_id = ?"
            params.append(user_id)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        query += " ORDER BY created_at DESC"

        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(query, params).fetchall()

        results = []
        for row in rows:
            r = dict(row)
            r["evidence"] = json.loads(r.get("evidence") or "{}")
            results.append(r)
        return results

    def resolve_alert(
        self,
        alert_id: str,
        resolution: str,
        resolved_by: str,
        org_id: str = "default",
    ) -> Dict[str, Any]:
        """Resolve an alert. resolution: 'false_positive'|'confirmed'|'escalated'."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    UPDATE threat_alerts
                    SET status = 'resolved', resolution = ?, resolved_by = ?, resolved_at = ?
                    WHERE id = ? AND org_id = ?
                    """,
                    (resolution, resolved_by, now, alert_id, org_id),
                )
                row = conn.execute(
                    "SELECT * FROM threat_alerts WHERE id = ? AND org_id = ?",
                    (alert_id, org_id),
                ).fetchone()

        if row is None:
            raise ValueError(f"Alert not found: {alert_id}")

        r = dict(row)
        r["evidence"] = json.loads(r.get("evidence") or "{}")
        return r

    def get_user_timeline(
        self,
        user_id: str,
        org_id: str = "default",
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get chronological event history for a user."""
        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(
                    """
                    SELECT * FROM user_events
                    WHERE org_id = ? AND user_id = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                    """,
                    (org_id, user_id, limit),
                ).fetchall()

        results = []
        for row in rows:
            r = dict(row)
            r["details"] = json.loads(r.get("details") or "{}")
            results.append(r)
        return results

    def get_trustgraph_context(self, org_id: str, entity_id: str) -> Dict[str, Any]:
        """Query TrustGraph for cross-domain context about an insider threat entity.

        Returns related assets, findings, and incidents for enriched investigation.
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

            for core_id in (1, 2, 3):
                try:
                    results = store.search(core_id=core_id, query_text=entity_id, limit=10)
                    for entity in results:
                        if entity.org_id not in ("default", org_id):
                            continue
                        entry = {"id": entity.entity_id, "name": entity.name, "type": entity.entity_type}
                        etype = entity.entity_type.lower()
                        if etype in ("asset", "service", "host"):
                            context["related_assets"].append(entry)
                        elif etype in ("finding", "vulnerability"):
                            context["related_findings"].append(entry)
                        elif etype in ("incident", "breach", "alert"):
                            context["related_incidents"].append(entry)
                except Exception:
                    pass

            neighbors = store.get_neighbors(entity_id=entity_id, depth=1)
            for n in neighbors:
                if n.org_id not in ("default", org_id):
                    continue
                entry = {"id": n.entity_id, "name": n.name, "type": n.entity_type}
                etype = n.entity_type.lower()
                if etype in ("asset", "service", "host"):
                    if entry not in context["related_assets"]:
                        context["related_assets"].append(entry)
                elif etype in ("finding", "vulnerability"):
                    if entry not in context["related_findings"]:
                        context["related_findings"].append(entry)
                elif etype in ("incident", "breach", "alert"):
                    if entry not in context["related_incidents"]:
                        context["related_incidents"].append(entry)
        except Exception:
            pass
        return context

    def get_org_risk_summary(self, org_id: str = "default") -> Dict[str, Any]:
        """
        Return org-level risk summary:
        {total_users_monitored, high_risk_users, active_alerts, top_indicators, avg_risk_score}
        """
        with self._lock:
            with self._get_conn() as conn:
                users = conn.execute(
                    "SELECT DISTINCT user_id FROM user_events WHERE org_id = ?",
                    (org_id,),
                ).fetchall()

                active_alerts_row = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM threat_alerts WHERE org_id = ? AND status = 'open'",
                    (org_id,),
                ).fetchone()

                indicator_rows = conn.execute(
                    """
                    SELECT indicator, COUNT(*) AS cnt
                    FROM threat_alerts
                    WHERE org_id = ?
                    GROUP BY indicator
                    ORDER BY cnt DESC
                    LIMIT 5
                    """,
                    (org_id,),
                ).fetchall()

        user_ids = [r["user_id"] for r in users]
        total_users = len(user_ids)
        active_alerts = active_alerts_row["cnt"] if active_alerts_row else 0
        top_indicators = [{"indicator": r["indicator"], "count": r["cnt"]} for r in indicator_rows]

        # Compute risk scores for all users
        scores = []
        high_risk_count = 0
        for uid in user_ids:
            analysis = self.analyze_user_risk(uid, org_id=org_id)
            score = analysis["risk_score"]
            scores.append(score)
            if score >= 60.0:
                high_risk_count += 1

        avg_risk_score = (sum(scores) / len(scores)) if scores else 0.0

        return {
            "org_id": org_id,
            "total_users_monitored": total_users,
            "high_risk_users": high_risk_count,
            "active_alerts": active_alerts,
            "top_indicators": top_indicators,
            "avg_risk_score": round(avg_risk_score, 2),
        }

    # ------------------------------------------------------------------
    # Watchlist for developer identities (GAP-016)
    # ------------------------------------------------------------------

    def watch_developer(
        self,
        org_id: str,
        author_email: str,
        reason: str = "",
        watched_by: str = "",
    ) -> Dict[str, Any]:
        """Add a developer to the active watchlist.

        Uses partial unique index UNIQUE(org_id, author_email) WHERE unwatched_at IS NULL,
        so re-watching an already-active developer raises IntegrityError.
        After an unwatch, the developer can be re-watched (creates a new active row).
        """
        if not author_email:
            raise ValueError("author_email is required")

        rec_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._get_conn() as conn:
                try:
                    conn.execute(
                        """INSERT INTO watched_developers
                           (id, org_id, author_email, reason, watched_by,
                            watched_at, unwatched_at, unwatched_by)
                           VALUES (?, ?, ?, ?, ?, ?, NULL, NULL)""",
                        (rec_id, org_id, author_email, reason, watched_by, now),
                    )
                except sqlite3.IntegrityError as exc:
                    raise ValueError(
                        f"Developer {author_email} is already on the active watchlist"
                    ) from exc

        return {
            "id": rec_id,
            "org_id": org_id,
            "author_email": author_email,
            "reason": reason,
            "watched_by": watched_by,
            "watched_at": now,
            "unwatched_at": None,
            "unwatched_by": None,
        }

    def unwatch_developer(
        self,
        org_id: str,
        author_email: str,
        unwatched_by: str = "",
    ) -> Dict[str, Any]:
        """Mark the active watch record as unwatched.

        Returns the updated row. Raises ValueError if no active watch exists.
        """
        if not author_email:
            raise ValueError("author_email is required")

        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._get_conn() as conn:
                cur = conn.execute(
                    """UPDATE watched_developers
                       SET unwatched_at = ?, unwatched_by = ?
                       WHERE org_id = ? AND author_email = ?
                         AND unwatched_at IS NULL""",
                    (now, unwatched_by, org_id, author_email),
                )
                if cur.rowcount == 0:
                    raise ValueError(
                        f"No active watch found for {author_email} in org {org_id}"
                    )
                row = conn.execute(
                    """SELECT * FROM watched_developers
                       WHERE org_id = ? AND author_email = ?
                         AND unwatched_at = ?""",
                    (org_id, author_email, now),
                ).fetchone()

        return dict(row) if row else {
            "org_id": org_id,
            "author_email": author_email,
            "unwatched_at": now,
            "unwatched_by": unwatched_by,
        }

    def list_watched_developers(
        self,
        org_id: str,
        include_inactive: bool = False,
    ) -> List[Dict[str, Any]]:
        """List watched developers for an org.

        By default returns only active (unwatched_at IS NULL) entries.
        Set include_inactive=True to include the history.
        """
        if include_inactive:
            query = """SELECT * FROM watched_developers
                       WHERE org_id = ?
                       ORDER BY watched_at DESC"""
            params: list = [org_id]
        else:
            query = """SELECT * FROM watched_developers
                       WHERE org_id = ? AND unwatched_at IS NULL
                       ORDER BY watched_at DESC"""
            params = [org_id]

        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(query, params).fetchall()

        return [dict(r) for r in rows]
