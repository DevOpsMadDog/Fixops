"""
Insider Threat Detection Engine — ALDECI.

Detects malicious or risky insider behaviour by analysing user-activity logs:
- UNUSUAL_ACCESS:       Resources accessed outside normal scope
- DATA_HOARDING:        Bulk download / copy of sensitive artefacts
- OFF_HOURS_ACTIVITY:   Activity during weekends or outside business hours
- PRIVILEGE_ABUSE:      Escalation or misuse of elevated permissions
- RESIGNATION_RISK:     Behavioural pattern consistent with imminent departure
- POLICY_VIOLATION:     Explicit violation of security policy
- ANOMALOUS_DOWNLOAD:   Single large download event
- UNAUTHORIZED_TOOL:    Use of tool not approved by policy

SQLite-backed, thread-safe, multi-tenant (per org_id).

Compliance: SOC2 CC6.3, NIST SP 800-53 AU-6, ISO 27001 A.7.2.3
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default DB path (data/ directory alongside the running process)
# ---------------------------------------------------------------------------
_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / "data" / "insider_threat.db"
)

# Risk score thresholds (0-100)
_THRESHOLD_HIGH = 60
_THRESHOLD_CRITICAL = 80

# Indicator weights — sum used to derive risk_score (capped at 100)
_INDICATOR_WEIGHTS: Dict[str, int] = {
    "UNUSUAL_ACCESS": 15,
    "DATA_HOARDING": 20,
    "OFF_HOURS_ACTIVITY": 10,
    "PRIVILEGE_ABUSE": 25,
    "RESIGNATION_RISK": 20,
    "POLICY_VIOLATION": 20,
    "ANOMALOUS_DOWNLOAD": 15,
    "UNAUTHORIZED_TOOL": 10,
}


# ============================================================================
# ENUMS
# ============================================================================


class ThreatIndicator(str, Enum):
    """Behavioural indicators of insider threat."""

    UNUSUAL_ACCESS = "UNUSUAL_ACCESS"
    DATA_HOARDING = "DATA_HOARDING"
    OFF_HOURS_ACTIVITY = "OFF_HOURS_ACTIVITY"
    PRIVILEGE_ABUSE = "PRIVILEGE_ABUSE"
    RESIGNATION_RISK = "RESIGNATION_RISK"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    ANOMALOUS_DOWNLOAD = "ANOMALOUS_DOWNLOAD"
    UNAUTHORIZED_TOOL = "UNAUTHORIZED_TOOL"


class AlertLevel(str, Enum):
    """Severity of a user risk profile."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ============================================================================
# PYDANTIC MODELS
# ============================================================================


class UserRiskProfile(BaseModel):
    """Risk assessment for a single user."""

    user_email: str
    risk_score: float = Field(ge=0, le=100)
    indicators: List[ThreatIndicator]
    alert_level: AlertLevel
    last_assessed: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    org_id: str


class ActivityRecord(BaseModel):
    """A single recorded user-activity event."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_email: str
    activity_type: str
    details: Dict[str, Any] = Field(default_factory=dict)
    org_id: str
    recorded_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    acknowledged: bool = False
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None


class DetectionStats(BaseModel):
    """Aggregate statistics for an org's insider-threat programme."""

    org_id: str
    total_activities: int
    total_alerts: int
    reviewed_alerts: int
    pending_alerts: int
    risk_distribution: Dict[str, int]
    top_indicators: Dict[str, int]


class RiskDistribution(BaseModel):
    """Count of users at each alert level."""

    org_id: str
    low: int
    medium: int
    high: int
    critical: int
    total: int


# ============================================================================
# DETECTOR
# ============================================================================


class InsiderThreatDetector:
    """
    SQLite-backed insider threat detection engine.

    All public methods are thread-safe via RLock.

    Args:
        db_path: Path to SQLite database. Defaults to data/insider_threat.db.
        org_id:  Default org_id used when none is specified.
    """

    def __init__(
        self,
        db_path: str = _DEFAULT_DB,
        org_id: str = "default",
    ) -> None:
        self.db_path = db_path
        self.org_id = org_id
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        """Create SQLite schema if it doesn't exist."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._get_conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS user_activities (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT    NOT NULL,
                    user_email      TEXT    NOT NULL,
                    activity_type   TEXT    NOT NULL,
                    details         TEXT    DEFAULT '{}',
                    recorded_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
                    acknowledged    INTEGER DEFAULT 0,
                    acknowledged_by TEXT,
                    acknowledged_at DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_ua_org_user
                    ON user_activities (org_id, user_email, recorded_at DESC);

                CREATE INDEX IF NOT EXISTS idx_ua_org_type
                    ON user_activities (org_id, activity_type, recorded_at DESC);

                CREATE TABLE IF NOT EXISTS risk_profiles (
                    user_email      TEXT    NOT NULL,
                    org_id          TEXT    NOT NULL,
                    risk_score      REAL    NOT NULL DEFAULT 0,
                    indicators      TEXT    DEFAULT '[]',
                    alert_level     TEXT    NOT NULL DEFAULT 'low',
                    last_assessed   DATETIME DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (user_email, org_id)
                );

                CREATE INDEX IF NOT EXISTS idx_rp_org_score
                    ON risk_profiles (org_id, risk_score DESC);
                """
            )

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _score_to_level(self, score: float) -> AlertLevel:
        if score >= _THRESHOLD_CRITICAL:
            return AlertLevel.CRITICAL
        if score >= _THRESHOLD_HIGH:
            return AlertLevel.HIGH
        if score >= 30:
            return AlertLevel.MEDIUM
        return AlertLevel.LOW

    def _derive_indicators(self, user_email: str, org_id: str) -> List[ThreatIndicator]:
        """
        Derive ThreatIndicators from the activity log for a user.

        Heuristics (all time-window agnostic for simplicity; full
        production implementation would add rolling windows):
          - DATA_HOARDING        : ≥ 5 data_download events
          - ANOMALOUS_DOWNLOAD   : any single event with bytes_transferred > 100 MB
          - OFF_HOURS_ACTIVITY   : any event recorded outside 07:00-19:00 UTC weekdays
          - PRIVILEGE_ABUSE      : ≥ 1 privilege_escalation or sudo event
          - UNUSUAL_ACCESS       : ≥ 3 access_denied events
          - POLICY_VIOLATION     : ≥ 1 policy_violation event
          - UNAUTHORIZED_TOOL    : ≥ 1 unauthorized_tool event
          - RESIGNATION_RISK     : ≥ 1 resignation_indicator event or bulk export + off-hours
        """
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT activity_type, details, recorded_at FROM user_activities "
                "WHERE org_id = ? AND user_email = ?",
                (org_id, user_email),
            ).fetchall()

        indicators: set[ThreatIndicator] = set()
        download_count = 0
        off_hours_count = 0
        access_denied_count = 0

        for row in rows:
            atype = (row["activity_type"] or "").lower()
            details: Dict[str, Any] = {}
            try:
                details = json.loads(row["details"] or "{}")
            except (json.JSONDecodeError, TypeError):
                pass

            # Parse timestamp
            ts_str = row["recorded_at"]
            try:
                if ts_str:
                    ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                    hour = ts.hour
                    weekday = ts.weekday()  # Mon=0, Sun=6
                    if weekday >= 5 or hour < 7 or hour >= 19:
                        off_hours_count += 1
            except (ValueError, AttributeError):
                pass

            if atype in ("data_download", "bulk_download", "file_download"):
                download_count += 1
                bytes_transferred = details.get("bytes_transferred", 0)
                if bytes_transferred > 100 * 1024 * 1024:  # 100 MB
                    indicators.add(ThreatIndicator.ANOMALOUS_DOWNLOAD)

            if atype in ("privilege_escalation", "sudo", "admin_access"):
                indicators.add(ThreatIndicator.PRIVILEGE_ABUSE)

            if atype in ("access_denied", "unauthorized_access"):
                access_denied_count += 1

            if atype in ("policy_violation",):
                indicators.add(ThreatIndicator.POLICY_VIOLATION)

            if atype in ("unauthorized_tool", "unapproved_tool"):
                indicators.add(ThreatIndicator.UNAUTHORIZED_TOOL)

            if atype in ("resignation_indicator", "job_search", "linkedin_update"):
                indicators.add(ThreatIndicator.RESIGNATION_RISK)

        if download_count >= 5:
            indicators.add(ThreatIndicator.DATA_HOARDING)

        if off_hours_count >= 2:
            indicators.add(ThreatIndicator.OFF_HOURS_ACTIVITY)

        if access_denied_count >= 3:
            indicators.add(ThreatIndicator.UNUSUAL_ACCESS)

        # RESIGNATION_RISK via combo: data hoarding + off-hours
        if (
            ThreatIndicator.DATA_HOARDING in indicators
            and ThreatIndicator.OFF_HOURS_ACTIVITY in indicators
        ):
            indicators.add(ThreatIndicator.RESIGNATION_RISK)

        return sorted(indicators, key=lambda x: x.value)

    def _compute_risk_score(self, indicators: List[ThreatIndicator]) -> float:
        """Compute risk score (0-100) from the set of active indicators."""
        total = sum(_INDICATOR_WEIGHTS.get(ind.value, 0) for ind in indicators)
        return min(float(total), 100.0)

    def _upsert_profile(
        self,
        user_email: str,
        org_id: str,
        indicators: List[ThreatIndicator],
        risk_score: float,
        alert_level: AlertLevel,
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        ind_json = json.dumps([i.value for i in indicators])
        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO risk_profiles
                        (user_email, org_id, risk_score, indicators, alert_level, last_assessed)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(user_email, org_id) DO UPDATE SET
                        risk_score    = excluded.risk_score,
                        indicators    = excluded.indicators,
                        alert_level   = excluded.alert_level,
                        last_assessed = excluded.last_assessed
                    """,
                    (user_email, org_id, risk_score, ind_json, alert_level.value, now),
                )
                conn.commit()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record_activity(
        self,
        user_email: str,
        activity_type: str,
        details: Optional[Dict[str, Any]] = None,
        org_id: Optional[str] = None,
        recorded_at: Optional[datetime] = None,
    ) -> str:
        """
        Log a user activity event.

        Args:
            user_email:    User's email address.
            activity_type: Type of activity (e.g. 'data_download', 'sudo').
            details:       Arbitrary context dict (bytes_transferred, resource, etc.).
            org_id:        Organisation ID (defaults to self.org_id).
            recorded_at:   Timestamp (defaults to now UTC).

        Returns:
            UUID of the inserted activity record.
        """
        org = org_id or self.org_id
        det = details or {}
        ts = recorded_at or datetime.now(timezone.utc)
        activity_id = str(uuid.uuid4())

        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO user_activities
                        (id, org_id, user_email, activity_type, details, recorded_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        activity_id,
                        org,
                        user_email,
                        activity_type,
                        json.dumps(det),
                        ts.isoformat(),
                    ),
                )
                conn.commit()

        _logger.debug(
            "Recorded activity %s for %s in org %s", activity_type, user_email, org
        )
        return activity_id

    def assess_user_risk(
        self,
        user_email: str,
        org_id: Optional[str] = None,
    ) -> UserRiskProfile:
        """
        Compute and persist the risk profile for a single user.

        Args:
            user_email: User to assess.
            org_id:     Organisation ID (defaults to self.org_id).

        Returns:
            UserRiskProfile with risk_score, indicators, and alert_level.
        """
        org = org_id or self.org_id
        indicators = self._derive_indicators(user_email, org)
        risk_score = self._compute_risk_score(indicators)
        alert_level = self._score_to_level(risk_score)
        self._upsert_profile(user_email, org, indicators, risk_score, alert_level)

        return UserRiskProfile(
            user_email=user_email,
            risk_score=risk_score,
            indicators=indicators,
            alert_level=alert_level,
            org_id=org,
        )

    def detect_anomalies(
        self,
        org_id: Optional[str] = None,
    ) -> List[UserRiskProfile]:
        """
        Scan all users in the org for suspicious patterns.

        Re-assesses every user who has logged at least one activity and
        returns profiles where at least one ThreatIndicator is present.

        Args:
            org_id: Organisation ID (defaults to self.org_id).

        Returns:
            List of UserRiskProfile for users with detected anomalies.
        """
        org = org_id or self.org_id
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT DISTINCT user_email FROM user_activities WHERE org_id = ?",
                (org,),
            ).fetchall()

        profiles: List[UserRiskProfile] = []
        for row in rows:
            profile = self.assess_user_risk(row["user_email"], org)
            if profile.indicators:
                profiles.append(profile)

        _logger.info(
            "detect_anomalies: found %d suspicious users in org %s",
            len(profiles),
            org,
        )
        return profiles

    def get_high_risk_users(
        self,
        org_id: Optional[str] = None,
        threshold: float = _THRESHOLD_HIGH,
    ) -> List[UserRiskProfile]:
        """
        Return profiles for users whose risk_score is at or above threshold.

        Args:
            org_id:    Organisation ID (defaults to self.org_id).
            threshold: Minimum risk_score to include (default: 60).

        Returns:
            List of UserRiskProfile sorted by risk_score descending.
        """
        org = org_id or self.org_id
        with self._get_conn() as conn:
            rows = conn.execute(
                """
                SELECT user_email, risk_score, indicators, alert_level, last_assessed
                FROM risk_profiles
                WHERE org_id = ? AND risk_score >= ?
                ORDER BY risk_score DESC
                """,
                (org, threshold),
            ).fetchall()

        profiles: List[UserRiskProfile] = []
        for row in rows:
            try:
                indicators = [
                    ThreatIndicator(i) for i in json.loads(row["indicators"] or "[]")
                ]
            except (json.JSONDecodeError, ValueError):
                indicators = []
            profiles.append(
                UserRiskProfile(
                    user_email=row["user_email"],
                    risk_score=row["risk_score"],
                    indicators=indicators,
                    alert_level=AlertLevel(row["alert_level"]),
                    last_assessed=datetime.fromisoformat(
                        row["last_assessed"].replace("Z", "+00:00")
                    ),
                    org_id=org,
                )
            )
        return profiles

    def get_user_timeline(
        self,
        user_email: str,
        org_id: Optional[str] = None,
        limit: int = 200,
    ) -> List[ActivityRecord]:
        """
        Return the activity history for a user, newest first.

        Args:
            user_email: Target user.
            org_id:     Organisation ID (defaults to self.org_id).
            limit:      Maximum records to return (default: 200).

        Returns:
            List of ActivityRecord sorted by recorded_at descending.
        """
        org = org_id or self.org_id
        with self._get_conn() as conn:
            rows = conn.execute(
                """
                SELECT id, user_email, activity_type, details, org_id,
                       recorded_at, acknowledged, acknowledged_by, acknowledged_at
                FROM user_activities
                WHERE org_id = ? AND user_email = ?
                ORDER BY recorded_at DESC
                LIMIT ?
                """,
                (org, user_email, limit),
            ).fetchall()

        records: List[ActivityRecord] = []
        for row in rows:
            try:
                details = json.loads(row["details"] or "{}")
            except (json.JSONDecodeError, TypeError):
                details = {}
            ack_at = None
            if row["acknowledged_at"]:
                try:
                    ack_at = datetime.fromisoformat(
                        row["acknowledged_at"].replace("Z", "+00:00")
                    )
                except ValueError:
                    pass
            records.append(
                ActivityRecord(
                    id=row["id"],
                    user_email=row["user_email"],
                    activity_type=row["activity_type"],
                    details=details,
                    org_id=row["org_id"],
                    recorded_at=datetime.fromisoformat(
                        row["recorded_at"].replace("Z", "+00:00")
                    ),
                    acknowledged=bool(row["acknowledged"]),
                    acknowledged_by=row["acknowledged_by"],
                    acknowledged_at=ack_at,
                )
            )
        return records

    def get_risk_distribution(
        self,
        org_id: Optional[str] = None,
    ) -> RiskDistribution:
        """
        Return count of users at each alert level for the org.

        Args:
            org_id: Organisation ID (defaults to self.org_id).

        Returns:
            RiskDistribution with low/medium/high/critical counts.
        """
        org = org_id or self.org_id
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT alert_level, COUNT(*) AS cnt FROM risk_profiles "
                "WHERE org_id = ? GROUP BY alert_level",
                (org,),
            ).fetchall()

        counts: Dict[str, int] = {level.value: 0 for level in AlertLevel}
        for row in rows:
            level = row["alert_level"]
            if level in counts:
                counts[level] = row["cnt"]

        total = sum(counts.values())
        return RiskDistribution(
            org_id=org,
            low=counts["low"],
            medium=counts["medium"],
            high=counts["high"],
            critical=counts["critical"],
            total=total,
        )

    def acknowledge_alert(
        self,
        user_email: str,
        reviewer: str,
        org_id: Optional[str] = None,
    ) -> bool:
        """
        Mark all unacknowledged activity records for a user as reviewed.

        Args:
            user_email: User whose alerts are being acknowledged.
            reviewer:   Reviewer's identifier (email / username).
            org_id:     Organisation ID (defaults to self.org_id).

        Returns:
            True if at least one record was updated, False otherwise.
        """
        org = org_id or self.org_id
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._get_conn() as conn:
                cur = conn.execute(
                    """
                    UPDATE user_activities
                    SET acknowledged    = 1,
                        acknowledged_by = ?,
                        acknowledged_at = ?
                    WHERE org_id = ? AND user_email = ? AND acknowledged = 0
                    """,
                    (reviewer, now, org, user_email),
                )
                conn.commit()
                updated = cur.rowcount > 0

        _logger.info(
            "acknowledge_alert: %s reviewed alerts for %s in org %s (updated=%s)",
            reviewer,
            user_email,
            org,
            updated,
        )
        return updated

    def get_detection_stats(
        self,
        org_id: Optional[str] = None,
    ) -> DetectionStats:
        """
        Return aggregate statistics for the org's insider-threat programme.

        Args:
            org_id: Organisation ID (defaults to self.org_id).

        Returns:
            DetectionStats with totals, reviewed counts, and risk distribution.
        """
        org = org_id or self.org_id
        with self._get_conn() as conn:
            total_activities: int = conn.execute(
                "SELECT COUNT(*) FROM user_activities WHERE org_id = ?", (org,)
            ).fetchone()[0]

            # High/critical risk users are "alerts"
            total_alerts: int = conn.execute(
                "SELECT COUNT(*) FROM risk_profiles "
                "WHERE org_id = ? AND alert_level IN ('high', 'critical')",
                (org,),
            ).fetchone()[0]

            # Reviewed = at least one acknowledged activity and a high/critical profile
            reviewed_alerts: int = conn.execute(
                """
                SELECT COUNT(DISTINCT rp.user_email)
                FROM risk_profiles rp
                JOIN user_activities ua
                    ON ua.user_email = rp.user_email AND ua.org_id = rp.org_id
                WHERE rp.org_id = ?
                  AND rp.alert_level IN ('high', 'critical')
                  AND ua.acknowledged = 1
                """,
                (org,),
            ).fetchone()[0]

            # Risk distribution
            dist_rows = conn.execute(
                "SELECT alert_level, COUNT(*) AS cnt FROM risk_profiles "
                "WHERE org_id = ? GROUP BY alert_level",
                (org,),
            ).fetchall()

            # Top indicators
            ind_rows = conn.execute(
                "SELECT indicators FROM risk_profiles WHERE org_id = ?", (org,)
            ).fetchall()

        risk_dist: Dict[str, int] = {}
        for row in dist_rows:
            risk_dist[row["alert_level"]] = row["cnt"]

        indicator_counts: Dict[str, int] = {}
        for row in ind_rows:
            try:
                inds = json.loads(row["indicators"] or "[]")
            except (json.JSONDecodeError, TypeError):
                inds = []
            for ind in inds:
                indicator_counts[ind] = indicator_counts.get(ind, 0) + 1

        return DetectionStats(
            org_id=org,
            total_activities=total_activities,
            total_alerts=total_alerts,
            reviewed_alerts=reviewed_alerts,
            pending_alerts=max(0, total_alerts - reviewed_alerts),
            risk_distribution=risk_dist,
            top_indicators=indicator_counts,
        )

    def get_trustgraph_context(
        self,
        org_id: str,
        entity_id: str,
    ) -> Dict[str, Any]:
        """Query TrustGraph for cross-domain context about an insider threat entity.

        Returns related assets, findings, and incidents for enriched investigation.
        Degrades gracefully when TrustGraph is unavailable.

        Args:
            org_id: Organisation identifier for tenant isolation.
            entity_id: User email or identifier to look up in TrustGraph.

        Returns:
            Dict with keys: related_assets, related_findings, related_incidents,
            trustgraph_available (bool).

        Compliance: SOC2 CC7.2, NIST SP 800-53 IR-4 (Incident Handling).
        """
        context: Dict[str, Any] = {
            "entity_id": entity_id,
            "org_id": org_id,
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
                        entry = {
                            "id": entity.entity_id,
                            "name": entity.name,
                            "type": entity.entity_type,
                        }
                        etype = entity.entity_type.lower()
                        if etype in ("asset", "service", "host"):
                            context["related_assets"].append(entry)
                        elif etype in ("finding", "vulnerability"):
                            context["related_findings"].append(entry)
                        elif etype in ("incident", "breach", "alert"):
                            context["related_incidents"].append(entry)
                except Exception:
                    pass

            try:
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

        except Exception:
            # TrustGraph unavailable — degrade gracefully
            pass

        return context
