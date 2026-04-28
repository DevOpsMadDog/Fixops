"""Security posture improvement advisor — AI-driven recommendations engine."""
from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog

_logger = structlog.get_logger(__name__)

RECOMMENDATION_CATEGORIES = [
    "vulnerability_management", "access_control", "data_protection",
    "incident_response", "cloud_security", "application_security",
    "network_security", "compliance", "threat_intelligence", "supply_chain"
]
PRIORITY_LEVELS = ["critical", "high", "medium", "low"]
EFFORT_LEVELS = ["days", "weeks", "months"]

# Built-in recommendation templates
RECOMMENDATION_TEMPLATES = [
    {
        "id": "rec-001", "category": "vulnerability_management",
        "title": "Enable automated patch management",
        "description": "Configure automated patching for critical and high severity CVEs with SLA under 7 days",
        "impact": "Reduces attack surface from known vulnerabilities by up to 80%",
        "effort": "weeks", "priority": "high",
        "trigger_condition": "avg_patch_time_days > 30",
        "score_improvement": 5.0,
    },
    {
        "id": "rec-002", "category": "access_control",
        "title": "Enforce MFA for all privileged accounts",
        "description": "Require multi-factor authentication for all accounts with write access",
        "impact": "Prevents 99.9% of account compromise attacks",
        "effort": "days", "priority": "critical",
        "trigger_condition": "mfa_coverage_pct < 100",
        "score_improvement": 8.0,
    },
    {
        "id": "rec-003", "category": "incident_response",
        "title": "Reduce mean time to detect (MTTD) below 1 hour",
        "description": "Configure real-time alerting for critical severity anomalies",
        "impact": "Reduces breach impact by 50% when detected within 1 hour",
        "effort": "weeks", "priority": "high",
        "trigger_condition": "avg_mttd_hours > 1",
        "score_improvement": 6.0,
    },
    {
        "id": "rec-004", "category": "data_protection",
        "title": "Enable encryption at rest for all databases",
        "description": "Apply AES-256 encryption to all customer data stores",
        "impact": "Eliminates data exposure risk from physical media theft",
        "effort": "months", "priority": "critical",
        "trigger_condition": "unencrypted_databases > 0",
        "score_improvement": 10.0,
    },
    {
        "id": "rec-005", "category": "cloud_security",
        "title": "Remove wildcard IAM permissions",
        "description": "Replace * permissions with least-privilege role definitions",
        "impact": "Reduces blast radius of compromised credentials by 90%",
        "effort": "weeks", "priority": "critical",
        "trigger_condition": "wildcard_permissions_count > 0",
        "score_improvement": 9.0,
    },
    {
        "id": "rec-006", "category": "vulnerability_management",
        "title": "Remediate all open critical vulnerabilities",
        "description": "Prioritize and close all open critical CVEs within 24 hours",
        "impact": "Eliminates highest-risk known exposure points immediately",
        "effort": "days", "priority": "critical",
        "trigger_condition": "open_critical_vulns > 0",
        "score_improvement": 12.0,
    },
    {
        "id": "rec-007", "category": "compliance",
        "title": "Achieve 100% SLA compliance",
        "description": "Implement automated SLA tracking and escalation workflows",
        "impact": "Ensures regulatory commitments are met and audit-ready posture",
        "effort": "weeks", "priority": "medium",
        "trigger_condition": "sla_compliance_pct < 95",
        "score_improvement": 4.0,
    },
]

_EFFORT_PHASE_MAP = {
    "days": 1,
    "weeks": 2,
    "months": 3,
}

_PRIORITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _eval_trigger(condition: str, posture_data: Dict[str, Any]) -> bool:
    """Evaluate a trigger condition string against posture_data."""
    try:
        return bool(eval(condition, {"__builtins__": {}}, posture_data))  # noqa: S307  # nosemgrep: eval-detected  # nosec
    except Exception:
        return False


class _AdvisorDB:
    """Thin SQLite wrapper for posture advisor data."""

    def __init__(self, db_path: str) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_schema(self) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.executescript("""
                    CREATE TABLE IF NOT EXISTS analyses (
                        analysis_id TEXT PRIMARY KEY,
                        org_id TEXT NOT NULL,
                        posture_score REAL NOT NULL,
                        recommendation_ids TEXT NOT NULL,
                        critical_count INTEGER NOT NULL DEFAULT 0,
                        estimated_score_improvement REAL NOT NULL DEFAULT 0.0,
                        created_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS recommendations (
                        rec_id TEXT PRIMARY KEY,
                        analysis_id TEXT NOT NULL,
                        org_id TEXT NOT NULL,
                        template_id TEXT NOT NULL,
                        category TEXT NOT NULL,
                        priority TEXT NOT NULL,
                        title TEXT NOT NULL,
                        description TEXT NOT NULL,
                        impact TEXT NOT NULL,
                        effort TEXT NOT NULL,
                        score_improvement REAL NOT NULL DEFAULT 0.0,
                        status TEXT NOT NULL DEFAULT 'open',
                        owner TEXT,
                        target_date TEXT,
                        completed_by TEXT,
                        actual_improvement REAL DEFAULT 0.0,
                        dismiss_reason TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS idx_recs_org ON recommendations(org_id);
                    CREATE INDEX IF NOT EXISTS idx_recs_status ON recommendations(status);
                    CREATE INDEX IF NOT EXISTS idx_recs_priority ON recommendations(priority);
                    CREATE INDEX IF NOT EXISTS idx_recs_category ON recommendations(category);
                """)

    def insert_analysis(self, row: Dict[str, Any]) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """INSERT OR REPLACE INTO analyses
                       (analysis_id, org_id, posture_score, recommendation_ids,
                        critical_count, estimated_score_improvement, created_at)
                       VALUES (:analysis_id, :org_id, :posture_score,
                               :recommendation_ids, :critical_count,
                               :estimated_score_improvement, :created_at)""",
                    row,
                )

    def insert_recommendation(self, row: Dict[str, Any]) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """INSERT OR REPLACE INTO recommendations
                       (rec_id, analysis_id, org_id, template_id, category, priority,
                        title, description, impact, effort, score_improvement, status,
                        owner, target_date, completed_by, actual_improvement,
                        dismiss_reason, created_at, updated_at)
                       VALUES (:rec_id, :analysis_id, :org_id, :template_id,
                               :category, :priority, :title, :description, :impact,
                               :effort, :score_improvement, :status, :owner,
                               :target_date, :completed_by, :actual_improvement,
                               :dismiss_reason, :created_at, :updated_at)""",
                    row,
                )

    def get_recommendation(self, rec_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM recommendations WHERE rec_id = ?", (rec_id,)
                ).fetchone()
                return dict(row) if row else None

    def list_recommendations(
        self,
        org_id: str,
        category: Optional[str] = None,
        priority: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        query = "SELECT * FROM recommendations WHERE org_id = ?"
        params: List[Any] = [org_id]
        if category:
            query += " AND category = ?"
            params.append(category)
        if priority:
            query += " AND priority = ?"
            params.append(priority)
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY CASE priority WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, created_at DESC"
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute(query, params).fetchall()
                return [dict(r) for r in rows]

    def update_recommendation(self, rec_id: str, updates: Dict[str, Any]) -> None:
        updates["updated_at"] = datetime.now(timezone.utc).isoformat()
        set_clause = ", ".join(f"{k} = :{k}" for k in updates)
        updates["rec_id"] = rec_id
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    f"UPDATE recommendations SET {set_clause} WHERE rec_id = :rec_id",  # nosec B608
                    updates,
                )

    def get_stats(self, org_id: str) -> Dict[str, Any]:
        with self._lock:
            with self._connect() as conn:
                total_analyses = conn.execute(
                    "SELECT COUNT(*) FROM analyses WHERE org_id = ?", (org_id,)
                ).fetchone()[0]
                accepted = conn.execute(
                    "SELECT COUNT(*) FROM recommendations WHERE org_id = ? AND status = 'accepted'",
                    (org_id,),
                ).fetchone()[0]
                completed = conn.execute(
                    "SELECT COUNT(*) FROM recommendations WHERE org_id = ? AND status = 'completed'",
                    (org_id,),
                ).fetchone()[0]
                avg_row = conn.execute(
                    "SELECT AVG(actual_improvement) FROM recommendations WHERE org_id = ? AND status = 'completed'",
                    (org_id,),
                ).fetchone()
                avg_improvement = avg_row[0] or 0.0
                return {
                    "total_analyses": total_analyses,
                    "recommendations_accepted": accepted,
                    "recommendations_completed": completed,
                    "avg_score_improvement": round(avg_improvement, 2),
                }


class PostureAdvisor:
    """Security posture improvement advisor — generates prioritized recommendations."""

    def __init__(self, db_path: str = "data/posture_advisor.db") -> None:
        self._db = _AdvisorDB(db_path)

    def analyze_posture(self, posture_data: Dict[str, Any], org_id: str = "default") -> Dict[str, Any]:
        """Analyze current posture and generate recommendations.

        posture_data keys:
            posture_score: float
            open_critical_vulns: int
            avg_patch_time_days: float
            mfa_coverage_pct: float
            avg_mttd_hours: float
            unencrypted_databases: int
            wildcard_permissions_count: int
            sla_compliance_pct: float

        Returns analysis dict with recommendations list.
        """
        analysis_id = f"ana-{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc).isoformat()
        posture_score = float(posture_data.get("posture_score", 50.0))

        triggered: List[Dict[str, Any]] = []
        for template in RECOMMENDATION_TEMPLATES:
            if _eval_trigger(template["trigger_condition"], posture_data):
                triggered.append(template)

        # Sort by priority then effort (faster wins tie)
        triggered.sort(key=lambda t: (
            _PRIORITY_ORDER.get(t["priority"], 99),
            _EFFORT_PHASE_MAP.get(t["effort"], 99),
        ))

        rec_ids: List[str] = []
        rec_dicts: List[Dict[str, Any]] = []
        critical_count = 0
        total_improvement = 0.0

        for template in triggered:
            rec_id = f"rec-{uuid.uuid4().hex[:12]}"
            rec_row: Dict[str, Any] = {
                "rec_id": rec_id,
                "analysis_id": analysis_id,
                "org_id": org_id,
                "template_id": template["id"],
                "category": template["category"],
                "priority": template["priority"],
                "title": template["title"],
                "description": template["description"],
                "impact": template["impact"],
                "effort": template["effort"],
                "score_improvement": template.get("score_improvement", 0.0),
                "status": "open",
                "owner": None,
                "target_date": None,
                "completed_by": None,
                "actual_improvement": 0.0,
                "dismiss_reason": None,
                "created_at": now,
                "updated_at": now,
            }
            self._db.insert_recommendation(rec_row)
            rec_ids.append(rec_id)
            rec_dicts.append(rec_row)
            if template["priority"] == "critical":
                critical_count += 1
            total_improvement += template.get("score_improvement", 0.0)

        # Cap improvement at 100
        estimated_improvement = min(total_improvement, 100.0 - posture_score)

        analysis_row: Dict[str, Any] = {
            "analysis_id": analysis_id,
            "org_id": org_id,
            "posture_score": posture_score,
            "recommendation_ids": json.dumps(rec_ids),
            "critical_count": critical_count,
            "estimated_score_improvement": round(estimated_improvement, 2),
            "created_at": now,
        }
        self._db.insert_analysis(analysis_row)

        _logger.info(
            "posture_analysis_complete",
            analysis_id=analysis_id,
            org_id=org_id,
            posture_score=posture_score,
            total_recommendations=len(rec_ids),
            critical_count=critical_count,
        )

        return {
            "analysis_id": analysis_id,
            "posture_score": posture_score,
            "recommendations": rec_dicts,
            "total_recommendations": len(rec_ids),
            "critical_count": critical_count,
            "estimated_score_improvement": round(estimated_improvement, 2),
        }

    def get_recommendation(self, rec_id: str, org_id: str = "default") -> Optional[Dict[str, Any]]:
        """Retrieve a single recommendation by ID."""
        return self._db.get_recommendation(rec_id)

    def list_recommendations(
        self,
        org_id: str = "default",
        category: Optional[str] = None,
        priority: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List recommendations with optional filters."""
        return self._db.list_recommendations(org_id, category=category, priority=priority, status=status)

    def accept_recommendation(
        self, rec_id: str, owner: str, target_date: str, org_id: str = "default"
    ) -> Dict[str, Any]:
        """Accept a recommendation and assign an owner with target date."""
        rec = self._db.get_recommendation(rec_id)
        if not rec:
            raise ValueError(f"Recommendation not found: {rec_id}")
        self._db.update_recommendation(rec_id, {
            "status": "accepted",
            "owner": owner,
            "target_date": target_date,
        })
        rec = self._db.get_recommendation(rec_id)
        _logger.info("recommendation_accepted", rec_id=rec_id, owner=owner, target_date=target_date)
        return rec  # type: ignore[return-value]

    def complete_recommendation(
        self, rec_id: str, completed_by: str, actual_improvement: float = 0.0
    ) -> Dict[str, Any]:
        """Mark a recommendation as completed."""
        rec = self._db.get_recommendation(rec_id)
        if not rec:
            raise ValueError(f"Recommendation not found: {rec_id}")
        self._db.update_recommendation(rec_id, {
            "status": "completed",
            "completed_by": completed_by,
            "actual_improvement": actual_improvement,
        })
        rec = self._db.get_recommendation(rec_id)
        _logger.info("recommendation_completed", rec_id=rec_id, completed_by=completed_by, actual_improvement=actual_improvement)
        return rec  # type: ignore[return-value]

    def dismiss_recommendation(
        self, rec_id: str, reason: str, org_id: str = "default"
    ) -> Dict[str, Any]:
        """Dismiss a recommendation with justification."""
        rec = self._db.get_recommendation(rec_id)
        if not rec:
            raise ValueError(f"Recommendation not found: {rec_id}")
        self._db.update_recommendation(rec_id, {
            "status": "dismissed",
            "dismiss_reason": reason,
        })
        rec = self._db.get_recommendation(rec_id)
        _logger.info("recommendation_dismissed", rec_id=rec_id, reason=reason)
        return rec  # type: ignore[return-value]

    def get_roadmap(self, org_id: str = "default") -> Dict[str, Any]:
        """Generate a prioritized improvement roadmap grouped into 3 phases."""
        open_recs = self._db.list_recommendations(org_id, status="open")
        accepted_recs = self._db.list_recommendations(org_id, status="accepted")
        active_recs = open_recs + accepted_recs

        phases: List[Dict[str, Any]] = [
            {
                "phase": 1,
                "timeframe": "immediate (0-30 days)",
                "recommendations": [],
            },
            {
                "phase": 2,
                "timeframe": "short-term (30-90 days)",
                "recommendations": [],
            },
            {
                "phase": 3,
                "timeframe": "long-term (90+ days)",
                "recommendations": [],
            },
        ]

        total_improvement = 0.0
        for rec in active_recs:
            effort = rec.get("effort", "months")
            phase_idx = _EFFORT_PHASE_MAP.get(effort, 3) - 1
            phases[phase_idx]["recommendations"].append(rec)
            total_improvement += rec.get("score_improvement", 0.0)

        return {
            "phases": phases,
            "total_estimated_improvement": round(min(total_improvement, 100.0), 2),
        }

    def get_advisor_stats(self, org_id: str = "default") -> Dict[str, Any]:
        """Return advisor statistics for the given org."""
        return self._db.get_stats(org_id)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_advisor_instance: Optional[PostureAdvisor] = None
_advisor_lock = threading.Lock()


def get_posture_advisor() -> PostureAdvisor:
    """Return the module-level PostureAdvisor singleton."""
    global _advisor_instance
    if _advisor_instance is None:
        with _advisor_lock:
            if _advisor_instance is None:
                _advisor_instance = PostureAdvisor()
    return _advisor_instance
