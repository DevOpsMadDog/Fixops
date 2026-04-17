"""Security Architecture Review Engine — ALDECI.

Tracks architecture reviews, findings, and control gaps across systems.

Features:
- Review lifecycle (draft → completed)
- Finding tracking with severity-driven risk_level recomputation
- Control gap analysis with effectiveness clamping
- complete_review computes overall_score = AVG(control effectiveness)
- get_control_gaps returns unimplemented controls ordered by effectiveness ASC
- Multi-tenant org_id isolation

Compliance: NIST SP 800-53 SA-8 (Security Engineering Principles),
            ISO 27001 A.14.2, CIS Control 16, TOGAF Security Architecture
"""

from __future__ import annotations

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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "security_architecture_review.db"
)

_VALID_REVIEW_TYPES = {"full", "partial", "threat-model", "compliance", "vendor"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_VALID_IMPL_STATUSES = {"implemented", "partial", "not_implemented", "compensating"}
_VALID_FINDING_TYPES = {
    "design-flaw", "missing-control", "weak-implementation",
    "configuration", "dependency-risk", "data-exposure",
}


def _compute_risk_level(critical_count: int, finding_count: int) -> str:
    if critical_count > 0:
        return "critical"
    if finding_count > 5:
        return "high"
    if finding_count > 2:
        return "medium"
    return "low"


class SecurityArchitectureReviewEngine:
    """Engine for security architecture review tracking and control gap analysis."""

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # DB INIT
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS arch_reviews (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    review_name     TEXT NOT NULL DEFAULT '',
                    system_name     TEXT NOT NULL DEFAULT '',
                    review_type     TEXT NOT NULL DEFAULT 'full',
                    reviewer        TEXT NOT NULL DEFAULT '',
                    status          TEXT NOT NULL DEFAULT 'draft',
                    overall_score   REAL NOT NULL DEFAULT 0.0,
                    risk_level      TEXT NOT NULL DEFAULT 'medium',
                    finding_count   INTEGER NOT NULL DEFAULT 0,
                    critical_count  INTEGER NOT NULL DEFAULT 0,
                    created_at      TEXT,
                    completed_at    TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_ar_org    ON arch_reviews(org_id);
                CREATE INDEX IF NOT EXISTS idx_ar_status ON arch_reviews(org_id, status);

                CREATE TABLE IF NOT EXISTS arch_findings (
                    id              TEXT PRIMARY KEY,
                    review_id       TEXT NOT NULL,
                    org_id          TEXT NOT NULL,
                    component       TEXT NOT NULL DEFAULT '',
                    finding_type    TEXT NOT NULL DEFAULT 'design-flaw',
                    title           TEXT NOT NULL DEFAULT '',
                    description     TEXT NOT NULL DEFAULT '',
                    severity        TEXT NOT NULL DEFAULT 'medium',
                    recommendation  TEXT NOT NULL DEFAULT '',
                    status          TEXT NOT NULL DEFAULT 'open',
                    created_at      TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_af_review ON arch_findings(review_id);
                CREATE INDEX IF NOT EXISTS idx_af_org    ON arch_findings(org_id);

                CREATE TABLE IF NOT EXISTS arch_controls (
                    id                    TEXT PRIMARY KEY,
                    review_id             TEXT NOT NULL,
                    org_id                TEXT NOT NULL,
                    control_name          TEXT NOT NULL DEFAULT '',
                    domain                TEXT NOT NULL DEFAULT '',
                    implementation_status TEXT NOT NULL DEFAULT 'not_implemented',
                    effectiveness         REAL NOT NULL DEFAULT 0.0,
                    gaps                  TEXT NOT NULL DEFAULT '',
                    created_at            TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_ac_review ON arch_controls(review_id);
                CREATE INDEX IF NOT EXISTS idx_ac_org    ON arch_controls(org_id);
            """)

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # PUBLIC API
    # ------------------------------------------------------------------

    def create_review(
        self,
        org_id: str,
        review_name: str,
        system_name: str,
        review_type: str = "full",
        reviewer: str = "",
    ) -> Dict[str, Any]:
        """Create a new architecture review in draft status."""
        if review_type not in _VALID_REVIEW_TYPES:
            raise ValueError(
                f"Invalid review_type '{review_type}'. Must be one of {sorted(_VALID_REVIEW_TYPES)}"
            )
        review_id = str(uuid.uuid4())
        now = self._now()
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO arch_reviews
                   (id, org_id, review_name, system_name, review_type, reviewer,
                    status, overall_score, risk_level, finding_count, critical_count,
                    created_at, completed_at)
                   VALUES (?,?,?,?,?,?,'draft',0.0,'medium',0,0,?,NULL)""",
                (review_id, org_id, review_name, system_name, review_type, reviewer, now),
            )
        _logger.info(
            "arch_review.created org=%s review_id=%s system=%s",
            org_id, review_id, system_name,
        )
        return self.get_review(review_id, org_id)

    def add_finding(
        self,
        review_id: str,
        org_id: str,
        component: str,
        finding_type: str,
        title: str,
        description: str = "",
        severity: str = "medium",
        recommendation: str = "",
    ) -> Dict[str, Any]:
        """Add a finding to a review. Increments finding/critical counts and recomputes risk_level."""
        if finding_type not in _VALID_FINDING_TYPES:
            raise ValueError(
                f"Invalid finding_type '{finding_type}'. Must be one of {sorted(_VALID_FINDING_TYPES)}"
            )
        if severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity '{severity}'. Must be one of {sorted(_VALID_SEVERITIES)}"
            )

        finding_id = str(uuid.uuid4())
        now = self._now()

        with self._lock, self._conn() as conn:
            # Verify review exists and belongs to org
            row = conn.execute(
                "SELECT finding_count, critical_count FROM arch_reviews WHERE id=? AND org_id=?",
                (review_id, org_id),
            ).fetchone()
            if row is None:
                raise ValueError(f"Review '{review_id}' not found for org '{org_id}'")

            # Insert finding
            conn.execute(
                """INSERT INTO arch_findings
                   (id, review_id, org_id, component, finding_type, title, description,
                    severity, recommendation, status, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,'open',?)""",
                (
                    finding_id, review_id, org_id, component, finding_type,
                    title, description, severity, recommendation, now,
                ),
            )

            # Update counters
            new_finding_count = row["finding_count"] + 1
            new_critical_count = row["critical_count"] + (1 if severity == "critical" else 0)
            new_risk_level = _compute_risk_level(new_critical_count, new_finding_count)

            conn.execute(
                """UPDATE arch_reviews
                   SET finding_count=?, critical_count=?, risk_level=?
                   WHERE id=? AND org_id=?""",
                (new_finding_count, new_critical_count, new_risk_level, review_id, org_id),
            )

        _logger.info(
            "arch_review.finding_added org=%s review_id=%s finding_id=%s severity=%s",
            org_id, review_id, finding_id, severity,
        )
        return self._get_finding(finding_id, org_id)

    def _get_finding(self, finding_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM arch_findings WHERE id=? AND org_id=?",
                (finding_id, org_id),
            ).fetchone()
        return self._row(row) if row else None

    def add_control(
        self,
        review_id: str,
        org_id: str,
        control_name: str,
        domain: str,
        implementation_status: str = "not_implemented",
        effectiveness: float = 0.0,
        gaps: str = "",
    ) -> Dict[str, Any]:
        """Add a control assessment to a review. Effectiveness is clamped 0–100."""
        if implementation_status not in _VALID_IMPL_STATUSES:
            raise ValueError(
                f"Invalid implementation_status '{implementation_status}'. "
                f"Must be one of {sorted(_VALID_IMPL_STATUSES)}"
            )
        # Verify review exists for org
        with self._conn() as conn:
            exists = conn.execute(
                "SELECT 1 FROM arch_reviews WHERE id=? AND org_id=?",
                (review_id, org_id),
            ).fetchone()
        if exists is None:
            raise ValueError(f"Review '{review_id}' not found for org '{org_id}'")

        # Clamp effectiveness
        effectiveness = max(0.0, min(100.0, float(effectiveness)))

        control_id = str(uuid.uuid4())
        now = self._now()
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO arch_controls
                   (id, review_id, org_id, control_name, domain, implementation_status,
                    effectiveness, gaps, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    control_id, review_id, org_id, control_name, domain,
                    implementation_status, effectiveness, gaps, now,
                ),
            )
        _logger.info(
            "arch_review.control_added org=%s review_id=%s control=%s status=%s",
            org_id, review_id, control_name, implementation_status,
        )
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM arch_controls WHERE id=?", (control_id,)
            ).fetchone()
        return self._row(row)

    def complete_review(self, review_id: str, org_id: str) -> Dict[str, Any]:
        """Complete a review. Computes overall_score = AVG(effectiveness of controls)."""
        with self._conn() as conn:
            exists = conn.execute(
                "SELECT 1 FROM arch_reviews WHERE id=? AND org_id=?",
                (review_id, org_id),
            ).fetchone()
        if exists is None:
            raise ValueError(f"Review '{review_id}' not found for org '{org_id}'")

        with self._lock, self._conn() as conn:
            avg_row = conn.execute(
                """SELECT AVG(effectiveness)
                   FROM arch_controls
                   WHERE review_id=? AND org_id=?""",
                (review_id, org_id),
            ).fetchone()[0]
            overall_score = round(avg_row, 2) if avg_row is not None else 0.0

            conn.execute(
                """UPDATE arch_reviews
                   SET status='completed', overall_score=?, completed_at=?
                   WHERE id=? AND org_id=?""",
                (overall_score, self._now(), review_id, org_id),
            )
        _logger.info(
            "arch_review.completed org=%s review_id=%s score=%.2f",
            org_id, review_id, overall_score,
        )
        return self.get_review(review_id, org_id)

    def get_review(self, review_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        """Return review dict with nested findings and controls lists."""
        with self._conn() as conn:
            review_row = conn.execute(
                "SELECT * FROM arch_reviews WHERE id=? AND org_id=?",
                (review_id, org_id),
            ).fetchone()
            if review_row is None:
                return None
            review = self._row(review_row)

            findings = conn.execute(
                "SELECT * FROM arch_findings WHERE review_id=? AND org_id=? ORDER BY created_at",
                (review_id, org_id),
            ).fetchall()
            controls = conn.execute(
                "SELECT * FROM arch_controls WHERE review_id=? AND org_id=? ORDER BY created_at",
                (review_id, org_id),
            ).fetchall()

        review["findings"] = [self._row(r) for r in findings]
        review["controls"] = [self._row(r) for r in controls]
        return review

    def list_reviews(
        self,
        org_id: str,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List reviews for an org, optionally filtered by status."""
        query = "SELECT * FROM arch_reviews WHERE org_id=?"
        params: List[Any] = [org_id]
        if status:
            query += " AND status=?"
            params.append(status)
        query += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def get_control_gaps(self, org_id: str) -> List[Dict[str, Any]]:
        """Return all controls where implementation_status != 'implemented', ordered by effectiveness ASC."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM arch_controls
                   WHERE org_id=? AND implementation_status != 'implemented'
                   ORDER BY effectiveness ASC""",
                (org_id,),
            ).fetchall()
        return [self._row(r) for r in rows]

    def get_summary(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate summary: counts, by_status, by_risk_level, avg_score, critical_findings."""
        with self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM arch_reviews WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            by_status_rows = conn.execute(
                "SELECT status, COUNT(*) AS cnt FROM arch_reviews WHERE org_id=? GROUP BY status",
                (org_id,),
            ).fetchall()

            by_risk_rows = conn.execute(
                "SELECT risk_level, COUNT(*) AS cnt FROM arch_reviews WHERE org_id=? GROUP BY risk_level",
                (org_id,),
            ).fetchall()

            avg_score_row = conn.execute(
                "SELECT AVG(overall_score) FROM arch_reviews WHERE org_id=? AND status='completed'",
                (org_id,),
            ).fetchone()[0]

            critical_sum = conn.execute(
                "SELECT SUM(critical_count) FROM arch_reviews WHERE org_id=?",
                (org_id,),
            ).fetchone()[0]

        return {
            "total_reviews": total,
            "by_status": {r["status"]: r["cnt"] for r in by_status_rows},
            "by_risk_level": {r["risk_level"]: r["cnt"] for r in by_risk_rows},
            "avg_score": round(avg_score_row, 2) if avg_score_row is not None else 0.0,
            "critical_finding_count": critical_sum or 0,
        }
