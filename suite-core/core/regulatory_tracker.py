"""
Regulatory Change Tracker — ALDECI compliance intelligence module.

Tracks changes in compliance regulations (GDPR updates, PCI DSS v4.0,
SEC cyber rules, NIS2, DORA, AI Act) and assesses organisational impact.

Each regulation is persisted in SQLite with impact assessments, action plans,
and a chronological timeline view.

Compliance: SOC2 CC6.1 (Change management), ISO27001 A.18.1 (Legal requirements)
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)


# ============================================================================
# PYDANTIC MODELS
# ============================================================================


class Regulation(BaseModel):
    """A tracked regulatory change or requirement."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    framework: str = Field(..., description="e.g. GDPR, PCI-DSS, SEC, NIS2, DORA, AI-Act")
    title: str = Field(..., min_length=1)
    description: str = Field(default="")
    effective_date: str = Field(..., description="ISO-8601 date string, e.g. 2024-03-31")
    impact: str = Field(..., description="high | medium | low")
    affected_controls: List[str] = Field(default_factory=list)
    status: str = Field(default="upcoming", description="upcoming | active | superseded")
    org_id: str = Field(..., min_length=1)


class RegulatoryImpact(BaseModel):
    """Impact assessment for a single regulation against an organisation."""

    regulation_id: str
    gap_count: int = Field(default=0, ge=0)
    controls_affected: List[str] = Field(default_factory=list)
    remediation_needed: bool = False
    estimated_effort_days: float = Field(default=0.0, ge=0.0)


# ============================================================================
# BUILT-IN SEED DATA
# ============================================================================

_BUILTIN_REGULATIONS: List[Dict[str, Any]] = [
    {
        "framework": "GDPR",
        "title": "GDPR Article 25 – Privacy by Design updates (2024)",
        "description": (
            "Strengthened enforcement of privacy-by-design and data-minimisation "
            "obligations following EDPB guidelines 4/2019 revision."
        ),
        "effective_date": "2024-01-01",
        "impact": "high",
        "affected_controls": ["GDPR-Art25", "GDPR-Art32", "ISO27001-A.8.3", "SOC2-P1"],
        "status": "active",
    },
    {
        "framework": "PCI-DSS",
        "title": "PCI DSS v4.0 – New authentication and encryption requirements",
        "description": (
            "PCI DSS v4.0 mandates multi-factor authentication for all CDE access, "
            "upgraded TLS 1.2+ enforcement, and targeted risk analysis for custom controls."
        ),
        "effective_date": "2024-03-31",
        "impact": "high",
        "affected_controls": ["PCI-Req8", "PCI-Req4", "PCI-Req12.3.2", "NIST-IA-2"],
        "status": "active",
    },
    {
        "framework": "SEC",
        "title": "SEC Cybersecurity Disclosure Rules – Material incident reporting",
        "description": (
            "Public companies must disclose material cybersecurity incidents within 4 "
            "business days (Form 8-K Item 1.05) and annual cybersecurity risk management "
            "disclosures (Form 10-K)."
        ),
        "effective_date": "2023-12-18",
        "impact": "high",
        "affected_controls": ["SEC-Item1.05", "NIST-RS.CO-2", "SOC2-CC7.5"],
        "status": "active",
    },
    {
        "framework": "NIS2",
        "title": "NIS2 Directive – EU network and information systems security",
        "description": (
            "Expands scope to 18 critical sectors, introduces strict supply-chain "
            "security requirements, mandatory incident reporting within 24 h, and "
            "personal liability for management."
        ),
        "effective_date": "2024-10-17",
        "impact": "high",
        "affected_controls": ["NIS2-Art21", "NIS2-Art23", "ISO27001-A.5.23", "NIST-ID.SC"],
        "status": "active",
    },
    {
        "framework": "DORA",
        "title": "DORA – Digital Operational Resilience Act (EU financial sector)",
        "description": (
            "Mandates ICT risk management, incident classification and reporting, "
            "TLPT threat-led penetration testing, and oversight of critical ICT third-party providers."
        ),
        "effective_date": "2025-01-17",
        "impact": "high",
        "affected_controls": ["DORA-Art6", "DORA-Art17", "DORA-Art25", "ISO27001-A.17"],
        "status": "upcoming",
    },
    {
        "framework": "AI-Act",
        "title": "EU AI Act – High-risk AI system obligations",
        "description": (
            "High-risk AI systems must implement risk management, data governance, "
            "transparency, human oversight, and undergo conformity assessment before "
            "EU market placement."
        ),
        "effective_date": "2026-08-02",
        "impact": "medium",
        "affected_controls": ["AI-Act-Art9", "AI-Act-Art13", "NIST-AI-RMF", "ISO42001"],
        "status": "upcoming",
    },
]

# Effort estimate (days) per impact level for an average-sized org
_EFFORT_BY_IMPACT: Dict[str, float] = {
    "high": 30.0,
    "medium": 10.0,
    "low": 3.0,
}


# ============================================================================
# REGULATORY TRACKER
# ============================================================================


class RegulatoryTracker:
    """
    SQLite-backed tracker for regulatory changes and their organisational impact.

    Provides:
    - CRUD for regulations
    - Impact assessment per regulation × organisation
    - Upcoming / active regulation queries
    - Action plan generation
    - Timeline and statistics views
    """

    def __init__(self, db_path: str = ":memory:", org_id: str = "default") -> None:
        self.db_path = db_path
        self.org_id = org_id
        self._lock = threading.RLock()
        # For in-memory SQLite, keep a single persistent connection so all
        # operations share the same database (new connections create empty DBs).
        if db_path == ":memory:":
            self._mem_conn: Optional[sqlite3.Connection] = sqlite3.connect(
                ":memory:", check_same_thread=False
            )
        else:
            self._mem_conn = None
        self._init_db()
        self._seed_builtins()

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        """Return a database connection.

        For in-memory databases, returns the single shared connection so all
        operations see the same schema and data.  For file-backed databases,
        opens a new connection per call (safe for multi-thread use with RLock).
        """
        if self._mem_conn is not None:
            return self._mem_conn
        return sqlite3.connect(self.db_path)

    def _close(self, conn: sqlite3.Connection) -> None:
        """Close connection only if it is NOT the shared in-memory connection."""
        if conn is not self._mem_conn:
            conn.close()

    def _init_db(self) -> None:
        """Create SQLite schema."""
        with self._lock:
            conn = self._connect()
            try:
                cursor = conn.cursor()

                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS regulations (
                        id TEXT PRIMARY KEY,
                        org_id TEXT NOT NULL,
                        framework TEXT NOT NULL,
                        title TEXT NOT NULL,
                        description TEXT DEFAULT '',
                        effective_date TEXT NOT NULL,
                        impact TEXT NOT NULL,
                        affected_controls TEXT DEFAULT '[]',
                        status TEXT DEFAULT 'upcoming',
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )

                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS regulatory_impacts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        regulation_id TEXT NOT NULL,
                        org_id TEXT NOT NULL,
                        gap_count INTEGER DEFAULT 0,
                        controls_affected TEXT DEFAULT '[]',
                        remediation_needed INTEGER DEFAULT 0,
                        estimated_effort_days REAL DEFAULT 0.0,
                        assessed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(regulation_id, org_id)
                    )
                    """
                )

                cursor.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_reg_org_status
                    ON regulations (org_id, status, effective_date)
                    """
                )

                cursor.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_impact_org
                    ON regulatory_impacts (org_id)
                    """
                )

                conn.commit()
            finally:
                self._close(conn)

    def _seed_builtins(self) -> None:
        """Insert built-in regulations if they don't already exist (keyed by title)."""
        with self._lock:
            conn = self._connect()
            try:
                cursor = conn.cursor()
                for reg_data in _BUILTIN_REGULATIONS:
                    cursor.execute(
                        "SELECT id FROM regulations WHERE title = ? AND org_id = ?",
                        (reg_data["title"], self.org_id),
                    )
                    if cursor.fetchone() is None:
                        reg_id = str(uuid.uuid4())
                        cursor.execute(
                            """
                            INSERT INTO regulations
                            (id, org_id, framework, title, description,
                             effective_date, impact, affected_controls, status)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                reg_id,
                                self.org_id,
                                reg_data["framework"],
                                reg_data["title"],
                                reg_data["description"],
                                reg_data["effective_date"],
                                reg_data["impact"],
                                json.dumps(reg_data["affected_controls"]),
                                reg_data["status"],
                            ),
                        )
                conn.commit()
            finally:
                self._close(conn)

    # ------------------------------------------------------------------
    # Core CRUD
    # ------------------------------------------------------------------

    def add_regulation(self, regulation: Regulation) -> str:
        """
        Persist a new regulatory change.

        Args:
            regulation: Validated Regulation model.

        Returns:
            The regulation's ID.
        """
        with self._lock:
            conn = self._connect()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO regulations
                    (id, org_id, framework, title, description,
                     effective_date, impact, affected_controls, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        regulation.id,
                        regulation.org_id,
                        regulation.framework,
                        regulation.title,
                        regulation.description,
                        regulation.effective_date,
                        regulation.impact,
                        json.dumps(regulation.affected_controls),
                        regulation.status,
                    ),
                )
                conn.commit()
                _logger.info("Added regulation %s (%s)", regulation.id, regulation.title)
                return regulation.id
            finally:
                self._close(conn)

    # ------------------------------------------------------------------
    # Impact assessment
    # ------------------------------------------------------------------

    def assess_impact(self, regulation_id: str, org_id: str) -> RegulatoryImpact:
        """
        Analyse the impact of a regulation on the organisation.

        Calculates gap count from affected_controls length, determines effort
        estimate based on impact level, and persists the result.

        Args:
            regulation_id: ID of the regulation to assess.
            org_id: Organisation ID.

        Returns:
            RegulatoryImpact with gap count, controls, and effort estimate.

        Raises:
            ValueError: If regulation_id does not exist for this org.
        """
        reg = self._get_regulation_row(regulation_id, org_id)
        if reg is None:
            raise ValueError(f"Regulation {regulation_id!r} not found for org {org_id!r}")

        controls: List[str] = []
        try:
            controls = json.loads(reg["affected_controls"] or "[]")
        except (json.JSONDecodeError, TypeError):
            controls = []

        gap_count = len(controls)
        remediation_needed = gap_count > 0
        effort_days = _EFFORT_BY_IMPACT.get(reg["impact"].lower(), 5.0)

        impact = RegulatoryImpact(
            regulation_id=regulation_id,
            gap_count=gap_count,
            controls_affected=controls,
            remediation_needed=remediation_needed,
            estimated_effort_days=effort_days,
        )

        # Persist
        with self._lock:
            conn = self._connect()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO regulatory_impacts
                    (regulation_id, org_id, gap_count, controls_affected,
                     remediation_needed, estimated_effort_days, assessed_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        regulation_id,
                        org_id,
                        gap_count,
                        json.dumps(controls),
                        int(remediation_needed),
                        effort_days,
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
                conn.commit()
            finally:
                self._close(conn)

        return impact

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def get_upcoming(self, org_id: str) -> List[Regulation]:
        """Return regulations with status 'upcoming' for the organisation."""
        return self._query_by_status(org_id, "upcoming")

    def get_active(self, org_id: str) -> List[Regulation]:
        """Return currently active/enforced regulations for the organisation."""
        return self._query_by_status(org_id, "active")

    def get_impact_summary(self, org_id: str) -> Dict[str, Any]:
        """
        Aggregate regulatory exposure across all regulations for an org.

        Returns:
            Dict with total_regulations, total_gaps, total_effort_days,
            high_impact_count, frameworks_affected.
        """
        with self._lock:
            conn = self._connect()
            conn.row_factory = sqlite3.Row
            try:
                cursor = conn.cursor()

                # Total regulations for org
                cursor.execute(
                    "SELECT COUNT(*) as cnt FROM regulations WHERE org_id = ?",
                    (org_id,),
                )
                total_regulations = int(cursor.fetchone()["cnt"])

                # Impact aggregation
                cursor.execute(
                    """
                    SELECT
                        COALESCE(SUM(gap_count), 0) AS total_gaps,
                        COALESCE(SUM(estimated_effort_days), 0.0) AS total_effort
                    FROM regulatory_impacts
                    WHERE org_id = ?
                    """,
                    (org_id,),
                )
                row = cursor.fetchone()
                total_gaps = int(row["total_gaps"])
                total_effort_days = float(row["total_effort"])

                # High-impact regulation count
                cursor.execute(
                    "SELECT COUNT(*) as cnt FROM regulations WHERE org_id = ? AND impact = 'high'",
                    (org_id,),
                )
                high_impact_count = int(cursor.fetchone()["cnt"])

                # Distinct frameworks
                cursor.execute(
                    "SELECT DISTINCT framework FROM regulations WHERE org_id = ?",
                    (org_id,),
                )
                frameworks_affected = [r["framework"] for r in cursor.fetchall()]

            finally:
                self._close(conn)

        return {
            "org_id": org_id,
            "total_regulations": total_regulations,
            "total_gaps": total_gaps,
            "total_effort_days": total_effort_days,
            "high_impact_count": high_impact_count,
            "frameworks_affected": frameworks_affected,
        }

    def generate_action_plan(self, regulation_id: str) -> Dict[str, Any]:
        """
        Generate compliance action steps for a regulation.

        Returns a structured action plan with prioritised steps,
        responsible parties, and time estimates.

        Args:
            regulation_id: ID of the regulation.

        Returns:
            Dict with regulation metadata and ordered action steps.

        Raises:
            ValueError: If regulation not found.
        """
        reg = self._get_regulation_row(regulation_id, self.org_id)
        if reg is None:
            raise ValueError(f"Regulation {regulation_id!r} not found")

        controls: List[str] = []
        try:
            controls = json.loads(reg["affected_controls"] or "[]")
        except (json.JSONDecodeError, TypeError):
            controls = []

        impact = reg["impact"].lower()
        effort_days = _EFFORT_BY_IMPACT.get(impact, 5.0)

        # Build action steps
        steps: List[Dict[str, Any]] = [
            {
                "step": 1,
                "action": f"Conduct gap assessment against {reg['framework']} requirements",
                "owner": "Compliance Team",
                "effort_days": round(effort_days * 0.1, 1),
                "priority": "immediate",
            },
            {
                "step": 2,
                "action": f"Map affected controls ({', '.join(controls[:3])}{'...' if len(controls) > 3 else ''}) to current control inventory",
                "owner": "Security Architecture",
                "effort_days": round(effort_days * 0.15, 1),
                "priority": "immediate",
            },
            {
                "step": 3,
                "action": "Assign remediation owners and establish tracking milestones",
                "owner": "CISO / Risk Committee",
                "effort_days": round(effort_days * 0.05, 1),
                "priority": "high",
            },
            {
                "step": 4,
                "action": "Implement technical controls and process changes",
                "owner": "Engineering + Compliance",
                "effort_days": round(effort_days * 0.5, 1),
                "priority": "high",
            },
            {
                "step": 5,
                "action": "Conduct internal audit and evidence collection",
                "owner": "Internal Audit",
                "effort_days": round(effort_days * 0.1, 1),
                "priority": "medium",
            },
            {
                "step": 6,
                "action": f"Validate compliance posture before {reg['effective_date']} effective date",
                "owner": "CISO",
                "effort_days": round(effort_days * 0.1, 1),
                "priority": "medium",
            },
        ]

        return {
            "regulation_id": regulation_id,
            "framework": reg["framework"],
            "title": reg["title"],
            "effective_date": reg["effective_date"],
            "impact": reg["impact"],
            "total_effort_days": effort_days,
            "action_steps": steps,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def get_regulatory_timeline(self, org_id: str) -> List[Dict[str, Any]]:
        """
        Chronological view of all regulations for an organisation.

        Returns:
            List of regulation dicts ordered by effective_date ascending.
        """
        with self._lock:
            conn = self._connect()
            conn.row_factory = sqlite3.Row
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT id, framework, title, effective_date, impact, status
                    FROM regulations
                    WHERE org_id = ?
                    ORDER BY effective_date ASC
                    """,
                    (org_id,),
                )
                rows = cursor.fetchall()
                return [dict(r) for r in rows]
            finally:
                self._close(conn)

    def get_tracker_stats(self, org_id: str) -> Dict[str, Any]:
        """
        Statistics grouped by framework and impact level.

        Returns:
            Dict with by_framework (count per framework) and
            by_impact (count per impact level).
        """
        with self._lock:
            conn = self._connect()
            conn.row_factory = sqlite3.Row
            try:
                cursor = conn.cursor()

                cursor.execute(
                    """
                    SELECT framework, COUNT(*) as cnt
                    FROM regulations
                    WHERE org_id = ?
                    GROUP BY framework
                    ORDER BY cnt DESC
                    """,
                    (org_id,),
                )
                by_framework = {r["framework"]: int(r["cnt"]) for r in cursor.fetchall()}

                cursor.execute(
                    """
                    SELECT impact, COUNT(*) as cnt
                    FROM regulations
                    WHERE org_id = ?
                    GROUP BY impact
                    """,
                    (org_id,),
                )
                by_impact = {r["impact"]: int(r["cnt"]) for r in cursor.fetchall()}

                cursor.execute(
                    """
                    SELECT status, COUNT(*) as cnt
                    FROM regulations
                    WHERE org_id = ?
                    GROUP BY status
                    """,
                    (org_id,),
                )
                by_status = {r["status"]: int(r["cnt"]) for r in cursor.fetchall()}

            finally:
                self._close(conn)

        return {
            "org_id": org_id,
            "by_framework": by_framework,
            "by_impact": by_impact,
            "by_status": by_status,
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _query_by_status(self, org_id: str, status: str) -> List[Regulation]:
        """Return Regulation objects filtered by status."""
        with self._lock:
            conn = self._connect()
            conn.row_factory = sqlite3.Row
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT id, org_id, framework, title, description,
                           effective_date, impact, affected_controls, status
                    FROM regulations
                    WHERE org_id = ? AND status = ?
                    ORDER BY effective_date ASC
                    """,
                    (org_id, status),
                )
                rows = cursor.fetchall()
                result: List[Regulation] = []
                for row in rows:
                    controls: List[str] = []
                    try:
                        controls = json.loads(row["affected_controls"] or "[]")
                    except (json.JSONDecodeError, TypeError):
                        controls = []
                    result.append(
                        Regulation(
                            id=row["id"],
                            org_id=row["org_id"],
                            framework=row["framework"],
                            title=row["title"],
                            description=row["description"] or "",
                            effective_date=row["effective_date"],
                            impact=row["impact"],
                            affected_controls=controls,
                            status=row["status"],
                        )
                    )
                return result
            finally:
                self._close(conn)

    def _get_regulation_row(
        self, regulation_id: str, org_id: str
    ) -> Optional[Dict[str, Any]]:
        """Fetch a single regulation row by ID and org_id as a plain dict."""
        with self._lock:
            conn = self._connect()
            conn.row_factory = sqlite3.Row
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT id, org_id, framework, title, description,
                           effective_date, impact, affected_controls, status
                    FROM regulations
                    WHERE id = ? AND org_id = ?
                    """,
                    (regulation_id, org_id),
                )
                row = cursor.fetchone()
                return dict(row) if row is not None else None
            finally:
                self._close(conn)
