"""Security Capacity Planning Engine — ALDECI. SQLite WAL + RLock + org_id isolation.

Manages security team capacity: headcount, workload, skills gap analysis.
  - Resource registration with skills/certifications (JSON)
  - Utilization tracking (clamped 0-100)
  - Demand management with gap_fte computation
  - Resource assignment with fulfilled/partially_fulfilled status
  - Capacity snapshots for trend analysis
  - Summary, skill gap, and team breakdown analytics

Compliance: NIST NICE Framework, CISA Workforce Development
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "security_capacity_planning_engine.db"
)

_VALID_ROLES = {
    "analyst", "engineer", "architect", "manager", "director", "consultant", "researcher",
}
_VALID_DOMAINS = {
    "detection", "response", "compliance", "risk", "application_security",
    "cloud_security", "identity",
}
_VALID_PRIORITIES = {"critical", "high", "medium", "low"}
_VALID_TIMELINES = {"immediate", "q1", "q2", "q3", "q4", "next_year"}
_VALID_STATUSES = {"open", "partially_fulfilled", "fulfilled", "cancelled"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _today_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


class SecurityCapacityPlanningEngine:
    """SQLite WAL-backed Security Capacity Planning engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/security_capacity_planning_engine.db
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
                CREATE TABLE IF NOT EXISTS capacity_resources (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    resource_name    TEXT NOT NULL DEFAULT '',
                    role             TEXT NOT NULL DEFAULT 'analyst',
                    team             TEXT NOT NULL DEFAULT '',
                    fte              REAL NOT NULL DEFAULT 1.0,
                    utilization_pct  REAL NOT NULL DEFAULT 0.0,
                    skills           TEXT NOT NULL DEFAULT '[]',
                    certifications   TEXT NOT NULL DEFAULT '[]',
                    cost_per_year    REAL NOT NULL DEFAULT 0.0,
                    status           TEXT NOT NULL DEFAULT 'active',
                    created_at       TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_cap_res_org
                    ON capacity_resources (org_id, status, team);

                CREATE TABLE IF NOT EXISTS capacity_demands (
                    id                   TEXT PRIMARY KEY,
                    org_id               TEXT NOT NULL,
                    demand_name          TEXT NOT NULL DEFAULT '',
                    domain               TEXT NOT NULL DEFAULT 'detection',
                    priority             TEXT NOT NULL DEFAULT 'medium',
                    required_fte         REAL NOT NULL DEFAULT 1.0,
                    required_skills      TEXT NOT NULL DEFAULT '[]',
                    timeline             TEXT NOT NULL DEFAULT 'q1',
                    status               TEXT NOT NULL DEFAULT 'open',
                    assigned_resource_id TEXT NOT NULL DEFAULT '',
                    gap_fte              REAL NOT NULL DEFAULT 0.0,
                    created_at           TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_cap_dem_org
                    ON capacity_demands (org_id, status, priority);

                CREATE TABLE IF NOT EXISTS capacity_snapshots (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    snapshot_date    TEXT NOT NULL,
                    total_fte        REAL NOT NULL DEFAULT 0.0,
                    utilized_fte     REAL NOT NULL DEFAULT 0.0,
                    demand_fte       REAL NOT NULL DEFAULT 0.0,
                    gap_fte          REAL NOT NULL DEFAULT 0.0,
                    utilization_rate REAL NOT NULL DEFAULT 0.0,
                    skill_gaps       TEXT NOT NULL DEFAULT '[]',
                    created_at       TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_cap_snap_org
                    ON capacity_snapshots (org_id, snapshot_date);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Resource management
    # ------------------------------------------------------------------

    def register_resource(
        self,
        org_id: str,
        resource_name: str,
        role: str = "analyst",
        team: str = "",
        fte: float = 1.0,
        skills: Optional[List[str]] = None,
        certifications: Optional[List[str]] = None,
        cost_per_year: float = 0.0,
    ) -> Dict[str, Any]:
        """Register a new security team resource."""
        if role not in _VALID_ROLES:
            raise ValueError(f"Invalid role: {role}. Must be one of {_VALID_ROLES}")

        resource_id = str(uuid.uuid4())
        now = _now_iso()
        skills_json = json.dumps(skills or [])
        certs_json = json.dumps(certifications or [])
        fte = max(0.0, float(fte))

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO capacity_resources
                        (id, org_id, resource_name, role, team, fte, utilization_pct,
                         skills, certifications, cost_per_year, status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, 0.0, ?, ?, ?, 'active', ?)
                    """,
                    (resource_id, org_id, resource_name, role, team, fte,
                     skills_json, certs_json, cost_per_year, now),
                )
        return self._get_resource_by_id(resource_id, org_id)

    def _get_resource_by_id(self, resource_id: str, org_id: str) -> Dict[str, Any]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM capacity_resources WHERE id=? AND org_id=?",
                (resource_id, org_id),
            ).fetchone()
        if not row:
            raise ValueError(f"Resource {resource_id} not found")
        return self._row_to_resource(row)

    def _row_to_resource(self, row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        d["skills"] = json.loads(d.get("skills", "[]"))
        d["certifications"] = json.loads(d.get("certifications", "[]"))
        return d

    def update_utilization(
        self, resource_id: str, org_id: str, utilization_pct: float
    ) -> Dict[str, Any]:
        """Update utilization percentage for a resource (clamped 0-100)."""
        utilization_pct = max(0.0, min(100.0, float(utilization_pct)))
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    """
                    UPDATE capacity_resources
                       SET utilization_pct=?
                     WHERE id=? AND org_id=?
                    """,
                    (utilization_pct, resource_id, org_id),
                )
                if cur.rowcount == 0:
                    raise ValueError(f"Resource {resource_id} not found for org {org_id}")
        return self._get_resource_by_id(resource_id, org_id)

    # ------------------------------------------------------------------
    # Demand management
    # ------------------------------------------------------------------

    def _compute_gap_fte(
        self, org_id: str, required_fte: float, required_skills: List[str], conn: sqlite3.Connection
    ) -> float:
        """Compute gap_fte: required_fte minus FTE of matching unassigned active resources."""
        if not required_skills:
            # No skill requirement — any active unassigned resource qualifies
            rows = conn.execute(
                """
                SELECT COALESCE(SUM(fte), 0.0) AS total_fte
                  FROM capacity_resources
                 WHERE org_id=? AND status='active'
                   AND id NOT IN (
                       SELECT assigned_resource_id FROM capacity_demands
                        WHERE org_id=? AND assigned_resource_id!='' AND status!='cancelled'
                   )
                """,
                (org_id, org_id),
            ).fetchone()
            available = rows["total_fte"] if rows else 0.0
            return max(0.0, required_fte - available)

        # Find active unassigned resources with at least one matching skill
        all_resources = conn.execute(
            """
            SELECT id, fte, skills FROM capacity_resources
             WHERE org_id=? AND status='active'
               AND id NOT IN (
                   SELECT assigned_resource_id FROM capacity_demands
                    WHERE org_id=? AND assigned_resource_id!='' AND status!='cancelled'
               )
            """,
            (org_id, org_id),
        ).fetchall()

        matched_fte = 0.0
        required_set = set(required_skills)
        for r in all_resources:
            try:
                resource_skills = set(json.loads(r["skills"]))
            except (json.JSONDecodeError, TypeError):
                resource_skills = set()
            if resource_skills & required_set:  # any overlap
                matched_fte += r["fte"]

        return max(0.0, required_fte - matched_fte) if matched_fte > 0 else float(required_fte)

    def add_demand(
        self,
        org_id: str,
        demand_name: str,
        domain: str = "detection",
        priority: str = "medium",
        required_fte: float = 1.0,
        required_skills: Optional[List[str]] = None,
        timeline: str = "q1",
    ) -> Dict[str, Any]:
        """Add a capacity demand with auto-computed gap_fte."""
        if domain not in _VALID_DOMAINS:
            raise ValueError(f"Invalid domain: {domain}")
        if priority not in _VALID_PRIORITIES:
            raise ValueError(f"Invalid priority: {priority}")
        if timeline not in _VALID_TIMELINES:
            raise ValueError(f"Invalid timeline: {timeline}")

        demand_id = str(uuid.uuid4())
        now = _now_iso()
        required_skills = required_skills or []
        skills_json = json.dumps(required_skills)
        required_fte = max(0.0, float(required_fte))

        with self._lock:
            with self._conn() as conn:
                gap_fte = self._compute_gap_fte(org_id, required_fte, required_skills, conn)
                conn.execute(
                    """
                    INSERT INTO capacity_demands
                        (id, org_id, demand_name, domain, priority, required_fte,
                         required_skills, timeline, status, assigned_resource_id,
                         gap_fte, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', '', ?, ?)
                    """,
                    (demand_id, org_id, demand_name, domain, priority, required_fte,
                     skills_json, timeline, gap_fte, now),
                )
        return self._get_demand_by_id(demand_id, org_id)

    def _get_demand_by_id(self, demand_id: str, org_id: str) -> Dict[str, Any]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM capacity_demands WHERE id=? AND org_id=?",
                (demand_id, org_id),
            ).fetchone()
        if not row:
            raise ValueError(f"Demand {demand_id} not found")
        return self._row_to_demand(row)

    def _row_to_demand(self, row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        d["required_skills"] = json.loads(d.get("required_skills", "[]"))
        return d

    def assign_resource(
        self, demand_id: str, org_id: str, resource_id: str
    ) -> Dict[str, Any]:
        """Assign a resource to a demand and recompute gap_fte and status."""
        with self._lock:
            with self._conn() as conn:
                # Fetch demand
                demand_row = conn.execute(
                    "SELECT * FROM capacity_demands WHERE id=? AND org_id=?",
                    (demand_id, org_id),
                ).fetchone()
                if not demand_row:
                    raise ValueError(f"Demand {demand_id} not found for org {org_id}")

                # Fetch resource
                res_row = conn.execute(
                    "SELECT * FROM capacity_resources WHERE id=? AND org_id=?",
                    (resource_id, org_id),
                ).fetchone()
                if not res_row:
                    raise ValueError(f"Resource {resource_id} not found for org {org_id}")

                required_fte = float(demand_row["required_fte"])
                resource_fte = float(res_row["fte"])
                gap_fte = max(0.0, required_fte - resource_fte)
                status = "fulfilled" if gap_fte == 0.0 else "partially_fulfilled"

                conn.execute(
                    """
                    UPDATE capacity_demands
                       SET assigned_resource_id=?, gap_fte=?, status=?
                     WHERE id=? AND org_id=?
                    """,
                    (resource_id, gap_fte, status, demand_id, org_id),
                )
        return self._get_demand_by_id(demand_id, org_id)

    # ------------------------------------------------------------------
    # Snapshots
    # ------------------------------------------------------------------

    def take_snapshot(self, org_id: str) -> Dict[str, Any]:
        """Take a capacity snapshot for the current date."""
        snapshot_id = str(uuid.uuid4())
        now = _now_iso()
        today = _today_str()

        with self._lock:
            with self._conn() as conn:
                # total_fte: SUM of active resources
                res = conn.execute(
                    "SELECT COALESCE(SUM(fte), 0.0) AS t FROM capacity_resources WHERE org_id=? AND status='active'",
                    (org_id,),
                ).fetchone()
                total_fte = float(res["t"])

                # utilized_fte: SUM(fte * utilization_pct / 100)
                res2 = conn.execute(
                    "SELECT COALESCE(SUM(fte * utilization_pct / 100.0), 0.0) AS u FROM capacity_resources WHERE org_id=? AND status='active'",
                    (org_id,),
                ).fetchone()
                utilized_fte = float(res2["u"])

                # demand_fte: SUM of required_fte of open demands
                res3 = conn.execute(
                    "SELECT COALESCE(SUM(required_fte), 0.0) AS d FROM capacity_demands WHERE org_id=? AND status='open'",
                    (org_id,),
                ).fetchone()
                demand_fte = float(res3["d"])

                # gap_fte: SUM of gap_fte of open demands
                res4 = conn.execute(
                    "SELECT COALESCE(SUM(gap_fte), 0.0) AS g FROM capacity_demands WHERE org_id=? AND status='open'",
                    (org_id,),
                ).fetchone()
                gap_fte = float(res4["g"])

                utilization_rate = (utilized_fte / total_fte * 100.0) if total_fte > 0 else 0.0

                # skill_gaps: required_skills from open/unmet demands (gap_fte > 0)
                unmet = conn.execute(
                    "SELECT required_skills FROM capacity_demands WHERE org_id=? AND status='open' AND gap_fte > 0",
                    (org_id,),
                ).fetchall()
                skill_gaps: List[str] = []
                seen: set = set()
                for row in unmet:
                    try:
                        skills = json.loads(row["required_skills"])
                        for s in skills:
                            if s not in seen:
                                seen.add(s)
                                skill_gaps.append(s)
                    except (json.JSONDecodeError, TypeError):
                        pass

                skill_gaps_json = json.dumps(skill_gaps)

                conn.execute(
                    """
                    INSERT INTO capacity_snapshots
                        (id, org_id, snapshot_date, total_fte, utilized_fte,
                         demand_fte, gap_fte, utilization_rate, skill_gaps, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (snapshot_id, org_id, today, total_fte, utilized_fte,
                     demand_fte, gap_fte, utilization_rate, skill_gaps_json, now),
                )

        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM capacity_snapshots WHERE id=? AND org_id=?",
                (snapshot_id, org_id),
            ).fetchone()
        d = dict(row)
        d["skill_gaps"] = json.loads(d.get("skill_gaps", "[]"))
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "security_capacity_planning", "org_id": org_id, "source_engine": "security_capacity_planning"})
            except Exception:
                pass

        return d

    # ------------------------------------------------------------------
    # Analytics
    # ------------------------------------------------------------------

    def get_capacity_summary(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated capacity summary for the org."""
        with self._conn() as conn:
            res_stats = conn.execute(
                """
                SELECT
                    COUNT(*) AS total_resources,
                    COALESCE(SUM(fte), 0.0) AS total_fte,
                    COALESCE(AVG(utilization_pct), 0.0) AS avg_utilization,
                    COALESCE(SUM(CASE WHEN utilization_pct > 90 THEN 1 ELSE 0 END), 0) AS over_utilized
                FROM capacity_resources
                WHERE org_id=? AND status='active'
                """,
                (org_id,),
            ).fetchone()

            dem_stats = conn.execute(
                """
                SELECT
                    COUNT(*) AS open_demands,
                    COALESCE(SUM(required_fte), 0.0) AS total_demand_fte,
                    COALESCE(SUM(gap_fte), 0.0) AS total_gap_fte
                FROM capacity_demands
                WHERE org_id=? AND status='open'
                """,
                (org_id,),
            ).fetchone()

        return {
            "org_id": org_id,
            "total_resources": res_stats["total_resources"],
            "total_fte": round(float(res_stats["total_fte"]), 2),
            "avg_utilization": round(float(res_stats["avg_utilization"]), 2),
            "over_utilized": res_stats["over_utilized"],
            "open_demands": dem_stats["open_demands"],
            "total_demand_fte": round(float(dem_stats["total_demand_fte"]), 2),
            "total_gap_fte": round(float(dem_stats["total_gap_fte"]), 2),
        }

    def get_skill_gap_analysis(self, org_id: str) -> List[Dict[str, Any]]:
        """Return open demands with no assigned resource, showing skill gaps."""
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM capacity_demands
                 WHERE org_id=? AND status='open' AND assigned_resource_id=''
                 ORDER BY priority, created_at
                """,
                (org_id,),
            ).fetchall()
        result = []
        for row in rows:
            d = self._row_to_demand(row)
            result.append(d)
        return result

    def get_team_breakdown(self, org_id: str) -> List[Dict[str, Any]]:
        """Return per-team resource count, total FTE, and avg utilization."""
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT
                    team,
                    COUNT(*) AS resource_count,
                    COALESCE(SUM(fte), 0.0) AS total_fte,
                    COALESCE(AVG(utilization_pct), 0.0) AS avg_utilization
                FROM capacity_resources
                WHERE org_id=? AND status='active'
                GROUP BY team
                ORDER BY team
                """,
                (org_id,),
            ).fetchall()
        return [
            {
                "team": row["team"],
                "resource_count": row["resource_count"],
                "total_fte": round(float(row["total_fte"]), 2),
                "avg_utilization": round(float(row["avg_utilization"]), 2),
            }
            for row in rows
        ]
