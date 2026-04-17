"""Risk Scenario Engine — ALDECI. SQLite WAL + RLock + org_id isolation.

Models risk scenarios for threat/risk scenario analysis and what-if planning:
  - Define threats with likelihood/impact to compute inherent_risk
  - Add mitigations with effectiveness to reduce residual_risk
  - Review scenarios to adjust parameters over time
  - Top-risk ranking and risk reduction summaries

Compliance: ISO 31000, NIST RMF, FAIR model
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "risk_scenario_engine.db"
)

_VALID_THREAT_CATEGORIES = {
    "ransomware", "data-breach", "insider-threat", "supply-chain",
    "ddos", "phishing", "zero-day", "compliance",
}
_VALID_MITIGATION_TYPES = {
    "technical", "administrative", "physical", "detective", "preventive", "corrective",
}
_VALID_STATUSES = {
    "active", "monitoring", "mitigated", "accepted", "transferred", "closed",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _compute_risk_level(risk_score: float) -> str:
    if risk_score >= 70:
        return "critical"
    if risk_score >= 40:
        return "high"
    if risk_score >= 20:
        return "medium"
    return "low"


def _clamp(value: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, value))


class RiskScenarioEngine:
    """SQLite WAL-backed Risk Scenario engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/risk_scenario_engine.db
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
                CREATE TABLE IF NOT EXISTS risk_scenarios (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    scenario_name   TEXT NOT NULL DEFAULT '',
                    threat_category TEXT NOT NULL DEFAULT 'ransomware',
                    description     TEXT NOT NULL DEFAULT '',
                    likelihood      REAL NOT NULL DEFAULT 5.0,
                    impact          REAL NOT NULL DEFAULT 5.0,
                    inherent_risk   REAL NOT NULL DEFAULT 0.0,
                    residual_risk   REAL NOT NULL DEFAULT 0.0,
                    risk_level      TEXT NOT NULL DEFAULT 'low',
                    status          TEXT NOT NULL DEFAULT 'active',
                    owner           TEXT NOT NULL DEFAULT '',
                    created_at      TEXT,
                    reviewed_at     TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_rs_scenarios_org
                    ON risk_scenarios (org_id, risk_level, threat_category, status);

                CREATE TABLE IF NOT EXISTS scenario_mitigations (
                    id              TEXT PRIMARY KEY,
                    scenario_id     TEXT NOT NULL,
                    org_id          TEXT NOT NULL,
                    mitigation_name TEXT NOT NULL DEFAULT '',
                    mitigation_type TEXT NOT NULL DEFAULT 'technical',
                    effectiveness   REAL NOT NULL DEFAULT 0.0,
                    implemented     INTEGER NOT NULL DEFAULT 0,
                    cost_estimate   REAL NOT NULL DEFAULT 0.0,
                    created_at      TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_rs_mitigations_scenario
                    ON scenario_mitigations (scenario_id, org_id);

                CREATE TABLE IF NOT EXISTS scenario_reviews (
                    id                    TEXT PRIMARY KEY,
                    scenario_id           TEXT NOT NULL,
                    org_id                TEXT NOT NULL,
                    reviewer              TEXT NOT NULL DEFAULT '',
                    likelihood_adjustment REAL NOT NULL DEFAULT 0.0,
                    impact_adjustment     REAL NOT NULL DEFAULT 0.0,
                    notes                 TEXT NOT NULL DEFAULT '',
                    reviewed_at           TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_rs_reviews_scenario
                    ON scenario_reviews (scenario_id, org_id);
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
    # Internal helpers
    # ------------------------------------------------------------------

    def _recompute_residual_risk(self, conn: sqlite3.Connection, scenario_id: str, inherent_risk: float) -> float:
        """Compute residual risk from implemented mitigations (capped at 0.9 total effectiveness)."""
        rows = conn.execute(
            "SELECT effectiveness FROM scenario_mitigations WHERE scenario_id = ? AND implemented = 1",
            (scenario_id,),
        ).fetchall()
        total_eff = sum(float(r["effectiveness"]) for r in rows)
        total_eff = _clamp(total_eff, 0.0, 0.9)
        return round(inherent_risk * (1.0 - total_eff), 4)

    def _update_scenario_risk(
        self, conn: sqlite3.Connection, scenario_id: str, org_id: str
    ) -> None:
        """Recompute and persist residual_risk + risk_level for a scenario."""
        row = conn.execute(
            "SELECT inherent_risk FROM risk_scenarios WHERE id = ? AND org_id = ?",
            (scenario_id, org_id),
        ).fetchone()
        if not row:
            return
        inherent_risk = float(row["inherent_risk"])
        residual_risk = self._recompute_residual_risk(conn, scenario_id, inherent_risk)
        risk_level = _compute_risk_level(residual_risk)
        conn.execute(
            "UPDATE risk_scenarios SET residual_risk = ?, risk_level = ? WHERE id = ? AND org_id = ?",
            (residual_risk, risk_level, scenario_id, org_id),
        )

    # ------------------------------------------------------------------
    # Scenarios
    # ------------------------------------------------------------------

    def create_scenario(
        self,
        org_id: str,
        scenario_name: str,
        threat_category: str,
        description: str,
        likelihood: float,
        impact: float,
        owner: str = "",
    ) -> Dict[str, Any]:
        """Create a risk scenario with auto-computed inherent and residual risk."""
        if threat_category not in _VALID_THREAT_CATEGORIES:
            raise ValueError(
                f"Invalid threat_category '{threat_category}'. "
                f"Must be one of {sorted(_VALID_THREAT_CATEGORIES)}"
            )
        likelihood = _clamp(float(likelihood), 0.0, 10.0)
        impact = _clamp(float(impact), 0.0, 10.0)
        inherent_risk = round(likelihood * impact, 4)
        residual_risk = inherent_risk  # no mitigations yet
        risk_level = _compute_risk_level(inherent_risk)
        now = _now_iso()

        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "scenario_name": scenario_name,
            "threat_category": threat_category,
            "description": description,
            "likelihood": likelihood,
            "impact": impact,
            "inherent_risk": inherent_risk,
            "residual_risk": residual_risk,
            "risk_level": risk_level,
            "status": "active",
            "owner": owner,
            "created_at": now,
            "reviewed_at": None,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO risk_scenarios
                       (id, org_id, scenario_name, threat_category, description,
                        likelihood, impact, inherent_risk, residual_risk,
                        risk_level, status, owner, created_at, reviewed_at)
                       VALUES (:id, :org_id, :scenario_name, :threat_category, :description,
                               :likelihood, :impact, :inherent_risk, :residual_risk,
                               :risk_level, :status, :owner, :created_at, :reviewed_at)""",
                    record,
                )
        return record

    def add_mitigation(
        self,
        scenario_id: str,
        org_id: str,
        mitigation_name: str,
        mitigation_type: str = "technical",
        effectiveness: float = 0.5,
        cost_estimate: float = 0.0,
    ) -> Dict[str, Any]:
        """Add a mitigation to a scenario; recomputes residual_risk."""
        if mitigation_type not in _VALID_MITIGATION_TYPES:
            raise ValueError(
                f"Invalid mitigation_type '{mitigation_type}'. "
                f"Must be one of {sorted(_VALID_MITIGATION_TYPES)}"
            )
        effectiveness = _clamp(float(effectiveness), 0.0, 1.0)
        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "scenario_id": scenario_id,
            "org_id": org_id,
            "mitigation_name": mitigation_name,
            "mitigation_type": mitigation_type,
            "effectiveness": effectiveness,
            "implemented": 0,
            "cost_estimate": float(cost_estimate),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO scenario_mitigations
                       (id, scenario_id, org_id, mitigation_name, mitigation_type,
                        effectiveness, implemented, cost_estimate, created_at)
                       VALUES (:id, :scenario_id, :org_id, :mitigation_name, :mitigation_type,
                               :effectiveness, :implemented, :cost_estimate, :created_at)""",
                    record,
                )
                # Recompute (mitigation not yet implemented — no change in residual)
                self._update_scenario_risk(conn, scenario_id, org_id)
        return record

    def implement_mitigation(
        self, mitigation_id: str, scenario_id: str, org_id: str
    ) -> Optional[Dict[str, Any]]:
        """Mark a mitigation as implemented; recomputes residual_risk and risk_level."""
        with self._lock:
            with self._conn() as conn:
                updated = conn.execute(
                    """UPDATE scenario_mitigations SET implemented = 1
                       WHERE id = ? AND scenario_id = ? AND org_id = ?""",
                    (mitigation_id, scenario_id, org_id),
                ).rowcount
                if updated == 0:
                    return None
                self._update_scenario_risk(conn, scenario_id, org_id)
                row = conn.execute(
                    "SELECT * FROM scenario_mitigations WHERE id = ?",
                    (mitigation_id,),
                ).fetchone()
        return self._row(row) if row else None

    def review_scenario(
        self,
        scenario_id: str,
        org_id: str,
        reviewer: str,
        likelihood_adjustment: float,
        impact_adjustment: float,
        notes: str = "",
    ) -> Dict[str, Any]:
        """Create a review; adjusts likelihood/impact; recomputes all risk fields."""
        now = _now_iso()
        review: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "scenario_id": scenario_id,
            "org_id": org_id,
            "reviewer": reviewer,
            "likelihood_adjustment": float(likelihood_adjustment),
            "impact_adjustment": float(impact_adjustment),
            "notes": notes,
            "reviewed_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO scenario_reviews
                       (id, scenario_id, org_id, reviewer, likelihood_adjustment,
                        impact_adjustment, notes, reviewed_at)
                       VALUES (:id, :scenario_id, :org_id, :reviewer, :likelihood_adjustment,
                               :impact_adjustment, :notes, :reviewed_at)""",
                    review,
                )
                # Update scenario likelihood + impact
                row = conn.execute(
                    "SELECT likelihood, impact FROM risk_scenarios WHERE id = ? AND org_id = ?",
                    (scenario_id, org_id),
                ).fetchone()
                if row:
                    new_likelihood = _clamp(float(row["likelihood"]) + float(likelihood_adjustment), 0.0, 10.0)
                    new_impact = _clamp(float(row["impact"]) + float(impact_adjustment), 0.0, 10.0)
                    inherent_risk = round(new_likelihood * new_impact, 4)
                    residual_risk = self._recompute_residual_risk(conn, scenario_id, inherent_risk)
                    risk_level = _compute_risk_level(residual_risk)
                    conn.execute(
                        """UPDATE risk_scenarios
                           SET likelihood = ?, impact = ?, inherent_risk = ?,
                               residual_risk = ?, risk_level = ?, reviewed_at = ?
                           WHERE id = ? AND org_id = ?""",
                        (new_likelihood, new_impact, inherent_risk,
                         residual_risk, risk_level, now, scenario_id, org_id),
                    )
        return review

    def get_scenario(self, scenario_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        """Get scenario with its mitigations and reviews."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM risk_scenarios WHERE id = ? AND org_id = ?",
                (scenario_id, org_id),
            ).fetchone()
            if not row:
                return None
            scenario = self._row(row)

            mit_rows = conn.execute(
                "SELECT * FROM scenario_mitigations WHERE scenario_id = ? AND org_id = ?",
                (scenario_id, org_id),
            ).fetchall()
            scenario["mitigations"] = [self._row(m) for m in mit_rows]

            rev_rows = conn.execute(
                "SELECT * FROM scenario_reviews WHERE scenario_id = ? AND org_id = ?",
                (scenario_id, org_id),
            ).fetchall()
            scenario["reviews"] = [self._row(r) for r in rev_rows]
        return scenario

    def list_scenarios(
        self,
        org_id: str,
        risk_level: Optional[str] = None,
        threat_category: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List scenarios for an org with optional filters."""
        sql = "SELECT * FROM risk_scenarios WHERE org_id = ?"
        params: List[Any] = [org_id]
        if risk_level:
            sql += " AND risk_level = ?"
            params.append(risk_level)
        if threat_category:
            sql += " AND threat_category = ?"
            params.append(threat_category)
        sql += " ORDER BY residual_risk DESC, created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_top_risks(self, org_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Return top N scenarios ordered by residual_risk DESC."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM risk_scenarios WHERE org_id = ?
                   ORDER BY residual_risk DESC LIMIT ?""",
                (org_id, limit),
            ).fetchall()
        return [self._row(r) for r in rows]

    def get_risk_reduction_summary(self, org_id: str) -> List[Dict[str, Any]]:
        """Per scenario: inherent_risk, residual_risk, reduction_pct."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT id, scenario_name, inherent_risk, residual_risk FROM risk_scenarios WHERE org_id = ?",
                (org_id,),
            ).fetchall()
        summary = []
        for r in rows:
            inherent = float(r["inherent_risk"])
            residual = float(r["residual_risk"])
            reduction_pct = (
                round((inherent - residual) / inherent * 100.0, 2)
                if inherent > 0
                else 0.0
            )
            summary.append({
                "scenario_id": r["id"],
                "scenario_name": r["scenario_name"],
                "inherent_risk": inherent,
                "residual_risk": residual,
                "reduction_pct": reduction_pct,
            })
        return summary

    def get_scenario_stats(self, org_id: str) -> Dict[str, Any]:
        """Return scenario counts by risk_level, avg risks, mitigation totals."""
        with self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM risk_scenarios WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            level_rows = conn.execute(
                "SELECT risk_level, COUNT(*) as cnt FROM risk_scenarios WHERE org_id = ? GROUP BY risk_level",
                (org_id,),
            ).fetchall()
            by_risk_level = {r["risk_level"]: r["cnt"] for r in level_rows}

            avg_row = conn.execute(
                "SELECT AVG(inherent_risk) as ai, AVG(residual_risk) as ar FROM risk_scenarios WHERE org_id = ?",
                (org_id,),
            ).fetchone()
            avg_inherent = round(float(avg_row["ai"]), 4) if avg_row["ai"] is not None else None
            avg_residual = round(float(avg_row["ar"]), 4) if avg_row["ar"] is not None else None

            total_mitigations = conn.execute(
                """SELECT COUNT(*) FROM scenario_mitigations sm
                   JOIN risk_scenarios rs ON sm.scenario_id = rs.id
                   WHERE rs.org_id = ?""",
                (org_id,),
            ).fetchone()[0]

            implemented_mitigations = conn.execute(
                """SELECT COUNT(*) FROM scenario_mitigations sm
                   JOIN risk_scenarios rs ON sm.scenario_id = rs.id
                   WHERE rs.org_id = ? AND sm.implemented = 1""",
                (org_id,),
            ).fetchone()[0]

        return {
            "total_scenarios": total,
            "by_risk_level": by_risk_level,
            "avg_inherent_risk": avg_inherent,
            "avg_residual_risk": avg_residual,
            "total_mitigations": total_mitigations,
            "implemented_mitigations": implemented_mitigations,
        }
