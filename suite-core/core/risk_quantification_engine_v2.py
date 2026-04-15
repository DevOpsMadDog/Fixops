"""Risk Quantification Engine v2 — ALDECI. SQLite WAL + RLock + org_id isolation.

FAIR methodology: SLE, ARO, ALE calculations with control effectiveness and ROI.

Tables:
  risk_scenarios  — FAIR scenario parameters and computed risk metrics
  risk_controls   — Controls per scenario with ROI computation
  risk_snapshots  — Point-in-time portfolio snapshots
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

_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "risk_quantification_v2.db"
)

_VALID_THREAT_TYPES = {
    "malware", "ransomware", "insider", "ddos", "phishing",
    "supply_chain", "physical", "natural_disaster", "system_failure",
}

_VALID_CONTROL_TYPES = {
    "preventive", "detective", "corrective", "deterrent", "recovery",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _today_iso() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def _clamp(value: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, float(value)))


def _risk_level_from_ale(ale: float) -> str:
    if ale >= 1_000_000:
        return "critical"
    if ale >= 100_000:
        return "high"
    if ale >= 10_000:
        return "medium"
    return "low"


class RiskQuantificationEngineV2:
    """SQLite WAL-backed FAIR risk quantification engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/risk_quantification_v2.db
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
                    id                      TEXT PRIMARY KEY,
                    org_id                  TEXT NOT NULL,
                    scenario_name           TEXT NOT NULL DEFAULT '',
                    asset_name              TEXT NOT NULL DEFAULT '',
                    threat_actor            TEXT NOT NULL DEFAULT '',
                    threat_type             TEXT NOT NULL DEFAULT 'malware',
                    asset_value             REAL NOT NULL DEFAULT 0.0,
                    exposure_factor         REAL NOT NULL DEFAULT 0.5,
                    annual_rate_occurrence  REAL NOT NULL DEFAULT 1.0,
                    single_loss_expectancy  REAL NOT NULL DEFAULT 0.0,
                    annual_loss_expectancy  REAL NOT NULL DEFAULT 0.0,
                    control_effectiveness   REAL NOT NULL DEFAULT 0.0,
                    residual_ale            REAL NOT NULL DEFAULT 0.0,
                    risk_level              TEXT NOT NULL DEFAULT 'medium',
                    created_at              TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_rqv2_scenarios_org
                    ON risk_scenarios (org_id, risk_level, threat_type);

                CREATE TABLE IF NOT EXISTS risk_controls (
                    id                  TEXT PRIMARY KEY,
                    scenario_id         TEXT NOT NULL,
                    org_id              TEXT NOT NULL,
                    control_name        TEXT NOT NULL DEFAULT '',
                    control_type        TEXT NOT NULL DEFAULT 'preventive',
                    implementation_cost REAL NOT NULL DEFAULT 0.0,
                    annual_cost         REAL NOT NULL DEFAULT 0.0,
                    effectiveness_pct   REAL NOT NULL DEFAULT 0.0,
                    roi                 REAL NOT NULL DEFAULT 0.0,
                    recommended         INTEGER NOT NULL DEFAULT 0,
                    created_at          TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_rqv2_controls_scenario
                    ON risk_controls (scenario_id, org_id);

                CREATE TABLE IF NOT EXISTS risk_snapshots (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    snapshot_date       TEXT NOT NULL,
                    total_ale           REAL NOT NULL DEFAULT 0.0,
                    avg_ale             REAL NOT NULL DEFAULT 0.0,
                    critical_scenarios  INTEGER NOT NULL DEFAULT 0,
                    by_threat_type      TEXT NOT NULL DEFAULT '{}',
                    created_at          TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_rqv2_snapshots_org
                    ON risk_snapshots (org_id, snapshot_date);
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

    def _recompute_scenario(self, conn: sqlite3.Connection, scenario_id: str, org_id: str) -> None:
        """Recompute SLE, ALE, control_effectiveness, residual_ale, risk_level in-place."""
        row = conn.execute(
            "SELECT asset_value, exposure_factor, annual_rate_occurrence "
            "FROM risk_scenarios WHERE id = ? AND org_id = ?",
            (scenario_id, org_id),
        ).fetchone()
        if not row:
            return

        asset_value = float(row["asset_value"])
        exposure_factor = float(row["exposure_factor"])
        aro = float(row["annual_rate_occurrence"])

        sle = asset_value * exposure_factor
        ale = sle * aro

        # MAX effectiveness_pct among all controls for this scenario
        ctrl_row = conn.execute(
            "SELECT MAX(effectiveness_pct) as max_eff FROM risk_controls "
            "WHERE scenario_id = ? AND org_id = ?",
            (scenario_id, org_id),
        ).fetchone()
        max_eff = float(ctrl_row["max_eff"]) if ctrl_row["max_eff"] is not None else 0.0
        max_eff = _clamp(max_eff, 0.0, 100.0)

        residual_ale = ale * (1.0 - max_eff / 100.0)
        risk_level = _risk_level_from_ale(ale)

        conn.execute(
            """UPDATE risk_scenarios
               SET single_loss_expectancy = ?, annual_loss_expectancy = ?,
                   control_effectiveness = ?, residual_ale = ?, risk_level = ?
               WHERE id = ? AND org_id = ?""",
            (sle, ale, max_eff, residual_ale, risk_level, scenario_id, org_id),
        )

    # ------------------------------------------------------------------
    # Scenarios
    # ------------------------------------------------------------------

    def create_scenario(
        self,
        org_id: str,
        scenario_name: str,
        asset_name: str,
        threat_actor: str,
        threat_type: str,
        asset_value: float,
        exposure_factor: float,
        annual_rate_occurrence: float,
    ) -> Dict[str, Any]:
        """Create a FAIR risk scenario with computed SLE and ALE."""
        exposure_factor = _clamp(exposure_factor, 0.0, 1.0)
        asset_value = float(asset_value)
        aro = float(annual_rate_occurrence)

        sle = asset_value * exposure_factor
        ale = sle * aro
        risk_level = _risk_level_from_ale(ale)
        now = _now_iso()

        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "scenario_name": scenario_name,
            "asset_name": asset_name,
            "threat_actor": threat_actor,
            "threat_type": threat_type,
            "asset_value": asset_value,
            "exposure_factor": exposure_factor,
            "annual_rate_occurrence": aro,
            "single_loss_expectancy": sle,
            "annual_loss_expectancy": ale,
            "control_effectiveness": 0.0,
            "residual_ale": ale,
            "risk_level": risk_level,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO risk_scenarios
                       (id, org_id, scenario_name, asset_name, threat_actor, threat_type,
                        asset_value, exposure_factor, annual_rate_occurrence,
                        single_loss_expectancy, annual_loss_expectancy,
                        control_effectiveness, residual_ale, risk_level, created_at)
                       VALUES (:id, :org_id, :scenario_name, :asset_name, :threat_actor,
                               :threat_type, :asset_value, :exposure_factor,
                               :annual_rate_occurrence, :single_loss_expectancy,
                               :annual_loss_expectancy, :control_effectiveness,
                               :residual_ale, :risk_level, :created_at)""",
                    record,
                )
        return record

    def add_control(
        self,
        scenario_id: str,
        org_id: str,
        control_name: str,
        control_type: str,
        implementation_cost: float,
        annual_cost: float,
        effectiveness_pct: float,
    ) -> Dict[str, Any]:
        """Add a control to a scenario; compute ROI; recompute scenario metrics."""
        effectiveness_pct = _clamp(effectiveness_pct, 0.0, 100.0)
        implementation_cost = float(implementation_cost)
        annual_cost = float(annual_cost)
        now = _now_iso()

        with self._lock:
            with self._conn() as conn:
                # Need the scenario's ALE for ROI
                sc_row = conn.execute(
                    "SELECT annual_loss_expectancy FROM risk_scenarios WHERE id = ? AND org_id = ?",
                    (scenario_id, org_id),
                ).fetchone()
                if not sc_row:
                    raise ValueError(f"Scenario {scenario_id} not found for org {org_id}")

                ale = float(sc_row["annual_loss_expectancy"])
                risk_reduction = ale * (effectiveness_pct / 100.0)
                denom = max(1.0, implementation_cost)
                roi = (risk_reduction - annual_cost) / denom * 100.0
                recommended = 1 if roi > 0 else 0

                record: Dict[str, Any] = {
                    "id": str(uuid.uuid4()),
                    "scenario_id": scenario_id,
                    "org_id": org_id,
                    "control_name": control_name,
                    "control_type": control_type,
                    "implementation_cost": implementation_cost,
                    "annual_cost": annual_cost,
                    "effectiveness_pct": effectiveness_pct,
                    "roi": roi,
                    "recommended": recommended,
                    "created_at": now,
                }
                conn.execute(
                    """INSERT INTO risk_controls
                       (id, scenario_id, org_id, control_name, control_type,
                        implementation_cost, annual_cost, effectiveness_pct,
                        roi, recommended, created_at)
                       VALUES (:id, :scenario_id, :org_id, :control_name, :control_type,
                               :implementation_cost, :annual_cost, :effectiveness_pct,
                               :roi, :recommended, :created_at)""",
                    record,
                )
                # Recompute scenario with new control
                self._recompute_scenario(conn, scenario_id, org_id)
        return record

    def update_rates(
        self,
        scenario_id: str,
        org_id: str,
        asset_value: Optional[float] = None,
        exposure_factor: Optional[float] = None,
        annual_rate_occurrence: Optional[float] = None,
    ) -> Optional[Dict[str, Any]]:
        """Update scenario rate fields and recompute SLE/ALE/residual_ale/risk_level."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM risk_scenarios WHERE id = ? AND org_id = ?",
                    (scenario_id, org_id),
                ).fetchone()
                if not row:
                    return None

                updates: Dict[str, Any] = {}
                if asset_value is not None:
                    updates["asset_value"] = float(asset_value)
                if exposure_factor is not None:
                    updates["exposure_factor"] = _clamp(exposure_factor, 0.0, 1.0)
                if annual_rate_occurrence is not None:
                    updates["annual_rate_occurrence"] = float(annual_rate_occurrence)

                if updates:
                    set_clause = ", ".join(f"{k} = ?" for k in updates)
                    conn.execute(
                        f"UPDATE risk_scenarios SET {set_clause} WHERE id = ? AND org_id = ?",
                        list(updates.values()) + [scenario_id, org_id],
                    )
                    self._recompute_scenario(conn, scenario_id, org_id)

                updated = conn.execute(
                    "SELECT * FROM risk_scenarios WHERE id = ? AND org_id = ?",
                    (scenario_id, org_id),
                ).fetchone()
        return self._row(updated) if updated else None

    def take_snapshot(self, org_id: str) -> Dict[str, Any]:
        """Take a portfolio snapshot for the org."""
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT annual_loss_expectancy, risk_level, threat_type "
                    "FROM risk_scenarios WHERE org_id = ?",
                    (org_id,),
                ).fetchall()

                total_ale = sum(float(r["annual_loss_expectancy"]) for r in rows)
                avg_ale = total_ale / len(rows) if rows else 0.0
                critical_count = sum(1 for r in rows if r["risk_level"] == "critical")

                by_threat_type: Dict[str, float] = {}
                for r in rows:
                    tt = r["threat_type"]
                    by_threat_type[tt] = by_threat_type.get(tt, 0.0) + float(r["annual_loss_expectancy"])

                now = _now_iso()
                record: Dict[str, Any] = {
                    "id": str(uuid.uuid4()),
                    "org_id": org_id,
                    "snapshot_date": _today_iso(),
                    "total_ale": total_ale,
                    "avg_ale": avg_ale,
                    "critical_scenarios": critical_count,
                    "by_threat_type": json.dumps(by_threat_type),
                    "created_at": now,
                }
                conn.execute(
                    """INSERT INTO risk_snapshots
                       (id, org_id, snapshot_date, total_ale, avg_ale,
                        critical_scenarios, by_threat_type, created_at)
                       VALUES (:id, :org_id, :snapshot_date, :total_ale, :avg_ale,
                               :critical_scenarios, :by_threat_type, :created_at)""",
                    record,
                )
        # Deserialize for return
        record["by_threat_type"] = by_threat_type
        return record

    def get_portfolio_summary(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate portfolio summary for an org."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM risk_scenarios WHERE org_id = ? ORDER BY annual_loss_expectancy DESC",
                (org_id,),
            ).fetchall()

        total = len(rows)
        total_ale = sum(float(r["annual_loss_expectancy"]) for r in rows)
        avg_ale = total_ale / total if total else 0.0
        by_risk_level: Dict[str, int] = {}
        critical_count = 0
        for r in rows:
            rl = r["risk_level"]
            by_risk_level[rl] = by_risk_level.get(rl, 0) + 1
            if rl == "critical":
                critical_count += 1

        top5 = [self._row(r) for r in rows[:5]]

        return {
            "total_scenarios": total,
            "total_ale": total_ale,
            "avg_ale": avg_ale,
            "by_risk_level": by_risk_level,
            "critical_scenarios": critical_count,
            "top_5_ale_scenarios": top5,
        }

    def get_scenario_detail(self, scenario_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        """Return scenario with all controls and recommended controls."""
        with self._conn() as conn:
            sc_row = conn.execute(
                "SELECT * FROM risk_scenarios WHERE id = ? AND org_id = ?",
                (scenario_id, org_id),
            ).fetchone()
            if not sc_row:
                return None
            scenario = self._row(sc_row)

            ctrl_rows = conn.execute(
                "SELECT * FROM risk_controls WHERE scenario_id = ? AND org_id = ? ORDER BY roi DESC",
                (scenario_id, org_id),
            ).fetchall()
            controls = [self._row(c) for c in ctrl_rows]
            scenario["controls"] = controls
            scenario["recommended_controls"] = [c for c in controls if c["recommended"] == 1]
        return scenario

    def get_snapshot_history(self, org_id: str, days: int = 90) -> List[Dict[str, Any]]:
        """Return snapshots for the org within the last N days, newest first."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM risk_snapshots WHERE org_id = ?
                   AND snapshot_date >= date('now', ?)
                   ORDER BY snapshot_date DESC""",
                (org_id, f"-{days} days"),
            ).fetchall()
        results = []
        for r in rows:
            d = self._row(r)
            try:
                d["by_threat_type"] = json.loads(d["by_threat_type"])
            except (TypeError, ValueError):
                d["by_threat_type"] = {}
            results.append(d)
        return results

    def get_roi_analysis(self, org_id: str) -> List[Dict[str, Any]]:
        """Return all controls with positive ROI across the org, ordered by ROI DESC."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT rc.*, rs.scenario_name, rs.annual_loss_expectancy
                   FROM risk_controls rc
                   JOIN risk_scenarios rs ON rc.scenario_id = rs.id
                   WHERE rc.org_id = ? AND rc.roi > 0
                   ORDER BY rc.roi DESC""",
                (org_id,),
            ).fetchall()
        return [self._row(r) for r in rows]
