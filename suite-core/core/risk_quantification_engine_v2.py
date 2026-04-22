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
import math
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


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

                CREATE TABLE IF NOT EXISTS business_units (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    name         TEXT NOT NULL,
                    criticality  TEXT NOT NULL DEFAULT 'medium',
                    created_at   TEXT,
                    UNIQUE (org_id, name)
                );

                CREATE INDEX IF NOT EXISTS idx_rqv2_bu_org
                    ON business_units (org_id);

                CREATE TABLE IF NOT EXISTS fix_costs (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    finding_id    TEXT NOT NULL,
                    cost          REAL NOT NULL DEFAULT 0.0,
                    ale_reduced   REAL NOT NULL DEFAULT 0.0,
                    fixed_at      TEXT NOT NULL,
                    created_at    TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_rqv2_fix_costs_org
                    ON fix_costs (org_id, fixed_at);
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
                        f"UPDATE risk_scenarios SET {set_clause} WHERE id = ? AND org_id = ?",  # nosec B608
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

    # ------------------------------------------------------------------
    # GAP-028: FAIR per-Business-Unit
    # GAP-051: ROI-of-fixes trend
    # ------------------------------------------------------------------

    _DEFAULT_BUS = (
        ("Finance", "critical"),
        ("Engineering", "high"),
        ("Sales", "medium"),
        ("Ops", "high"),
        ("HR", "medium"),
    )

    # Severity → (SLE mean multiplier in $, ARO, probability weight 0-1)
    _SEVERITY_PROFILE = {
        "critical": (500_000.0, 2.0, 0.9),
        "high":     (150_000.0, 1.5, 0.75),
        "medium":   (40_000.0,  1.0, 0.5),
        "low":      (10_000.0,  0.5, 0.25),
        "info":     (2_000.0,   0.2, 0.1),
    }

    # BU criticality multiplier on SLE
    _BU_CRIT_MULTIPLIER = {
        "critical": 2.0,
        "high":     1.5,
        "medium":   1.0,
        "low":      0.5,
    }

    def business_units(self, org_id: str) -> List[Dict[str, Any]]:
        """List business units for an org. Seeds 5 defaults on first call if none exist.

        Idempotent: the seed uses INSERT OR IGNORE on (org_id, name) UNIQUE, so a
        repeat call produces no duplicates.
        """
        with self._lock:
            with self._conn() as conn:
                existing = conn.execute(
                    "SELECT COUNT(*) AS c FROM business_units WHERE org_id = ?",
                    (org_id,),
                ).fetchone()["c"]
                if existing == 0:
                    now = _now_iso()
                    for name, crit in self._DEFAULT_BUS:
                        conn.execute(
                            """INSERT OR IGNORE INTO business_units
                               (id, org_id, name, criticality, created_at)
                               VALUES (?, ?, ?, ?, ?)""",
                            (str(uuid.uuid4()), org_id, name, crit, now),
                        )
                rows = conn.execute(
                    "SELECT * FROM business_units WHERE org_id = ? ORDER BY name ASC",
                    (org_id,),
                ).fetchall()
        return [self._row(r) for r in rows]

    def _get_business_unit(self, org_id: str, bu_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM business_units WHERE id = ? AND org_id = ?",
                (bu_id, org_id),
            ).fetchone()
        return self._row(row) if row else None

    def _findings_for_bu(self, org_id: str, bu_id: str) -> List[Dict[str, Any]]:
        """Pull findings tagged to this BU from security_findings engine DB if present.

        Robust to missing table / missing column — returns [] when nothing available
        so callers can degrade gracefully (no RCE on malformed input, no crash).
        """
        findings: List[Dict[str, Any]] = []
        db_path = str(Path(self.db_path).parent / "security_findings.db")
        if not Path(db_path).exists():
            return findings
        try:
            conn = sqlite3.connect(db_path, timeout=5)
            conn.row_factory = sqlite3.Row
            # discover tag/BU column — common names: bu_id, business_unit, asset_tag
            cols_row = conn.execute("PRAGMA table_info(security_findings)").fetchall()
            col_names = {r["name"] for r in cols_row}
            tag_col = None
            for candidate in ("bu_id", "business_unit", "asset_tag", "tags"):
                if candidate in col_names:
                    tag_col = candidate
                    break
            if tag_col is None:
                conn.close()
                return findings
            query = (
                f"SELECT * FROM security_findings "  # nosec B608 - col whitelisted above
                f"WHERE org_id = ? AND {tag_col} = ? AND status != 'resolved'"
            )
            rows = conn.execute(query, (org_id, bu_id)).fetchall()
            findings = [dict(r) for r in rows]
            conn.close()
        except (sqlite3.Error, OSError) as exc:
            _logger.debug("findings lookup skipped: %s", exc)
        return findings

    def compute_per_bu_risk(
        self,
        org_id: str,
        bu_id: str,
        findings: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Compute FAIR per-BU risk using SLE × ARO × probability distribution.

        - Empty/None findings → clean zeros (no crash)
        - Aggregates SLE mean & ALE with p95 approx via log-normal σ=0.4
        """
        bu = self._get_business_unit(org_id, bu_id)
        if not bu:
            raise ValueError(f"Business unit {bu_id} not found for org {org_id}")

        if findings is None:
            findings = self._findings_for_bu(org_id, bu_id)

        crit_mult = self._BU_CRIT_MULTIPLIER.get(bu["criticality"], 1.0)

        total_sle = 0.0
        total_ale = 0.0
        aro_weighted = 0.0
        weight_sum = 0.0
        for f in findings or []:
            sev = str(f.get("severity", "medium")).lower()
            profile = self._SEVERITY_PROFILE.get(sev, self._SEVERITY_PROFILE["medium"])
            base_sle, aro, prob = profile
            # Per-finding expected contribution
            sle_i = base_sle * crit_mult
            # Weight by probability of occurrence (FAIR uses loss event frequency)
            ale_i = sle_i * aro * prob
            total_sle += sle_i
            total_ale += ale_i
            aro_weighted += aro * prob
            weight_sum += 1.0

        n = int(weight_sum)
        sle_mean = (total_sle / n) if n else 0.0
        aro_mean = (aro_weighted / n) if n else 0.0

        # p95 via log-normal approximation (σ=0.4)
        if total_ale > 0:
            sigma = 0.4
            mu = math.log(total_ale) - (sigma * sigma) / 2.0
            # z(0.95) ≈ 1.645
            ale_p95 = math.exp(mu + 1.645 * sigma)
        else:
            ale_p95 = 0.0

        return {
            "bu_id": bu_id,
            "name": bu["name"],
            "criticality": bu["criticality"],
            "sle_mean": round(sle_mean, 2),
            "aro": round(aro_mean, 4),
            "ale_mean": round(total_ale, 2),
            "ale_p95": round(ale_p95, 2),
            "contributing_findings_count": n,
        }

    def record_fix_cost(
        self,
        org_id: str,
        finding_id: str,
        cost: float,
        fixed_at: str,
        ale_reduced: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Record the cost and ALE reduction of fixing a finding.

        If ale_reduced is None, it is inferred from the finding's severity using
        _SEVERITY_PROFILE (SLE × ARO × prob).
        """
        cost = max(0.0, float(cost))
        if not fixed_at:
            raise ValueError("fixed_at must be an ISO date string")

        # Best-effort severity lookup if ale_reduced not supplied
        if ale_reduced is None:
            severity = "medium"
            db_path = str(Path(self.db_path).parent / "security_findings.db")
            if Path(db_path).exists():
                try:
                    conn = sqlite3.connect(db_path, timeout=5)
                    conn.row_factory = sqlite3.Row
                    row = conn.execute(
                        "SELECT severity FROM security_findings WHERE id = ? AND org_id = ?",
                        (finding_id, org_id),
                    ).fetchone()
                    if row and row["severity"]:
                        severity = str(row["severity"]).lower()
                    conn.close()
                except sqlite3.Error:
                    pass
            sle, aro, prob = self._SEVERITY_PROFILE.get(
                severity, self._SEVERITY_PROFILE["medium"]
            )
            ale_reduced = sle * aro * prob
        ale_reduced = max(0.0, float(ale_reduced))

        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "finding_id": finding_id,
            "cost": cost,
            "ale_reduced": ale_reduced,
            "fixed_at": fixed_at,
            "created_at": _now_iso(),
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO fix_costs
                       (id, org_id, finding_id, cost, ale_reduced, fixed_at, created_at)
                       VALUES (:id, :org_id, :finding_id, :cost, :ale_reduced,
                               :fixed_at, :created_at)""",
                    record,
                )
        return record

    def roi_of_fixes_trend(
        self,
        org_id: str,
        window_days: int = 90,
    ) -> Dict[str, Any]:
        """Weekly cumulative ALE-reduced ÷ cumulative cost across the window.

        Returns exactly N+1 weekly buckets where N = window_days // 7 (so a 90-day
        window = 13 weeks → 14 points including the "start of window" baseline).
        """
        window_days = max(1, int(window_days))
        num_weeks = max(1, window_days // 7)
        num_points = num_weeks + 1

        now = datetime.now(timezone.utc)
        window_start = now - timedelta(days=window_days)

        # Pull all fix_costs within window
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT cost, ale_reduced, fixed_at
                   FROM fix_costs
                   WHERE org_id = ? AND fixed_at >= ?
                   ORDER BY fixed_at ASC""",
                (org_id, window_start.isoformat()),
            ).fetchall()

        # Build weekly bucket boundaries (point 0 = window_start, point k = +7k days)
        bucket_edges: List[datetime] = [
            window_start + timedelta(days=7 * i) for i in range(num_points)
        ]
        # Ensure last edge = now
        bucket_edges[-1] = now

        weeks_labels: List[str] = [dt.date().isoformat() for dt in bucket_edges]
        cum_ale: List[float] = [0.0] * num_points
        cum_cost: List[float] = [0.0] * num_points

        # Index fixes by week index (they accumulate into bucket k and onward)
        for r in rows:
            try:
                fixed_dt = datetime.fromisoformat(str(r["fixed_at"]).replace("Z", "+00:00"))
                if fixed_dt.tzinfo is None:
                    fixed_dt = fixed_dt.replace(tzinfo=timezone.utc)
            except (ValueError, TypeError):
                continue
            if fixed_dt < window_start:
                continue
            # Find the first bucket edge >= fixed_dt
            for k, edge in enumerate(bucket_edges):
                if fixed_dt <= edge:
                    # Add to this bucket and all later buckets (cumulative)
                    for j in range(k, num_points):
                        cum_ale[j] += float(r["ale_reduced"])
                        cum_cost[j] += float(r["cost"])
                    break

        roi_trend: List[float] = []
        for ale_v, cost_v in zip(cum_ale, cum_cost):
            if cost_v > 0:
                roi_trend.append(round((ale_v - cost_v) / cost_v * 100.0, 2))
            else:
                roi_trend.append(0.0)

        return {
            "window_days": window_days,
            "weeks": weeks_labels,
            "cumulative_ale_reduced": [round(v, 2) for v in cum_ale],
            "cumulative_cost": [round(v, 2) for v in cum_cost],
            "roi_trend": roi_trend,
        }
