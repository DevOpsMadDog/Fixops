"""Risk Quantification Engine — ALDECI.

FAIR-inspired financial risk quantification with Monte Carlo simulation.
Supports scenario modelling, treatment ROI analysis, and financial impact tracking.

Compliance: NIST SP 800-30, ISO 27005, FAIR (Factor Analysis of Information Risk)
"""

from __future__ import annotations

import json
import logging
import random
import sqlite3
import statistics
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "risk_quantification.db"
)

_THREAT_ACTORS = {"nation_state", "cybercriminal", "insider", "hacktivist", "opportunist"}
_ATTACK_VECTORS = {"phishing", "supply_chain", "zero_day", "credential", "physical"}
_ASSET_TYPES = {"data", "infrastructure", "application", "personnel"}
_TREATMENT_TYPES = {"accept", "mitigate", "transfer", "avoid"}
_TREATMENT_STATUSES = {"proposed", "approved", "implemented"}


class RiskQuantificationEngine:
    """SQLite WAL-backed FAIR risk quantification engine.

    Thread-safe via RLock. Multi-tenant via org_id.
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
                    scenario_id          TEXT PRIMARY KEY,
                    org_id               TEXT NOT NULL,
                    name                 TEXT NOT NULL,
                    threat_actor         TEXT NOT NULL DEFAULT 'cybercriminal',
                    attack_vector        TEXT NOT NULL DEFAULT 'phishing',
                    target_asset_type    TEXT NOT NULL DEFAULT 'data',
                    likelihood_pct       REAL NOT NULL DEFAULT 50.0,
                    minimum_loss         REAL NOT NULL DEFAULT 0.0,
                    maximum_loss         REAL NOT NULL DEFAULT 0.0,
                    expected_loss        REAL NOT NULL DEFAULT 0.0,
                    ale                  REAL NOT NULL DEFAULT 0.0,
                    created_at           TEXT NOT NULL,
                    updated_at           TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_rq_scenario_org
                    ON risk_scenarios (org_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS quantification_models (
                    model_id     TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    scenario_id  TEXT NOT NULL,
                    model_type   TEXT NOT NULL DEFAULT 'monte_carlo',
                    iterations   INTEGER NOT NULL DEFAULT 1000,
                    result_json  TEXT NOT NULL DEFAULT '{}',
                    ran_at       TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_rq_model_scenario
                    ON quantification_models (org_id, scenario_id, ran_at DESC);

                CREATE TABLE IF NOT EXISTS financial_impacts (
                    impact_id                TEXT PRIMARY KEY,
                    org_id                   TEXT NOT NULL,
                    incident_type            TEXT NOT NULL,
                    direct_cost              REAL NOT NULL DEFAULT 0.0,
                    regulatory_fines         REAL NOT NULL DEFAULT 0.0,
                    remediation_cost         REAL NOT NULL DEFAULT 0.0,
                    business_disruption_cost REAL NOT NULL DEFAULT 0.0,
                    reputational_cost        REAL NOT NULL DEFAULT 0.0,
                    total_loss               REAL NOT NULL DEFAULT 0.0,
                    incident_date            TEXT NOT NULL,
                    fiscal_year              INTEGER NOT NULL,
                    created_at               TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_rq_impact_org
                    ON financial_impacts (org_id, fiscal_year, incident_date DESC);

                CREATE TABLE IF NOT EXISTS risk_treatments (
                    treatment_id       TEXT PRIMARY KEY,
                    org_id             TEXT NOT NULL,
                    scenario_id        TEXT NOT NULL,
                    treatment_type     TEXT NOT NULL DEFAULT 'mitigate',
                    description        TEXT NOT NULL DEFAULT '',
                    cost               REAL NOT NULL DEFAULT 0.0,
                    risk_reduction_pct REAL NOT NULL DEFAULT 0.0,
                    roi                REAL NOT NULL DEFAULT 0.0,
                    status             TEXT NOT NULL DEFAULT 'proposed',
                    created_at         TEXT NOT NULL,
                    updated_at         TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_rq_treatment_org
                    ON risk_treatments (org_id, scenario_id, created_at DESC);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _compute_expected_loss(likelihood_pct: float, min_loss: float, max_loss: float) -> float:
        avg_loss = (min_loss + max_loss) / 2.0
        return (likelihood_pct / 100.0) * avg_loss

    @staticmethod
    def _compute_ale(likelihood_pct: float, min_loss: float, max_loss: float) -> float:
        """Annualized Loss Expectancy = probability × average single loss expectancy."""
        sle = (min_loss + max_loss) / 2.0
        aro = likelihood_pct / 100.0  # annual rate of occurrence
        return aro * sle

    # ------------------------------------------------------------------
    # Scenarios
    # ------------------------------------------------------------------

    def create_scenario(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new risk scenario. Returns the full scenario dict."""
        scenario_id = str(uuid.uuid4())
        now = self._now()

        likelihood_pct = float(data.get("likelihood_pct", 50.0))
        likelihood_pct = max(0.0, min(100.0, likelihood_pct))
        min_loss = float(data.get("minimum_loss", 0.0))
        max_loss = float(data.get("maximum_loss", 0.0))
        expected_loss = self._compute_expected_loss(likelihood_pct, min_loss, max_loss)
        ale = self._compute_ale(likelihood_pct, min_loss, max_loss)

        threat_actor = data.get("threat_actor", "cybercriminal")
        if threat_actor not in _THREAT_ACTORS:
            threat_actor = "cybercriminal"
        attack_vector = data.get("attack_vector", "phishing")
        if attack_vector not in _ATTACK_VECTORS:
            attack_vector = "phishing"
        target_asset_type = data.get("target_asset_type", "data")
        if target_asset_type not in _ASSET_TYPES:
            target_asset_type = "data"

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO risk_scenarios
                        (scenario_id, org_id, name, threat_actor, attack_vector,
                         target_asset_type, likelihood_pct, minimum_loss, maximum_loss,
                         expected_loss, ale, created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        scenario_id, org_id,
                        data.get("name", "Unnamed Scenario"),
                        threat_actor, attack_vector, target_asset_type,
                        likelihood_pct, min_loss, max_loss,
                        expected_loss, ale, now, now,
                    ),
                )

        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("RISK_ASSESSED", {"entity_type": "risk_quantification", "org_id": org_id, "source_engine": "risk_quantification"})
            except Exception:
                pass

        return self.get_scenario(org_id, scenario_id)  # type: ignore[return-value]

    def get_scenario(self, org_id: str, scenario_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM risk_scenarios WHERE scenario_id=? AND org_id=?",
                (scenario_id, org_id),
            ).fetchone()
        return self._row_to_dict(row) if row else None

    def list_scenarios(self, org_id: str) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM risk_scenarios WHERE org_id=? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def update_scenario(self, org_id: str, scenario_id: str, data: Dict[str, Any]) -> bool:
        """Update allowed fields on a scenario. Returns True if updated."""
        allowed = {
            "name", "threat_actor", "attack_vector", "target_asset_type",
            "likelihood_pct", "minimum_loss", "maximum_loss",
        }
        fields = {k: v for k, v in data.items() if k in allowed}
        if not fields:
            return False

        # Validate enums
        if "threat_actor" in fields and fields["threat_actor"] not in _THREAT_ACTORS:
            fields["threat_actor"] = "cybercriminal"
        if "attack_vector" in fields and fields["attack_vector"] not in _ATTACK_VECTORS:
            fields["attack_vector"] = "phishing"
        if "target_asset_type" in fields and fields["target_asset_type"] not in _ASSET_TYPES:
            fields["target_asset_type"] = "data"
        if "likelihood_pct" in fields:
            fields["likelihood_pct"] = max(0.0, min(100.0, float(fields["likelihood_pct"])))

        # Fetch current values to recompute derived fields
        current = self.get_scenario(org_id, scenario_id)
        if not current:
            return False

        likelihood_pct = float(fields.get("likelihood_pct", current["likelihood_pct"]))
        min_loss = float(fields.get("minimum_loss", current["minimum_loss"]))
        max_loss = float(fields.get("maximum_loss", current["maximum_loss"]))
        fields["expected_loss"] = self._compute_expected_loss(likelihood_pct, min_loss, max_loss)
        fields["ale"] = self._compute_ale(likelihood_pct, min_loss, max_loss)
        fields["updated_at"] = self._now()

        set_clause = ", ".join(f"{k}=?" for k in fields)
        values = list(fields.values()) + [scenario_id, org_id]

        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    f"UPDATE risk_scenarios SET {set_clause} WHERE scenario_id=? AND org_id=?",  # nosec B608
                    values,
                )
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Monte Carlo simulation
    # ------------------------------------------------------------------

    def run_monte_carlo(
        self, org_id: str, scenario_id: str, iterations: int = 1000
    ) -> Dict[str, Any]:
        """Run a Monte Carlo simulation on the scenario's loss distribution.

        Draws `iterations` samples from Uniform(min_loss, max_loss) scaled by
        likelihood_pct. Returns mean, median, p95, p99, worst_case, best_case.
        """
        scenario = self.get_scenario(org_id, scenario_id)
        if not scenario:
            raise ValueError(f"Scenario {scenario_id} not found for org {org_id}")

        min_loss = float(scenario["minimum_loss"])
        max_loss = float(scenario["maximum_loss"])
        likelihood = float(scenario["likelihood_pct"]) / 100.0
        iterations = max(1, min(100_000, int(iterations)))

        rng = random.Random()
        samples: List[float] = []
        for _ in range(iterations):
            # Event occurs with probability = likelihood
            if rng.random() < likelihood:
                loss = rng.uniform(min_loss, max_loss)
            else:
                loss = 0.0
            samples.append(loss)

        samples_sorted = sorted(samples)
        n = len(samples_sorted)

        def percentile(p: float) -> float:
            idx = int(p / 100.0 * (n - 1))
            return samples_sorted[idx]

        mean_val = statistics.mean(samples) if samples else 0.0
        median_val = statistics.median(samples) if samples else 0.0
        result = {
            "scenario_id": scenario_id,
            "iterations": iterations,
            "mean": round(mean_val, 2),
            "median": round(median_val, 2),
            "p95": round(percentile(95), 2),
            "p99": round(percentile(99), 2),
            "worst_case": round(samples_sorted[-1], 2),
            "best_case": round(samples_sorted[0], 2),
            "ran_at": self._now(),
        }

        # Persist the model run
        model_id = str(uuid.uuid4())
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO quantification_models
                        (model_id, org_id, scenario_id, model_type, iterations, result_json, ran_at)
                    VALUES (?,?,?,?,?,?,?)
                    """,
                    (
                        model_id, org_id, scenario_id, "monte_carlo",
                        iterations, json.dumps(result), result["ran_at"],
                    ),
                )

        return result

    # ------------------------------------------------------------------
    # Treatments
    # ------------------------------------------------------------------

    def create_treatment(
        self, org_id: str, scenario_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create a risk treatment. ROI = (expected_loss × risk_reduction_pct/100) / cost."""
        treatment_id = str(uuid.uuid4())
        now = self._now()

        treatment_type = data.get("treatment_type", "mitigate")
        if treatment_type not in _TREATMENT_TYPES:
            treatment_type = "mitigate"
        status = data.get("status", "proposed")
        if status not in _TREATMENT_STATUSES:
            status = "proposed"

        cost = float(data.get("cost", 0.0))
        risk_reduction_pct = float(data.get("risk_reduction_pct", 0.0))
        risk_reduction_pct = max(0.0, min(100.0, risk_reduction_pct))

        # Compute ROI from the parent scenario's expected_loss
        roi = 0.0
        scenario = self.get_scenario(org_id, scenario_id)
        if scenario and cost > 0:
            expected_loss = float(scenario.get("expected_loss", 0.0))
            avoided_loss = expected_loss * (risk_reduction_pct / 100.0)
            roi = round(avoided_loss / cost, 4)

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO risk_treatments
                        (treatment_id, org_id, scenario_id, treatment_type, description,
                         cost, risk_reduction_pct, roi, status, created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        treatment_id, org_id, scenario_id,
                        treatment_type,
                        data.get("description", ""),
                        cost, risk_reduction_pct, roi, status,
                        now, now,
                    ),
                )

        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM risk_treatments WHERE treatment_id=?", (treatment_id,)
            ).fetchone()
        return self._row_to_dict(row)  # type: ignore[return-value]

    def list_treatments(
        self, org_id: str, scenario_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        if scenario_id:
            query = (
                "SELECT * FROM risk_treatments WHERE org_id=? AND scenario_id=? "
                "ORDER BY created_at DESC"
            )
            params = (org_id, scenario_id)
        else:
            query = "SELECT * FROM risk_treatments WHERE org_id=? ORDER BY created_at DESC"
            params = (org_id,)  # type: ignore[assignment]

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Financial Impacts
    # ------------------------------------------------------------------

    def record_financial_impact(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a financial impact from an actual incident."""
        impact_id = str(uuid.uuid4())
        now = self._now()

        direct_cost = float(data.get("direct_cost", 0.0))
        regulatory_fines = float(data.get("regulatory_fines", 0.0))
        remediation_cost = float(data.get("remediation_cost", 0.0))
        business_disruption_cost = float(data.get("business_disruption_cost", 0.0))
        reputational_cost = float(data.get("reputational_cost", 0.0))
        total_loss = (
            direct_cost
            + regulatory_fines
            + remediation_cost
            + business_disruption_cost
            + reputational_cost
        )

        incident_date = data.get("incident_date", now)
        # Extract fiscal year from incident_date or data
        fiscal_year = int(data.get("fiscal_year", datetime.now(timezone.utc).year))

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO financial_impacts
                        (impact_id, org_id, incident_type, direct_cost, regulatory_fines,
                         remediation_cost, business_disruption_cost, reputational_cost,
                         total_loss, incident_date, fiscal_year, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        impact_id, org_id,
                        data.get("incident_type", "unclassified"),
                        direct_cost, regulatory_fines, remediation_cost,
                        business_disruption_cost, reputational_cost, total_loss,
                        incident_date, fiscal_year, now,
                    ),
                )

        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM financial_impacts WHERE impact_id=?", (impact_id,)
            ).fetchone()
        return self._row_to_dict(row)  # type: ignore[return-value]

    def list_financial_impacts(
        self, org_id: str, fiscal_year: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        if fiscal_year is not None:
            query = (
                "SELECT * FROM financial_impacts WHERE org_id=? AND fiscal_year=? "
                "ORDER BY incident_date DESC"
            )
            params = (org_id, fiscal_year)
        else:
            query = (
                "SELECT * FROM financial_impacts WHERE org_id=? ORDER BY incident_date DESC"
            )
            params = (org_id,)  # type: ignore[assignment]

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_risk_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate risk statistics for an org."""
        with self._conn() as conn:
            # Scenario stats
            scenario_row = conn.execute(
                """
                SELECT
                    COUNT(*) AS total_scenarios,
                    COALESCE(SUM(ale), 0) AS total_ale,
                    MAX(ale) AS max_ale
                FROM risk_scenarios
                WHERE org_id=?
                """,
                (org_id,),
            ).fetchone()

            # Highest risk scenario
            hr_row = conn.execute(
                """
                SELECT name, ale FROM risk_scenarios
                WHERE org_id=?
                ORDER BY ale DESC LIMIT 1
                """,
                (org_id,),
            ).fetchone()

            # Treatment stats
            treatment_row = conn.execute(
                """
                SELECT
                    COUNT(*) AS total_treatments,
                    COALESCE(AVG(roi), 0) AS avg_roi
                FROM risk_treatments
                WHERE org_id=?
                """,
                (org_id,),
            ).fetchone()

            # Financial impact YTD
            current_year = datetime.now(timezone.utc).year
            impact_row = conn.execute(
                """
                SELECT COALESCE(SUM(total_loss), 0) AS ytd_total
                FROM financial_impacts
                WHERE org_id=? AND fiscal_year=?
                """,
                (org_id, current_year),
            ).fetchone()

        return {
            "total_scenarios": scenario_row["total_scenarios"] if scenario_row else 0,
            "total_ale": round(float(scenario_row["total_ale"] or 0), 2) if scenario_row else 0.0,
            "highest_risk_scenario": (
                {"name": hr_row["name"], "ale": round(float(hr_row["ale"]), 2)}
                if hr_row else None
            ),
            "total_treatments": treatment_row["total_treatments"] if treatment_row else 0,
            "avg_roi": round(float(treatment_row["avg_roi"] or 0), 4) if treatment_row else 0.0,
            "financial_impact_ytd": round(
                float(impact_row["ytd_total"] or 0), 2
            ) if impact_row else 0.0,
        }
