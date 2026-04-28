"""
Risk Quantification Engine — ALDECI FAIR-based Financial Risk Modeling.

This module provides financial impact quantification of security risks using
the FAIR (Factor Analysis of Information Risk) methodology with Monte Carlo
simulation for probabilistic loss estimation.

Key Capabilities:
- RiskScenario: define assets, threat events, and financial parameters
- Monte Carlo ALE simulation (1000 iterations) for probabilistic estimates
- Auto-scenario creation from finding severity + asset value
- Portfolio risk aggregation across all org scenarios
- ROI analysis: control investment vs risk reduction
- Scenario comparison side-by-side
- Probability × impact heatmap data
- Built-in asset value templates (web_app=$500K, database=$2M, etc.)

FAIR Methodology Reference:
- ALE = Probability × Loss Magnitude
- Loss ranges modeled with PERT distribution (Beta-PERT: low, mode, high)
- Risk tier thresholds: critical >$1M ALE, high >$100K, medium >$10K, low ≤$10K

Compliance: SOC2 CC3.2 (Risk Assessment), CC9.1 (Risk Mitigation)
"""

from __future__ import annotations

import logging
import random
import sqlite3
import threading
import uuid
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

# ============================================================================
# ASSET VALUE TEMPLATES
# ============================================================================

ASSET_VALUE_TEMPLATES: Dict[str, float] = {
    "web_app": 500_000.0,
    "database": 2_000_000.0,
    "api": 300_000.0,
    "mobile_app": 250_000.0,
    "internal_tool": 100_000.0,
    "saas_platform": 5_000_000.0,
    "microservice": 150_000.0,
    "data_pipeline": 800_000.0,
    "auth_service": 1_000_000.0,
    "payment_service": 3_000_000.0,
    "cloud_infra": 2_500_000.0,
    "endpoint": 50_000.0,
    "network_segment": 1_500_000.0,
    "iot_device": 25_000.0,
    "backup_system": 400_000.0,
}

# Severity → probability range mapping (FAIR-aligned)
SEVERITY_PROBABILITY: Dict[str, tuple[float, float]] = {
    "critical": (0.60, 0.90),
    "high": (0.30, 0.60),
    "medium": (0.10, 0.30),
    "low": (0.02, 0.10),
    "info": (0.01, 0.05),
}

# Severity → loss magnitude fraction of asset value
SEVERITY_LOSS_FRACTION: Dict[str, tuple[float, float]] = {
    "critical": (0.50, 1.00),
    "high": (0.20, 0.60),
    "medium": (0.05, 0.25),
    "low": (0.01, 0.10),
    "info": (0.001, 0.02),
}

# Risk tier ALE thresholds (USD)
RISK_TIER_THRESHOLDS = {
    "critical": 1_000_000.0,
    "high": 100_000.0,
    "medium": 10_000.0,
}

# Recommended security investment as fraction of ALE
INVESTMENT_FRACTION = 0.35


# ============================================================================
# PYDANTIC MODELS
# ============================================================================


class RiskScenario(BaseModel):
    """
    Defines a financial risk scenario using FAIR parameters.

    Attributes:
        id: Unique scenario identifier (UUID)
        name: Human-readable scenario name
        threat_event: Description of the threat (e.g., "SQL Injection attack")
        asset_value_usd: Replacement/business value of the at-risk asset in USD
        loss_magnitude_low: Minimum estimated financial loss (USD)
        loss_magnitude_high: Maximum estimated financial loss (USD)
        probability_low: Minimum annual probability of occurrence (0.0–1.0)
        probability_high: Maximum annual probability of occurrence (0.0–1.0)
        annual_loss_expectancy: Pre-calculated ALE in USD (optional override)
        org_id: Organization identifier for multi-tenancy
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    threat_event: str
    asset_value_usd: float = Field(ge=0.0)
    loss_magnitude_low: float = Field(ge=0.0)
    loss_magnitude_high: float = Field(ge=0.0)
    probability_low: float = Field(ge=0.0, le=1.0)
    probability_high: float = Field(ge=0.0, le=1.0)
    annual_loss_expectancy: Optional[float] = None
    org_id: str = "default"


class QuantifiedRisk(BaseModel):
    """
    Monte Carlo quantification result for a risk scenario.

    Attributes:
        scenario_id: Reference to the source RiskScenario
        ale_low: 10th-percentile Annual Loss Expectancy (USD)
        ale_high: 90th-percentile Annual Loss Expectancy (USD)
        ale_most_likely: Median (50th-percentile) ALE (USD)
        risk_tier: Classification — critical / high / medium / low
        recommended_investment_usd: Suggested control budget (35% of ALE median)
    """

    scenario_id: str
    ale_low: float
    ale_high: float
    ale_most_likely: float
    risk_tier: str  # "critical" | "high" | "medium" | "low"
    recommended_investment_usd: float


# ============================================================================
# RISK QUANTIFIER ENGINE
# ============================================================================


class RiskQuantifier:
    """
    FAIR-based financial risk quantification engine with SQLite persistence.

    Uses Monte Carlo simulation (1000 iterations) with PERT distribution to
    model loss magnitude uncertainty and produce probabilistic ALE estimates.
    """

    _MONTE_CARLO_ITERATIONS = 1000

    def __init__(self, db_path: str = ":memory:", org_id: str = "default") -> None:
        """
        Initialize the risk quantifier.

        Args:
            db_path: SQLite database path (":memory:" for tests)
            org_id: Default organization identifier
        """
        self.db_path = db_path
        self.org_id = org_id
        self._lock = threading.RLock()
        # For in-memory DBs, keep a single persistent connection so the
        # schema survives across calls (each new connect(":memory:") is empty).
        self._mem_conn: Optional[sqlite3.Connection] = None
        if db_path == ":memory:":
            self._mem_conn = sqlite3.connect(db_path, check_same_thread=False)
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        """Return a connection — persistent for :memory:, new for file-backed DBs."""
        if self._mem_conn is not None:
            return self._mem_conn
        return sqlite3.connect(self.db_path)

    def _close(self, conn: sqlite3.Connection) -> None:
        """Close connection only if it is not the shared in-memory connection."""
        if conn is not self._mem_conn:
            conn.close()

    def _init_db(self) -> None:
        """Initialize SQLite schema for scenarios and quantification results."""
        with self._lock:
            conn = self._connect()
            try:
                cursor = conn.cursor()

                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS risk_scenarios (
                        id TEXT PRIMARY KEY,
                        org_id TEXT NOT NULL,
                        name TEXT NOT NULL,
                        threat_event TEXT NOT NULL,
                        asset_value_usd REAL NOT NULL,
                        loss_magnitude_low REAL NOT NULL,
                        loss_magnitude_high REAL NOT NULL,
                        probability_low REAL NOT NULL,
                        probability_high REAL NOT NULL,
                        annual_loss_expectancy REAL,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )

                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS quantified_risks (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scenario_id TEXT NOT NULL,
                        org_id TEXT NOT NULL,
                        ale_low REAL NOT NULL,
                        ale_high REAL NOT NULL,
                        ale_most_likely REAL NOT NULL,
                        risk_tier TEXT NOT NULL,
                        recommended_investment_usd REAL NOT NULL,
                        quantified_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (scenario_id) REFERENCES risk_scenarios(id)
                    )
                    """
                )

                cursor.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_scenarios_org
                    ON risk_scenarios (org_id)
                    """
                )

                cursor.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_risks_org_scenario
                    ON quantified_risks (org_id, scenario_id)
                    """
                )

                conn.commit()
            finally:
                self._close(conn)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _pert_sample(self, low: float, high: float, rng: random.Random) -> float:
        """
        Sample from a PERT (Beta-PERT) distribution.

        Uses the mode = (low + 4*mid + high) / 6 approximation where
        mid = (low + high) / 2.  Falls back to uniform if range is zero.

        Args:
            low: Minimum value
            high: Maximum value
            rng: Random number generator instance

        Returns:
            Sampled value within [low, high]
        """
        if high <= low:
            return low
        mid = (low + high) / 2.0
        # Beta-PERT: alpha = 1 + 4 * (mode - low) / (high - low)
        alpha = 1.0 + 4.0 * (mid - low) / (high - low)
        beta = 1.0 + 4.0 * (high - mid) / (high - low)
        # Use betavariate and scale to range
        try:
            sample = rng.betavariate(alpha, beta)
            return low + sample * (high - low)
        except Exception:
            return rng.uniform(low, high)

    def _classify_tier(self, ale: float) -> str:
        """Classify ALE into risk tier."""
        if ale >= RISK_TIER_THRESHOLDS["critical"]:
            return "critical"
        if ale >= RISK_TIER_THRESHOLDS["high"]:
            return "high"
        if ale >= RISK_TIER_THRESHOLDS["medium"]:
            return "medium"
        return "low"

    def _run_monte_carlo(self, scenario: RiskScenario) -> QuantifiedRisk:
        """
        Run Monte Carlo simulation to compute ALE distribution.

        Args:
            scenario: Risk scenario with parameter ranges

        Returns:
            QuantifiedRisk with percentile-based ALE estimates
        """
        rng = random.Random(hash(scenario.id) % (2**31))
        ale_samples: List[float] = []

        for _ in range(self._MONTE_CARLO_ITERATIONS):
            prob = self._pert_sample(scenario.probability_low, scenario.probability_high, rng)
            loss = self._pert_sample(scenario.loss_magnitude_low, scenario.loss_magnitude_high, rng)
            ale_samples.append(prob * loss)

        ale_samples.sort()
        n = len(ale_samples)
        ale_low = ale_samples[int(n * 0.10)]
        ale_most_likely = ale_samples[int(n * 0.50)]
        ale_high = ale_samples[int(n * 0.90)]

        risk_tier = self._classify_tier(ale_most_likely)
        recommended_investment = round(ale_most_likely * INVESTMENT_FRACTION, 2)

        return QuantifiedRisk(
            scenario_id=scenario.id,
            ale_low=round(ale_low, 2),
            ale_high=round(ale_high, 2),
            ale_most_likely=round(ale_most_likely, 2),
            risk_tier=risk_tier,
            recommended_investment_usd=recommended_investment,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_scenario(
        self,
        name: str,
        threat_event: str,
        asset_value_usd: float,
        loss_magnitude_low: float,
        loss_magnitude_high: float,
        probability_low: float,
        probability_high: float,
        annual_loss_expectancy: Optional[float] = None,
        org_id: Optional[str] = None,
        scenario_id: Optional[str] = None,
    ) -> RiskScenario:
        """
        Define and persist a new risk scenario.

        Args:
            name: Scenario name
            threat_event: Threat description
            asset_value_usd: Asset value in USD
            loss_magnitude_low: Minimum loss (USD)
            loss_magnitude_high: Maximum loss (USD)
            probability_low: Minimum annual probability (0–1)
            probability_high: Maximum annual probability (0–1)
            annual_loss_expectancy: Optional pre-calculated ALE override
            org_id: Organization ID (defaults to instance org_id)
            scenario_id: Optional explicit ID (defaults to UUID)

        Returns:
            Persisted RiskScenario instance
        """
        effective_org = org_id or self.org_id
        scenario = RiskScenario(
            id=scenario_id or str(uuid.uuid4()),
            name=name,
            threat_event=threat_event,
            asset_value_usd=asset_value_usd,
            loss_magnitude_low=loss_magnitude_low,
            loss_magnitude_high=loss_magnitude_high,
            probability_low=probability_low,
            probability_high=probability_high,
            annual_loss_expectancy=annual_loss_expectancy,
            org_id=effective_org,
        )

        with self._lock:
            conn = self._connect()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO risk_scenarios
                    (id, org_id, name, threat_event, asset_value_usd,
                     loss_magnitude_low, loss_magnitude_high,
                     probability_low, probability_high, annual_loss_expectancy,
                     updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    """,
                    (
                        scenario.id,
                        scenario.org_id,
                        scenario.name,
                        scenario.threat_event,
                        scenario.asset_value_usd,
                        scenario.loss_magnitude_low,
                        scenario.loss_magnitude_high,
                        scenario.probability_low,
                        scenario.probability_high,
                        scenario.annual_loss_expectancy,
                    ),
                )
                conn.commit()
            finally:
                self._close(conn)

        _logger.info("Created risk scenario %s: %s", scenario.id, scenario.name)
        return scenario

    def get_scenario(self, scenario_id: str) -> Optional[RiskScenario]:
        """Retrieve a scenario by ID."""
        with self._lock:
            conn = self._connect()
            conn.row_factory = sqlite3.Row
            try:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT * FROM risk_scenarios WHERE id = ?",
                    (scenario_id,),
                )
                row = cursor.fetchone()
                if row is None:
                    return None
                return RiskScenario(
                    id=row["id"],
                    name=row["name"],
                    threat_event=row["threat_event"],
                    asset_value_usd=row["asset_value_usd"],
                    loss_magnitude_low=row["loss_magnitude_low"],
                    loss_magnitude_high=row["loss_magnitude_high"],
                    probability_low=row["probability_low"],
                    probability_high=row["probability_high"],
                    annual_loss_expectancy=row["annual_loss_expectancy"],
                    org_id=row["org_id"],
                )
            finally:
                self._close(conn)

    def quantify(self, scenario_id: str) -> QuantifiedRisk:
        """
        Quantify financial risk for a scenario using Monte Carlo simulation.

        Args:
            scenario_id: ID of an existing risk scenario

        Returns:
            QuantifiedRisk with ALE percentiles and tier classification

        Raises:
            ValueError: If scenario not found
        """
        scenario = self.get_scenario(scenario_id)
        if scenario is None:
            raise ValueError(f"Scenario not found: {scenario_id}")

        result = self._run_monte_carlo(scenario)

        # Persist result
        with self._lock:
            conn = self._connect()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO quantified_risks
                    (scenario_id, org_id, ale_low, ale_high, ale_most_likely,
                     risk_tier, recommended_investment_usd)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        result.scenario_id,
                        scenario.org_id,
                        result.ale_low,
                        result.ale_high,
                        result.ale_most_likely,
                        result.risk_tier,
                        result.recommended_investment_usd,
                    ),
                )
                conn.commit()
            finally:
                self._close(conn)

        _logger.info(
            "Quantified scenario %s: ALE median=$%.0f tier=%s",
            scenario_id,
            result.ale_most_likely,
            result.risk_tier,
        )
        return result

    def quantify_finding(
        self,
        finding: Dict[str, Any],
        org_id: Optional[str] = None,
    ) -> QuantifiedRisk:
        """
        Auto-create a scenario from a finding and quantify it.

        Derives financial parameters from finding severity and asset_type.
        Uses built-in ASSET_VALUE_TEMPLATES and SEVERITY_* mappings.

        Args:
            finding: Dict with keys: id, title, severity, asset_type (optional),
                     asset_value_usd (optional), description (optional)
            org_id: Organization ID

        Returns:
            QuantifiedRisk result
        """
        effective_org = org_id or self.org_id
        severity = (finding.get("severity") or "medium").lower()
        if severity not in SEVERITY_PROBABILITY:
            severity = "medium"

        # Determine asset value
        asset_type = (finding.get("asset_type") or "web_app").lower()
        asset_value = finding.get("asset_value_usd") or ASSET_VALUE_TEMPLATES.get(
            asset_type, ASSET_VALUE_TEMPLATES["web_app"]
        )

        prob_low, prob_high = SEVERITY_PROBABILITY[severity]
        loss_frac_low, loss_frac_high = SEVERITY_LOSS_FRACTION[severity]

        loss_low = asset_value * loss_frac_low
        loss_high = asset_value * loss_frac_high

        finding_id = finding.get("id") or str(uuid.uuid4())
        title = finding.get("title") or f"Finding {finding_id[:8]}"
        description = finding.get("description") or f"{severity.capitalize()} security finding"

        scenario = self.create_scenario(
            name=f"Auto: {title}",
            threat_event=description,
            asset_value_usd=float(asset_value),
            loss_magnitude_low=loss_low,
            loss_magnitude_high=loss_high,
            probability_low=prob_low,
            probability_high=prob_high,
            org_id=effective_org,
        )

        return self.quantify(scenario.id)

    def get_portfolio_risk(self, org_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Aggregate total financial risk exposure for an organization.

        Args:
            org_id: Organization ID (defaults to instance org_id)

        Returns:
            Portfolio summary with total ALE, tier breakdown, top scenarios
        """
        effective_org = org_id or self.org_id

        with self._lock:
            conn = self._connect()
            conn.row_factory = sqlite3.Row
            try:
                cursor = conn.cursor()

                # Get latest quantification per scenario for the org
                cursor.execute(
                    """
                    SELECT qr.scenario_id, qr.ale_low, qr.ale_high,
                           qr.ale_most_likely, qr.risk_tier,
                           qr.recommended_investment_usd, rs.name, rs.threat_event
                    FROM quantified_risks qr
                    JOIN risk_scenarios rs ON qr.scenario_id = rs.id
                    WHERE qr.org_id = ?
                    AND qr.id = (
                        SELECT MAX(id) FROM quantified_risks
                        WHERE scenario_id = qr.scenario_id AND org_id = qr.org_id
                    )
                    ORDER BY qr.ale_most_likely DESC
                    """,
                    (effective_org,),
                )
                rows = cursor.fetchall()
            finally:
                self._close(conn)

        if not rows:
            return {
                "org_id": effective_org,
                "total_ale_low": 0.0,
                "total_ale_most_likely": 0.0,
                "total_ale_high": 0.0,
                "total_recommended_investment": 0.0,
                "scenario_count": 0,
                "tier_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "top_scenarios": [],
            }

        total_ale_low = sum(r["ale_low"] for r in rows)
        total_ale_ml = sum(r["ale_most_likely"] for r in rows)
        total_ale_high = sum(r["ale_high"] for r in rows)
        total_investment = sum(r["recommended_investment_usd"] for r in rows)

        tier_breakdown: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for r in rows:
            tier = r["risk_tier"]
            if tier in tier_breakdown:
                tier_breakdown[tier] += 1

        top_scenarios = [
            {
                "scenario_id": r["scenario_id"],
                "name": r["name"],
                "threat_event": r["threat_event"],
                "ale_most_likely": r["ale_most_likely"],
                "risk_tier": r["risk_tier"],
            }
            for r in rows[:10]
        ]

        return {
            "org_id": effective_org,
            "total_ale_low": round(total_ale_low, 2),
            "total_ale_most_likely": round(total_ale_ml, 2),
            "total_ale_high": round(total_ale_high, 2),
            "total_recommended_investment": round(total_investment, 2),
            "scenario_count": len(rows),
            "tier_breakdown": tier_breakdown,
            "top_scenarios": top_scenarios,
        }

    def get_roi_analysis(self, org_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Investment vs risk reduction ROI analysis for an organization.

        Computes: ROI = (Risk Reduction - Control Cost) / Control Cost × 100

        Args:
            org_id: Organization ID

        Returns:
            ROI analysis with per-tier breakdowns and net benefit
        """
        effective_org = org_id or self.org_id
        portfolio = self.get_portfolio_risk(effective_org)

        total_ale = portfolio["total_ale_most_likely"]
        total_investment = portfolio["total_recommended_investment"]

        # Assume control effectiveness: 70% risk reduction
        control_effectiveness = 0.70
        risk_reduction = total_ale * control_effectiveness
        net_benefit = risk_reduction - total_investment
        roi_pct = (net_benefit / total_investment * 100) if total_investment > 0 else 0.0

        return {
            "org_id": effective_org,
            "total_annual_risk_usd": total_ale,
            "recommended_control_investment_usd": total_investment,
            "expected_risk_reduction_usd": round(risk_reduction, 2),
            "net_benefit_usd": round(net_benefit, 2),
            "roi_percent": round(roi_pct, 1),
            "control_effectiveness_assumed": control_effectiveness,
            "payback_years": round(total_investment / risk_reduction, 2) if risk_reduction > 0 else None,
            "scenario_count": portfolio["scenario_count"],
            "tier_breakdown": portfolio["tier_breakdown"],
        }

    def compare_scenarios(self, scenario_ids: List[str]) -> List[Dict[str, Any]]:
        """
        Side-by-side risk comparison for multiple scenarios.

        Args:
            scenario_ids: List of scenario IDs to compare

        Returns:
            List of comparison dicts sorted by ALE descending
        """
        results: List[Dict[str, Any]] = []

        for sid in scenario_ids:
            scenario = self.get_scenario(sid)
            if scenario is None:
                _logger.warning("Scenario not found for comparison: %s", sid)
                continue

            # Get latest quantification or run fresh
            with self._lock:
                conn = self._connect()
                conn.row_factory = sqlite3.Row
                try:
                    cursor = conn.cursor()
                    cursor.execute(
                        """
                        SELECT * FROM quantified_risks
                        WHERE scenario_id = ?
                        ORDER BY id DESC LIMIT 1
                        """,
                        (sid,),
                    )
                    row = cursor.fetchone()
                finally:
                    self._close(conn)

            if row is not None:
                qr = QuantifiedRisk(
                    scenario_id=row["scenario_id"],
                    ale_low=row["ale_low"],
                    ale_high=row["ale_high"],
                    ale_most_likely=row["ale_most_likely"],
                    risk_tier=row["risk_tier"],
                    recommended_investment_usd=row["recommended_investment_usd"],
                )
            else:
                qr = self._run_monte_carlo(scenario)

            results.append(
                {
                    "scenario_id": scenario.id,
                    "name": scenario.name,
                    "threat_event": scenario.threat_event,
                    "asset_value_usd": scenario.asset_value_usd,
                    "ale_low": qr.ale_low,
                    "ale_most_likely": qr.ale_most_likely,
                    "ale_high": qr.ale_high,
                    "risk_tier": qr.risk_tier,
                    "recommended_investment_usd": qr.recommended_investment_usd,
                }
            )

        results.sort(key=lambda x: x["ale_most_likely"], reverse=True)
        return results

    def get_risk_heatmap(self, org_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Probability × impact matrix data for risk heatmap visualization.

        Divides probability (0–1) and impact (USD) into 5×5 grid cells.
        Each cell contains scenario count and cumulative ALE.

        Args:
            org_id: Organization ID

        Returns:
            Heatmap grid with axes, cells, and summary statistics
        """
        effective_org = org_id or self.org_id

        with self._lock:
            conn = self._connect()
            conn.row_factory = sqlite3.Row
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT rs.probability_low, rs.probability_high,
                           rs.loss_magnitude_low, rs.loss_magnitude_high,
                           rs.name,
                           qr.ale_most_likely, qr.risk_tier
                    FROM risk_scenarios rs
                    LEFT JOIN quantified_risks qr ON rs.id = qr.scenario_id
                        AND qr.id = (
                            SELECT MAX(id) FROM quantified_risks
                            WHERE scenario_id = rs.id AND org_id = rs.org_id
                        )
                    WHERE rs.org_id = ?
                    """,
                    (effective_org,),
                )
                rows = cursor.fetchall()
            finally:
                self._close(conn)

        # 5×5 grid: probability bands × impact bands
        prob_bands = [(0.0, 0.2), (0.2, 0.4), (0.4, 0.6), (0.6, 0.8), (0.8, 1.0)]
        prob_labels = ["Very Low", "Low", "Medium", "High", "Very High"]

        # Impact bands in USD
        impact_bands = [
            (0, 10_000),
            (10_000, 100_000),
            (100_000, 500_000),
            (500_000, 2_000_000),
            (2_000_000, float("inf")),
        ]
        impact_labels = ["<$10K", "$10K–$100K", "$100K–$500K", "$500K–$2M", ">$2M"]

        # Initialize grid
        grid: List[List[Dict[str, Any]]] = [
            [{"probability_label": pl, "impact_label": il, "scenario_count": 0, "total_ale": 0.0}
             for il in impact_labels]
            for pl in prob_labels
        ]

        for row in rows:
            mid_prob = (row["probability_low"] + row["probability_high"]) / 2.0
            mid_impact = (row["loss_magnitude_low"] + row["loss_magnitude_high"]) / 2.0
            ale = row["ale_most_likely"] or 0.0

            # Find probability band
            p_idx = 0
            for i, (lo, hi) in enumerate(prob_bands):
                if lo <= mid_prob < hi or (i == len(prob_bands) - 1 and mid_prob >= lo):
                    p_idx = i
                    break

            # Find impact band
            i_idx = 0
            for i, (lo, hi) in enumerate(impact_bands):
                if lo <= mid_impact < hi:
                    i_idx = i
                    break

            grid[p_idx][i_idx]["scenario_count"] += 1
            grid[p_idx][i_idx]["total_ale"] += ale

        # Flatten and round
        cells = []
        for p_idx, row_cells in enumerate(grid):
            for i_idx, cell in enumerate(row_cells):
                cells.append(
                    {
                        "probability_band": p_idx,
                        "impact_band": i_idx,
                        "probability_label": prob_labels[p_idx],
                        "impact_label": impact_labels[i_idx],
                        "scenario_count": cell["scenario_count"],
                        "total_ale": round(cell["total_ale"], 2),
                    }
                )

        return {
            "org_id": effective_org,
            "probability_labels": prob_labels,
            "impact_labels": impact_labels,
            "cells": cells,
            "total_scenarios": len(rows),
        }

    def list_scenarios(self, org_id: Optional[str] = None) -> List[RiskScenario]:
        """List all scenarios for an organization."""
        effective_org = org_id or self.org_id

        with self._lock:
            conn = self._connect()
            conn.row_factory = sqlite3.Row
            try:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT * FROM risk_scenarios WHERE org_id = ? ORDER BY rowid DESC",
                    (effective_org,),
                )
                rows = cursor.fetchall()
            finally:
                self._close(conn)

        return [
            RiskScenario(
                id=r["id"],
                name=r["name"],
                threat_event=r["threat_event"],
                asset_value_usd=r["asset_value_usd"],
                loss_magnitude_low=r["loss_magnitude_low"],
                loss_magnitude_high=r["loss_magnitude_high"],
                probability_low=r["probability_low"],
                probability_high=r["probability_high"],
                annual_loss_expectancy=r["annual_loss_expectancy"],
                org_id=r["org_id"],
            )
            for r in rows
        ]


# ============================================================================
# MODULE-LEVEL SINGLETON (lazy)
# ============================================================================

_instance: Optional[RiskQuantifier] = None
_instance_lock = threading.Lock()


def get_risk_quantifier(db_path: str = "risk_quantifier.db") -> RiskQuantifier:
    """Return module-level singleton RiskQuantifier."""
    global _instance
    with _instance_lock:
        if _instance is None:
            _instance = RiskQuantifier(db_path=db_path)
    return _instance


__all__ = [
    "RiskScenario",
    "QuantifiedRisk",
    "RiskQuantifier",
    "get_risk_quantifier",
    "ASSET_VALUE_TEMPLATES",
    "SEVERITY_PROBABILITY",
    "SEVERITY_LOSS_FRACTION",
]
