"""Monte Carlo Risk Quantification Engine for ALdeci.

This module implements FAIR-compliant Monte Carlo simulation for
quantified financial risk assessment of vulnerabilities.

Features:
- FAIR (Factor Analysis of Information Risk) model integration
- Monte Carlo simulation with configurable iterations
- Value at Risk (VaR) calculation
- Loss exceedance curves
- Confidence intervals for breach probability
- Portfolio-level aggregate risk
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

import numpy as np


class RiskCategory(Enum):
    """FAIR risk categories."""

    CONFIDENTIALITY = "confidentiality"
    INTEGRITY = "integrity"
    AVAILABILITY = "availability"
    FRAUD = "fraud"
    REPUTATION = "reputation"
    REGULATORY = "regulatory"


class ThreatCapability(Enum):
    """Threat actor capability levels."""

    SCRIPT_KIDDIE = "script_kiddie"
    OPPORTUNIST = "opportunist"
    ORGANIZED_CRIME = "organized_crime"
    NATION_STATE = "nation_state"
    INSIDER = "insider"


@dataclass
class FAIRInputs:
    """Input parameters for FAIR risk model."""

    # Threat Event Frequency (TEF) - how often threat actors attempt
    tef_min: float = 0.1  # Minimum attempts per year
    tef_max: float = 10.0  # Maximum attempts per year
    tef_mode: float = 2.0  # Most likely attempts per year

    # Vulnerability (probability of success given attempt)
    vuln_min: float = 0.1
    vuln_max: float = 0.9
    vuln_mode: float = 0.5

    # Loss Magnitude parameters (in dollars)
    primary_loss_min: float = 10000
    primary_loss_max: float = 1000000
    primary_loss_mode: float = 100000

    secondary_loss_min: float = 50000
    secondary_loss_max: float = 5000000
    secondary_loss_mode: float = 500000

    # Secondary Loss Event Frequency (SLEF)
    slef_probability: float = 0.3  # Probability of secondary loss

    # Asset value (for context)
    asset_value: float = 1000000


@dataclass
class MonteCarloResult:
    """Result of Monte Carlo simulation."""

    # Core statistics
    mean_annual_loss: float
    median_annual_loss: float
    std_annual_loss: float

    # Value at Risk
    var_90: float  # 90th percentile
    var_95: float  # 95th percentile
    var_99: float  # 99th percentile

    # Loss exceedance probabilities
    prob_exceed_100k: float
    prob_exceed_500k: float
    prob_exceed_1m: float
    prob_exceed_5m: float

    # Breach probability
    breach_probability: float
    breach_probability_ci_lower: float
    breach_probability_ci_upper: float

    # Distribution data (for visualization)
    loss_distribution: List[float] = field(default_factory=list)
    percentiles: Dict[int, float] = field(default_factory=dict)

    # Simulation metadata
    iterations: int = 10000
    execution_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "mean_annual_loss": round(self.mean_annual_loss, 2),
            "median_annual_loss": round(self.median_annual_loss, 2),
            "std_annual_loss": round(self.std_annual_loss, 2),
            "value_at_risk": {
                "var_90": round(self.var_90, 2),
                "var_95": round(self.var_95, 2),
                "var_99": round(self.var_99, 2),
            },
            "loss_exceedance": {
                "prob_exceed_100k": round(self.prob_exceed_100k, 4),
                "prob_exceed_500k": round(self.prob_exceed_500k, 4),
                "prob_exceed_1m": round(self.prob_exceed_1m, 4),
                "prob_exceed_5m": round(self.prob_exceed_5m, 4),
            },
            "breach_probability": {
                "estimate": round(self.breach_probability, 4),
                "ci_lower": round(self.breach_probability_ci_lower, 4),
                "ci_upper": round(self.breach_probability_ci_upper, 4),
            },
            "percentiles": {str(k): round(v, 2) for k, v in self.percentiles.items()},
            "iterations": self.iterations,
            "execution_time_ms": round(self.execution_time_ms, 2),
        }


class MonteCarloRiskEngine:
    """FAIR-compliant Monte Carlo risk simulation engine.

    This engine uses the Factor Analysis of Information Risk (FAIR)
    methodology to quantify cyber risk in financial terms.

    The simulation models:
    1. Threat Event Frequency (TEF) - How often attacks occur
    2. Vulnerability - Probability an attack succeeds
    3. Loss Event Frequency (LEF) = TEF × Vulnerability
    4. Primary Loss Magnitude - Direct costs (response, recovery)
    5. Secondary Loss Magnitude - Indirect costs (reputation, regulatory)
    6. Annual Loss Expectancy (ALE) - Expected yearly loss
    """

    def __init__(
        self,
        iterations: int = 10000,
        seed: Optional[int] = None,
    ):
        """Initialize Monte Carlo engine.

        Args:
            iterations: Number of simulation iterations (default 10000)
            seed: Random seed for reproducibility
        """
        self.iterations = iterations
        self.rng = np.random.default_rng(seed)

    def _sample_pert(
        self,
        minimum: float,
        maximum: float,
        mode: float,
        size: int = 1,
    ) -> np.ndarray:
        """Sample from PERT distribution (commonly used in risk analysis).

        PERT (Program Evaluation and Review Technique) distribution is
        a modified beta distribution that's more intuitive for experts
        to parameterize with min, max, and most likely values.
        """
        # Calculate PERT parameters
        if maximum <= minimum:
            return np.full(size, minimum)

        # Lambda parameter (typically 4 for standard PERT)
        lam = 4.0

        # Mean of PERT distribution
        mean = (minimum + lam * mode + maximum) / (lam + 2)

        # Alpha and beta for underlying beta distribution
        if mode == mean:
            alpha = beta = 3.0
        else:
            alpha = ((mean - minimum) * (2 * mode - minimum - maximum)) / (
                (mode - mean) * (maximum - minimum)
            )
            beta = alpha * (maximum - mean) / (mean - minimum)

        # Ensure valid parameters
        alpha = max(0.1, alpha)
        beta = max(0.1, beta)

        # Sample from beta and scale to [min, max]
        samples = self.rng.beta(alpha, beta, size=size)
        return minimum + samples * (maximum - minimum)

    def _sample_lognormal(
        self,
        mean: float,
        std: float,
        size: int = 1,
    ) -> np.ndarray:
        """Sample from lognormal distribution (for loss magnitudes)."""
        if mean <= 0:
            return np.zeros(size)

        # Convert normal mean/std to lognormal parameters
        variance = std**2
        mu = np.log(mean**2 / np.sqrt(variance + mean**2))
        sigma = np.sqrt(np.log(1 + variance / mean**2))

        return self.rng.lognormal(mu, sigma, size=size)

    def simulate(
        self,
        inputs: FAIRInputs,
        include_distribution: bool = False,
    ) -> MonteCarloResult:
        """Run Monte Carlo simulation for risk quantification.

        Args:
            inputs: FAIR model input parameters
            include_distribution: Whether to include full loss distribution

        Returns:
            MonteCarloResult with quantified risk metrics
        """
        import time

        start = time.perf_counter()

        n = self.iterations

        # Sample Threat Event Frequency (PERT distribution)
        tef_samples = self._sample_pert(
            inputs.tef_min,
            inputs.tef_max,
            inputs.tef_mode,
            size=n,
        )

        # Sample Vulnerability (PERT distribution)
        vuln_samples = self._sample_pert(
            inputs.vuln_min,
            inputs.vuln_max,
            inputs.vuln_mode,
            size=n,
        )

        # Calculate Loss Event Frequency
        lef_samples = tef_samples * vuln_samples

        # For each iteration, simulate whether a loss event occurs
        annual_losses = np.zeros(n)
        breach_count = 0

        for i in range(n):
            # Number of loss events this year (Poisson with rate LEF)
            num_events = self.rng.poisson(lef_samples[i])

            if num_events > 0:
                breach_count += 1

                # Calculate total loss for this year
                year_loss = 0.0

                for _ in range(num_events):
                    # Primary loss (always occurs)
                    primary_loss = self._sample_pert(
                        inputs.primary_loss_min,
                        inputs.primary_loss_max,
                        inputs.primary_loss_mode,
                        size=1,
                    )[0]
                    year_loss += primary_loss

                    # Secondary loss (probabilistic)
                    if self.rng.random() < inputs.slef_probability:
                        secondary_loss = self._sample_pert(
                            inputs.secondary_loss_min,
                            inputs.secondary_loss_max,
                            inputs.secondary_loss_mode,
                            size=1,
                        )[0]
                        year_loss += secondary_loss

                annual_losses[i] = year_loss

        # Calculate statistics
        mean_loss = float(np.mean(annual_losses))
        median_loss = float(np.median(annual_losses))
        std_loss = float(np.std(annual_losses))

        # Value at Risk (percentiles)
        var_90 = float(np.percentile(annual_losses, 90))
        var_95 = float(np.percentile(annual_losses, 95))
        var_99 = float(np.percentile(annual_losses, 99))

        # Loss exceedance probabilities
        prob_100k = float(np.mean(annual_losses > 100000))
        prob_500k = float(np.mean(annual_losses > 500000))
        prob_1m = float(np.mean(annual_losses > 1000000))
        prob_5m = float(np.mean(annual_losses > 5000000))

        # Breach probability with confidence interval
        breach_prob = breach_count / n
        # Wilson score interval for binomial proportion
        z = 1.96  # 95% confidence
        denominator = 1 + z**2 / n
        center = (breach_prob + z**2 / (2 * n)) / denominator
        margin = (
            z
            * np.sqrt((breach_prob * (1 - breach_prob) + z**2 / (4 * n)) / n)
            / denominator
        )
        ci_lower = max(0, center - margin)
        ci_upper = min(1, center + margin)

        # Percentiles for distribution
        percentiles = {
            5: float(np.percentile(annual_losses, 5)),
            10: float(np.percentile(annual_losses, 10)),
            25: float(np.percentile(annual_losses, 25)),
            50: float(np.percentile(annual_losses, 50)),
            75: float(np.percentile(annual_losses, 75)),
            90: float(np.percentile(annual_losses, 90)),
            95: float(np.percentile(annual_losses, 95)),
            99: float(np.percentile(annual_losses, 99)),
        }

        execution_time = (time.perf_counter() - start) * 1000

        return MonteCarloResult(
            mean_annual_loss=mean_loss,
            median_annual_loss=median_loss,
            std_annual_loss=std_loss,
            var_90=var_90,
            var_95=var_95,
            var_99=var_99,
            prob_exceed_100k=prob_100k,
            prob_exceed_500k=prob_500k,
            prob_exceed_1m=prob_1m,
            prob_exceed_5m=prob_5m,
            breach_probability=breach_prob,
            breach_probability_ci_lower=ci_lower,
            breach_probability_ci_upper=ci_upper,
            loss_distribution=annual_losses.tolist() if include_distribution else [],
            percentiles=percentiles,
            iterations=n,
            execution_time_ms=execution_time,
        )

    def simulate_from_cvss(
        self,
        cvss_score: float,
        asset_value: float = 1000000,
        has_exploit: bool = False,
        is_internet_facing: bool = False,
        industry: str = "technology",
    ) -> MonteCarloResult:
        """Derive FAIR inputs from CVSS score and context.

        This is a convenience method that maps CVSS scores and contextual
        factors to FAIR model parameters for simulation.
        """
        # Map CVSS to vulnerability probability
        vuln_mode = cvss_score / 10.0
        vuln_min = max(0.1, vuln_mode - 0.2)
        vuln_max = min(0.95, vuln_mode + 0.2)

        # Adjust for exploit availability
        if has_exploit:
            vuln_mode = min(0.95, vuln_mode + 0.2)
            vuln_max = min(0.98, vuln_max + 0.2)

        # Map to threat event frequency
        base_tef = 1.0  # 1 attack attempt per year baseline
        if is_internet_facing:
            base_tef *= 5.0
        if cvss_score >= 9.0:
            base_tef *= 3.0
        elif cvss_score >= 7.0:
            base_tef *= 2.0

        tef_mode = base_tef
        tef_min = base_tef * 0.2
        tef_max = base_tef * 5.0

        # Industry-specific loss multipliers
        industry_multipliers = {
            "healthcare": 1.5,
            "finance": 2.0,
            "technology": 1.0,
            "retail": 0.8,
            "manufacturing": 0.7,
            "government": 1.3,
        }
        multiplier = industry_multipliers.get(industry.lower(), 1.0)

        # Calculate loss magnitudes based on asset value
        primary_loss_mode = asset_value * 0.1 * multiplier
        primary_loss_min = primary_loss_mode * 0.2
        primary_loss_max = primary_loss_mode * 5.0

        secondary_loss_mode = asset_value * 0.5 * multiplier
        secondary_loss_min = secondary_loss_mode * 0.2
        secondary_loss_max = secondary_loss_mode * 3.0

        inputs = FAIRInputs(
            tef_min=tef_min,
            tef_max=tef_max,
            tef_mode=tef_mode,
            vuln_min=vuln_min,
            vuln_max=vuln_max,
            vuln_mode=vuln_mode,
            primary_loss_min=primary_loss_min,
            primary_loss_max=primary_loss_max,
            primary_loss_mode=primary_loss_mode,
            secondary_loss_min=secondary_loss_min,
            secondary_loss_max=secondary_loss_max,
            secondary_loss_mode=secondary_loss_mode,
            slef_probability=0.3 if cvss_score >= 7.0 else 0.15,
            asset_value=asset_value,
        )

        return self.simulate(inputs)

    def portfolio_risk(
        self,
        vulnerability_results: List[MonteCarloResult],
        correlation: float = 0.3,
    ) -> Dict[str, Any]:
        """Calculate portfolio-level aggregate risk.

        Args:
            vulnerability_results: List of individual vulnerability simulations
            correlation: Assumed correlation between vulnerabilities (0-1)

        Returns:
            Portfolio risk metrics including VaR and diversification benefit
        """
        if not vulnerability_results:
            return {"error": "No vulnerability results provided"}

        n = len(vulnerability_results)

        # Sum of individual risks
        sum_mean = sum(r.mean_annual_loss for r in vulnerability_results)
        sum_var95 = sum(r.var_95 for r in vulnerability_results)

        # Portfolio variance considering correlation
        # Using simplified correlation model
        individual_vars = [r.std_annual_loss**2 for r in vulnerability_results]

        # Portfolio variance = sum of variances + 2*sum of covariances
        portfolio_variance = sum(individual_vars)
        for i in range(n):
            for j in range(i + 1, n):
                covariance = (
                    correlation
                    * np.sqrt(individual_vars[i])
                    * np.sqrt(individual_vars[j])
                )
                portfolio_variance += 2 * covariance

        portfolio_std = np.sqrt(portfolio_variance)

        # Approximate portfolio VaR (assuming normal distribution)
        z_95 = 1.645
        portfolio_var95 = sum_mean + z_95 * portfolio_std

        # Diversification benefit
        diversification_benefit = (
            (sum_var95 - portfolio_var95) / sum_var95 if sum_var95 > 0 else 0
        )

        return {
            "num_vulnerabilities": n,
            "aggregate_mean_annual_loss": round(sum_mean, 2),
            "aggregate_std": round(portfolio_std, 2),
            "portfolio_var_95": round(portfolio_var95, 2),
            "undiversified_var_95": round(sum_var95, 2),
            "diversification_benefit": round(diversification_benefit, 4),
            "correlation_assumed": correlation,
        }


# Convenience functions for API use
def quantify_vulnerability_risk(
    cvss_score: float,
    asset_value: float = 1000000,
    has_exploit: bool = False,
    is_internet_facing: bool = False,
    industry: str = "technology",
    iterations: int = 10000,
) -> Dict[str, Any]:
    """Quantify financial risk for a single vulnerability.

    Args:
        cvss_score: CVSS score (0-10)
        asset_value: Estimated value of affected asset in dollars
        has_exploit: Whether a known exploit exists
        is_internet_facing: Whether the vulnerable asset is internet-exposed
        industry: Industry vertical for loss estimation
        iterations: Number of Monte Carlo iterations

    Returns:
        Dictionary with quantified risk metrics
    """
    engine = MonteCarloRiskEngine(iterations=iterations)
    result = engine.simulate_from_cvss(
        cvss_score=cvss_score,
        asset_value=asset_value,
        has_exploit=has_exploit,
        is_internet_facing=is_internet_facing,
        industry=industry,
    )
    return result.to_dict()


def quantify_cve_risk(
    cve_id: str,
    cvss_score: float,
    epss_score: float = 0.0,
    kev_listed: bool = False,
    asset_value: float = 1000000,
    is_reachable: bool = True,
) -> Dict[str, Any]:
    """Quantify financial risk for a specific CVE.

    Args:
        cve_id: CVE identifier
        cvss_score: CVSS score
        epss_score: EPSS score (0-1)
        kev_listed: Whether CVE is in CISA KEV catalog
        asset_value: Affected asset value
        is_reachable: Whether vulnerable code is reachable

    Returns:
        Risk quantification with CVE context
    """
    engine = MonteCarloRiskEngine(iterations=10000)

    # Build FAIR inputs based on CVE intelligence
    has_exploit = kev_listed or epss_score > 0.5

    result = engine.simulate_from_cvss(
        cvss_score=cvss_score,
        asset_value=asset_value,
        has_exploit=has_exploit,
        is_internet_facing=is_reachable,
    )

    output = result.to_dict()
    output["cve_id"] = cve_id
    output["context"] = {
        "epss_score": epss_score,
        "kev_listed": kev_listed,
        "is_reachable": is_reachable,
        "exploit_likely": has_exploit,
    }

    return output
