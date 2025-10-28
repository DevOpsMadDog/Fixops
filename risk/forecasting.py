"""Probabilistic forecasting for CVE exploitation using Bayesian and Markov models."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional

from risk.enrichment import EnrichmentEvidence

logger = logging.getLogger(__name__)


@dataclass
class ForecastResult:
    """Forecast result for CVE exploitation probability."""

    cve_id: str
    p_exploit_now: float
    p_exploit_30d: float
    evidence_breakdown: Dict[str, Any] = field(default_factory=dict)
    method: str = "naive_bayes"
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "cve_id": self.cve_id,
            "p_exploit_now": round(self.p_exploit_now, 4),
            "p_exploit_30d": round(self.p_exploit_30d, 4),
            "evidence_breakdown": dict(self.evidence_breakdown),
            "method": self.method,
            "confidence": round(self.confidence, 3),
        }


def _apply_likelihood_ratio(probability: float, likelihood_ratio: float) -> float:
    """Apply likelihood ratio using correct Bayesian odds update.

    Parameters
    ----------
    probability:
        Current probability (must be in range (0, 1)).
    likelihood_ratio:
        Likelihood ratio to apply.

    Returns
    -------
    float
        Updated probability after applying likelihood ratio.
    """
    epsilon = 1e-6
    p = max(epsilon, min(1.0 - epsilon, probability))

    odds = p / (1.0 - p)
    new_odds = odds * likelihood_ratio
    new_probability = new_odds / (1.0 + new_odds)

    return max(epsilon, min(1.0 - epsilon, new_probability))


def _naive_bayes_update(
    prior: float,
    evidence: EnrichmentEvidence,
    config: Optional[Mapping[str, Any]] = None,
) -> tuple[float, Dict[str, Any]]:
    """Update exploitation probability using Naive Bayes.

    Parameters
    ----------
    prior:
        Prior probability (typically EPSS score or baseline).
    evidence:
        Enrichment evidence for the CVE.
    config:
        Optional configuration with likelihood ratios.

    Returns
    -------
    tuple[float, Dict[str, Any]]
        Updated probability and evidence breakdown.
    """
    config = config or {}

    likelihood_ratios = {
        "kev_listed": config.get("kev_likelihood", 5.0),
        "exploitdb_refs": config.get("exploitdb_likelihood", 3.0),
        "high_cvss": config.get("high_cvss_likelihood", 2.0),
        "vendor_advisory": config.get("vendor_advisory_likelihood", 0.7),
        "old_vulnerability": config.get("old_vuln_likelihood", 1.5),
    }

    posterior = prior
    breakdown: Dict[str, Any] = {
        "prior": round(prior, 4),
        "signals_applied": [],
    }

    if evidence.kev_listed:
        posterior = _apply_likelihood_ratio(posterior, likelihood_ratios["kev_listed"])
        breakdown["signals_applied"].append(
            {
                "signal": "kev_listed",
                "likelihood_ratio": likelihood_ratios["kev_listed"],
                "posterior_after": round(posterior, 4),
            }
        )

    if evidence.exploitdb_refs > 0:
        ratio = (
            likelihood_ratios["exploitdb_refs"] * min(evidence.exploitdb_refs, 3) / 3
        )
        posterior = _apply_likelihood_ratio(posterior, ratio)
        breakdown["signals_applied"].append(
            {
                "signal": "exploitdb_refs",
                "count": evidence.exploitdb_refs,
                "likelihood_ratio": round(ratio, 2),
                "posterior_after": round(posterior, 4),
            }
        )

    if evidence.cvss_score is not None and evidence.cvss_score >= 7.0:
        posterior = _apply_likelihood_ratio(posterior, likelihood_ratios["high_cvss"])
        breakdown["signals_applied"].append(
            {
                "signal": "high_cvss",
                "cvss_score": evidence.cvss_score,
                "likelihood_ratio": likelihood_ratios["high_cvss"],
                "posterior_after": round(posterior, 4),
            }
        )

    if evidence.has_vendor_advisory:
        posterior = _apply_likelihood_ratio(
            posterior, likelihood_ratios["vendor_advisory"]
        )
        breakdown["signals_applied"].append(
            {
                "signal": "vendor_advisory",
                "likelihood_ratio": likelihood_ratios["vendor_advisory"],
                "posterior_after": round(posterior, 4),
            }
        )

    if evidence.age_days is not None and evidence.age_days > 365:
        posterior = _apply_likelihood_ratio(
            posterior, likelihood_ratios["old_vulnerability"]
        )
        breakdown["signals_applied"].append(
            {
                "signal": "old_vulnerability",
                "age_days": evidence.age_days,
                "likelihood_ratio": likelihood_ratios["old_vulnerability"],
                "posterior_after": round(posterior, 4),
            }
        )

    epsilon = 1e-6
    posterior = max(epsilon, min(1.0 - epsilon, posterior))
    breakdown["final_posterior"] = round(posterior, 4)

    return posterior, breakdown


def _markov_forecast_30d(
    p_now: float,
    evidence: EnrichmentEvidence,
    config: Optional[Mapping[str, Any]] = None,
) -> float:
    """Forecast 30-day exploitation probability using Markov model.

    Parameters
    ----------
    p_now:
        Current exploitation probability.
    evidence:
        Enrichment evidence for the CVE.
    config:
        Optional configuration with transition rates.

    Returns
    -------
    float
        Probability of exploitation within 30 days.
    """
    config = config or {}

    lambda_ux_to_ex = config.get("lambda_ux_to_ex", 0.01)  # Unexploited → Exploited
    lambda_ux_to_mit = config.get("lambda_ux_to_mit", 0.03)  # Unexploited → Mitigated

    if evidence.kev_listed:
        lambda_ux_to_ex = 0.05  # 5% per day if KEV-listed
    elif evidence.epss_score is not None and evidence.epss_score >= 0.7:
        lambda_ux_to_ex += 0.02  # Boost by 2% if high EPSS

    if evidence.has_vendor_advisory:
        lambda_ux_to_mit = 0.10  # 10% per day if patch available
        lambda_ux_to_ex *= 0.5  # Reduce exploitation rate if patch available

    days = 30
    total_rate = lambda_ux_to_ex + lambda_ux_to_mit

    if total_rate > 0:
        p_transition = 1.0 - (1.0 - total_rate) ** days

        p_exploit_given_transition = lambda_ux_to_ex / total_rate

        p_exploit_30d = p_transition * p_exploit_given_transition
    else:
        p_exploit_30d = p_now

    p_exploit_30d = max(p_now, min(0.99, p_exploit_30d))

    return p_exploit_30d


def compute_forecast(
    enrichment_map: Dict[str, EnrichmentEvidence],
    config: Optional[Mapping[str, Any]] = None,
) -> Dict[str, ForecastResult]:
    """Compute exploitation probability forecasts for all CVEs.

    Parameters
    ----------
    enrichment_map:
        Mapping of CVE ID to enrichment evidence.
    config:
        Optional configuration with likelihood ratios and transition rates.

    Returns
    -------
    Dict[str, ForecastResult]
        Mapping of CVE ID to forecast result.
    """
    config = config or {}
    forecast_map: Dict[str, ForecastResult] = {}

    for cve_id, evidence in enrichment_map.items():
        if evidence.epss_score is not None:
            prior = evidence.epss_score
        elif evidence.kev_listed:
            prior = 0.5  # High baseline if KEV-listed but no EPSS
        else:
            prior = 0.1  # Default baseline

        p_exploit_now, breakdown = _naive_bayes_update(prior, evidence, config)

        p_exploit_30d = _markov_forecast_30d(p_exploit_now, evidence, config)

        confidence = 0.5  # Base confidence
        if evidence.epss_score is not None:
            confidence += 0.2  # EPSS available
        if evidence.kev_listed:
            confidence += 0.2  # KEV-listed (high confidence)
        if evidence.cvss_score is not None:
            confidence += 0.1  # CVSS available
        confidence = min(0.95, confidence)

        forecast = ForecastResult(
            cve_id=cve_id,
            p_exploit_now=p_exploit_now,
            p_exploit_30d=p_exploit_30d,
            evidence_breakdown=breakdown,
            method="naive_bayes_markov",
            confidence=confidence,
        )

        forecast_map[cve_id] = forecast

    logger.info(
        "Computed forecasts for %d CVEs: avg p_now=%.3f, avg p_30d=%.3f",
        len(forecast_map),
        sum(f.p_exploit_now for f in forecast_map.values()) / len(forecast_map)
        if forecast_map
        else 0,
        sum(f.p_exploit_30d for f in forecast_map.values()) / len(forecast_map)
        if forecast_map
        else 0,
    )

    return forecast_map


__all__ = ["ForecastResult", "compute_forecast"]
