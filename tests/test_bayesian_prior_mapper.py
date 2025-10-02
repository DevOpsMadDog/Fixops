"""Unit tests for the Bayesian prior mapper using pgmpy inference."""

import math

from pomegranate.distributions import DiscreteDistribution

from fixops.bayesian import BayesianPriorMapper


def build_network():
    edges = [("threat", "risk"), ("exploit", "risk")]
    threat_dist = DiscreteDistribution({"low": 0.7, "high": 0.3})
    exploit_dist = DiscreteDistribution({"low": 0.8, "high": 0.2})
    risk_conditional = {
        ("low", "low"): {"low": 0.9, "medium": 0.08, "high": 0.02},
        ("low", "high"): {"low": 0.6, "medium": 0.3, "high": 0.1},
        ("high", "low"): {"low": 0.5, "medium": 0.4, "high": 0.1},
        ("high", "high"): {"low": 0.1, "medium": 0.3, "high": 0.6},
    }
    cpds = {
        "threat": threat_dist,
        "exploit": exploit_dist,
        "risk": risk_conditional,
    }
    return edges, cpds


def test_update_probabilities_returns_expected_posteriors():
    mapper = BayesianPriorMapper(risk_node="risk")
    edges, cpds = build_network()
    component_evidence = {
        "api": {"threat": "high", "exploit": "high"},
        "database": {"threat": "low", "exploit": "low"},
    }

    posteriors = mapper.update_probabilities(edges, cpds, component_evidence)

    assert set(posteriors) == {"api", "database"}
    api_posterior = posteriors["api"].distribution
    db_posterior = posteriors["database"].distribution

    assert api_posterior == {"low": 0.1, "medium": 0.3, "high": 0.6}
    assert db_posterior == {"low": 0.9, "medium": 0.08, "high": 0.02}
    assert posteriors["api"].most_likely == "high"
    assert math.isclose(posteriors["api"].expected_risk, 0.7, rel_tol=1e-6)
    assert math.isclose(posteriors["database"].expected_risk, 0.148, rel_tol=1e-6)


def test_attach_component_posterior_includes_scores():
    mapper = BayesianPriorMapper(risk_node="risk")
    edges, cpds = build_network()
    mapper.update_probabilities(
        edges,
        cpds,
        {
            "api": {"threat": "high", "exploit": "high"},
            "database": {"threat": "low", "exploit": "low"},
        },
    )

    enriched = mapper.attach_component_posterior(
        {"id": "VULN-1", "component": "api", "severity": "critical"}
    )
    assert enriched["bayesian_most_likely_state"] == "high"
    assert math.isclose(enriched["bayesian_expected_risk"], 0.7, rel_tol=1e-6)
    assert math.isclose(enriched["bayesian_score"], 0.7, rel_tol=1e-6)

    medium_enriched = mapper.attach_component_posterior(
        {"id": "VULN-2", "component": "database", "severity": "medium"}
    )
    assert math.isclose(medium_enriched["bayesian_expected_risk"], 0.148, rel_tol=1e-6)
    assert math.isclose(medium_enriched["bayesian_score"], 0.074, rel_tol=1e-6)
