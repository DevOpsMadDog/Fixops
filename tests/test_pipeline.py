"""Tests for the Bayesian component processing pipeline."""
from __future__ import annotations

import math

import pytest

from new_backend.processing.bayesian import (
    BayesianComponentNetwork,
    ComponentNode,
    attach_component_posterior,
    update_probabilities,
)


@pytest.fixture
def component_network() -> BayesianComponentNetwork:
    """Create a small Bayesian network with deterministic CPTs."""

    database = ComponentNode(
        name="database",
        states=("healthy", "degraded"),
        cpt=((0.85,), (0.15,)),
    )

    api = ComponentNode(
        name="api",
        states=("healthy", "degraded"),
        parents=("database",),
        parent_states={"database": ("healthy", "degraded")},
        cpt=(
            (0.95, 0.4),  # P(api=healthy | database)
            (0.05, 0.6),  # P(api=degraded | database)
        ),
    )

    frontend = ComponentNode(
        name="frontend",
        states=("healthy", "degraded"),
        parents=("api",),
        parent_states={"api": ("healthy", "degraded")},
        cpt=(
            (0.97, 0.3),  # P(frontend=healthy | api)
            (0.03, 0.7),  # P(frontend=degraded | api)
        ),
    )

    return BayesianComponentNetwork([database, api, frontend])


def test_bayesian_update_returns_posterior(component_network: BayesianComponentNetwork) -> None:
    """Posterior distribution reflects Bayesian inference results."""

    evidence = {"database": "degraded"}
    posteriors = update_probabilities(component_network, evidence=evidence, targets=["frontend", "api"])

    assert set(posteriors) == {"frontend", "api"}

    # Expected P(api=degraded | database=degraded) = 0.6
    assert math.isclose(posteriors["api"]["degraded"], 0.6, rel_tol=1e-6)

    # Expected P(frontend=degraded | database=degraded) = 0.03*0.4 + 0.7*0.6 = 0.432
    expected_frontend_degraded = 0.03 * 0.4 + 0.7 * 0.6
    assert math.isclose(posteriors["frontend"]["degraded"], expected_frontend_degraded, rel_tol=1e-6)
    assert math.isclose(sum(posteriors["frontend"].values()), 1.0, rel_tol=1e-9)


def test_attach_component_posterior_merges_results(component_network: BayesianComponentNetwork) -> None:
    """Attaching posteriors adds a dedicated key without mutating the input list."""

    components = [
        {"name": "frontend", "owner": "edge"},
        {"name": "api", "owner": "core"},
        {"name": "monitoring", "owner": "ops"},
    ]

    posteriors = component_network.update_probabilities(evidence={"database": "degraded"})
    enriched = attach_component_posterior(components, posteriors)

    # Ensure original components list was not mutated
    assert all("posterior" not in component for component in components)

    frontend_posterior = enriched[0]["posterior"]
    assert math.isclose(frontend_posterior["degraded"], posteriors["frontend"]["degraded"], rel_tol=1e-6)
    assert "posterior" not in enriched[2]  # No inference data for monitoring
