"""Validate Processing Layer fallbacks when scientific libraries are unavailable.

NOTE: this suite targets the legacy ``archive.enterprise_legacy.src.services.
processing_layer`` module (classes BayesianPriorMapping / MarkovTransitionMatrix
Builder / SSVCContext / MarkovState). That archive tree was removed; the current
implementation is ``core.processing_layer`` with a different API
(ProcessingLayer / BayesianNetwork / Mapping / PomegranateBayes). Rewriting these
fallback assertions against the current API is a separate, larger task — until
then the suite skips cleanly rather than erroring on a missing module.
"""

from __future__ import annotations

import asyncio
import importlib
from datetime import datetime, timezone

import pytest

# Skip the whole module if the legacy archive it targets is absent (it was
# removed from the tree). Prevents a hard ModuleNotFoundError collection error.
pytest.importorskip(
    "archive.enterprise_legacy.src.services.processing_layer",
    reason="legacy archive removed; current impl is core.processing_layer "
    "(different API) — fallback assertions need a rewrite against it.",
)


def test_bayesian_mapping_fallback_returns_distribution() -> None:
    module = importlib.import_module(
        "archive.enterprise_legacy.src.services.processing_layer"
    )
    importlib.reload(module)

    mapper = module.BayesianPriorMapping()
    mapper.network = None
    mapper.inference_engine = None
    context = module.SSVCContext(
        exploitation="poc",
        exposure="controlled",
        utility="efficient",
        safety_impact="marginal",
        mission_impact="crippled",
    )

    priors = asyncio.run(mapper.compute_priors(context))
    assert pytest.approx(sum(priors.values()), rel=1e-6) == 1.0
    assert set(priors) == {"critical", "high", "medium", "low"}
    assert priors["critical"] >= 0.0
    assert priors["low"] >= 0.0


def test_markov_builder_fallback_uses_epss_and_kev_bias() -> None:
    module = importlib.import_module(
        "archive.enterprise_legacy.src.services.processing_layer"
    )
    importlib.reload(module)

    builder = module.MarkovTransitionMatrixBuilder()
    builder.hmm_model = None
    state = module.MarkovState(
        current_state="vulnerable",
        cve_id="CVE-2024-1111",
        epss_score=0.95,
        kev_flag=True,
        disclosure_date=datetime(2024, 1, 1, tzinfo=timezone.utc),
    )

    result = asyncio.run(builder.predict_state_evolution([state]))
    assert result["real_mchmm_used"] is False
    assert result["predictions"]
    prediction = result["predictions"][0]
    assert (
        pytest.approx(sum(prediction["predicted_transitions"].values()), rel=1e-6)
        == 1.0
    )
    exploited_probability = prediction["predicted_transitions"]["exploited"]
    assert exploited_probability > 0.5
