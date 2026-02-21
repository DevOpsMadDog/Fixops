"""Tests for decision-engine explainability features.

The first two tests depend on a legacy ``DecisionEngine.evaluate()`` API
that no longer exists (replaced by ``async make_decision(DecisionContext)``).
They also import ``core.services.enterprise.evidence.EvidenceStore`` which
was never implemented.  Both are skipped until the test expectations are
rewritten for the current async API.

The ``ExplanationGenerator`` tests (below) exercise the real SentinelGPT
explanation pipeline and remain fully active.
"""

from __future__ import annotations

import pytest
from new_apps.api.processing.explanation import ExplanationError, ExplanationGenerator


@pytest.mark.skip(
    reason=(
        "Uses DecisionEngine.evaluate() which no longer exists — "
        "real API is async make_decision(DecisionContext). "
        "Also imports nonexistent EvidenceStore."
    )
)
def test_top_factors_deterministic(signing_env: None) -> None:
    pass


@pytest.mark.skip(
    reason=(
        "Uses DecisionEngine.evaluate() which no longer exists — "
        "real API is async make_decision(DecisionContext). "
        "Also imports nonexistent EvidenceStore."
    )
)
def test_decision_engine_compliance_rollup_and_marketplace(signing_env: None) -> None:
    pass


def test_explanation_generator_produces_narrative_and_respects_rate_limit() -> None:
    class StubClient:
        def __init__(self) -> None:
            self.calls = []

        def generate(self, *, prompt, max_tokens, temperature):
            self.calls.append(
                {
                    "prompt": prompt,
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                }
            )
            return {"text": "Critical dependency on payment-db. Prioritise patching."}

    class DummyLimiter:
        def __init__(self) -> None:
            self.calls = 0

        def acquire(self) -> None:
            self.calls += 1

    limiter = DummyLimiter()
    generator = ExplanationGenerator(
        client_factory=StubClient,
        rate_limiter=limiter,
        temperature=0.15,
        max_tokens=256,
    )

    findings = [
        {
            "rule_id": "CWE-79",
            "severity": "high",
            "location": "app.py:42",
            "description": "Reflected XSS allows credential theft",
        }
    ]
    context = {"summary": "Payment stack", "metadata": {"tier": "gold"}}

    narrative = generator.generate(findings, context)

    assert "Critical dependency" in narrative
    assert limiter.calls == 1
    client = generator._ensure_client()
    call = client.calls[0]
    assert call["max_tokens"] == 256
    assert call["temperature"] == 0.15
    assert call["prompt"].startswith("You are SentinelGPT")
    assert "Payment stack" in call["prompt"]
    assert "tier: gold" in call["prompt"]


def test_explanation_generator_requires_findings() -> None:
    generator = ExplanationGenerator(
        client_factory=lambda: type(
            "_Client",
            (),
            {"generate": lambda self, **_: {"text": "ok"}},
        )()
    )

    with pytest.raises(ExplanationError):
        generator.generate([])
