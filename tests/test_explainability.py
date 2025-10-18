from __future__ import annotations

import pytest
from src.services.compliance import ComplianceEngine
from src.services.decision_engine import DecisionEngine
from src.services.evidence import EvidenceStore

from new_apps.api.processing.explanation import ExplanationError, ExplanationGenerator


def test_top_factors_deterministic(signing_env: None) -> None:
    engine = DecisionEngine(EvidenceStore(), ComplianceEngine())
    payload = {
        "findings": [
            {"id": "A", "severity": "high"},
            {"id": "B", "severity": "medium"},
            {"id": "C", "severity": "low"},
        ],
        "controls": [
            {"id": "CM-1", "framework": "nist_ssdf", "status": "fail"},
            {"id": "AC-1", "framework": "iso_27001", "status": "pass"},
        ],
        "frameworks": ["nist_ssdf", "iso_27001"],
    }
    outcome = engine.evaluate(payload)
    weights = [factor["weight"] for factor in outcome.top_factors]
    assert weights == sorted(weights, reverse=True)
    names = [factor["name"] for factor in outcome.top_factors]
    assert names[0].startswith("High")
    # Re-running with the same payload should not change ordering
    outcome_again = engine.evaluate(payload)
    assert [factor["name"] for factor in outcome_again.top_factors] == names


def test_decision_engine_compliance_rollup_and_marketplace(signing_env: None) -> None:
    engine = DecisionEngine(EvidenceStore(), ComplianceEngine())
    submission = {
        "findings": [{"id": "Z", "severity": "critical"}],
        "controls": [
            {"id": "ISO27001:AC-2", "framework": "iso_27001", "status": "fail"},
            {"id": "ISO27001:AC-1", "framework": "iso_27001", "status": "partial"},
        ],
        "frameworks": ["iso_27001"],
        "deploy": {
            "control_evidence": [
                {"control": "ISO27001:AC-2", "result": "fail"},
                {"control": "ISO27001:AC-1", "result": "partial"},
            ]
        },
        "test": {"summary": {"critical": 1, "high": 0, "medium": 0, "low": 0}},
        "operate": {
            "kev_hits": ["CVE-2021-44228"],
            "pressure_by_service": [
                {"service": "life-claims-portal", "pressure": 0.65}
            ],
        },
    }
    outcome = engine.evaluate(submission)
    assert outcome.compliance_rollup[
        "controls"
    ], "Compliance rollup should include control coverage"
    assert any(factor["name"] == "Compliance gaps" for factor in outcome.top_factors)
    assert (
        outcome.marketplace_recommendations
    ), "Marketplace packs should surface for failing controls"


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
