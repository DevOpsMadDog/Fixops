"""SPEC-032 — real-moat LIVE: the council makes REAL paid LLM calls (cost>0).

This is the only test that proves the $100K moat actually runs: it builds the real
5-member OpenRouter council and convenes it on a real finding, asserting a non-zero
paid cost and multiple distinct member reasonings. It costs money and needs network +
a live key, so it is marked `live` and runs nightly — NOT in the blocking PR gate and
NOT air-gap compatible. See test_real_moat_e2e.py for the CI-safe counterpart.

Run: pytest -m live tests/test_real_moat_live.py
"""

from __future__ import annotations

import os

import pytest

pytestmark = pytest.mark.live

_LIVE_KEYS = ("OPENROUTER_API_KEY", "FIXOPS_LLM_API_KEY", "MULEROUTER_API_KEY", "ANTHROPIC_API_KEY")


def _has_live_key() -> bool:
    return any((os.environ.get(k) or "").strip() for k in _LIVE_KEYS)


@pytest.mark.skipif(not _has_live_key(), reason="no live LLM key — real-moat live test needs real OpenRouter/Anthropic")
def test_council_makes_real_paid_calls_with_distinct_reasoning():
    from core.llm_council import CouncilFactory
    from core.llm_providers import CouncilNotConfiguredError

    try:
        council = CouncilFactory().create_default_council()
    except CouncilNotConfiguredError:
        pytest.skip("council not configured despite key present")

    finding = {
        "title": "SQL Injection in login handler",
        "severity": "high",
        "cve_id": "CVE-2021-44228",
        "cwe": "CWE-89",
        "description": "User input concatenated into a SQL query in the auth path.",
    }
    context = {"service_name": "auth-service", "risk_score": 80, "internet_facing": True}

    verdict = council.convene(finding, context, org_id="real-moat-live")

    # Real paid inference happened — deterministic/placeholder paths report cost 0.
    assert verdict.cost_usd > 0, (
        f"council made no real paid call (cost_usd={verdict.cost_usd}); it is not running live inference"
    )
    # Multiple members produced genuinely distinct reasoning (not one echoed verdict).
    analyses = getattr(verdict, "raw_analyses", None) or []
    reasonings = {(getattr(a, "reasoning", "") or "").strip() for a in analyses}
    reasonings.discard("")
    assert len(reasonings) >= 2, (
        f"expected >=2 distinct member reasonings from a real council, got {len(reasonings)}"
    )
    assert (verdict.reasoning or "").strip(), "chairman synthesis reasoning is empty"
