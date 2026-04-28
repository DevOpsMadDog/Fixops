"""Tests for the LLM council preset fix — mulerouter+openrouter real consensus.

Proves:
1. With MULEROUTER_API_KEY + OPENROUTER_API_KEY present → 2 real members,
   neither of which is DeterministicLLMProvider.
2. convene() with a fixture finding produces a verdict where confidence != 0.5
   OR action != "review" (i.e. real LLM output, not the hardcoded fallback).
3. FIXOPS_COUNCIL_PRESET=mulerouter+openrouter explicitly selects the 2-member council.
4. FIXOPS_COUNCIL_PRESET=auto + only free-tier keys → same 2-member council.

All HTTP calls to mulerouter/openrouter are mocked so tests run offline.
"""

from __future__ import annotations

import json
import os
import types
import unittest
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FIXTURE_FINDING = {
    "id": "FIND-001",
    "title": "SQL Injection in login endpoint",
    "severity": "critical",
    "cve": "CVE-2024-99999",
    "description": "Unsanitized user input passed directly to SQL query.",
    "affected_component": "auth/login.py",
}

_REAL_LLM_RESPONSE_BODY = json.dumps({
    "recommended_action": "fix",
    "confidence": 0.92,
    "reasoning": "SQL injection with critical severity must be remediated immediately.",
    "mitre_techniques": ["T1190"],
    "compliance_concerns": ["PCI-DSS 6.5.1"],
    "attack_vectors": ["network"],
})

_OPENROUTER_HTTP_RESPONSE = {
    "choices": [{"message": {"content": _REAL_LLM_RESPONSE_BODY}}],
    "model": "deepseek/deepseek-chat-v3-0324:free",
    "usage": {"prompt_tokens": 120, "completion_tokens": 80},
}


def _make_mock_http_response(body: dict) -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = body
    resp.raise_for_status = MagicMock()
    return resp


# ---------------------------------------------------------------------------
# Test: provider_has_key correctly detects keys
# ---------------------------------------------------------------------------

class TestProviderHasKey:
    def test_mulerouter_has_key_when_env_set(self, monkeypatch):
        monkeypatch.setenv("MULEROUTER_API_KEY", "sk-test-mule-key")
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test-or-key")
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.delenv("FIXOPS_COUNCIL_PRESET", raising=False)

        from core.llm_council import CouncilFactory
        factory = CouncilFactory()

        assert factory._provider_has_key("mulerouter") is True
        assert factory._provider_has_key("openrouter") is True
        assert factory._provider_has_key("openai") is False
        assert factory._provider_has_key("anthropic") is False
        assert factory._provider_has_key("gemini") is False

    def test_available_providers_ordered_filters_keyless(self, monkeypatch):
        monkeypatch.setenv("MULEROUTER_API_KEY", "sk-test-mule")
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test-or")
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("FIXOPS_COUNCIL_PRESET", raising=False)

        from core.llm_council import CouncilFactory
        factory = CouncilFactory()

        order = ["openai", "mulerouter", "openrouter", "anthropic"]
        result = factory._available_providers_ordered(order)
        assert result == ["mulerouter", "openrouter"], f"Got: {result}"


# ---------------------------------------------------------------------------
# Test: create_security_council with auto preset + free-tier keys only
# ---------------------------------------------------------------------------

class TestAutoPresetFreeTierKeys:
    def test_returns_2_real_members_not_deterministic(self, monkeypatch):
        monkeypatch.setenv("MULEROUTER_API_KEY", "sk-test-mule-key")
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test-or-key")
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.setenv("FIXOPS_COUNCIL_PRESET", "auto")

        from core.llm_council import CouncilFactory
        from core.llm_providers import DeterministicLLMProvider

        factory = CouncilFactory()
        council = factory.create_security_council()

        assert len(council.members) == 2, (
            f"Expected 2 members for free-tier preset, got {len(council.members)}: "
            f"{[m.name for m in council.members]}"
        )
        for member in council.members:
            assert not isinstance(member.provider, DeterministicLLMProvider), (
                f"Member {member.name} is DeterministicLLMProvider — keys not detected"
            )

    def test_member_names_identify_real_providers(self, monkeypatch):
        monkeypatch.setenv("MULEROUTER_API_KEY", "sk-test-mule-key")
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test-or-key")
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.setenv("FIXOPS_COUNCIL_PRESET", "auto")

        from core.llm_council import CouncilFactory
        factory = CouncilFactory()
        council = factory.create_security_council()

        names = [m.name for m in council.members]
        assert any("MuleRouter" in n or "mulerouter" in n.lower() for n in names), (
            f"No MuleRouter member found: {names}"
        )
        assert any("OpenRouter" in n or "openrouter" in n.lower() for n in names), (
            f"No OpenRouter member found: {names}"
        )


# ---------------------------------------------------------------------------
# Test: explicit FIXOPS_COUNCIL_PRESET=mulerouter+openrouter
# ---------------------------------------------------------------------------

class TestExplicitMulerouterPreset:
    def test_explicit_preset_returns_2_members(self, monkeypatch):
        monkeypatch.setenv("MULEROUTER_API_KEY", "sk-test-mule-key")
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test-or-key")
        monkeypatch.setenv("FIXOPS_COUNCIL_PRESET", "mulerouter+openrouter")

        from core.llm_council import CouncilFactory
        from core.llm_providers import DeterministicLLMProvider

        factory = CouncilFactory()
        council = factory.create_security_council()

        assert len(council.members) == 2
        for m in council.members:
            assert not isinstance(m.provider, DeterministicLLMProvider), (
                f"{m.name} is Deterministic"
            )

    def test_explicit_preset_direct_create_mulerouter_council(self, monkeypatch):
        monkeypatch.setenv("MULEROUTER_API_KEY", "sk-test-mule-key")
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test-or-key")

        from core.llm_council import CouncilFactory
        factory = CouncilFactory()
        council = factory.create_mulerouter_council()

        assert len(council.members) == 2
        assert council.chairman is not None


# ---------------------------------------------------------------------------
# Test: convene() produces real verdict (confidence != 0.5, action != "review")
# ---------------------------------------------------------------------------

class TestConveneRealVerdict:
    def test_convene_with_mocked_http_not_deterministic(self, monkeypatch):
        """Mocks the HTTP POST on both providers so the test runs offline.

        Verifies that when the LLM returns {"recommended_action":"fix","confidence":0.92}
        the council verdict reflects those real values rather than the hardcoded
        confidence=0.5 / action="review" from DeterministicLLMProvider.
        """
        monkeypatch.setenv("MULEROUTER_API_KEY", "sk-test-mule-key")
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test-or-key")
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.setenv("FIXOPS_COUNCIL_PRESET", "mulerouter+openrouter")

        mock_resp = _make_mock_http_response(_OPENROUTER_HTTP_RESPONSE)

        # Patch requests.Session.post on both providers
        with patch("requests.Session.post", return_value=mock_resp):
            from core.llm_council import CouncilFactory
            factory = CouncilFactory()
            council = factory.create_security_council()

            verdict = council.convene(
                _FIXTURE_FINDING,
                {"service_name": "auth-service", "risk_score": 9.0},
            )

        # The key assertion: real LLM output, not hardcoded defaults
        assert verdict.action != "review" or verdict.confidence != 0.5, (
            f"Got deterministic defaults: action={verdict.action!r}, "
            f"confidence={verdict.confidence} — council is still using DeterministicLLMProvider"
        )
        assert verdict.confidence > 0.5, (
            f"Confidence {verdict.confidence} matches deterministic fallback 0.5"
        )
        assert verdict.action == "fix", (
            f"Expected action='fix' from mock LLM, got {verdict.action!r}"
        )

    def test_pre_fix_deterministic_shape(self, monkeypatch):
        """Documents the broken pre-fix behaviour: if openai/anthropic/gemini are used
        without keys, confidence=0.5 and action='review'.

        This test uses FIXOPS_COUNCIL_PRESET=full to force legacy behaviour and
        verifies the deterministic output pattern.
        """
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        # Also remove free-tier keys so mulerouter/openrouter also go deterministic
        monkeypatch.delenv("MULEROUTER_API_KEY", raising=False)
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        monkeypatch.setenv("FIXOPS_COUNCIL_PRESET", "full")

        from core.llm_council import CouncilFactory
        factory = CouncilFactory()
        council = factory.create_security_council()

        verdict = council.convene(
            _FIXTURE_FINDING,
            {"service_name": "auth-service", "risk_score": 9.0},
        )

        # When all providers lack keys they all return deterministic defaults
        assert verdict.confidence == 0.5, (
            f"Expected deterministic 0.5 but got {verdict.confidence}"
        )
        assert verdict.action == "review", (
            f"Expected deterministic 'review' but got {verdict.action!r}"
        )
