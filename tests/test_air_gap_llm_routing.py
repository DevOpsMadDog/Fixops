"""Air-gap LLM routing tests.

Verifies that:
  1. Without air-gap (DISABLED), the council keeps external providers.
  2. With ENFORCED + a detected local backend, every external provider is
     swapped for AirGapLLMProvider.
  3. With ENFORCED and no detected local backend, CouncilFactory raises.
  4. AirGapLLMProvider POSTs to the LOCAL backend URL (Ollama/vLLM/llama.cpp),
     never to api.openai.com.

These tests must NEVER make real network calls — every probe and POST is
mocked at the requests layer.
"""

from __future__ import annotations

import json
from unittest.mock import patch, MagicMock

import pytest

from core.airgap_config import (
    AirGapMode,
    LLMBackend,
    LocalLLMConfig,
    LocalLLMRouter,
)
from core.llm_council import CouncilFactory
from core.llm_providers import (
    AirGapLLMProvider,
    AnthropicMessagesProvider,
    OpenAIChatProvider,
)


# ---------------------------------------------------------------------------
# Test 1 — DISABLED mode keeps external providers
# ---------------------------------------------------------------------------


def test_unenforced_mode_uses_external_providers() -> None:
    """With air-gap DISABLED, CouncilFactory keeps the original cloud providers."""
    with patch("core.airgap_config.get_air_gap_mode", return_value=AirGapMode.DISABLED):
        factory = CouncilFactory()
    assert isinstance(factory.manager.providers["openai"], OpenAIChatProvider)
    assert isinstance(factory.manager.providers["anthropic"], AnthropicMessagesProvider)
    # Opus escalation must still be the cloud Anthropic adapter
    assert isinstance(factory.opus, AnthropicMessagesProvider)


# ---------------------------------------------------------------------------
# Test 2 — ENFORCED + backend available swaps providers
# ---------------------------------------------------------------------------


def test_enforced_mode_replaces_with_airgap_provider() -> None:
    """With ENFORCED + Ollama detected, every external provider becomes AirGapLLMProvider."""
    detected = LocalLLMConfig(
        backend=LLMBackend.OLLAMA.value,
        endpoint="http://localhost:11434",
        model_name="codellama:13b",
        available=True,
    )

    with patch(
        "core.airgap_config.get_air_gap_mode", return_value=AirGapMode.ENFORCED
    ), patch.object(LocalLLMRouter, "detect_available_backend", return_value=detected):
        factory = CouncilFactory()

    # External providers must be AirGapLLMProvider instances
    for pname in ("openai", "anthropic", "gemini", "openrouter", "mulerouter", "deepseek"):
        provider = factory.manager.providers.get(pname)
        assert isinstance(provider, AirGapLLMProvider), (
            f"Provider '{pname}' should be AirGapLLMProvider in ENFORCED mode, got {type(provider).__name__}"
        )
        # And it must point at the LOCAL endpoint
        assert provider.endpoint == "http://localhost:11434"
        assert provider.backend == LLMBackend.OLLAMA.value

    # Escalation provider must also be air-gapped
    assert isinstance(factory.opus, AirGapLLMProvider)


# ---------------------------------------------------------------------------
# Test 3 — ENFORCED + no backend → RuntimeError
# ---------------------------------------------------------------------------


def test_enforced_mode_no_backend_raises() -> None:
    """ENFORCED with no detected backend MUST refuse to start the council."""
    no_backend = LocalLLMConfig(backend=LLMBackend.NONE.value, available=False)

    with patch(
        "core.airgap_config.get_air_gap_mode", return_value=AirGapMode.ENFORCED
    ), patch.object(LocalLLMRouter, "detect_available_backend", return_value=no_backend):
        with pytest.raises(RuntimeError, match="ENFORCED.*no local LLM backend"):
            CouncilFactory()


# ---------------------------------------------------------------------------
# Test 4 — AirGapLLMProvider POSTs to the local URL, not api.openai.com
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "backend,endpoint,expected_url_substr",
    [
        (LLMBackend.OLLAMA.value, "http://localhost:11434", "localhost:11434/api/chat"),
        (LLMBackend.VLLM.value, "http://localhost:8000", "localhost:8000/v1/chat/completions"),
        (LLMBackend.LLAMACPP.value, "http://localhost:8080", "localhost:8080/v1/chat/completions"),
    ],
)
def test_airgap_provider_routes_to_local_endpoint(
    backend: str, endpoint: str, expected_url_substr: str
) -> None:
    """AirGapLLMProvider must POST to the LOCAL backend URL, never to a cloud API."""
    detected = LocalLLMConfig(
        backend=backend,
        endpoint=endpoint,
        model_name="local-model",
        available=True,
    )
    router = LocalLLMRouter()

    # Stage 1: construction probes for backend
    with patch.object(LocalLLMRouter, "detect_available_backend", return_value=detected):
        provider = AirGapLLMProvider(
            name="airgap-test",
            local_llm_router=router,
            style="consensus",
        )

    # Stage 2: analyse() must POST to the local URL
    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.raise_for_status = MagicMock(return_value=None)
    if backend == LLMBackend.OLLAMA.value:
        fake_response.json.return_value = {
            "message": {
                "content": json.dumps({
                    "recommended_action": "remediate_critical",
                    "confidence": 0.91,
                    "reasoning": "local-LLM verdict",
                })
            }
        }
    else:
        fake_response.json.return_value = {
            "choices": [{
                "message": {
                    "content": json.dumps({
                        "recommended_action": "remediate_critical",
                        "confidence": 0.91,
                        "reasoning": "local-LLM verdict",
                    })
                }
            }]
        }

    with patch.object(provider._session, "post", return_value=fake_response) as mock_post:
        result = provider.analyse(
            prompt="Should we patch CVE-2024-9999?",
            context={"service_name": "api"},
            default_action="review",
            default_confidence=0.5,
            default_reasoning="default",
        )

    # The POST URL MUST be the local endpoint, NOT api.openai.com / api.anthropic.com.
    assert mock_post.called, "AirGapLLMProvider must POST through requests"
    call_args = mock_post.call_args
    posted_url = call_args[0][0] if call_args[0] else call_args.kwargs.get("url", "")
    assert expected_url_substr in posted_url, (
        f"Expected POST to {expected_url_substr}, got {posted_url}"
    )
    assert "openai.com" not in posted_url
    assert "anthropic.com" not in posted_url

    # Verdict surfaced from the local LLM
    assert result.recommended_action == "remediate_critical"
    assert result.metadata["air_gapped"] is True
    assert result.metadata["backend"] == backend
