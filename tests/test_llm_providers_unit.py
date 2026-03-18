"""Unit tests for core.llm_providers — V3 Decision Intelligence LLM adapters.

Tests the multi-LLM provider system (OpenAI, Anthropic, Gemini, Sentinel)
that powers the brain pipeline's consensus decision engine.
"""

import os
from unittest.mock import MagicMock, patch


class TestLLMResponse:
    """Test LLMResponse dataclass."""

    def test_creation_basic(self):
        from core.llm_providers import LLMResponse
        resp = LLMResponse(
            recommended_action="block",
            confidence=0.95,
            reasoning="Critical SQL injection detected",
        )
        assert resp.recommended_action == "block"
        assert resp.confidence == 0.95
        assert resp.reasoning == "Critical SQL injection detected"
        assert resp.mitre_techniques == []
        assert resp.compliance_concerns == []
        assert resp.attack_vectors == []
        assert resp.metadata == {}

    def test_creation_full(self):
        from core.llm_providers import LLMResponse
        resp = LLMResponse(
            recommended_action="review",
            confidence=0.72,
            reasoning="Needs manual review",
            mitre_techniques=["T1190"],
            compliance_concerns=["PCI-DSS 6.5.1"],
            attack_vectors=["web_injection"],
            metadata={"provider": "openai"},
        )
        assert resp.mitre_techniques == ["T1190"]
        assert resp.compliance_concerns == ["PCI-DSS 6.5.1"]
        assert resp.attack_vectors == ["web_injection"]
        assert resp.metadata["provider"] == "openai"


class TestBaseLLMProvider:
    """Test BaseLLMProvider deterministic fallback."""

    def test_init(self):
        from core.llm_providers import BaseLLMProvider
        provider = BaseLLMProvider("test-provider", style="analyst", focus=["severity"])
        assert provider.name == "test-provider"
        assert provider.style == "analyst"
        assert provider.focus == ["severity"]

    def test_init_defaults(self):
        from core.llm_providers import BaseLLMProvider
        provider = BaseLLMProvider("p1")
        assert provider.style == "consensus"
        assert provider.focus == []

    def test_analyse_returns_deterministic(self):
        from core.llm_providers import BaseLLMProvider
        provider = BaseLLMProvider("test")
        result = provider.analyse(
            prompt="Test prompt",
            context={"service": "auth"},
            default_action="review",
            default_confidence=0.5,
            default_reasoning="Deterministic fallback",
        )
        assert result.recommended_action == "review"
        assert result.confidence == 0.5
        assert result.reasoning == "Deterministic fallback"
        assert result.metadata["mode"] == "deterministic"

    def test_analyse_with_mitigation_hints(self):
        from core.llm_providers import BaseLLMProvider
        provider = BaseLLMProvider("test")
        hints = {
            "mitre_candidates": ["T1190", "T1059"],
            "compliance": ["PCI-DSS"],
            "attack_vectors": ["injection"],
        }
        result = provider.analyse(
            prompt="Test",
            context={},
            default_action="block",
            default_confidence=0.9,
            default_reasoning="Test",
            mitigation_hints=hints,
        )
        assert "T1190" in result.mitre_techniques
        assert "PCI-DSS" in result.compliance_concerns
        assert "injection" in result.attack_vectors


class TestDeterministicLLMProvider:
    """Test DeterministicLLMProvider."""

    def test_inherits_base_behaviour(self):
        from core.llm_providers import DeterministicLLMProvider
        provider = DeterministicLLMProvider("deterministic")
        result = provider.analyse(
            prompt="Test",
            context={},
            default_action="allow",
            default_confidence=0.3,
            default_reasoning="No risk",
        )
        assert result.recommended_action == "allow"
        assert result.confidence == 0.3


class TestOpenAIChatProvider:
    """Test OpenAI provider adapter."""

    def test_init_no_api_key(self):
        from core.llm_providers import OpenAIChatProvider
        with patch.dict(os.environ, {}, clear=True):
            provider = OpenAIChatProvider("openai-test")
            assert provider.api_key is None

    def test_analyse_without_key_returns_deterministic(self):
        from core.llm_providers import OpenAIChatProvider
        with patch.dict(os.environ, {}, clear=True):
            provider = OpenAIChatProvider("openai-test")
            result = provider.analyse(
                prompt="Test",
                context={},
                default_action="review",
                default_confidence=0.5,
                default_reasoning="No API key",
            )
            assert result.metadata["mode"] == "deterministic"
            assert result.recommended_action == "review"

    def test_model_default(self):
        from core.llm_providers import OpenAIChatProvider
        with patch.dict(os.environ, {}, clear=True):
            provider = OpenAIChatProvider("test")
            assert provider.model == "gpt-5.2"

    def test_custom_model(self):
        from core.llm_providers import OpenAIChatProvider
        with patch.dict(os.environ, {}, clear=True):
            provider = OpenAIChatProvider("test", model="gpt-4-turbo")
            assert provider.model == "gpt-4-turbo"

    def test_resolve_api_key_from_env(self):
        from core.llm_providers import OpenAIChatProvider
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test123"}, clear=True):
            provider = OpenAIChatProvider("test")
            assert provider.api_key == "sk-test123"

    def test_resolve_api_key_fallback_env(self):
        from core.llm_providers import OpenAIChatProvider
        with patch.dict(os.environ, {"FIXOPS_OPENAI_KEY": "sk-fallback"}, clear=True):
            provider = OpenAIChatProvider("test")
            assert provider.api_key == "sk-fallback"

    def test_analyse_timeout_fallback(self):
        import requests
        from core.llm_providers import OpenAIChatProvider
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}, clear=True):
            provider = OpenAIChatProvider("test")
            provider._session = MagicMock()
            provider._session.post.side_effect = requests.Timeout("Connection timed out")
            result = provider.analyse(
                prompt="Test",
                context={},
                default_action="review",
                default_confidence=0.5,
                default_reasoning="Timeout test",
            )
            assert result.metadata["mode"] == "fallback"
            assert result.metadata["error_type"] == "timeout"

    def test_analyse_http_error_fallback(self):
        import requests
        from core.llm_providers import OpenAIChatProvider
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}, clear=True):
            provider = OpenAIChatProvider("test")
            mock_response = MagicMock()
            mock_response.status_code = 429
            mock_response.json.return_value = {"error": {"message": "Rate limited"}}
            mock_response.raise_for_status.side_effect = requests.HTTPError(response=mock_response)
            provider._session = MagicMock()
            provider._session.post.return_value = mock_response
            result = provider.analyse(
                prompt="Test",
                context={},
                default_action="review",
                default_confidence=0.5,
                default_reasoning="Error test",
            )
            assert result.metadata["mode"] == "fallback"
            assert result.metadata["error_type"] == "http_error"

    def test_analyse_generic_error_fallback(self):
        from core.llm_providers import OpenAIChatProvider
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}, clear=True):
            provider = OpenAIChatProvider("test")
            provider._session = MagicMock()
            provider._session.post.side_effect = ConnectionError("Network down")
            result = provider.analyse(
                prompt="Test",
                context={},
                default_action="review",
                default_confidence=0.5,
                default_reasoning="Network test",
            )
            assert result.metadata["mode"] == "fallback"
            assert result.metadata["error_type"] == "ConnectionError"


class TestAnthropicMessagesProvider:
    """Test Anthropic provider adapter."""

    def test_init_no_api_key(self):
        from core.llm_providers import AnthropicMessagesProvider
        with patch.dict(os.environ, {}, clear=True):
            provider = AnthropicMessagesProvider("anthropic-test")
            assert provider.api_key is None

    def test_analyse_without_key_returns_deterministic(self):
        from core.llm_providers import AnthropicMessagesProvider
        with patch.dict(os.environ, {}, clear=True):
            provider = AnthropicMessagesProvider("test")
            result = provider.analyse(
                prompt="Test",
                context={},
                default_action="allow",
                default_confidence=0.3,
                default_reasoning="No key",
            )
            assert result.metadata["mode"] == "deterministic"

    def test_model_default(self):
        from core.llm_providers import AnthropicMessagesProvider
        with patch.dict(os.environ, {}, clear=True):
            provider = AnthropicMessagesProvider("test")
            assert "claude" in provider.model

    def test_style_default(self):
        from core.llm_providers import AnthropicMessagesProvider
        with patch.dict(os.environ, {}, clear=True):
            provider = AnthropicMessagesProvider("test")
            assert provider.style == "analyst"

    def test_analyse_exception_fallback(self):
        from core.llm_providers import AnthropicMessagesProvider
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test"}, clear=True):
            provider = AnthropicMessagesProvider("test")
            provider._session = MagicMock()
            provider._session.post.side_effect = ConnectionError("fail")
            result = provider.analyse(
                prompt="Test",
                context={},
                default_action="review",
                default_confidence=0.5,
                default_reasoning="Error test",
            )
            assert result.metadata["mode"] == "fallback"


class TestGeminiProvider:
    """Test Gemini provider adapter."""

    def test_init_no_api_key(self):
        from core.llm_providers import GeminiProvider
        with patch.dict(os.environ, {}, clear=True):
            provider = GeminiProvider("gemini-test")
            assert provider.api_key is None

    def test_analyse_without_key_returns_deterministic(self):
        from core.llm_providers import GeminiProvider
        with patch.dict(os.environ, {}, clear=True):
            provider = GeminiProvider("test")
            result = provider.analyse(
                prompt="Test",
                context={},
                default_action="block",
                default_confidence=0.8,
                default_reasoning="No key",
            )
            assert result.metadata["mode"] == "deterministic"

    def test_model_default(self):
        from core.llm_providers import GeminiProvider
        with patch.dict(os.environ, {}, clear=True):
            provider = GeminiProvider("test")
            assert "gemini" in provider.model

    def test_style_default(self):
        from core.llm_providers import GeminiProvider
        with patch.dict(os.environ, {}, clear=True):
            provider = GeminiProvider("test")
            assert provider.style == "signals"

    def test_analyse_exception_fallback(self):
        from core.llm_providers import GeminiProvider
        with patch.dict(os.environ, {"GOOGLE_API_KEY": "test-key"}, clear=True):
            provider = GeminiProvider("test")
            provider._session = MagicMock()
            provider._session.post.side_effect = RuntimeError("API error")
            result = provider.analyse(
                prompt="Test",
                context={},
                default_action="review",
                default_confidence=0.5,
                default_reasoning="Fallback",
            )
            assert result.metadata["mode"] == "fallback"


class TestSentinelCyberProvider:
    """Test SentinelCyber provider."""

    def test_analyse_returns_deterministic_with_context(self):
        from core.llm_providers import SentinelCyberProvider
        provider = SentinelCyberProvider("sentinel")
        context = {
            "service_name": "payment-gateway",
            "security_findings": [{"id": 1}, {"id": 2}],
        }
        result = provider.analyse(
            prompt="Analyze findings",
            context=context,
            default_action="block",
            default_confidence=0.85,
            default_reasoning="Default",
        )
        assert result.recommended_action == "block"
        assert result.confidence == 0.85
        assert "payment-gateway" in result.reasoning
        assert "2 findings" in result.reasoning
        assert result.metadata["mode"] == "deterministic"
        assert result.metadata["reason"] == "specialised_rules"


class TestEnsureList:
    """Test _ensure_list helper."""

    def test_none_returns_empty(self):
        from core.llm_providers import _ensure_list
        assert _ensure_list(None) == []

    def test_list_passes_through(self):
        from core.llm_providers import _ensure_list
        assert _ensure_list([1, 2, 3]) == [1, 2, 3]

    def test_tuple_converted(self):
        from core.llm_providers import _ensure_list
        assert _ensure_list((1, 2)) == [1, 2]

    def test_set_converted(self):
        from core.llm_providers import _ensure_list
        result = _ensure_list({1, 2})
        assert len(result) == 2

    def test_single_value_wrapped(self):
        from core.llm_providers import _ensure_list
        assert _ensure_list("T1190") == ["T1190"]

    def test_none_values_filtered(self):
        from core.llm_providers import _ensure_list
        assert _ensure_list([1, None, 3]) == [1, 3]


class TestResponseFromPayload:
    """Test _response_from_payload helper."""

    def test_valid_payload(self):
        from core.llm_providers import _response_from_payload
        payload = {
            "recommended_action": "block",
            "confidence": 0.9,
            "reasoning": "Exploit confirmed",
            "mitre_techniques": ["T1190"],
            "compliance_concerns": ["PCI-DSS"],
            "attack_vectors": ["web"],
        }
        result = _response_from_payload(
            payload,
            default_action="review",
            default_confidence=0.5,
            default_reasoning="default",
            mitigation_hints=None,
            metadata={"mode": "remote"},
        )
        assert result.recommended_action == "block"
        assert result.confidence == 0.9
        assert result.reasoning == "Exploit confirmed"
        assert "T1190" in result.mitre_techniques

    def test_missing_fields_use_defaults(self):
        from core.llm_providers import _response_from_payload
        result = _response_from_payload(
            {},
            default_action="review",
            default_confidence=0.5,
            default_reasoning="Default reasoning",
            mitigation_hints={"mitre_candidates": ["T1059"]},
            metadata={"mode": "test"},
        )
        assert result.recommended_action == "review"
        assert result.confidence == 0.5
        assert result.reasoning == "Default reasoning"
        assert "T1059" in result.mitre_techniques

    def test_invalid_confidence_uses_default(self):
        from core.llm_providers import _response_from_payload
        result = _response_from_payload(
            {"confidence": "not-a-number"},
            default_action="review",
            default_confidence=0.5,
            default_reasoning="Test",
            mitigation_hints=None,
            metadata={},
        )
        assert result.confidence == 0.5


class TestLLMProviderManager:
    """Test LLMProviderManager."""

    def test_init_has_default_providers(self):
        from core.llm_providers import LLMProviderManager
        manager = LLMProviderManager()
        assert "openai" in manager.providers
        assert "anthropic" in manager.providers
        assert "gemini" in manager.providers
        assert "sentinel" in manager.providers

    def test_get_provider_known(self):
        from core.llm_providers import LLMProviderManager, OpenAIChatProvider
        manager = LLMProviderManager()
        provider = manager.get_provider("openai")
        assert isinstance(provider, OpenAIChatProvider)

    def test_get_provider_unknown_returns_deterministic(self):
        from core.llm_providers import DeterministicLLMProvider, LLMProviderManager
        manager = LLMProviderManager()
        provider = manager.get_provider("nonexistent")
        assert isinstance(provider, DeterministicLLMProvider)

    def test_analyse_delegates_to_provider(self):
        from core.llm_providers import LLMProviderManager
        manager = LLMProviderManager()
        result = manager.analyse(
            "sentinel",
            prompt="Test",
            context={"service_name": "test", "security_findings": []},
        )
        assert result.metadata["mode"] == "deterministic"
        assert result.metadata["reason"] == "specialised_rules"
