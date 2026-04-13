"""Unit tests for VLLMSelfHostedProvider and OllamaSelfHostedProvider.

Tests the self-hosted LLM providers that enable air-gapped operation
of Brain Pipeline (V3) and AutoFix engine without external API keys.

Covers:
- VLLMSelfHostedProvider: init, config, API calls, error handling
- OllamaSelfHostedProvider: init, config, API calls, error handling
- JSON extraction from mixed model output
- LLMProviderManager integration with self-hosted backends
- VLLMAutoFixAdapter: fix generation, fallback logic, deterministic rules
"""

import json
import os
from unittest.mock import MagicMock, patch



# ===================================================================
# VLLMSelfHostedProvider
# ===================================================================


class TestVLLMSelfHostedProvider:
    """Test vLLM provider for air-gapped LLM inference."""

    def test_init_defaults(self):
        from core.llm_providers import VLLMSelfHostedProvider
        with patch.dict(os.environ, {}, clear=True):
            p = VLLMSelfHostedProvider("vllm-test")
            assert p.base_url == "http://localhost:8001/v1"
            assert p.model == "deepseek-ai/deepseek-coder-33b-instruct"
            assert p.timeout == 120.0
            assert p.max_tokens == 1024
            assert p.temperature == 0.0
            assert p.api_key is None
            assert p.style == "consensus"

    def test_init_from_env(self):
        from core.llm_providers import VLLMSelfHostedProvider
        env = {
            "FIXOPS_VLLM_URL": "http://gpu-box:9000/v1",
            "FIXOPS_VLLM_MODEL": "codellama/CodeLlama-34b-Instruct-hf",
            "FIXOPS_VLLM_API_KEY": "test-key-123",
        }
        with patch.dict(os.environ, env, clear=True):
            p = VLLMSelfHostedProvider("vllm-env")
            assert p.base_url == "http://gpu-box:9000/v1"
            assert p.model == "codellama/CodeLlama-34b-Instruct-hf"
            assert p.api_key == "test-key-123"

    def test_init_custom_params(self):
        from core.llm_providers import VLLMSelfHostedProvider
        with patch.dict(os.environ, {}, clear=True):
            p = VLLMSelfHostedProvider(
                "custom",
                base_url="http://10.0.0.1:8001/v1",
                model="meta-llama/Llama-3.1-70B-Instruct",
                timeout=60.0,
                max_tokens=2048,
                temperature=0.1,
                style="analyst",
                focus=["severity", "exploitability"],
            )
            assert p.base_url == "http://10.0.0.1:8001/v1"
            assert p.model == "meta-llama/Llama-3.1-70B-Instruct"
            assert p.timeout == 60.0
            assert p.max_tokens == 2048
            assert p.temperature == 0.1
            assert p.style == "analyst"
            assert p.focus == ["severity", "exploitability"]

    def test_analyse_connection_error_returns_deterministic(self):
        """When vLLM is not running, should gracefully return deterministic."""
        import requests
        from core.llm_providers import VLLMSelfHostedProvider
        with patch.dict(os.environ, {}, clear=True):
            p = VLLMSelfHostedProvider("test")
            p._session = MagicMock()
            p._session.post.side_effect = requests.ConnectionError("Connection refused")
            result = p.analyse(
                prompt="Test prompt",
                context={},
                default_action="review",
                default_confidence=0.5,
                default_reasoning="Fallback",
            )
            assert result.metadata["mode"] == "deterministic"
            assert result.recommended_action == "review"
            assert result.confidence == 0.5

    def test_analyse_timeout_returns_fallback(self):
        import requests
        from core.llm_providers import VLLMSelfHostedProvider
        with patch.dict(os.environ, {}, clear=True):
            p = VLLMSelfHostedProvider("test")
            p._session = MagicMock()
            p._session.post.side_effect = requests.Timeout("Timed out")
            result = p.analyse(
                prompt="Test",
                context={},
                default_action="block",
                default_confidence=0.8,
                default_reasoning="Timeout",
            )
            assert result.metadata["mode"] == "fallback"
            assert result.metadata["error_type"] == "timeout"
            assert result.metadata["backend"] == "vllm"

    def test_analyse_generic_error_returns_fallback(self):
        from core.llm_providers import VLLMSelfHostedProvider
        with patch.dict(os.environ, {}, clear=True):
            p = VLLMSelfHostedProvider("test")
            p._session = MagicMock()
            p._session.post.side_effect = RuntimeError("GPU OOM")
            result = p.analyse(
                prompt="Test",
                context={},
                default_action="review",
                default_confidence=0.5,
                default_reasoning="Error test",
            )
            assert result.metadata["mode"] == "fallback"
            assert result.metadata["backend"] == "vllm"

    def test_analyse_success_json_response(self):
        from core.llm_providers import VLLMSelfHostedProvider
        with patch.dict(os.environ, {}, clear=True):
            p = VLLMSelfHostedProvider("test")
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.raise_for_status = MagicMock()
            mock_response.json.return_value = {
                "choices": [{
                    "message": {
                        "content": json.dumps({
                            "recommended_action": "block",
                            "confidence": 0.95,
                            "reasoning": "Critical SQL injection confirmed",
                            "mitre_techniques": ["T1190"],
                            "compliance_concerns": ["PCI-DSS 6.5.1"],
                            "attack_vectors": ["web_injection"],
                        })
                    }
                }]
            }
            p._session = MagicMock()
            p._session.post.return_value = mock_response

            result = p.analyse(
                prompt="Analyze SQL injection",
                context={"finding": "sqli"},
                default_action="review",
                default_confidence=0.5,
                default_reasoning="default",
            )
            assert result.recommended_action == "block"
            assert result.confidence == 0.95
            assert result.metadata["mode"] == "self-hosted"
            assert result.metadata["backend"] == "vllm"
            assert result.metadata["air_gapped"] is True
            assert "T1190" in result.mitre_techniques

    def test_analyse_success_markdown_json(self):
        """Test parsing JSON wrapped in markdown code blocks."""
        from core.llm_providers import VLLMSelfHostedProvider
        with patch.dict(os.environ, {}, clear=True):
            p = VLLMSelfHostedProvider("test")
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.raise_for_status = MagicMock()
            mock_response.json.return_value = {
                "choices": [{
                    "message": {
                        "content": '```json\n{"recommended_action": "fix", "confidence": 0.88, "reasoning": "Patch available"}\n```'
                    }
                }]
            }
            p._session = MagicMock()
            p._session.post.return_value = mock_response

            result = p.analyse(
                prompt="Test",
                context={},
                default_action="review",
                default_confidence=0.5,
                default_reasoning="default",
            )
            assert result.recommended_action == "fix"
            assert result.confidence == 0.88
            assert result.metadata["mode"] == "self-hosted"

    def test_analyse_success_plain_text(self):
        """When model returns plain text, should wrap into structured response."""
        from core.llm_providers import VLLMSelfHostedProvider
        with patch.dict(os.environ, {}, clear=True):
            p = VLLMSelfHostedProvider("test")
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.raise_for_status = MagicMock()
            mock_response.json.return_value = {
                "choices": [{
                    "message": {
                        "content": "This is a critical vulnerability that should be fixed immediately."
                    }
                }]
            }
            p._session = MagicMock()
            p._session.post.return_value = mock_response

            result = p.analyse(
                prompt="Test",
                context={},
                default_action="fix",
                default_confidence=0.7,
                default_reasoning="default",
            )
            # Should use defaults since model didn't return JSON
            assert result.metadata["mode"] == "self-hosted"
            assert result.recommended_action == "fix"

    def test_analyse_sends_api_key_header(self):
        from core.llm_providers import VLLMSelfHostedProvider
        env = {"FIXOPS_VLLM_API_KEY": "bearer-key-123"}
        with patch.dict(os.environ, env, clear=True):
            p = VLLMSelfHostedProvider("test")
            p._session = MagicMock()
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.raise_for_status = MagicMock()
            mock_resp.json.return_value = {
                "choices": [{"message": {"content": '{"recommended_action": "review", "confidence": 0.5, "reasoning": "ok"}'}}]
            }
            p._session.post.return_value = mock_resp

            p.analyse(
                prompt="Test",
                context={},
                default_action="review",
                default_confidence=0.5,
                default_reasoning="test",
            )

            call_kwargs = p._session.post.call_args
            headers = call_kwargs.kwargs.get("headers", call_kwargs[1].get("headers", {}))
            assert headers.get("Authorization") == "Bearer bearer-key-123"

    def test_is_available_true(self):
        from core.llm_providers import VLLMSelfHostedProvider
        with patch.dict(os.environ, {}, clear=True):
            p = VLLMSelfHostedProvider("test")
            p._session = MagicMock()
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            p._session.get.return_value = mock_resp
            assert p.is_available() is True

    def test_is_available_false(self):
        import requests
        from core.llm_providers import VLLMSelfHostedProvider
        with patch.dict(os.environ, {}, clear=True):
            p = VLLMSelfHostedProvider("test")
            p._session = MagicMock()
            p._session.get.side_effect = requests.ConnectionError()
            assert p.is_available() is False

    def test_model_info(self):
        from core.llm_providers import VLLMSelfHostedProvider
        with patch.dict(os.environ, {}, clear=True):
            p = VLLMSelfHostedProvider("test")
            p._session = MagicMock()
            p._session.get.side_effect = Exception("offline")
            info = p.model_info()
            assert info["backend"] == "vllm"
            assert info["cost"] == "$0/month (self-hosted)"
            assert info["air_gapped"] is True

    def test_analyse_missing_choices(self):
        from core.llm_providers import VLLMSelfHostedProvider
        with patch.dict(os.environ, {}, clear=True):
            p = VLLMSelfHostedProvider("test")
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.raise_for_status = MagicMock()
            mock_resp.json.return_value = {}
            p._session = MagicMock()
            p._session.post.return_value = mock_resp
            result = p.analyse(
                prompt="Test",
                context={},
                default_action="review",
                default_confidence=0.5,
                default_reasoning="test",
            )
            assert result.metadata["mode"] == "fallback"

    def test_analyse_with_mitigation_hints(self):
        import requests
        from core.llm_providers import VLLMSelfHostedProvider
        with patch.dict(os.environ, {}, clear=True):
            p = VLLMSelfHostedProvider("test")
            p._session = MagicMock()
            p._session.post.side_effect = requests.Timeout()
            hints = {
                "mitre_candidates": ["T1190", "T1059"],
                "compliance": ["PCI-DSS"],
                "attack_vectors": ["injection"],
            }
            result = p.analyse(
                prompt="Test",
                context={},
                default_action="block",
                default_confidence=0.9,
                default_reasoning="Test",
                mitigation_hints=hints,
            )
            assert "T1190" in result.mitre_techniques
            assert "PCI-DSS" in result.compliance_concerns


# ===================================================================
# OllamaSelfHostedProvider
# ===================================================================


class TestOllamaSelfHostedProvider:
    """Test Ollama provider for air-gapped LLM inference."""

    def test_init_defaults(self):
        from core.llm_providers import OllamaSelfHostedProvider
        with patch.dict(os.environ, {}, clear=True):
            p = OllamaSelfHostedProvider("ollama-test")
            assert p.base_url == "http://localhost:11434"
            assert p.model == "codellama:13b"
            assert p.timeout == 120.0

    def test_init_from_env(self):
        from core.llm_providers import OllamaSelfHostedProvider
        env = {
            "FIXOPS_OLLAMA_URL": "http://gpu-server:11434",
            "FIXOPS_OLLAMA_MODEL": "deepseek-coder:33b",
        }
        with patch.dict(os.environ, env, clear=True):
            p = OllamaSelfHostedProvider("ollama-env")
            assert p.base_url == "http://gpu-server:11434"
            assert p.model == "deepseek-coder:33b"

    def test_analyse_connection_error_returns_deterministic(self):
        import requests
        from core.llm_providers import OllamaSelfHostedProvider
        with patch.dict(os.environ, {}, clear=True):
            p = OllamaSelfHostedProvider("test")
            p._session = MagicMock()
            p._session.post.side_effect = requests.ConnectionError()
            result = p.analyse(
                prompt="Test",
                context={},
                default_action="review",
                default_confidence=0.5,
                default_reasoning="Fallback",
            )
            assert result.metadata["mode"] == "deterministic"

    def test_analyse_success_json_response(self):
        from core.llm_providers import OllamaSelfHostedProvider
        with patch.dict(os.environ, {}, clear=True):
            p = OllamaSelfHostedProvider("test")
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.raise_for_status = MagicMock()
            mock_resp.json.return_value = {
                "response": json.dumps({
                    "recommended_action": "fix",
                    "confidence": 0.82,
                    "reasoning": "Dependency update available",
                })
            }
            p._session = MagicMock()
            p._session.post.return_value = mock_resp
            result = p.analyse(
                prompt="Test",
                context={},
                default_action="review",
                default_confidence=0.5,
                default_reasoning="default",
            )
            assert result.recommended_action == "fix"
            assert result.confidence == 0.82
            assert result.metadata["backend"] == "ollama"
            assert result.metadata["air_gapped"] is True

    def test_analyse_plain_text_response(self):
        from core.llm_providers import OllamaSelfHostedProvider
        with patch.dict(os.environ, {}, clear=True):
            p = OllamaSelfHostedProvider("test")
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.raise_for_status = MagicMock()
            mock_resp.json.return_value = {
                "response": "This vulnerability is critical and should be patched."
            }
            p._session = MagicMock()
            p._session.post.return_value = mock_resp
            result = p.analyse(
                prompt="Test",
                context={},
                default_action="fix",
                default_confidence=0.7,
                default_reasoning="default",
            )
            assert result.metadata["mode"] == "self-hosted"

    def test_is_available_true(self):
        from core.llm_providers import OllamaSelfHostedProvider
        with patch.dict(os.environ, {}, clear=True):
            p = OllamaSelfHostedProvider("test")
            p._session = MagicMock()
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            p._session.get.return_value = mock_resp
            assert p.is_available() is True

    def test_is_available_false(self):
        import requests
        from core.llm_providers import OllamaSelfHostedProvider
        with patch.dict(os.environ, {}, clear=True):
            p = OllamaSelfHostedProvider("test")
            p._session = MagicMock()
            p._session.get.side_effect = requests.ConnectionError()
            assert p.is_available() is False

    def test_model_info(self):
        from core.llm_providers import OllamaSelfHostedProvider
        with patch.dict(os.environ, {}, clear=True):
            p = OllamaSelfHostedProvider("test")
            info = p.model_info()
            assert info["backend"] == "ollama"
            assert info["air_gapped"] is True


# ===================================================================
# JSON extraction helper
# ===================================================================


class TestExtractJsonFromText:
    """Test _extract_json_from_text helper."""

    def test_extract_from_markdown_code_block(self):
        from core.llm_providers import _extract_json_from_text
        text = '```json\n{"key": "value"}\n```'
        result = _extract_json_from_text(text)
        assert result is not None
        parsed = json.loads(result)
        assert parsed["key"] == "value"

    def test_extract_from_bare_code_block(self):
        from core.llm_providers import _extract_json_from_text
        text = '```\n{"action": "fix"}\n```'
        result = _extract_json_from_text(text)
        assert result is not None
        parsed = json.loads(result)
        assert parsed["action"] == "fix"

    def test_extract_from_mixed_text(self):
        from core.llm_providers import _extract_json_from_text
        text = 'Here is my analysis:\n{"recommended_action": "block", "confidence": 0.9}\nDone.'
        result = _extract_json_from_text(text)
        assert result is not None
        parsed = json.loads(result)
        assert parsed["recommended_action"] == "block"

    def test_extract_nested_json(self):
        from core.llm_providers import _extract_json_from_text
        text = 'Result: {"outer": {"inner": "value"}, "list": [1, 2]}'
        result = _extract_json_from_text(text)
        assert result is not None
        parsed = json.loads(result)
        assert parsed["outer"]["inner"] == "value"

    def test_no_json_returns_none(self):
        from core.llm_providers import _extract_json_from_text
        assert _extract_json_from_text("No JSON here.") is None

    def test_empty_string(self):
        from core.llm_providers import _extract_json_from_text
        assert _extract_json_from_text("") is None


# ===================================================================
# LLMProviderManager with self-hosted providers
# ===================================================================


class TestLLMProviderManagerSelfHosted:
    """Test that LLMProviderManager includes self-hosted providers."""

    def test_has_vllm_provider(self):
        from core.llm_providers import LLMProviderManager, VLLMSelfHostedProvider
        manager = LLMProviderManager()
        assert "vllm" in manager.providers
        assert isinstance(manager.providers["vllm"], VLLMSelfHostedProvider)

    def test_has_ollama_provider(self):
        from core.llm_providers import LLMProviderManager, OllamaSelfHostedProvider
        manager = LLMProviderManager()
        assert "ollama" in manager.providers
        assert isinstance(manager.providers["ollama"], OllamaSelfHostedProvider)

    def test_get_vllm_provider(self):
        from core.llm_providers import LLMProviderManager, VLLMSelfHostedProvider
        manager = LLMProviderManager()
        provider = manager.get_provider("vllm")
        assert isinstance(provider, VLLMSelfHostedProvider)

    def test_analyse_via_vllm(self):
        """Test that analyse delegates to vLLM provider (connection refused = deterministic)."""
        import requests
        from core.llm_providers import LLMProviderManager
        manager = LLMProviderManager()
        # Mock the vLLM session to simulate connection refused
        manager.providers["vllm"]._session = MagicMock()
        manager.providers["vllm"]._session.post.side_effect = requests.ConnectionError()
        result = manager.analyse(
            "vllm",
            prompt="Test",
            context={},
        )
        assert result.metadata["mode"] == "deterministic"

    def test_all_six_providers_present(self):
        from core.llm_providers import LLMProviderManager
        manager = LLMProviderManager()
        expected = {"openai", "anthropic", "gemini", "openrouter", "sentinel", "vllm", "ollama"}
        assert set(manager.providers.keys()) == expected


# ===================================================================
# VLLMAutoFixAdapter
# ===================================================================


class TestVLLMAutoFixAdapter:
    """Test the AutoFix adapter for self-hosted LLMs."""

    def test_init(self):
        from core.vllm_autofix_adapter import VLLMAutoFixAdapter
        adapter = VLLMAutoFixAdapter()
        assert "vllm" in adapter._providers
        assert "ollama" in adapter._providers

    def test_get_active_backend_none(self):
        """When no backend is running, should return 'none'."""
        import requests
        from core.vllm_autofix_adapter import VLLMAutoFixAdapter
        adapter = VLLMAutoFixAdapter(backend="auto")
        # Mock both as unavailable
        adapter._providers["vllm"]._session = MagicMock()
        adapter._providers["vllm"]._session.get.side_effect = requests.ConnectionError()
        adapter._providers["ollama"]._session = MagicMock()
        adapter._providers["ollama"]._session.get.side_effect = requests.ConnectionError()
        assert adapter.get_active_backend() == "none"

    def test_get_active_backend_vllm(self):
        from core.vllm_autofix_adapter import VLLMAutoFixAdapter
        adapter = VLLMAutoFixAdapter(backend="auto")
        # Mock vLLM as available
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        adapter._providers["vllm"]._session = MagicMock()
        adapter._providers["vllm"]._session.get.return_value = mock_resp
        assert adapter.get_active_backend() == "vllm"

    def test_build_fix_prompt_code(self):
        from core.vllm_autofix_adapter import VLLMAutoFixAdapter
        adapter = VLLMAutoFixAdapter()
        finding = {
            "title": "SQL Injection in login",
            "severity": "critical",
            "cwe_id": "CWE-89",
            "description": "Unsanitized input in SQL query",
            "file_path": "app/auth.py",
        }
        prompt = adapter.build_fix_prompt(finding, "cursor.execute(f'SELECT * FROM users WHERE id={user_id}')")
        assert "SQL Injection" in prompt
        assert "CWE-89" in prompt
        assert "python" in prompt.lower()
        assert "cursor.execute" in prompt

    def test_build_fix_prompt_dependency(self):
        from core.vllm_autofix_adapter import VLLMAutoFixAdapter
        adapter = VLLMAutoFixAdapter()
        finding = {
            "title": "Outdated dependency with known CVE",
            "severity": "high",
            "cve_ids": ["CVE-2024-1234"],
            "package_name": "lodash",
            "current_version": "4.17.19",
            "ecosystem": "npm",
        }
        prompt = adapter.build_fix_prompt(finding)
        assert "lodash" in prompt
        assert "4.17.19" in prompt
        assert "npm" in prompt

    def test_build_fix_prompt_config(self):
        from core.vllm_autofix_adapter import VLLMAutoFixAdapter
        adapter = VLLMAutoFixAdapter()
        finding = {
            "title": "Insecure TLS config",
            "severity": "high",
            "cwe_id": "CWE-326",
            "description": "TLS 1.0 enabled",
            "file_path": "config/nginx.yaml",
        }
        prompt = adapter.build_fix_prompt(finding, "tls_min_version: 1.0")
        assert "configuration" in prompt.lower()
        assert "TLS" in prompt

    def test_deterministic_fix_sqli(self):
        from core.vllm_autofix_adapter import VLLMAutoFixAdapter
        adapter = VLLMAutoFixAdapter()
        finding = {
            "title": "SQL Injection",
            "severity": "critical",
            "cwe_id": "CWE-89",
        }
        result = adapter._deterministic_fix(finding)
        assert result.success is True
        assert result.backend == "deterministic"
        assert result.confidence >= 0.7
        assert "parameterized" in result.explanation.lower()

    def test_deterministic_fix_xss(self):
        from core.vllm_autofix_adapter import VLLMAutoFixAdapter
        adapter = VLLMAutoFixAdapter()
        result = adapter._deterministic_fix({"cwe_id": "CWE-79"})
        assert result.success is True
        assert "encoding" in result.explanation.lower() or "escaping" in result.explanation.lower()

    def test_deterministic_fix_hardcoded_secrets(self):
        from core.vllm_autofix_adapter import VLLMAutoFixAdapter
        adapter = VLLMAutoFixAdapter()
        result = adapter._deterministic_fix({"cwe_id": "CWE-798"})
        assert result.success is True
        assert "environment" in result.explanation.lower()

    def test_deterministic_fix_keyword_match(self):
        from core.vllm_autofix_adapter import VLLMAutoFixAdapter
        adapter = VLLMAutoFixAdapter()
        result = adapter._deterministic_fix({
            "title": "SSRF vulnerability in webhook handler",
            "cwe_id": "",  # No CWE, should match keyword
        })
        assert result.success is True
        assert "url" in result.explanation.lower() or "restrict" in result.explanation.lower()

    def test_deterministic_fix_unknown(self):
        from core.vllm_autofix_adapter import VLLMAutoFixAdapter
        adapter = VLLMAutoFixAdapter()
        result = adapter._deterministic_fix({
            "title": "Some obscure vulnerability",
            "cwe_id": "CWE-999999",
        })
        assert result.success is False
        assert result.backend == "none"

    def test_generate_fix_no_backend(self):
        """When no backend is available, should fall back to deterministic."""
        import requests
        from core.vllm_autofix_adapter import VLLMAutoFixAdapter
        adapter = VLLMAutoFixAdapter(backend="auto")
        adapter._providers["vllm"]._session = MagicMock()
        adapter._providers["vllm"]._session.get.side_effect = requests.ConnectionError()
        adapter._providers["ollama"]._session = MagicMock()
        adapter._providers["ollama"]._session.get.side_effect = requests.ConnectionError()

        result = adapter.generate_fix(
            {"title": "SQL Injection", "cwe_id": "CWE-89", "severity": "critical"}
        )
        assert result.backend == "deterministic"
        assert result.success is True

    def test_get_status(self):
        from core.vllm_autofix_adapter import VLLMAutoFixAdapter
        adapter = VLLMAutoFixAdapter()
        status = adapter.get_status()
        assert "backend_preference" in status
        assert "active_backend" in status
        assert "providers" in status
        assert "vllm" in status["providers"]
        assert "ollama" in status["providers"]

    def test_deterministic_fix_deserialization(self):
        from core.vllm_autofix_adapter import VLLMAutoFixAdapter
        adapter = VLLMAutoFixAdapter()
        result = adapter._deterministic_fix({"cwe_id": "CWE-502"})
        assert result.success is True
        assert "deserialization" in result.explanation.lower() or "safe" in result.explanation.lower()

    def test_deterministic_fix_path_traversal(self):
        from core.vllm_autofix_adapter import VLLMAutoFixAdapter
        adapter = VLLMAutoFixAdapter()
        result = adapter._deterministic_fix({"cwe_id": "CWE-22"})
        assert result.success is True
        assert "path" in result.explanation.lower()

    def test_deterministic_fix_command_injection(self):
        from core.vllm_autofix_adapter import VLLMAutoFixAdapter
        adapter = VLLMAutoFixAdapter()
        result = adapter._deterministic_fix({"cwe_id": "CWE-78"})
        assert result.success is True

    def test_deterministic_fix_all_rules_have_confidence(self):
        """Every deterministic fix rule must have a confidence > 0."""
        from core.vllm_autofix_adapter import _DETERMINISTIC_FIX_RULES
        for cwe, rules in _DETERMINISTIC_FIX_RULES.items():
            assert rules["confidence"] > 0, f"{cwe} has zero confidence"
            assert rules["explanation"], f"{cwe} has empty explanation"
            assert rules["code_pattern"], f"{cwe} has empty code_pattern"


# ===================================================================
# Language inference
# ===================================================================


class TestInferLanguage:
    """Test _infer_language helper."""

    def test_python(self):
        from core.vllm_autofix_adapter import _infer_language
        assert _infer_language("app/main.py") == "python"

    def test_javascript(self):
        from core.vllm_autofix_adapter import _infer_language
        assert _infer_language("src/index.js") == "javascript"

    def test_typescript(self):
        from core.vllm_autofix_adapter import _infer_language
        assert _infer_language("src/App.tsx") == "typescript"

    def test_java(self):
        from core.vllm_autofix_adapter import _infer_language
        assert _infer_language("Main.java") == "java"

    def test_go(self):
        from core.vllm_autofix_adapter import _infer_language
        assert _infer_language("main.go") == "go"

    def test_unknown(self):
        from core.vllm_autofix_adapter import _infer_language
        assert _infer_language("README.md") == "text"

    def test_yaml(self):
        from core.vllm_autofix_adapter import _infer_language
        assert _infer_language("config.yaml") == "yaml"

    def test_terraform(self):
        from core.vllm_autofix_adapter import _infer_language
        assert _infer_language("main.tf") == "hcl"
