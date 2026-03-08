"""Tests for VLLMAutoFixAdapter — air-gapped autofix generation."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

import pytest
from core.vllm_autofix_adapter import (
    AutoFixLLMResult,
    VLLMAutoFixAdapter,
    _infer_language,
    _DETERMINISTIC_FIX_RULES,
    _KEYWORD_FIX_RULES,
)


# ---------------------------------------------------------------------------
# AutoFixLLMResult tests
# ---------------------------------------------------------------------------
class TestAutoFixLLMResult:
    def test_defaults(self):
        r = AutoFixLLMResult()
        assert r.success is False
        assert r.fix_code == ""
        assert r.unified_diff == ""
        assert r.explanation == ""
        assert r.confidence == 0.0
        assert r.backend == "none"
        assert r.model == ""
        assert r.duration_ms == 0.0
        assert r.error == ""
        assert r.metadata == {}

    def test_custom_values(self):
        r = AutoFixLLMResult(
            success=True,
            fix_code="fixed = sanitize(input)",
            confidence=0.85,
            backend="vllm",
            model="deepseek-coder",
        )
        assert r.success is True
        assert r.confidence == 0.85
        assert r.backend == "vllm"


# ---------------------------------------------------------------------------
# _infer_language tests
# ---------------------------------------------------------------------------
class TestInferLanguage:
    def test_python(self):
        assert _infer_language("app/main.py") == "python"

    def test_javascript(self):
        assert _infer_language("src/index.js") == "javascript"

    def test_typescript(self):
        assert _infer_language("src/app.ts") == "typescript"

    def test_tsx(self):
        assert _infer_language("Component.tsx") == "typescript"

    def test_java(self):
        assert _infer_language("App.java") == "java"

    def test_go(self):
        assert _infer_language("main.go") == "go"

    def test_rust(self):
        assert _infer_language("lib.rs") == "rust"

    def test_yaml(self):
        assert _infer_language("config.yaml") == "yaml"
        assert _infer_language("config.yml") == "yaml"

    def test_json(self):
        assert _infer_language("package.json") == "json"

    def test_unknown(self):
        assert _infer_language("readme.txt") == "text"

    def test_no_extension(self):
        assert _infer_language("Dockerfile") == "text"

    def test_terraform(self):
        assert _infer_language("main.tf") == "hcl"


# ---------------------------------------------------------------------------
# Deterministic fix rules tests
# ---------------------------------------------------------------------------
class TestDeterministicFixRules:
    def test_sql_injection_rule(self):
        rule = _DETERMINISTIC_FIX_RULES["CWE-89"]
        assert "parameterized" in rule["explanation"]
        assert rule["confidence"] > 0

    def test_xss_rule(self):
        rule = _DETERMINISTIC_FIX_RULES["CWE-79"]
        assert "escap" in rule["explanation"].lower() or "encod" in rule["explanation"].lower()

    def test_command_injection_rule(self):
        rule = _DETERMINISTIC_FIX_RULES["CWE-78"]
        assert "subprocess" in rule["code_pattern"]

    def test_deserialization_rule(self):
        rule = _DETERMINISTIC_FIX_RULES["CWE-502"]
        assert "pickle" in rule["code_pattern"]

    def test_hardcoded_creds_rule(self):
        rule = _DETERMINISTIC_FIX_RULES["CWE-798"]
        assert "environment" in rule["explanation"]

    def test_ssrf_rule(self):
        rule = _DETERMINISTIC_FIX_RULES["CWE-918"]
        assert "SSRF" in rule["explanation"] or "URL" in rule["explanation"]

    def test_path_traversal_rule(self):
        rule = _DETERMINISTIC_FIX_RULES["CWE-22"]
        assert "traversal" in rule["explanation"]

    def test_weak_crypto_rule(self):
        rule = _DETERMINISTIC_FIX_RULES["CWE-327"]
        assert "SHA256" in rule["code_pattern"]

    def test_all_rules_have_required_keys(self):
        for cwe, rule in _DETERMINISTIC_FIX_RULES.items():
            assert "explanation" in rule, f"{cwe} missing explanation"
            assert "code_pattern" in rule, f"{cwe} missing code_pattern"
            assert "confidence" in rule, f"{cwe} missing confidence"
            assert 0 < rule["confidence"] <= 1.0, f"{cwe} confidence out of range"


# ---------------------------------------------------------------------------
# Keyword fix rules tests
# ---------------------------------------------------------------------------
class TestKeywordFixRules:
    def test_sql_injection_keyword(self):
        assert "sql injection" in _KEYWORD_FIX_RULES
        assert _KEYWORD_FIX_RULES["sql injection"] == _DETERMINISTIC_FIX_RULES["CWE-89"]

    def test_xss_keyword(self):
        assert "xss" in _KEYWORD_FIX_RULES

    def test_command_injection_keyword(self):
        assert "command injection" in _KEYWORD_FIX_RULES

    def test_ssrf_keyword(self):
        assert "ssrf" in _KEYWORD_FIX_RULES

    def test_hardcoded_keyword(self):
        assert "hardcoded" in _KEYWORD_FIX_RULES

    def test_path_traversal_keyword(self):
        assert "path traversal" in _KEYWORD_FIX_RULES


# ---------------------------------------------------------------------------
# VLLMAutoFixAdapter tests
# ---------------------------------------------------------------------------
class TestVLLMAutoFixAdapter:
    @pytest.fixture
    def adapter(self):
        return VLLMAutoFixAdapter(backend="auto")

    def test_init_default(self, adapter):
        assert adapter.backend_preference == "auto"

    def test_get_active_backend_none(self, adapter):
        # No real vLLM/Ollama running in test env
        backend = adapter.get_active_backend()
        assert backend == "none"

    def test_build_fix_prompt_code(self, adapter):
        finding = {
            "title": "SQL Injection in user query",
            "severity": "high",
            "cwe_id": "CWE-89",
            "description": "User input concatenated in SQL",
            "file_path": "app/db.py",
        }
        prompt = adapter.build_fix_prompt(finding, "cursor.execute('SELECT * FROM users WHERE id=' + uid)")
        assert "SQL Injection" in prompt
        assert "high" in prompt
        assert "CWE-89" in prompt
        assert "app/db.py" in prompt

    def test_build_fix_prompt_dependency(self, adapter):
        finding = {
            "title": "Outdated dependency vulnerability",
            "severity": "medium",
            "category": "dependency",
            "package_name": "lodash",
            "current_version": "4.17.15",
            "cve_ids": ["CVE-2024-1234"],
        }
        prompt = adapter.build_fix_prompt(finding)
        assert "lodash" in prompt
        assert "4.17.15" in prompt

    def test_build_fix_prompt_config(self, adapter):
        finding = {
            "title": "Insecure TLS config",
            "severity": "high",
            "cwe_id": "CWE-327",
            "description": "TLS 1.0 enabled",
            "file_path": "config/tls.yaml",
        }
        prompt = adapter.build_fix_prompt(finding, "tls_version: 1.0")
        assert "config/tls.yaml" in prompt

    def test_generate_fix_deterministic(self, adapter):
        finding = {
            "title": "SQL Injection",
            "severity": "high",
            "cwe_id": "CWE-89",
            "file_path": "app.py",
        }
        result = adapter.generate_fix(finding)
        assert result.backend == "deterministic"
        assert result.success is True
        assert result.confidence > 0

    def test_generate_fix_by_keyword(self, adapter):
        finding = {
            "title": "XSS reflected cross-site scripting",
            "severity": "high",
            "file_path": "views.py",
        }
        result = adapter.generate_fix(finding)
        assert result.success is True
        assert result.backend == "deterministic"

    def test_generate_fix_no_match(self, adapter):
        finding = {
            "title": "Obscure vulnerability type",
            "severity": "low",
            "cwe_id": "CWE-99999",
            "file_path": "unknown.py",
        }
        result = adapter.generate_fix(finding)
        assert result.success is False
        assert result.backend == "none"

    def test_generate_fix_hardcoded_creds(self, adapter):
        finding = {
            "title": "Hardcoded password in config",
            "severity": "high",
            "cwe_id": "CWE-798",
            "file_path": "settings.py",
        }
        result = adapter.generate_fix(finding)
        assert result.success is True
        assert "environment" in result.explanation.lower()

    def test_get_status(self, adapter):
        status = adapter.get_status()
        assert "backend_preference" in status
        assert "active_backend" in status
        assert "providers" in status
        assert "vllm" in status["providers"]
        assert "ollama" in status["providers"]

    def test_init_with_explicit_urls(self):
        adapter = VLLMAutoFixAdapter(
            vllm_url="http://vllm.local:8001/v1",
            ollama_url="http://ollama.local:11434",
            vllm_model="codellama:7b",
            ollama_model="deepseek-coder:6.7b",
            backend="vllm",
        )
        assert adapter.backend_preference == "vllm"
        assert adapter._vllm_url == "http://vllm.local:8001/v1"

    def test_deterministic_fix_all_cwes(self, adapter):
        """Test deterministic fix for every known CWE."""
        for cwe_id in _DETERMINISTIC_FIX_RULES:
            finding = {
                "title": f"Vulnerability {cwe_id}",
                "severity": "high",
                "cwe_id": cwe_id,
                "file_path": "test.py",
            }
            result = adapter._deterministic_fix(finding)
            assert result.success is True
            assert result.backend == "deterministic"
            assert result.confidence > 0

    def test_deterministic_fix_keyword_match(self, adapter):
        for keyword in _KEYWORD_FIX_RULES:
            finding = {
                "title": f"Found {keyword} vulnerability",
                "severity": "medium",
                "file_path": "test.py",
            }
            result = adapter._deterministic_fix(finding)
            assert result.success is True
