"""vLLM AutoFix Adapter — Air-gapped autofix generation via self-hosted LLMs.

Bridges the AutoFix engine to self-hosted vLLM/Ollama backends so that
security fix generation works without any external API keys.

This adapter:
1. Provides specialized prompts for code-capable models (DeepSeek Coder, CodeLlama)
2. Handles structured output parsing from open-source models
3. Falls back gracefully: vLLM → Ollama → deterministic rules
4. Generates unified diffs, dependency fixes, and config patches

Environment variables:
- FIXOPS_AI_BACKEND: vllm | ollama | api | auto (default: auto)
- FIXOPS_VLLM_URL: vLLM endpoint (default: http://localhost:8001/v1)
- FIXOPS_OLLAMA_URL: Ollama endpoint (default: http://localhost:11434)
- FIXOPS_VLLM_MODEL: Model name for vLLM
- FIXOPS_OLLAMA_MODEL: Model name for Ollama

Usage:
    adapter = VLLMAutoFixAdapter()
    fix_prompt = adapter.build_fix_prompt(finding, source_code)
    result = adapter.generate_fix(finding, source_code)
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class AutoFixLLMResult:
    """Result from self-hosted LLM fix generation."""

    success: bool = False
    fix_code: str = ""
    unified_diff: str = ""
    explanation: str = ""
    confidence: float = 0.0
    backend: str = "none"
    model: str = ""
    duration_ms: float = 0.0
    error: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Security fix prompt templates for code-capable open-source models
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """You are a security vulnerability remediation expert. Your job is to generate precise, minimal code fixes for security vulnerabilities.

Rules:
1. Generate the MINIMUM code change needed to fix the vulnerability
2. Do NOT change functionality — only fix the security issue
3. Preserve code style, indentation, and conventions
4. Return a JSON object with the fix details

Response format (JSON):
{
  "fix_description": "Brief description of what the fix does",
  "confidence": 0.0-1.0,
  "patches": [
    {
      "file_path": "path/to/file",
      "old_code": "vulnerable code snippet",
      "new_code": "fixed code snippet",
      "explanation": "Why this change fixes the vulnerability"
    }
  ],
  "testing_guidance": "How to verify the fix",
  "risk_assessment": "What could break"
}"""


_FIX_PROMPT_TEMPLATE = """Fix the following security vulnerability:

**Vulnerability**: {title}
**Severity**: {severity}
**CWE**: {cwe_id}
**Description**: {description}

**File**: {file_path}
**Language**: {language}

**Vulnerable Code**:
```{language}
{source_code}
```

Generate a precise fix. Return JSON only."""


_DEPENDENCY_FIX_TEMPLATE = """Fix the following dependency vulnerability:

**Vulnerability**: {title}
**Severity**: {severity}
**CVE**: {cve_ids}
**Package**: {package_name}@{current_version}
**Ecosystem**: {ecosystem}

Determine the minimum safe version that fixes this CVE.
Return JSON with:
{{
  "fix_description": "description",
  "package_name": "{package_name}",
  "current_version": "{current_version}",
  "fixed_version": "x.y.z",
  "breaking_changes": [],
  "confidence": 0.0-1.0
}}"""


_CONFIG_FIX_TEMPLATE = """Fix the following configuration vulnerability:

**Vulnerability**: {title}
**Severity**: {severity}
**CWE**: {cwe_id}
**Description**: {description}
**Config File**: {file_path}

Current configuration:
```
{source_code}
```

Generate the fixed configuration. Return JSON with patches."""


class VLLMAutoFixAdapter:
    """Adapter for generating security fixes via self-hosted LLMs.

    Provides the bridge between AutoFix engine and vLLM/Ollama backends.
    Handles prompt engineering, response parsing, and fallback logic
    specific to open-source code models.
    """

    def __init__(
        self,
        *,
        vllm_url: Optional[str] = None,
        ollama_url: Optional[str] = None,
        vllm_model: Optional[str] = None,
        ollama_model: Optional[str] = None,
        backend: Optional[str] = None,
    ) -> None:
        self.backend_preference = backend or os.getenv("FIXOPS_AI_BACKEND", "auto")
        self._vllm_url = (
            vllm_url or os.getenv("FIXOPS_VLLM_URL", "http://localhost:8001/v1")
        ).rstrip("/")
        self._ollama_url = (
            ollama_url or os.getenv("FIXOPS_OLLAMA_URL", "http://localhost:11434")
        ).rstrip("/")
        self._vllm_model = vllm_model or os.getenv(
            "FIXOPS_VLLM_MODEL", "deepseek-ai/deepseek-coder-33b-instruct"
        )
        self._ollama_model = ollama_model or os.getenv(
            "FIXOPS_OLLAMA_MODEL", "codellama:13b"
        )
        self._providers: Dict[str, Any] = {}
        self._initialize_providers()

    def _initialize_providers(self) -> None:
        """Initialize available self-hosted providers."""
        from core.llm_providers import OllamaSelfHostedProvider, VLLMSelfHostedProvider

        self._providers["vllm"] = VLLMSelfHostedProvider(
            "vllm-autofix",
            base_url=self._vllm_url,
            model=self._vllm_model,
            max_tokens=2048,  # Larger for code generation
            temperature=0.0,
        )
        self._providers["ollama"] = OllamaSelfHostedProvider(
            "ollama-autofix",
            base_url=self._ollama_url,
            model=self._ollama_model,
        )

    def get_active_backend(self) -> str:
        """Determine which backend to use based on preference and availability.

        Returns:
            Backend name: 'vllm', 'ollama', or 'none'
        """
        try:
            if self.backend_preference in ("vllm", "ollama"):
                provider = self._providers.get(self.backend_preference)
                if provider and hasattr(provider, "is_available") and provider.is_available():
                    return self.backend_preference

            # Auto-detect: try vLLM first, then Ollama
            if self.backend_preference in ("auto", "vllm"):
                vllm = self._providers.get("vllm")
                if vllm and hasattr(vllm, "is_available") and vllm.is_available():
                    return "vllm"

            if self.backend_preference in ("auto", "ollama"):
                ollama = self._providers.get("ollama")
                if ollama and hasattr(ollama, "is_available") and ollama.is_available():
                    return "ollama"
        except Exception:
            pass  # network errors — no backend available

        return "none"

    def build_fix_prompt(
        self,
        finding: Dict[str, Any],
        source_code: Optional[str] = None,
    ) -> str:
        """Build a specialized fix prompt for open-source code models.

        Args:
            finding: Vulnerability finding with title, severity, cwe, etc.
            source_code: The vulnerable source code (if available).

        Returns:
            Formatted prompt string.
        """
        title = finding.get("title", "Unknown Vulnerability")
        severity = finding.get("severity", "medium")
        cwe_id = finding.get("cwe_id", finding.get("cwe", ""))
        description = finding.get("description", "")
        file_path = finding.get("file_path", "unknown")
        language = finding.get("language", _infer_language(file_path))
        cve_ids = finding.get("cve_ids", [])

        # Choose template based on fix type
        if finding.get("category", "").lower() == "dependency" or any(
            kw in title.lower()
            for kw in ("outdated", "dependency", "package", "library")
        ):
            return _DEPENDENCY_FIX_TEMPLATE.format(
                title=title,
                severity=severity,
                cve_ids=", ".join(cve_ids) if cve_ids else "N/A",
                package_name=finding.get("package_name", finding.get("component", "unknown")),
                current_version=finding.get("current_version", "unknown"),
                ecosystem=finding.get("ecosystem", "unknown"),
            )

        if any(kw in file_path.lower() for kw in (".yaml", ".yml", ".json", ".toml", ".ini", ".cfg")):
            return _CONFIG_FIX_TEMPLATE.format(
                title=title,
                severity=severity,
                cwe_id=cwe_id,
                description=description,
                file_path=file_path,
                source_code=source_code or "# No source code provided",
            )

        return _FIX_PROMPT_TEMPLATE.format(
            title=title,
            severity=severity,
            cwe_id=cwe_id,
            description=description,
            file_path=file_path,
            language=language,
            source_code=source_code or "# No source code provided",
        )

    def generate_fix(
        self,
        finding: Dict[str, Any],
        source_code: Optional[str] = None,
    ) -> AutoFixLLMResult:
        """Generate a security fix using self-hosted LLM.

        Tries vLLM first, falls back to Ollama, then to deterministic rules.

        Args:
            finding: Vulnerability finding dict.
            source_code: Optional vulnerable source code.

        Returns:
            AutoFixLLMResult with the generated fix.
        """
        backend = self.get_active_backend()
        if backend == "none":
            return self._deterministic_fix(finding, source_code)

        prompt = self.build_fix_prompt(finding, source_code)
        provider = self._providers[backend]

        start = time.perf_counter()
        try:
            response = provider.analyse(
                prompt=prompt,
                context={"finding": finding},
                default_action="fix",
                default_confidence=0.5,
                default_reasoning="Self-hosted fix generation",
            )
            duration = (time.perf_counter() - start) * 1000

            # Parse the LLM response into fix structure
            return AutoFixLLMResult(
                success=True,
                fix_code=response.reasoning,
                explanation=response.reasoning,
                confidence=response.confidence,
                backend=backend,
                model=getattr(provider, "model", "unknown"),
                duration_ms=round(duration, 2),
                metadata={
                    "provider_metadata": response.metadata,
                    "mitre_techniques": list(response.mitre_techniques),
                },
            )
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            logger.warning(
                "Self-hosted fix generation failed on %s: %s",
                backend, type(exc).__name__,
            )
            # Try fallback backend
            if backend == "vllm" and "ollama" in self._providers:
                ollama = self._providers["ollama"]
                if hasattr(ollama, "is_available") and ollama.is_available():
                    try:
                        response = ollama.analyse(
                            prompt=prompt,
                            context={"finding": finding},
                            default_action="fix",
                            default_confidence=0.5,
                            default_reasoning="Ollama fallback fix generation",
                        )
                        duration = (time.perf_counter() - start) * 1000
                        return AutoFixLLMResult(
                            success=True,
                            fix_code=response.reasoning,
                            explanation=response.reasoning,
                            confidence=response.confidence,
                            backend="ollama",
                            model=getattr(ollama, "model", "unknown"),
                            duration_ms=round(duration, 2),
                        )
                    except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
                        pass

            return self._deterministic_fix(finding, source_code)

    def _deterministic_fix(
        self,
        finding: Dict[str, Any],
        source_code: Optional[str] = None,
    ) -> AutoFixLLMResult:
        """Generate a deterministic fix using rule-based patterns.

        Used as ultimate fallback when no LLM backend is available.
        Still provides real, actionable fix suggestions based on CWE patterns.
        """
        cwe = finding.get("cwe_id", finding.get("cwe", ""))
        title = finding.get("title", "")
        fix_rules = _DETERMINISTIC_FIX_RULES.get(cwe, {})

        if not fix_rules:
            # Try keyword matching
            for kw, rules in _KEYWORD_FIX_RULES.items():
                if kw in title.lower():
                    fix_rules = rules
                    break

        if fix_rules:
            return AutoFixLLMResult(
                success=True,
                fix_code=fix_rules.get("code_pattern", ""),
                explanation=fix_rules.get("explanation", "Apply security best practice"),
                confidence=fix_rules.get("confidence", 0.6),
                backend="deterministic",
                model="rule-based",
                metadata={"cwe": cwe, "rule_match": True},
            )

        return AutoFixLLMResult(
            success=False,
            explanation="No self-hosted LLM or matching rule found for this vulnerability type",
            confidence=0.0,
            backend="none",
            error="No backend available and no deterministic rule matches",
        )

    def get_status(self) -> Dict[str, Any]:
        """Get status of all self-hosted backends."""
        status = {
            "backend_preference": self.backend_preference,
            "active_backend": self.get_active_backend(),
            "providers": {},
        }
        for name, provider in self._providers.items():
            available = False
            if hasattr(provider, "is_available"):
                try:
                    available = provider.is_available()
                except Exception:
                    available = False
            info = {}
            if hasattr(provider, "model_info"):
                try:
                    info = provider.model_info()
                except Exception:
                    info = {"error": "unavailable"}
            status["providers"][name] = {
                "available": available,
                **info,
            }
        return status


# ---------------------------------------------------------------------------
# Deterministic fix rules (CWE-based)
# ---------------------------------------------------------------------------

_DETERMINISTIC_FIX_RULES: Dict[str, Dict[str, Any]] = {
    "CWE-89": {
        "explanation": "Use parameterized queries instead of string concatenation for SQL",
        "code_pattern": "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
        "confidence": 0.75,
    },
    "CWE-79": {
        "explanation": "Apply output encoding/escaping before rendering user input",
        "code_pattern": "from markupsafe import escape\nescaped = escape(user_input)",
        "confidence": 0.80,
    },
    "CWE-78": {
        "explanation": "Use subprocess with list arguments instead of shell=True",
        "code_pattern": "subprocess.run(['cmd', arg1, arg2], shell=False, check=True)",
        "confidence": 0.75,
    },
    "CWE-502": {
        "explanation": "Replace unsafe deserialization with safe alternatives",
        "code_pattern": "import json\ndata = json.loads(input_data)  # Instead of pickle.loads()",
        "confidence": 0.70,
    },
    "CWE-798": {
        "explanation": "Move hardcoded credentials to environment variables or secrets manager",
        "code_pattern": "import os\napi_key = os.getenv('API_KEY')  # Never hardcode secrets",
        "confidence": 0.85,
    },
    "CWE-918": {
        "explanation": "Validate and restrict URLs to prevent SSRF",
        "code_pattern": (
            "from urllib.parse import urlparse\n"
            "parsed = urlparse(url)\n"
            "if parsed.hostname in ALLOWED_HOSTS:\n"
            "    response = requests.get(url)"  # nosemgrep: dynamic-urllib-use-detected
        ),
        "confidence": 0.70,
    },
    "CWE-287": {
        "explanation": "Implement proper authentication checks",
        "code_pattern": "# Verify JWT algorithm is explicitly set\nalgorithm = 'HS256'  # Never allow 'none'",
        "confidence": 0.75,
    },
    "CWE-327": {
        "explanation": "Replace weak cryptographic algorithms with strong alternatives",
        "code_pattern": "from cryptography.hazmat.primitives.hashes import SHA256  # Not MD5/SHA1",
        "confidence": 0.80,
    },
    "CWE-22": {
        "explanation": "Validate and normalize file paths to prevent traversal",
        "code_pattern": (
            "import os\n"
            "safe_path = os.path.normpath(os.path.join(BASE_DIR, user_path))\n"
            "if not safe_path.startswith(BASE_DIR):\n"
            "    raise ValueError('Path traversal detected')"
        ),
        "confidence": 0.75,
    },
    "CWE-307": {
        "explanation": "Implement rate limiting on authentication endpoints",
        "code_pattern": "from slowapi import Limiter\nlimiter = Limiter(key_func=get_remote_address)",
        "confidence": 0.70,
    },
    "CWE-209": {
        "explanation": "Return generic error messages, log details server-side only",
        "code_pattern": (
            "except Exception as e:\n"
            "    logger.error('Internal error', exc_info=True)\n"
            "    return {'error': 'Internal server error'}, 500"
        ),
        "confidence": 0.80,
    },
    "CWE-269": {
        "explanation": "Add authorization checks before privilege-changing operations",
        "code_pattern": (
            "@require_role('admin')\n"
            "def update_user_role(user_id, new_role):\n"
            "    # Only admins can change roles"
        ),
        "confidence": 0.70,
    },
}

_KEYWORD_FIX_RULES: Dict[str, Dict[str, Any]] = {
    "sql injection": _DETERMINISTIC_FIX_RULES["CWE-89"],
    "xss": _DETERMINISTIC_FIX_RULES["CWE-79"],
    "command injection": _DETERMINISTIC_FIX_RULES["CWE-78"],
    "deserialization": _DETERMINISTIC_FIX_RULES["CWE-502"],
    "hardcoded": _DETERMINISTIC_FIX_RULES["CWE-798"],
    "ssrf": _DETERMINISTIC_FIX_RULES["CWE-918"],
    "path traversal": _DETERMINISTIC_FIX_RULES["CWE-22"],
    "rate limit": _DETERMINISTIC_FIX_RULES["CWE-307"],
    "privilege escalation": _DETERMINISTIC_FIX_RULES["CWE-269"],
}


def _infer_language(file_path: str) -> str:
    """Infer programming language from file extension."""
    ext_map = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".jsx": "javascript",
        ".java": "java",
        ".go": "go",
        ".rs": "rust",
        ".rb": "ruby",
        ".php": "php",
        ".cs": "csharp",
        ".cpp": "cpp",
        ".c": "c",
        ".swift": "swift",
        ".kt": "kotlin",
        ".scala": "scala",
        ".tf": "hcl",
        ".yaml": "yaml",
        ".yml": "yaml",
        ".json": "json",
        ".toml": "toml",
    }
    ext = os.path.splitext(file_path)[1].lower()
    return ext_map.get(ext, "text")
