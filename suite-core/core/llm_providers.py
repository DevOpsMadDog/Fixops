"""LLM provider adapters for the enhanced decision engine."""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Sequence

logger = logging.getLogger(__name__)

import requests  # type: ignore[import-untyped]
from dotenv import load_dotenv

# Load environment variables from .env file so API keys are available
load_dotenv()

# TrustGraph event bus — optional, never blocks on failure
try:  # pragma: no cover - bus is optional
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload: Dict[str, Any]) -> None:
    """Emit an event to the TrustGraph event bus. Never raises."""
    if _get_tg_bus is None:
        return
    try:
        bus = _get_tg_bus()
        if bus is None:
            return
        emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
        if emit is None:
            return
        result = emit(event_type, payload)
        try:
            import asyncio
            import inspect
            if inspect.iscoroutine(result):
                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    result.close()
        except Exception:  # pragma: no cover
            pass
    except Exception:  # pragma: no cover
        pass


@dataclass
class LLMResponse:
    """Normalised output returned by a provider invocation.

    SPEC-003 honest-labelling contract
    -----------------------------------
    Every response now carries three mandatory provenance fields so callers
    (council, learning loop, UI) can distinguish a genuine model verdict from a
    heuristic/deterministic fallback:

    ``source``
        Human-readable provenance string.  One of:
        - ``"local_model:<backend>:<model>"``   — real inference via local LLM
        - ``"remote:<provider>:<model>"``        — real inference via cloud API
        - ``"heuristic"``                        — deterministic rule / no model

    ``is_real_inference``
        True only when a model (local or cloud) was actually called and the
        response text came from that model. False for heuristic/deterministic
        paths. MUST NOT be set True on a fallback/error path. This is the
        machine-readable DPO guard — the learning loop checks it before
        accepting a verdict as training signal.

    ``model``
        The model identifier string, or None when is_real_inference is False.
    """

    recommended_action: str
    confidence: float
    reasoning: str
    mitre_techniques: Sequence[str] = field(default_factory=list)
    compliance_concerns: Sequence[str] = field(default_factory=list)
    attack_vectors: Sequence[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    # SPEC-003: honest provenance fields — always set by providers
    source: str = "heuristic"
    is_real_inference: bool = False
    model: Optional[str] = None


class BaseLLMProvider:
    """Base class for LLM provider adapters."""

    def __init__(
        self, name: str, *, style: str = "consensus", focus: Sequence[str] | None = None
    ) -> None:
        self.name = name
        self.style = style
        self.focus = list(focus or [])

    def analyse(
        self,
        *,
        prompt: str,
        context: Mapping[str, Any],
        default_action: str,
        default_confidence: float,
        default_reasoning: str,
        mitigation_hints: Mapping[str, Any] | None = None,
        system_prompt: str | None = None,
    ) -> LLMResponse:
        """Return a deterministic/heuristic response when a provider cannot be reached.

        SPEC-003: sets is_real_inference=False and source="heuristic" so callers
        (learning loop, council) can detect that no model was consulted.  Reasoning
        is explicitly labelled with "[heuristic: no local or cloud model available]"
        so the label is visible at every layer, not just in metadata.
        """

        heuristic_label = "[heuristic: no local or cloud model available]"
        metadata = {
            "mode": "deterministic",
            "reason": "provider_disabled",
            "style": self.style,
        }
        hints = dict(mitigation_hints or {})
        mitre = _ensure_list(hints.get("mitre_candidates"))
        compliance = _ensure_list(hints.get("compliance"))
        attack_vectors = _ensure_list(hints.get("attack_vectors"))
        # Embed the heuristic label in reasoning so every consumer sees it
        labelled_reasoning = (
            default_reasoning
            if default_reasoning.endswith(heuristic_label)
            else f"{default_reasoning} {heuristic_label}"
        )
        response = LLMResponse(
            recommended_action=default_action,
            confidence=default_confidence,
            reasoning=labelled_reasoning,
            mitre_techniques=mitre,
            compliance_concerns=compliance,
            attack_vectors=attack_vectors,
            metadata=metadata,
            # SPEC-003: explicit honest labelling — never claim to be a model verdict
            source="heuristic",
            is_real_inference=False,
            model=None,
        )
        _emit_event(
            "llm.analysis.completed",
            {
                "provider": self.name,
                "style": self.style,
                "mode": metadata.get("mode", "unknown"),
                "recommended_action": response.recommended_action,
                "confidence": response.confidence,
                "mitre_count": len(response.mitre_techniques),
            },
        )
        return response


class DeterministicLLMProvider(BaseLLMProvider):
    """Provider that always echoes the heuristic defaults."""


class OpenAIChatProvider(BaseLLMProvider):
    """Adapter for OpenAI chat completion models."""

    def __init__(
        self,
        name: str,
        *,
        model: str = "gpt-5.2",
        api_key_envs: Sequence[str] | None = None,
        timeout: float = 30.0,
        focus: Sequence[str] | None = None,
        style: str = "consensus",
    ) -> None:
        super().__init__(name, style=style, focus=focus)
        # Allow env-var override for model selection
        self.model = os.environ.get("FIXOPS_OPENAI_MODEL", model)
        self.api_key_envs = list(
            api_key_envs or ("OPENAI_API_KEY", "FIXOPS_OPENAI_KEY")
        )
        self.timeout = timeout
        self.api_key = self._resolve_api_key()
        self._session = requests.Session()

    _DEFAULT_SYSTEM_PROMPT = (
        "You are a security decision assistant. Return JSON with keys "
        "recommended_action, confidence, reasoning, mitre_techniques, "
        "compliance_concerns, attack_vectors."
    )

    def analyse(
        self,
        *,
        prompt: str,
        context: Mapping[str, Any],
        default_action: str,
        default_confidence: float,
        default_reasoning: str,
        mitigation_hints: Mapping[str, Any] | None = None,
        system_prompt: str | None = None,
    ) -> LLMResponse:
        if not self.api_key:
            return super().analyse(
                prompt=prompt,
                context=context,
                default_action=default_action,
                default_confidence=default_confidence,
                default_reasoning=default_reasoning,
                mitigation_hints=mitigation_hints,
            )
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": system_prompt or self._DEFAULT_SYSTEM_PROMPT,
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
            "temperature": 0,
            "response_format": {"type": "json_object"},
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        start = time.perf_counter()
        try:
            response = self._session.post(
                "https://api.openai.com/v1/chat/completions",
                json=payload,
                headers=headers,
                timeout=self.timeout,
            )
            response.raise_for_status()
            response_json = response.json()

            if "choices" not in response_json or not response_json["choices"]:
                raise ValueError("OpenAI response missing choices")

            message = response_json["choices"][0].get("message", {})
            content = message.get("content")

            if not content:
                raise ValueError("OpenAI response missing message content")

            try:
                parsed = json.loads(content)
            except json.JSONDecodeError as json_exc:
                raise ValueError(
                    f"OpenAI returned non-JSON content: {content[:100]}"
                ) from json_exc
        except requests.Timeout as exc:
            metadata = {
                "mode": "fallback",
                "provider": self.name,
                "error": f"Timeout after {self.timeout}s",
                "model": self.model,
                "error_type": "timeout",
            }
            return LLMResponse(
                recommended_action=default_action,
                confidence=default_confidence,
                reasoning=f"{default_reasoning}\n[OpenAI timeout: {exc}]",
                mitre_techniques=_ensure_list(
                    (mitigation_hints or {}).get("mitre_candidates")
                ),
                compliance_concerns=_ensure_list(
                    (mitigation_hints or {}).get("compliance")
                ),
                attack_vectors=_ensure_list(
                    (mitigation_hints or {}).get("attack_vectors")
                ),
                metadata=metadata,
            )
        except requests.HTTPError as exc:
            error_detail = "HTTP error"
            if exc.response is not None:
                try:
                    error_json = exc.response.json()
                    # Extract structured error message, never raw exception string — may contain API keys
                    error_detail = error_json.get("error", {}).get("message", f"HTTP {exc.response.status_code}")
                except (ValueError, KeyError, RuntimeError, TypeError, AttributeError):
                    error_detail = f"HTTP {exc.response.status_code}" if exc.response else type(exc).__name__
            metadata = {
                "mode": "fallback",
                "provider": self.name,
                "error": error_detail,
                "model": self.model,
                "error_type": "http_error",
                "status_code": exc.response.status_code if exc.response else None,  # type: ignore[dict-item]
            }
            return LLMResponse(
                recommended_action=default_action,
                confidence=default_confidence,
                reasoning=f"{default_reasoning}\n[OpenAI error: {error_detail}]",
                mitre_techniques=_ensure_list(
                    (mitigation_hints or {}).get("mitre_candidates")
                ),
                compliance_concerns=_ensure_list(
                    (mitigation_hints or {}).get("compliance")
                ),
                attack_vectors=_ensure_list(
                    (mitigation_hints or {}).get("attack_vectors")
                ),
                metadata=metadata,
            )
        except (json.JSONDecodeError, KeyError, ValueError) as exc:
            metadata = {
                "mode": "fallback",
                "provider": self.name,
                "error": f"Invalid response format: {exc}",
                "model": self.model,
                "error_type": "parse_error",
            }
            return LLMResponse(
                recommended_action=default_action,
                confidence=default_confidence,
                reasoning=f"{default_reasoning}\n[OpenAI parse error: {exc}]",
                mitre_techniques=_ensure_list(
                    (mitigation_hints or {}).get("mitre_candidates")
                ),
                compliance_concerns=_ensure_list(
                    (mitigation_hints or {}).get("compliance")
                ),
                attack_vectors=_ensure_list(
                    (mitigation_hints or {}).get("attack_vectors")
                ),
                metadata=metadata,
            )
        except Exception as exc:  # noqa: BLE001 - capture provider error
            logger.warning(
                "OpenAI provider %s failed, falling back to deterministic: %s",
                self.name,
                type(exc).__name__,
            )
            metadata = {
                "mode": "fallback",
                "provider": self.name,
                "error": type(exc).__name__,
                "model": self.model,
                "error_type": type(exc).__name__,
            }
            return LLMResponse(
                recommended_action=default_action,
                confidence=default_confidence,
                reasoning=f"{default_reasoning}\n[OpenAI fallback: {type(exc).__name__}]",
                mitre_techniques=_ensure_list(
                    (mitigation_hints or {}).get("mitre_candidates")
                ),
                compliance_concerns=_ensure_list(
                    (mitigation_hints or {}).get("compliance")
                ),
                attack_vectors=_ensure_list(
                    (mitigation_hints or {}).get("attack_vectors")
                ),
                metadata=metadata,
            )
        duration = (time.perf_counter() - start) * 1000
        return _response_from_payload(
            parsed,
            default_action=default_action,
            default_confidence=default_confidence,
            default_reasoning=default_reasoning,
            mitigation_hints=mitigation_hints,
            metadata={
                "mode": "remote",
                "provider": self.name,
                "model": self.model,
                "duration_ms": round(duration, 2),
            },
        )

    def _resolve_api_key(self) -> Optional[str]:
        for env_name in self.api_key_envs:
            value = os.getenv(env_name)
            if value:
                token = value.strip()
                if token:
                    return token
        return None


class AnthropicMessagesProvider(BaseLLMProvider):
    """Adapter for Anthropic Claude models."""

    def __init__(
        self,
        name: str,
        *,
        model: str = "claude-sonnet-4-20250514",
        api_key_envs: Sequence[str] | None = None,
        timeout: float = 30.0,
        focus: Sequence[str] | None = None,
        style: str = "analyst",
    ) -> None:
        super().__init__(name, style=style, focus=focus)
        # Allow env-var override for model selection
        self.model = os.environ.get("FIXOPS_ANTHROPIC_MODEL", model)
        self.api_key_envs = list(
            api_key_envs or ("ANTHROPIC_API_KEY", "FIXOPS_ANTHROPIC_KEY")
        )
        self.timeout = timeout
        self.api_key = self._resolve_api_key()
        self._session = requests.Session()

    _DEFAULT_SYSTEM_PROMPT = (
        "Return a JSON object with recommended_action, confidence, reasoning, "
        "mitre_techniques, compliance_concerns, attack_vectors."
    )

    def analyse(
        self,
        *,
        prompt: str,
        context: Mapping[str, Any],
        default_action: str,
        default_confidence: float,
        default_reasoning: str,
        mitigation_hints: Mapping[str, Any] | None = None,
        system_prompt: str | None = None,
    ) -> LLMResponse:
        if not self.api_key:
            return super().analyse(
                prompt=prompt,
                context=context,
                default_action=default_action,
                default_confidence=default_confidence,
                default_reasoning=default_reasoning,
                mitigation_hints=mitigation_hints,
            )
        payload = {
            "model": self.model,
            "max_tokens": 2048,
            "temperature": 0,
            "system": system_prompt or self._DEFAULT_SYSTEM_PROMPT,
            "messages": [
                {"role": "user", "content": prompt},
            ],
        }
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        start = time.perf_counter()
        try:
            response = self._session.post(
                "https://api.anthropic.com/v1/messages",
                json=payload,
                headers=headers,
                timeout=self.timeout,
            )
            response.raise_for_status()
            content = response.json()["content"][0]["text"]
            parsed = json.loads(content)
        except Exception as exc:  # noqa: BLE001 - capture provider error
            logger.warning(
                "Anthropic provider %s failed, falling back to deterministic: %s",
                self.name,
                type(exc).__name__,
            )
            metadata = {
                "mode": "fallback",
                "provider": self.name,
                "error": type(exc).__name__,
                "model": self.model,
            }
            return LLMResponse(
                recommended_action=default_action,
                confidence=default_confidence,
                reasoning=f"{default_reasoning}\n[Anthropic fallback: {type(exc).__name__}]",
                mitre_techniques=_ensure_list(
                    (mitigation_hints or {}).get("mitre_candidates")
                ),
                compliance_concerns=_ensure_list(
                    (mitigation_hints or {}).get("compliance")
                ),
                attack_vectors=_ensure_list(
                    (mitigation_hints or {}).get("attack_vectors")
                ),
                metadata=metadata,
            )
        duration = (time.perf_counter() - start) * 1000
        return _response_from_payload(
            parsed,
            default_action=default_action,
            default_confidence=default_confidence,
            default_reasoning=default_reasoning,
            mitigation_hints=mitigation_hints,
            metadata={
                "mode": "remote",
                "provider": self.name,
                "model": self.model,
                "duration_ms": round(duration, 2),
            },
        )

    def _resolve_api_key(self) -> Optional[str]:
        for env_name in self.api_key_envs:
            value = os.getenv(env_name)
            if value:
                token = value.strip()
                if token:
                    return token
        return None


class GeminiProvider(BaseLLMProvider):
    """Adapter for Google Gemini models."""

    def __init__(
        self,
        name: str,
        *,
        model: str = "gemini-1.5-pro",
        api_key_envs: Sequence[str] | None = None,
        timeout: float = 30.0,
        focus: Sequence[str] | None = None,
        style: str = "signals",
    ) -> None:
        super().__init__(name, style=style, focus=focus)
        self.model = model
        self.api_key_envs = list(
            api_key_envs or ("GOOGLE_API_KEY", "FIXOPS_GEMINI_KEY")
        )
        self.timeout = timeout
        self.api_key = self._resolve_api_key()
        self._session = requests.Session()

    def analyse(
        self,
        *,
        prompt: str,
        context: Mapping[str, Any],
        default_action: str,
        default_confidence: float,
        default_reasoning: str,
        mitigation_hints: Mapping[str, Any] | None = None,
        system_prompt: str | None = None,
    ) -> LLMResponse:
        if not self.api_key:
            return super().analyse(
                prompt=prompt,
                context=context,
                default_action=default_action,
                default_confidence=default_confidence,
                default_reasoning=default_reasoning,
                mitigation_hints=mitigation_hints,
            )
        params = {"key": self.api_key}
        payload = {
            "contents": [
                {
                    "role": "user",
                    "parts": [
                        {
                            "text": (
                                "Respond with JSON containing recommended_action, confidence, reasoning, "
                                "mitre_techniques, compliance_concerns, attack_vectors.\n"
                                + prompt
                            )
                        }
                    ],
                }
            ]
        }
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
        start = time.perf_counter()
        try:
            response = self._session.post(
                url, params=params, json=payload, timeout=self.timeout
            )
            response.raise_for_status()
            candidates = response.json().get("candidates", [])
            if not candidates:
                raise RuntimeError("no candidates returned")
            content = candidates[0]["content"]["parts"][0]["text"]
            parsed = json.loads(content)
        except Exception as exc:  # noqa: BLE001 - capture provider error
            logger.warning(
                "Gemini provider %s failed, falling back to deterministic: %s",
                self.name,
                type(exc).__name__,
            )
            metadata = {
                "mode": "fallback",
                "provider": self.name,
                "error": type(exc).__name__,
                "model": self.model,
            }
            return LLMResponse(
                recommended_action=default_action,
                confidence=default_confidence,
                reasoning=f"{default_reasoning}\n[Gemini fallback: {type(exc).__name__}]",
                mitre_techniques=_ensure_list(
                    (mitigation_hints or {}).get("mitre_candidates")
                ),
                compliance_concerns=_ensure_list(
                    (mitigation_hints or {}).get("compliance")
                ),
                attack_vectors=_ensure_list(
                    (mitigation_hints or {}).get("attack_vectors")
                ),
                metadata=metadata,
            )
        duration = (time.perf_counter() - start) * 1000
        return _response_from_payload(
            parsed,
            default_action=default_action,
            default_confidence=default_confidence,
            default_reasoning=default_reasoning,
            mitigation_hints=mitigation_hints,
            metadata={
                "mode": "remote",
                "provider": self.name,
                "model": self.model,
                "duration_ms": round(duration, 2),
            },
        )

    def _resolve_api_key(self) -> Optional[str]:
        for env_name in self.api_key_envs:
            value = os.getenv(env_name)
            if value:
                token = value.strip()
                if token:
                    return token
        return None


OPENROUTER_FREE_MODELS = [
    "deepseek/deepseek-r1:free",
    "deepseek/deepseek-chat-v3-0324:free",
    "qwen/qwen-2.5-72b-instruct:free",
    "google/gemma-2-9b-it:free",
    "meta-llama/llama-3.3-70b-instruct:free",
    "nousresearch/nous-hermes-3-llama-3.1-405b:free",
    "openchat/openchat-3.6-8b:free",
    "gryphe/mythomist-7b:free",
    "mistralai/mistral-7b-instruct:free",
]


class OpenRouterProvider(BaseLLMProvider):
    """Adapter for OpenRouter API aggregator (openrouter.ai).

    OpenRouter provides unified access to 200+ models through an OpenAI-compatible
    endpoint. Enables cost-effective operation using free/cheap models for the
    ALDECI LLM Council without cloud API fees.

    Supported models include:
    - DeepSeek R1 (free tier) — reasoning specialist
    - DeepSeek V3 (free tier)
    - Qwen 2.5 (free tier)
    - Gemma 2 (free tier)
    - Llama 3.3 (free tier)

    Environment variables:
    - OPENROUTER_API_KEY or FIXOPS_OPENROUTER_KEY: API key for openrouter.ai
    - FIXOPS_OPENROUTER_MODEL: Model name (default: deepseek/deepseek-chat-v3-0324:free)
    - FIXOPS_URL: Used for HTTP-Referer header (optional)
    """

    def __init__(
        self,
        name: str,
        *,
        model: str = "deepseek/deepseek-chat-v3-0324:free",
        api_key_envs: Sequence[str] | None = None,
        timeout: float = 30.0,
        focus: Sequence[str] | None = None,
        style: str = "consensus",
    ) -> None:
        super().__init__(name, style=style, focus=focus)
        # Allow env-var override for model selection
        self.model = os.environ.get("FIXOPS_OPENROUTER_MODEL", model)
        self.api_key_envs = list(
            api_key_envs or ("OPENROUTER_API_KEY", "FIXOPS_OPENROUTER_KEY")
        )
        self.timeout = timeout
        self.api_key = self._resolve_api_key()
        self._session = requests.Session()

    _DEFAULT_SYSTEM_PROMPT = (
        "You are a security decision assistant. Return JSON with keys "
        "recommended_action, confidence, reasoning, mitre_techniques, "
        "compliance_concerns, attack_vectors."
    )

    def analyse(
        self,
        *,
        prompt: str,
        context: Mapping[str, Any],
        default_action: str,
        default_confidence: float,
        default_reasoning: str,
        mitigation_hints: Mapping[str, Any] | None = None,
        system_prompt: str | None = None,
    ) -> LLMResponse:
        if not self.api_key:
            return super().analyse(
                prompt=prompt,
                context=context,
                default_action=default_action,
                default_confidence=default_confidence,
                default_reasoning=default_reasoning,
                mitigation_hints=mitigation_hints,
            )
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": system_prompt or self._DEFAULT_SYSTEM_PROMPT,
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
            "temperature": 0,
            "response_format": {"type": "json_object"},
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": os.getenv("FIXOPS_URL", "https://fixops.local"),
            "X-Title": "ALDECI",
        }
        start = time.perf_counter()
        try:
            response = self._session.post(
                "https://openrouter.ai/api/v1/chat/completions",
                json=payload,
                headers=headers,
                timeout=self.timeout,
            )
            response.raise_for_status()
            response_json = response.json()

            if "choices" not in response_json or not response_json["choices"]:
                raise ValueError("OpenRouter response missing choices")

            message = response_json["choices"][0].get("message", {})
            content = message.get("content")

            if not content:
                raise ValueError("OpenRouter response missing message content")

            try:
                parsed = json.loads(content)
            except json.JSONDecodeError as json_exc:
                raise ValueError(
                    f"OpenRouter returned non-JSON content: {content[:100]}"
                ) from json_exc
        except requests.Timeout as exc:
            metadata = {
                "mode": "fallback",
                "provider": self.name,
                "error": f"Timeout after {self.timeout}s",
                "model": self.model,
                "error_type": "timeout",
            }
            return LLMResponse(
                recommended_action=default_action,
                confidence=default_confidence,
                reasoning=f"{default_reasoning}\n[OpenRouter timeout: {exc}]",
                mitre_techniques=_ensure_list(
                    (mitigation_hints or {}).get("mitre_candidates")
                ),
                compliance_concerns=_ensure_list(
                    (mitigation_hints or {}).get("compliance")
                ),
                attack_vectors=_ensure_list(
                    (mitigation_hints or {}).get("attack_vectors")
                ),
                metadata=metadata,
            )
        except requests.HTTPError as exc:
            error_detail = "HTTP error"
            if exc.response is not None:
                try:
                    error_json = exc.response.json()
                    # Extract structured error message, never raw exception string — may contain API keys
                    error_detail = error_json.get("error", {}).get("message", f"HTTP {exc.response.status_code}")
                except (ValueError, KeyError, RuntimeError, TypeError, AttributeError):
                    error_detail = f"HTTP {exc.response.status_code}" if exc.response else type(exc).__name__
            metadata = {
                "mode": "fallback",
                "provider": self.name,
                "error": error_detail,
                "model": self.model,
                "error_type": "http_error",
                "status_code": exc.response.status_code if exc.response else None,  # type: ignore[dict-item]
            }
            return LLMResponse(
                recommended_action=default_action,
                confidence=default_confidence,
                reasoning=f"{default_reasoning}\n[OpenRouter error: {error_detail}]",
                mitre_techniques=_ensure_list(
                    (mitigation_hints or {}).get("mitre_candidates")
                ),
                compliance_concerns=_ensure_list(
                    (mitigation_hints or {}).get("compliance")
                ),
                attack_vectors=_ensure_list(
                    (mitigation_hints or {}).get("attack_vectors")
                ),
                metadata=metadata,
            )
        except (json.JSONDecodeError, KeyError, ValueError) as exc:
            metadata = {
                "mode": "fallback",
                "provider": self.name,
                "error": f"Invalid response format: {exc}",
                "model": self.model,
                "error_type": "parse_error",
            }
            return LLMResponse(
                recommended_action=default_action,
                confidence=default_confidence,
                reasoning=f"{default_reasoning}\n[OpenRouter parse error: {exc}]",
                mitre_techniques=_ensure_list(
                    (mitigation_hints or {}).get("mitre_candidates")
                ),
                compliance_concerns=_ensure_list(
                    (mitigation_hints or {}).get("compliance")
                ),
                attack_vectors=_ensure_list(
                    (mitigation_hints or {}).get("attack_vectors")
                ),
                metadata=metadata,
            )
        except Exception as exc:  # noqa: BLE001 - capture provider error
            logger.warning(
                "OpenRouter provider %s failed, falling back to deterministic: %s",
                self.name,
                type(exc).__name__,
            )
            metadata = {
                "mode": "fallback",
                "provider": self.name,
                "error": type(exc).__name__,
                "model": self.model,
                "error_type": type(exc).__name__,
            }
            return LLMResponse(
                recommended_action=default_action,
                confidence=default_confidence,
                reasoning=f"{default_reasoning}\n[OpenRouter fallback: {type(exc).__name__}]",
                mitre_techniques=_ensure_list(
                    (mitigation_hints or {}).get("mitre_candidates")
                ),
                compliance_concerns=_ensure_list(
                    (mitigation_hints or {}).get("compliance")
                ),
                attack_vectors=_ensure_list(
                    (mitigation_hints or {}).get("attack_vectors")
                ),
                metadata=metadata,
            )
        duration = (time.perf_counter() - start) * 1000
        return _response_from_payload(
            parsed,
            default_action=default_action,
            default_confidence=default_confidence,
            default_reasoning=default_reasoning,
            mitigation_hints=mitigation_hints,
            metadata={
                "mode": "remote",
                "provider": self.name,
                "model": self.model,
                "duration_ms": round(duration, 2),
            },
        )

    def is_available(self) -> bool:
        """Check if the OpenRouter API is available."""
        if not self.api_key:
            return False
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            }
            resp = self._session.get(
                "https://openrouter.ai/api/v1/models",
                headers=headers,
                timeout=5,
            )
            return resp.status_code == 200
        except Exception:
            return False

    def model_info(self) -> Dict[str, Any]:
        """Return metadata about the configured OpenRouter model."""
        is_free = ":free" in self.model
        return {
            "backend": "openrouter",
            "url": "https://openrouter.ai",
            "model": self.model,
            "cost": "$0/month (free tier)" if is_free else "$0.01-1.00/million tokens",
            "available": self.is_available(),
            "free_tier": is_free,
            "models_available": len(OPENROUTER_FREE_MODELS),
        }

    def _resolve_api_key(self) -> Optional[str]:
        for env_name in self.api_key_envs:
            value = os.getenv(env_name)
            if value:
                token = value.strip()
                if token:
                    return token
        return None


class MuleRouterProvider(OpenRouterProvider):
    """Adapter for mulerouter.ai — OpenRouter-compatible API with Qwen3-6b-Max.

    mulerouter.ai is a drop-in OpenRouter-compatible endpoint. Configured as the
    primary free model provider for the ALDECI LLM Council, using Qwen3-6b-Max
    as the default model.

    Falls back to OpenRouterProvider behaviour (and then to deterministic) if the
    MULEROUTER_API_KEY is not set.

    Environment variables:
    - MULEROUTER_API_KEY: API key for mulerouter.ai
    - FIXOPS_MULEROUTER_MODEL: Model override (default: qwen/qwen3-6b-max)
    """

    MULEROUTER_API_URL = "https://mulerouter.ai/api/v1/chat/completions"
    MULEROUTER_MODELS_URL = "https://mulerouter.ai/api/v1/models"

    def __init__(
        self,
        name: str,
        *,
        model: str = "qwen/qwen3-6b-max",
        api_key_envs: Sequence[str] | None = None,
        timeout: float = 30.0,
        focus: Sequence[str] | None = None,
        style: str = "consensus",
    ) -> None:
        # Initialise BaseLLMProvider directly — we override everything OpenRouterProvider does
        from core.llm_providers import BaseLLMProvider as _Base
        _Base.__init__(self, name, style=style, focus=focus)
        self.model = os.environ.get("FIXOPS_MULEROUTER_MODEL", model)
        self.api_key_envs = list(
            api_key_envs or ("MULEROUTER_API_KEY",)
        )
        self.timeout = timeout
        self.api_key = self._resolve_api_key()
        self._session = requests.Session()

    _DEFAULT_SYSTEM_PROMPT = (
        "You are a security decision assistant. Return JSON with keys "
        "recommended_action, confidence, reasoning, mitre_techniques, "
        "compliance_concerns, attack_vectors."
    )

    def analyse(
        self,
        *,
        prompt: str,
        context: Mapping[str, Any],
        default_action: str,
        default_confidence: float,
        default_reasoning: str,
        mitigation_hints: Mapping[str, Any] | None = None,
        system_prompt: str | None = None,
    ) -> LLMResponse:
        if not self.api_key:
            # No MuleRouter key — fall back to deterministic base
            return super(OpenRouterProvider, self).analyse(
                prompt=prompt,
                context=context,
                default_action=default_action,
                default_confidence=default_confidence,
                default_reasoning=default_reasoning,
                mitigation_hints=mitigation_hints,
            )
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": system_prompt or self._DEFAULT_SYSTEM_PROMPT,
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
            "temperature": 0,
            "response_format": {"type": "json_object"},
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": os.getenv("FIXOPS_URL", "https://fixops.local"),
            "X-Title": "ALDECI",
        }
        start = time.perf_counter()
        try:
            response = self._session.post(
                self.MULEROUTER_API_URL,
                json=payload,
                headers=headers,
                timeout=self.timeout,
            )
            response.raise_for_status()
            response_json = response.json()

            if "choices" not in response_json or not response_json["choices"]:
                raise ValueError("MuleRouter response missing choices")

            message = response_json["choices"][0].get("message", {})
            content = message.get("content")

            if not content:
                raise ValueError("MuleRouter response missing message content")

            try:
                parsed = json.loads(content)
            except json.JSONDecodeError as json_exc:
                raise ValueError(
                    f"MuleRouter returned non-JSON content: {content[:100]}"
                ) from json_exc
        except requests.Timeout as exc:
            metadata = {
                "mode": "fallback",
                "provider": self.name,
                "error": f"Timeout after {self.timeout}s",
                "model": self.model,
                "error_type": "timeout",
            }
            return LLMResponse(
                recommended_action=default_action,
                confidence=default_confidence,
                reasoning=f"{default_reasoning}\n[MuleRouter timeout: {exc}]",
                mitre_techniques=_ensure_list(
                    (mitigation_hints or {}).get("mitre_candidates")
                ),
                compliance_concerns=_ensure_list(
                    (mitigation_hints or {}).get("compliance")
                ),
                attack_vectors=_ensure_list(
                    (mitigation_hints or {}).get("attack_vectors")
                ),
                metadata=metadata,
            )
        except requests.HTTPError as exc:
            error_detail = "HTTP error"
            if exc.response is not None:
                try:
                    error_json = exc.response.json()
                    error_detail = error_json.get("error", {}).get("message", f"HTTP {exc.response.status_code}")
                except (ValueError, KeyError, RuntimeError, TypeError, AttributeError):
                    error_detail = f"HTTP {exc.response.status_code}" if exc.response else type(exc).__name__
            metadata = {
                "mode": "fallback",
                "provider": self.name,
                "error": error_detail,
                "model": self.model,
                "error_type": "http_error",
                "status_code": exc.response.status_code if exc.response else None,  # type: ignore[dict-item]
            }
            return LLMResponse(
                recommended_action=default_action,
                confidence=default_confidence,
                reasoning=f"{default_reasoning}\n[MuleRouter error: {error_detail}]",
                mitre_techniques=_ensure_list(
                    (mitigation_hints or {}).get("mitre_candidates")
                ),
                compliance_concerns=_ensure_list(
                    (mitigation_hints or {}).get("compliance")
                ),
                attack_vectors=_ensure_list(
                    (mitigation_hints or {}).get("attack_vectors")
                ),
                metadata=metadata,
            )
        except Exception as exc:  # noqa: BLE001 - capture provider error
            logger.warning(
                "MuleRouter provider %s failed, falling back to deterministic: %s",
                self.name,
                type(exc).__name__,
            )
            metadata = {
                "mode": "fallback",
                "provider": self.name,
                "error": type(exc).__name__,
                "model": self.model,
                "error_type": type(exc).__name__,
            }
            return LLMResponse(
                recommended_action=default_action,
                confidence=default_confidence,
                reasoning=f"{default_reasoning}\n[MuleRouter fallback: {type(exc).__name__}]",
                mitre_techniques=_ensure_list(
                    (mitigation_hints or {}).get("mitre_candidates")
                ),
                compliance_concerns=_ensure_list(
                    (mitigation_hints or {}).get("compliance")
                ),
                attack_vectors=_ensure_list(
                    (mitigation_hints or {}).get("attack_vectors")
                ),
                metadata=metadata,
            )
        duration = (time.perf_counter() - start) * 1000
        return _response_from_payload(
            parsed,
            default_action=default_action,
            default_confidence=default_confidence,
            default_reasoning=default_reasoning,
            mitigation_hints=mitigation_hints,
            metadata={
                "mode": "remote",
                "provider": self.name,
                "model": self.model,
                "duration_ms": round(duration, 2),
                "backend": "mulerouter",
            },
        )

    def is_available(self) -> bool:
        """Check if the MuleRouter API is available."""
        if not self.api_key:
            return False
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            }
            resp = self._session.get(
                self.MULEROUTER_MODELS_URL,
                headers=headers,
                timeout=5,
            )
            return resp.status_code == 200
        except Exception:
            return False

    def model_info(self) -> Dict[str, Any]:
        """Return metadata about the configured MuleRouter model."""
        return {
            "backend": "mulerouter",
            "url": "https://mulerouter.ai",
            "model": self.model,
            "cost": "$0/month (free tier)",
            "available": self.is_available(),
            "free_tier": True,
        }


class VLLMSelfHostedProvider(BaseLLMProvider):
    """Adapter for self-hosted vLLM inference servers (OpenAI-compatible API).

    Enables air-gapped operation of the Brain Pipeline and AutoFix engine
    without any external API keys. Uses the OpenAI-compatible endpoint that
    vLLM exposes (``/v1/chat/completions``).

    Recommended models for security analysis:
    - deepseek-ai/deepseek-coder-33b-instruct (code fixes)
    - codellama/CodeLlama-34b-Instruct-hf (code analysis)
    - meta-llama/Llama-3.1-70B-Instruct (general reasoning)

    Environment variables:
    - FIXOPS_VLLM_URL: vLLM endpoint (default: http://localhost:8001/v1)
    - FIXOPS_VLLM_MODEL: Model name served by vLLM
    - FIXOPS_VLLM_API_KEY: Optional API key for vLLM (some deployments require one)
    """

    def __init__(
        self,
        name: str,
        *,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        api_key_envs: Sequence[str] | None = None,
        timeout: float = 120.0,
        focus: Sequence[str] | None = None,
        style: str = "consensus",
        max_tokens: int = 1024,
        temperature: float = 0.0,
    ) -> None:
        super().__init__(name, style=style, focus=focus)
        self.base_url = (
            base_url
            or os.getenv("FIXOPS_VLLM_URL", "http://localhost:8001/v1")
        ).rstrip("/")
        self.model = model or os.getenv(
            "FIXOPS_VLLM_MODEL", "deepseek-ai/deepseek-coder-33b-instruct"
        )
        self.api_key_envs = list(
            api_key_envs or ("FIXOPS_VLLM_API_KEY",)
        )
        self.timeout = timeout
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.api_key = self._resolve_api_key()
        self._session = requests.Session()

    _DEFAULT_SYSTEM_PROMPT = (
        "You are a security decision assistant running in air-gapped mode. "
        "Return JSON with keys: recommended_action, confidence, reasoning, "
        "mitre_techniques, compliance_concerns, attack_vectors."
    )

    def analyse(
        self,
        *,
        prompt: str,
        context: Mapping[str, Any],
        default_action: str,
        default_confidence: float,
        default_reasoning: str,
        mitigation_hints: Mapping[str, Any] | None = None,
        system_prompt: str | None = None,
    ) -> LLMResponse:
        """Send analysis request to self-hosted vLLM server.

        vLLM exposes an OpenAI-compatible ``/v1/chat/completions`` endpoint,
        so the payload format mirrors OpenAI exactly.
        """
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": system_prompt or self._DEFAULT_SYSTEM_PROMPT,
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        start = time.perf_counter()
        try:
            url = f"{self.base_url}/chat/completions"
            response = self._session.post(
                url, json=payload, headers=headers, timeout=self.timeout,
            )
            response.raise_for_status()
            response_json = response.json()

            if "choices" not in response_json or not response_json["choices"]:
                raise ValueError("vLLM response missing choices")

            content = response_json["choices"][0].get("message", {}).get("content", "")
            if not content:
                raise ValueError("vLLM response missing message content")

            # Try to parse as JSON — vLLM models may return raw text
            try:
                parsed = json.loads(content)
            except json.JSONDecodeError:
                # Extract JSON from markdown code blocks or mixed text
                json_match = _extract_json_from_text(content)
                if json_match:
                    parsed = json.loads(json_match)
                else:
                    # Model returned plain text — wrap into structured response
                    parsed = {
                        "recommended_action": default_action,
                        "confidence": default_confidence,
                        "reasoning": content[:2000],
                    }
        except requests.ConnectionError:
            # vLLM server not running — this is expected in non-air-gapped setups
            logger.info(
                "vLLM provider %s: server not reachable at %s — using deterministic fallback",
                self.name, self.base_url,
            )
            return super().analyse(
                prompt=prompt,
                context=context,
                default_action=default_action,
                default_confidence=default_confidence,
                default_reasoning=default_reasoning,
                mitigation_hints=mitigation_hints,
            )
        except requests.Timeout:
            logger.warning("vLLM provider %s timed out after %.0fs", self.name, self.timeout)
            metadata = {
                "mode": "fallback",
                "provider": self.name,
                "error": f"Timeout after {self.timeout}s",
                "model": self.model,
                "error_type": "timeout",
                "backend": "vllm",
            }
            return LLMResponse(
                recommended_action=default_action,
                confidence=default_confidence,
                reasoning=f"{default_reasoning}\n[vLLM timeout]",
                mitre_techniques=_ensure_list(
                    (mitigation_hints or {}).get("mitre_candidates")
                ),
                compliance_concerns=_ensure_list(
                    (mitigation_hints or {}).get("compliance")
                ),
                attack_vectors=_ensure_list(
                    (mitigation_hints or {}).get("attack_vectors")
                ),
                metadata=metadata,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "vLLM provider %s failed, falling back to deterministic: %s",
                self.name, type(exc).__name__,
            )
            metadata = {
                "mode": "fallback",
                "provider": self.name,
                "error": type(exc).__name__,
                "model": self.model,
                "error_type": type(exc).__name__,
                "backend": "vllm",
            }
            return LLMResponse(
                recommended_action=default_action,
                confidence=default_confidence,
                reasoning=f"{default_reasoning}\n[vLLM fallback: {type(exc).__name__}]",
                mitre_techniques=_ensure_list(
                    (mitigation_hints or {}).get("mitre_candidates")
                ),
                compliance_concerns=_ensure_list(
                    (mitigation_hints or {}).get("compliance")
                ),
                attack_vectors=_ensure_list(
                    (mitigation_hints or {}).get("attack_vectors")
                ),
                metadata=metadata,
            )

        duration = (time.perf_counter() - start) * 1000
        return _response_from_payload(
            parsed,
            default_action=default_action,
            default_confidence=default_confidence,
            default_reasoning=default_reasoning,
            mitigation_hints=mitigation_hints,
            metadata={
                "mode": "self-hosted",
                "provider": self.name,
                "model": self.model,
                "duration_ms": round(duration, 2),
                "backend": "vllm",
                "air_gapped": True,
            },
        )

    def is_available(self) -> bool:
        """Check if the vLLM server is reachable."""
        try:
            url = f"{self.base_url}/models"
            resp = self._session.get(url, timeout=5)
            return resp.status_code == 200
        except Exception:
            return False

    def model_info(self) -> Dict[str, Any]:
        """Return metadata about the configured vLLM backend."""
        try:
            available = self.is_available()
        except Exception:
            available = False
        return {
            "backend": "vllm",
            "url": self.base_url,
            "model": self.model,
            "cost": "$0/month (self-hosted)",
            "air_gapped": True,
            "available": available,
        }

    def _resolve_api_key(self) -> Optional[str]:
        for env_name in self.api_key_envs:
            value = os.getenv(env_name)
            if value:
                token = value.strip()
                if token:
                    return token
        return None


class OllamaSelfHostedProvider(BaseLLMProvider):
    """Adapter for self-hosted Ollama inference (air-gapped fallback).

    Ollama provides a simpler deployment model than vLLM and supports
    GGUF models. Used as fallback when vLLM is not available.

    Environment variables:
    - FIXOPS_OLLAMA_URL: Ollama endpoint (default: http://localhost:11434)
    - FIXOPS_OLLAMA_MODEL: Model name (default: codellama:13b)
    """

    def __init__(
        self,
        name: str,
        *,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: float = 120.0,
        focus: Sequence[str] | None = None,
        style: str = "consensus",
    ) -> None:
        super().__init__(name, style=style, focus=focus)
        self.base_url = (
            base_url
            or os.getenv("FIXOPS_OLLAMA_URL", "http://localhost:11434")
        ).rstrip("/")
        self.model = model or os.getenv("FIXOPS_OLLAMA_MODEL", "codellama:13b")
        self.timeout = timeout
        self._session = requests.Session()

    _DEFAULT_SYSTEM_PROMPT = (
        "You are a security decision assistant. Return JSON with keys: "
        "recommended_action, confidence, reasoning, mitre_techniques, "
        "compliance_concerns, attack_vectors."
    )

    def analyse(
        self,
        *,
        prompt: str,
        context: Mapping[str, Any],
        default_action: str,
        default_confidence: float,
        default_reasoning: str,
        mitigation_hints: Mapping[str, Any] | None = None,
        system_prompt: str | None = None,
    ) -> LLMResponse:
        """Send analysis request to Ollama server."""
        _sys = system_prompt or self._DEFAULT_SYSTEM_PROMPT
        payload = {
            "model": self.model,
            "prompt": _sys + "\n\n" + prompt,
            "stream": False,
            "options": {"temperature": 0},
        }
        start = time.perf_counter()
        try:
            url = f"{self.base_url}/api/generate"
            response = self._session.post(
                url, json=payload, timeout=self.timeout,
            )
            response.raise_for_status()
            content = response.json().get("response", "")
            if not content:
                raise ValueError("Ollama response empty")

            try:
                parsed = json.loads(content)
            except json.JSONDecodeError:
                json_match = _extract_json_from_text(content)
                if json_match:
                    parsed = json.loads(json_match)
                else:
                    parsed = {
                        "recommended_action": default_action,
                        "confidence": default_confidence,
                        "reasoning": content[:2000],
                    }
        except requests.ConnectionError:
            logger.info(
                "Ollama provider %s: server not reachable at %s — using deterministic fallback",
                self.name, self.base_url,
            )
            return super().analyse(
                prompt=prompt,
                context=context,
                default_action=default_action,
                default_confidence=default_confidence,
                default_reasoning=default_reasoning,
                mitigation_hints=mitigation_hints,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Ollama provider %s failed: %s", self.name, type(exc).__name__,
            )
            return super().analyse(
                prompt=prompt,
                context=context,
                default_action=default_action,
                default_confidence=default_confidence,
                default_reasoning=default_reasoning,
                mitigation_hints=mitigation_hints,
            )

        duration = (time.perf_counter() - start) * 1000
        return _response_from_payload(
            parsed,
            default_action=default_action,
            default_confidence=default_confidence,
            default_reasoning=default_reasoning,
            mitigation_hints=mitigation_hints,
            metadata={
                "mode": "self-hosted",
                "provider": self.name,
                "model": self.model,
                "duration_ms": round(duration, 2),
                "backend": "ollama",
                "air_gapped": True,
            },
        )

    def is_available(self) -> bool:
        """Check if Ollama server is reachable."""
        try:
            resp = self._session.get(f"{self.base_url}/api/tags", timeout=5)
            return resp.status_code == 200
        except Exception:
            return False

    def model_info(self) -> Dict[str, Any]:
        return {
            "backend": "ollama",
            "url": self.base_url,
            "model": self.model,
            "cost": "$0/month (self-hosted)",
            "air_gapped": True,
        }


def _extract_json_from_text(text: str) -> Optional[str]:
    """Extract JSON object from text that may contain markdown code blocks or mixed content."""
    import re

    # Try markdown code blocks first: ```json ... ``` or ``` ... ```
    code_block = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
    if code_block:
        candidate = code_block.group(1).strip()
        if candidate.startswith("{"):
            return candidate

    # Try to find a raw JSON object in the text
    brace_start = text.find("{")
    if brace_start >= 0:
        depth = 0
        for i in range(brace_start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    return text[brace_start : i + 1]

    return None


class AirGapLLMProvider(BaseLLMProvider):
    """Air-gapped LLM provider — routes ALL requests through a LocalLLMRouter.

    Used when ``AirGapMode`` is CONFIGURED or ENFORCED so that the LLM council
    NEVER reaches out to api.openai.com / api.anthropic.com / etc. The constructor
    probes for an available local backend (Ollama / vLLM / llama.cpp) and refuses
    to initialise if none is detected — preserving the "fail closed, never silently
    degrade" rule for air-gapped deployments.

    The provider speaks the OpenAI-compatible chat-completions protocol against the
    detected backend (Ollama uses /api/chat with its native schema; vLLM and
    llama.cpp use /v1/chat/completions). It returns the same LLMResponse shape as
    every other BaseLLMProvider so it is a drop-in replacement.
    """

    def __init__(
        self,
        name: str,
        *,
        local_llm_router: Any,
        style: str = "consensus",
        focus: Sequence[str] | None = None,
        model: Optional[str] = None,
        timeout: float = 60.0,
        max_tokens: int = 1024,
    ) -> None:
        super().__init__(name, style=style, focus=focus)
        self.timeout = timeout
        self.max_tokens = max_tokens
        self._session = requests.Session()

        if local_llm_router is None:
            raise RuntimeError(
                "Air-gap LLM provider requires a LocalLLMRouter instance — got None."
            )

        # Detect available backend at construction time. If none is reachable,
        # we MUST fail closed: callers in CONFIGURED/ENFORCED modes are
        # responsible for handling the RuntimeError (degrade vs. abort).
        detected = local_llm_router.detect_available_backend()
        if not getattr(detected, "available", False):
            raise RuntimeError(
                "Air-gap LLM provider requires a local backend "
                "(Ollama/vLLM/llama.cpp) — none detected."
            )

        # Bind the router to its detected configuration for build_chat_payload().
        local_llm_router.config = detected
        self._router = local_llm_router
        self._backend_config = detected
        self.backend = detected.backend
        self.endpoint = detected.endpoint
        self.model = model or detected.model_name

        logger.info(
            "AirGapLLMProvider %s initialised: backend=%s endpoint=%s model=%s",
            self.name, self.backend, self.endpoint, self.model,
        )

    _DEFAULT_SYSTEM_PROMPT = (
        "You are a security decision assistant running in air-gapped mode. "
        "Return a JSON object with keys: recommended_action, confidence, reasoning, "
        "mitre_techniques, compliance_concerns, attack_vectors."
    )

    def chat(
        self,
        messages: Sequence[Mapping[str, str]],
        *,
        model: Optional[str] = None,
        max_tokens: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Send a chat-completion request to the local backend.

        Builds the URL+payload via the bound LocalLLMRouter, POSTs, and returns the
        backend's JSON response unchanged. Retries once on connection error; raises
        on the second failure so air-gap callers see the failure (no silent fallback).
        """
        url, payload = self._router.build_chat_payload(
            messages=[dict(m) for m in messages],
            model=model or self.model,
            max_tokens=max_tokens or self.max_tokens,
        )
        last_exc: Optional[Exception] = None
        for attempt in (1, 2):
            try:
                response = self._session.post(
                    url,
                    json=payload,
                    timeout=self.timeout,
                    headers={"Content-Type": "application/json"},
                )
                response.raise_for_status()
                return response.json()
            except (requests.ConnectionError, requests.Timeout) as exc:
                last_exc = exc
                logger.warning(
                    "AirGapLLMProvider %s attempt %d/2 to %s failed: %s",
                    self.name, attempt, url, type(exc).__name__,
                )
                if attempt == 2:
                    raise RuntimeError(
                        f"Air-gap LLM backend unreachable at {url}: {exc}"
                    ) from exc
        # Unreachable but mypy needs it
        raise RuntimeError(f"Air-gap LLM unreachable: {last_exc}")  # pragma: no cover

    def _extract_content(self, response_json: Mapping[str, Any]) -> str:
        """Pull the assistant message text out of the backend response.

        Handles both Ollama-native (/api/chat: {"message": {"content": ...}}) and
        OpenAI-compatible (/v1/chat/completions: {"choices":[{"message":{"content":...}}]}).
        """
        if "choices" in response_json:
            choices = response_json.get("choices") or []
            if not choices:
                raise ValueError("Air-gap LLM response missing choices")
            content = (choices[0].get("message") or {}).get("content")
        elif "message" in response_json:
            content = (response_json.get("message") or {}).get("content", "")
        else:
            content = response_json.get("response", "")  # llama.cpp /completion
        if not content:
            raise ValueError("Air-gap LLM response missing message content")
        return content

    def analyse(
        self,
        *,
        prompt: str,
        context: Mapping[str, Any],
        default_action: str,
        default_confidence: float,
        default_reasoning: str,
        mitigation_hints: Mapping[str, Any] | None = None,
        system_prompt: str | None = None,
    ) -> LLMResponse:
        messages = [
            {"role": "system", "content": system_prompt or self._DEFAULT_SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]
        start = time.perf_counter()
        try:
            response_json = self.chat(messages)
            content = self._extract_content(response_json)
            try:
                parsed = json.loads(content)
            except json.JSONDecodeError:
                # Tolerate plain-text replies from local models — wrap into schema
                extracted = _extract_json_from_text(content)
                if extracted:
                    parsed = json.loads(extracted)
                else:
                    parsed = {
                        "recommended_action": default_action,
                        "confidence": default_confidence,
                        "reasoning": content[:2000],
                    }
        except Exception as exc:  # noqa: BLE001 - air-gap fallback path
            logger.warning(
                "AirGapLLMProvider %s failed (%s) — returning heuristic fallback (still air-gapped)",
                self.name, type(exc).__name__,
            )
            metadata = {
                "mode": "fallback",
                "provider": self.name,
                "error": type(exc).__name__,
                "backend": self.backend,
                "endpoint": self.endpoint,
                "model": self.model,
                "air_gapped": True,
            }
            # SPEC-003: backend-down fallback — is_real_inference MUST be False.
            # Reasoning explicitly labels this as a heuristic so no consumer can
            # mistake it for model output.
            heuristic_reason = (
                f"[heuristic: local model unavailable — {type(exc).__name__}]"
            )
            return LLMResponse(
                recommended_action=default_action,
                confidence=default_confidence,
                reasoning=f"{default_reasoning} {heuristic_reason}",
                mitre_techniques=_ensure_list(
                    (mitigation_hints or {}).get("mitre_candidates")
                ),
                compliance_concerns=_ensure_list(
                    (mitigation_hints or {}).get("compliance")
                ),
                attack_vectors=_ensure_list(
                    (mitigation_hints or {}).get("attack_vectors")
                ),
                metadata=metadata,
                # SPEC-003: honest labelling — never a model verdict on failure path
                source="heuristic",
                is_real_inference=False,
                model=None,
            )
        duration = (time.perf_counter() - start) * 1000
        # SPEC-003: real inference succeeded — label with local_model:<backend>:<model>
        local_source = f"local_model:{self.backend}:{self.model}"
        resp = _response_from_payload(
            parsed,
            default_action=default_action,
            default_confidence=default_confidence,
            default_reasoning=default_reasoning,
            mitigation_hints=mitigation_hints,
            metadata={
                "mode": "air-gapped",
                "provider": self.name,
                "model": self.model,
                "backend": self.backend,
                "endpoint": self.endpoint,
                "duration_ms": round(duration, 2),
                "air_gapped": True,
                "source": local_source,
                "is_real_inference": True,
            },
        )
        # Attach provenance fields directly onto the response object
        resp.source = local_source
        resp.is_real_inference = True
        resp.model = self.model
        return resp


class SentinelCyberProvider(BaseLLMProvider):
    """Specialised fallback provider for domain-specific tuning."""

    def analyse(
        self,
        *,
        prompt: str,
        context: Mapping[str, Any],
        default_action: str,
        default_confidence: float,
        default_reasoning: str,
        mitigation_hints: Mapping[str, Any] | None = None,
        system_prompt: str | None = None,
    ) -> LLMResponse:
        hints = dict(mitigation_hints or {})
        metadata = {
            "mode": "deterministic",
            "provider": self.name,
            "reason": "specialised_rules",
        }
        mitre = _ensure_list(hints.get("mitre_candidates"))
        compliance = _ensure_list(hints.get("compliance"))
        attack_vectors = _ensure_list(hints.get("attack_vectors"))
        reasoning = (
            f"Sentinel cyber heuristics applied to {context.get('service_name', 'service')} with "
            f"{len(context.get('security_findings', []))} findings. "
            f"Default action: {default_action.upper()}."
        )
        return LLMResponse(
            recommended_action=default_action,
            confidence=default_confidence,
            reasoning=reasoning,
            mitre_techniques=mitre,
            compliance_concerns=compliance,
            attack_vectors=attack_vectors,
            metadata=metadata,
        )


def _ensure_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [item for item in value if item is not None]
    return [value]


def _response_from_payload(
    payload: Mapping[str, Any],
    *,
    default_action: str,
    default_confidence: float,
    default_reasoning: str,
    mitigation_hints: Mapping[str, Any] | None,
    metadata: Mapping[str, Any],
) -> LLMResponse:
    hints = dict(mitigation_hints or {})
    recommended_action = str(
        payload.get("recommended_action") or default_action
    ).lower()
    confidence_value = payload.get("confidence", default_confidence)
    try:
        confidence = float(confidence_value)
    except (TypeError, ValueError):  # noqa: PERF203 - defensive conversion
        confidence = default_confidence
    reasoning = str(payload.get("reasoning") or default_reasoning)
    mitre = _ensure_list(payload.get("mitre_techniques")) or _ensure_list(
        hints.get("mitre_candidates")
    )
    compliance = _ensure_list(payload.get("compliance_concerns")) or _ensure_list(
        hints.get("compliance")
    )
    attack_vectors = _ensure_list(payload.get("attack_vectors")) or _ensure_list(
        hints.get("attack_vectors")
    )
    full_metadata = dict(metadata)
    # Preserve the full LLM response payload so callers (e.g. AutoFix engine)
    # can access structured fields like "patches", "title", etc. that are not
    # part of the normalised LLMResponse schema.
    full_metadata["raw_payload"] = dict(payload)

    # SPEC-003: derive provenance fields from metadata when present.
    # Callers (AirGapLLMProvider, OpenRouterChatProvider) inject these into
    # metadata so the response carries honest labelling without needing a
    # separate code path.
    meta_source: str = full_metadata.get("source", "")
    meta_is_real: bool = bool(full_metadata.get("is_real_inference", False))
    meta_model: Optional[str] = full_metadata.get("model")

    # If caller didn't set provenance, infer from the "mode" key:
    # "remote" / "self-hosted" / "air-gapped" = real inference; anything else = heuristic.
    if not meta_source:
        mode_val = full_metadata.get("mode", "")
        if mode_val in ("remote", "self-hosted", "air-gapped"):
            meta_is_real = True
            meta_source = f"remote:{full_metadata.get('provider', 'unknown')}:{meta_model or 'unknown'}"
        else:
            meta_is_real = False
            meta_source = "heuristic"

    return LLMResponse(
        recommended_action=recommended_action,
        confidence=confidence,
        reasoning=reasoning,
        mitre_techniques=mitre,
        compliance_concerns=compliance,
        attack_vectors=attack_vectors,
        metadata=full_metadata,
        source=meta_source,
        is_real_inference=meta_is_real,
        model=meta_model,
    )


class LLMProviderManager:
    """Manager class for LLM providers."""

    def __init__(self) -> None:
        """Initialize the LLM provider manager with default providers.

        Includes self-hosted providers (vLLM, Ollama) for air-gapped
        deployments alongside cloud providers (OpenAI, Anthropic, Gemini, OpenRouter).
        """
        self.providers: Dict[str, BaseLLMProvider] = {
            "openai": OpenAIChatProvider("openai"),
            "anthropic": AnthropicMessagesProvider("anthropic"),
            "gemini": GeminiProvider("gemini"),
            "deepseek": OpenRouterProvider(
                "deepseek_r1",
                model="deepseek/deepseek-r1:free",
                api_key_envs=("OPENROUTER_API_KEY", "MULEROUTER_API_KEY"),
                focus=["reasoning", "code_analysis", "vulnerability_research"],
                style="analyst",
            ),
            "mulerouter": MuleRouterProvider("mulerouter"),
            "openrouter": OpenRouterProvider("openrouter"),
            "sentinel": SentinelCyberProvider("sentinel"),
            "vllm": VLLMSelfHostedProvider("vllm"),
            "ollama": OllamaSelfHostedProvider("ollama"),
        }

    def get_provider(self, name: str) -> BaseLLMProvider:
        """Get a provider by name."""
        if name not in self.providers:
            return DeterministicLLMProvider(name)
        return self.providers[name]

    def analyse(
        self,
        provider_name: str,
        *,
        prompt: str,
        context: Mapping[str, Any],
        default_action: str = "review",
        default_confidence: float = 0.5,
        default_reasoning: str = "Default analysis",
        mitigation_hints: Mapping[str, Any] | None = None,
        system_prompt: str | None = None,
    ) -> LLMResponse:
        """Analyse using a specific provider."""
        provider = self.get_provider(provider_name)
        return provider.analyse(
            prompt=prompt,
            context=context,
            default_action=default_action,
            default_confidence=default_confidence,
            default_reasoning=default_reasoning,
            mitigation_hints=mitigation_hints,
            system_prompt=system_prompt,
        )


class CouncilNotConfiguredError(RuntimeError):
    """Raised when no LLM API keys are available for the council to operate.

    This is an honest failure — callers must handle it rather than silently
    degrading to DeterministicLLMProvider placeholder verdicts (cost_usd=0,
    confidence=0.5, reasoning="inconclusive").
    """


class OpenRouterChatProvider(BaseLLMProvider):
    """OpenRouter provider that accepts a specific model at construction time.

    Unlike ``OpenRouterProvider`` (which reads FIXOPS_OPENROUTER_MODEL and
    defaults all instances to the same model), this class lets the caller pin
    each council member to a *distinct* model so the consensus reflects genuine
    cross-vendor diversity.

    All 5 verified paid models for the pipeline council:
      - google/gemini-2.5-flash        (Google)
      - deepseek/deepseek-chat-v3.1    (DeepSeek)
      - qwen/qwen3-next-80b-a3b-instruct (Alibaba/Qwen)
      - meta-llama/llama-3.3-70b-instruct (Meta)
      - anthropic/claude-3.5-haiku     (Anthropic via OpenRouter)

    The key is always read from OPENROUTER_API_KEY (or FIXOPS_OPENROUTER_KEY).
    """

    _BASE_URL = "https://openrouter.ai/api/v1/chat/completions"

    _DEFAULT_SYSTEM_PROMPT = (
        "You are a security decision assistant. "
        "Return a JSON object with keys: recommended_action, confidence, reasoning, "
        "mitre_techniques, compliance_concerns, attack_vectors.\n\n"
        "recommended_action must be one of: remediate_critical, remediate_high, "
        "accept_risk, defer, investigate, false_positive.\n"
        "confidence is a float 0.0-1.0 reflecting your genuine certainty.\n"
        "reasoning is a detailed explanation (2-4 sentences) of your security analysis.\n"
        "Do NOT use markdown fences. Return raw JSON only."
    )

    def __init__(
        self,
        name: str,
        *,
        model: str,
        api_key_envs: Sequence[str] | None = None,
        timeout: float = 45.0,
        focus: Sequence[str] | None = None,
        style: str = "consensus",
    ) -> None:
        super().__init__(name, style=style, focus=focus)
        # model is fixed at construction — no env override, so each council
        # member genuinely represents a different vendor.
        self.model = model
        self.api_key_envs = list(
            api_key_envs or ("OPENROUTER_API_KEY", "FIXOPS_OPENROUTER_KEY")
        )
        self.timeout = timeout
        self.api_key = self._resolve_api_key()
        self._session = requests.Session()

    def analyse(
        self,
        *,
        prompt: str,
        context: Mapping[str, Any],
        default_action: str,
        default_confidence: float,
        default_reasoning: str,
        mitigation_hints: Mapping[str, Any] | None = None,
        system_prompt: str | None = None,
    ) -> LLMResponse:
        if not self.api_key:
            # No key at all — return deterministic but tag it clearly so callers
            # can detect fabrication. The council itself raises before getting here
            # when built via create_default_council(), but this path remains for
            # direct instantiation.
            result = super().analyse(
                prompt=prompt,
                context=context,
                default_action=default_action,
                default_confidence=default_confidence,
                default_reasoning=default_reasoning,
                mitigation_hints=mitigation_hints,
            )
            result.metadata["mode"] = "no_key"
            result.metadata["model"] = self.model
            return result

        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": system_prompt or self._DEFAULT_SYSTEM_PROMPT,
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
            "temperature": 0,
            "response_format": {"type": "json_object"},
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": os.getenv("FIXOPS_URL", "https://fixops.local"),
            "X-Title": "ALDECI",
        }
        start = time.perf_counter()
        try:
            resp = self._session.post(
                self._BASE_URL,
                json=payload,
                headers=headers,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            resp_json = resp.json()

            if not resp_json.get("choices"):
                raise ValueError("OpenRouter response missing choices")

            content = resp_json["choices"][0].get("message", {}).get("content")
            if not content:
                raise ValueError("OpenRouter response missing message content")

            try:
                parsed = json.loads(content)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"OpenRouter returned non-JSON content: {content[:120]}"
                ) from exc

            # Extract usage for cost accounting (paid models include this).
            usage = resp_json.get("usage", {})
            prompt_tokens = usage.get("prompt_tokens", 0)
            completion_tokens = usage.get("completion_tokens", 0)
            # Rough cost estimate: ~$0.15/M input, ~$0.60/M output for mid-tier models.
            cost_est = (prompt_tokens * 0.00000015) + (completion_tokens * 0.0000006)

        except requests.Timeout:
            logger.warning("OpenRouterChatProvider %s timed out (model=%s)", self.name, self.model)
            result = super().analyse(
                prompt=prompt, context=context,
                default_action=default_action, default_confidence=default_confidence,
                default_reasoning=default_reasoning, mitigation_hints=mitigation_hints,
            )
            result.metadata.update({"mode": "fallback", "error": "timeout", "model": self.model})
            return result
        except requests.HTTPError as exc:
            error_detail = "HTTP error"
            if exc.response is not None:
                try:
                    error_detail = exc.response.json().get("error", {}).get(
                        "message", f"HTTP {exc.response.status_code}"
                    )
                except Exception:  # noqa: BLE001
                    error_detail = f"HTTP {exc.response.status_code if exc.response else '?'}"
            logger.warning(
                "OpenRouterChatProvider %s HTTP error (model=%s): %s",
                self.name, self.model, error_detail,
            )
            result = super().analyse(
                prompt=prompt, context=context,
                default_action=default_action, default_confidence=default_confidence,
                default_reasoning=default_reasoning, mitigation_hints=mitigation_hints,
            )
            result.metadata.update({"mode": "fallback", "error": error_detail, "model": self.model})
            return result
        except (json.JSONDecodeError, KeyError, ValueError) as exc:
            logger.warning(
                "OpenRouterChatProvider %s parse error (model=%s): %s",
                self.name, self.model, exc,
            )
            result = super().analyse(
                prompt=prompt, context=context,
                default_action=default_action, default_confidence=default_confidence,
                default_reasoning=default_reasoning, mitigation_hints=mitigation_hints,
            )
            result.metadata.update({"mode": "fallback", "error": str(exc), "model": self.model})
            return result
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "OpenRouterChatProvider %s failed (model=%s): %s",
                self.name, self.model, type(exc).__name__,
            )
            result = super().analyse(
                prompt=prompt, context=context,
                default_action=default_action, default_confidence=default_confidence,
                default_reasoning=default_reasoning, mitigation_hints=mitigation_hints,
            )
            result.metadata.update({"mode": "fallback", "error": type(exc).__name__, "model": self.model})
            return result

        duration_ms = (time.perf_counter() - start) * 1000
        llm_result = _response_from_payload(
            parsed,
            default_action=default_action,
            default_confidence=default_confidence,
            default_reasoning=default_reasoning,
            mitigation_hints=mitigation_hints,
            metadata={
                "mode": "remote",
                "provider": self.name,
                "model": self.model,
                "backend": "openrouter",
                "duration_ms": round(duration_ms, 2),
                "cost_usd": round(cost_est, 8),
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
            },
        )
        _emit_event(
            "llm.analysis.completed",
            {
                "provider": self.name,
                "model": self.model,
                "mode": "remote",
                "recommended_action": llm_result.recommended_action,
                "confidence": llm_result.confidence,
                "cost_usd": cost_est,
            },
        )
        return llm_result

    def _resolve_api_key(self) -> Optional[str]:
        for env_name in self.api_key_envs:
            value = os.getenv(env_name)
            if value:
                token = value.strip()
                if token:
                    return token
        return None


__all__ = [
    "AirGapLLMProvider",
    "AnthropicMessagesProvider",
    "BaseLLMProvider",
    "CouncilNotConfiguredError",
    "DeterministicLLMProvider",
    "GeminiProvider",
    "LLMProviderManager",
    "LLMResponse",
    "MuleRouterProvider",
    "OllamaSelfHostedProvider",
    "OpenAIChatProvider",
    "OpenRouterChatProvider",
    "OpenRouterProvider",
    "SentinelCyberProvider",
    "VLLMSelfHostedProvider",
]
