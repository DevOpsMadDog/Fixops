"""LLM provider adapters for the enhanced decision engine."""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Sequence

import requests  # type: ignore[import-untyped]
from dotenv import load_dotenv

# Load environment variables from .env file so API keys are available
load_dotenv()


@dataclass
class LLMResponse:
    """Normalised output returned by a provider invocation."""

    recommended_action: str
    confidence: float
    reasoning: str
    mitre_techniques: Sequence[str] = field(default_factory=list)
    compliance_concerns: Sequence[str] = field(default_factory=list)
    attack_vectors: Sequence[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


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
    ) -> LLMResponse:
        """Return a deterministic response when a provider cannot be reached."""

        metadata = {
            "mode": "deterministic",
            "reason": "provider_disabled",
            "style": self.style,
        }
        hints = dict(mitigation_hints or {})
        mitre = _ensure_list(hints.get("mitre_candidates"))
        compliance = _ensure_list(hints.get("compliance"))
        attack_vectors = _ensure_list(hints.get("attack_vectors"))
        return LLMResponse(
            recommended_action=default_action,
            confidence=default_confidence,
            reasoning=default_reasoning,
            mitre_techniques=mitre,
            compliance_concerns=compliance,
            attack_vectors=attack_vectors,
            metadata=metadata,
        )


class DeterministicLLMProvider(BaseLLMProvider):
    """Provider that always echoes the heuristic defaults."""


class OpenAIChatProvider(BaseLLMProvider):
    """Adapter for OpenAI chat completion models."""

    def __init__(
        self,
        name: str,
        *,
        model: str = "gpt-4o-mini",
        api_key_envs: Sequence[str] | None = None,
        timeout: float = 30.0,
        focus: Sequence[str] | None = None,
        style: str = "consensus",
    ) -> None:
        super().__init__(name, style=style, focus=focus)
        self.model = model
        self.api_key_envs = list(
            api_key_envs or ("OPENAI_API_KEY", "FIXOPS_OPENAI_KEY")
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
                    "content": (
                        "You are a security decision assistant. Return JSON with keys "
                        "recommended_action, confidence, reasoning, mitre_techniques, "
                        "compliance_concerns, attack_vectors."
                    ),
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
                    error_detail = error_json.get("error", {}).get("message", str(exc))
                except Exception:
                    error_detail = str(exc)
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
            metadata = {
                "mode": "fallback",
                "provider": self.name,
                "error": str(exc),
                "model": self.model,
                "error_type": "unknown",
            }
            return LLMResponse(
                recommended_action=default_action,
                confidence=default_confidence,
                reasoning=f"{default_reasoning}\n[OpenAI fallback: {exc}]",
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
        model: str = "claude-3-5-sonnet-20240620",
        api_key_envs: Sequence[str] | None = None,
        timeout: float = 30.0,
        focus: Sequence[str] | None = None,
        style: str = "analyst",
    ) -> None:
        super().__init__(name, style=style, focus=focus)
        self.model = model
        self.api_key_envs = list(
            api_key_envs or ("ANTHROPIC_API_KEY", "FIXOPS_ANTHROPIC_KEY")
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
            "max_tokens": 400,
            "temperature": 0,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "Return a JSON object with recommended_action, confidence, reasoning, "
                        "mitre_techniques, compliance_concerns, attack_vectors."
                    ),
                },
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
            metadata = {
                "mode": "fallback",
                "provider": self.name,
                "error": str(exc),
                "model": self.model,
            }
            return LLMResponse(
                recommended_action=default_action,
                confidence=default_confidence,
                reasoning=f"{default_reasoning}\n[Anthropic fallback: {exc}]",
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
            metadata = {
                "mode": "fallback",
                "provider": self.name,
                "error": str(exc),
                "model": self.model,
            }
            return LLMResponse(
                recommended_action=default_action,
                confidence=default_confidence,
                reasoning=f"{default_reasoning}\n[Gemini fallback: {exc}]",
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
    return LLMResponse(
        recommended_action=recommended_action,
        confidence=confidence,
        reasoning=reasoning,
        mitre_techniques=mitre,
        compliance_concerns=compliance,
        attack_vectors=attack_vectors,
        metadata=dict(metadata),
    )


class LLMProviderManager:
    """Manager class for LLM providers."""

    def __init__(self) -> None:
        """Initialize the LLM provider manager with default providers."""
        self.providers: Dict[str, BaseLLMProvider] = {
            "openai": OpenAIChatProvider("openai"),
            "anthropic": AnthropicMessagesProvider("anthropic"),
            "gemini": GeminiProvider("gemini"),
            "sentinel": SentinelCyberProvider("sentinel"),
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
        )


__all__ = [
    "AnthropicMessagesProvider",
    "BaseLLMProvider",
    "DeterministicLLMProvider",
    "GeminiProvider",
    "LLMProviderManager",
    "LLMResponse",
    "OpenAIChatProvider",
    "SentinelCyberProvider",
]
