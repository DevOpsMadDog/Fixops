"""OpenRouter API provider for accessing 200+ LLM models.

OpenRouter (openrouter.ai) provides unified access to models from Qwen, DeepSeek,
Google, Meta, and more via a single API. Excellent for council-based decisions where
you want multiple model families without managing separate API keys.

Env: OPENROUTER_API_KEY
Models: qwen/qwen-2.5-72b-instruct, deepseek/deepseek-v3,
        google/gemma-3-27b-it, meta-llama/llama-4-maverick
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Mapping, Optional, Sequence

logger = logging.getLogger(__name__)

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore[assignment]

from core.llm_providers import (
    BaseLLMProvider,
    LLMResponse,
    _ensure_list,
    _response_from_payload,
)

__all__ = ["OpenRouterProvider"]


class OpenRouterProvider(BaseLLMProvider):
    """Access 200+ models via OpenRouter API.

    Uses the unified OpenRouter endpoint to route requests to various model providers.
    Supports cost tracking per request and fallback to deterministic mode if no API key.

    Attributes:
        model (str): Model ID per OpenRouter naming (e.g. qwen/qwen-2.5-72b-instruct)
        api_key (Optional[str]): API key from OPENROUTER_API_KEY env var
        timeout (float): Request timeout in seconds
    """

    OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"

    def __init__(
        self,
        name: str,
        *,
        model: str = "meta-llama/llama-2-70b-chat",
        api_key_envs: Sequence[str] | None = None,
        timeout: float = 45.0,
        focus: Sequence[str] | None = None,
        style: str = "consensus",
    ) -> None:
        """Initialize OpenRouter provider.

        Args:
            name: Provider identifier (e.g. 'openrouter_qwen')
            model: Model ID per OpenRouter (e.g. 'qwen/qwen-2.5-72b-instruct')
            api_key_envs: Environment variables to check for API key (default: OPENROUTER_API_KEY)
            timeout: Request timeout in seconds
            focus: Expertise focus areas
            style: Response style (consensus, analyst, etc)
        """
        super().__init__(name, style=style, focus=focus)
        self.model = os.environ.get("FIXOPS_OPENROUTER_MODEL", model)
        self.api_key_envs = list(api_key_envs or ("OPENROUTER_API_KEY",))
        self.timeout = timeout
        self.api_key = self._resolve_api_key()
        self.total_cost_usd = 0.0

    _DEFAULT_SYSTEM_PROMPT = (
        "You are a security decision assistant. Return a JSON object with keys: "
        "recommended_action, confidence, reasoning, mitre_techniques, "
        "compliance_concerns, attack_vectors. "
        "Be precise and actionable."
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
        """Analyze via OpenRouter API or fallback to deterministic.

        Args:
            prompt: Analysis prompt
            context: Contextual data (service_name, etc)
            default_action: Fallback action if analysis fails
            default_confidence: Fallback confidence score
            default_reasoning: Fallback reasoning
            mitigation_hints: MITRE/compliance hints for fallback
            system_prompt: Override system prompt

        Returns:
            LLMResponse with analysis or fallback deterministic result.
        """
        if not self.api_key or httpx is None:
            # Fallback to deterministic when no API key or httpx unavailable
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
            "temperature": 0.0,
            "top_p": 1.0,
            "max_tokens": 2048,
        }

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "HTTP-Referer": "https://fixops.local",
            "X-Title": "Fixops Security Council",
            "Content-Type": "application/json",
        }

        start = time.perf_counter()
        try:
            client = httpx.Client(timeout=self.timeout)
            try:
                response = client.post(
                    self.OPENROUTER_API_URL,
                    json=payload,
                    headers=headers,
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

                # Track cost if available
                cost_data = response_json.get("usage", {})
                if cost_data:
                    self._track_cost(cost_data)

            finally:
                client.close()

        except Exception as exc:  # noqa: BLE001 - capture provider error
            logger.warning(
                "OpenRouter provider %s failed with %s, falling back to deterministic",
                self.name,
                type(exc).__name__,
            )
            metadata = {
                "mode": "fallback",
                "provider": self.name,
                "error": type(exc).__name__,
                "model": self.model,
                "error_type": "openrouter_error",
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
                "cost_usd": round(self.total_cost_usd, 6),
            },
        )

    def _resolve_api_key(self) -> Optional[str]:
        """Resolve API key from environment variables."""
        for env_name in self.api_key_envs:
            value = os.getenv(env_name)
            if value:
                token = value.strip()
                if token:
                    return token
        return None

    def _track_cost(self, cost_data: Mapping[str, Any]) -> None:
        """Track API cost from response metadata.

        Args:
            cost_data: Usage data from OpenRouter response (input_tokens, output_tokens, etc)
        """
        # OpenRouter pricing varies by model; we estimate from tokens
        # In production, parse the actual pricing from response headers
        input_tokens = cost_data.get("prompt_tokens", 0)
        output_tokens = cost_data.get("completion_tokens", 0)

        # Rough estimates; OpenRouter returns actual cost in response headers
        input_cost_per_1k = 0.001  # Placeholder
        output_cost_per_1k = 0.002

        estimated_cost = (
            (input_tokens / 1000) * input_cost_per_1k
            + (output_tokens / 1000) * output_cost_per_1k
        )
        self.total_cost_usd += estimated_cost

    @property
    def cost_usd(self) -> float:
        """Total cumulative cost in USD."""
        return self.total_cost_usd
