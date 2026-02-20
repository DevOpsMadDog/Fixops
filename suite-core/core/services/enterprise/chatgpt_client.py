"""Utility wrappers around the OpenAI ChatGPT API used across the enterprise stack.

The previous implementation relied on the proprietary ``emergentintegrations``
package.  Those classes exposed a very small surface area that the rest of the
codebase depended on (``generate_text`` for completions and ``LlmChat`` style
helpers for conversational prompts).  To keep the rest of the code stable we
re-implement the required behaviour with the official OpenAI Python SDK while
mirroring the minimal interface expected by existing services.

The helpers in this module intentionally avoid pulling in optional dependencies
at import time.  They only raise clear, actionable errors when the OpenAI SDK is
unavailable or an API key has not been provided.  This keeps the demo workflow
usable in environments without network access, while still providing rich
ChatGPT-backed analysis when an ``OPENAI_API_KEY`` (or legacy
``EMERGENT_LLM_KEY``) is present.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

import structlog
from config.enterprise.settings import get_settings

try:  # pragma: no cover - import guarded for minimal environments
    from openai import AsyncOpenAI
except Exception:  # pragma: no cover - fallback when OpenAI SDK missing
    AsyncOpenAI = None  # type: ignore[assignment]


logger = structlog.get_logger()


@dataclass
class UserMessage:
    """Light-weight message container mirroring ``emergentintegrations``."""

    text: str


class ChatGPTClient:
    """Thin asynchronous wrapper around the ChatGPT responses endpoint."""

    def __init__(
        self,
        api_key: str,
        *,
        model: str = "gpt-4o-mini",
        max_tokens: int = 800,
        temperature: float = 0.3,
    ) -> None:
        if AsyncOpenAI is None:  # pragma: no cover - handled in minimal envs
            raise RuntimeError(
                "openai package is not installed. Install 'openai' to enable ChatGPT integrations."
            )

        self._client = AsyncOpenAI(api_key=api_key)
        self._model = model
        self._max_tokens = max_tokens
        self._temperature = temperature

    async def generate_text(
        self,
        *,
        prompt: str,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        system_message: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Generate a completion using ChatGPT and return a dict compatible with the legacy client."""

        messages = []
        if system_message:
            messages.append({"role": "system", "content": system_message})
        messages.append({"role": "user", "content": prompt})

        try:
            response = await self._client.chat.completions.create(
                model=self._model,
                messages=messages,
                max_tokens=max_tokens or self._max_tokens,
                temperature=temperature
                if temperature is not None
                else self._temperature,
            )
        except Exception as exc:  # pragma: no cover - network/runtime errors
            logger.error("ChatGPT completion failed", error=str(exc))
            raise

        content = ""
        if response.choices:
            content = (response.choices[0].message.content or "").strip()

        usage = getattr(response, "usage", None)
        usage_payload: Optional[Dict[str, Any]] = None
        if usage is not None:
            usage_payload = {
                "prompt_tokens": getattr(usage, "prompt_tokens", None),
                "completion_tokens": getattr(usage, "completion_tokens", None),
                "total_tokens": getattr(usage, "total_tokens", None),
            }

        return {
            "content": content,
            "model": getattr(response, "model", self._model),
            "usage": usage_payload,
        }


class ChatGPTChatSession:
    """Drop-in replacement for the ``LlmChat`` helper used by policy/correlation engines."""

    def __init__(
        self,
        api_key: str,
        *,
        system_message: Optional[str] = None,
        session_id: Optional[str] = None,  # session id kept for API compatibility
        model: str = "gpt-4o-mini",
        max_tokens: int = 800,
        temperature: float = 0.3,
    ) -> None:
        self._model = model
        self._max_tokens = max_tokens
        self._temperature = temperature
        self._api_key = api_key
        self._client = ChatGPTClient(
            api_key,
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
        )
        self._system_message = system_message
        self._session_id = session_id

    def with_model(self, provider: str, model: str) -> "ChatGPTChatSession":
        """Mimic the fluent interface exposed by ``LlmChat``."""

        if provider.lower() != "openai":
            logger.warning(
                "ChatGPTChatSession only supports OpenAI provider", provider=provider
            )

        # Re-create the underlying client with the new model to mirror the original behaviour.
        settings = get_settings()
        api_key = settings.primary_llm_api_key or self._api_key
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY is required for ChatGPTChatSession")

        self._model = model
        self._client = ChatGPTClient(
            api_key,
            model=model,
            max_tokens=self._max_tokens,
            temperature=self._temperature,
        )
        self._api_key = api_key
        return self

    async def send_message(self, message: UserMessage) -> str:
        response = await self._client.generate_text(
            prompt=message.text,
            system_message=self._system_message,
        )
        return response.get("content", "")


def get_primary_llm_api_key() -> Optional[str]:
    """Helper used by services to fetch the preferred ChatGPT API key."""

    settings = get_settings()
    return settings.primary_llm_api_key
