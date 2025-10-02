"""Adapter for Awesome-LLM4Cybersecurity models."""

from __future__ import annotations

import asyncio
from typing import Any, Dict

import structlog

logger = structlog.get_logger()


class AwesomeLLMClient:
    """Thin wrapper above the Awesome-LLM4Cybersecurity SDK.

    The real SDK exposes both synchronous and asynchronous interfaces.  For the
    production environment we try to import the official client.  During tests
    we fall back to a simple stub so that prompts and error handling remain
    deterministic.
    """

    def __init__(self, model_name: str, *, temperature: float = 0.2, max_tokens: int = 2048) -> None:
        self._client = self._load_client(model_name, temperature, max_tokens)

    async def generate(self, prompt: str, *, system_prompt: str) -> str:
        """Generate text using the configured Awesome-LLM4Cybersecurity model."""

        response = self._client.generate(prompt=prompt, system_prompt=system_prompt)
        if asyncio.iscoroutine(response):  # pragma: no cover - depends on SDK
            response = await response
        return self._unwrap_response(response)

    def _load_client(self, model_name: str, temperature: float, max_tokens: int):
        try:
            from awesome_llm4cybersecurity import Client  # type: ignore

            logger.info("✅ Loaded Awesome-LLM4Cybersecurity client", model=model_name)
            return Client(model=model_name, temperature=temperature, max_tokens=max_tokens)
        except Exception as exc:  # pragma: no cover - fallback exercised in tests
            logger.warning("Awesome-LLM4Cybersecurity client unavailable, using stub", exc_info=exc)
            return _StubAwesomeClient(model=model_name, temperature=temperature, max_tokens=max_tokens)

    def _unwrap_response(self, response: Any) -> str:
        if isinstance(response, dict) and "text" in response:
            return str(response["text"])
        return str(response)


class _StubAwesomeClient:
    """Local client used when the real dependency is not installed."""

    def __init__(self, *, model: str, temperature: float, max_tokens: int) -> None:
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens

    def generate(self, *, prompt: str, system_prompt: str) -> Dict[str, str]:
        safe_prompt = prompt.strip().splitlines()[0] if prompt else ""
        return {
            "text": f"[{self.model}] Stub response for prompt: {safe_prompt[:60]}...",
            "system_prompt": system_prompt,
        }

