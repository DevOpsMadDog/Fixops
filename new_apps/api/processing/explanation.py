"""Narrative generation helpers for the enhanced API surface."""

from __future__ import annotations

import importlib
import logging
import textwrap
import time
from collections import deque
from typing import Any, Callable, Deque, Iterable, Mapping, Optional, Sequence

logger = logging.getLogger(__name__)


class ExplanationError(RuntimeError):
    """Raised when the explanation engine cannot complete a request."""


class RateLimiter:
    """Simple token bucket rate limiter for outbound LLM calls."""

    def __init__(
        self,
        max_requests: int,
        period: float,
        *,
        time_source: Callable[[], float] | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        if max_requests <= 0:
            raise ValueError("max_requests must be positive")
        if period <= 0:
            raise ValueError("period must be positive")
        self._max_requests = max_requests
        self._period = period
        self._time_source = time_source or time.monotonic
        self._sleep = sleep or time.sleep
        self._events: Deque[float] = deque()

    def acquire(self) -> None:
        """Block until a slot becomes available under the token bucket."""

        now = self._time_source()
        self._drain(now)
        if len(self._events) >= self._max_requests:
            wait_time = self._period - (now - self._events[0])
            if wait_time > 0:
                logger.debug("Rate limit reached; sleeping %.2fs", wait_time)
                self._sleep(wait_time)
            now = self._time_source()
            self._drain(now)
        self._events.append(now)

    def _drain(self, now: float) -> None:
        while self._events and now - self._events[0] >= self._period:
            self._events.popleft()


class ExplanationGenerator:
    """LLM-powered explanation engine using the SentinelGPT model."""

    def __init__(
        self,
        *,
        model_name: str = "sentinel_gpt",
        client_factory: Optional[Callable[[], Any]] = None,
        rate_limiter: Optional[RateLimiter] = None,
        temperature: float = 0.2,
        max_tokens: int = 512,
    ) -> None:
        self._model_name = model_name
        self._client_factory = client_factory or self._default_client_factory
        self._rate_limiter = rate_limiter or RateLimiter(max_requests=5, period=60.0)
        self._temperature = temperature
        self._max_tokens = max_tokens
        self._client: Any | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def generate(
        self,
        findings: Sequence[Mapping[str, Any]],
        context: Optional[Mapping[str, Any]] = None,
    ) -> str:
        """Generate a natural language explanation for the supplied findings."""

        if not findings:
            raise ExplanationError(
                "At least one finding is required to generate an explanation"
            )

        prompt = self._build_prompt(findings, context or {})
        self._rate_limiter.acquire()
        client = self._ensure_client()
        response = self._invoke_model(client, prompt)
        explanation = self._extract_text(response)
        logger.debug("Generated explanation using %s", self._model_name)
        return explanation.strip()

    # ------------------------------------------------------------------
    # Prompt handling
    # ------------------------------------------------------------------
    def _build_prompt(
        self, findings: Sequence[Mapping[str, Any]], context: Mapping[str, Any]
    ) -> str:
        summary = context.get("summary")
        metadata = context.get("metadata", {})
        extra_sections = []
        if summary:
            extra_sections.append(f"Context summary: {summary}")
        if metadata:
            formatted = "\n".join(f"- {key}: {value}" for key, value in metadata.items())
            extra_sections.append(f"Context metadata:\n{formatted}")

        formatted_findings = []
        for idx, finding in enumerate(findings, start=1):
            line_items = [f"Finding {idx}:"]
            if rule := finding.get("rule_id"):
                line_items.append(f"Rule {rule}")
            if severity := finding.get("severity"):
                line_items.append(f"Severity {severity}")
            if location := finding.get("location"):
                line_items.append(f"Location {location}")
            if description := finding.get("description"):
                line_items.append(f"Detail {description}")
            formatted_findings.append(" - ".join(line_items))

        prompt = textwrap.dedent(
            f"""
            You are SentinelGPT, a cybersecurity assistant from the Awesome-LLM4Cybersecurity project.
            Provide an executive-ready narrative that summarises the risk, likely impact, and
            recommended mitigation steps for the following findings.

            Findings:
            {chr(10).join(formatted_findings)}

            Respond using short paragraphs. Highlight the most critical
            dependencies or attack paths when relevant.
            """
        ).strip()

        if extra_sections:
            extra_block = "\n".join(extra_sections)
            prompt = f"{prompt}\n\n{extra_block}"
        return prompt

    # ------------------------------------------------------------------
    # Model invocation helpers
    # ------------------------------------------------------------------
    def _ensure_client(self) -> Any:
        if self._client is None:
            try:
                self._client = self._client_factory()
            except Exception as exc:  # pragma: no cover - defensive guard
                raise ExplanationError("Unable to initialise SentinelGPT client") from exc
        return self._client

    def _default_client_factory(self) -> Any:
        submodule_name = f"awesome_llm4cybersecurity.{self._model_name}"
        submodule = importlib.import_module(submodule_name)
        for attr in ("SentinelGPT", "Client", "Model"):
            client_cls = getattr(submodule, attr, None)
            if client_cls is not None:
                return client_cls()
        create_client = getattr(submodule, "create_client", None)
        if callable(create_client):
            return create_client()
        raise ExplanationError(
            f"Module '{submodule_name}' does not expose a usable client factory"
        )

    def _invoke_model(self, client: Any, prompt: str) -> Any:
        invocation_order = (
            "generate",
            "complete",
            "invoke",
        )
        kwargs = {
            "prompt": prompt,
            "max_tokens": self._max_tokens,
            "temperature": self._temperature,
        }
        for method_name in invocation_order:
            method = getattr(client, method_name, None)
            if callable(method):
                return method(**kwargs)
        raise ExplanationError(
            "The SentinelGPT client does not implement a recognised invocation method"
        )

    def _extract_text(self, response: Any) -> str:
        if response is None:
            raise ExplanationError("Empty response received from SentinelGPT")
        if isinstance(response, str):
            return response
        if isinstance(response, Mapping):
            for key in ("text", "output", "completion", "generated_text"):
                if key in response:
                    return str(response[key])
            choices = response.get("choices")
            if isinstance(choices, Iterable):
                for choice in choices:
                    if isinstance(choice, Mapping):
                        message = choice.get("message")
                        if isinstance(message, Mapping) and "content" in message:
                            return str(message["content"])
                        if "text" in choice:
                            return str(choice["text"])
        raise ExplanationError("Unable to parse SentinelGPT response payload")


__all__ = ["ExplanationError", "ExplanationGenerator", "RateLimiter"]
