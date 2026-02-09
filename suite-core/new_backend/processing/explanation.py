"""Explanation generator using SentinelGPT."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Protocol


class RateLimiter(Protocol):
    """Protocol for rate limiters."""

    def acquire(self) -> None:
        """Acquire a rate limit token."""
        ...


class ExplanationGenerator:
    """Generator for security finding explanations using LLM."""

    def __init__(self, rate_limiter: Optional[RateLimiter] = None) -> None:
        self._rate_limiter = rate_limiter
        self._client = None

    def _ensure_client(self):
        """Get or create the SentinelGPT client."""
        if self._client is None:
            try:
                from awesome_llm4cybersecurity.sentinel_gpt import SentinelGPT

                self._client = SentinelGPT()
            except ImportError:
                raise ImportError(
                    "awesome_llm4cybersecurity is required for explanation generation"
                )
        return self._client

    def _build_prompt(
        self, findings: List[Dict[str, Any]], context: Dict[str, Any]
    ) -> str:
        """Build the prompt for the LLM.

        Args:
            findings: List of security findings
            context: Additional context information

        Returns:
            Formatted prompt string
        """
        prompt_parts = ["You are SentinelGPT, a security analysis assistant."]

        if context:
            context_str = ", ".join(f"{k}: {v}" for k, v in context.items())
            prompt_parts.append(f"Context: {context_str}")

        prompt_parts.append("Analyze the following security findings:")
        for finding in findings:
            finding_str = (
                f"- {finding.get('rule_id', 'Unknown')}: "
                f"{finding.get('description', 'No description')} "
                f"(severity: {finding.get('severity', 'unknown')}, "
                f"location: {finding.get('location', 'unknown')})"
            )
            prompt_parts.append(finding_str)

        prompt_parts.append(
            "Provide a concise explanation of the security implications and recommended actions."
        )

        return "\n".join(prompt_parts)

    def generate(
        self, findings: List[Dict[str, Any]], context: Optional[Dict[str, Any]] = None
    ) -> str:
        """Generate an explanation for security findings.

        Args:
            findings: List of security findings to explain
            context: Optional context information

        Returns:
            Generated explanation text
        """
        if self._rate_limiter:
            self._rate_limiter.acquire()

        client = self._ensure_client()
        prompt = self._build_prompt(findings, context or {})

        response = client.generate(
            prompt=prompt,
            max_tokens=500,
            temperature=0.7,
        )

        return response.get("text", "")


__all__ = ["ExplanationGenerator"]
