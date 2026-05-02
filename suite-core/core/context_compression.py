"""Context Compression Service — Reduce LLM token usage via headroom.

Wraps chopratejas/headroom (Apache 2.0, 776 stars) for prompt compression.
Air-gap compatible: falls back to naive truncation when headroom is unavailable.

Usage:
    from core.context_compression import compress_prompt
    compressed = compress_prompt(long_prompt, max_tokens=4000)
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict

logger = logging.getLogger(__name__)

# headroom — RETIRED 2026-05-03 per docs/suite_core_install_retire_decisions_2026-05-03.md
# Marketing-only ML compression; the regex/truncation heuristic below ships and
# is sufficient. Flag stays ``False`` so the existing False-branches in
# ``compress_prompt`` short-circuit straight to the heuristic path.
_HAS_HEADROOM = False

# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------
_stats: Dict[str, int] = {
    "calls": 0,
    "tokens_saved_estimate": 0,
    "fallback_count": 0,
}


# ---------------------------------------------------------------------------
# Heuristic fallback compression
# ---------------------------------------------------------------------------

# Patterns that add tokens but little value in security prompts
_NOISE_PATTERNS = [
    (re.compile(r"\n{3,}"), "\n\n"),                    # Triple+ newlines → double
    (re.compile(r"[ \t]{2,}"), " "),                     # Multiple spaces → single
    (re.compile(r"```\n\n"), "```\n"),                    # Empty lines after code fences
    (re.compile(r"\n\n```"), "\n```"),                    # Empty lines before code fences
    (re.compile(r"#{1,3} "), ""),                         # Remove markdown headers (keep text)
    (re.compile(r"[*_]{2}([^*_]+)[*_]{2}"), r"\1"),      # Remove bold/italic markers
    (re.compile(r"^\s*[-*]\s+", re.MULTILINE), "- "),    # Normalize list markers
]


def _heuristic_compress(text: str, max_chars: int) -> str:
    """Compress text using regex heuristics when headroom is unavailable."""
    result = text
    for pattern, replacement in _NOISE_PATTERNS:
        result = pattern.sub(replacement, result)

    # If still too long, truncate intelligently (keep start + end)
    if len(result) > max_chars:
        keep = max_chars // 2
        result = result[:keep] + "\n\n[... compressed ...]\n\n" + result[-keep:]

    return result.strip()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def compress_prompt(
    text: str,
    max_tokens: int = 4000,
    method: str = "auto",
) -> str:
    """Compress a prompt to reduce LLM token usage.

    Args:
        text: The prompt text to compress.
        max_tokens: Target maximum token count (approximate).
        method: "headroom", "heuristic", or "auto" (try headroom first).

    Returns:
        Compressed text string.
    """
    _stats["calls"] += 1
    original_len = len(text)

    # Approximate: 1 token ≈ 4 chars for English
    max_chars = max_tokens * 4

    # Already short enough
    if original_len <= max_chars:
        return text

    if method == "headroom" or (method == "auto" and _HAS_HEADROOM):
        try:
            result = compress(text, target_tokens=max_tokens)
            compressed = result if isinstance(result, str) else str(result)
            saved = original_len - len(compressed)
            _stats["tokens_saved_estimate"] += saved // 4
            return compressed
        except (OSError, ValueError, RuntimeError, TypeError) as exc:
            logger.warning("headroom compression failed: %s — using heuristic", type(exc).__name__)

    # Fallback
    _stats["fallback_count"] += 1
    compressed = _heuristic_compress(text, max_chars)
    saved = original_len - len(compressed)
    _stats["tokens_saved_estimate"] += saved // 4
    return compressed


def get_compression_stats() -> Dict[str, Any]:
    """Return compression usage statistics."""
    return {
        "backend": "headroom" if _HAS_HEADROOM else "heuristic_fallback",
        "headroom_available": _HAS_HEADROOM,
        **_stats,
    }

