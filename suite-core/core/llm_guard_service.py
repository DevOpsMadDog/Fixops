"""LLM-Guard Security Service — prompt/output scanning for LLM interactions.

Wraps Protect AI's LLM-Guard (MIT) to provide:
  - Prompt injection detection
  - PII / secrets leakage prevention
  - Toxic content filtering
  - Invisible-text / unicode attack detection

Air-gap compatible: falls back to regex-based heuristics when LLM-Guard
models are unavailable (no network download required).

Usage:
    from core.llm_guard_service import LLMGuardService

    svc = LLMGuardService()
    result = svc.scan_prompt("Analyze CVE-2024-3094 ...")
    if result["blocked"]:
        print("Prompt blocked:", result["issues"])
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# TrustGraph second-brain wiring
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload: dict) -> None:
    """Emit to TrustGraph event bus. Never raises."""
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
            import asyncio as _aio
            import inspect as _insp
            if _insp.iscoroutine(result):
                try:
                    loop = _aio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    result.close()
        except Exception:  # pragma: no cover
            pass
    except Exception:  # pragma: no cover
        pass


try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass


import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# LLM-Guard — RETIRED 2026-05-03 per docs/suite_core_install_retire_decisions_2026-05-03.md
# We ship our own guards (core.aidefence_*); the regex fallback path below is
# canonical. Flag remains as ``False`` so the existing branches (`if _HAS_LLM_GUARD`)
# continue to short-circuit to the regex implementation that already shipped.
# ---------------------------------------------------------------------------
_HAS_LLM_GUARD = False


# ---------------------------------------------------------------------------
# Regex-based fallback patterns (air-gap / no-dependency mode)
# ---------------------------------------------------------------------------
_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"forget\s+(all\s+)?previous\s+(instructions|context)", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(a|an)\s+", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(prior|previous|above)", re.IGNORECASE),
    re.compile(r"system\s*:\s*", re.IGNORECASE),
    re.compile(r"\[INST\]|\[/INST\]|<\|im_start\|>|<\|im_end\|>", re.IGNORECASE),
    re.compile(r"<\s*script\b", re.IGNORECASE),
]

_SECRET_PATTERNS = [
    re.compile(r"(?:api[_-]?key|apikey)\s*[:=]\s*\S{8,}", re.IGNORECASE),
    re.compile(r"(?:password|passwd|pwd)\s*[:=]\s*\S{4,}", re.IGNORECASE),
    re.compile(r"(?:secret|token)\s*[:=]\s*\S{8,}", re.IGNORECASE),
    re.compile(r"(?:aws_?access_?key_?id)\s*[:=]\s*\S{16,}", re.IGNORECASE),
    re.compile(r"(?:aws_?secret_?access_?key)\s*[:=]\s*\S{16,}", re.IGNORECASE),
    re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", re.IGNORECASE),
    re.compile(r"ghp_[A-Za-z0-9_]{36,}", re.IGNORECASE),
    re.compile(r"sk-[A-Za-z0-9]{32,}", re.IGNORECASE),
]

_INVISIBLE_CHARS = re.compile(
    r"[\u200b\u200c\u200d\u2060\u2061\u2062\u2063\u2064\ufeff\u00ad]"
)


@dataclass
class ScanResult:
    """Result of a prompt or output scan."""

    sanitized_text: str
    blocked: bool
    issues: List[str] = field(default_factory=list)
    scanner_scores: Dict[str, float] = field(default_factory=dict)
    scanner_valid: Dict[str, bool] = field(default_factory=dict)
    scan_time_ms: float = 0.0
    method: str = "llm_guard"  # or "regex_fallback"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sanitized_text": self.sanitized_text,
            "blocked": self.blocked,
            "issues": self.issues,
            "scanner_scores": self.scanner_scores,
            "scanner_valid": self.scanner_valid,
            "scan_time_ms": round(self.scan_time_ms, 2),
            "method": self.method,
        }


class LLMGuardService:
    """Unified LLM security scanning service.

    Uses LLM-Guard when available; falls back to regex heuristics for
    air-gapped / lightweight deployments.
    """

    def __init__(
        self,
        *,
        enable_prompt_injection: bool = True,
        enable_secrets: bool = True,
        enable_toxicity: bool = True,
        enable_invisible_text: bool = True,
        enable_output_bias: bool = True,
        enable_output_sensitive: bool = True,
        max_tokens: int = 4096,
        fail_fast: bool = True,
    ) -> None:
        self._fail_fast = fail_fast
        self._config = {
            "prompt_injection": enable_prompt_injection,
            "secrets": enable_secrets,
            "toxicity": enable_toxicity,
            "invisible_text": enable_invisible_text,
            "output_bias": enable_output_bias,
            "output_sensitive": enable_output_sensitive,
            "max_tokens": max_tokens,
        }
        self._input_scanners: list = []
        self._output_scanners: list = []
        self._stats: Dict[str, int] = {
            "prompts_scanned": 0,
            "prompts_blocked": 0,
            "outputs_scanned": 0,
            "outputs_blocked": 0,
        }

        if _HAS_LLM_GUARD:
            self._init_llm_guard_scanners()
            logger.info("LLMGuardService initialized with LLM-Guard scanners")
        else:
            logger.info("LLMGuardService initialized with regex fallback")

    # ------------------------------------------------------------------
    # LLM-Guard scanner initialization
    # ------------------------------------------------------------------
    def _init_llm_guard_scanners(self) -> None:
        """Initialize LLM-Guard scanner instances based on config."""
        if self._config["prompt_injection"]:
            self._input_scanners.append(PromptInjection())
        if self._config["secrets"]:
            self._input_scanners.append(Secrets())
        if self._config["toxicity"]:
            self._input_scanners.append(InputToxicity())
        if self._config["invisible_text"]:
            self._input_scanners.append(InvisibleText())
        if self._config["max_tokens"]:
            self._input_scanners.append(
                TokenLimit(limit=self._config["max_tokens"])
            )

        # Output scanners
        if self._config["output_sensitive"]:
            self._output_scanners.append(Sensitive())
        if self._config["toxicity"]:
            self._output_scanners.append(OutputToxicity())
        if self._config["output_bias"]:
            self._output_scanners.append(Bias())

    # ------------------------------------------------------------------
    # Public API: scan_prompt
    # ------------------------------------------------------------------
    def scan_prompt(self, prompt: str) -> ScanResult:
        """Scan an input prompt before sending to LLM.

        Returns a ScanResult with sanitized text and any issues found.
        """
        start = time.perf_counter()
        self._stats["prompts_scanned"] += 1

        if _HAS_LLM_GUARD and self._input_scanners:
            result = self._scan_prompt_llm_guard(prompt)
        else:
            result = self._scan_prompt_regex(prompt)

        result.scan_time_ms = (time.perf_counter() - start) * 1000
        if result.blocked:
            self._stats["prompts_blocked"] += 1
            logger.warning(
                "Prompt blocked by LLMGuardService: %s", result.issues
            )
            _emit_event("llm_guard_service.prompt_blocked", {
                "issues": list(result.issues),
                "method": result.method,
                "scan_time_ms": result.scan_time_ms,
            })
        return result

    # ------------------------------------------------------------------
    # Public API: scan_output
    # ------------------------------------------------------------------
    def scan_output(self, prompt: str, output: str) -> ScanResult:
        """Scan LLM output before returning to the caller.

        Returns a ScanResult with sanitized text and any issues found.
        """
        start = time.perf_counter()
        self._stats["outputs_scanned"] += 1

        if _HAS_LLM_GUARD and self._output_scanners:
            result = self._scan_output_llm_guard(prompt, output)
        else:
            result = self._scan_output_regex(output)

        result.scan_time_ms = (time.perf_counter() - start) * 1000
        if result.blocked:
            self._stats["outputs_blocked"] += 1
            logger.warning(
                "Output blocked by LLMGuardService: %s", result.issues
            )
            _emit_event("llm_guard_service.output_blocked", {
                "issues": list(result.issues),
                "method": result.method,
                "scan_time_ms": result.scan_time_ms,
            })
        return result

    # ------------------------------------------------------------------
    # Public API: health / stats
    # ------------------------------------------------------------------
    def get_status(self) -> Dict[str, Any]:
        """Return service health and scan statistics."""
        return {
            "available": True,
            "backend": "llm_guard" if _HAS_LLM_GUARD else "regex_fallback",
            "input_scanners": (
                [type(s).__name__ for s in self._input_scanners]
                if _HAS_LLM_GUARD
                else ["regex_injection", "regex_secrets", "regex_invisible"]
            ),
            "output_scanners": (
                [type(s).__name__ for s in self._output_scanners]
                if _HAS_LLM_GUARD
                else ["regex_secrets"]
            ),
            "config": self._config,
            "stats": dict(self._stats),
        }

    # ------------------------------------------------------------------
    # LLM-Guard backed scanning
    # ------------------------------------------------------------------
    def _scan_prompt_llm_guard(self, prompt: str) -> ScanResult:
        sanitized, valid_map, score_map = _lg_scan_prompt(
            self._input_scanners, prompt, fail_fast=self._fail_fast
        )
        issues = [name for name, ok in valid_map.items() if not ok]
        return ScanResult(
            sanitized_text=sanitized,
            blocked=len(issues) > 0,
            issues=issues,
            scanner_scores=score_map,
            scanner_valid=valid_map,
            method="llm_guard",
        )

    def _scan_output_llm_guard(self, prompt: str, output: str) -> ScanResult:
        sanitized, valid_map, score_map = _lg_scan_output(
            self._output_scanners, prompt, output, fail_fast=self._fail_fast
        )
        issues = [name for name, ok in valid_map.items() if not ok]
        return ScanResult(
            sanitized_text=sanitized,
            blocked=len(issues) > 0,
            issues=issues,
            scanner_scores=score_map,
            scanner_valid=valid_map,
            method="llm_guard",
        )

    # ------------------------------------------------------------------
    # Regex fallback scanning (air-gap / no-dependency)
    # ------------------------------------------------------------------
    def _scan_prompt_regex(self, prompt: str) -> ScanResult:
        issues: List[str] = []
        scores: Dict[str, float] = {}
        valid: Dict[str, bool] = {}

        # Prompt injection check
        if self._config["prompt_injection"]:
            for pat in _INJECTION_PATTERNS:
                if pat.search(prompt):
                    issues.append("PromptInjection")
                    scores["PromptInjection"] = 1.0
                    valid["PromptInjection"] = False
                    break
            else:
                scores["PromptInjection"] = 0.0
                valid["PromptInjection"] = True

        # Secrets check
        if self._config["secrets"]:
            for pat in _SECRET_PATTERNS:
                if pat.search(prompt):
                    issues.append("Secrets")
                    scores["Secrets"] = 1.0
                    valid["Secrets"] = False
                    break
            else:
                scores["Secrets"] = 0.0
                valid["Secrets"] = True

        # Invisible text check
        if self._config["invisible_text"]:
            if _INVISIBLE_CHARS.search(prompt):
                issues.append("InvisibleText")
                scores["InvisibleText"] = 1.0
                valid["InvisibleText"] = False
                prompt = _INVISIBLE_CHARS.sub("", prompt)
            else:
                scores["InvisibleText"] = 0.0
                valid["InvisibleText"] = True

        return ScanResult(
            sanitized_text=prompt,
            blocked=len(issues) > 0,
            issues=issues,
            scanner_scores=scores,
            scanner_valid=valid,
            method="regex_fallback",
        )

    def _scan_output_regex(self, output: str) -> ScanResult:
        issues: List[str] = []
        scores: Dict[str, float] = {}
        valid: Dict[str, bool] = {}

        # Check for leaked secrets in output
        if self._config["output_sensitive"]:
            for pat in _SECRET_PATTERNS:
                if pat.search(output):
                    issues.append("Sensitive")
                    scores["Sensitive"] = 1.0
                    valid["Sensitive"] = False
                    break
            else:
                scores["Sensitive"] = 0.0
                valid["Sensitive"] = True

        return ScanResult(
            sanitized_text=output,
            blocked=len(issues) > 0,
            issues=issues,
            scanner_scores=scores,
            scanner_valid=valid,
            method="regex_fallback",
        )


# ---------------------------------------------------------------------------
# Module-level singleton (lazy)
# ---------------------------------------------------------------------------
_service_instance: Optional[LLMGuardService] = None


def get_llm_guard_service(**kwargs: Any) -> LLMGuardService:
    """Get or create the singleton LLMGuardService instance."""
    global _service_instance
    if _service_instance is None:
        _service_instance = LLMGuardService(**kwargs)
    return _service_instance
