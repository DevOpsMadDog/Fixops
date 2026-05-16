"""Real LLM Council — 4-model OpenRouter consensus + Opus escalation + DPO capture.

Fans out a security-decision prompt to 4 free OpenRouter models in parallel,
aggregates votes via majority rule, escalates to Claude Opus when confidence
is below threshold OR no majority exists, and persists every verdict as a DPO
pair to suite-core/core/dpo_pairs.db for the learning loop.

Public API:
    council = LLMCouncil()
    result  = await council.convene(prompt, context, threshold=0.75)

Result shape:
    {
        "verdict":          "approve" | "reject" | "escalate",
        "vote_counts":      {"approve": N, "reject": N, "escalate": N},
        "individual_votes": [{"model": str, "vote": str, "reasoning": str,
                              "confidence": float, "latency_ms": int}, ...],
        "escalated":        bool,
        "final_reasoning":  str,
        "latency_ms":       int,
    }

If OPENROUTER_API_KEY is not set the class raises CouncilNotConfiguredError
at construction time. The router wraps this in a 503 response.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_OPENROUTER_BASE = "https://openrouter.ai/api/v1/chat/completions"
_ANTHROPIC_BASE  = "https://api.anthropic.com/v1/messages"

# The 4 free models to poll in parallel.
_FREE_MODELS: list[str] = [
    "google/gemini-2.0-flash-exp:free",
    "meta-llama/llama-3.3-70b-instruct:free",
    "qwen/qwen-2.5-72b-instruct:free",
    "mistralai/mistral-small-3.1-24b-instruct:free",
]

_OPUS_MODEL = "claude-opus-4-5"          # escalation target
_VOTE_LABELS = frozenset({"approve", "reject", "escalate"})

# Per-model HTTP timeout (free models can be slow)
_MODEL_TIMEOUT_S  = 30.0
# Total fan-out timeout — we wait this long for all 4 models together
_FANOUT_TIMEOUT_S = 35.0

# DPO DB path (relative to repo root; also settable via env)
_DPO_DB_DEFAULT = "suite-core/core/dpo_pairs.db"

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class CouncilNotConfiguredError(RuntimeError):
    """Raised when OPENROUTER_API_KEY is not set."""


# ---------------------------------------------------------------------------
# Vote schema builder
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are a security decision council member. Your job is to evaluate a security \
decision prompt and return a structured JSON verdict.

Respond ONLY with valid JSON — no markdown fences, no extra text:
{
  "vote": "approve" | "reject" | "escalate",
  "reasoning": "<one sentence justification>",
  "confidence": <float 0.0-1.0>
}

Rules:
- "approve"  → the action/change is safe to proceed
- "reject"   → the action/change poses unacceptable security risk
- "escalate" → insufficient information or genuinely ambiguous; human review needed
- confidence must reflect genuine certainty (0.5 = coin-flip, 1.0 = certain)
"""


def _build_user_message(prompt: str, context: dict[str, Any]) -> str:
    ctx_str = json.dumps(context, default=str)[:2000]
    return (
        f"Security decision prompt:\n{prompt}\n\n"
        f"Additional context:\n{ctx_str}"
    )


# ---------------------------------------------------------------------------
# DPO persistence
# ---------------------------------------------------------------------------

_DPO_SCHEMA = """
CREATE TABLE IF NOT EXISTS dpo_pairs (
    id           TEXT PRIMARY KEY,
    prompt       TEXT NOT NULL,
    context_json TEXT NOT NULL,
    verdict      TEXT NOT NULL,
    vote_counts  TEXT NOT NULL,
    individual_votes TEXT NOT NULL,
    escalated    INTEGER NOT NULL DEFAULT 0,
    final_reasoning TEXT NOT NULL,
    latency_ms   INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT NOT NULL
)
"""


def _get_dpo_db_path() -> str:
    return os.environ.get("FIXOPS_DPO_DB", _DPO_DB_DEFAULT)


def _ensure_dpo_db(db_path: str) -> None:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=10)
    try:
        conn.execute(_DPO_SCHEMA)
        conn.commit()
    finally:
        conn.close()


def _persist_dpo(
    *,
    db_path: str,
    prompt: str,
    context: dict[str, Any],
    result: dict[str, Any],
) -> str:
    """Insert verdict into dpo_pairs table. Returns row id. Never raises."""
    row_id = str(uuid.uuid4())
    try:
        conn = sqlite3.connect(db_path, timeout=10)
        try:
            conn.execute(
                """
                INSERT INTO dpo_pairs
                    (id, prompt, context_json, verdict, vote_counts,
                     individual_votes, escalated, final_reasoning,
                     latency_ms, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row_id,
                    prompt[:4096],
                    json.dumps(context, default=str)[:4096],
                    result["verdict"],
                    json.dumps(result["vote_counts"]),
                    json.dumps(result["individual_votes"]),
                    int(result["escalated"]),
                    result["final_reasoning"][:2048],
                    result["latency_ms"],
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception as exc:  # noqa: BLE001
        logger.warning("DPO persist failed (non-fatal): %s", exc)
    return row_id


# ---------------------------------------------------------------------------
# Core engine
# ---------------------------------------------------------------------------


class LLMCouncil:
    """Real 4-model consensus council.

    Construction raises CouncilNotConfiguredError if OPENROUTER_API_KEY is absent.
    The Anthropic escalation is optional — if ANTHROPIC_API_KEY is absent,
    escalation falls back to a conservative "escalate" verdict with a warning.
    """

    def __init__(
        self,
        models: list[str] | None = None,
        *,
        openrouter_key: str | None = None,
        anthropic_key: str | None = None,
        dpo_db_path: str | None = None,
    ) -> None:
        key = openrouter_key or os.environ.get("OPENROUTER_API_KEY", "")
        if not key:
            raise CouncilNotConfiguredError(
                "OPENROUTER_API_KEY is not set — LLM Council is not configured. "
                "Set the environment variable to enable real consensus."
            )
        self._or_key      = key
        self._anth_key    = anthropic_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self._models      = models or _FREE_MODELS
        self._dpo_db      = dpo_db_path or _get_dpo_db_path()

        _ensure_dpo_db(self._dpo_db)
        logger.info(
            "LLMCouncil initialized: %d models, dpo_db=%s, opus_escalation=%s",
            len(self._models),
            self._dpo_db,
            bool(self._anth_key),
        )

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def convene(
        self,
        prompt: str,
        context: dict[str, Any],
        *,
        threshold: float = 0.75,
    ) -> dict[str, Any]:
        """Fan out prompt to all models, aggregate votes, optionally escalate.

        Args:
            prompt:    The security decision question.
            context:   Arbitrary dict with supporting data (finding, asset, etc.).
            threshold: Minimum average confidence required before accepting the
                       majority verdict without escalation. If avg confidence <
                       threshold OR no majority, escalate to Opus.

        Returns:
            Full verdict dict — see module docstring for shape.

        Raises:
            CouncilNotConfiguredError: if OPENROUTER_API_KEY missing (raised at __init__).
        """
        t0 = time.perf_counter()

        user_msg = _build_user_message(prompt, context)

        # Fan out to all 4 models in parallel
        individual_votes = await self._fan_out(user_msg)

        # Aggregate
        vote_counts, avg_confidence, majority = _aggregate(individual_votes)

        # Decide whether to escalate
        need_escalate = (
            majority is None
            or avg_confidence < threshold
        )

        escalated       = False
        final_reasoning = ""

        if need_escalate:
            escalated = True
            opus_verdict, opus_reasoning = await self._escalate_opus(
                prompt=prompt,
                context=context,
                individual_votes=individual_votes,
                vote_counts=vote_counts,
            )
            verdict         = opus_verdict
            final_reasoning = opus_reasoning
            # Reflect escalation in vote counts
            vote_counts["escalate"] = vote_counts.get("escalate", 0) + 1
        else:
            verdict = majority  # type: ignore[assignment]
            final_reasoning = _synthesize_reasoning(individual_votes, verdict)

        latency_ms = int((time.perf_counter() - t0) * 1000)

        result: dict[str, Any] = {
            "verdict":          verdict,
            "vote_counts":      vote_counts,
            "individual_votes": individual_votes,
            "escalated":        escalated,
            "final_reasoning":  final_reasoning,
            "latency_ms":       latency_ms,
        }

        # Persist to DPO DB (non-blocking, non-fatal)
        _persist_dpo(
            db_path=self._dpo_db,
            prompt=prompt,
            context=context,
            result=result,
        )

        logger.info(
            "Council verdict=%s escalated=%s avg_conf=%.2f latency=%dms",
            verdict,
            escalated,
            avg_confidence,
            latency_ms,
        )
        return result

    # ------------------------------------------------------------------
    # Fan-out
    # ------------------------------------------------------------------

    async def _fan_out(self, user_msg: str) -> list[dict[str, Any]]:
        """Call all models concurrently. Returns individual_votes list."""
        async with httpx.AsyncClient(timeout=_MODEL_TIMEOUT_S) as client:
            tasks = [
                self._call_model(client, model, user_msg)
                for model in self._models
            ]
            try:
                results = await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=_FANOUT_TIMEOUT_S,
                )
            except asyncio.TimeoutError:
                logger.warning("Fan-out timed out after %.0fs", _FANOUT_TIMEOUT_S)
                results = [TimeoutError("fan-out global timeout")] * len(self._models)

        votes: list[dict[str, Any]] = []
        for model, res in zip(self._models, results):
            if isinstance(res, BaseException):
                logger.warning("Model %s error: %s", model, res)
                votes.append(_error_vote(model, str(res)))
            else:
                votes.append(res)
        return votes

    async def _call_model(
        self,
        client: httpx.AsyncClient,
        model: str,
        user_msg: str,
    ) -> dict[str, Any]:
        """Call one OpenRouter model and return a structured vote dict."""
        t0 = time.perf_counter()
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user",   "content": user_msg},
            ],
            "temperature":      0.2,
            "max_tokens":       256,
            "response_format":  {"type": "json_object"},
        }
        headers = {
            "Authorization":  f"Bearer {self._or_key}",
            "Content-Type":   "application/json",
            "HTTP-Referer":   "https://aldeci.ai",
            "X-Title":        "ALdeci LLM Council",
        }
        try:
            resp = await client.post(_OPENROUTER_BASE, json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            raw  = data["choices"][0]["message"]["content"]
            parsed = _parse_vote(raw)
        except httpx.HTTPStatusError as exc:
            logger.warning("Model %s HTTP %d: %s", model, exc.response.status_code, exc)
            return _error_vote(model, f"HTTP {exc.response.status_code}")
        except (KeyError, IndexError, json.JSONDecodeError) as exc:
            logger.warning("Model %s parse error: %s", model, exc)
            return _error_vote(model, f"parse error: {exc}")

        latency_ms = int((time.perf_counter() - t0) * 1000)
        return {
            "model":      model,
            "vote":       parsed["vote"],
            "reasoning":  parsed.get("reasoning", ""),
            "confidence": parsed.get("confidence", 0.5),
            "latency_ms": latency_ms,
        }

    # ------------------------------------------------------------------
    # Escalation
    # ------------------------------------------------------------------

    async def _escalate_opus(
        self,
        *,
        prompt: str,
        context: dict[str, Any],
        individual_votes: list[dict[str, Any]],
        vote_counts: dict[str, int],
    ) -> tuple[str, str]:
        """Call Claude Opus for tie-breaking / low-confidence escalation.

        Returns (verdict_str, reasoning_str).
        Falls back to "escalate" + warning if Anthropic key is missing.
        """
        if not self._anth_key:
            logger.warning(
                "Opus escalation triggered but ANTHROPIC_API_KEY not set; "
                "returning conservative 'escalate' verdict"
            )
            return (
                "escalate",
                "Escalation required but Anthropic API key not configured — "
                "human review mandatory.",
            )

        council_summary = "\n".join(
            f"  {v['model']}: {v['vote']} (conf={v['confidence']:.2f}) — {v['reasoning'][:120]}"
            for v in individual_votes
        )
        escalation_prompt = (
            f"You are the final authority on a contested security decision.\n\n"
            f"Original question:\n{prompt}\n\n"
            f"Context:\n{json.dumps(context, default=str)[:1500]}\n\n"
            f"Council votes (low confidence or no majority):\n{council_summary}\n\n"
            f"Vote counts: {json.dumps(vote_counts)}\n\n"
            f"Return ONLY valid JSON:\n"
            f'{{"vote": "approve"|"reject"|"escalate", "reasoning": "<sentence>"}}'
        )

        payload = {
            "model":      _OPUS_MODEL,
            "max_tokens": 256,
            "messages":   [{"role": "user", "content": escalation_prompt}],
        }
        headers = {
            "x-api-key":         self._anth_key,
            "anthropic-version": "2023-06-01",
            "content-type":      "application/json",
        }

        try:
            async with httpx.AsyncClient(timeout=45.0) as client:
                resp = await client.post(_ANTHROPIC_BASE, json=payload, headers=headers)
                resp.raise_for_status()
                data = resp.json()
                raw  = data["content"][0]["text"]
                parsed = _parse_vote(raw)
                return (
                    parsed["vote"],
                    f"Opus escalation: {parsed.get('reasoning', 'No reasoning provided')}",
                )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Opus escalation HTTP call failed: %s", exc)
            return (
                "escalate",
                f"Opus escalation failed ({type(exc).__name__}): {exc}. Human review required.",
            )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_vote(raw: str) -> dict[str, Any]:
    """Parse JSON vote from LLM response. Normalise vote label. Never raises."""
    try:
        data = json.loads(raw.strip())
    except json.JSONDecodeError:
        # Try to extract JSON from a markdown-fenced response
        import re
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        if m:
            try:
                data = json.loads(m.group())
            except json.JSONDecodeError:
                data = {}
        else:
            data = {}

    raw_vote = str(data.get("vote", "")).lower().strip()
    if raw_vote not in _VOTE_LABELS:
        # Map common synonyms
        if raw_vote in ("yes", "safe", "allow", "approved"):
            raw_vote = "approve"
        elif raw_vote in ("no", "block", "deny", "rejected", "risky"):
            raw_vote = "reject"
        else:
            raw_vote = "escalate"

    confidence = float(data.get("confidence", 0.5))
    confidence = max(0.0, min(1.0, confidence))

    return {
        "vote":       raw_vote,
        "reasoning":  str(data.get("reasoning", ""))[:500],
        "confidence": confidence,
    }


def _error_vote(model: str, error: str) -> dict[str, Any]:
    return {
        "model":      model,
        "vote":       "escalate",
        "reasoning":  f"Model error: {error}",
        "confidence": 0.0,
        "latency_ms": 0,
        "error":      error,
    }


def _aggregate(
    votes: list[dict[str, Any]],
) -> tuple[dict[str, int], float, str | None]:
    """Return (vote_counts, avg_confidence, majority_or_None).

    majority is None when no single label has > 50% of valid votes.
    Error votes (confidence=0, vote=escalate due to error) are counted but
    their confidence does not inflate the average.
    """
    counts: dict[str, int] = {"approve": 0, "reject": 0, "escalate": 0}
    valid_confidences: list[float] = []

    for v in votes:
        label = v.get("vote", "escalate")
        if label not in counts:
            label = "escalate"
        counts[label] += 1
        if not v.get("error"):
            valid_confidences.append(v.get("confidence", 0.5))

    avg_conf = sum(valid_confidences) / len(valid_confidences) if valid_confidences else 0.0

    total = sum(counts.values())
    majority: str | None = None
    for label, cnt in counts.items():
        if cnt / total > 0.5:
            majority = label
            break

    return counts, avg_conf, majority


def _synthesize_reasoning(
    votes: list[dict[str, Any]],
    verdict: str,
) -> str:
    agreeing = [v for v in votes if v.get("vote") == verdict and not v.get("error")]
    snippets = [
        f"{v['model'].split('/')[1] if '/' in v['model'] else v['model']}: "
        f"{v.get('reasoning', '')[:100]}"
        for v in agreeing[:2]
    ]
    return (
        f"Majority verdict: {verdict}. "
        + " | ".join(snippets)
    )
