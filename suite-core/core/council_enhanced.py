"""Enhanced LLM Council — confidence scoring, dissent tracking, and calibration.

Extends the existing LLMCouncilEngine (Karpathy 3-stage pattern) with:
- Per-finding deliberation returning a structured CouncilVerdict
- Confidence scoring based on weighted agreement across models
- Dissent tracking (which models disagreed and why)
- Auto-escalation to Opus when confidence < 0.7
- Outcome feedback loop to calibrate model weights over time
- TrustGraph Core 4 (Decision Memory) storage
- SQLite-backed weight persistence and calibration report

Usage:
    from core.council_enhanced import EnhancedLLMCouncil, CouncilVerdict

    council = EnhancedLLMCouncil()
    verdict = council.deliberate(finding={"title": "CVE-2024-1234"}, question="TP or FP?")
    print(verdict.verdict, verdict.confidence, verdict.dissenting_models)

    # Feed back the actual outcome later
    council.track_accuracy(verdict.verdict_id, actual_outcome="TRUE_POSITIVE")

    report = council.get_calibration_report()
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sqlite3
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

logger = logging.getLogger(__name__)

# Sentinel returned as the reasoning prefix when council is not configured,
# so callers can distinguish honest unavailability from real votes.
_NOT_CONFIGURED_PREFIX = "[NOT_CONFIGURED]"
_TEST_MOCK_PREFIX = "[MOCK_VOTE]"

__all__ = [
    "CouncilVerdict",
    "CalibrationReport",
    "ModelCalibration",
    "EnhancedLLMCouncil",
]

# ---------------------------------------------------------------------------
# Vote literals
# ---------------------------------------------------------------------------

VoteLabel = Literal["TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_REVIEW"]
VerdictLabel = Literal["TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_REVIEW", "ESCALATED"]

# Default model weights (calibration adjusts these over time)
_DEFAULT_WEIGHTS: Dict[str, float] = {
    "qwen_qwq": 1.0,
    "kimi_k2": 1.0,
    "deepseek_r1": 1.0,  # DeepSeek R1 — strong reasoning and vulnerability research
    "gemma4": 0.8,
    "claude_opus": 1.5,  # escalation only
}

# Confidence threshold below which we escalate to Opus
_ESCALATION_THRESHOLD = 0.7


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class CouncilVerdict:
    """Full deliberation result from EnhancedLLMCouncil."""

    verdict_id: str
    verdict: VerdictLabel
    confidence: float
    votes: Dict[str, str]  # model_name -> vote label
    agreement_pct: float
    dissenting_models: List[str]
    reasoning: str
    escalated_to_opus: bool
    processing_time_ms: int
    trustgraph_entity_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict_id": self.verdict_id,
            "verdict": self.verdict,
            "confidence": round(self.confidence, 4),
            "votes": self.votes,
            "agreement_pct": round(self.agreement_pct, 4),
            "dissenting_models": self.dissenting_models,
            "reasoning": self.reasoning,
            "escalated_to_opus": self.escalated_to_opus,
            "processing_time_ms": self.processing_time_ms,
            "trustgraph_entity_id": self.trustgraph_entity_id,
        }


@dataclass
class ModelCalibration:
    """Accuracy metrics for a single model."""

    model_name: str
    total_predictions: int
    correct_predictions: int
    current_weight: float
    accuracy: float
    last_updated: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_name": self.model_name,
            "total_predictions": self.total_predictions,
            "correct_predictions": self.correct_predictions,
            "current_weight": round(self.current_weight, 4),
            "accuracy": round(self.accuracy, 4),
            "last_updated": self.last_updated,
        }


@dataclass
class CalibrationReport:
    """Accuracy metrics per model over last 30 days."""

    generated_at: str
    window_days: int
    models: List[ModelCalibration]
    total_verdicts: int
    total_with_outcomes: int
    overall_accuracy: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "window_days": self.window_days,
            "models": [m.to_dict() for m in self.models],
            "total_verdicts": self.total_verdicts,
            "total_with_outcomes": self.total_with_outcomes,
            "overall_accuracy": round(self.overall_accuracy, 4),
        }


# ---------------------------------------------------------------------------
# SQLite schema helpers
# ---------------------------------------------------------------------------

_SCHEMA_VERDICTS = """
CREATE TABLE IF NOT EXISTS enhanced_verdicts (
    verdict_id     TEXT PRIMARY KEY,
    finding_json   TEXT NOT NULL,
    question       TEXT NOT NULL,
    votes_json     TEXT NOT NULL,
    verdict        TEXT NOT NULL,
    confidence     REAL NOT NULL,
    agreement_pct  REAL NOT NULL,
    dissenting_json TEXT NOT NULL,
    reasoning      TEXT NOT NULL,
    escalated      INTEGER NOT NULL DEFAULT 0,
    processing_ms  INTEGER NOT NULL DEFAULT 0,
    tg_entity_id   TEXT,
    created_at     TEXT NOT NULL
)
"""

_SCHEMA_OUTCOMES = """
CREATE TABLE IF NOT EXISTS verdict_outcomes (
    outcome_id   TEXT PRIMARY KEY,
    verdict_id   TEXT NOT NULL,
    actual_outcome TEXT NOT NULL,
    recorded_at  TEXT NOT NULL
)
"""

_SCHEMA_WEIGHTS = """
CREATE TABLE IF NOT EXISTS model_weights (
    model_name     TEXT PRIMARY KEY,
    weight         REAL NOT NULL,
    total_preds    INTEGER NOT NULL DEFAULT 0,
    correct_preds  INTEGER NOT NULL DEFAULT 0,
    updated_at     TEXT NOT NULL
)
"""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# EnhancedLLMCouncil
# ---------------------------------------------------------------------------


class EnhancedLLMCouncil:
    """Karpathy-inspired multi-model consensus with confidence + dissent tracking.

    Wraps/extends the existing LLMCouncilEngine with:
    - Structured CouncilVerdict output (TP/FP/NEEDS_REVIEW/ESCALATED)
    - Weighted confidence scoring
    - Dissent tracking per model
    - Outcome feedback and weight calibration
    - TrustGraph Core 4 storage (Decision Memory)
    - SQLite-backed persistence

    If no real LLM providers are available (e.g. in tests), falls back to
    mock deliberation that still exercises all scoring/escalation logic.
    """

    def __init__(
        self,
        db_path: Optional[str] = None,
        weights: Optional[Dict[str, float]] = None,
        escalation_threshold: float = _ESCALATION_THRESHOLD,
        *,
        _allow_mock: bool = False,
    ) -> None:
        """Initialise the enhanced council.

        Args:
            db_path: SQLite path for verdict/calibration storage.
            weights: Optional per-model weight overrides.
            escalation_threshold: Confidence below which Opus escalation fires.
            _allow_mock: If True, enables the deterministic ``_mock_vote``
                fallback when no LLM providers are reachable.  Intended
                **exclusively for unit tests** — never set True in production.
                When False (default) and no real council is available, an
                honest NOT_CONFIGURED verdict is returned instead.
        """
        db_path = db_path or os.environ.get(
            "FIXOPS_ENHANCED_COUNCIL_DB",
            "data/enhanced_council.db",
        )
        self._db_path = db_path
        self._escalation_threshold = escalation_threshold
        self._allow_mock = _allow_mock
        self._lock = threading.Lock()

        # Ensure the data directory exists
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

        self._init_db()

        # Load weights from DB (fall back to defaults then supplied overrides)
        self._weights: Dict[str, float] = dict(_DEFAULT_WEIGHTS)
        self._weights.update(self._load_weights_from_db())
        if weights:
            self._weights.update(weights)

        # Lazy-init real council (may not be available in test/air-gap environments)
        self._real_council: Optional[Any] = None
        # PERF: cache DecisionMemoryStore so we don't open a new sqlite3
        # connection on every deliberate() call (was one new connection per verdict).
        self._decision_memory_store: Optional[Any] = None

        logger.info(
            "EnhancedLLMCouncil initialized: db=%s, threshold=%.2f, allow_mock=%s",
            db_path,
            escalation_threshold,
            _allow_mock,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def deliberate(self, finding: Dict[str, Any], question: str) -> CouncilVerdict:
        """Run full council deliberation with confidence scoring.

        Steps:
        1. Each model votes: TRUE_POSITIVE / FALSE_POSITIVE / NEEDS_REVIEW
        2. Calculate weighted agreement percentage
        3. Track dissenting models and their reasoning
        4. Compute confidence score (0.0-1.0) based on agreement + model weights
        5. Auto-escalate to Opus if confidence < threshold
        6. Store verdict in TrustGraph Core 4 (Decision Memory)

        Args:
            finding: Security finding dict (title, severity, cve_id, etc.)
            question: Deliberation question (e.g. "Is this a true positive?")

        Returns:
            CouncilVerdict with full deliberation result
        """
        t_start = time.perf_counter()
        verdict_id = str(uuid.uuid4())

        # Collect votes from all models
        raw_votes, vote_reasoning = self._collect_votes(finding, question)

        # Score the votes
        votes, agreement_pct, confidence, dissenting = self._score_votes(raw_votes)

        # Determine raw verdict from majority
        majority_verdict = self._majority_label(votes)
        escalated = False
        tg_entity_id: Optional[str] = None

        # Auto-escalate if confidence too low
        if confidence < self._escalation_threshold:
            escalated = True
            majority_verdict, confidence, opus_reasoning = self._escalate_to_opus(
                finding, question, votes, vote_reasoning
            )
            reasoning = opus_reasoning
        else:
            reasoning = self._synthesize_reasoning(votes, vote_reasoning, majority_verdict)

        final_verdict: VerdictLabel = "ESCALATED" if escalated else majority_verdict  # type: ignore[assignment]

        elapsed_ms = int((time.perf_counter() - t_start) * 1000)

        verdict = CouncilVerdict(
            verdict_id=verdict_id,
            verdict=final_verdict,
            confidence=confidence,
            votes=votes,
            agreement_pct=agreement_pct,
            dissenting_models=dissenting,
            reasoning=reasoning,
            escalated_to_opus=escalated,
            processing_time_ms=elapsed_ms,
            trustgraph_entity_id=tg_entity_id,
        )

        # Persist to SQLite
        self._store_verdict(verdict, finding, question)

        # Attempt TrustGraph storage (non-fatal if unavailable)
        tg_id = self._store_in_trustgraph(verdict, finding)
        if tg_id:
            verdict.trustgraph_entity_id = tg_id
            self._update_tg_entity(verdict_id, tg_id)

        logger.info(
            "Council verdict: %s (confidence=%.2f, agreement=%.0f%%, escalated=%s, %dms)",
            final_verdict,
            confidence,
            agreement_pct * 100,
            escalated,
            elapsed_ms,
        )

        return verdict

    def track_accuracy(self, verdict_id: str, actual_outcome: str) -> None:
        """Feed actual outcome back to calibrate model weights.

        If a model's prediction matches the actual outcome, its weight increases.
        If wrong, weight decreases. Weights are persisted to SQLite.

        Args:
            verdict_id: ID returned in CouncilVerdict
            actual_outcome: Ground-truth label (e.g. "TRUE_POSITIVE", "FALSE_POSITIVE")
        """
        votes = self._load_votes_for_verdict(verdict_id)
        if not votes:
            logger.warning("track_accuracy: verdict %s not found", verdict_id)
            return

        outcome_id = str(uuid.uuid4())
        with self._get_conn() as conn:
            conn.execute(
                "INSERT INTO verdict_outcomes VALUES (?, ?, ?, ?)",
                (outcome_id, verdict_id, actual_outcome, _now_iso()),
            )
            conn.commit()

        with self._lock:
            for model_name, vote in votes.items():
                correct = vote == actual_outcome
                self._update_model_weight(model_name, correct)

        logger.info(
            "Accuracy tracked for verdict %s: outcome=%s", verdict_id, actual_outcome
        )

    def get_calibration_report(self, window_days: int = 30) -> CalibrationReport:
        """Return accuracy metrics per model over the last N days.

        Args:
            window_days: Rolling window in days (default 30)

        Returns:
            CalibrationReport with per-model accuracy and current weights
        """
        cutoff = (
            datetime.now(timezone.utc) - timedelta(days=window_days)
        ).isoformat()

        with self._get_conn() as conn:
            total_verdicts = conn.execute(
                "SELECT COUNT(*) FROM enhanced_verdicts WHERE created_at >= ?",
                (cutoff,),
            ).fetchone()[0]

            total_with_outcomes = conn.execute(
                """
                SELECT COUNT(DISTINCT vo.verdict_id)
                FROM verdict_outcomes vo
                JOIN enhanced_verdicts ev ON ev.verdict_id = vo.verdict_id
                WHERE ev.created_at >= ?
                """,
                (cutoff,),
            ).fetchone()[0]

            weight_rows = conn.execute(
                "SELECT model_name, weight, total_preds, correct_preds, updated_at "
                "FROM model_weights"
            ).fetchall()

        models: List[ModelCalibration] = []
        total_correct = 0
        total_preds = 0

        for model_name, weight, total_p, correct_p, updated_at in weight_rows:
            accuracy = correct_p / total_p if total_p > 0 else 0.0
            models.append(
                ModelCalibration(
                    model_name=model_name,
                    total_predictions=total_p,
                    correct_predictions=correct_p,
                    current_weight=weight,
                    accuracy=accuracy,
                    last_updated=updated_at,
                )
            )
            total_correct += correct_p
            total_preds += total_p

        # Include models that exist in weights but have no DB row yet
        for model_name, weight in self._weights.items():
            if not any(m.model_name == model_name for m in models):
                models.append(
                    ModelCalibration(
                        model_name=model_name,
                        total_predictions=0,
                        correct_predictions=0,
                        current_weight=weight,
                        accuracy=0.0,
                        last_updated="never",
                    )
                )

        overall_accuracy = total_correct / total_preds if total_preds > 0 else 0.0

        return CalibrationReport(
            generated_at=_now_iso(),
            window_days=window_days,
            models=models,
            total_verdicts=total_verdicts,
            total_with_outcomes=total_with_outcomes,
            overall_accuracy=overall_accuracy,
        )

    def get_recent_verdicts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return the last N verdicts with accuracy info where available.

        Args:
            limit: Max number of verdicts to return

        Returns:
            List of verdict dicts (most recent first)
        """
        with self._get_conn() as conn:
            rows = conn.execute(
                """
                SELECT
                    ev.verdict_id,
                    ev.verdict,
                    ev.confidence,
                    ev.agreement_pct,
                    ev.escalated,
                    ev.processing_ms,
                    ev.created_at,
                    vo.actual_outcome
                FROM enhanced_verdicts ev
                LEFT JOIN verdict_outcomes vo ON vo.verdict_id = ev.verdict_id
                ORDER BY ev.created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        return [
            {
                "verdict_id": r[0],
                "verdict": r[1],
                "confidence": round(r[2], 4),
                "agreement_pct": round(r[3], 4),
                "escalated": bool(r[4]),
                "processing_ms": r[5],
                "created_at": r[6],
                "actual_outcome": r[7],
                "accurate": (r[1] == r[7]) if r[7] else None,
            }
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Voting & scoring internals
    # ------------------------------------------------------------------

    def _collect_votes(
        self,
        finding: Dict[str, Any],
        question: str,
    ) -> tuple[Dict[str, str], Dict[str, str]]:
        """Collect a vote from each configured model.

        Decision tree:
        A. _allow_mock=True → deterministic offline mock votes (unit-test
           opt-in only, clearly labelled with _TEST_MOCK_PREFIX). Short-circuits
           before any network call. Never set True in production.
        B. _allow_mock=False + OPENROUTER_API_KEY set → LLMCouncil real fan-out
           to 5 models via OpenRouter. Returns real votes.
        C. _allow_mock=False + no key / all providers failed → honest
           NOT_CONFIGURED vote so callers get NEEDS_REVIEW/ESCALATED rather
           than fabricated consensus.

        Returns:
            Tuple of (votes dict, reasoning dict) keyed by model name.
        """
        # Path A (mock — offline, deterministic): explicit test opt-in.
        # Short-circuits before any network call so unit tests are fast and
        # hermetic. Never set _allow_mock=True in production.
        if self._allow_mock:
            votes: Dict[str, str] = {}
            reasoning: Dict[str, str] = {}
            for model_name in self._weights:
                if model_name == "claude_opus":
                    continue  # Opus is escalation-only
                vote = self._mock_vote(finding, model_name)
                votes[model_name] = vote
                reasoning[model_name] = (
                    f"{_TEST_MOCK_PREFIX} {model_name} assessed finding as {vote} "
                    f"based on severity and context (test mock — not real consensus)."
                )
            return votes, reasoning

        # Path B (real): OPENROUTER_API_KEY present → LLMCouncil fan-out.
        real_votes, real_reasoning = self._try_real_council_votes(finding, question)
        if real_votes:
            return real_votes, real_reasoning

        # Path C (honest unavailable): key absent or all providers failed.
        # Return a single NOT_CONFIGURED vote so the caller gets an honest
        # NEEDS_REVIEW/ESCALATED verdict, never a fabricated consensus.
        logger.info(
            "EnhancedLLMCouncil: no LLM providers reachable and _allow_mock=False; "
            "returning NOT_CONFIGURED result (set OPENROUTER_API_KEY for real votes)"
        )
        not_configured_vote = "NEEDS_REVIEW"
        not_configured_reason = (
            f"{_NOT_CONFIGURED_PREFIX} Council not configured — "
            "OPENROUTER_API_KEY is absent or all providers unreachable. "
            "Set OPENROUTER_API_KEY to enable real consensus voting."
        )
        return (
            {"council": not_configured_vote},
            {"council": not_configured_reason},
        )

    def _try_real_council_votes(
        self,
        finding: Dict[str, Any],
        question: str,
    ) -> tuple[Dict[str, str], Dict[str, str]]:
        """Attempt to get votes from the real LLM council (LLMCouncil / OpenRouter).

        Routes to ``core.llm_council_real.LLMCouncil`` — the proven 5-model
        OpenRouter fan-out already used by /council/convene.  Falls back to
        empty dicts (not mock votes) if the key is absent or a network error
        occurs so the caller can apply the correct honest fallback.

        Vote label mapping (LLMCouncil → EnhancedLLMCouncil):
            approve   → TRUE_POSITIVE
            reject    → FALSE_POSITIVE
            escalate  → NEEDS_REVIEW

        Returns:
            (votes, reasoning) dicts keyed by model slug, or ({}, {}) if
            the real council is unavailable.
        """
        # Fast-path: skip the import if key is definitely absent (avoids
        # spinning up httpx / sqlite inside LLMCouncil.__init__).
        or_key = os.environ.get("OPENROUTER_API_KEY", "").strip()
        if not or_key:
            logger.debug("_try_real_council_votes: OPENROUTER_API_KEY not set, skipping")
            return {}, {}

        try:
            from core.llm_council_real import CouncilNotConfiguredError, LLMCouncil
        except ImportError as exc:
            logger.debug("_try_real_council_votes: import failed: %s", exc)
            return {}, {}

        try:
            council = LLMCouncil()
        except CouncilNotConfiguredError as exc:
            logger.debug("_try_real_council_votes: council not configured: %s", exc)
            return {}, {}
        except Exception as exc:
            logger.debug("_try_real_council_votes: council init failed: %s", exc)
            return {}, {}

        prompt = (
            f"Security finding deliberation.\n"
            f"Question: {question}\n"
            f"Finding: {json.dumps(finding, default=str)[:500]}\n\n"
            f"Respond with one of: approve (this is a real security issue — TRUE POSITIVE), "
            f"reject (this is a false alarm — FALSE POSITIVE), or "
            f"escalate (needs human review / ambiguous)."
        )

        try:
            # LLMCouncil.convene is async; run it without blocking an existing
            # event loop.  In FastAPI context there may be a running loop, so
            # we use a dedicated thread to avoid "cannot run nested event loop".
            import concurrent.futures as _cf

            result: Dict[str, Any] = {}

            def _run() -> None:
                coro = council.convene(prompt, finding)
                # This runs in a dedicated worker thread (no running loop), so
                # asyncio.run is safe here. Use the standard loop-detection guard
                # anyway for defense-in-depth and to satisfy the no-unsafe-
                # asyncio.run lockdown.
                try:
                    asyncio.get_running_loop()
                    loop = asyncio.new_event_loop()
                    try:
                        res = loop.run_until_complete(coro)
                    finally:
                        loop.close()
                except RuntimeError:
                    res = asyncio.run(coro)
                result.update(res)

            with _cf.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(_run)
                future.result(timeout=40)  # hard cap: 5 models × 30s + buffer

        except Exception as exc:
            logger.warning(
                "_try_real_council_votes: council.convene failed (%s: %s); "
                "falling back to NOT_CONFIGURED path",
                type(exc).__name__,
                exc,
            )
            return {}, {}

        # Map individual votes from LLMCouncil result to TP/FP/NR labels.
        # ``individual_votes`` is a list of {model, vote, reasoning, confidence, latency_ms}.
        individual_votes: List[Dict[str, Any]] = result.get("individual_votes", [])
        if not individual_votes:
            logger.debug("_try_real_council_votes: no individual_votes in result")
            return {}, {}

        _label_map = {
            "approve": "TRUE_POSITIVE",
            "reject": "FALSE_POSITIVE",
            "escalate": "NEEDS_REVIEW",
        }

        votes: Dict[str, str] = {}
        reasoning_out: Dict[str, str] = {}
        for entry in individual_votes:
            model_slug = str(entry.get("model", "unknown")).replace("/", "_").replace(":", "_")
            raw_vote = str(entry.get("vote", "escalate")).lower().strip()
            mapped_vote = _label_map.get(raw_vote, "NEEDS_REVIEW")
            votes[model_slug] = mapped_vote
            reasoning_out[model_slug] = entry.get("reasoning", "") or ""

        logger.info(
            "_try_real_council_votes: got %d real votes from LLMCouncil "
            "(overall verdict=%s, escalated=%s)",
            len(votes),
            result.get("verdict"),
            result.get("escalated"),
        )
        return votes, reasoning_out

    def _normalize_vote(self, raw: str) -> str:
        """Map arbitrary LLM action strings to TP/FP/NEEDS_REVIEW."""
        raw_upper = (raw or "").upper().strip()
        if raw_upper in ("TRUE_POSITIVE", "TP", "BLOCK", "REMEDIATE_CRITICAL", "REMEDIATE_HIGH"):
            return "TRUE_POSITIVE"
        if raw_upper in ("FALSE_POSITIVE", "FP", "ALLOW", "FALSE_POS"):
            return "FALSE_POSITIVE"
        return "NEEDS_REVIEW"

    def _mock_vote(self, finding: Dict[str, Any], model_name: str) -> str:
        """Deterministic mock vote based on finding severity.

        ONLY reachable when ``_allow_mock=True`` is explicitly passed to
        ``__init__``.  This path is reserved for unit tests.  It is NEVER
        reached on the default production path (``_allow_mock=False``).
        Votes produced here are labelled with ``_TEST_MOCK_PREFIX`` in the
        reasoning string so they can never be mistaken for real consensus.
        """
        severity = str(finding.get("severity", "medium")).lower()
        risk_score = float(finding.get("risk_score", 0.5))

        if severity in ("critical", "high") or risk_score >= 0.8:
            return "TRUE_POSITIVE"
        if risk_score < 0.3:
            return "FALSE_POSITIVE"
        # Introduce per-model variation for realistic dissent simulation
        if model_name == "gemma4" and risk_score < 0.6:
            return "NEEDS_REVIEW"
        return "TRUE_POSITIVE"

    def _score_votes(
        self, votes: Dict[str, str]
    ) -> tuple[Dict[str, str], float, float, List[str]]:
        """Calculate weighted agreement, confidence, and dissenting models.

        Args:
            votes: model_name -> vote_label

        Returns:
            Tuple of (votes, agreement_pct, confidence, dissenting_models)
        """
        if not votes:
            return {}, 0.0, 0.0, []

        # Weighted tally
        tally: Dict[str, float] = {}
        total_weight = 0.0
        for model_name, vote in votes.items():
            w = self._weights.get(model_name, 1.0)
            tally[vote] = tally.get(vote, 0.0) + w
            total_weight += w

        if total_weight == 0:
            return votes, 0.0, 0.0, []

        winning_vote = max(tally, key=tally.__getitem__)
        winning_weight = tally[winning_vote]

        agreement_pct = winning_weight / total_weight
        # Confidence: agreement_pct weighted by fraction of models that voted
        # (penalise if only 1 model responded)
        model_count = len(votes)
        participation_factor = min(model_count / 3.0, 1.0)
        confidence = agreement_pct * participation_factor

        dissenting = [m for m, v in votes.items() if v != winning_vote]

        return votes, agreement_pct, confidence, dissenting

    def _majority_label(self, votes: Dict[str, str]) -> VoteLabel:
        """Return the majority vote label."""
        if not votes:
            return "NEEDS_REVIEW"
        tally: Dict[str, float] = {}
        for model_name, vote in votes.items():
            w = self._weights.get(model_name, 1.0)
            tally[vote] = tally.get(vote, 0.0) + w
        return max(tally, key=tally.__getitem__)  # type: ignore[return-value]

    def _synthesize_reasoning(
        self,
        votes: Dict[str, str],
        vote_reasoning: Dict[str, str],
        majority_verdict: str,
    ) -> str:
        """Build a concise synthesized reasoning string."""
        agreeing = [m for m, v in votes.items() if v == majority_verdict]
        dissenting = [m for m, v in votes.items() if v != majority_verdict]

        lines = [f"Majority verdict: {majority_verdict}"]
        lines.append(f"Agreement: {', '.join(agreeing)}")
        if dissenting:
            lines.append(f"Dissent: {', '.join(dissenting)}")
        # Include first reasoning snippet
        for model in agreeing[:1]:
            snippet = vote_reasoning.get(model, "")[:200]
            if snippet:
                lines.append(f"Key reasoning ({model}): {snippet}")
        return " | ".join(lines)

    def _escalate_to_opus(
        self,
        finding: Dict[str, Any],
        question: str,
        votes: Dict[str, str],
        vote_reasoning: Dict[str, str],
    ) -> tuple[VoteLabel, float, str]:
        """Escalate to Claude Opus when confidence is below threshold.

        Returns:
            Tuple of (verdict_label, confidence, reasoning)
        """
        logger.info("Escalating to Opus: confidence below %.2f", self._escalation_threshold)

        try:
            from core.llm_providers import AnthropicMessagesProvider

            opus = AnthropicMessagesProvider(
                "claude-opus",
                model=os.environ.get(
                    "FIXOPS_ANTHROPIC_MODEL", "claude-opus-4-1-20250805"
                ),
            )
            if not opus.api_key:
                raise RuntimeError("Anthropic API key not configured")

            council_summary = "\n".join(
                f"  {m}: {v} — {vote_reasoning.get(m, '')[:100]}"
                for m, v in votes.items()
            )
            prompt = (
                f"OPUS ESCALATION — Low confidence council decision\n\n"
                f"Question: {question}\n"
                f"Finding: {json.dumps(finding, default=str)[:500]}\n\n"
                f"Council votes (low agreement):\n{council_summary}\n\n"
                f"Provide final verdict as JSON:\n"
                f"  vote: TRUE_POSITIVE | FALSE_POSITIVE | NEEDS_REVIEW\n"
                f"  confidence: 0.0-1.0\n"
                f"  reasoning: detailed explanation"
            )

            resp = opus.analyse(
                prompt=prompt,
                context=finding,
                default_action="NEEDS_REVIEW",
                default_confidence=0.75,
                default_reasoning="Opus escalation fallback",
            )

            vote = self._normalize_vote(resp.recommended_action)
            reasoning = f"Opus CTO escalation: {resp.reasoning or 'No reasoning provided'}"
            return vote, resp.confidence, reasoning  # type: ignore[return-value]

        except Exception as exc:
            logger.warning("Opus escalation failed (%s); falling back to NEEDS_REVIEW", exc)
            majority = self._majority_label(votes) if votes else "NEEDS_REVIEW"
            return majority, 0.65, f"Escalation failed ({type(exc).__name__}); conservative fallback"  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Weight calibration
    # ------------------------------------------------------------------

    def _update_model_weight(self, model_name: str, correct: bool) -> None:
        """Adjust model weight based on prediction accuracy.

        Correct prediction → weight * 1.05 (capped at 2.0)
        Incorrect prediction → weight * 0.95 (floor at 0.1)
        """
        current = self._weights.get(model_name, 1.0)
        if correct:
            new_weight = min(current * 1.05, 2.0)
        else:
            new_weight = max(current * 0.95, 0.1)

        self._weights[model_name] = new_weight

        now = _now_iso()
        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO model_weights (model_name, weight, total_preds, correct_preds, updated_at)
                VALUES (?, ?, 1, ?, ?)
                ON CONFLICT(model_name) DO UPDATE SET
                    weight = excluded.weight,
                    total_preds = total_preds + 1,
                    correct_preds = correct_preds + ?,
                    updated_at = excluded.updated_at
                """,
                (
                    model_name,
                    new_weight,
                    1 if correct else 0,
                    now,
                    1 if correct else 0,
                ),
            )
            conn.commit()

        logger.debug(
            "Weight updated: %s %.3f -> %.3f (correct=%s)",
            model_name,
            current,
            new_weight,
            correct,
        )

    # ------------------------------------------------------------------
    # TrustGraph integration (non-fatal)
    # ------------------------------------------------------------------

    def _store_in_trustgraph(
        self, verdict: CouncilVerdict, finding: Dict[str, Any]
    ) -> Optional[str]:
        """Store verdict in TrustGraph Core 4 (Decision Memory).

        Returns entity ID if successful, None otherwise (non-fatal).
        """
        try:
            from core.decision_memory import DecisionMemoryStore, DecisionRecord

            # PERF: reuse the cached store (one DB connection for the lifetime
            # of this EnhancedLLMCouncil instance) instead of opening a new
            # sqlite3 connection on every call.
            if self._decision_memory_store is None:
                db_path = os.environ.get(
                    "FIXOPS_DECISION_MEMORY_DB", "data/decision_memory.db"
                )
                self._decision_memory_store = DecisionMemoryStore(db_path=db_path)
            store = self._decision_memory_store
            record = DecisionRecord(
                finding_id=finding.get("id", verdict.verdict_id),
                finding_hash=verdict.verdict_id,
                decision_type="enhanced_council",
                action=verdict.verdict,
                confidence=verdict.confidence,
                reasoning=verdict.reasoning,
                council_session_id=verdict.verdict_id,
                org_id=os.environ.get("FIXOPS_ORG_ID", "default"),
                metadata={
                    "agreement_pct": verdict.agreement_pct,
                    "dissenting_models": verdict.dissenting_models,
                    "escalated": verdict.escalated_to_opus,
                    "votes": verdict.votes,
                },
            )
            record_id = store.record(record)
            return record_id
        except Exception as exc:
            logger.debug("TrustGraph storage skipped: %s", exc)
            return None

    # ------------------------------------------------------------------
    # SQLite persistence
    # ------------------------------------------------------------------

    def _get_conn(self) -> sqlite3.Connection:
        """Return a cached per-thread SQLite connection.

        PERF: Previously opened a new sqlite3.connect() for every operation
        (_store_verdict, _update_tg_entity, _load_votes_for_verdict, etc.) —
        each call paid the file-open + schema-check overhead (~0.5-2ms on cold
        disk). Now we cache one connection per thread (thread-local storage) so
        the connection stays warm for the lifetime of the thread that deliberates.

        Thread-safety: sqlite3 connections are NOT safe to share across threads,
        so we store one per thread in self._local. This is safe because
        ThreadPoolExecutor reuses threads for multiple tasks.
        """
        if not hasattr(self, "_local"):
            self._local = threading.local()
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self._db_path, timeout=10, check_same_thread=False)
            self._local.conn = conn
        return conn

    def _init_db(self) -> None:
        """Create tables if they don't exist."""
        with self._get_conn() as conn:
            conn.execute(_SCHEMA_VERDICTS)
            conn.execute(_SCHEMA_OUTCOMES)
            conn.execute(_SCHEMA_WEIGHTS)
            conn.commit()

    def _store_verdict(
        self,
        verdict: CouncilVerdict,
        finding: Dict[str, Any],
        question: str,
    ) -> None:
        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO enhanced_verdicts
                (verdict_id, finding_json, question, votes_json, verdict,
                 confidence, agreement_pct, dissenting_json, reasoning,
                 escalated, processing_ms, tg_entity_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    verdict.verdict_id,
                    json.dumps(finding, default=str)[:4096],
                    question[:1024],
                    json.dumps(verdict.votes),
                    verdict.verdict,
                    verdict.confidence,
                    verdict.agreement_pct,
                    json.dumps(verdict.dissenting_models),
                    verdict.reasoning[:2048],
                    int(verdict.escalated_to_opus),
                    verdict.processing_time_ms,
                    verdict.trustgraph_entity_id,
                    _now_iso(),
                ),
            )
            conn.commit()

    def _update_tg_entity(self, verdict_id: str, tg_entity_id: str) -> None:
        with self._get_conn() as conn:
            conn.execute(
                "UPDATE enhanced_verdicts SET tg_entity_id = ? WHERE verdict_id = ?",
                (tg_entity_id, verdict_id),
            )
            conn.commit()

    def _load_weights_from_db(self) -> Dict[str, float]:
        """Load persisted weights from SQLite."""
        try:
            with self._get_conn() as conn:
                rows = conn.execute(
                    "SELECT model_name, weight FROM model_weights"
                ).fetchall()
            return {row[0]: row[1] for row in rows}
        except Exception:
            return {}

    def _load_votes_for_verdict(self, verdict_id: str) -> Dict[str, str]:
        """Load votes dict for a given verdict_id."""
        try:
            with self._get_conn() as conn:
                row = conn.execute(
                    "SELECT votes_json FROM enhanced_verdicts WHERE verdict_id = ?",
                    (verdict_id,),
                ).fetchone()
            if row:
                return json.loads(row[0])
        except Exception as exc:
            logger.warning("Could not load votes for %s: %s", verdict_id, exc)
        return {}
