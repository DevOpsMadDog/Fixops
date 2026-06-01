"""LLM Distill Router — student-first triage with council fall-through.

Phase-2 inference layer for the LLM training roadmap. When a distilled student
adapter is available (set ``FIXOPS_DISTILL_ADAPTER=path/to/adapter`` in env),
this router will:

1. Run **routine triage** through the local student model (typically Qwen 7B
   + LoRA adapter served via vLLM or HF transformers locally).
2. Inspect student confidence. If ``confidence >= threshold`` (default 0.7),
   accept the student verdict and return it.
3. If ``confidence < threshold``, **fall through** to the full
   ``LLMCouncilEngine`` (the existing Phase-1 production stack).
4. Persist every fall-through to ``data/learning_signals.db`` as a new DPO
   pair (chosen=council/Opus action, rejected=student action) — feeding the
   continuous-improvement loop documented in roadmap §1.

The router is intentionally fail-soft: if the adapter cannot be loaded
(missing libs, bad path, wrong architecture), it logs a warning and
permanently delegates to the council. Production stays online.

Public surface:

    >>> router = LLMDistillRouter()        # auto-detects FIXOPS_DISTILL_ADAPTER
    >>> verdict = router.triage(finding, context)
    >>> verdict.metadata["routed_via"]     # "student" | "council" | "council_after_student"

The ``routed_via`` annotation lets dashboards show student-vs-council mix and
calculate the cost saving promised in the Phase-2 deck.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

logger = logging.getLogger(__name__)

# Env vars
ENV_ADAPTER_PATH = "FIXOPS_DISTILL_ADAPTER"
ENV_BASE_MODEL = "FIXOPS_DISTILL_BASE_MODEL"
ENV_CONFIDENCE_THRESHOLD = "FIXOPS_DISTILL_CONFIDENCE"
ENV_SIGNALS_DB = "FIXOPS_LEARNING_SIGNALS_DB"

DEFAULT_BASE_MODEL = "Qwen/Qwen2.5-7B-Instruct"
DEFAULT_CONFIDENCE_THRESHOLD = 0.70
DEFAULT_SIGNALS_DB = "data/learning_signals.db"

VALID_ACTIONS = (
    "remediate_critical",
    "remediate_high",
    "accept_risk",
    "defer",
    "investigate",
    "false_positive",
    "review",
)


__all__ = [
    "DistillVerdict",
    "DistillStudent",
    "LLMDistillRouter",
]


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------


@dataclass
class DistillVerdict:
    """Routing-aware verdict.

    Mirrors the surface of ``CouncilVerdict`` enough that downstream code can
    treat both interchangeably, but adds ``routed_via`` and ``student_*``
    fields so observability can split costs between student and council.
    """

    action: str
    confidence: float
    reasoning: str
    routed_via: str  # "student" | "council" | "council_after_student"
    student_action: Optional[str] = None
    student_confidence: Optional[float] = None
    student_latency_ms: Optional[float] = None
    council_latency_ms: Optional[float] = None
    cost_usd: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "confidence": round(self.confidence, 3),
            "reasoning": self.reasoning,
            "routed_via": self.routed_via,
            "student_action": self.student_action,
            "student_confidence": (
                round(self.student_confidence, 3) if self.student_confidence is not None else None
            ),
            "student_latency_ms": self.student_latency_ms,
            "council_latency_ms": self.council_latency_ms,
            "cost_usd": round(self.cost_usd, 6),
            "metadata": self.metadata,
        }


# ---------------------------------------------------------------------------
# Student wrapper
# ---------------------------------------------------------------------------


class DistillStudent:
    """Loads a LoRA adapter on top of a base causal LM for student inference.

    Lazy-loads on first ``analyse()``. If transformers/peft are missing or the
    adapter path is invalid, ``available`` returns False and the router skips
    student routing entirely.
    """

    def __init__(
        self,
        adapter_path: str,
        base_model: str = DEFAULT_BASE_MODEL,
        max_new_tokens: int = 256,
    ) -> None:
        self.adapter_path = adapter_path
        self.base_model = base_model
        self.max_new_tokens = max_new_tokens
        self._loaded = False
        self._load_error: Optional[str] = None
        self._model: Any = None
        self._tokenizer: Any = None

    @property
    def available(self) -> bool:
        if self._load_error:
            return False
        return self._loaded or Path(self.adapter_path).exists()

    def load(self) -> bool:
        if self._loaded or self._load_error:
            return self._loaded
        try:
            import torch  # type: ignore
            from peft import PeftModel  # type: ignore
            from transformers import AutoModelForCausalLM, AutoTokenizer  # type: ignore
        except ImportError as exc:
            self._load_error = f"transformers/peft not installed: {exc}"
            logger.warning("DistillStudent unavailable — %s", self._load_error)
            return False

        if not Path(self.adapter_path).exists():
            self._load_error = f"adapter path not found: {self.adapter_path}"
            logger.warning("DistillStudent unavailable — %s", self._load_error)
            return False

        try:
            logger.info("Loading distill student: base=%s adapter=%s",
                        self.base_model, self.adapter_path)
            tok = AutoTokenizer.from_pretrained(self.base_model, use_fast=True)
            if tok.pad_token is None:
                tok.pad_token = tok.eos_token
            base = AutoModelForCausalLM.from_pretrained(
                self.base_model,
                torch_dtype=torch.float16,
            )
            model = PeftModel.from_pretrained(base, self.adapter_path)
            model.eval()
            self._model = model
            self._tokenizer = tok
            self._loaded = True
            return True
        except (RuntimeError, OSError, ValueError) as exc:
            self._load_error = f"failed to load student: {exc}"
            logger.exception("DistillStudent load failed")
            return False

    def analyse(self, prompt: str) -> Dict[str, Any]:
        """Run the student. Returns dict with action/confidence/reasoning/raw."""
        if not self.load():
            return {
                "action": "review",
                "confidence": 0.0,
                "reasoning": f"student unavailable: {self._load_error}",
                "raw": "",
            }

        import torch  # type: ignore  # guaranteed available at this point

        t0 = time.perf_counter()
        inputs = self._tokenizer(prompt, return_tensors="pt", truncation=True, max_length=2048)
        with torch.no_grad():
            out = self._model.generate(
                **inputs,
                max_new_tokens=self.max_new_tokens,
                do_sample=False,
                temperature=1.0,
                pad_token_id=self._tokenizer.pad_token_id,
            )
        text = self._tokenizer.decode(out[0][inputs["input_ids"].shape[1] :], skip_special_tokens=True)
        latency = (time.perf_counter() - t0) * 1000

        action, confidence = _parse_student_output(text)
        return {
            "action": action,
            "confidence": confidence,
            "reasoning": text.strip(),
            "raw": text,
            "latency_ms": round(latency, 2),
        }


def _parse_student_output(text: str) -> tuple[str, float]:
    """Parse "Recommended action: X\\nConfidence: 0.YY" out of student text.

    Falls back to ``("review", 0.0)`` when the structure is unrecognisable so
    that the router will fall through to the council.
    """
    action = "review"
    confidence = 0.0
    for line in text.splitlines():
        line = line.strip()
        low = line.lower()
        if low.startswith("recommended action:") or low.startswith("action:"):
            value = line.split(":", 1)[1].strip().lower().rstrip(".,;")
            value = value.split()[0] if value else ""
            if value in VALID_ACTIONS:
                action = value
        elif low.startswith("confidence:"):
            try:
                value = line.split(":", 1)[1].strip().rstrip("%").rstrip(".,;")
                confidence = float(value)
                if confidence > 1.0:  # percent form
                    confidence = confidence / 100.0
                confidence = max(0.0, min(1.0, confidence))
            except ValueError:
                pass
    return action, confidence


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------


class LLMDistillRouter:
    """Route triage to student first, council second."""

    def __init__(
        self,
        *,
        adapter_path: Optional[str] = None,
        base_model: Optional[str] = None,
        confidence_threshold: Optional[float] = None,
        council: Any = None,  # CouncilFactory result; injected for testability
        signals_db_path: Optional[str] = None,
    ) -> None:
        self.adapter_path = adapter_path or os.environ.get(ENV_ADAPTER_PATH)
        self.base_model = base_model or os.environ.get(ENV_BASE_MODEL, DEFAULT_BASE_MODEL)
        try:
            self.confidence_threshold = float(
                confidence_threshold
                if confidence_threshold is not None
                else os.environ.get(ENV_CONFIDENCE_THRESHOLD, DEFAULT_CONFIDENCE_THRESHOLD)
            )
        except (TypeError, ValueError):
            self.confidence_threshold = DEFAULT_CONFIDENCE_THRESHOLD
        self.signals_db_path = (
            signals_db_path
            or os.environ.get(ENV_SIGNALS_DB)
            or DEFAULT_SIGNALS_DB
        )
        self._council = council
        self._student: Optional[DistillStudent] = None
        if self.adapter_path:
            self._student = DistillStudent(self.adapter_path, base_model=self.base_model)

    # -- public surface ----------------------------------------------------

    @property
    def student_available(self) -> bool:
        return self._student is not None and self._student.available

    def triage(
        self,
        finding: Mapping[str, Any],
        context: Mapping[str, Any],
        *,
        rag_context: Optional[Mapping[str, Any]] = None,
    ) -> DistillVerdict:
        """Triage a finding. Student first, council on low confidence."""
        prompt = self._build_prompt(finding, context, rag_context or {})

        # Student attempt
        student_action: Optional[str] = None
        student_conf: Optional[float] = None
        student_latency: Optional[float] = None
        student_reasoning: Optional[str] = None

        if self.student_available:
            try:
                s = self._student.analyse(prompt)  # type: ignore[union-attr]
                student_action = s.get("action")
                student_conf = float(s.get("confidence", 0.0))
                student_latency = s.get("latency_ms")
                student_reasoning = s.get("reasoning")
            except (RuntimeError, ValueError) as exc:
                logger.warning("Student inference failed; falling through: %s", exc)

        # Accept student verdict?
        if student_conf is not None and student_conf >= self.confidence_threshold and student_action:
            verdict = DistillVerdict(
                action=student_action,
                confidence=student_conf,
                reasoning=student_reasoning or "",
                routed_via="student",
                student_action=student_action,
                student_confidence=student_conf,
                student_latency_ms=student_latency,
                metadata={
                    "finding_id": finding.get("id") or finding.get("finding_id"),
                    "threshold": self.confidence_threshold,
                },
            )
            return verdict

        # Fall through to council
        council_verdict, council_latency = self._call_council(finding, context)
        if council_verdict is None:
            # Council unavailable AND student unavailable — degrade gracefully.
            return DistillVerdict(
                action=student_action or "review",
                confidence=student_conf or 0.0,
                reasoning=student_reasoning or "router fallback: no decision engine available",
                routed_via="student" if student_action else "fallback",
                student_action=student_action,
                student_confidence=student_conf,
                student_latency_ms=student_latency,
                council_latency_ms=None,
                metadata={"finding_id": finding.get("id") or finding.get("finding_id")},
            )

        # Capture this fall-through as a new DPO signal — student got
        # over-ruled by council/Opus, so council action is "chosen".
        if student_action and student_action != council_verdict.action:
            try:
                self._persist_dpo_signal(
                    finding=finding,
                    chosen_action=council_verdict.action,
                    rejected_action=student_action,
                    student_confidence=student_conf or 0.0,
                    council_confidence=council_verdict.confidence,
                    council_reasoning=council_verdict.reasoning,
                    rag_context=rag_context or {},
                )
            except (sqlite3.Error, OSError) as exc:
                logger.warning("Failed to persist fall-through DPO signal: %s", exc)

        return DistillVerdict(
            action=council_verdict.action,
            confidence=council_verdict.confidence,
            reasoning=council_verdict.reasoning,
            routed_via="council_after_student" if student_action else "council",
            student_action=student_action,
            student_confidence=student_conf,
            student_latency_ms=student_latency,
            council_latency_ms=council_latency,
            cost_usd=getattr(council_verdict, "cost_usd", 0.0),
            metadata={
                "finding_id": finding.get("id") or finding.get("finding_id"),
                "threshold": self.confidence_threshold,
                "council_escalated": getattr(council_verdict, "escalated", False),
            },
        )

    # -- internals ---------------------------------------------------------

    def _build_prompt(
        self,
        finding: Mapping[str, Any],
        context: Mapping[str, Any],
        rag_context: Mapping[str, Any],
    ) -> str:
        title = finding.get("title", "Unknown finding")
        finding_id = finding.get("id") or finding.get("finding_id", "unknown")
        severity = finding.get("severity", "unknown")
        cve = finding.get("cve_id") or finding.get("cve", "N/A")
        risk_score = finding.get("risk_score", 0.0)
        service = context.get("service_name", "unknown")
        rag_block = ""
        retrieved = rag_context.get("retrieved") if isinstance(rag_context, Mapping) else None
        if isinstance(retrieved, list) and retrieved:
            snippets = []
            for ent in retrieved[:5]:
                if isinstance(ent, dict):
                    snippets.append(
                        f"- [{ent.get('core', '?')}] {ent.get('label', ent.get('id', '?'))}"
                    )
            rag_block = "\n\nRetrieved context:\n" + "\n".join(snippets)
        return (
            f"Finding ID: {finding_id}\n"
            f"Title: {title}\n"
            f"Severity: {severity}\n"
            f"CVE: {cve}\n"
            f"Risk Score: {risk_score}\n"
            f"Service: {service}{rag_block}\n\n"
            "Decide the remediation action and explain your reasoning."
        )

    def _call_council(
        self,
        finding: Mapping[str, Any],
        context: Mapping[str, Any],
    ) -> tuple[Any, Optional[float]]:
        if self._council is None:
            try:
                # Lazy import to keep the module importable in air-gapped envs
                from core.llm_council import CouncilFactory  # type: ignore

                self._council = CouncilFactory().create_security_council()
            except Exception as exc:  # broad: factory may fail for many reasons
                logger.warning("Council unavailable for fall-through: %s", exc)
                return None, None

        t0 = time.perf_counter()
        try:
            verdict = self._council.convene(finding=finding, context=context)
        except Exception as exc:
            logger.warning("Council convene failed: %s", exc)
            return None, None
        return verdict, (time.perf_counter() - t0) * 1000

    def _persist_dpo_signal(
        self,
        *,
        finding: Mapping[str, Any],
        chosen_action: str,
        rejected_action: str,
        student_confidence: float,
        council_confidence: float,
        council_reasoning: str,
        rag_context: Mapping[str, Any],
    ) -> None:
        db_path = Path(self.signals_db_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(db_path))
        try:
            self._ensure_schema(conn)
            now = datetime.now(timezone.utc).isoformat()
            verdict_id = f"v_{uuid.uuid4().hex[:12]}"
            pair_id = f"p_{uuid.uuid4().hex[:12]}"
            finding_id = (
                finding.get("id") or finding.get("finding_id") or f"unknown-{uuid.uuid4().hex[:6]}"
            )
            org_id = finding.get("org_id") or "unknown"

            raw_verdict = json.dumps(
                {
                    "action": chosen_action,
                    "confidence": council_confidence,
                    "escalated": False,
                    "router_source": "distill_router_fallthrough",
                }
            )
            rag_serialized = json.dumps(dict(rag_context)) if isinstance(rag_context, Mapping) else "{}"

            conn.execute(
                "INSERT INTO council_verdicts(verdict_id, finding_id, org_id, rag_context, "
                "council_action, confidence, reasoning, raw_verdict, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (verdict_id, finding_id, org_id, rag_serialized, chosen_action,
                 council_confidence, council_reasoning, raw_verdict, now),
            )
            conn.execute(
                "INSERT INTO feedback_pairs(pair_id, verdict_id, chosen_action, "
                "rejected_action, pair_source, metadata, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    pair_id,
                    verdict_id,
                    chosen_action,
                    rejected_action,
                    "distill_router_fallthrough",
                    json.dumps({"student_confidence": student_confidence}),
                    now,
                ),
            )
            conn.commit()
            logger.info(
                "Captured fall-through DPO signal: chosen=%s rejected=%s student_conf=%.2f",
                chosen_action, rejected_action, student_confidence,
            )
        finally:
            conn.close()

    @staticmethod
    def _ensure_schema(conn: sqlite3.Connection) -> None:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS council_verdicts (
                verdict_id      TEXT PRIMARY KEY,
                finding_id      TEXT NOT NULL,
                org_id          TEXT NOT NULL,
                rag_context     TEXT NOT NULL,
                council_action  TEXT NOT NULL,
                confidence      REAL NOT NULL,
                reasoning       TEXT NOT NULL,
                raw_verdict     TEXT NOT NULL,
                created_at      TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS feedback_pairs (
                pair_id         TEXT PRIMARY KEY,
                verdict_id      TEXT NOT NULL,
                chosen_action   TEXT NOT NULL,
                rejected_action TEXT NOT NULL,
                pair_source     TEXT NOT NULL,
                metadata        TEXT NOT NULL,
                created_at      TEXT NOT NULL,
                FOREIGN KEY (verdict_id) REFERENCES council_verdicts(verdict_id)
            );
            CREATE INDEX IF NOT EXISTS idx_verdicts_finding ON council_verdicts(finding_id);
            CREATE INDEX IF NOT EXISTS idx_pairs_verdict   ON feedback_pairs(verdict_id);
            """
        )
