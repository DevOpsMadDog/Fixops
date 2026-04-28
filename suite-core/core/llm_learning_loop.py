"""LLM Learning Loop — long-running closed-loop subscriber for Phase 1 training.

Wires:

    TrustGraph EventBus  --(finding.created/alert.created/threat.detected)-->
        TrustGraph RAG retriever (KnowledgeStore)  -->
            LLMCouncilEngine.convene()  -->
                learning_signals.db (council_verdicts + feedback_pairs)
                    -->  EventBus.emit("decision.made", verdict)

The skeleton at ``scripts/llm_training_phase1_skeleton.py`` proves the loop on
disk; this module is the *production* version: it subscribes to the in-process
``core.event_bus.EventBus`` (the cross-suite one with rich EventType enum) and
runs every event through the same RAG -> Council -> persistence -> republish
pipeline as the smoke script. The only change is the source of findings:
real org events instead of CLI args.

Designed to be:

* Opt-in via ``FIXOPS_LLM_LEARNING_LOOP=1`` so existing prod isn't surprised.
* Air-gap clean: if council providers have no API keys, the loop falls through
  to ``DeterministicLLMProvider`` exactly like the skeleton does.
* Best-effort: a failed convene/persist for one event NEVER kills the loop.

Public surface:

    start_llm_learning_loop(app=None) -> LLMLearningLoop
    stop_llm_learning_loop() -> None
    get_llm_learning_loop() -> LLMLearningLoop | None

The loop is launched at FastAPI ``startup`` (when wired into ``app.py``) and
torn down at ``shutdown``. There is no explicit polling -- the EventBus pushes
events, so the loop only consumes CPU when an event arrives.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Defaults & env knobs
# ---------------------------------------------------------------------------

_DEFAULT_TG_DB = "data/phase1_trustgraph.db"
_DEFAULT_SIGNALS_DB = "data/learning_signals.db"

# Event types we subscribe to. Strings deliberately match
# ``core.event_bus.EventType`` values so we don't import the enum at module
# import time (keeps the loop importable in non-FastAPI contexts).
_SUBSCRIBED_EVENT_TYPES: tuple[str, ...] = (
    "finding.created",
    "alert.created",
    "threat.detected",
)

_DECISION_EVENT_TYPE = "decision.made"

# Schema MUST match scripts/llm_training_phase1_skeleton.py — same DB.
_LEARNING_SIGNALS_SCHEMA = """
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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_enabled() -> bool:
    """Honour the opt-in env flag. Default OFF to protect existing prod."""
    return os.environ.get("FIXOPS_LLM_LEARNING_LOOP", "0").lower() in ("1", "true", "yes")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _build_council_with_fallback() -> Any:
    """Construct the security council; gracefully fall back to a deterministic
    single-member council if API providers can't be wired (no keys / offline).

    Mirrors the skeleton's ``convene_with_rag()`` fallback so air-gap behaviour
    is identical between smoke script and production loop.
    """
    from core.llm_council import (  # local import keeps module light
        CouncilFactory,
        CouncilMember,
        LLMCouncilEngine,
    )
    from core.llm_providers import DeterministicLLMProvider

    try:
        factory = CouncilFactory()
        return factory.create_security_council()
    except Exception as exc:  # noqa: BLE001 — fallback is the intended behaviour
        logger.warning(
            "llm_learning_loop: CouncilFactory failed (%s) — falling back to "
            "deterministic single-member council.",
            exc,
        )
        det = DeterministicLLMProvider("deterministic-fallback", style="consensus")
        return LLMCouncilEngine(
            members=[
                CouncilMember(
                    provider=det,
                    expertise="vulnerability_assessment",
                    weight=1.0,
                    name="deterministic-fallback",
                )
            ],
            chairman=det,
            escalation_provider=None,
            confidence_threshold=0.0,  # never escalate from the loop
            max_disagreement=99,
        )


def _build_rag_block(retrieved: List[Any]) -> str:
    """Render retrieved entities to a prompt-ready context block.

    Matches ``scripts/llm_training_phase1_skeleton.py:build_rag_context_block``.
    """
    if not retrieved:
        return "[NO PRIOR DECISIONS RETRIEVED — cold-start]"
    lines = ["[PRIOR DECISIONS — TrustGraph Core 4/5]"]
    for ent in retrieved:
        props = getattr(ent, "properties", {}) or {}
        prior_action = props.get("prior_action", "unknown")
        confidence = props.get("prior_confidence", "n/a")
        lines.append(
            f"  - {getattr(ent, 'name', '?')} (action={prior_action}, conf={confidence})"
        )
    return "\n".join(lines)


def _coerce_finding(event_data: Mapping[str, Any]) -> Dict[str, Any]:
    """Normalize an arbitrary EventBus payload into a council-ready finding dict.

    The cross-suite EventBus carries free-form ``data`` payloads. We only need
    the canonical fields the council prompt builder reads.
    """
    cve = (
        event_data.get("cve_id")
        or event_data.get("cve")
        or event_data.get("CVE")
        or "N/A"
    )
    title = (
        event_data.get("title")
        or event_data.get("name")
        or event_data.get("description")
        or f"Finding {event_data.get('finding_id', event_data.get('id', 'unknown'))}"
    )
    severity = event_data.get("severity") or event_data.get("priority") or "medium"
    finding_id = (
        event_data.get("finding_id")
        or event_data.get("alert_id")
        or event_data.get("id")
        or f"f_{uuid.uuid4().hex[:10]}"
    )
    return {
        "finding_id": finding_id,
        "title": title,
        "severity": severity,
        "cve_id": cve,
        "tenant": event_data.get("tenant") or event_data.get("org_id") or "default",
        "context": {
            "service_name": event_data.get("service_name")
            or event_data.get("service")
            or event_data.get("source", "unknown"),
            "asset_criticality": event_data.get("asset_criticality", "medium"),
            "raw_event": {
                k: v
                for k, v in event_data.items()
                if k not in ("password", "secret", "token")
            },
        },
    }


# ---------------------------------------------------------------------------
# The loop
# ---------------------------------------------------------------------------


class LLMLearningLoop:
    """Long-running closed-loop trainer subscribing to TrustGraph events.

    Uses the in-process ``core.event_bus.EventBus`` (rich EventType enum) for
    subscriptions so we get the full Event payload (event_type, source, data,
    org_id, event_id, timestamp). We deliberately do NOT subscribe via the
    ``trustgraph_event_bus`` middleware bus — that one is HTTP-response-driven
    and harder to test. The two buses are bridged in production by other code.
    """

    def __init__(
        self,
        *,
        tg_db_path: Optional[str] = None,
        signals_db_path: Optional[str] = None,
        org_id: str = "default",
    ) -> None:
        self.tg_db_path = tg_db_path or os.environ.get(
            "FIXOPS_LLM_LOOP_TG_DB", _DEFAULT_TG_DB
        )
        self.signals_db_path = signals_db_path or os.environ.get(
            "FIXOPS_LLM_LOOP_SIGNALS_DB", _DEFAULT_SIGNALS_DB
        )
        self.org_id = org_id

        # NOTE: We intentionally do NOT use a Python threading.Lock around
        # SQLite writes. SQLite already serialises writers internally, and a
        # Python lock just adds an extra layer of contention without helping
        # multi-writer concurrency. With WAL mode enabled (see
        # `_init_signals_db`) readers don't block writers, and writers
        # serialise on the SQLite write lock with `PRAGMA busy_timeout`
        # backing off automatically.
        #
        # See: docs/load_test_llm_loop_2026-04-26.md "Bottleneck #2" — the
        # previous `_signals_lock` capped 8-worker throughput at +13% over
        # 1-worker. After this change concurrency=8 should scale ~4-6x.
        self._council = None  # built lazily on first event
        self._knowledge_store = None  # built lazily
        self._retriever = None  # built lazily

        self._running = False
        self._processed = 0
        self._last_error: Optional[str] = None

        # Initialise the signals DB so verdicts/pairs can be written even if
        # no event has fired yet (tests + observability). Also flips the DB
        # to WAL + synchronous=NORMAL for concurrent-writer throughput.
        self._init_signals_db()

    # ------------------------------------------------------------------
    # Public lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Subscribe to the EventBus. Idempotent."""
        if self._running:
            return
        try:
            from core.event_bus import EventType, get_event_bus
        except ImportError as exc:
            logger.error("llm_learning_loop: event bus import failed: %s", exc)
            return

        bus = get_event_bus()
        # Subscribe with EventType where we can; fall back to string for
        # types the enum may not yet declare.
        type_map = {
            "finding.created": getattr(EventType, "FINDING_CREATED", "finding.created"),
            "alert.created": "alert.created",  # not in EventType yet — string OK
            "threat.detected": getattr(EventType, "THREAT_DETECTED", "threat.detected"),
        }
        for raw_type in _SUBSCRIBED_EVENT_TYPES:
            event_type_value = type_map.get(raw_type, raw_type)
            bus.subscribe(event_type_value, self._on_event)
            logger.info("llm_learning_loop: subscribed to %s", raw_type)

        self._running = True
        logger.info(
            "llm_learning_loop: started (tg_db=%s, signals_db=%s)",
            self.tg_db_path,
            self.signals_db_path,
        )

    def stop(self) -> None:
        """Mark the loop as stopped. The EventBus has no unsubscribe API today
        so subscribed handlers stay registered, but ``_on_event`` short-circuits
        when ``_running`` is False.
        """
        self._running = False
        logger.info(
            "llm_learning_loop: stopped (processed=%d, last_error=%s)",
            self._processed,
            self._last_error,
        )

    # ------------------------------------------------------------------
    # Status (used by tests + ops)
    # ------------------------------------------------------------------

    def status(self) -> Dict[str, Any]:
        return {
            "running": self._running,
            "processed_events": self._processed,
            "last_error": self._last_error,
            "tg_db_path": self.tg_db_path,
            "signals_db_path": self.signals_db_path,
            "subscribed_event_types": list(_SUBSCRIBED_EVENT_TYPES),
            "council_built": self._council is not None,
        }

    def signals_summary(self) -> Dict[str, Any]:
        """Return current verdict + pair counts for ops/tests."""
        conn = self._connect_signals()
        try:
            vc = conn.execute("SELECT COUNT(*) FROM council_verdicts").fetchone()[0]
            pc = conn.execute("SELECT COUNT(*) FROM feedback_pairs").fetchone()[0]
        finally:
            conn.close()
        return {
            "verdicts": int(vc),
            "pairs": int(pc),
            "signals_db_path": self.signals_db_path,
        }

    # ------------------------------------------------------------------
    # Event handler (the heart of the loop)
    # ------------------------------------------------------------------

    async def _on_event(self, event: Any) -> None:
        """Subscriber callback — runs council, persists, republishes."""
        if not self._running:
            return

        try:
            event_type = (
                event.event_type.value
                if hasattr(event.event_type, "value")
                else str(event.event_type)
            )
            event_data = getattr(event, "data", {}) or {}
            org_id = getattr(event, "org_id", None) or self.org_id

            finding = _coerce_finding(event_data)

            # Run the heavy work (RAG + council) off the event loop so we never
            # block other subscribers.
            verdict = await asyncio.to_thread(
                self._run_pipeline_blocking, finding, org_id
            )

            verdict_id, dpo_pair_id = await asyncio.to_thread(
                self._persist_blocking,
                finding["finding_id"],
                org_id,
                verdict["rag_block"],
                verdict["raw_verdict"],
                verdict["raw_verdict"].get("action", "unknown"),
            )

            # Republish as decision.made so downstream subscribers (UI feed,
            # audit log, telemetry) see the council outcome.
            await self._republish_decision(
                source_event_type=event_type,
                finding_id=finding["finding_id"],
                org_id=org_id,
                verdict_id=verdict_id,
                council_verdict=verdict["raw_verdict"],
            )

            self._processed += 1
            logger.info(
                "llm_learning_loop: processed event=%s finding=%s verdict_id=%s "
                "action=%s pair_id=%s",
                event_type,
                finding["finding_id"],
                verdict_id,
                verdict["raw_verdict"].get("action"),
                dpo_pair_id or "<none>",
            )
        except Exception as exc:  # noqa: BLE001 — loop must never die
            self._last_error = f"{type(exc).__name__}: {exc}"
            logger.warning(
                "llm_learning_loop: event handling failed: %s", self._last_error
            )

    # ------------------------------------------------------------------
    # Internals (blocking, called via asyncio.to_thread)
    # ------------------------------------------------------------------

    def _run_pipeline_blocking(
        self, finding: Mapping[str, Any], org_id: str
    ) -> Dict[str, Any]:
        """RAG -> Council, returns the rag_block + raw verdict dict."""
        # Lazy-build expensive objects once.
        if self._retriever is None:
            self._build_rag()
        if self._council is None:
            self._council = _build_council_with_fallback()

        # RAG retrieve over Core 4 + Core 5 for THIS org.
        query = f"{finding.get('title', '')} {finding.get('cve_id', '')}".strip()
        try:
            retrieved = self._retriever.retrieve(query=query, top_k=5)
        except Exception as exc:  # noqa: BLE001 — never block on retrieval
            logger.debug("llm_learning_loop: rag retrieve fallback: %s", exc)
            retrieved = []
        rag_block = _build_rag_block(retrieved)

        context = dict(finding.get("context", {}))
        context["rag_context_block"] = rag_block

        try:
            verdict_obj = self._council.convene(finding=finding, context=context)
            raw = (
                verdict_obj.to_dict()
                if hasattr(verdict_obj, "to_dict")
                else dict(verdict_obj)
            )
        except Exception as exc:  # noqa: BLE001 — degrade rather than crash
            logger.warning("llm_learning_loop: council convene failed: %s", exc)
            raw = {
                "action": "investigate",
                "confidence": 0.0,
                "reasoning": f"Council unavailable ({type(exc).__name__})",
                "member_votes": [],
                "escalated": False,
                "cost_usd": 0.0,
                "latency_ms": 0.0,
            }

        return {"rag_block": rag_block, "raw_verdict": raw}

    def _build_rag(self) -> None:
        """Construct KnowledgeStore + retriever lazily."""
        # Ensure parent dir exists.
        Path(self.tg_db_path).parent.mkdir(parents=True, exist_ok=True)

        from trustgraph.knowledge_store import KnowledgeStore

        # Inline the retriever — same logic as the skeleton's class but local
        # so we don't pull a script dep into the suite-core module.
        class _Retriever:
            DEFAULT_CORES = (4, 5)

            def __init__(self, store: KnowledgeStore, org_id: str) -> None:
                self.store = store
                self.org_id = org_id

            @staticmethod
            def _tokens(query: str) -> list[str]:
                import re

                toks = re.findall(r"[A-Za-z0-9_]+", query)
                return [t for t in toks if len(t) >= 3]

            def retrieve(self, query: str, top_k: int = 5) -> list:
                tokens = self._tokens(query)
                fts_query = " OR ".join(tokens) if tokens else (query or "*")
                out: list = []
                for core_id in self.DEFAULT_CORES:
                    try:
                        out.extend(
                            self.store.search(
                                core_id=core_id,
                                query_text=fts_query,
                                filters={"org_id": self.org_id},
                                limit=top_k,
                            )
                        )
                    except Exception:  # noqa: BLE001 — best-effort
                        continue
                return out[:top_k]

        self._knowledge_store = KnowledgeStore(db_path=self.tg_db_path)
        self._retriever = _Retriever(self._knowledge_store, self.org_id)

    def _connect_signals(self, *, apply_pragmas: bool = False) -> sqlite3.Connection:
        """Open a SQLite connection. WAL is a database-level mode that
        persists across connections — we only need to set it once during
        ``_init_signals_db``. Subsequent connects skip the PRAGMA round-trip
        (which was costing ~1ms per event in the hot path).

        ``busy_timeout`` IS connection-local — we always set it because it
        is what lets concurrent writers wait for the SQLite write lock instead
        of raising ``database is locked``.

        WAL (Write-Ahead Logging) lets readers run concurrently with a writer,
        replacing the previous Python ``threading.Lock`` that serialised every
        thread for every operation.

        Reasoning: see ``docs/load_test_llm_loop_2026-04-26.md`` Bottleneck #2.
        """
        conn = sqlite3.connect(self.signals_db_path, timeout=30.0)
        try:
            # busy_timeout is per-connection in SQLite; always set it.
            conn.execute("PRAGMA busy_timeout=30000")
            if apply_pragmas:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA synchronous=NORMAL")
        except sqlite3.Error:  # noqa: PERF203 - PRAGMA probe is best-effort
            # WAL not always supported (e.g. some tmpfs). Fall back silently —
            # busy_timeout is enough on its own for correctness.
            pass
        return conn

    def _init_signals_db(self) -> None:
        Path(self.signals_db_path).parent.mkdir(parents=True, exist_ok=True)
        # First connection sets WAL mode (database-level, persists).
        conn = self._connect_signals(apply_pragmas=True)
        try:
            conn.executescript(_LEARNING_SIGNALS_SCHEMA)
            conn.commit()
        finally:
            conn.close()

    def _persist_blocking(
        self,
        finding_id: str,
        org_id: str,
        rag_block: str,
        verdict: Mapping[str, Any],
        council_action: str,
    ) -> tuple[str, str]:
        """Insert verdict + (synthetic) DPO pair. Returns (verdict_id, pair_id|"")."""
        verdict_id = f"v_{uuid.uuid4().hex[:12]}"
        conn = self._connect_signals()
        try:
            # Schema is initialised once in __init__; avoid re-running
            # `executescript` on every insert (was adding a parser pass per
            # event under the old lock-protected hot path).
            conn.execute(
                """INSERT INTO council_verdicts
                   (verdict_id, finding_id, org_id, rag_context, council_action,
                    confidence, reasoning, raw_verdict, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    verdict_id,
                    finding_id,
                    org_id,
                    rag_block,
                    council_action or "unknown",
                    float(verdict.get("confidence", 0.0)),
                    verdict.get("reasoning", ""),
                    json.dumps(verdict, default=str),
                    _now_iso(),
                ),
            )

            # Auto-emit a DPO pair for low-confidence verdicts so we always
            # accumulate training signal even before any human override.
            # The pair lists the council action as "rejected" and a
            # contrasting alternative as "chosen" — this is the
            # "council-disagreement" pair flavour from the roadmap §2.
            pair_id = ""
            confidence = float(verdict.get("confidence", 0.0))
            if confidence < 0.75:
                chosen = (
                    "remediate_high"
                    if council_action != "remediate_high"
                    else "accept_risk"
                )
                pair_id = f"p_{uuid.uuid4().hex[:12]}"
                conn.execute(
                    """INSERT INTO feedback_pairs
                       (pair_id, verdict_id, chosen_action, rejected_action,
                        pair_source, metadata, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        pair_id,
                        verdict_id,
                        chosen,
                        council_action or "unknown",
                        "llm_learning_loop_low_confidence",
                        json.dumps(
                            {
                                "trigger": "confidence_below_threshold",
                                "threshold": 0.75,
                                "observed_confidence": confidence,
                            }
                        ),
                        _now_iso(),
                    ),
                )
            conn.commit()
        finally:
            conn.close()
        return verdict_id, pair_id

    async def _republish_decision(
        self,
        *,
        source_event_type: str,
        finding_id: str,
        org_id: str,
        verdict_id: str,
        council_verdict: Mapping[str, Any],
    ) -> None:
        """Emit ``decision.made`` so downstream subscribers see the verdict."""
        try:
            from core.event_bus import Event, EventType, get_event_bus

            bus = get_event_bus()
            decision_event_type = getattr(
                EventType, "DECISION_MADE", _DECISION_EVENT_TYPE
            )
            await bus.emit(
                Event(
                    event_type=decision_event_type,
                    source="llm_learning_loop",
                    data={
                        "verdict_id": verdict_id,
                        "finding_id": finding_id,
                        "source_event_type": source_event_type,
                        "action": council_verdict.get("action"),
                        "confidence": council_verdict.get("confidence"),
                        "reasoning": (council_verdict.get("reasoning") or "")[:500],
                        "escalated": council_verdict.get("escalated", False),
                        "members_voted": len(council_verdict.get("member_votes", [])),
                    },
                    org_id=org_id,
                )
            )
        except Exception as exc:  # noqa: BLE001 — republish is best-effort
            logger.debug("llm_learning_loop: republish skipped: %s", exc)


# ---------------------------------------------------------------------------
# Module-level singleton + start/stop helpers
# ---------------------------------------------------------------------------

_loop_singleton: Optional[LLMLearningLoop] = None
_singleton_lock = threading.Lock()


def get_llm_learning_loop() -> Optional[LLMLearningLoop]:
    """Return the running loop, or None if it hasn't been started."""
    return _loop_singleton


def start_llm_learning_loop(
    app: Any = None,
    *,
    force: bool = False,
) -> Optional[LLMLearningLoop]:
    """Construct + start the loop. No-op (returns None) when env opt-out is in
    effect, unless ``force=True`` (used by tests).

    If ``app`` is a FastAPI instance, the loop is also stopped on app shutdown.
    """
    global _loop_singleton

    if not force and not _is_enabled():
        logger.info(
            "llm_learning_loop: disabled (set FIXOPS_LLM_LEARNING_LOOP=1 to enable)"
        )
        return None

    with _singleton_lock:
        if _loop_singleton is not None:
            return _loop_singleton
        loop = LLMLearningLoop()
        loop.start()
        _loop_singleton = loop

    if app is not None and hasattr(app, "on_event"):

        @app.on_event("shutdown")
        async def _shutdown_llm_learning_loop() -> None:  # pragma: no cover
            stop_llm_learning_loop()

    return _loop_singleton


def stop_llm_learning_loop() -> None:
    """Stop and clear the singleton. Safe to call multiple times."""
    global _loop_singleton
    with _singleton_lock:
        if _loop_singleton is not None:
            _loop_singleton.stop()
        _loop_singleton = None


__all__ = [
    "LLMLearningLoop",
    "start_llm_learning_loop",
    "stop_llm_learning_loop",
    "get_llm_learning_loop",
]
