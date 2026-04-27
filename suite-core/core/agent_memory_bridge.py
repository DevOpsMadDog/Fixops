"""Agent Memory Bridge — persistent cross-session memory for specialist agents.

Wires our specialist agents (backend-hardener, frontend-craftsman, qa-engineer,
agent-doctor, security-reviewer, ...) onto the existing AgentDBBridge so their
context survives across Claude Code sessions.

Why
---
Specialist agents currently start cold: every invocation re-derives the project
state from scratch. The ruflo swarm evaluation
(``docs/ruflo_swarm_evaluation_2026-04-26.md``, commit ``40e57f92``) flagged
persistent cross-session memory as the biggest win we were not capturing — the
``.swarm/memory.db`` already has 4,642 entries with HNSW vector index.

This module is the thin adapter that lets specialists:

1. **On task start** — query AgentDB for the top-K past tasks they themselves
   completed that look semantically similar to the new task brief.
2. **On task end** — persist a structured summary (task brief, outcome, findings,
   commit SHA, files touched) so the *next* invocation can find this work.

Each agent gets a stable namespace: ``agent:<agent-id>`` (e.g.
``agent:backend-hardener``). All memory writes go through the existing
``AgentDBBridge`` ⇒ same SQLite DB, same embedder, same async-queue plumbing,
same observability.

Public API
----------

    from core.agent_memory_bridge import (
        AgentMemoryBridge,
        AgentTaskMemory,
        get_agent_memory_bridge,
        recall_for_agent,
        remember_for_agent,
    )

    bridge = get_agent_memory_bridge()

    # Recall: at the START of a task
    past = bridge.recall(
        agent_id="backend-hardener",
        task_brief="Fix IDOR in /admin/users endpoint",
        k=5,
    )
    for hit in past:
        print(hit.summary, hit.outcome, hit.commit_sha)

    # Persist: at the END of a task
    bridge.remember(
        agent_id="backend-hardener",
        task_brief="Fix IDOR in /admin/users endpoint",
        outcome="success",
        summary="Added tenant scoping to admin user list, 4 tests, no regressions.",
        findings=["IDOR via /admin/users?org_id=", "Missing role guard on /admin/users"],
        commit_sha="abc1234",
        files_touched=["suite-api/apps/api/admin_router.py", "tests/test_admin_idor.py"],
    )

Retention
---------
Memory entries inherit the AgentDB lifecycle (status='active'). We do NOT delete
on read. Pruning policy lives in the worker daemon
(``scripts/agentdb_async_worker.py``) so a future revision can age out
``outcome='failed'`` rows older than 90 days while keeping 'success' rows
indefinitely.

Never raises. If AgentDB is unavailable (e.g. ``.swarm/memory.db`` missing),
``recall`` returns ``[]`` and ``remember`` returns ``False`` — the calling
agent continues as before. Mission-critical: NEVER block the specialist agent
on a memory failure.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence

# We layer on top of the existing AgentDBBridge so we share the embedder,
# async queue, fallback paths, and ops metrics. No new SQLite store, no
# duplicate plumbing.
try:  # pragma: no cover - import path tested at runtime
    from trustgraph.agentdb_bridge import (
        AgentDBBridge,
        AgentDBSearchResult,
        get_agentdb_bridge,
    )
except ImportError:  # pragma: no cover
    # Fallback for when sys.path hasn't been mangled by sitecustomize yet
    # (rare; only matters in some test invocations).
    import sys
    from pathlib import Path

    _root = Path(__file__).resolve().parent.parent.parent
    for _sub in ("suite-core",):
        _p = _root / _sub
        if _p.exists() and str(_p) not in sys.path:
            sys.path.insert(0, str(_p))
    from trustgraph.agentdb_bridge import (  # type: ignore[no-redef]
        AgentDBBridge,
        AgentDBSearchResult,
        get_agentdb_bridge,
    )

logger = logging.getLogger(__name__)

__all__ = [
    "AgentMemoryBridge",
    "AgentTaskMemory",
    "get_agent_memory_bridge",
    "reset_agent_memory_bridge",
    "recall_for_agent",
    "remember_for_agent",
    "agent_namespace",
]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Namespace prefix used in AgentDB. Keep this stable — once written, namespace
# is the partition key for retrieval. ``agent:<agent-id>`` matches the format
# used elsewhere in the codebase (e.g. ``agent:backend-hardener-status.md``
# in ``.claude/team-state/``).
_AGENT_NS_PREFIX = "agent:"

# Tag added to every agent-memory event so we can grep across all specialists
# in the council/trustgraph layer.
_AGENT_MEMORY_EVENT_TYPE = "agent.task.completed"

# Default similarity floor when recalling. Hash-embedder cosine for unrelated
# strings is typically <0.20; same-topic >0.30. We default conservatively low
# so weakly relevant past work surfaces — the agent can ignore noise but can't
# magic up missing context.
_DEFAULT_RECALL_FLOOR = 0.15
_DEFAULT_RECALL_K = 5


def agent_namespace(agent_id: str) -> str:
    """Return the canonical AgentDB namespace for ``agent_id``.

    >>> agent_namespace("backend-hardener")
    'agent:backend-hardener'
    """
    aid = (agent_id or "").strip().lower()
    if not aid:
        return f"{_AGENT_NS_PREFIX}unknown"
    if aid.startswith(_AGENT_NS_PREFIX):
        return aid
    return f"{_AGENT_NS_PREFIX}{aid}"


# ---------------------------------------------------------------------------
# Data class — what we persist and what callers see on recall
# ---------------------------------------------------------------------------


@dataclass
class AgentTaskMemory:
    """Structured snapshot of one specialist-agent task invocation.

    Returned from ``AgentMemoryBridge.recall``. Reconstructed from the AgentDB
    ``content``/``metadata`` fields written at ``remember`` time.
    """

    agent_id: str
    task_brief: str
    outcome: str  # "success" | "partial" | "failed" | "blocked" | "unknown"
    summary: str
    findings: List[str] = field(default_factory=list)
    commit_sha: Optional[str] = None
    files_touched: List[str] = field(default_factory=list)
    similarity: float = 0.0
    created_at_ms: int = 0
    entry_key: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "task_brief": self.task_brief,
            "outcome": self.outcome,
            "summary": self.summary,
            "findings": list(self.findings),
            "commit_sha": self.commit_sha,
            "files_touched": list(self.files_touched),
            "similarity": round(self.similarity, 4),
            "created_at_ms": self.created_at_ms,
            "entry_key": self.entry_key,
        }

    def render_for_prompt(self, index: int = 1) -> str:
        """Render this past task as a prompt-friendly snippet.

        Output is bounded so a top-5 recall stays under ~2KB of prompt tokens.
        """
        head = (
            f"[Past task #{index}] outcome={self.outcome} "
            f"similarity={self.similarity:.2f}"
        )
        if self.commit_sha:
            head += f" commit={self.commit_sha[:8]}"
        body_parts = [head, f"  Brief: {self.task_brief[:200]}"]
        if self.summary:
            body_parts.append(f"  Summary: {self.summary[:300]}")
        if self.findings:
            findings_str = "; ".join(str(f)[:120] for f in self.findings[:3])
            body_parts.append(f"  Findings: {findings_str}")
        if self.files_touched:
            files_str = ", ".join(self.files_touched[:5])
            body_parts.append(f"  Files: {files_str}")
        return "\n".join(body_parts)


# ---------------------------------------------------------------------------
# Bridge
# ---------------------------------------------------------------------------


class AgentMemoryBridge:
    """Adapter on top of AgentDBBridge for specialist-agent persistent memory.

    Thread-safe. Never raises. All writes are best-effort.
    """

    def __init__(self, *, agentdb: Optional[AgentDBBridge] = None) -> None:
        self._agentdb = agentdb or get_agentdb_bridge()
        self._recalls = 0
        self._remembers = 0
        self._failures = 0
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Recall — at task start
    # ------------------------------------------------------------------

    def recall(
        self,
        *,
        agent_id: str,
        task_brief: str,
        k: int = _DEFAULT_RECALL_K,
        min_similarity: float = _DEFAULT_RECALL_FLOOR,
        cross_agent: bool = False,
    ) -> List[AgentTaskMemory]:
        """Retrieve top-K past task memories most similar to ``task_brief``.

        Args:
            agent_id: which specialist is asking (e.g. ``"backend-hardener"``).
            task_brief: the prompt or short description of the new task.
            k: max entries to return (default 5).
            min_similarity: cosine cutoff (default 0.15 = "weakly related").
            cross_agent: if True, search across all agent namespaces — useful
                for cross-discipline retrieval (e.g. backend-hardener wants to
                know what qa-engineer wrote about an endpoint). Default False
                keeps each agent in its own lane.

        Returns:
            List of :class:`AgentTaskMemory` ordered by descending similarity.
            Empty list on any failure or missing AgentDB.
        """
        if not agent_id or not task_brief:
            return []

        with self._lock:
            self._recalls += 1
        try:
            ns = None if cross_agent else agent_namespace(agent_id)
            hits = self._agentdb.semantic_search(
                task_brief,
                namespace=ns,
                k=max(1, int(k)),
                min_similarity=float(min_similarity),
            )
            return [self._to_task_memory(h) for h in hits]
        except Exception as exc:  # noqa: BLE001 - never block the agent
            with self._lock:
                self._failures += 1
            logger.debug("agent_memory_bridge.recall failed: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Remember — at task end
    # ------------------------------------------------------------------

    def remember(
        self,
        *,
        agent_id: str,
        task_brief: str,
        outcome: str,
        summary: str,
        findings: Optional[Sequence[str]] = None,
        commit_sha: Optional[str] = None,
        files_touched: Optional[Sequence[str]] = None,
        extra: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """Persist a task memory to AgentDB. Never raises.

        Args:
            agent_id: which specialist did the work.
            task_brief: the prompt / mission statement.
            outcome: ``"success" | "partial" | "failed" | "blocked"``.
            summary: 1-3 sentences on what happened. This is the field future
                recalls will read first.
            findings: bullet list of observations (e.g. bugs found, decisions made).
            commit_sha: the commit produced by this task, if any.
            files_touched: paths the agent edited or created.
            extra: free-form metadata bag (merged into the AgentDB ``metadata``).

        Returns:
            True if the memory landed in AgentDB. False if disabled / unavailable
            / write failed.
        """
        if not agent_id or not task_brief:
            return False

        normalized_outcome = self._normalize_outcome(outcome)

        # Stable dedup key — same agent + same brief deduplicates by design,
        # so re-running the same mission updates the row instead of polluting
        # recall with N copies. Use a uuid suffix when caller wants to keep
        # history (rare; expose via extra={"force_unique": True}).
        force_unique = bool((extra or {}).get("force_unique"))
        key_seed = f"{agent_id}|{task_brief[:200]}"
        if force_unique:
            key_seed = f"{key_seed}|{uuid.uuid4().hex[:8]}"
        # AgentDBBridge will prefix with event_type, so key just identifies the row.

        payload: Dict[str, Any] = {
            "agent_id": agent_id,
            # 'title' is what AgentDBBridge._render_content highlights in the
            # head of the embedding text. Putting the brief here makes recall
            # match on what the new agent actually asks about.
            "title": task_brief[:300],
            "task_brief": task_brief,
            "outcome": normalized_outcome,
            "summary": summary or "",
            "findings": list(findings or []),
            "commit_sha": commit_sha,
            "files_touched": list(files_touched or []),
            "completed_at_ms": int(time.time() * 1000),
            # Used by _make_key in AgentDBBridge → stable namespace+key dedup.
            "id": key_seed,
        }
        if extra:
            # Preserve caller fields, but never let them clobber our reserved keys.
            reserved = set(payload.keys())
            for k, v in extra.items():
                if k not in reserved:
                    payload[k] = v

        try:
            ok = self._agentdb.dual_write(
                event_type=_AGENT_MEMORY_EVENT_TYPE,
                payload=payload,
                namespace=agent_namespace(agent_id),
                key=None,  # Let AgentDBBridge derive from payload['id']
            )
            if ok:
                with self._lock:
                    self._remembers += 1
            else:
                with self._lock:
                    self._failures += 1
            return bool(ok)
        except Exception as exc:  # noqa: BLE001
            with self._lock:
                self._failures += 1
            logger.debug("agent_memory_bridge.remember failed: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Health / metrics
    # ------------------------------------------------------------------

    def health(self) -> Dict[str, Any]:
        """Return ops view: AgentDB health + our local counters."""
        underlying = self._agentdb.health()
        with self._lock:
            return {
                "available": underlying.get("available", False),
                "store_path": underlying.get("store_path"),
                "embedder": underlying.get("embedder"),
                "recalls": self._recalls,
                "remembers": self._remembers,
                "failures": self._failures,
                "agentdb": underlying,
            }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_outcome(outcome: Optional[str]) -> str:
        if not outcome:
            return "unknown"
        v = str(outcome).strip().lower()
        if v in {"success", "ok", "passed", "done", "completed"}:
            return "success"
        if v in {"partial", "partial-success", "degraded"}:
            return "partial"
        if v in {"fail", "failed", "error", "errored"}:
            return "failed"
        if v in {"block", "blocked", "stuck"}:
            return "blocked"
        return v[:32] or "unknown"

    @staticmethod
    def _to_task_memory(hit: AgentDBSearchResult) -> AgentTaskMemory:
        """Reconstruct AgentTaskMemory from a raw AgentDB search hit.

        AgentDBBridge stores the JSON payload as the *tail* of the ``content``
        field after a ``\\n`` separator. We split on first newline and parse
        the tail; on any parse failure we fall back to surfacing what we can
        from ``content``/``metadata`` so callers never see an empty entry.
        """
        agent_id = "unknown"
        task_brief = ""
        outcome = "unknown"
        summary = ""
        findings: List[str] = []
        commit_sha: Optional[str] = None
        files_touched: List[str] = []

        try:
            tail_start = hit.content.find("\n")
            if tail_start != -1:
                import json as _json

                tail = hit.content[tail_start + 1 :].strip()
                if tail:
                    payload = _json.loads(tail)
                    agent_id = payload.get("agent_id") or agent_id
                    task_brief = payload.get("task_brief") or payload.get("title") or task_brief
                    outcome = payload.get("outcome") or outcome
                    summary = payload.get("summary") or summary
                    raw_findings = payload.get("findings") or []
                    if isinstance(raw_findings, list):
                        findings = [str(f) for f in raw_findings if f is not None]
                    commit_sha = payload.get("commit_sha")
                    raw_files = payload.get("files_touched") or []
                    if isinstance(raw_files, list):
                        files_touched = [str(f) for f in raw_files if f]
        except Exception as exc:  # noqa: BLE001
            logger.debug("agent_memory_bridge: failed to parse hit %s: %s", hit.entry_id, exc)

        # Fallback: derive agent_id from the namespace if payload was missing.
        if agent_id == "unknown" and hit.namespace and hit.namespace.startswith(_AGENT_NS_PREFIX):
            agent_id = hit.namespace[len(_AGENT_NS_PREFIX) :] or agent_id

        # Fallback summary: first line of the content if structured parse failed.
        if not summary and hit.content:
            first_line = hit.content.split("\n", 1)[0]
            summary = first_line[:300]

        return AgentTaskMemory(
            agent_id=agent_id,
            task_brief=task_brief,
            outcome=outcome,
            summary=summary,
            findings=findings,
            commit_sha=commit_sha,
            files_touched=files_touched,
            similarity=hit.similarity,
            created_at_ms=hit.created_at_ms,
            entry_key=hit.key,
        )


# ---------------------------------------------------------------------------
# Singleton access
# ---------------------------------------------------------------------------

_bridge_singleton: Optional[AgentMemoryBridge] = None
_bridge_singleton_lock = threading.Lock()


def get_agent_memory_bridge() -> AgentMemoryBridge:
    """Return the process-wide AgentMemoryBridge, creating it on first call."""
    global _bridge_singleton
    if _bridge_singleton is None:
        with _bridge_singleton_lock:
            if _bridge_singleton is None:
                _bridge_singleton = AgentMemoryBridge()
    return _bridge_singleton


def reset_agent_memory_bridge() -> None:
    """Drop the singleton — used by tests for isolation."""
    global _bridge_singleton
    with _bridge_singleton_lock:
        _bridge_singleton = None


# ---------------------------------------------------------------------------
# Module-level convenience wrappers (so CLI/agent prompts can do one-liners)
# ---------------------------------------------------------------------------


def recall_for_agent(
    agent_id: str,
    task_brief: str,
    *,
    k: int = _DEFAULT_RECALL_K,
    min_similarity: float = _DEFAULT_RECALL_FLOOR,
    cross_agent: bool = False,
) -> List[AgentTaskMemory]:
    """One-call recall for the top-level prompt wrapper."""
    return get_agent_memory_bridge().recall(
        agent_id=agent_id,
        task_brief=task_brief,
        k=k,
        min_similarity=min_similarity,
        cross_agent=cross_agent,
    )


def remember_for_agent(
    agent_id: str,
    task_brief: str,
    *,
    outcome: str,
    summary: str,
    findings: Optional[Sequence[str]] = None,
    commit_sha: Optional[str] = None,
    files_touched: Optional[Sequence[str]] = None,
    extra: Optional[Mapping[str, Any]] = None,
) -> bool:
    """One-call remember for end-of-task hooks."""
    return get_agent_memory_bridge().remember(
        agent_id=agent_id,
        task_brief=task_brief,
        outcome=outcome,
        summary=summary,
        findings=findings,
        commit_sha=commit_sha,
        files_touched=files_touched,
        extra=extra,
    )
