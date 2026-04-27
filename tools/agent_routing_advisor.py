"""Agent Routing Advisor — Q-Learning task router (mirrors ``ruflo route``).

Given a free-text task description, returns the recommended specialist agent,
model tier, confidence score, and the top-3 most-similar past tasks (drawn
from AgentDB) for justification.

Why
---
Today the CTO manually routes ~30 agent dispatches per session across 12
specialist agents (backend-hardener, frontend-craftsman, qa-engineer, ...).
Roughly 20% of those dispatches are wrong-routed (lightweight task to opus,
or opus-grade task to a junior worker). A Q-Learning router that learns from
outcomes auto-suggests the right agent and shrinks that error rate over time.

Architecture
------------

    route(task) ──▶ ┌────────────────────────────────────────┐
                    │ 1. Keyword-extract task                │
                    │ 2. Q-table lookup: argmax over agents  │
                    │ 3. AgentDB semantic-search top-3 past  │
                    │    tasks for justification             │
                    │ 4. Map agent → model tier              │
                    └────────────────────────────────────────┘
                                       │
                                       ▼
                          {agent, tier, confidence, similar:[...]}

    record_outcome(task, agent, success) ──▶ Q-table SARSA update

Q-table schema (data/agent_routing_qtable.db):

    routing_q(state TEXT, action TEXT, q REAL, n INTEGER, updated_at TEXT,
              PRIMARY KEY(state, action))
    routing_history(id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task TEXT, agent TEXT, tier TEXT,
                    success INTEGER, created_at TEXT)

State = sorted tuple of top-K task keywords (deterministic per task).
Action = agent_id (one of the 12 specialists).
Reward = +1 success, -1 failure, 0 unknown.

Public API
----------

    from tools.agent_routing_advisor import route, record_outcome

    rec = route("fix the bulk-triage IDOR vuln")
    # rec = {
    #   "agent": "backend-hardener",
    #   "tier": "sonnet",
    #   "confidence": 0.78,
    #   "similar": [...],
    #   "reasoning": "...",
    # }

    record_outcome(task="...", agent="backend-hardener", success=True)

CLI
---

    python tools/agent_routing_advisor.py "fix the bulk-triage IDOR vuln"

    Outputs JSON to stdout. Non-zero exit if no Q-table can be created.

Fallback when AgentDB unavailable
---------------------------------
If ``.swarm/memory.db`` is missing or unreadable, ``similar`` is returned as
``[]`` and ``reasoning`` is keyword-only. Q-table still works (it's a
separate SQLite file at ``data/agent_routing_qtable.db``).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sqlite3
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

__all__ = [
    "route",
    "record_outcome",
    "AgentRoutingAdvisor",
    "RoutingDecision",
    "AGENT_REGISTRY",
]

# ---------------------------------------------------------------------------
# Agent registry — the 12 specialists we route across, with capability priors
# ---------------------------------------------------------------------------
# Each entry: (agent_id, model_tier, keywords, prior_q)
# - model_tier: haiku-junior | sonnet | opus  (model-tier hint, not a hard pin)
# - keywords:   substrings that boost this agent's score for the state
# - prior_q:    optimistic prior so cold-start picks something reasonable

AGENT_REGISTRY: Dict[str, Dict[str, Any]] = {
    "backend-hardener": {
        "tier": "sonnet",
        "keywords": [
            "api", "endpoint", "router", "fastapi", "auth", "idor",
            "injection", "vuln", "vulnerability", "harden", "fix",
            "500", "404", "backend", "sqlite", "secret", "input validation",
            "rate limit", "cors", "header", "middleware", "scanner",
            "pydantic", "sql", "owasp",
        ],
        "prior_q": 0.55,
    },
    "frontend-craftsman": {
        "tier": "sonnet",
        "keywords": [
            "ui", "react", "vite", "tailwind", "page", "component",
            "tsx", "jsx", "frontend", "form", "modal", "dashboard",
            "playwright", "screenshot", "css", "responsive", "a11y",
            "mock", "fetch", "useEffect", "useQuery",
        ],
        "prior_q": 0.55,
    },
    "qa-engineer": {
        "tier": "sonnet",
        "keywords": [
            "test", "pytest", "coverage", "regression", "e2e", "unit",
            "integration", "fixture", "mock", "qa", "validate",
            "smoke", "snapshot", "ci",
        ],
        "prior_q": 0.55,
    },
    "technical-writer": {
        "tier": "haiku-junior",
        "keywords": [
            "doc", "docs", "documentation", "readme", "guide",
            "changelog", "writeup", "explain", "tutorial", "spec",
            "markdown", ".md",
        ],
        "prior_q": 0.50,
    },
    "marketing-head": {
        "tier": "haiku-junior",
        "keywords": [
            "marketing", "landing", "pitch", "narrative", "copy",
            "blog", "press", "campaign", "tagline", "hero",
            "messaging", "positioning",
        ],
        "prior_q": 0.50,
    },
    "devops-engineer": {
        "tier": "sonnet",
        "keywords": [
            "docker", "compose", "deploy", "k8s", "kubernetes",
            "terraform", "ci/cd", "github action", "pipeline",
            "infra", "helm", "registry", "cluster", "kind",
            "ingress", "tls", "secret manager",
        ],
        "prior_q": 0.55,
    },
    "sales-engineer": {
        "tier": "haiku-junior",
        "keywords": [
            "demo", "pitch", "rfp", "rfi", "soc2", "compliance",
            "customer", "sales", "deck", "proposal", "trial",
            "onboarding script", "roi",
        ],
        "prior_q": 0.45,
    },
    "security-analyst": {
        "tier": "opus",
        "keywords": [
            "owasp", "cve", "exploit", "pentest", "threat model",
            "stride", "attack", "kill chain", "mitre", "ttp",
            "red team", "purple team", "vuln triage",
        ],
        "prior_q": 0.55,
    },
    "data-scientist": {
        "tier": "sonnet",
        "keywords": [
            "ml", "model", "embedding", "vector", "training",
            "feature", "metric", "statistic", "regression analysis",
            "cluster", "anomaly", "ai", "llm",
        ],
        "prior_q": 0.55,
    },
    "enterprise-architect": {
        "tier": "opus",
        "keywords": [
            "architecture", "design", "adr", "rfc", "system design",
            "scalability", "tradeoff", "epic", "blueprint",
            "tenant", "isolation", "domain model",
        ],
        "prior_q": 0.55,
    },
    "ux-architect": {
        "tier": "sonnet",
        "keywords": [
            "ux", "user flow", "wireframe", "prototype", "persona",
            "journey", "ia", "information architecture", "navigation",
            "usability", "accessibility audit",
        ],
        "prior_q": 0.50,
    },
    "agent-doctor": {
        "tier": "opus",
        "keywords": [
            "agent", "swarm", "orchestrat", "dispatch", "stalled",
            "recover", "doctor", "audit agents", "agent health",
            "team coordination", "context-engineer",
        ],
        "prior_q": 0.55,
    },
}

# ---------------------------------------------------------------------------
# Paths + defaults
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parent.parent
_QTABLE_DEFAULT = _REPO_ROOT / "data" / "agent_routing_qtable.db"
_AGENTDB_DEFAULT = _REPO_ROOT / ".swarm" / "memory.db"

_LEARNING_RATE = 0.3       # alpha
_DISCOUNT = 0.0            # contextual bandit (no future state) — gamma=0
_KEYWORD_TOP_K = 5         # state = top-K sorted task keywords
_SIMILAR_TOP_K = 3         # how many similar past tasks to surface

# Stop-words removed before keyword extraction
_STOP_WORDS = frozenset(
    {
        "the", "a", "an", "of", "for", "to", "in", "on", "and", "or",
        "with", "is", "are", "be", "this", "that", "it", "its", "as",
        "fix", "add", "make", "new", "old", "our", "we", "i", "you",
        "task", "please", "do", "should", "must", "can", "will",
    }
)

_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9_-]{1,}")

# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

_QTABLE_SCHEMA = """
CREATE TABLE IF NOT EXISTS routing_q (
    state      TEXT NOT NULL,
    action     TEXT NOT NULL,
    q          REAL NOT NULL DEFAULT 0.0,
    n          INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(state, action)
);

CREATE INDEX IF NOT EXISTS idx_routing_q_action ON routing_q(action);

CREATE TABLE IF NOT EXISTS routing_history (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    task       TEXT NOT NULL,
    state      TEXT NOT NULL,
    agent      TEXT NOT NULL,
    tier       TEXT NOT NULL,
    success    INTEGER,                         -- 1, 0, NULL=pending
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_routing_history_agent ON routing_history(agent);
CREATE INDEX IF NOT EXISTS idx_routing_history_state ON routing_history(state);
"""


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class SimilarTask:
    """A past task surfaced by AgentDB semantic search."""

    key: str
    snippet: str
    namespace: str
    score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "snippet": self.snippet,
            "namespace": self.namespace,
            "score": round(self.score, 4),
        }


@dataclass
class RoutingDecision:
    """The advisor's recommendation."""

    task: str
    agent: str
    tier: str
    confidence: float
    state: str
    q_value: float
    visit_count: int
    explored: bool
    alternatives: List[Tuple[str, float]] = field(default_factory=list)
    similar: List[SimilarTask] = field(default_factory=list)
    reasoning: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task": self.task,
            "agent": self.agent,
            "tier": self.tier,
            "confidence": round(self.confidence, 4),
            "state": self.state,
            "q_value": round(self.q_value, 4),
            "visit_count": self.visit_count,
            "explored": self.explored,
            "alternatives": [
                {"agent": a, "score": round(s, 4)} for a, s in self.alternatives
            ],
            "similar": [s.to_dict() for s in self.similar],
            "reasoning": self.reasoning,
        }


# ---------------------------------------------------------------------------
# Keyword + state extraction
# ---------------------------------------------------------------------------


def _tokenize(text: str) -> List[str]:
    if not text:
        return []
    return [
        t.lower()
        for t in _TOKEN_RE.findall(text)
        if t.lower() not in _STOP_WORDS and len(t) > 2
    ]


def _extract_keywords(task: str, top_k: int = _KEYWORD_TOP_K) -> List[str]:
    """Return up to top_k keywords, sorted (so state is deterministic)."""
    tokens = _tokenize(task)
    if not tokens:
        return []
    # frequency-rank, ties broken alphabetically
    freq: Dict[str, int] = {}
    for t in tokens:
        freq[t] = freq.get(t, 0) + 1
    ranked = sorted(freq.items(), key=lambda kv: (-kv[1], kv[0]))
    keywords = [k for k, _ in ranked[:top_k]]
    return sorted(keywords)


def _state_from_task(task: str) -> str:
    keywords = _extract_keywords(task)
    return "|".join(keywords) if keywords else "<empty>"


def _keyword_overlap_score(task: str, agent_keywords: Sequence[str]) -> float:
    """How well does this task's text overlap with this agent's capability
    keywords? Returns score in [0, 1.5] (slightly >1 is fine)."""
    text = task.lower()
    hits = 0
    for kw in agent_keywords:
        if kw in text:
            hits += 1
    if not agent_keywords:
        return 0.0
    return min(1.5, hits / max(1, len(agent_keywords)) * 4.0)


# ---------------------------------------------------------------------------
# Q-table store (SQLite)
# ---------------------------------------------------------------------------


class _QTableStore:
    """Tiny SQLite-backed Q-table. Thread-safe via per-call connections."""

    def __init__(self, path: Path):
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._path), timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(_QTABLE_SCHEMA)
            conn.commit()

    def get(self, state: str, action: str) -> Tuple[float, int]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT q, n FROM routing_q WHERE state=? AND action=?",
                (state, action),
            ).fetchone()
        if row is None:
            return 0.0, 0
        return float(row["q"]), int(row["n"])

    def get_all_for_state(self, state: str) -> Dict[str, Tuple[float, int]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT action, q, n FROM routing_q WHERE state=?",
                (state,),
            ).fetchall()
        return {r["action"]: (float(r["q"]), int(r["n"])) for r in rows}

    def update(self, state: str, action: str, reward: float) -> Tuple[float, int]:
        """SARSA-style update with γ=0 (contextual bandit).

        Q(s, a) ← Q(s, a) + α(r - Q(s, a))
        """
        old_q, n = self.get(state, action)
        new_q = old_q + _LEARNING_RATE * (reward - old_q)
        new_n = n + 1
        ts = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO routing_q(state, action, q, n, updated_at)
                       VALUES(?, ?, ?, ?, ?)
                       ON CONFLICT(state, action) DO UPDATE SET
                           q = excluded.q, n = excluded.n,
                           updated_at = excluded.updated_at""",
                (state, action, new_q, new_n, ts),
            )
            conn.commit()
        return new_q, new_n

    def record_history(
        self, task: str, state: str, agent: str, tier: str,
        success: Optional[bool],
    ) -> int:
        ts = datetime.now(timezone.utc).isoformat()
        succ = None if success is None else (1 if success else 0)
        with self._connect() as conn:
            cur = conn.execute(
                """INSERT INTO routing_history(task, state, agent, tier,
                                              success, created_at)
                       VALUES(?, ?, ?, ?, ?, ?)""",
                (task[:1000], state, agent, tier, succ, ts),
            )
            conn.commit()
            return int(cur.lastrowid or 0)

    def stats(self) -> Dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS rows, COUNT(DISTINCT state) AS states "
                "FROM routing_q"
            ).fetchone()
            hist = conn.execute(
                "SELECT COUNT(*) AS n, "
                "SUM(CASE WHEN success=1 THEN 1 ELSE 0 END) AS wins, "
                "SUM(CASE WHEN success=0 THEN 1 ELSE 0 END) AS losses "
                "FROM routing_history"
            ).fetchone()
        return {
            "q_entries": int(row["rows"] or 0),
            "states": int(row["states"] or 0),
            "history_total": int(hist["n"] or 0),
            "history_wins": int(hist["wins"] or 0),
            "history_losses": int(hist["losses"] or 0),
        }


# ---------------------------------------------------------------------------
# AgentDB semantic-search adapter (read-only, best-effort)
# ---------------------------------------------------------------------------


class _AgentDBSearcher:
    """Minimal read-only adapter over the AgentDB SQLite store.

    We deliberately avoid importing ``suite-core/trustgraph/agentdb_bridge``
    so the advisor stays usable from a venv without the full Fixops sys.path
    setup. We just open ``.swarm/memory.db`` directly and run lexical search
    over ``content`` + ``tags`` (cosine over MiniLM is overkill for top-3
    justification — lexical FTS-lite is plenty and never crashes).
    """

    def __init__(self, path: Path):
        self._path = path
        self._available = path.exists()

    @property
    def available(self) -> bool:
        return self._available

    def search(self, task: str, k: int = _SIMILAR_TOP_K) -> List[SimilarTask]:
        if not self._available:
            return []
        keywords = _tokenize(task)
        if not keywords:
            return []
        try:
            conn = sqlite3.connect(f"file:{self._path}?mode=ro", uri=True, timeout=2.0)
            conn.row_factory = sqlite3.Row
        except sqlite3.Error as exc:
            logger.debug("agentdb open failed: %s", exc)
            return []

        try:
            cur = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name='memory_entries'"
            ).fetchone()
            if not cur:
                return []
            # Score = #keyword hits in content+tags (cheap, deterministic).
            # Limit candidate set so we don't full-scan multi-GB stores.
            where_parts = []
            params: List[Any] = []
            for kw in keywords[: _KEYWORD_TOP_K]:
                where_parts.append("(content LIKE ? OR tags LIKE ?)")
                params.extend([f"%{kw}%", f"%{kw}%"])
            where_sql = " OR ".join(where_parts) if where_parts else "1=1"
            sql = (
                "SELECT key, namespace, content, tags FROM memory_entries "
                f"WHERE {where_sql} LIMIT 200"
            )
            rows = conn.execute(sql, params).fetchall()
        except sqlite3.Error as exc:
            logger.debug("agentdb search failed: %s", exc)
            return []
        finally:
            conn.close()

        scored: List[Tuple[float, sqlite3.Row]] = []
        for row in rows:
            blob = ((row["content"] or "") + " " + (row["tags"] or "")).lower()
            score = sum(1 for kw in keywords if kw in blob)
            if score == 0:
                continue
            scored.append((score / max(1, len(keywords)), row))

        scored.sort(key=lambda kv: -kv[0])
        out: List[SimilarTask] = []
        for score, row in scored[:k]:
            content = row["content"] or ""
            snippet = content[:200].replace("\n", " ").strip()
            out.append(
                SimilarTask(
                    key=row["key"] or "",
                    snippet=snippet,
                    namespace=row["namespace"] or "",
                    score=float(score),
                )
            )
        return out


# ---------------------------------------------------------------------------
# The advisor
# ---------------------------------------------------------------------------


class AgentRoutingAdvisor:
    """Q-Learning agent routing advisor.

    Combines a keyword-state Q-table with AgentDB semantic-search-backed
    justification. Cold-start is handled by capability priors so the very
    first dispatch already routes sensibly.
    """

    def __init__(
        self,
        qtable_path: Optional[Path] = None,
        agentdb_path: Optional[Path] = None,
    ):
        self._qtable = _QTableStore(Path(qtable_path) if qtable_path else _QTABLE_DEFAULT)
        agentdb = Path(agentdb_path) if agentdb_path else _AGENTDB_DEFAULT
        self._agentdb = _AgentDBSearcher(agentdb)

    # ---------------------------------------------------------------- route

    def route(self, task: str) -> RoutingDecision:
        if not isinstance(task, str) or not task.strip():
            raise ValueError("task must be a non-empty string")

        state = _state_from_task(task)
        # Score = learned Q + capability prior + keyword overlap bonus
        learned = self._qtable.get_all_for_state(state)

        scores: Dict[str, float] = {}
        visits: Dict[str, int] = {}
        for agent_id, meta in AGENT_REGISTRY.items():
            q, n = learned.get(agent_id, (0.0, 0))
            prior = meta["prior_q"] if n == 0 else 0.0
            overlap = _keyword_overlap_score(task, meta["keywords"])
            # Confidence-weighted blend: as we gather evidence, lean on Q.
            evidence_weight = min(1.0, n / 5.0)
            blended = (
                evidence_weight * q
                + (1.0 - evidence_weight) * (prior + 0.4 * overlap)
                + 0.15 * overlap          # always reward keyword fit
            )
            scores[agent_id] = blended
            visits[agent_id] = n

        # argmax
        ranked = sorted(scores.items(), key=lambda kv: -kv[1])
        best_agent, best_score = ranked[0]
        meta = AGENT_REGISTRY[best_agent]

        # Confidence:
        #   if no second place, 1.0
        #   else softmax-ish margin between top-1 and top-2
        if len(ranked) >= 2:
            second_score = ranked[1][1]
            margin = best_score - second_score
            confidence = max(0.0, min(1.0, 0.5 + margin))
        else:
            confidence = 1.0

        explored = visits.get(best_agent, 0) == 0
        q_val, n = learned.get(best_agent, (0.0, 0))

        similar = self._agentdb.search(task, k=_SIMILAR_TOP_K)

        reasoning_bits: List[str] = []
        reasoning_bits.append(
            f"State='{state}' (top-{_KEYWORD_TOP_K} keywords). "
            f"{best_agent} scored {best_score:.3f} "
            f"(Q={q_val:.3f}, visits={n}, prior={meta['prior_q']:.2f})."
        )
        overlap_kw = [k for k in meta["keywords"] if k in task.lower()]
        if overlap_kw:
            reasoning_bits.append(
                f"Capability hit: {', '.join(overlap_kw[:5])}."
            )
        if similar:
            reasoning_bits.append(
                f"AgentDB: {len(similar)} similar past task(s) found."
            )
        elif not self._agentdb.available:
            reasoning_bits.append("AgentDB unavailable — keyword-only mode.")

        return RoutingDecision(
            task=task,
            agent=best_agent,
            tier=str(meta["tier"]),
            confidence=confidence,
            state=state,
            q_value=q_val,
            visit_count=n,
            explored=explored,
            alternatives=[(a, s) for a, s in ranked[1:4]],
            similar=similar,
            reasoning=" ".join(reasoning_bits),
        )

    # ---------------------------------------------------- record_outcome

    def record_outcome(
        self,
        task: str,
        agent: str,
        success: bool,
        notes: str = "",
    ) -> Dict[str, Any]:
        """Update Q-value after observing a dispatch outcome.

        success = test pass + commit landed → reward +1
        failure = stall, rollback, or test regression → reward -1
        """
        if agent not in AGENT_REGISTRY:
            raise ValueError(f"unknown agent: {agent!r}")
        state = _state_from_task(task)
        reward = 1.0 if success else -1.0
        new_q, new_n = self._qtable.update(state, agent, reward)
        tier = str(AGENT_REGISTRY[agent]["tier"])
        hist_id = self._qtable.record_history(task, state, agent, tier, success)
        return {
            "state": state,
            "agent": agent,
            "tier": tier,
            "reward": reward,
            "new_q": round(new_q, 4),
            "visits": new_n,
            "history_id": hist_id,
            "notes": notes,
        }

    # --------------------------------------------------------------- meta

    def stats(self) -> Dict[str, Any]:
        s = self._qtable.stats()
        s["agentdb_available"] = self._agentdb.available
        s["agents"] = len(AGENT_REGISTRY)
        return s


# ---------------------------------------------------------------------------
# Module-level helpers (for inline use)
# ---------------------------------------------------------------------------

_DEFAULT_ADVISOR: Optional[AgentRoutingAdvisor] = None


def _get_default() -> AgentRoutingAdvisor:
    global _DEFAULT_ADVISOR
    if _DEFAULT_ADVISOR is None:
        _DEFAULT_ADVISOR = AgentRoutingAdvisor()
    return _DEFAULT_ADVISOR


def route(task: str) -> Dict[str, Any]:
    """Convenience function: returns dict-shaped recommendation."""
    return _get_default().route(task).to_dict()


def record_outcome(task: str, agent: str, success: bool, notes: str = "") -> Dict[str, Any]:
    """Convenience function: records outcome to Q-table."""
    return _get_default().record_outcome(task, agent, success, notes)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _cli(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="agent_routing_advisor",
        description="Q-Learning agent routing advisor (mirrors `ruflo route`).",
    )
    sub = p.add_subparsers(dest="cmd")

    p_route = sub.add_parser("route", help="Recommend an agent for a task")
    p_route.add_argument("task", help="Task description")

    p_outcome = sub.add_parser("outcome", help="Record outcome of a dispatch")
    p_outcome.add_argument("task")
    p_outcome.add_argument("agent")
    p_outcome.add_argument(
        "--success", action="store_true", help="Mark dispatch as successful"
    )
    p_outcome.add_argument(
        "--fail", action="store_true", help="Mark dispatch as failed"
    )
    p_outcome.add_argument("--notes", default="")

    sub.add_parser("stats", help="Show advisor statistics")

    # Default mode: a single bare positional == route(task). Argparse would
    # otherwise interpret the string as the subcommand and fail. We detect
    # that case BEFORE handing argv to argparse.
    raw = list(argv) if argv is not None else []
    known = {"route", "outcome", "stats", "-h", "--help"}
    if len(raw) >= 1 and raw[0] not in known:
        raw = ["route"] + raw

    args = p.parse_args(raw)

    advisor = AgentRoutingAdvisor()
    if args.cmd == "route":
        decision = advisor.route(args.task)
        json.dump(decision.to_dict(), sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    if args.cmd == "outcome":
        if args.success and args.fail:
            print("error: pass --success OR --fail, not both", file=sys.stderr)
            return 2
        if not (args.success or args.fail):
            print("error: must pass --success or --fail", file=sys.stderr)
            return 2
        out = advisor.record_outcome(
            args.task, args.agent, success=bool(args.success), notes=args.notes
        )
        json.dump(out, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    if args.cmd == "stats":
        json.dump(advisor.stats(), sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    p.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
