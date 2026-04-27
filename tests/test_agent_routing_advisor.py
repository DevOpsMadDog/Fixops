"""Tests for tools/agent_routing_advisor.py — Q-Learning agent routing advisor.

Real Q-table persistence, real (read-only) AgentDB lookup. No mocks.
Each test gets a fresh ``data/agent_routing_qtable.db`` in a tmp directory.
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import pytest

# Ensure tools/ is importable
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tools.agent_routing_advisor import (  # noqa: E402
    AGENT_REGISTRY,
    AgentRoutingAdvisor,
    _state_from_task,
    _extract_keywords,
)


@pytest.fixture
def advisor(tmp_path: Path) -> AgentRoutingAdvisor:
    qpath = tmp_path / "qtable.db"
    # Point AgentDB to a non-existent file to exercise the unavailable path
    agentdb = tmp_path / "no_such.db"
    return AgentRoutingAdvisor(qtable_path=qpath, agentdb_path=agentdb)


@pytest.fixture
def advisor_with_agentdb(tmp_path: Path) -> AgentRoutingAdvisor:
    """Advisor pointed at a real (tiny, real-schema) AgentDB SQLite store."""
    qpath = tmp_path / "qtable.db"
    agentdb = tmp_path / "memory.db"
    conn = sqlite3.connect(str(agentdb))
    conn.executescript(
        """
        CREATE TABLE memory_entries (
            id          TEXT PRIMARY KEY,
            key         TEXT,
            namespace   TEXT,
            content     TEXT,
            type        TEXT,
            embedding   BLOB,
            embedding_model TEXT,
            embedding_dimensions INTEGER,
            tags        TEXT,
            metadata    TEXT
        );
        INSERT INTO memory_entries(id, key, namespace, content, tags) VALUES
            ('1', 'past1', 'findings',
             'fixed IDOR vuln in bulk-triage endpoint, added auth check', 'idor,auth,api'),
            ('2', 'past2', 'findings',
             'patched SQL injection in user search endpoint', 'sql,injection,api'),
            ('3', 'past3', 'findings',
             'rebuilt the dashboard component with React useQuery', 'ui,react,dashboard');
        """
    )
    conn.commit()
    conn.close()
    return AgentRoutingAdvisor(qtable_path=qpath, agentdb_path=agentdb)


# ---------------------------------------------------------------------------
# Test 1 — keyword routing routes a security task to backend-hardener
# ---------------------------------------------------------------------------


def test_security_task_routes_to_backend_hardener(advisor: AgentRoutingAdvisor) -> None:
    decision = advisor.route("fix the bulk-triage IDOR vuln in the API router")

    assert decision.agent == "backend-hardener", (
        f"expected backend-hardener, got {decision.agent}. "
        f"reasoning={decision.reasoning}"
    )
    assert decision.tier == "sonnet"
    assert 0.0 <= decision.confidence <= 1.0
    # State must be deterministic
    assert decision.state == _state_from_task(
        "fix the bulk-triage IDOR vuln in the API router"
    )
    # Round-trip JSON-shaped output works
    payload = decision.to_dict()
    assert json.dumps(payload), "decision must be JSON-serialisable"
    assert payload["agent"] == "backend-hardener"
    assert isinstance(payload["alternatives"], list)
    assert payload["explored"] is True  # cold start


def test_frontend_task_routes_to_frontend_craftsman(advisor: AgentRoutingAdvisor) -> None:
    decision = advisor.route("rebuild the dashboard React component using useQuery")
    assert decision.agent == "frontend-craftsman"
    assert decision.tier == "sonnet"


def test_doc_task_routes_to_technical_writer(advisor: AgentRoutingAdvisor) -> None:
    decision = advisor.route("write documentation guide for the new API endpoints")
    assert decision.agent == "technical-writer"
    assert decision.tier == "haiku-junior"


# ---------------------------------------------------------------------------
# Test 2 — Q-learning updates change routing after enough negative feedback
# ---------------------------------------------------------------------------


def test_qlearning_updates_change_routing_with_feedback(
    advisor: AgentRoutingAdvisor,
) -> None:
    task = "harden the secrets scanner against malicious input"

    # Initial routing
    first = advisor.route(task)
    assert first.agent in AGENT_REGISTRY
    initial_agent = first.agent

    # Hammer the chosen agent with failures so its Q drops well below others.
    for _ in range(8):
        out = advisor.record_outcome(task, initial_agent, success=False)
        assert out["reward"] == -1.0
        assert out["agent"] == initial_agent
    # Q-value should now be strongly negative for that (state, action)
    q_after_fail, visits_after_fail = advisor._qtable.get(
        first.state, initial_agent
    )
    assert q_after_fail < -0.3, q_after_fail
    assert visits_after_fail == 8

    # Reward a different but reasonable agent for the same state
    runner_up = first.alternatives[0][0] if first.alternatives else "qa-engineer"
    for _ in range(5):
        advisor.record_outcome(task, runner_up, success=True)

    second = advisor.route(task)
    # The advisor should no longer recommend the punished agent
    assert second.agent != initial_agent, (
        f"expected route to switch away from {initial_agent} "
        f"after 8 failures, but advisor still picks it. "
        f"q_after_fail={q_after_fail}, alts={second.alternatives}"
    )

    # And history should reflect 13 total dispatches
    stats = advisor.stats()
    assert stats["history_total"] == 13
    assert stats["history_wins"] == 5
    assert stats["history_losses"] == 8


# ---------------------------------------------------------------------------
# Test 3 — AgentDB integration surfaces similar past tasks; absent gracefully
# ---------------------------------------------------------------------------


def test_agentdb_similar_tasks_surfaced(
    advisor_with_agentdb: AgentRoutingAdvisor,
) -> None:
    decision = advisor_with_agentdb.route(
        "fix bulk-triage IDOR vuln, add auth"
    )
    assert decision.agent == "backend-hardener"
    # The seeded AgentDB row about IDOR + auth must be top-1
    assert decision.similar, "expected at least one similar past task from AgentDB"
    top = decision.similar[0]
    assert "IDOR" in top.snippet or "idor" in top.snippet.lower() or \
           "injection" in top.snippet.lower(), top.snippet
    # Real schema fields are populated
    assert top.namespace == "findings"
    assert top.score > 0
    # And reasoning string mentions AgentDB
    assert "AgentDB" in decision.reasoning


def test_agentdb_absent_falls_back_gracefully(advisor: AgentRoutingAdvisor) -> None:
    # advisor fixture points at a non-existent AgentDB
    decision = advisor.route("fix the bulk-triage IDOR vuln")
    assert decision.similar == []
    assert "AgentDB unavailable" in decision.reasoning
    # Routing still works
    assert decision.agent == "backend-hardener"


# ---------------------------------------------------------------------------
# Bonus invariants worth nailing down
# ---------------------------------------------------------------------------


def test_state_is_deterministic_and_keyword_sorted() -> None:
    s1 = _state_from_task("Fix the bulk-triage IDOR vuln in the API router")
    s2 = _state_from_task("vuln, IDOR API bulk-triage router fix")
    # Word reordering shouldn't change the state (within stop-word filter)
    assert s1 == s2 or set(s1.split("|")) == set(s2.split("|"))
    keys = _extract_keywords("Fix the bulk-triage IDOR vuln in the API router")
    assert keys == sorted(keys)
    assert len(keys) <= 5


def test_invalid_task_raises(advisor: AgentRoutingAdvisor) -> None:
    with pytest.raises(ValueError):
        advisor.route("")
    with pytest.raises(ValueError):
        advisor.route("   ")
    with pytest.raises(ValueError):
        advisor.route(None)  # type: ignore[arg-type]


def test_unknown_agent_in_record_outcome_raises(advisor: AgentRoutingAdvisor) -> None:
    with pytest.raises(ValueError):
        advisor.record_outcome("a task", "nope-not-an-agent", success=True)
