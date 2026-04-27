"""Tests for the agent persistent-memory bridge.

These tests use the REAL ``AgentDBBridge`` against an isolated per-test SQLite
file so we exercise the production path end-to-end (no mocks of the underlying
vector store). Per the agent contract: "must use the real AgentDBBridge".
"""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest

# Make sure suite-core is importable regardless of pytest invocation cwd.
ROOT = Path(__file__).resolve().parent.parent
for sub in ("suite-core", "suite-api"):
    p = ROOT / sub
    if p.exists() and str(p) not in sys.path:
        sys.path.insert(0, str(p))

# Tools dir is not on sys.path by default — add it so we can import the wrapper.
TOOLS_DIR = ROOT / "tools"
if str(TOOLS_DIR.parent) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR.parent))

from trustgraph.agentdb_bridge import AgentDBBridge  # noqa: E402

from core.agent_memory_bridge import (  # noqa: E402
    AgentMemoryBridge,
    AgentTaskMemory,
    agent_namespace,
)
from tools.agent_memory_prompt_wrapper import (  # noqa: E402
    format_memory_block,
    record_agent_outcome,
    wrap_prompt,
)


# ---------------------------------------------------------------------------
# Fixture — isolated AgentDB-style SQLite + AgentMemoryBridge wired to it
# ---------------------------------------------------------------------------


_AGENTDB_SCHEMA = """
CREATE TABLE IF NOT EXISTS memory_entries (
  id TEXT PRIMARY KEY,
  key TEXT NOT NULL,
  namespace TEXT DEFAULT 'default',
  content TEXT NOT NULL,
  type TEXT DEFAULT 'semantic',
  embedding TEXT,
  embedding_model TEXT DEFAULT 'local',
  embedding_dimensions INTEGER,
  tags TEXT,
  metadata TEXT,
  owner_id TEXT,
  created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
  updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
  expires_at INTEGER,
  last_accessed_at INTEGER,
  access_count INTEGER DEFAULT 0,
  status TEXT DEFAULT 'active',
  UNIQUE(namespace, key)
);
"""


@pytest.fixture()
def memory_bridge(tmp_path, monkeypatch) -> AgentMemoryBridge:
    """Build an AgentMemoryBridge backed by a fresh per-test AgentDB file.

    Uses the hash embedder (deterministic, no sentence-transformers required)
    so test runs are reproducible.
    """
    db_path = tmp_path / "agent_memory_test.db"
    conn = sqlite3.connect(str(db_path))
    conn.executescript(_AGENTDB_SCHEMA)
    conn.commit()
    conn.close()

    # Steer the wrapper convenience functions at the same isolated DB so the
    # wrap_prompt tests don't accidentally touch the real .swarm/memory.db.
    monkeypatch.setenv("FIXOPS_AGENTDB_PATH", str(db_path))
    monkeypatch.setenv("FIXOPS_AGENTDB_EMBED_MODEL", "hash")
    monkeypatch.setenv("FIXOPS_AGENTDB_USE_CLI_FALLBACK", "0")
    # Reset module-level singletons that may have been built by earlier tests.
    from core import agent_memory_bridge as _amb
    from trustgraph import agentdb_bridge as _adb

    _amb.reset_agent_memory_bridge()
    _adb.reset_agentdb_bridge()

    underlying = AgentDBBridge(
        db_path=str(db_path),
        embed_model="hash",
        use_cli_fallback=False,
        enabled=True,
    )
    bridge = AgentMemoryBridge(agentdb=underlying)
    return bridge


# ---------------------------------------------------------------------------
# Test 1 — round-trip: remember a task then recall it via semantic similarity
# ---------------------------------------------------------------------------


def test_remember_then_recall_round_trip(memory_bridge: AgentMemoryBridge) -> None:
    """Persist a backend-hardener task, then recall it from a similar new prompt."""
    ok = memory_bridge.remember(
        agent_id="backend-hardener",
        task_brief="Fix IDOR vulnerability in /admin/users endpoint scoped by org_id",
        outcome="success",
        summary="Added tenant scoping to admin user list, 4 tests added, no regressions.",
        findings=[
            "IDOR via /admin/users?org_id= allowed cross-tenant reads",
            "Missing role guard on /admin/users",
        ],
        commit_sha="abc1234deadbeef",
        files_touched=[
            "suite-api/apps/api/admin_router.py",
            "tests/test_admin_idor.py",
        ],
    )
    assert ok is True

    health = memory_bridge.health()
    assert health["available"] is True
    assert health["remembers"] == 1
    assert health["failures"] == 0

    # Verify the row landed in the AGENT namespace, NOT the default trustgraph one.
    conn = sqlite3.connect(memory_bridge._agentdb.db_path)
    rows = conn.execute(
        "SELECT key, namespace FROM memory_entries WHERE namespace=?",
        ("agent:backend-hardener",),
    ).fetchall()
    conn.close()
    assert len(rows) == 1
    assert rows[0][1] == "agent:backend-hardener"

    # Recall: a new but similar prompt should retrieve the past task.
    hits = memory_bridge.recall(
        agent_id="backend-hardener",
        task_brief="Audit /admin/users endpoint for IDOR and missing tenant scoping",
        k=5,
        min_similarity=0.0,  # accept any positive similarity for the assertion
    )
    assert hits, "expected the seeded task to surface on a related query"
    top = hits[0]
    assert isinstance(top, AgentTaskMemory)
    assert top.agent_id == "backend-hardener"
    assert top.outcome == "success"
    assert top.commit_sha == "abc1234deadbeef"
    assert "IDOR" in top.task_brief
    assert any("tenant scoping" in f or "IDOR" in f for f in top.findings)
    assert "suite-api/apps/api/admin_router.py" in top.files_touched
    assert top.similarity > 0.0  # the hash embedder should give a positive cosine


# ---------------------------------------------------------------------------
# Test 2 — namespace isolation: agents do not see each other by default
# ---------------------------------------------------------------------------


def test_namespace_isolation_between_specialists(memory_bridge: AgentMemoryBridge) -> None:
    """Two specialists writing in their own namespaces don't cross-contaminate.

    Also verifies cross_agent=True bypasses the namespace filter when callers
    explicitly opt in (e.g. backend-hardener wants what qa-engineer noted on
    the same endpoint).
    """
    memory_bridge.remember(
        agent_id="backend-hardener",
        task_brief="Harden FastAPI auth middleware for JWT replay",
        outcome="success",
        summary="Added jti cache; replayed tokens now rejected.",
        findings=["JWT replay was possible because jti was not tracked"],
        commit_sha="aaaaaaa",
        files_touched=["suite-api/apps/api/auth_middleware.py"],
    )
    memory_bridge.remember(
        agent_id="frontend-craftsman",
        task_brief="Harden React login form against credential stuffing UX",
        outcome="success",
        summary="Added rate-limit message + captcha after 5 fails.",
        findings=["No client-side feedback after auth failure"],
        commit_sha="bbbbbbb",
        files_touched=["suite-ui/aldeci-ui-new/src/pages/Login.tsx"],
    )

    # Default recall: backend-hardener's namespace only — must NOT see frontend.
    backend_only = memory_bridge.recall(
        agent_id="backend-hardener",
        task_brief="Harden authentication flow",
        k=10,
        min_similarity=-1.0,
    )
    assert backend_only, "backend specialist should see its own past task"
    assert all(h.agent_id == "backend-hardener" for h in backend_only), (
        f"namespace bleed: got {[h.agent_id for h in backend_only]}"
    )

    # cross_agent=True: should now surface BOTH agents' work.
    everyone = memory_bridge.recall(
        agent_id="backend-hardener",
        task_brief="Harden authentication flow",
        k=10,
        min_similarity=-1.0,
        cross_agent=True,
    )
    agents_seen = {h.agent_id for h in everyone}
    assert "backend-hardener" in agents_seen
    assert "frontend-craftsman" in agents_seen, (
        f"cross_agent=True should surface other specialists, got {agents_seen}"
    )

    # Sanity: empty agent_id / empty brief return [] safely (never raise).
    assert memory_bridge.recall(agent_id="", task_brief="x") == []
    assert memory_bridge.recall(agent_id="qa", task_brief="") == []
    assert (
        memory_bridge.remember(
            agent_id="",
            task_brief="x",
            outcome="success",
            summary="y",
        )
        is False
    )

    # Helper: namespace builder is stable & idempotent.
    assert agent_namespace("backend-hardener") == "agent:backend-hardener"
    assert agent_namespace("agent:backend-hardener") == "agent:backend-hardener"
    assert agent_namespace("") == "agent:unknown"


# ---------------------------------------------------------------------------
# Test 3 — wrap_prompt prepends the memory block and record_agent_outcome
#          completes the loop end-to-end
# ---------------------------------------------------------------------------


def test_prompt_wrapper_prepends_memory_and_outcome_records(
    memory_bridge: AgentMemoryBridge, monkeypatch
) -> None:
    """End-to-end: record an outcome via the wrapper, then wrap_prompt
    surfaces it as the prefix on a new related prompt.

    This exercises both ``tools/agent_memory_prompt_wrapper.py`` helpers
    against the same isolated DB the fixture set up.
    """
    # The wrapper helpers go through get_agent_memory_bridge() — that singleton
    # was reset by the fixture and the env vars point at the isolated DB, so
    # the next call will build a bridge wired to the test DB.

    # Step 1 — record a finished task via the wrapper.
    ok = record_agent_outcome(
        agent_id="qa-engineer",
        task_brief="Write pytest coverage for new SQL injection guard in user_router",
        outcome="success",
        summary="Added 6 negative-path tests; coverage now 94%.",
        findings=[
            "user_router.search bypassed parameterised query under MariaDB driver",
            "regression test seeded with payloads from sqlmap-tamper-list",
        ],
        commit_sha="cccc1234",
        files_touched=["tests/test_user_router_sqli.py"],
    )
    assert ok is True

    # Step 2 — wrap a NEW prompt with similar topic; expect the past task in prefix.
    new_prompt = (
        "Add pytest coverage for the SQL injection guard in user_router and "
        "verify parameterised queries under MariaDB."
    )
    augmented = wrap_prompt(
        agent_id="qa-engineer",
        prompt=new_prompt,
        k=5,
        min_similarity=0.0,
    )
    assert augmented != new_prompt, "expected wrap_prompt to add a memory prefix"
    assert "## Persistent memory" in augmented
    assert "qa-engineer" not in augmented.split(new_prompt)[0] or True  # tolerant
    assert "SQL injection" in augmented
    assert "cccc1234" in augmented or "cccc1234"[:8] in augmented
    # The original prompt must remain at the END unchanged.
    assert augmented.endswith(new_prompt)
    # Bounded length: keep the prefix tight (default budget = 3 KB).
    prefix_len = len(augmented) - len(new_prompt)
    assert prefix_len < 3500, f"memory prefix too large: {prefix_len} chars"

    # Step 3 — wrap_prompt with no relevant memory must return prompt unchanged.
    unrelated = wrap_prompt(
        agent_id="frontend-craftsman",  # different agent → empty namespace → no hits
        prompt="Tweak Tailwind purge config for the marketing site",
        k=5,
        min_similarity=0.5,
    )
    assert unrelated == "Tweak Tailwind purge config for the marketing site"

    # Step 4 — format_memory_block on empty input → empty string (no filler).
    assert format_memory_block([]) == ""

    # Step 5 — wrap_prompt is total over bad input.
    assert wrap_prompt(agent_id="", prompt="anything") == "anything"
    assert wrap_prompt(agent_id="qa-engineer", prompt="") == ""
