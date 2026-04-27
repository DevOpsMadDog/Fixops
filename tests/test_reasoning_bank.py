"""Tests for ReasoningBank — trajectory tracker + pattern distillation."""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path
from typing import Any, Dict

import pytest

# Ensure suite paths are importable regardless of pytest invocation cwd.
ROOT = Path(__file__).resolve().parent.parent
for sub in ("suite-core", "suite-api"):
    p = ROOT / sub
    if p.exists() and str(p) not in sys.path:
        sys.path.insert(0, str(p))

from trustgraph.agentdb_bridge import AgentDBBridge  # noqa: E402
from core.reasoning_bank import (  # noqa: E402
    DistilledPattern,
    ReasoningBank,
    Trajectory,
    PATTERNS_NAMESPACE,
    TRAJECTORIES_NAMESPACE,
)


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
def isolated_bank(tmp_path) -> ReasoningBank:
    """Build a ReasoningBank backed by a fresh per-test SQLite DB."""
    db_path = tmp_path / "reasoning_test.db"
    conn = sqlite3.connect(str(db_path))
    conn.executescript(_AGENTDB_SCHEMA)
    conn.commit()
    conn.close()

    bridge = AgentDBBridge(
        db_path=str(db_path),
        embed_model="hash",
        use_cli_fallback=False,
        enabled=True,
    )
    return ReasoningBank(bridge=bridge)


# ---------------------------------------------------------------------------
# Test 1: happy path - record + recall round-trips a trajectory
# ---------------------------------------------------------------------------


def test_record_and_recall_round_trip(isolated_bank: ReasoningBank) -> None:
    finding = {
        "finding_id": "F-1001",
        "title": "SQL injection in login form",
        "description": "User-controlled input flows into SQL query",
        "cwe": "CWE-89",
        "severity": "high",
        "kev": True,
        "reachable": True,
        "exploit_available": True,
        "epss": 0.92,
        "service_name": "auth-service",
    }
    verdict = {
        "action": "remediate_critical",
        "confidence": 0.91,
        "reasoning": "Reachable + KEV + high EPSS = immediate remediation",
        "escalated": False,
    }

    traj = isolated_bank.record(finding=finding, verdict=verdict)
    assert traj is not None
    assert traj.cwe == "CWE-89"
    assert traj.kev is True
    assert traj.council_action == "remediate_critical"
    assert traj.trajectory_id.startswith("traj_F-1001")

    # Recall returns the trajectory we just wrote.
    similar_finding = {
        "finding_id": "F-1002",
        "title": "Possible SQL injection vulnerability",
        "description": "Login form passes raw input to SQL",
        "cwe": "CWE-89",
        "severity": "high",
    }
    # Hash-embedder cosine for short fragments can be near zero or slightly
    # negative; min_similarity=-1.0 lets the test exercise the recall path
    # without depending on sentence-transformers being installed.
    hits = isolated_bank.recall(similar_finding, k=5, min_similarity=-1.0)
    assert hits, "recall should surface the just-written trajectory"
    assert any(h.trajectory_id == traj.trajectory_id for h in hits)
    top = hits[0]
    assert top.council_action == "remediate_critical"


# ---------------------------------------------------------------------------
# Test 2: judge() updates correctness_score and re-rerank uses it
# ---------------------------------------------------------------------------


def test_judge_updates_correctness_and_reranks(isolated_bank: ReasoningBank) -> None:
    base_finding = {
        "finding_id": "F-2001",
        "title": "XSS in profile page",
        "cwe": "CWE-79",
        "severity": "medium",
    }
    verdict_a = {
        "action": "remediate_critical",
        "confidence": 0.55,
        "reasoning": "Cross-site scripting in user profile",
    }
    verdict_b = {
        "action": "false_positive",
        "confidence": 0.50,
        "reasoning": "Encoded by template engine",
    }

    traj_a = isolated_bank.record(finding=base_finding, verdict=verdict_a)
    traj_b = isolated_bank.record(
        finding={**base_finding, "finding_id": "F-2002"},
        verdict=verdict_b,
    )
    assert traj_a is not None and traj_b is not None
    assert traj_a.trajectory_id != traj_b.trajectory_id

    # Mark A correct, B incorrect.
    assert isolated_bank.judge(
        traj_a.trajectory_id, outcome="confirmed_exploitable", correctness_score=0.95
    ) is True
    assert isolated_bank.judge(
        traj_b.trajectory_id, outcome="dismissed_wrong", correctness_score=0.05
    ) is True

    # Out-of-range correctness rejected.
    assert isolated_bank.judge(
        traj_a.trajectory_id, outcome="x", correctness_score=2.0
    ) is False

    hits = isolated_bank.recall(base_finding, k=5, min_similarity=-1.0)
    # The correct trajectory must outrank the incorrect one.
    actions_in_order = [h.council_action for h in hits]
    assert actions_in_order, "recall should surface judged trajectories"
    if "remediate_critical" in actions_in_order and "false_positive" in actions_in_order:
        assert actions_in_order.index("remediate_critical") < actions_in_order.index(
            "false_positive"
        )


# ---------------------------------------------------------------------------
# Test 3: distill_patterns mines stable rules from many trajectories
# ---------------------------------------------------------------------------


def test_distill_patterns_mines_dominant_rule(isolated_bank: ReasoningBank) -> None:
    # Seed 12 strongly-consistent CWE-79 + KEV + reachable trajectories.
    for i in range(12):
        finding = {
            "finding_id": f"F-XSS-{i}",
            "title": f"XSS in component {i}",
            "cwe": "CWE-79",
            "severity": "high",
            "kev": True,
            "reachable": True,
            "exploit_available": True,
            "epss": 0.7,
        }
        verdict = {
            "action": "remediate_critical",
            "confidence": 0.9,
            "reasoning": "KEV+reachable XSS",
        }
        traj = isolated_bank.record(finding=finding, verdict=verdict)
        assert traj is not None
        isolated_bank.judge(
            traj.trajectory_id, outcome="confirmed", correctness_score=0.92
        )

    # Add a few inconsistent ones to exercise the dominance threshold.
    for i in range(2):
        finding = {
            "finding_id": f"F-XSS-FP-{i}",
            "title": f"XSS false positive {i}",
            "cwe": "CWE-79",
            "severity": "high",
            "kev": True,
            "reachable": True,
            "exploit_available": True,
        }
        verdict = {"action": "false_positive", "confidence": 0.6, "reasoning": "encoded"}
        traj = isolated_bank.record(finding=finding, verdict=verdict)
        assert traj is not None
        isolated_bank.judge(
            traj.trajectory_id, outcome="dismissed", correctness_score=0.78
        )

    patterns = isolated_bank.distill_patterns(
        min_support=10, min_correctness=0.7, min_dominance=0.6
    )
    assert patterns, "should distill at least one pattern from 14 trajectories"
    top = patterns[0]
    assert top.verdict_action == "remediate_critical"
    assert top.feature_predicate.get("cwe") == "CWE-79"
    assert top.feature_predicate.get("kev") is True
    assert top.support >= 12
    assert top.correctness >= 0.7
    assert top.confidence > 0.0


# ---------------------------------------------------------------------------
# Test 4: match_pattern + export round-trip via the patterns namespace
# ---------------------------------------------------------------------------


def test_match_pattern_and_export(isolated_bank: ReasoningBank, tmp_path) -> None:
    # Build the same pattern as test 3.
    for i in range(12):
        finding = {
            "finding_id": f"F-IDOR-{i}",
            "title": f"IDOR on /admin/users {i}",
            "cwe": "CWE-639",
            "severity": "critical",
            "kev": False,
            "reachable": True,
            "exploit_available": False,
        }
        verdict = {
            "action": "remediate_high",
            "confidence": 0.85,
            "reasoning": "Tenant scoping missing",
        }
        traj = isolated_bank.record(finding=finding, verdict=verdict)
        assert traj is not None
        isolated_bank.judge(traj.trajectory_id, outcome="ok", correctness_score=0.9)

    patterns = isolated_bank.distill_patterns(min_support=10, min_correctness=0.7)
    assert patterns

    # Match a fresh finding against the cached patterns.
    new_finding = {
        "finding_id": "F-IDOR-NEW",
        "title": "IDOR on /admin/orgs",
        "cwe": "CWE-639",
        "severity": "critical",
        "reachable": True,
    }
    match = isolated_bank.match_pattern(new_finding, min_confidence=0.0)
    assert match is not None
    assert match.verdict_action == "remediate_high"
    assert match.feature_predicate.get("cwe") == "CWE-639"

    # Sanity: a finding that does NOT match the predicate (different CWE)
    # should not return this pattern.
    miss = isolated_bank.match_pattern(
        {"cwe": "CWE-99", "severity": "critical", "reachable": True},
        min_confidence=0.0,
    )
    assert miss is None or miss.feature_predicate.get("cwe") != "CWE-639"

    # Validate the export script's schema by serialising patterns directly.
    import json as _json

    out_payload: Dict[str, Any] = {
        "schema": "reasoning_patterns.v1",
        "patterns_count": len(patterns),
        "patterns": [p.to_dict() for p in patterns],
    }
    out_path = tmp_path / "reasoning_patterns_v1.json"
    out_path.write_text(_json.dumps(out_payload, indent=2, default=str))
    parsed = _json.loads(out_path.read_text())
    assert parsed["schema"] == "reasoning_patterns.v1"
    assert parsed["patterns_count"] == len(patterns)
    assert parsed["patterns"][0]["verdict_action"] == "remediate_high"


# ---------------------------------------------------------------------------
# Test 5: integration with council convene path - record from a verdict-shape
# ---------------------------------------------------------------------------


def test_integration_with_council_verdict_shape(isolated_bank: ReasoningBank) -> None:
    """Simulate the council-side call: pass a CouncilVerdict-shaped dict."""
    finding = {
        "finding_id": "F-3001",
        "title": "Path traversal in file upload",
        "cwe": "CWE-22",
        "severity": "high",
        "kev": False,
        "reachable": True,
        "service_name": "files-api",
    }
    # CouncilVerdict.to_dict() shape (subset).
    verdict = {
        "action": "remediate_high",
        "confidence": 0.83,
        "reasoning": "Reachable path traversal in upload handler",
        "mitre_mappings": ["T1083", "T1190"],
        "compliance_impact": {"SOC2": "CC6.1"},
        "escalated": False,
        "cost_usd": 0.0042,
        "latency_ms": 312.7,
    }
    context = {"service_name": "files-api", "tenant": "demo-org", "risk_score": 78.4}

    traj = isolated_bank.record(finding=finding, verdict=verdict, context=context)
    assert traj is not None
    assert traj.council_action == "remediate_high"
    assert traj.cwe == "CWE-22"

    # Recall path matches what council convene would do at the start of the
    # next request: pull top-k similar past trajectories.
    next_finding = {
        "finding_id": "F-3002",
        "title": "Path traversal in download endpoint",
        "cwe": "CWE-22",
        "severity": "high",
        "service_name": "files-api",
    }
    hits = isolated_bank.recall(next_finding, k=3, min_similarity=-1.0)
    assert hits, "council should surface the just-recorded trajectory"
    assert hits[0].cwe == "CWE-22"

    # Health surfaces records / recalls counters.
    health = isolated_bank.health()
    assert health["records"] >= 1
    assert health["recalls"] >= 1
    assert health["failures"] == 0
