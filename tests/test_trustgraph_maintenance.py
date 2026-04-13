"""Tests for TrustGraph Knowledge Core Maintenance Agent.

Covers:
- Full sweep on empty store returns no issues
- Orphan detection finds entities with no relationships
- Duplicate detection
- Staleness detection with mocked timestamps
- Auto-fix in dry_run mode
- Core health scores
- Contradiction detection
- Missing field detection
- Type consistency checks
- MaintenanceReport dataclass helpers
- Router-level model structure
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List

import pytest

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_db(tmp_path):
    """Create a temporary SQLite DB path."""
    return str(tmp_path / "test_trustgraph.db")


@pytest.fixture
def agent(tmp_db):
    """Return a TrustGraphMaintenanceAgent pointing at a fresh DB."""
    from trustgraph.maintenance_agent import TrustGraphMaintenanceAgent
    return TrustGraphMaintenanceAgent(db_path=tmp_db)


@pytest.fixture
def store(tmp_db):
    """Return a KnowledgeStore pointing at the same DB."""
    from trustgraph.knowledge_store import KnowledgeStore
    return KnowledgeStore(db_path=tmp_db)


@pytest.fixture
def agent_and_store(tmp_db):
    """Return both agent and store sharing the same DB."""
    from trustgraph.maintenance_agent import TrustGraphMaintenanceAgent
    from trustgraph.knowledge_store import KnowledgeStore
    a = TrustGraphMaintenanceAgent(db_path=tmp_db)
    s = KnowledgeStore(db_path=tmp_db)
    return a, s


# ---------------------------------------------------------------------------
# Helper builders
# ---------------------------------------------------------------------------

def _make_entity(
    entity_id: str,
    core_id: int,
    entity_type: str = "Finding",
    name: str = "Test Entity",
    properties: Dict[str, Any] = None,
    org_id: str = "default",
):
    from trustgraph.knowledge_store import KnowledgeEntity
    return KnowledgeEntity(
        entity_id=entity_id,
        core_id=core_id,
        entity_type=entity_type,
        name=name,
        properties=properties or {},
        org_id=org_id,
    )


def _make_rel(rel_id: str, source_id: str, target_id: str, rel_type: str = "related_to"):
    from trustgraph.knowledge_store import KnowledgeRelationship
    return KnowledgeRelationship(
        rel_id=rel_id,
        source_id=source_id,
        target_id=target_id,
        rel_type=rel_type,
    )


# ---------------------------------------------------------------------------
# 1. Full sweep on empty store returns no issues
# ---------------------------------------------------------------------------


def test_full_sweep_empty_store(agent):
    report = agent.run_full_sweep()
    assert report.issue_count == 0
    assert report.issues == []
    assert report.cores_checked == [1, 2, 3, 4, 5]
    assert report.duration_ms >= 0


def test_full_sweep_empty_store_stats_empty(agent):
    report = agent.run_full_sweep()
    assert report.stats == {}


# ---------------------------------------------------------------------------
# 2. Orphan detection
# ---------------------------------------------------------------------------


def test_orphan_detection_finds_unconnected_entity(agent_and_store):
    agent, store = agent_and_store
    store.ingest(_make_entity("finding_001", core_id=2, entity_type="Finding",
                               properties={"severity": "high"}))
    issues = agent.find_orphaned_entities()
    assert len(issues) == 1
    assert issues[0].entity_id == "finding_001"
    assert issues[0].issue_type == "orphan"
    assert issues[0].severity == "medium"


def test_orphan_detection_skips_connected_entity(agent_and_store):
    agent, store = agent_and_store
    store.ingest(_make_entity("finding_001", core_id=2, entity_type="Finding",
                               properties={"severity": "high"}))
    store.ingest(_make_entity("asset_001", core_id=1, entity_type="Asset"))
    store.add_relationship(_make_rel("rel_001", "finding_001", "asset_001"))

    issues = agent.find_orphaned_entities()
    entity_ids = [i.entity_id for i in issues]
    assert "finding_001" not in entity_ids
    assert "asset_001" not in entity_ids


def test_orphan_detection_multiple_cores(agent_and_store):
    agent, store = agent_and_store
    # Ingest 3 orphans in different cores
    store.ingest(_make_entity("e1", core_id=1, entity_type="Asset"))
    store.ingest(_make_entity("e2", core_id=2, entity_type="Finding",
                               properties={"severity": "low"}))
    store.ingest(_make_entity("e3", core_id=3, entity_type="Control"))

    issues = agent.find_orphaned_entities()
    assert len(issues) == 3
    ids = {i.entity_id for i in issues}
    assert ids == {"e1", "e2", "e3"}


# ---------------------------------------------------------------------------
# 3. Duplicate detection
# ---------------------------------------------------------------------------


def test_duplicate_detection_finds_dupes(agent_and_store):
    agent, store = agent_and_store
    props = {"source": "bandit", "rule": "B101", "file": "app.py", "severity": "high"}
    store.ingest(_make_entity("f1", core_id=2, properties=props))
    store.ingest(_make_entity("f2", core_id=2, properties=props))
    store.ingest(_make_entity("f3", core_id=2, properties=props))

    issues = agent.detect_duplicates()
    assert len(issues) == 2  # f2 and f3 are duplicates of f1
    assert all(i.issue_type == "duplicate" for i in issues)
    assert all(i.core_id == 2 for i in issues)


def test_duplicate_detection_no_dupes(agent_and_store):
    agent, store = agent_and_store
    store.ingest(_make_entity("f1", core_id=2,
                               properties={"source": "bandit", "rule": "B101",
                                           "file": "a.py", "severity": "high"}))
    store.ingest(_make_entity("f2", core_id=2,
                               properties={"source": "bandit", "rule": "B102",
                                           "file": "a.py", "severity": "medium"}))

    issues = agent.detect_duplicates()
    assert len(issues) == 0


def test_duplicate_detection_different_files_not_dupes(agent_and_store):
    agent, store = agent_and_store
    store.ingest(_make_entity("f1", core_id=2,
                               properties={"source": "semgrep", "rule": "sql-injection",
                                           "file": "a.py", "severity": "high"}))
    store.ingest(_make_entity("f2", core_id=2,
                               properties={"source": "semgrep", "rule": "sql-injection",
                                           "file": "b.py", "severity": "high"}))

    issues = agent.detect_duplicates()
    assert len(issues) == 0


# ---------------------------------------------------------------------------
# 4. Staleness detection with mocked timestamps
# ---------------------------------------------------------------------------


def test_staleness_detection_finds_old_entities(agent_and_store, tmp_db):
    agent, store = agent_and_store

    store.ingest(_make_entity("old_entity", core_id=1, entity_type="Asset"))

    # Backdate updated_at in the DB directly
    old_ts = (datetime.utcnow() - timedelta(days=45)).isoformat()
    conn = sqlite3.connect(tmp_db)
    conn.execute("UPDATE entities SET updated_at = ? WHERE entity_id = 'old_entity'", (old_ts,))
    conn.commit()
    conn.close()

    issues = agent.check_staleness(days=30)
    assert len(issues) == 1
    assert issues[0].entity_id == "old_entity"
    assert issues[0].issue_type == "stale"
    assert issues[0].severity == "low"


def test_staleness_detection_skips_fresh_entities(agent_and_store):
    agent, store = agent_and_store
    store.ingest(_make_entity("fresh_entity", core_id=1, entity_type="Asset"))
    issues = agent.check_staleness(days=30)
    assert len(issues) == 0


def test_staleness_detection_custom_threshold(agent_and_store, tmp_db):
    agent, store = agent_and_store
    store.ingest(_make_entity("entity_10d", core_id=1, entity_type="Asset"))

    # Backdate to 15 days ago
    ts_15d = (datetime.utcnow() - timedelta(days=15)).isoformat()
    conn = sqlite3.connect(tmp_db)
    conn.execute("UPDATE entities SET updated_at = ? WHERE entity_id = 'entity_10d'", (ts_15d,))
    conn.commit()
    conn.close()

    # With threshold=7 days: should be stale
    issues_7 = agent.check_staleness(days=7)
    assert len(issues_7) == 1

    # With threshold=30 days: should NOT be stale
    issues_30 = agent.check_staleness(days=30)
    assert len(issues_30) == 0


# ---------------------------------------------------------------------------
# 5. Auto-fix in dry_run mode
# ---------------------------------------------------------------------------


def test_auto_fix_dry_run_orphan(agent_and_store):
    agent, store = agent_and_store
    store.ingest(_make_entity("orphan_001", core_id=2, entity_type="Finding",
                               properties={"severity": "high"}))

    issues = agent.find_orphaned_entities()
    assert len(issues) == 1

    result = agent.auto_fix(issues, dry_run=True)
    assert result["dry_run"] is True
    assert result["fixes_applied"] == 1
    assert result["errors"] == 0

    # Verify nothing was actually written
    conn = sqlite3.connect(agent.db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT COUNT(*) as cnt FROM relationships WHERE source_id = 'orphan_001'"
    ).fetchone()
    conn.close()
    assert row["cnt"] == 0  # dry_run: no relationship created


def test_auto_fix_dry_run_duplicate(agent_and_store):
    agent, store = agent_and_store
    props = {"source": "trivy", "rule": "CVE-2021-1234", "file": "go.sum", "severity": "critical"}
    store.ingest(_make_entity("d1", core_id=2, properties=props))
    store.ingest(_make_entity("d2", core_id=2, properties=props))

    issues = agent.detect_duplicates()
    assert len(issues) == 1  # d2 is duplicate of d1

    result = agent.auto_fix(issues, dry_run=True)
    assert result["dry_run"] is True
    assert result["fixes_applied"] == 1

    # Verify d2 not actually deleted
    conn = sqlite3.connect(agent.db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT deleted_at FROM entities WHERE entity_id = 'd2'"
    ).fetchone()
    conn.close()
    assert row["deleted_at"] is None  # dry_run: not deleted


def test_auto_fix_skips_non_fixable_types(agent_and_store, tmp_db):
    agent, store = agent_and_store
    from trustgraph.maintenance_agent import MaintenanceIssue

    # Create a contradiction issue (non-fixable)
    non_fixable = MaintenanceIssue(
        severity="high",
        issue_type="contradiction",
        entity_id="e1",
        description="test",
        suggested_fix="manual",
    )
    result = agent.auto_fix([non_fixable], dry_run=True)
    assert result["fixes_applied"] == 0
    assert result["fixes_skipped"] == 1


# ---------------------------------------------------------------------------
# 6. Core health scores
# ---------------------------------------------------------------------------


def test_core_health_no_db_returns_zero_scores(agent):
    # DB file does not exist yet — should return score=0 for all cores
    health = agent.get_core_health()
    assert set(health.keys()) == {"1", "2", "3", "4", "5"}
    for core_key in health:
        assert health[core_key]["score"] == 0


def test_core_health_empty_db(agent_and_store):
    # DB exists (KnowledgeStore created it) but has no entities
    agent, store = agent_and_store
    health = agent.get_core_health()
    assert set(health.keys()) == {"1", "2", "3", "4", "5"}
    for core_key in health:
        assert health[core_key]["score"] == 0
        assert health[core_key]["reason"] == "no_entities"


def test_core_health_connected_entities_score_high(agent_and_store):
    agent, store = agent_and_store

    # Ingest connected entities in Core 1
    store.ingest(_make_entity("a1", core_id=1, entity_type="Asset"))
    store.ingest(_make_entity("a2", core_id=1, entity_type="Asset"))
    store.add_relationship(_make_rel("r1", "a1", "a2"))

    health = agent.get_core_health()
    core1 = health["1"]
    assert core1["score"] > 60  # Both connected, no staleness, no missing fields
    assert core1["total_entities"] == 2
    assert core1["connected_pct"] == 100.0


def test_core_health_score_range(agent_and_store):
    agent, store = agent_and_store
    store.ingest(_make_entity("f1", core_id=2, entity_type="Finding",
                               properties={"severity": "high"}))
    health = agent.get_core_health()
    for core_key, core_data in health.items():
        assert 0 <= core_data["score"] <= 100


def test_core_health_returns_all_five_cores(agent_and_store):
    agent, store = agent_and_store
    store.ingest(_make_entity("e1", core_id=3, entity_type="Control"))
    health = agent.get_core_health()
    assert len(health) == 5
    assert all(str(c) in health for c in [1, 2, 3, 4, 5])


# ---------------------------------------------------------------------------
# 7. MaintenanceReport helpers
# ---------------------------------------------------------------------------


def test_report_issue_counts(agent_and_store):
    agent, store = agent_and_store

    # Ingest orphan to generate at least one issue
    store.ingest(_make_entity("e1", core_id=1, entity_type="Asset"))

    report = agent.run_full_sweep()
    assert report.issue_count == len(report.issues)
    assert report.critical_count == sum(1 for i in report.issues if i.severity == "critical")
    assert report.high_count == sum(1 for i in report.issues if i.severity == "high")


def test_report_to_dict_serializable(agent):
    report = agent.run_full_sweep()
    d = report.to_dict()
    # Must be JSON-serialisable
    serialized = json.dumps(d)
    assert "checked_at" in serialized
    assert "cores_checked" in serialized
    assert "issues" in serialized


def test_maintenance_issue_to_dict(agent_and_store):
    agent, store = agent_and_store
    store.ingest(_make_entity("e1", core_id=2, entity_type="Finding",
                               properties={"severity": "low"}))

    issues = agent.find_orphaned_entities()
    assert len(issues) >= 1
    d = issues[0].to_dict()
    assert "issue_id" in d
    assert "severity" in d
    assert "issue_type" in d
    assert "entity_id" in d
    assert d["issue_type"] == "orphan"


# ---------------------------------------------------------------------------
# 8. Missing field detection
# ---------------------------------------------------------------------------


def test_missing_field_finds_findings_without_severity(agent_and_store):
    agent, store = agent_and_store
    # Finding with no severity
    store.ingest(_make_entity("f1", core_id=2, entity_type="Finding", properties={}))

    issues = agent._check_missing_fields()
    assert any(i.entity_id == "f1" and i.issue_type == "missing_field" for i in issues)


def test_missing_field_passes_for_finding_with_severity(agent_and_store):
    agent, store = agent_and_store
    store.ingest(_make_entity("f1", core_id=2, entity_type="Finding",
                               properties={"severity": "high"}))
    issues = agent._check_missing_fields()
    assert all(i.entity_id != "f1" for i in issues)


# ---------------------------------------------------------------------------
# 9. Type consistency checks
# ---------------------------------------------------------------------------


def test_type_mismatch_finds_wrong_type_in_core(agent_and_store):
    agent, store = agent_and_store
    # "Decision" in Core 2 (Threat Intel) — expected types are Finding/CVE etc.
    store.ingest(_make_entity("wrong_type", core_id=2, entity_type="Decision",
                               properties={"severity": "low"}))
    issues = agent._check_type_consistency()
    assert any(i.entity_id == "wrong_type" and i.issue_type == "type_mismatch" for i in issues)


def test_type_mismatch_passes_for_correct_type(agent_and_store):
    agent, store = agent_and_store
    store.ingest(_make_entity("correct_type", core_id=2, entity_type="Finding",
                               properties={"severity": "medium"}))
    issues = agent._check_type_consistency()
    assert all(i.entity_id != "correct_type" for i in issues)


# ---------------------------------------------------------------------------
# 10. Full sweep integrates all checks
# ---------------------------------------------------------------------------


def test_full_sweep_collects_all_issue_types(agent_and_store, tmp_db):
    agent, store = agent_and_store

    # Orphan
    store.ingest(_make_entity("orphan_e", core_id=1, entity_type="Asset"))

    # Missing severity (Core 2)
    store.ingest(_make_entity("no_sev", core_id=2, entity_type="Finding", properties={}))

    # Duplicate
    props = {"source": "gitleaks", "rule": "aws-key", "file": ".env", "severity": "critical"}
    store.ingest(_make_entity("dup1", core_id=2, properties=props))
    store.ingest(_make_entity("dup2", core_id=2, properties=props))

    # Stale
    store.ingest(_make_entity("stale_e", core_id=3, entity_type="Control"))
    old_ts = (datetime.utcnow() - timedelta(days=60)).isoformat()
    conn = sqlite3.connect(tmp_db)
    conn.execute("UPDATE entities SET updated_at = ? WHERE entity_id = 'stale_e'", (old_ts,))
    conn.commit()
    conn.close()

    report = agent.run_full_sweep()
    issue_types = {i.issue_type for i in report.issues}

    assert "orphan" in issue_types
    assert "missing_field" in issue_types
    assert "duplicate" in issue_types
    assert "stale" in issue_types
    assert report.issue_count > 0
    assert "orphan" in report.stats
