"""
Tests for TrustGraphQualityMonitor.

Covers:
- get_coverage_report: per-core stats, zero-entity case, missing DB
- find_orphaned_findings: returns orphans, skips connected entities
- find_disconnected_assets: returns unconnected assets, skips connected
- backfill_missing_data: dry_run=True reports only, dry_run=False creates relationships
- get_graph_stats: counts entities, relationships, coverage %, per-core breakdown
- run_quality_checks: all 5 check types (severity, classification, duplicates, stale, disconnected)
"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from trustgraph.knowledge_store import KnowledgeEntity, KnowledgeRelationship, KnowledgeStore
from core.trustgraph_quality_monitor import (
    TrustGraphQualityMonitor,
    CoverageReport,
    BackfillReport,
    GraphStats,
    QualityIssue,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def temp_db(tmp_path):
    """Return path to a temporary SQLite DB file."""
    return str(tmp_path / "tg_quality_test.db")


@pytest.fixture
def store(temp_db):
    """KnowledgeStore backed by temp DB."""
    return KnowledgeStore(db_path=temp_db)


@pytest.fixture
def monitor(temp_db):
    """TrustGraphQualityMonitor backed by same temp DB."""
    return TrustGraphQualityMonitor(db_path=temp_db)


@pytest.fixture
def populated_store_and_monitor(temp_db):
    """Store + monitor with a variety of entities and relationships."""
    store = KnowledgeStore(db_path=temp_db)
    monitor = TrustGraphQualityMonitor(db_path=temp_db)

    # Core 1 — Assets
    store.ingest(KnowledgeEntity(
        entity_id="asset_web_01", core_id=1, entity_type="Service",
        name="Web Server", properties={"criticality": "high"},
    ))
    store.ingest(KnowledgeEntity(
        entity_id="asset_db_01", core_id=1, entity_type="Asset",
        name="Database", properties={},  # no classification
    ))

    # Core 2 — Findings
    store.ingest(KnowledgeEntity(
        entity_id="finding_001", core_id=2, entity_type="CVE",
        name="CVE-2024-001", properties={"severity": "critical", "source": "snyk", "rule": "r1", "file": "foo.py"},
    ))
    store.ingest(KnowledgeEntity(
        entity_id="finding_002", core_id=2, entity_type="Finding",
        name="SQL Injection", properties={},  # no severity
    ))

    # Core 3 — Compliance
    store.ingest(KnowledgeEntity(
        entity_id="ctrl_001", core_id=3, entity_type="Control",
        name="AC-2", properties={"framework": "NIST"},
    ))

    # Core 4 — Incidents
    store.ingest(KnowledgeEntity(
        entity_id="inc_001", core_id=4, entity_type="Incident",
        name="Incident 1", properties={"status": "open"},
    ))

    # Core 5 — Risks
    store.ingest(KnowledgeEntity(
        entity_id="risk_001", core_id=5, entity_type="Risk",
        name="Risk 1", properties={"score": 7},
    ))

    # Connect asset_web_01 to finding_001 (both get a relationship)
    store.add_relationship(KnowledgeRelationship(
        rel_id="rel_001",
        source_id="asset_web_01",
        target_id="finding_001",
        rel_type="has_finding",
        confidence=0.9,
    ))

    return store, monitor


# ============================================================================
# Tests: get_coverage_report
# ============================================================================


def test_coverage_report_missing_db(tmp_path):
    """Coverage report on non-existent DB returns zero-entity report."""
    monitor = TrustGraphQualityMonitor(db_path=str(tmp_path / "nonexistent.db"))
    report = monitor.get_coverage_report()
    assert isinstance(report, CoverageReport)
    assert report.total_entities == 0
    assert report.total_coverage_pct == 0.0
    assert len(report.cores) == 5


def test_coverage_report_empty_store(monitor):
    """Coverage report on empty DB returns all-zero core stats."""
    report = monitor.get_coverage_report()
    assert report.total_entities == 0
    assert report.orphaned_count == 0
    for core_id in range(1, 6):
        assert report.cores[core_id].total_entities == 0


def test_coverage_report_with_data(populated_store_and_monitor):
    """Coverage report counts entities and connected entities per core."""
    _, monitor = populated_store_and_monitor
    report = monitor.get_coverage_report()

    assert report.total_entities == 7  # 2+2+1+1+1
    # Core 1: 2 entities, 1 connected (asset_web_01)
    assert report.cores[1].total_entities == 2
    assert report.cores[1].connected_entities == 1
    assert report.cores[1].orphaned_entities == 1
    # Core 2: 2 entities, 1 connected (finding_001)
    assert report.cores[2].total_entities == 2
    assert report.cores[2].connected_entities == 1
    assert report.cores[2].coverage_pct == 50.0


def test_coverage_report_last_checked(monitor):
    """last_checked is a valid ISO datetime string."""
    report = monitor.get_coverage_report()
    dt = datetime.fromisoformat(report.last_checked)
    assert dt is not None


def test_coverage_report_to_dict(populated_store_and_monitor):
    """to_dict serializes without error and contains expected keys."""
    _, monitor = populated_store_and_monitor
    report = monitor.get_coverage_report()
    d = report.to_dict()
    assert "cores" in d
    assert "total_coverage_pct" in d
    assert "orphaned_count" in d


# ============================================================================
# Tests: find_orphaned_findings
# ============================================================================


def test_find_orphaned_findings_empty(monitor):
    """Empty store returns empty list."""
    assert monitor.find_orphaned_findings() == []


def test_find_orphaned_findings_returns_orphan(populated_store_and_monitor):
    """finding_002 (no relationships) appears in orphan list."""
    _, monitor = populated_store_and_monitor
    orphans = monitor.find_orphaned_findings()
    ids = [o["entity_id"] for o in orphans]
    assert "finding_002" in ids


def test_find_orphaned_findings_excludes_connected(populated_store_and_monitor):
    """finding_001 (has a relationship) does NOT appear in orphan list."""
    _, monitor = populated_store_and_monitor
    orphans = monitor.find_orphaned_findings()
    ids = [o["entity_id"] for o in orphans]
    assert "finding_001" not in ids


def test_find_orphaned_findings_schema(populated_store_and_monitor):
    """Each orphan has required keys."""
    _, monitor = populated_store_and_monitor
    orphans = monitor.find_orphaned_findings()
    for orphan in orphans:
        assert "entity_id" in orphan
        assert "entity_type" in orphan
        assert "name" in orphan
        assert "core_id" in orphan
        assert orphan["core_id"] == 2


# ============================================================================
# Tests: find_disconnected_assets
# ============================================================================


def test_find_disconnected_assets_empty(monitor):
    """Empty store returns empty list."""
    assert monitor.find_disconnected_assets() == []


def test_find_disconnected_assets_returns_asset(populated_store_and_monitor):
    """asset_db_01 (no relationships) appears in disconnected list."""
    _, monitor = populated_store_and_monitor
    disconnected = monitor.find_disconnected_assets()
    ids = [a["entity_id"] for a in disconnected]
    assert "asset_db_01" in ids


def test_find_disconnected_assets_excludes_connected(populated_store_and_monitor):
    """asset_web_01 (has a relationship) NOT in disconnected list."""
    _, monitor = populated_store_and_monitor
    disconnected = monitor.find_disconnected_assets()
    ids = [a["entity_id"] for a in disconnected]
    assert "asset_web_01" not in ids


# ============================================================================
# Tests: backfill_missing_data
# ============================================================================


def test_backfill_dry_run_no_writes(populated_store_and_monitor, temp_db):
    """dry_run=True does not create relationships in the DB."""
    import sqlite3
    store, monitor = populated_store_and_monitor

    # Count relationships before
    conn = sqlite3.connect(temp_db)
    before = conn.execute("SELECT COUNT(*) FROM relationships").fetchone()[0]
    conn.close()

    report = monitor.backfill_missing_data(dry_run=True)
    assert isinstance(report, BackfillReport)
    assert report.dry_run is True
    assert report.actually_indexed == 0

    # Count relationships after — must be same
    conn = sqlite3.connect(temp_db)
    after = conn.execute("SELECT COUNT(*) FROM relationships").fetchone()[0]
    conn.close()
    assert before == after


def test_backfill_dry_run_reports_would_index(populated_store_and_monitor):
    """dry_run=True populates would_index with orphan count."""
    _, monitor = populated_store_and_monitor
    report = monitor.backfill_missing_data(dry_run=True)
    # 2 orphans: asset_db_01 (core 1) + finding_002 (core 2)
    assert report.would_index >= 2


def test_backfill_live_creates_relationships(populated_store_and_monitor, temp_db):
    """dry_run=False actually creates relationships for orphaned entities."""
    import sqlite3
    store, monitor = populated_store_and_monitor

    conn = sqlite3.connect(temp_db)
    before = conn.execute("SELECT COUNT(*) FROM relationships").fetchone()[0]
    conn.close()

    report = monitor.backfill_missing_data(dry_run=False)
    assert report.dry_run is False
    assert report.actually_indexed > 0

    conn = sqlite3.connect(temp_db)
    after = conn.execute("SELECT COUNT(*) FROM relationships").fetchone()[0]
    conn.close()
    assert after > before


def test_backfill_missing_db(tmp_path):
    """Backfill on missing DB returns zero-count report without error."""
    monitor = TrustGraphQualityMonitor(db_path=str(tmp_path / "no.db"))
    report = monitor.backfill_missing_data(dry_run=True)
    assert report.would_index == 0
    assert report.errors == 0


# ============================================================================
# Tests: get_graph_stats
# ============================================================================


def test_get_graph_stats_empty(monitor):
    """Empty store returns zero stats."""
    stats = monitor.get_graph_stats()
    assert isinstance(stats, GraphStats)
    assert stats.total_entities == 0
    assert stats.total_relationships == 0
    assert stats.coverage_pct == 0.0


def test_get_graph_stats_with_data(populated_store_and_monitor):
    """Stats reflect entities and relationships in store."""
    _, monitor = populated_store_and_monitor
    stats = monitor.get_graph_stats()
    assert stats.total_entities == 7
    assert stats.total_relationships == 1
    assert stats.orphaned_count == 5  # 5 unconnected entities
    assert stats.coverage_pct == pytest.approx(100.0 * 2 / 7, abs=0.1)


def test_get_graph_stats_db_path(monitor, temp_db):
    """db_path in stats matches monitor's db_path."""
    stats = monitor.get_graph_stats()
    assert stats.db_path == temp_db


# ============================================================================
# Tests: run_quality_checks
# ============================================================================


def test_quality_checks_empty_db(monitor):
    """Quality checks on empty store return empty list (nothing to flag)."""
    issues = monitor.run_quality_checks()
    assert isinstance(issues, list)
    assert len(issues) == 0


def test_quality_check_missing_severity(populated_store_and_monitor):
    """Detects finding_002 which has no severity."""
    _, monitor = populated_store_and_monitor
    issues = monitor.run_quality_checks()
    types = [i.type for i in issues]
    assert "missing_severity" in types


def test_quality_check_missing_classification(populated_store_and_monitor):
    """Detects asset_db_01 which has no classification or criticality."""
    _, monitor = populated_store_and_monitor
    issues = monitor.run_quality_checks()
    types = [i.type for i in issues]
    assert "missing_classification" in types


def test_quality_check_disconnected_entities(populated_store_and_monitor):
    """Detects disconnected entities (orphans in any core)."""
    _, monitor = populated_store_and_monitor
    issues = monitor.run_quality_checks()
    types = [i.type for i in issues]
    assert "disconnected_entities" in types


def test_quality_check_stale_entities(temp_db):
    """Detects stale entities older than 30 days."""
    store = KnowledgeStore(db_path=temp_db)
    monitor = TrustGraphQualityMonitor(db_path=temp_db)

    old_date = (datetime.utcnow() - timedelta(days=45)).isoformat()

    # Manually insert a stale entity
    import sqlite3
    conn = sqlite3.connect(temp_db)
    conn.execute(
        "INSERT OR REPLACE INTO entities (entity_id, core_id, entity_type, name, properties, created_at, updated_at, org_id) "
        "VALUES ('stale_001', 1, 'Asset', 'Old Asset', '{}', ?, ?, 'default')",
        (old_date, old_date),
    )
    conn.commit()
    conn.close()

    issues = monitor.run_quality_checks()
    types = [i.type for i in issues]
    assert "stale_entities" in types


def test_quality_check_duplicate_findings(temp_db):
    """Detects duplicate findings with same source+rule+file."""
    store = KnowledgeStore(db_path=temp_db)
    monitor = TrustGraphQualityMonitor(db_path=temp_db)

    props = {"severity": "high", "source": "bandit", "rule": "B101", "file": "app.py"}
    for i in range(2):
        store.ingest(KnowledgeEntity(
            entity_id=f"dup_finding_{i}",
            core_id=2,
            entity_type="Finding",
            name=f"Duplicate Finding {i}",
            properties=props,
        ))

    issues = monitor.run_quality_checks()
    types = [i.type for i in issues]
    assert "duplicate_findings" in types


def test_quality_issue_schema(populated_store_and_monitor):
    """Each QualityIssue has required fields and valid severity."""
    _, monitor = populated_store_and_monitor
    issues = monitor.run_quality_checks()
    valid_severities = {"critical", "high", "medium", "low"}
    for issue in issues:
        assert isinstance(issue, QualityIssue)
        assert issue.issue_id
        assert issue.type
        assert issue.severity in valid_severities
        assert issue.entity_count >= 0
        assert isinstance(issue.auto_fixable, bool)
        d = issue.to_dict()
        assert "issue_id" in d
        assert "description" in d


def test_quality_check_missing_db(tmp_path):
    """Quality checks on non-existent DB return empty list."""
    monitor = TrustGraphQualityMonitor(db_path=str(tmp_path / "none.db"))
    issues = monitor.run_quality_checks()
    assert issues == []
