"""Tests for AlertTriageEngine.

Covers alert ingestion, priority auto-assignment, triage lifecycle,
bulk triage, queue ordering, and statistics.

Total: 35 tests.
"""

from __future__ import annotations

import os
import pytest
from core.alert_triage_engine import AlertTriageEngine


@pytest.fixture()
def engine(tmp_path):
    db = str(tmp_path / "alert_triage_test.db")
    return AlertTriageEngine(db_path=db)


@pytest.fixture()
def critical_alert(engine):
    return engine.ingest_alert("org1", {
        "title": "Critical breach detected",
        "source_system": "siem",
        "severity": "critical",
    })


@pytest.fixture()
def low_alert(engine):
    return engine.ingest_alert("org1", {
        "title": "Low noise event",
        "source_system": "firewall",
        "severity": "low",
    })


# ===========================================================================
# 1. Initialization
# ===========================================================================

def test_init_creates_db(tmp_path):
    db = str(tmp_path / "at_init.db")
    AlertTriageEngine(db_path=db)
    assert os.path.exists(db)


def test_init_idempotent(tmp_path):
    db = str(tmp_path / "at_idem.db")
    AlertTriageEngine(db_path=db)
    AlertTriageEngine(db_path=db)  # second init should not error


# ===========================================================================
# 2. ingest_alert — priority auto-assignment
# ===========================================================================

def test_ingest_critical_gets_p1(engine):
    alert = engine.ingest_alert("org1", {"title": "A", "source_system": "siem", "severity": "critical"})
    assert alert["priority"] == "p1"


def test_ingest_high_gets_p2(engine):
    alert = engine.ingest_alert("org1", {"title": "A", "source_system": "edr", "severity": "high"})
    assert alert["priority"] == "p2"


def test_ingest_medium_gets_p3(engine):
    alert = engine.ingest_alert("org1", {"title": "A", "source_system": "ndr", "severity": "medium"})
    assert alert["priority"] == "p3"


def test_ingest_low_gets_p4(engine):
    alert = engine.ingest_alert("org1", {"title": "A", "source_system": "cloud", "severity": "low"})
    assert alert["priority"] == "p4"


def test_ingest_info_gets_p4(engine):
    alert = engine.ingest_alert("org1", {"title": "A", "source_system": "waf", "severity": "info"})
    assert alert["priority"] == "p4"


def test_ingest_sets_status_new(engine, critical_alert):
    assert critical_alert["status"] == "new"


def test_ingest_sets_ingested_at(engine, critical_alert):
    assert critical_alert["ingested_at"] is not None


def test_ingest_stores_raw_alert_json(engine):
    raw = {"rule_id": "R001", "score": 95}
    alert = engine.ingest_alert("org1", {
        "title": "Raw test",
        "source_system": "ids",
        "severity": "high",
        "raw_alert_json": raw,
    })
    assert alert["raw_alert_json"] is not None


def test_ingest_invalid_source_system(engine):
    with pytest.raises(ValueError, match="source_system"):
        engine.ingest_alert("org1", {"title": "A", "source_system": "unknown", "severity": "low"})


def test_ingest_invalid_severity(engine):
    with pytest.raises(ValueError, match="severity"):
        engine.ingest_alert("org1", {"title": "A", "source_system": "siem", "severity": "ultra"})


def test_ingest_all_source_systems(engine):
    for src in ("siem", "edr", "ndr", "cloud", "waf", "ids", "firewall", "custom"):
        a = engine.ingest_alert("org1", {"title": "T", "source_system": src, "severity": "low"})
        assert a["source_system"] == src


# ===========================================================================
# 3. list_alerts / get_alert
# ===========================================================================

def test_list_alerts_returns_all(engine, critical_alert, low_alert):
    alerts = engine.list_alerts("org1")
    assert len(alerts) == 2


def test_list_alerts_filter_severity(engine, critical_alert, low_alert):
    alerts = engine.list_alerts("org1", severity="critical")
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "critical"


def test_list_alerts_filter_source_system(engine, critical_alert, low_alert):
    alerts = engine.list_alerts("org1", source_system="firewall")
    assert len(alerts) == 1
    assert alerts[0]["source_system"] == "firewall"


def test_list_alerts_filter_priority(engine, critical_alert, low_alert):
    alerts = engine.list_alerts("org1", priority="p1")
    assert len(alerts) == 1
    assert alerts[0]["priority"] == "p1"


def test_list_alerts_org_isolation(engine, critical_alert):
    alerts = engine.list_alerts("org2")
    assert len(alerts) == 0


def test_get_alert_returns_correct(engine, critical_alert):
    fetched = engine.get_alert("org1", critical_alert["id"])
    assert fetched["id"] == critical_alert["id"]


def test_get_alert_wrong_org_returns_none(engine, critical_alert):
    result = engine.get_alert("org2", critical_alert["id"])
    assert result is None


def test_get_alert_missing_returns_none(engine):
    assert engine.get_alert("org1", "nonexistent") is None


# ===========================================================================
# 4. triage_alert
# ===========================================================================

def test_triage_alert_updates_status(engine, critical_alert):
    updated = engine.triage_alert("org1", critical_alert["id"], {
        "triage_status": "triaging",
        "assigned_to": "analyst1",
        "triage_notes": "Looking into it",
    })
    assert updated["status"] == "triaging"
    assert updated["assigned_to"] == "analyst1"
    assert updated["triaged_at"] is not None


def test_triage_alert_escalated_sets_reason(engine, critical_alert):
    updated = engine.triage_alert("org1", critical_alert["id"], {
        "triage_status": "escalated",
        "escalation_reason": "Needs L3 review",
    })
    assert updated["status"] == "escalated"
    assert updated["escalation_reason"] == "Needs L3 review"


def test_triage_alert_resolved_sets_resolved_at(engine, critical_alert):
    updated = engine.triage_alert("org1", critical_alert["id"], {
        "triage_status": "resolved",
    })
    assert updated["status"] == "resolved"
    assert updated["resolved_at"] is not None


def test_triage_alert_invalid_status(engine, critical_alert):
    with pytest.raises(ValueError, match="triage_status"):
        engine.triage_alert("org1", critical_alert["id"], {"triage_status": "invalid"})


def test_triage_alert_not_found(engine):
    with pytest.raises(KeyError):
        engine.triage_alert("org1", "bad-id", {"triage_status": "triaging"})


# ===========================================================================
# 5. bulk_triage
# ===========================================================================

def test_bulk_triage_resolve(engine):
    ids = [
        engine.ingest_alert("org1", {"title": f"A{i}", "source_system": "siem", "severity": "medium"})["id"]
        for i in range(3)
    ]
    result = engine.bulk_triage("org1", ids, "resolve")
    assert result["updated"] == 3
    for aid in ids:
        assert engine.get_alert("org1", aid)["status"] == "resolved"


def test_bulk_triage_false_positive(engine, critical_alert, low_alert):
    result = engine.bulk_triage("org1", [critical_alert["id"], low_alert["id"]], "false_positive")
    assert result["updated"] == 2
    assert engine.get_alert("org1", critical_alert["id"])["status"] == "false_positive"


def test_bulk_triage_escalate(engine, critical_alert):
    result = engine.bulk_triage("org1", [critical_alert["id"]], "escalate")
    assert result["updated"] == 1
    assert engine.get_alert("org1", critical_alert["id"])["status"] == "escalated"


def test_bulk_triage_returns_correct_count(engine):
    ids = [
        engine.ingest_alert("org1", {"title": f"B{i}", "source_system": "edr", "severity": "high"})["id"]
        for i in range(5)
    ]
    result = engine.bulk_triage("org1", ids, "resolve")
    assert result["updated"] == 5


def test_bulk_triage_invalid_action(engine, critical_alert):
    with pytest.raises(ValueError, match="action"):
        engine.bulk_triage("org1", [critical_alert["id"]], "delete")


def test_bulk_triage_nonexistent_ids_returns_zero(engine):
    result = engine.bulk_triage("org1", ["fake-id-1", "fake-id-2"], "resolve")
    assert result["updated"] == 0


# ===========================================================================
# 6. get_triage_queue
# ===========================================================================

def test_queue_ordering_p1_before_p4(engine, critical_alert, low_alert):
    queue = engine.get_triage_queue("org1")
    # p1 should appear before p4
    priorities = [a["priority"] for a in queue]
    assert priorities.index("p1") < priorities.index("p4")


def test_queue_excludes_resolved(engine, critical_alert):
    engine.triage_alert("org1", critical_alert["id"], {"triage_status": "resolved"})
    queue = engine.get_triage_queue("org1")
    ids = [a["id"] for a in queue]
    assert critical_alert["id"] not in ids


def test_queue_respects_limit(engine):
    for i in range(10):
        engine.ingest_alert("org1", {"title": f"Q{i}", "source_system": "siem", "severity": "medium"})
    queue = engine.get_triage_queue("org1", limit=5)
    assert len(queue) <= 5


# ===========================================================================
# 7. get_triage_stats
# ===========================================================================

def test_stats_total_count(engine, critical_alert, low_alert):
    stats = engine.get_triage_stats("org1")
    assert stats["total_alerts"] == 2


def test_stats_new_alerts(engine, critical_alert, low_alert):
    stats = engine.get_triage_stats("org1")
    assert stats["new_alerts"] == 2


def test_stats_false_positive_rate(engine, critical_alert, low_alert):
    engine.triage_alert("org1", critical_alert["id"], {"triage_status": "false_positive"})
    stats = engine.get_triage_stats("org1")
    # 1 fp out of 2 total = 50%
    assert stats["false_positive_rate"] == 50.0


def test_stats_by_severity(engine, critical_alert, low_alert):
    stats = engine.get_triage_stats("org1")
    assert stats["by_severity"]["critical"] == 1
    assert stats["by_severity"]["low"] == 1


def test_stats_by_source_system(engine, critical_alert, low_alert):
    stats = engine.get_triage_stats("org1")
    assert "siem" in stats["by_source_system"]
    assert "firewall" in stats["by_source_system"]


def test_stats_empty_org(engine):
    stats = engine.get_triage_stats("org_empty")
    assert stats["total_alerts"] == 0
    assert stats["false_positive_rate"] == 0.0


# ===========================================================================
# 8. investigate — SOC analyst workflow
# ===========================================================================

def test_investigate_returns_alert_record(engine, critical_alert):
    result = engine.investigate("org1", critical_alert["id"])
    assert result["alert"]["id"] == critical_alert["id"]
    assert result["alert"]["severity"] == "critical"


def test_investigate_returns_related_alerts_same_source(engine):
    """Related alerts include same-source-system alerts (excluding self)."""
    a1 = engine.ingest_alert("org1", {"title": "SIEM alert A", "source_system": "siem", "severity": "high"})
    a2 = engine.ingest_alert("org1", {"title": "SIEM alert B", "source_system": "siem", "severity": "medium"})
    result = engine.investigate("org1", a1["id"])
    related_ids = [r["id"] for r in result["related_alerts"]]
    assert a2["id"] in related_ids
    assert a1["id"] not in related_ids  # self excluded


def test_investigate_not_found_raises_key_error(engine):
    with pytest.raises(KeyError, match="not found"):
        engine.investigate("org1", "nonexistent-alert-id")
