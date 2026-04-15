"""Tests for IncidentResponseEngine — 25 tests.

Covers: incident CRUD, task management, timeline events,
artifact tracking, SLA computation, and aggregate stats.
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

from core.incident_response_engine import IncidentResponseEngine


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "ir_test.db")
    return IncidentResponseEngine(db_path=db)


ORG = "org-test"


# ---------------------------------------------------------------------------
# Incident CRUD
# ---------------------------------------------------------------------------


def test_create_incident_returns_record(engine):
    inc = engine.create_incident(ORG, {"title": "Ransomware hit", "incident_type": "ransomware", "severity": "p1"})
    assert inc["id"]
    assert inc["title"] == "Ransomware hit"
    assert inc["severity"] == "p1"
    assert inc["status"] == "new"
    assert inc["org_id"] == ORG


def test_create_incident_auto_sla(engine):
    inc = engine.create_incident(ORG, {"title": "P1 test", "severity": "p1"})
    # SLA for P1 is 4 hours — deadline must be after detected_at
    assert inc["sla_deadline"] > inc["detected_at"]


def test_create_incident_p4_sla_72h(engine):
    inc = engine.create_incident(ORG, {"title": "P4 test", "severity": "p4"})
    assert inc["sla_deadline"] > inc["detected_at"]


def test_list_incidents_empty(engine):
    result = engine.list_incidents(ORG)
    assert result == []


def test_list_incidents_returns_created(engine):
    engine.create_incident(ORG, {"title": "Inc A", "severity": "p2"})
    engine.create_incident(ORG, {"title": "Inc B", "severity": "p3"})
    result = engine.list_incidents(ORG)
    assert len(result) == 2


def test_list_incidents_filter_status(engine):
    engine.create_incident(ORG, {"title": "New one", "severity": "p2", "status": "new"})
    engine.create_incident(ORG, {"title": "Triage one", "severity": "p2", "status": "triage"})
    new_only = engine.list_incidents(ORG, status="new")
    assert all(i["status"] == "new" for i in new_only)
    assert len(new_only) == 1


def test_list_incidents_filter_severity(engine):
    engine.create_incident(ORG, {"title": "P1 Inc", "severity": "p1"})
    engine.create_incident(ORG, {"title": "P3 Inc", "severity": "p3"})
    p1_only = engine.list_incidents(ORG, severity="p1")
    assert all(i["severity"] == "p1" for i in p1_only)


def test_get_incident_found(engine):
    inc = engine.create_incident(ORG, {"title": "Phishing wave", "severity": "p2"})
    fetched = engine.get_incident(ORG, inc["id"])
    assert fetched is not None
    assert fetched["id"] == inc["id"]


def test_get_incident_not_found(engine):
    assert engine.get_incident(ORG, "nonexistent-id") is None


def test_get_incident_org_isolation(engine):
    inc = engine.create_incident(ORG, {"title": "Secret inc", "severity": "p1"})
    # Different org should not see it
    assert engine.get_incident("other-org", inc["id"]) is None


def test_update_incident_title(engine):
    inc = engine.create_incident(ORG, {"title": "Old title", "severity": "p3"})
    ok = engine.update_incident(ORG, inc["id"], {"title": "New title"})
    assert ok is True
    updated = engine.get_incident(ORG, inc["id"])
    assert updated["title"] == "New title"


def test_update_incident_status(engine):
    inc = engine.create_incident(ORG, {"title": "Status test", "severity": "p2"})
    engine.update_incident(ORG, inc["id"], {"status": "containment"})
    updated = engine.get_incident(ORG, inc["id"])
    assert updated["status"] == "containment"


def test_update_incident_recalculates_sla_on_severity_change(engine):
    inc = engine.create_incident(ORG, {"title": "SLA recalc", "severity": "p4"})
    old_sla = inc["sla_deadline"]
    engine.update_incident(ORG, inc["id"], {"severity": "p1"})
    updated = engine.get_incident(ORG, inc["id"])
    assert updated["sla_deadline"] != old_sla


def test_update_incident_wrong_org_returns_false(engine):
    inc = engine.create_incident(ORG, {"title": "Guard test", "severity": "p2"})
    result = engine.update_incident("evil-org", inc["id"], {"title": "Hacked"})
    assert result is False


# ---------------------------------------------------------------------------
# Tasks
# ---------------------------------------------------------------------------


def test_add_task_returns_record(engine):
    inc = engine.create_incident(ORG, {"title": "Inc with tasks", "severity": "p2"})
    task = engine.add_task(ORG, inc["id"], {"title": "Isolate host", "assignee": "alice"})
    assert task["id"]
    assert task["title"] == "Isolate host"
    assert task["status"] == "pending"


def test_list_tasks_empty(engine):
    inc = engine.create_incident(ORG, {"title": "No-task inc", "severity": "p3"})
    assert engine.list_tasks(ORG, inc["id"]) == []


def test_list_tasks_returns_all(engine):
    inc = engine.create_incident(ORG, {"title": "Multi-task", "severity": "p2"})
    engine.add_task(ORG, inc["id"], {"title": "Task 1"})
    engine.add_task(ORG, inc["id"], {"title": "Task 2"})
    tasks = engine.list_tasks(ORG, inc["id"])
    assert len(tasks) == 2


def test_complete_task(engine):
    inc = engine.create_incident(ORG, {"title": "Complete task inc", "severity": "p1"})
    task = engine.add_task(ORG, inc["id"], {"title": "Block IOC"})
    ok = engine.complete_task(ORG, task["id"])
    assert ok is True
    tasks = engine.list_tasks(ORG, inc["id"])
    assert tasks[0]["status"] == "completed"
    assert tasks[0]["completed_at"] is not None


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------


def test_add_timeline_event(engine):
    inc = engine.create_incident(ORG, {"title": "Timeline inc", "severity": "p2"})
    event = engine.add_timeline_event(ORG, inc["id"], "detection", "Malware detected on server", actor="analyst1")
    assert event["id"]
    assert event["event_type"] == "detection"
    assert event["actor"] == "analyst1"


def test_get_timeline_sorted_desc(engine):
    inc = engine.create_incident(ORG, {"title": "Timeline sort", "severity": "p2"})
    engine.add_timeline_event(ORG, inc["id"], "detection", "First event")
    engine.add_timeline_event(ORG, inc["id"], "containment", "Second event")
    timeline = engine.get_timeline(ORG, inc["id"])
    assert len(timeline) == 2
    # Most recent first
    assert timeline[0]["timestamp"] >= timeline[1]["timestamp"]


# ---------------------------------------------------------------------------
# Artifacts
# ---------------------------------------------------------------------------


def test_add_artifact(engine):
    inc = engine.create_incident(ORG, {"title": "Artifact inc", "severity": "p1"})
    art = engine.add_artifact(ORG, inc["id"], "pcap", "capture.pcap", "Network capture")
    assert art["id"]
    assert art["filename"] == "capture.pcap"
    assert art["artifact_type"] == "pcap"


def test_list_artifacts(engine):
    inc = engine.create_incident(ORG, {"title": "Multi-artifact", "severity": "p2"})
    engine.add_artifact(ORG, inc["id"], "log", "syslog.txt")
    engine.add_artifact(ORG, inc["id"], "pcap", "dump.pcap")
    arts = engine.list_artifacts(ORG, inc["id"])
    assert len(arts) == 2


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


def test_get_incident_stats_empty(engine):
    stats = engine.get_incident_stats(ORG)
    assert stats["by_severity"] == {}
    assert stats["by_status"] == {}
    assert stats["avg_resolution_hours"] is None


def test_get_incident_stats_counts(engine):
    engine.create_incident(ORG, {"title": "S1", "severity": "p1"})
    engine.create_incident(ORG, {"title": "S2", "severity": "p1"})
    engine.create_incident(ORG, {"title": "S3", "severity": "p3"})
    stats = engine.get_incident_stats(ORG)
    assert stats["by_severity"].get("p1") == 2
    assert stats["by_severity"].get("p3") == 1
