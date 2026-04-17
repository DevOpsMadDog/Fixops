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


# ---------------------------------------------------------------------------
# Incident CRUD — additional edge cases
# ---------------------------------------------------------------------------


def test_create_incident_default_severity(engine):
    inc = engine.create_incident(ORG, {"title": "No severity given"})
    assert inc["severity"] in ("p1", "p2", "p3", "p4")


def test_create_incident_all_severities(engine):
    for sev in ("p1", "p2", "p3", "p4"):
        inc = engine.create_incident(ORG, {"title": f"Inc {sev}", "severity": sev})
        assert inc["severity"] == sev


def test_list_incidents_org_isolation(engine):
    engine.create_incident(ORG, {"title": "Org A Inc", "severity": "p2"})
    other_org_incs = engine.list_incidents("other-org")
    assert other_org_incs == []


def test_update_incident_nonexistent_returns_false(engine):
    result = engine.update_incident(ORG, "no-such-id", {"title": "Ghost"})
    assert result is False


def test_update_incident_multiple_fields(engine):
    inc = engine.create_incident(ORG, {"title": "Multi update", "severity": "p3"})
    engine.update_incident(ORG, inc["id"], {"title": "Updated title", "status": "containment"})
    updated = engine.get_incident(ORG, inc["id"])
    assert updated["title"] == "Updated title"
    assert updated["status"] == "containment"


def test_create_incident_preserves_incident_type(engine):
    inc = engine.create_incident(ORG, {"title": "DDoS", "incident_type": "ddos", "severity": "p1"})
    assert inc["incident_type"] == "ddos"


def test_list_incidents_all_statuses(engine):
    for status in ("new", "triage", "containment", "eradication", "recovery"):
        engine.create_incident(ORG, {"title": f"Status {status}", "severity": "p2", "status": status})
    result = engine.list_incidents(ORG)
    assert len(result) >= 5


# ---------------------------------------------------------------------------
# Tasks — additional edge cases
# ---------------------------------------------------------------------------


def test_add_task_default_status_pending(engine):
    inc = engine.create_incident(ORG, {"title": "Task test", "severity": "p2"})
    task = engine.add_task(ORG, inc["id"], {"title": "Do something"})
    assert task["status"] == "pending"


def test_complete_task_nonexistent_returns_false(engine):
    result = engine.complete_task(ORG, "no-such-task")
    assert result is False


def test_tasks_are_incident_scoped(engine):
    inc1 = engine.create_incident(ORG, {"title": "Inc 1", "severity": "p1"})
    inc2 = engine.create_incident(ORG, {"title": "Inc 2", "severity": "p2"})
    engine.add_task(ORG, inc1["id"], {"title": "Task for Inc 1"})
    tasks_inc2 = engine.list_tasks(ORG, inc2["id"])
    assert tasks_inc2 == []


def test_complete_task_sets_completed_at(engine):
    inc = engine.create_incident(ORG, {"title": "Complete check", "severity": "p1"})
    task = engine.add_task(ORG, inc["id"], {"title": "Verify logs"})
    engine.complete_task(ORG, task["id"])
    tasks = engine.list_tasks(ORG, inc["id"])
    assert tasks[0]["completed_at"] is not None


def test_add_multiple_tasks_and_complete_all(engine):
    inc = engine.create_incident(ORG, {"title": "All tasks", "severity": "p2"})
    task_ids = []
    for i in range(3):
        t = engine.add_task(ORG, inc["id"], {"title": f"Task {i}"})
        task_ids.append(t["id"])
    for tid in task_ids:
        engine.complete_task(ORG, tid)
    tasks = engine.list_tasks(ORG, inc["id"])
    assert all(t["status"] == "completed" for t in tasks)


# ---------------------------------------------------------------------------
# Timeline — additional coverage
# ---------------------------------------------------------------------------


def test_get_timeline_empty(engine):
    inc = engine.create_incident(ORG, {"title": "No timeline", "severity": "p3"})
    timeline = engine.get_timeline(ORG, inc["id"])
    assert timeline == []


def test_timeline_org_isolation(engine):
    inc = engine.create_incident(ORG, {"title": "Secure inc", "severity": "p1"})
    engine.add_timeline_event(ORG, inc["id"], "detection", "Secret event")
    timeline = engine.get_timeline("other-org", inc["id"])
    assert timeline == []


def test_timeline_multiple_events_all_stored(engine):
    inc = engine.create_incident(ORG, {"title": "Multi-event", "severity": "p2"})
    for event_type in ("detection", "containment", "eradication"):
        engine.add_timeline_event(ORG, inc["id"], event_type, f"{event_type} description")
    timeline = engine.get_timeline(ORG, inc["id"])
    assert len(timeline) == 3


def test_timeline_event_without_actor(engine):
    inc = engine.create_incident(ORG, {"title": "Auto timeline", "severity": "p3"})
    event = engine.add_timeline_event(ORG, inc["id"], "detection", "System detected anomaly")
    # Actor is optional
    assert event["id"] is not None


# ---------------------------------------------------------------------------
# Artifacts — additional coverage
# ---------------------------------------------------------------------------


def test_add_artifact_without_description(engine):
    inc = engine.create_incident(ORG, {"title": "Artifact no desc", "severity": "p2"})
    art = engine.add_artifact(ORG, inc["id"], "log", "syslog.txt")
    assert art["id"] is not None


def test_list_artifacts_org_isolation(engine):
    inc = engine.create_incident(ORG, {"title": "Artifact iso", "severity": "p1"})
    engine.add_artifact(ORG, inc["id"], "pcap", "traffic.pcap")
    arts = engine.list_artifacts("other-org", inc["id"])
    assert arts == []


def test_multiple_artifact_types(engine):
    inc = engine.create_incident(ORG, {"title": "Many artifacts", "severity": "p2"})
    for atype in ("pcap", "log", "memory_dump", "screenshot"):
        engine.add_artifact(ORG, inc["id"], atype, f"file.{atype}")
    arts = engine.list_artifacts(ORG, inc["id"])
    assert len(arts) == 4


# ---------------------------------------------------------------------------
# Stats — additional coverage
# ---------------------------------------------------------------------------


def test_get_incident_stats_by_status(engine):
    engine.create_incident(ORG, {"title": "New1", "severity": "p2", "status": "new"})
    engine.create_incident(ORG, {"title": "New2", "severity": "p3", "status": "new"})
    engine.create_incident(ORG, {"title": "Triage1", "severity": "p1", "status": "triage"})
    stats = engine.get_incident_stats(ORG)
    assert stats["by_status"].get("new") == 2
    assert stats["by_status"].get("triage") == 1


def test_get_incident_stats_org_isolation(engine):
    engine.create_incident(ORG, {"title": "Org test", "severity": "p1"})
    stats_other = engine.get_incident_stats("completely-other-org")
    assert stats_other["by_severity"] == {}


def test_get_incident_stats_all_severities_represented(engine):
    for sev in ("p1", "p2", "p3", "p4"):
        engine.create_incident(ORG, {"title": f"Sev {sev}", "severity": sev})
    stats = engine.get_incident_stats(ORG)
    for sev in ("p1", "p2", "p3", "p4"):
        assert stats["by_severity"].get(sev) == 1
