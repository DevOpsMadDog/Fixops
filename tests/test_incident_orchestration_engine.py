"""Tests for IncidentOrchestrationEngine — 30+ tests covering all methods and metrics."""

from __future__ import annotations

import pytest

from core.incident_orchestration_engine import IncidentOrchestrationEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "test_incident_orchestration.db")


@pytest.fixture
def engine(db_path):
    return IncidentOrchestrationEngine(db_path=db_path)


ORG = "org-io-test"
ORG2 = "org-io-other"


# ---------------------------------------------------------------------------
# create_incident
# ---------------------------------------------------------------------------

def test_create_incident_minimal(engine):
    inc = engine.create_incident(ORG, {"title": "Suspicious Login"})
    assert inc["title"] == "Suspicious Login"
    assert inc["status"] == "open"
    assert inc["severity"] == "medium"
    assert inc["type"] == "other"
    assert "id" in inc
    assert "created_at" in inc


def test_create_incident_all_fields(engine):
    inc = engine.create_incident(ORG, {
        "title": "Ransomware Outbreak",
        "severity": "critical",
        "type": "malware",
        "source": "EDR alert",
    })
    assert inc["severity"] == "critical"
    assert inc["type"] == "malware"
    assert inc["source"] == "EDR alert"


def test_create_incident_missing_title(engine):
    with pytest.raises(ValueError, match="title is required"):
        engine.create_incident(ORG, {})


def test_create_incident_invalid_severity(engine):
    with pytest.raises(ValueError, match="Invalid severity"):
        engine.create_incident(ORG, {"title": "X", "severity": "mega"})


def test_create_incident_invalid_type(engine):
    with pytest.raises(ValueError, match="Invalid type"):
        engine.create_incident(ORG, {"title": "X", "type": "aliens"})


def test_create_incident_all_severities(engine):
    for sev in ("critical", "high", "medium", "low"):
        inc = engine.create_incident(ORG, {"title": f"Sev {sev}", "severity": sev})
        assert inc["severity"] == sev


def test_create_incident_all_types(engine):
    for t in ("breach", "malware", "phishing", "ddos", "insider", "other"):
        inc = engine.create_incident(ORG, {"title": f"Type {t}", "type": t})
        assert inc["type"] == t


def test_create_incident_unique_ids(engine):
    i1 = engine.create_incident(ORG, {"title": "Inc1"})
    i2 = engine.create_incident(ORG, {"title": "Inc2"})
    assert i1["id"] != i2["id"]


# ---------------------------------------------------------------------------
# list_incidents
# ---------------------------------------------------------------------------

def test_list_incidents_empty(engine):
    assert engine.list_incidents(ORG) == []


def test_list_incidents_returns_all(engine):
    engine.create_incident(ORG, {"title": "A"})
    engine.create_incident(ORG, {"title": "B"})
    assert len(engine.list_incidents(ORG)) == 2


def test_list_incidents_filter_severity(engine):
    engine.create_incident(ORG, {"title": "Crit", "severity": "critical"})
    engine.create_incident(ORG, {"title": "Low", "severity": "low"})
    crits = engine.list_incidents(ORG, severity="critical")
    assert len(crits) == 1
    assert crits[0]["severity"] == "critical"


def test_list_incidents_filter_status(engine):
    inc = engine.create_incident(ORG, {"title": "To Resolve"})
    engine.update_incident_status(ORG, inc["id"], "resolved")
    open_incs = engine.list_incidents(ORG, status="open")
    resolved_incs = engine.list_incidents(ORG, status="resolved")
    assert len(open_incs) == 0
    assert len(resolved_incs) == 1


def test_list_incidents_limit(engine):
    for i in range(5):
        engine.create_incident(ORG, {"title": f"Inc {i}"})
    assert len(engine.list_incidents(ORG, limit=3)) == 3


def test_list_incidents_org_isolation(engine):
    engine.create_incident(ORG, {"title": "Org1"})
    engine.create_incident(ORG2, {"title": "Org2"})
    assert len(engine.list_incidents(ORG)) == 1
    assert len(engine.list_incidents(ORG2)) == 1


# ---------------------------------------------------------------------------
# get_incident
# ---------------------------------------------------------------------------

def test_get_incident_found(engine):
    inc = engine.create_incident(ORG, {"title": "Findable"})
    fetched = engine.get_incident(ORG, inc["id"])
    assert fetched is not None
    assert fetched["title"] == "Findable"


def test_get_incident_not_found(engine):
    assert engine.get_incident(ORG, "ghost-id") is None


def test_get_incident_wrong_org(engine):
    inc = engine.create_incident(ORG, {"title": "Private"})
    assert engine.get_incident(ORG2, inc["id"]) is None


# ---------------------------------------------------------------------------
# update_incident_status
# ---------------------------------------------------------------------------

def test_update_status_basic(engine):
    inc = engine.create_incident(ORG, {"title": "Status Test"})
    updated = engine.update_incident_status(ORG, inc["id"], "investigating")
    assert updated["status"] == "investigating"


def test_update_status_with_notes(engine):
    inc = engine.create_incident(ORG, {"title": "Note Test"})
    updated = engine.update_incident_status(ORG, inc["id"], "contained", notes="Isolated host")
    assert updated["notes"] == "Isolated host"


def test_update_status_resolved_sets_resolved_at(engine):
    inc = engine.create_incident(ORG, {"title": "Resolver"})
    updated = engine.update_incident_status(ORG, inc["id"], "resolved")
    assert updated["resolved_at"] is not None


def test_update_status_closed_sets_resolved_at(engine):
    inc = engine.create_incident(ORG, {"title": "Closer"})
    updated = engine.update_incident_status(ORG, inc["id"], "closed")
    assert updated["resolved_at"] is not None


def test_update_status_invalid(engine):
    inc = engine.create_incident(ORG, {"title": "Bad Status"})
    with pytest.raises(ValueError, match="Invalid status"):
        engine.update_incident_status(ORG, inc["id"], "quarantined")


def test_update_status_not_found(engine):
    result = engine.update_incident_status(ORG, "ghost-id", "investigating")
    assert result is None


def test_update_status_all_valid_statuses(engine):
    for status in ("open", "investigating", "contained", "resolved", "closed"):
        inc = engine.create_incident(ORG, {"title": f"Status {status}"})
        updated = engine.update_incident_status(ORG, inc["id"], status)
        assert updated["status"] == status


# ---------------------------------------------------------------------------
# assign_incident
# ---------------------------------------------------------------------------

def test_assign_incident(engine):
    inc = engine.create_incident(ORG, {"title": "Assignable"})
    updated = engine.assign_incident(ORG, inc["id"], "analyst@corp.com")
    assert updated["assignee"] == "analyst@corp.com"


def test_assign_incident_not_found(engine):
    assert engine.assign_incident(ORG, "ghost-id", "nobody") is None


def test_assign_incident_reassign(engine):
    inc = engine.create_incident(ORG, {"title": "Reassign"})
    engine.assign_incident(ORG, inc["id"], "first@corp.com")
    updated = engine.assign_incident(ORG, inc["id"], "second@corp.com")
    assert updated["assignee"] == "second@corp.com"


# ---------------------------------------------------------------------------
# add_timeline_event / get_timeline
# ---------------------------------------------------------------------------

def test_add_timeline_event_basic(engine):
    inc = engine.create_incident(ORG, {"title": "Timeline Inc"})
    event = engine.add_timeline_event(ORG, inc["id"], {
        "event_type": "detection",
        "description": "Alert triggered",
        "actor": "SIEM",
    })
    assert event is not None
    assert event["event_type"] == "detection"
    assert event["description"] == "Alert triggered"
    assert event["actor"] == "SIEM"
    assert "id" in event
    assert "occurred_at" in event


def test_add_timeline_event_invalid_type(engine):
    inc = engine.create_incident(ORG, {"title": "Bad Event"})
    with pytest.raises(ValueError, match="Invalid event_type"):
        engine.add_timeline_event(ORG, inc["id"], {"event_type": "dancing"})


def test_add_timeline_event_incident_not_found(engine):
    result = engine.add_timeline_event(ORG, "ghost-incident", {"event_type": "note"})
    assert result is None


def test_get_timeline_empty(engine):
    inc = engine.create_incident(ORG, {"title": "Empty Timeline"})
    assert engine.get_timeline(ORG, inc["id"]) == []


def test_get_timeline_ordered(engine):
    inc = engine.create_incident(ORG, {"title": "Ordered Timeline"})
    engine.add_timeline_event(ORG, inc["id"], {"event_type": "detection", "description": "First"})
    engine.add_timeline_event(ORG, inc["id"], {"event_type": "triage", "description": "Second"})
    engine.add_timeline_event(ORG, inc["id"], {"event_type": "containment", "description": "Third"})
    timeline = engine.get_timeline(ORG, inc["id"])
    assert len(timeline) == 3
    assert timeline[0]["description"] == "First"
    assert timeline[2]["description"] == "Third"


def test_get_timeline_all_event_types(engine):
    inc = engine.create_incident(ORG, {"title": "All Events"})
    for et in ("detection", "triage", "containment", "eradication",
               "recovery", "communication", "note", "escalation"):
        event = engine.add_timeline_event(ORG, inc["id"], {"event_type": et})
        assert event["event_type"] == et


# ---------------------------------------------------------------------------
# get_incident_metrics
# ---------------------------------------------------------------------------

def test_metrics_empty_org(engine):
    metrics = engine.get_incident_metrics(ORG)
    assert metrics["open_count"] == 0
    assert metrics["total_count"] == 0
    assert metrics["avg_mttr_hours"] == 0.0
    assert metrics["by_severity"] == {}
    assert metrics["by_type"] == {}


def test_metrics_open_count(engine):
    engine.create_incident(ORG, {"title": "Open1"})
    engine.create_incident(ORG, {"title": "Open2"})
    inc = engine.create_incident(ORG, {"title": "Resolved"})
    engine.update_incident_status(ORG, inc["id"], "resolved")
    metrics = engine.get_incident_metrics(ORG)
    assert metrics["open_count"] == 2
    assert metrics["total_count"] == 3


def test_metrics_by_severity(engine):
    engine.create_incident(ORG, {"title": "Crit", "severity": "critical"})
    engine.create_incident(ORG, {"title": "High", "severity": "high"})
    engine.create_incident(ORG, {"title": "High2", "severity": "high"})
    metrics = engine.get_incident_metrics(ORG)
    assert metrics["by_severity"]["critical"] == 1
    assert metrics["by_severity"]["high"] == 2


def test_metrics_by_type(engine):
    engine.create_incident(ORG, {"title": "Breach", "type": "breach"})
    engine.create_incident(ORG, {"title": "Malware", "type": "malware"})
    metrics = engine.get_incident_metrics(ORG)
    assert metrics["by_type"]["breach"] == 1
    assert metrics["by_type"]["malware"] == 1


def test_metrics_avg_mttr(engine):
    inc = engine.create_incident(ORG, {"title": "Fast Resolve"})
    engine.update_incident_status(ORG, inc["id"], "resolved")
    metrics = engine.get_incident_metrics(ORG)
    assert metrics["avg_mttr_hours"] >= 0.0


def test_metrics_no_mttr_without_resolved(engine):
    engine.create_incident(ORG, {"title": "Still Open"})
    metrics = engine.get_incident_metrics(ORG)
    assert metrics["avg_mttr_hours"] == 0.0
