"""Tests for IncidentTimelineEngine — Beast Mode suite."""

from __future__ import annotations

import pytest
import tempfile
import os
from datetime import datetime, timezone, timedelta


@pytest.fixture
def engine(tmp_path):
    from core.incident_timeline_engine import IncidentTimelineEngine
    db = str(tmp_path / "test_timeline.db")
    return IncidentTimelineEngine(db_path=db)


ORG = "org-timeline-test"
ORG2 = "org-other"


# ---------------------------------------------------------------------------
# create_timeline
# ---------------------------------------------------------------------------

def test_create_timeline_basic(engine):
    tl = engine.create_timeline(ORG, {"title": "Ransomware Attack", "incident_type": "ransomware", "severity": "critical"})
    assert tl["timeline_id"]
    assert tl["title"] == "Ransomware Attack"
    assert tl["incident_type"] == "ransomware"
    assert tl["severity"] == "critical"
    assert tl["status"] == "active"
    assert tl["org_id"] == ORG


def test_create_timeline_defaults(engine):
    tl = engine.create_timeline(ORG, {"title": "Unknown Event"})
    assert tl["incident_type"] == "unknown"
    assert tl["severity"] == "medium"
    assert tl["status"] == "active"
    assert tl["contained_at"] is None
    assert tl["resolved_at"] is None


def test_create_timeline_requires_title(engine):
    with pytest.raises(ValueError, match="title"):
        engine.create_timeline(ORG, {})


def test_create_timeline_invalid_type(engine):
    with pytest.raises(ValueError, match="incident_type"):
        engine.create_timeline(ORG, {"title": "X", "incident_type": "zombie_attack"})


def test_create_timeline_invalid_severity(engine):
    with pytest.raises(ValueError, match="severity"):
        engine.create_timeline(ORG, {"title": "X", "severity": "extreme"})


def test_create_timeline_all_types(engine):
    for itype in ("breach", "ransomware", "phishing", "insider", "ddos", "supply_chain", "unknown"):
        tl = engine.create_timeline(ORG, {"title": f"Test {itype}", "incident_type": itype})
        assert tl["incident_type"] == itype


# ---------------------------------------------------------------------------
# list_timelines
# ---------------------------------------------------------------------------

def test_list_timelines_returns_own_org_only(engine):
    engine.create_timeline(ORG, {"title": "TL1"})
    engine.create_timeline(ORG2, {"title": "TL2"})
    results = engine.list_timelines(ORG)
    assert len(results) == 1
    assert results[0]["title"] == "TL1"


def test_list_timelines_filter_by_status(engine):
    tl = engine.create_timeline(ORG, {"title": "Active TL"})
    engine.update_timeline_status(ORG, tl["timeline_id"], "resolved")
    engine.create_timeline(ORG, {"title": "Still Active"})

    active = engine.list_timelines(ORG, status="active")
    resolved = engine.list_timelines(ORG, status="resolved")
    assert len(active) == 1
    assert active[0]["title"] == "Still Active"
    assert len(resolved) == 1


def test_list_timelines_filter_by_type(engine):
    engine.create_timeline(ORG, {"title": "P1", "incident_type": "phishing"})
    engine.create_timeline(ORG, {"title": "R1", "incident_type": "ransomware"})
    phishing = engine.list_timelines(ORG, incident_type="phishing")
    assert len(phishing) == 1
    assert phishing[0]["incident_type"] == "phishing"


# ---------------------------------------------------------------------------
# get_timeline
# ---------------------------------------------------------------------------

def test_get_timeline_returns_correct(engine):
    tl = engine.create_timeline(ORG, {"title": "Fetch Me"})
    fetched = engine.get_timeline(ORG, tl["timeline_id"])
    assert fetched["timeline_id"] == tl["timeline_id"]
    assert fetched["title"] == "Fetch Me"


def test_get_timeline_wrong_org_returns_none(engine):
    tl = engine.create_timeline(ORG, {"title": "Org1 TL"})
    result = engine.get_timeline(ORG2, tl["timeline_id"])
    assert result is None


def test_get_timeline_not_found_returns_none(engine):
    assert engine.get_timeline(ORG, "nonexistent-id") is None


# ---------------------------------------------------------------------------
# update_timeline_status
# ---------------------------------------------------------------------------

def test_update_status_contained_sets_timestamp(engine):
    tl = engine.create_timeline(ORG, {"title": "TL"})
    updated = engine.update_timeline_status(ORG, tl["timeline_id"], "contained")
    assert updated is True
    fetched = engine.get_timeline(ORG, tl["timeline_id"])
    assert fetched["status"] == "contained"
    assert fetched["contained_at"] is not None


def test_update_status_resolved_sets_resolved_at(engine):
    tl = engine.create_timeline(ORG, {"title": "TL2"})
    engine.update_timeline_status(ORG, tl["timeline_id"], "resolved")
    fetched = engine.get_timeline(ORG, tl["timeline_id"])
    assert fetched["status"] == "resolved"
    assert fetched["resolved_at"] is not None


def test_update_status_invalid_raises(engine):
    tl = engine.create_timeline(ORG, {"title": "TL"})
    with pytest.raises(ValueError, match="Invalid status"):
        engine.update_timeline_status(ORG, tl["timeline_id"], "vaporized")


def test_update_status_wrong_org_returns_false(engine):
    tl = engine.create_timeline(ORG, {"title": "TL"})
    result = engine.update_timeline_status(ORG2, tl["timeline_id"], "resolved")
    assert result is False


# ---------------------------------------------------------------------------
# add_event / list_events
# ---------------------------------------------------------------------------

def test_add_event_basic(engine):
    tl = engine.create_timeline(ORG, {"title": "TL"})
    ev = engine.add_event(ORG, tl["timeline_id"], {
        "event_type": "detection",
        "title": "IDS alert fired",
        "actor": "siem",
        "severity": "high",
    })
    assert ev["event_id"]
    assert ev["event_type"] == "detection"
    assert ev["title"] == "IDS alert fired"
    assert ev["severity"] == "high"
    assert isinstance(ev["evidence_refs"], list)


def test_add_event_evidence_refs_list(engine):
    tl = engine.create_timeline(ORG, {"title": "TL"})
    ev = engine.add_event(ORG, tl["timeline_id"], {
        "event_type": "action",
        "title": "Blocked",
        "evidence_refs": ["log-1", "pcap-2"],
    })
    assert ev["evidence_refs"] == ["log-1", "pcap-2"]


def test_add_event_evidence_refs_json_string(engine):
    tl = engine.create_timeline(ORG, {"title": "TL"})
    ev = engine.add_event(ORG, tl["timeline_id"], {
        "event_type": "action",
        "title": "Blocked",
        "evidence_refs": '["ref-a", "ref-b"]',
    })
    assert ev["evidence_refs"] == ["ref-a", "ref-b"]


def test_add_event_invalid_type(engine):
    tl = engine.create_timeline(ORG, {"title": "TL"})
    with pytest.raises(ValueError, match="event_type"):
        engine.add_event(ORG, tl["timeline_id"], {"event_type": "pizza", "title": "X"})


def test_list_events_ordered_by_time(engine):
    tl = engine.create_timeline(ORG, {"title": "TL"})
    t1 = "2026-01-01T00:00:00"
    t2 = "2026-01-02T00:00:00"
    engine.add_event(ORG, tl["timeline_id"], {"event_type": "action", "title": "Later", "event_time": t2})
    engine.add_event(ORG, tl["timeline_id"], {"event_type": "detection", "title": "Earlier", "event_time": t1})
    events = engine.list_events(ORG, tl["timeline_id"])
    assert events[0]["event_time"] == t1
    assert events[1]["event_time"] == t2


def test_list_events_filter_by_type(engine):
    tl = engine.create_timeline(ORG, {"title": "TL"})
    engine.add_event(ORG, tl["timeline_id"], {"event_type": "detection", "title": "D1"})
    engine.add_event(ORG, tl["timeline_id"], {"event_type": "action", "title": "A1"})
    detections = engine.list_events(ORG, tl["timeline_id"], event_type="detection")
    assert len(detections) == 1
    assert detections[0]["title"] == "D1"


def test_list_events_org_isolation(engine):
    tl = engine.create_timeline(ORG, {"title": "TL"})
    engine.add_event(ORG, tl["timeline_id"], {"event_type": "action", "title": "E1"})
    events_other = engine.list_events(ORG2, tl["timeline_id"])
    assert events_other == []


# ---------------------------------------------------------------------------
# add_affected_system / list_affected_systems
# ---------------------------------------------------------------------------

def test_add_affected_system(engine):
    tl = engine.create_timeline(ORG, {"title": "TL"})
    sys = engine.add_affected_system(ORG, tl["timeline_id"], {
        "hostname": "web01",
        "ip_address": "10.0.0.1",
        "system_type": "web_server",
        "impact_description": "Full compromise",
    })
    assert sys["system_id"]
    assert sys["hostname"] == "web01"
    assert sys["ip_address"] == "10.0.0.1"


def test_list_affected_systems_org_isolation(engine):
    tl = engine.create_timeline(ORG, {"title": "TL"})
    engine.add_affected_system(ORG, tl["timeline_id"], {"hostname": "db01"})
    systems_other = engine.list_affected_systems(ORG2, tl["timeline_id"])
    assert systems_other == []


def test_list_affected_systems_returns_all(engine):
    tl = engine.create_timeline(ORG, {"title": "TL"})
    engine.add_affected_system(ORG, tl["timeline_id"], {"hostname": "h1"})
    engine.add_affected_system(ORG, tl["timeline_id"], {"hostname": "h2"})
    systems = engine.list_affected_systems(ORG, tl["timeline_id"])
    assert len(systems) == 2


# ---------------------------------------------------------------------------
# calculate_metrics
# ---------------------------------------------------------------------------

def test_calculate_metrics_basic(engine):
    tl = engine.create_timeline(ORG, {"title": "TL", "started_at": "2026-01-01T00:00:00"})
    engine.add_event(ORG, tl["timeline_id"], {
        "event_type": "detection",
        "title": "First detect",
        "event_time": "2026-01-01T01:00:00",
    })
    engine.add_event(ORG, tl["timeline_id"], {"event_type": "action", "title": "Response"})
    engine.add_affected_system(ORG, tl["timeline_id"], {"hostname": "srv1"})
    engine.update_timeline_status(ORG, tl["timeline_id"], "resolved")

    metrics = engine.calculate_metrics(ORG, tl["timeline_id"])
    assert metrics["metric_id"]
    assert metrics["timeline_id"] == tl["timeline_id"]
    assert metrics["total_events"] == 2
    assert metrics["affected_systems_count"] == 1
    assert metrics["mttd_minutes"] == pytest.approx(60.0, abs=1.0)


def test_calculate_metrics_no_detection_event(engine):
    tl = engine.create_timeline(ORG, {"title": "TL"})
    engine.add_event(ORG, tl["timeline_id"], {"event_type": "action", "title": "Action"})
    metrics = engine.calculate_metrics(ORG, tl["timeline_id"])
    assert metrics["mttd_minutes"] is None


def test_calculate_metrics_not_found_raises(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.calculate_metrics(ORG, "nonexistent-id")


# ---------------------------------------------------------------------------
# get_timeline_stats
# ---------------------------------------------------------------------------

def test_get_timeline_stats_empty(engine):
    stats = engine.get_timeline_stats(ORG)
    assert stats["total_timelines"] == 0
    assert stats["active_incidents"] == 0
    assert stats["resolved_incidents"] == 0
    assert stats["avg_mttd"] is None
    assert stats["avg_mttr"] is None
    assert stats["by_type"] == {}
    assert stats["by_severity"] == {}


def test_get_timeline_stats_counts(engine):
    engine.create_timeline(ORG, {"title": "A1", "incident_type": "phishing", "severity": "high"})
    tl2 = engine.create_timeline(ORG, {"title": "A2", "incident_type": "breach", "severity": "critical"})
    engine.update_timeline_status(ORG, tl2["timeline_id"], "resolved")

    stats = engine.get_timeline_stats(ORG)
    assert stats["total_timelines"] == 2
    assert stats["active_incidents"] == 1
    assert stats["resolved_incidents"] == 1
    assert stats["by_type"]["phishing"] == 1
    assert stats["by_type"]["breach"] == 1
    assert stats["by_severity"]["high"] == 1
    assert stats["by_severity"]["critical"] == 1


def test_get_timeline_stats_org_isolation(engine):
    engine.create_timeline(ORG, {"title": "Org1 TL"})
    engine.create_timeline(ORG2, {"title": "Org2 TL"})
    stats1 = engine.get_timeline_stats(ORG)
    stats2 = engine.get_timeline_stats(ORG2)
    assert stats1["total_timelines"] == 1
    assert stats2["total_timelines"] == 1
