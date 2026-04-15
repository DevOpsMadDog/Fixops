"""Tests for SecurityEventTimelineEngine — ALDECI.

Coverage:
  - create_timeline: status=open, event_count=0
  - add_event: event_count increment, start_time=MIN, end_time=MAX, duration_mins
  - correlate_events: confidence clamp (0.0-1.0)
  - close_timeline: status=closed
  - get_timeline: header + events + correlations
  - get_event_sequence: time-range filtering
  - get_actor_activity: actor filtering
  - get_timeline_summary: totals, open_count, by_event_type, recent
  - search_events: LIKE search across actor/target/action/raw_data
  - org isolation: events from org_a invisible to org_b
"""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any, Dict

import pytest

from core.security_event_timeline_engine import SecurityEventTimelineEngine


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "test_timeline.db")
    return SecurityEventTimelineEngine(db_path=db)


ORG_A = "org-alpha"
ORG_B = "org-beta"
INC_1 = "INC-001"
INC_2 = "INC-002"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_timeline(engine, org=ORG_A, incident=INC_1, title="Test Timeline"):
    return engine.create_timeline(org, incident, title)


def make_event(engine, org=ORG_A, incident=INC_1, event_time="2026-04-16T10:00:00+00:00",
               event_type="authentication", source_system="siem", actor="user1",
               target="server1", action="login", outcome="success", severity="medium",
               raw_data="", tags=None):
    return engine.add_event(
        org_id=org, incident_id=incident, event_time=event_time,
        event_type=event_type, source_system=source_system, actor=actor,
        target=target, action=action, outcome=outcome, severity=severity,
        raw_data=raw_data, tags=tags or [],
    )


# ---------------------------------------------------------------------------
# create_timeline
# ---------------------------------------------------------------------------

class TestCreateTimeline:
    def test_creates_with_open_status(self, engine):
        tl = make_timeline(engine)
        assert tl["status"] == "open"

    def test_creates_with_zero_event_count(self, engine):
        tl = make_timeline(engine)
        assert tl["event_count"] == 0

    def test_creates_with_correct_org_and_incident(self, engine):
        tl = make_timeline(engine, org=ORG_A, incident=INC_1)
        assert tl["org_id"] == ORG_A
        assert tl["incident_id"] == INC_1

    def test_creates_with_title(self, engine):
        tl = make_timeline(engine, title="Ransomware Investigation")
        assert tl["title"] == "Ransomware Investigation"

    def test_start_end_time_none_on_create(self, engine):
        tl = make_timeline(engine)
        assert tl["start_time"] is None
        assert tl["end_time"] is None

    def test_duration_zero_on_create(self, engine):
        tl = make_timeline(engine)
        assert tl["duration_mins"] == 0.0

    def test_returns_id(self, engine):
        tl = make_timeline(engine)
        assert tl["id"]


# ---------------------------------------------------------------------------
# add_event
# ---------------------------------------------------------------------------

class TestAddEvent:
    def test_event_count_increments(self, engine):
        make_timeline(engine)
        make_event(engine)
        tl = engine.get_timeline(ORG_A, INC_1)
        assert tl["event_count"] == 1

    def test_event_count_increments_multiple(self, engine):
        make_timeline(engine)
        make_event(engine, event_time="2026-04-16T10:00:00+00:00")
        make_event(engine, event_time="2026-04-16T10:05:00+00:00")
        make_event(engine, event_time="2026-04-16T10:10:00+00:00")
        tl = engine.get_timeline(ORG_A, INC_1)
        assert tl["event_count"] == 3

    def test_start_time_set_to_first_event(self, engine):
        make_timeline(engine)
        make_event(engine, event_time="2026-04-16T10:00:00+00:00")
        tl = engine.get_timeline(ORG_A, INC_1)
        assert tl["start_time"] == "2026-04-16T10:00:00+00:00"

    def test_start_time_is_min_of_events(self, engine):
        make_timeline(engine)
        make_event(engine, event_time="2026-04-16T10:30:00+00:00")
        make_event(engine, event_time="2026-04-16T10:00:00+00:00")  # earlier
        tl = engine.get_timeline(ORG_A, INC_1)
        assert tl["start_time"] == "2026-04-16T10:00:00+00:00"

    def test_end_time_is_max_of_events(self, engine):
        make_timeline(engine)
        make_event(engine, event_time="2026-04-16T10:00:00+00:00")
        make_event(engine, event_time="2026-04-16T11:00:00+00:00")  # later
        tl = engine.get_timeline(ORG_A, INC_1)
        assert tl["end_time"] == "2026-04-16T11:00:00+00:00"

    def test_duration_mins_computed(self, engine):
        make_timeline(engine)
        make_event(engine, event_time="2026-04-16T10:00:00+00:00")
        make_event(engine, event_time="2026-04-16T11:00:00+00:00")
        tl = engine.get_timeline(ORG_A, INC_1)
        # 60 minutes between events
        assert abs(tl["duration_mins"] - 60.0) < 0.5

    def test_duration_mins_30_minutes(self, engine):
        make_timeline(engine)
        make_event(engine, event_time="2026-04-16T10:00:00+00:00")
        make_event(engine, event_time="2026-04-16T10:30:00+00:00")
        tl = engine.get_timeline(ORG_A, INC_1)
        assert abs(tl["duration_mins"] - 30.0) < 0.5

    def test_single_event_zero_duration(self, engine):
        make_timeline(engine)
        make_event(engine, event_time="2026-04-16T10:00:00+00:00")
        tl = engine.get_timeline(ORG_A, INC_1)
        assert tl["duration_mins"] == 0.0

    def test_tags_stored_as_json(self, engine):
        make_timeline(engine)
        ev = make_event(engine, tags=["lateral-movement", "privilege-esc"])
        assert ev["tags"] == '["lateral-movement", "privilege-esc"]'

    def test_returns_event_id(self, engine):
        make_timeline(engine)
        ev = make_event(engine)
        assert ev["id"]

    def test_no_timeline_raises_key_error(self, engine):
        with pytest.raises(KeyError):
            make_event(engine, incident="NONEXISTENT")

    def test_invalid_outcome_defaults_to_unknown(self, engine):
        make_timeline(engine)
        ev = make_event(engine, outcome="bad_outcome")
        assert ev["outcome"] == "unknown"

    def test_invalid_severity_defaults_to_medium(self, engine):
        make_timeline(engine)
        ev = make_event(engine, severity="extreme")
        assert ev["severity"] == "medium"

    def test_valid_severity_preserved(self, engine):
        make_timeline(engine)
        ev = make_event(engine, severity="critical")
        assert ev["severity"] == "critical"


# ---------------------------------------------------------------------------
# correlate_events
# ---------------------------------------------------------------------------

class TestCorrelateEvents:
    def test_correlation_created(self, engine):
        make_timeline(engine)
        ev1 = make_event(engine, event_time="2026-04-16T10:00:00+00:00")
        ev2 = make_event(engine, event_time="2026-04-16T10:05:00+00:00")
        corr = engine.correlate_events(
            ORG_A, INC_1, ev1["id"], ev2["id"], "same_actor", 0.9
        )
        assert corr["correlation_type"] == "same_actor"
        assert corr["confidence"] == 0.9

    def test_confidence_clamped_above_1(self, engine):
        make_timeline(engine)
        ev1 = make_event(engine, event_time="2026-04-16T10:00:00+00:00")
        ev2 = make_event(engine, event_time="2026-04-16T10:05:00+00:00")
        corr = engine.correlate_events(ORG_A, INC_1, ev1["id"], ev2["id"], "causal", 1.5)
        assert corr["confidence"] == 1.0

    def test_confidence_clamped_below_0(self, engine):
        make_timeline(engine)
        ev1 = make_event(engine, event_time="2026-04-16T10:00:00+00:00")
        ev2 = make_event(engine, event_time="2026-04-16T10:05:00+00:00")
        corr = engine.correlate_events(ORG_A, INC_1, ev1["id"], ev2["id"], "temporal", -0.5)
        assert corr["confidence"] == 0.0

    def test_confidence_zero_allowed(self, engine):
        make_timeline(engine)
        ev1 = make_event(engine, event_time="2026-04-16T10:00:00+00:00")
        ev2 = make_event(engine, event_time="2026-04-16T10:05:00+00:00")
        corr = engine.correlate_events(ORG_A, INC_1, ev1["id"], ev2["id"], "ioc_match", 0.0)
        assert corr["confidence"] == 0.0


# ---------------------------------------------------------------------------
# close_timeline
# ---------------------------------------------------------------------------

class TestCloseTimeline:
    def test_close_sets_status_closed(self, engine):
        tl = make_timeline(engine)
        closed = engine.close_timeline(tl["id"], ORG_A)
        assert closed["status"] == "closed"

    def test_close_nonexistent_raises_key_error(self, engine):
        with pytest.raises(KeyError):
            engine.close_timeline("nonexistent-id", ORG_A)

    def test_close_wrong_org_raises_key_error(self, engine):
        tl = make_timeline(engine, org=ORG_A)
        with pytest.raises(KeyError):
            engine.close_timeline(tl["id"], ORG_B)


# ---------------------------------------------------------------------------
# get_timeline
# ---------------------------------------------------------------------------

class TestGetTimeline:
    def test_returns_timeline_with_events(self, engine):
        make_timeline(engine)
        make_event(engine, event_time="2026-04-16T10:00:00+00:00")
        make_event(engine, event_time="2026-04-16T10:05:00+00:00")
        tl = engine.get_timeline(ORG_A, INC_1)
        assert len(tl["events"]) == 2

    def test_events_ordered_by_event_time(self, engine):
        make_timeline(engine)
        make_event(engine, event_time="2026-04-16T10:30:00+00:00")
        make_event(engine, event_time="2026-04-16T10:00:00+00:00")
        tl = engine.get_timeline(ORG_A, INC_1)
        times = [e["event_time"] for e in tl["events"]]
        assert times == sorted(times)

    def test_returns_correlations(self, engine):
        make_timeline(engine)
        ev1 = make_event(engine, event_time="2026-04-16T10:00:00+00:00")
        ev2 = make_event(engine, event_time="2026-04-16T10:05:00+00:00")
        engine.correlate_events(ORG_A, INC_1, ev1["id"], ev2["id"], "causal", 0.8)
        tl = engine.get_timeline(ORG_A, INC_1)
        assert len(tl["correlations"]) == 1

    def test_returns_empty_for_missing(self, engine):
        result = engine.get_timeline(ORG_A, "NO-SUCH-INC")
        assert result == {}


# ---------------------------------------------------------------------------
# get_event_sequence
# ---------------------------------------------------------------------------

class TestGetEventSequence:
    def test_all_events_returned_without_filter(self, engine):
        make_timeline(engine)
        make_event(engine, event_time="2026-04-16T10:00:00+00:00")
        make_event(engine, event_time="2026-04-16T11:00:00+00:00")
        events = engine.get_event_sequence(ORG_A, INC_1)
        assert len(events) == 2

    def test_start_time_filter(self, engine):
        make_timeline(engine)
        make_event(engine, event_time="2026-04-16T09:00:00+00:00")
        make_event(engine, event_time="2026-04-16T10:00:00+00:00")
        make_event(engine, event_time="2026-04-16T11:00:00+00:00")
        events = engine.get_event_sequence(ORG_A, INC_1, start_time="2026-04-16T10:00:00+00:00")
        assert len(events) == 2
        assert all(e["event_time"] >= "2026-04-16T10:00:00+00:00" for e in events)

    def test_end_time_filter(self, engine):
        make_timeline(engine)
        make_event(engine, event_time="2026-04-16T09:00:00+00:00")
        make_event(engine, event_time="2026-04-16T10:00:00+00:00")
        make_event(engine, event_time="2026-04-16T11:00:00+00:00")
        events = engine.get_event_sequence(ORG_A, INC_1, end_time="2026-04-16T10:00:00+00:00")
        assert len(events) == 2

    def test_start_and_end_time_filter(self, engine):
        make_timeline(engine)
        make_event(engine, event_time="2026-04-16T09:00:00+00:00")
        make_event(engine, event_time="2026-04-16T10:00:00+00:00")
        make_event(engine, event_time="2026-04-16T11:00:00+00:00")
        events = engine.get_event_sequence(
            ORG_A, INC_1,
            start_time="2026-04-16T09:30:00+00:00",
            end_time="2026-04-16T10:30:00+00:00",
        )
        assert len(events) == 1
        assert events[0]["event_time"] == "2026-04-16T10:00:00+00:00"


# ---------------------------------------------------------------------------
# get_actor_activity
# ---------------------------------------------------------------------------

class TestGetActorActivity:
    def test_returns_only_actor_events(self, engine):
        make_timeline(engine)
        make_event(engine, actor="alice", event_time="2026-04-16T10:00:00+00:00")
        make_event(engine, actor="bob", event_time="2026-04-16T10:05:00+00:00")
        make_event(engine, actor="alice", event_time="2026-04-16T10:10:00+00:00")
        events = engine.get_actor_activity(ORG_A, INC_1, "alice")
        assert len(events) == 2
        assert all(e["actor"] == "alice" for e in events)

    def test_returns_empty_for_unknown_actor(self, engine):
        make_timeline(engine)
        make_event(engine, actor="alice")
        events = engine.get_actor_activity(ORG_A, INC_1, "unknown_actor")
        assert events == []

    def test_actor_events_ordered_by_time(self, engine):
        make_timeline(engine)
        make_event(engine, actor="alice", event_time="2026-04-16T10:30:00+00:00")
        make_event(engine, actor="alice", event_time="2026-04-16T10:00:00+00:00")
        events = engine.get_actor_activity(ORG_A, INC_1, "alice")
        times = [e["event_time"] for e in events]
        assert times == sorted(times)


# ---------------------------------------------------------------------------
# get_timeline_summary
# ---------------------------------------------------------------------------

class TestGetTimelineSummary:
    def test_total_timelines(self, engine):
        make_timeline(engine, incident=INC_1)
        make_timeline(engine, incident=INC_2)
        summary = engine.get_timeline_summary(ORG_A)
        assert summary["total_timelines"] == 2

    def test_open_count(self, engine):
        tl1 = make_timeline(engine, incident=INC_1)
        make_timeline(engine, incident=INC_2)
        engine.close_timeline(tl1["id"], ORG_A)
        summary = engine.get_timeline_summary(ORG_A)
        assert summary["open_count"] == 1

    def test_total_events(self, engine):
        make_timeline(engine, incident=INC_1)
        make_event(engine, incident=INC_1, event_time="2026-04-16T10:00:00+00:00")
        make_event(engine, incident=INC_1, event_time="2026-04-16T10:05:00+00:00")
        summary = engine.get_timeline_summary(ORG_A)
        assert summary["total_events"] == 2

    def test_by_event_type(self, engine):
        make_timeline(engine, incident=INC_1)
        make_event(engine, event_type="authentication", event_time="2026-04-16T10:00:00+00:00")
        make_event(engine, event_type="network", event_time="2026-04-16T10:05:00+00:00")
        make_event(engine, event_type="authentication", event_time="2026-04-16T10:10:00+00:00")
        summary = engine.get_timeline_summary(ORG_A)
        assert summary["by_event_type"]["authentication"] == 2
        assert summary["by_event_type"]["network"] == 1

    def test_recent_timelines_max_5(self, engine):
        for i in range(7):
            make_timeline(engine, incident=f"INC-{i:03d}")
        summary = engine.get_timeline_summary(ORG_A)
        assert len(summary["recent_timelines"]) == 5

    def test_empty_org_returns_zeros(self, engine):
        summary = engine.get_timeline_summary("empty-org")
        assert summary["total_timelines"] == 0
        assert summary["total_events"] == 0


# ---------------------------------------------------------------------------
# search_events
# ---------------------------------------------------------------------------

class TestSearchEvents:
    def test_search_by_actor(self, engine):
        make_timeline(engine)
        make_event(engine, actor="attacker_ip_10.0.0.1", event_time="2026-04-16T10:00:00+00:00")
        make_event(engine, actor="legit_user", event_time="2026-04-16T10:05:00+00:00")
        results = engine.search_events(ORG_A, "attacker")
        assert len(results) == 1
        assert results[0]["actor"] == "attacker_ip_10.0.0.1"

    def test_search_by_target(self, engine):
        make_timeline(engine)
        make_event(engine, target="db-server-prod", event_time="2026-04-16T10:00:00+00:00")
        make_event(engine, target="web-server", event_time="2026-04-16T10:05:00+00:00")
        results = engine.search_events(ORG_A, "db-server")
        assert len(results) == 1

    def test_search_by_action(self, engine):
        make_timeline(engine)
        make_event(engine, action="sudo_exec_bash", event_time="2026-04-16T10:00:00+00:00")
        make_event(engine, action="file_read", event_time="2026-04-16T10:05:00+00:00")
        results = engine.search_events(ORG_A, "sudo")
        assert len(results) == 1

    def test_search_by_raw_data(self, engine):
        make_timeline(engine)
        make_event(engine, raw_data='{"process": "mimikatz.exe"}', event_time="2026-04-16T10:00:00+00:00")
        make_event(engine, raw_data='{"process": "notepad.exe"}', event_time="2026-04-16T10:05:00+00:00")
        results = engine.search_events(ORG_A, "mimikatz")
        assert len(results) == 1

    def test_search_no_match_returns_empty(self, engine):
        make_timeline(engine)
        make_event(engine)
        results = engine.search_events(ORG_A, "zzz_no_match_zzz")
        assert results == []


# ---------------------------------------------------------------------------
# Org isolation
# ---------------------------------------------------------------------------

class TestOrgIsolation:
    def test_timeline_isolated_by_org(self, engine):
        engine.create_timeline(ORG_A, INC_1, "Org A Timeline")
        engine.create_timeline(ORG_B, INC_1, "Org B Timeline")
        tl_a = engine.get_timeline(ORG_A, INC_1)
        tl_b = engine.get_timeline(ORG_B, INC_1)
        assert tl_a["title"] == "Org A Timeline"
        assert tl_b["title"] == "Org B Timeline"

    def test_events_isolated_by_org(self, engine):
        engine.create_timeline(ORG_A, INC_1, "A")
        engine.create_timeline(ORG_B, INC_1, "B")
        make_event(engine, org=ORG_A, actor="alice", event_time="2026-04-16T10:00:00+00:00")
        make_event(engine, org=ORG_B, actor="bob", event_time="2026-04-16T10:00:00+00:00")
        events_a = engine.get_actor_activity(ORG_A, INC_1, "alice")
        events_b = engine.get_actor_activity(ORG_A, INC_1, "bob")
        assert len(events_a) == 1
        assert len(events_b) == 0

    def test_summary_isolated_by_org(self, engine):
        engine.create_timeline(ORG_A, INC_1, "A")
        make_event(engine, org=ORG_A, event_time="2026-04-16T10:00:00+00:00")
        summary_b = engine.get_timeline_summary(ORG_B)
        assert summary_b["total_timelines"] == 0
        assert summary_b["total_events"] == 0

    def test_search_isolated_by_org(self, engine):
        engine.create_timeline(ORG_A, INC_1, "A")
        make_event(engine, org=ORG_A, actor="secret_user", event_time="2026-04-16T10:00:00+00:00")
        results = engine.search_events(ORG_B, "secret_user")
        assert results == []
