"""
Tests for SLAEscalationEngine.

Covers:
- check_sla_breaches with no findings → empty list
- check_sla_breaches with past-deadline findings → correct breach list
- check_sla_breaches ignores future-deadline findings
- escalate with each valid action → returns record with correct fields
- escalate with invalid action → raises ValueError
- run_escalation_cycle returns correct structure keys
- run_escalation_cycle with no breaches → zero counts
- run_escalation_cycle with breaches → triggers actions
- run_escalation_cycle respects breach_threshold_hours policy
- set_escalation_policy round-trip (all fields)
- set_escalation_policy updates existing policy
- get_escalation_policy returns defaults when no policy set
- escalation_history empty for new org
- escalation_history returns events after escalate()
- escalation_history filtered by finding_id
- escalation_history different finding_ids isolated
- breach detection: 0-24h → notify only
- breach detection: 24-72h → reassign only
- breach detection: 72h+ → escalate_severity + create_incident
- severity_bump policy adds escalate_severity action
- track_finding enables breach detection
- multiple orgs are isolated from each other
"""
from __future__ import annotations

import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

from core.sla_escalation_engine import EscalationAction, SLAEscalationEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    """Fresh engine backed by a temp SQLite file per test."""
    db_file = str(tmp_path / "test_sla_escalation.db")
    return SLAEscalationEngine(db_path=db_file)


def _past(hours: float) -> datetime:
    """Return a UTC datetime `hours` in the past."""
    return datetime.now(timezone.utc) - timedelta(hours=hours)


def _future(hours: float) -> datetime:
    """Return a UTC datetime `hours` in the future."""
    return datetime.now(timezone.utc) + timedelta(hours=hours)


# ---------------------------------------------------------------------------
# check_sla_breaches
# ---------------------------------------------------------------------------


def test_check_sla_breaches_no_findings_returns_empty(engine):
    result = engine.check_sla_breaches(org_id="test-org")
    assert result == []


def test_check_sla_breaches_future_deadline_not_included(engine):
    engine.track_finding("f-future", _future(48), severity="high", org_id="test-org")
    result = engine.check_sla_breaches(org_id="test-org")
    assert result == []


def test_check_sla_breaches_past_deadline_returned(engine):
    engine.track_finding("f-past", _past(10), severity="critical", org_id="test-org")
    result = engine.check_sla_breaches(org_id="test-org")
    assert len(result) == 1
    item = result[0]
    assert item["finding_id"] == "f-past"
    assert item["severity"] == "critical"
    assert item["hours_past_deadline"] > 0


def test_check_sla_breaches_returns_recommended_actions(engine):
    engine.track_finding("f-notify", _past(5), severity="medium", org_id="test-org")
    result = engine.check_sla_breaches(org_id="test-org")
    assert EscalationAction.NOTIFY in result[0]["recommended_actions"]


def test_check_sla_breaches_multiple_findings(engine):
    engine.track_finding("f-1", _past(2), severity="low", org_id="test-org")
    engine.track_finding("f-2", _past(30), severity="critical", org_id="test-org")
    engine.track_finding("f-3", _future(10), severity="high", org_id="test-org")
    result = engine.check_sla_breaches(org_id="test-org")
    finding_ids = {r["finding_id"] for r in result}
    assert finding_ids == {"f-1", "f-2"}


# ---------------------------------------------------------------------------
# escalate
# ---------------------------------------------------------------------------


def test_escalate_notify_returns_record(engine):
    record = engine.escalate("f-x", EscalationAction.NOTIFY, org_id="test-org")
    assert record["finding_id"] == "f-x"
    assert record["action"] == EscalationAction.NOTIFY
    assert "id" in record
    assert "created_at" in record


def test_escalate_reassign_returns_record(engine):
    record = engine.escalate("f-x", EscalationAction.REASSIGN, org_id="test-org")
    assert record["action"] == EscalationAction.REASSIGN


def test_escalate_escalate_severity_returns_record(engine):
    record = engine.escalate("f-x", EscalationAction.ESCALATE_SEVERITY, org_id="test-org")
    assert record["action"] == EscalationAction.ESCALATE_SEVERITY


def test_escalate_create_incident_returns_record(engine):
    record = engine.escalate("f-x", EscalationAction.CREATE_INCIDENT, org_id="test-org")
    assert record["action"] == EscalationAction.CREATE_INCIDENT


def test_escalate_override_sla_returns_record(engine):
    record = engine.escalate("f-x", EscalationAction.OVERRIDE_SLA, org_id="test-org")
    assert record["action"] == EscalationAction.OVERRIDE_SLA


def test_escalate_invalid_action_raises_value_error(engine):
    with pytest.raises(ValueError, match="Unknown escalation action"):
        engine.escalate("f-x", "teleport", org_id="test-org")


def test_escalate_hours_past_populated_for_breached_finding(engine):
    engine.track_finding("f-breach", _past(50), severity="high", org_id="test-org")
    record = engine.escalate("f-breach", EscalationAction.REASSIGN, org_id="test-org")
    assert record["hours_past_deadline"] > 0


# ---------------------------------------------------------------------------
# run_escalation_cycle
# ---------------------------------------------------------------------------


def test_run_escalation_cycle_returns_correct_structure(engine):
    result = engine.run_escalation_cycle(org_id="test-org")
    assert "breaches_found" in result
    assert "escalations_triggered" in result
    assert "actions" in result
    assert isinstance(result["actions"], list)


def test_run_escalation_cycle_no_breaches_zero_counts(engine):
    engine.track_finding("f-ok", _future(24), severity="low", org_id="test-org")
    result = engine.run_escalation_cycle(org_id="test-org")
    assert result["breaches_found"] == 0
    assert result["escalations_triggered"] == 0


def test_run_escalation_cycle_with_breaches_triggers_actions(engine):
    # Policy: threshold = 0h so any breach triggers immediately
    engine.set_escalation_policy({"breach_threshold_hours": 0}, org_id="test-org")
    engine.track_finding("f-breach", _past(5), severity="critical", org_id="test-org")
    result = engine.run_escalation_cycle(org_id="test-org")
    assert result["breaches_found"] == 1
    assert result["escalations_triggered"] >= 1


def test_run_escalation_cycle_respects_threshold(engine):
    # Threshold = 48h; breach is only 5h old → should NOT fire
    engine.set_escalation_policy({"breach_threshold_hours": 48}, org_id="test-org")
    engine.track_finding("f-small", _past(5), severity="high", org_id="test-org")
    result = engine.run_escalation_cycle(org_id="test-org")
    assert result["escalations_triggered"] == 0


# ---------------------------------------------------------------------------
# set/get escalation policy
# ---------------------------------------------------------------------------


def test_set_get_policy_round_trip(engine):
    policy_in = {
        "breach_threshold_hours": 48,
        "auto_action": EscalationAction.REASSIGN,
        "severity_bump": True,
    }
    stored = engine.set_escalation_policy(policy_in, org_id="test-org")
    fetched = engine.get_escalation_policy(org_id="test-org")
    assert fetched["breach_threshold_hours"] == 48
    assert fetched["auto_action"] == EscalationAction.REASSIGN
    assert fetched["severity_bump"] is True


def test_set_policy_updates_existing(engine):
    engine.set_escalation_policy({"breach_threshold_hours": 24}, org_id="test-org")
    engine.set_escalation_policy({"breach_threshold_hours": 72}, org_id="test-org")
    fetched = engine.get_escalation_policy(org_id="test-org")
    assert fetched["breach_threshold_hours"] == 72


def test_get_policy_returns_defaults_when_none_set(engine):
    policy = engine.get_escalation_policy(org_id="no-policy-org")
    assert policy["breach_threshold_hours"] == 24
    assert policy["auto_action"] == EscalationAction.NOTIFY
    assert policy["severity_bump"] is False
    assert policy["updated_at"] is None


# ---------------------------------------------------------------------------
# escalation_history
# ---------------------------------------------------------------------------


def test_escalation_history_empty_for_new_org(engine):
    history = engine.get_escalation_history(org_id="fresh-org")
    assert history == []


def test_escalation_history_populated_after_escalate(engine):
    engine.escalate("f-1", EscalationAction.NOTIFY, org_id="test-org")
    history = engine.get_escalation_history(org_id="test-org")
    assert len(history) == 1
    assert history[0]["action"] == EscalationAction.NOTIFY


def test_escalation_history_filter_by_finding_id(engine):
    engine.escalate("f-a", EscalationAction.NOTIFY, org_id="test-org")
    engine.escalate("f-b", EscalationAction.REASSIGN, org_id="test-org")
    history_a = engine.get_escalation_history(finding_id="f-a", org_id="test-org")
    assert all(e["finding_id"] == "f-a" for e in history_a)
    assert len(history_a) == 1


def test_escalation_history_different_findings_isolated(engine):
    engine.escalate("f-x", EscalationAction.NOTIFY, org_id="test-org")
    engine.escalate("f-y", EscalationAction.NOTIFY, org_id="test-org")
    history_x = engine.get_escalation_history(finding_id="f-x", org_id="test-org")
    history_y = engine.get_escalation_history(finding_id="f-y", org_id="test-org")
    assert len(history_x) == 1
    assert len(history_y) == 1
    assert history_x[0]["finding_id"] == "f-x"
    assert history_y[0]["finding_id"] == "f-y"


# ---------------------------------------------------------------------------
# Breach tier detection
# ---------------------------------------------------------------------------


def test_breach_tier_0_24h_recommends_notify(engine):
    engine.track_finding("f-tier1", _past(5), severity="medium", org_id="test-org")
    result = engine.check_sla_breaches(org_id="test-org")
    assert result[0]["recommended_actions"] == [EscalationAction.NOTIFY]


def test_breach_tier_24_72h_recommends_reassign(engine):
    engine.track_finding("f-tier2", _past(36), severity="medium", org_id="test-org")
    result = engine.check_sla_breaches(org_id="test-org")
    assert result[0]["recommended_actions"] == [EscalationAction.REASSIGN]


def test_breach_tier_72h_plus_recommends_severity_and_incident(engine):
    engine.track_finding("f-tier3", _past(100), severity="low", org_id="test-org")
    result = engine.check_sla_breaches(org_id="test-org")
    actions = result[0]["recommended_actions"]
    assert EscalationAction.ESCALATE_SEVERITY in actions
    assert EscalationAction.CREATE_INCIDENT in actions


# ---------------------------------------------------------------------------
# Severity bump policy
# ---------------------------------------------------------------------------


def test_severity_bump_policy_adds_escalate_severity(engine):
    engine.set_escalation_policy(
        {"breach_threshold_hours": 0, "severity_bump": True},
        org_id="test-org",
    )
    # Use a 36h breach (would normally → reassign only)
    engine.track_finding("f-bump", _past(36), severity="high", org_id="test-org")
    result = engine.run_escalation_cycle(org_id="test-org")
    action_names = [a["action"] for a in result["actions"]]
    assert EscalationAction.ESCALATE_SEVERITY in action_names


# ---------------------------------------------------------------------------
# Multi-org isolation
# ---------------------------------------------------------------------------


def test_multiple_orgs_are_isolated(engine):
    engine.track_finding("f-shared-id", _past(10), severity="critical", org_id="org-a")
    engine.track_finding("f-shared-id", _past(10), severity="critical", org_id="org-b")
    engine.escalate("f-shared-id", EscalationAction.NOTIFY, org_id="org-a")

    history_a = engine.get_escalation_history(finding_id="f-shared-id", org_id="org-a")
    history_b = engine.get_escalation_history(finding_id="f-shared-id", org_id="org-b")
    assert len(history_a) == 1
    assert len(history_b) == 0
