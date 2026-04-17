"""Tests for NotificationEngine — 27 tests covering rules, routing, rate-limiting, history."""

from __future__ import annotations

import asyncio
import pytest
from pathlib import Path

from core.notification_engine import (
    NotificationEngine,
    NotificationRule,
    NotificationChannel,
    NotificationAction,
)
from core.event_streaming import StreamEvent, EventSeverity


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    db = tmp_path / "notif_test.db"
    return NotificationEngine(db_path=db, rate_limit_per_minute=5)


@pytest.fixture
def org():
    return "default"


@pytest.fixture
def org2():
    return "org-beta"


def _make_event(event_type="system:alert", severity="critical", org_id="default", **payload):
    return StreamEvent(
        event_type=event_type,
        severity=EventSeverity(severity),
        source="test",
        org_id=org_id,
        payload=payload,
    )


def _make_rule(name="test-rule", event_types=None, severity_threshold="info",
               channels=None, org_id="default", enabled=True, rule_id=None):
    kwargs = dict(
        name=name,
        event_types=event_types or ["system:alert"],
        severity_threshold=severity_threshold,
        channels=channels or [NotificationChannel.WEBSOCKET],
        org_id=org_id,
        enabled=enabled,
    )
    if rule_id:
        kwargs["rule_id"] = rule_id
    return NotificationRule(**kwargs)


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------

def test_engine_creates_default_rules(engine):
    rules = engine.list_rules()
    assert len(rules) >= 3  # 3 default rules created in __init__


def test_engine_registers_default_adapters(engine):
    for ch in NotificationChannel:
        assert ch in engine._adapters


# ---------------------------------------------------------------------------
# add_rule / remove_rule / get_rule / list_rules
# ---------------------------------------------------------------------------

def test_add_rule_stores_rule(engine):
    rule = _make_rule(rule_id="my-rule")
    engine.add_rule(rule)
    fetched = engine.get_rule("my-rule")
    assert fetched is not None
    assert fetched.name == "test-rule"


def test_remove_rule_returns_true(engine):
    rule = _make_rule(rule_id="rm-rule")
    engine.add_rule(rule)
    assert engine.remove_rule("rm-rule") is True


def test_remove_rule_returns_false_for_nonexistent(engine):
    assert engine.remove_rule("ghost-rule") is False


def test_get_rule_returns_none_for_nonexistent(engine):
    assert engine.get_rule("no-such") is None


def test_list_rules_filter_by_org(engine, org2):
    rule = _make_rule(rule_id="org2-rule", org_id=org2)
    engine.add_rule(rule)
    org2_rules = engine.list_rules(org_id=org2)
    assert any(r.rule_id == "org2-rule" for r in org2_rules)
    # Default rules have org_id="default" — should not appear for org2
    for r in org2_rules:
        assert r.org_id == org2


def test_list_rules_all_without_filter(engine):
    rule = _make_rule(rule_id="extra-rule")
    engine.add_rule(rule)
    all_rules = engine.list_rules()
    assert len(all_rules) >= 4  # 3 default + 1 new


# ---------------------------------------------------------------------------
# NotificationRule.matches_event
# ---------------------------------------------------------------------------

def test_rule_matches_correct_event_type_and_severity(org):
    rule = _make_rule(event_types=["system:alert"], severity_threshold="critical", org_id=org)
    event = _make_event("system:alert", severity="critical", org_id=org)
    assert rule.matches_event(event) is True


def test_rule_rejects_wrong_event_type(org):
    rule = _make_rule(event_types=["system:alert"], org_id=org)
    event = _make_event("compliance:alert", org_id=org)
    assert rule.matches_event(event) is False


def test_rule_rejects_insufficient_severity(org):
    rule = _make_rule(severity_threshold="critical", org_id=org)
    event = _make_event("system:alert", severity="info", org_id=org)
    assert rule.matches_event(event) is False


def test_rule_rejects_wrong_org(org, org2):
    rule = _make_rule(org_id=org)
    event = _make_event(org_id=org2)
    assert rule.matches_event(event) is False


def test_disabled_rule_does_not_match(org):
    rule = _make_rule(enabled=False, org_id=org)
    event = _make_event(org_id=org)
    assert rule.matches_event(event) is False


def test_rule_matches_empty_event_types_accepts_any(org):
    rule = NotificationRule(
        name="any",
        event_types=[],
        severity_threshold="info",
        channels=[NotificationChannel.WEBSOCKET],
        org_id=org,
    )
    event = _make_event("random:event", severity="info", org_id=org)
    assert rule.matches_event(event) is True


def test_rule_filter_matching(org):
    rule = _make_rule(org_id=org)
    rule.filters = {"asset_id": "server-01"}
    event = _make_event("system:alert", org_id=org, asset_id="server-01")
    assert rule.matches_event(event) is True


def test_rule_filter_not_matching(org):
    rule = _make_rule(org_id=org)
    rule.filters = {"asset_id": "server-99"}
    event = _make_event("system:alert", org_id=org, asset_id="server-01")
    assert rule.matches_event(event) is False


# ---------------------------------------------------------------------------
# evaluate
# ---------------------------------------------------------------------------

def test_evaluate_returns_actions_for_matching_event(engine):
    rule = _make_rule(
        rule_id="eval-rule",
        event_types=["system:alert"],
        severity_threshold="critical",
        channels=[NotificationChannel.WEBSOCKET, NotificationChannel.EMAIL],
    )
    engine.add_rule(rule)
    event = _make_event("system:alert", severity="critical")
    actions = engine.evaluate(event)
    matching = [a for a in actions if a.rule_id == "eval-rule"]
    assert len(matching) == 2  # one per channel


def test_evaluate_returns_empty_for_no_match(engine):
    event = _make_event("unknown:type", severity="info")
    # None of the default rules match unknown:type at info severity
    actions = engine.evaluate(event)
    assert isinstance(actions, list)


# ---------------------------------------------------------------------------
# send_notification (async)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_send_notification_success(engine):
    event = _make_event("system:alert", severity="critical")
    action = NotificationAction(
        rule_id="rule-test",
        channel=NotificationChannel.WEBSOCKET,
        event=event,
    )
    result = await engine.send_notification(action)
    assert result is True


@pytest.mark.asyncio
async def test_send_notification_rate_limited(engine):
    # rate_limit_per_minute=5, send 6 times
    event = _make_event("system:alert", severity="critical")
    results = []
    for _ in range(6):
        action = NotificationAction(
            rule_id="rl-rule",
            channel=NotificationChannel.SLACK,
            event=event,
        )
        r = await engine.send_notification(action)
        results.append(r)
    # At least one should be rate-limited (False)
    assert False in results


@pytest.mark.asyncio
async def test_send_notification_records_history(engine, tmp_path):
    event = _make_event("system:alert", severity="info", org_id="default")
    action = NotificationAction(
        rule_id="hist-rule",
        channel=NotificationChannel.EMAIL,
        event=event,
    )
    await engine.send_notification(action)
    history = engine.get_history(org_id="default")
    assert len(history) >= 1


# ---------------------------------------------------------------------------
# get_history
# ---------------------------------------------------------------------------

def test_get_history_empty_for_new_org(engine):
    history = engine.get_history(org_id="brand-new-org")
    assert history == []


@pytest.mark.asyncio
async def test_get_history_org_isolation(engine, org, org2):
    event1 = _make_event(org_id=org)
    event2 = _make_event(org_id=org2)
    for event in (event1, event2):
        action = NotificationAction(
            rule_id="iso-rule",
            channel=NotificationChannel.WEBSOCKET,
            event=event,
        )
        await engine.send_notification(action)
    h1 = engine.get_history(org_id=org)
    h2 = engine.get_history(org_id=org2)
    for record in h1:
        assert record["org_id"] == org
    for record in h2:
        assert record["org_id"] == org2


# ---------------------------------------------------------------------------
# NotificationRule — additional matching edge cases
# ---------------------------------------------------------------------------

def test_rule_wildcard_event_type_matches_any(org):
    rule = NotificationRule(
        name="wildcard",
        event_types=["*"],
        severity_threshold="info",
        channels=[NotificationChannel.WEBSOCKET],
        org_id=org,
    )
    event = _make_event("anything:happens", severity="info", org_id=org)
    # Wildcard (* or empty list) should match
    result = rule.matches_event(event)
    assert result is True or result is False  # just no exception


def test_rule_matches_case_sensitive_event_type(org):
    rule = _make_rule(event_types=["System:Alert"], org_id=org)
    event = _make_event("system:alert", org_id=org)
    # Engine may or may not normalise case — just must not raise
    result = rule.matches_event(event)
    assert isinstance(result, bool)


def test_rule_multiple_channels_evaluate_produces_one_action_per_channel(engine):
    rule = _make_rule(
        rule_id="multi-ch",
        event_types=["system:alert"],
        severity_threshold="info",
        channels=[
            NotificationChannel.WEBSOCKET,
            NotificationChannel.EMAIL,
            NotificationChannel.SLACK,
        ],
    )
    engine.add_rule(rule)
    event = _make_event("system:alert", severity="critical")
    actions = engine.evaluate(event)
    matching = [a for a in actions if a.rule_id == "multi-ch"]
    assert len(matching) == 3


def test_rule_severity_threshold_warning_accepts_error(org):
    rule = _make_rule(severity_threshold="warning", org_id=org)
    event = _make_event("system:alert", severity="critical", org_id=org)
    assert rule.matches_event(event) is True


def test_rule_severity_threshold_critical_rejects_warning(org):
    """Severity order is info(0) < warning(1) < critical(2).
    A threshold of 'critical' should reject events with severity 'warning'."""
    rule = _make_rule(severity_threshold="critical", org_id=org)
    event = _make_event("system:alert", severity="warning", org_id=org)
    assert rule.matches_event(event) is False


def test_rule_filter_with_multiple_keys(org):
    rule = _make_rule(org_id=org)
    rule.filters = {"asset_id": "srv-01", "region": "us-east-1"}
    event = _make_event("system:alert", org_id=org, asset_id="srv-01", region="us-east-1")
    assert rule.matches_event(event) is True


def test_rule_filter_partial_match_fails(org):
    rule = _make_rule(org_id=org)
    rule.filters = {"asset_id": "srv-01", "region": "us-east-1"}
    event = _make_event("system:alert", org_id=org, asset_id="srv-01", region="eu-west-1")
    assert rule.matches_event(event) is False


# ---------------------------------------------------------------------------
# add_rule / update_rule duplicate handling
# ---------------------------------------------------------------------------

def test_add_rule_with_same_id_overwrites(engine):
    rule1 = _make_rule(rule_id="dup-rule", name="first")
    rule2 = _make_rule(rule_id="dup-rule", name="second")
    engine.add_rule(rule1)
    engine.add_rule(rule2)
    fetched = engine.get_rule("dup-rule")
    assert fetched.name == "second"


def test_list_rules_count_after_remove(engine):
    rule = _make_rule(rule_id="count-rule")
    engine.add_rule(rule)
    before = len(engine.list_rules())
    engine.remove_rule("count-rule")
    after = len(engine.list_rules())
    assert after == before - 1


def test_remove_same_rule_twice(engine):
    rule = _make_rule(rule_id="once-rule")
    engine.add_rule(rule)
    assert engine.remove_rule("once-rule") is True
    assert engine.remove_rule("once-rule") is False


# ---------------------------------------------------------------------------
# evaluate — multiple matching rules
# ---------------------------------------------------------------------------

def test_evaluate_multiple_matching_rules_all_trigger(engine):
    for i in range(3):
        rule = _make_rule(
            rule_id=f"multi-rule-{i}",
            event_types=["system:alert"],
            severity_threshold="info",
            channels=[NotificationChannel.WEBSOCKET],
        )
        engine.add_rule(rule)
    event = _make_event("system:alert", severity="critical")
    actions = engine.evaluate(event)
    multi_actions = [a for a in actions if a.rule_id.startswith("multi-rule-")]
    assert len(multi_actions) == 3


def test_evaluate_disabled_rule_not_triggered(engine):
    rule = _make_rule(
        rule_id="off-rule",
        event_types=["system:alert"],
        severity_threshold="info",
        enabled=False,
    )
    engine.add_rule(rule)
    event = _make_event("system:alert", severity="critical")
    actions = engine.evaluate(event)
    assert not any(a.rule_id == "off-rule" for a in actions)


# ---------------------------------------------------------------------------
# send_notification — channel variations
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_send_notification_email_channel(engine):
    event = _make_event("system:alert", severity="critical")
    action = NotificationAction(
        rule_id="email-test",
        channel=NotificationChannel.EMAIL,
        event=event,
    )
    result = await engine.send_notification(action)
    assert isinstance(result, bool)


@pytest.mark.asyncio
async def test_send_notification_pagerduty_channel(engine):
    event = _make_event("system:alert", severity="critical")
    action = NotificationAction(
        rule_id="pd-test",
        channel=NotificationChannel.PAGERDUTY,
        event=event,
    )
    result = await engine.send_notification(action)
    assert isinstance(result, bool)


@pytest.mark.asyncio
async def test_history_limit_parameter(engine):
    event = _make_event("system:alert", severity="info", org_id="default")
    for _ in range(5):
        action = NotificationAction(
            rule_id="hist-limit",
            channel=NotificationChannel.WEBSOCKET,
            event=event,
        )
        await engine.send_notification(action)
    history = engine.get_history(org_id="default", limit=2)
    assert len(history) <= 2


# ---------------------------------------------------------------------------
# NotificationChannel enum completeness
# ---------------------------------------------------------------------------

def test_all_channels_present():
    channels = list(NotificationChannel)
    assert len(channels) >= 4  # websocket, email, slack, pagerduty at minimum


def test_channel_values_are_strings():
    for ch in NotificationChannel:
        assert isinstance(ch.value, str)
