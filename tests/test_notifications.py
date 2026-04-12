"""Tests for the ALDECI notification engine and API router.

Covers:
- Rule CRUD (add, update, delete, list)
- Event evaluation against rules (severity, type, source matching)
- Notification generation from events
- Channel dispatch (email mocked, slack mocked, in-app stored)
- Digest grouping (hourly, daily)
- User preferences (quiet hours, muted sources)
- Unread notifications + mark read
- API router endpoints

Total tests: 38
"""

import os
import sys
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

# Ensure suite-core is importable
sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent / "suite-core"))
sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent / "suite-api"))

# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------

from core.notifications import (
    AlertRule,
    Channel,
    DigestFrequency,
    Notification,
    NotificationEngine,
    NotificationPreference,
)
from core.event_emitter import SecurityEvent, EventType, Severity


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    """Fresh NotificationEngine backed by a temp SQLite DB."""
    db = str(tmp_path / "notifications_test.db")
    return NotificationEngine(db_path=db)


@pytest.fixture
def sample_rule():
    return AlertRule(
        name="Critical Findings",
        description="Alert on critical severity findings",
        enabled=True,
        conditions={"severity_gte": "critical"},
        channels=[Channel.EMAIL, Channel.IN_APP],
        recipients=["soc@example.com"],
        digest_frequency=DigestFrequency.IMMEDIATE,
    )


@pytest.fixture
def sample_event():
    return SecurityEvent(
        event_type=EventType.FINDING_CREATED,
        severity=Severity.CRITICAL,
        source="scanner",
        payload={"finding_type": "vulnerability", "cve": "CVE-2025-1234"},
    )


@pytest.fixture
def low_event():
    return SecurityEvent(
        event_type=EventType.FINDING_CREATED,
        severity=Severity.LOW,
        source="scanner",
        payload={},
    )


# ---------------------------------------------------------------------------
# Rule CRUD
# ---------------------------------------------------------------------------


class TestRuleCRUD:
    def test_add_rule_returns_rule(self, engine, sample_rule):
        created = engine.add_rule(sample_rule)
        assert created.id == sample_rule.id
        assert created.name == "Critical Findings"

    def test_add_rule_persisted(self, engine, sample_rule):
        engine.add_rule(sample_rule)
        rules = engine.list_rules()
        assert len(rules) == 1
        assert rules[0].name == "Critical Findings"

    def test_list_rules_empty(self, engine):
        assert engine.list_rules() == []

    def test_list_rules_multiple(self, engine):
        engine.add_rule(AlertRule(name="Rule A", conditions={}, channels=[], recipients=[]))
        engine.add_rule(AlertRule(name="Rule B", conditions={}, channels=[], recipients=[]))
        rules = engine.list_rules()
        assert len(rules) == 2
        names = {r.name for r in rules}
        assert names == {"Rule A", "Rule B"}

    def test_update_rule_name(self, engine, sample_rule):
        engine.add_rule(sample_rule)
        updated = engine.update_rule(sample_rule.id, {"name": "Updated Rule"})
        assert updated.name == "Updated Rule"

    def test_update_rule_enabled(self, engine, sample_rule):
        engine.add_rule(sample_rule)
        updated = engine.update_rule(sample_rule.id, {"enabled": False})
        assert updated.enabled is False

    def test_update_rule_conditions(self, engine, sample_rule):
        engine.add_rule(sample_rule)
        new_cond = {"severity_gte": "high", "event_type": "finding.created"}
        updated = engine.update_rule(sample_rule.id, {"conditions": new_cond})
        assert updated.conditions["severity_gte"] == "high"

    def test_update_nonexistent_rule_raises(self, engine):
        with pytest.raises(KeyError):
            engine.update_rule("nonexistent-id", {"name": "x"})

    def test_delete_rule(self, engine, sample_rule):
        engine.add_rule(sample_rule)
        result = engine.delete_rule(sample_rule.id)
        assert result is True
        assert engine.list_rules() == []

    def test_delete_nonexistent_rule(self, engine):
        result = engine.delete_rule("nonexistent-id")
        assert result is False

    def test_get_rule(self, engine, sample_rule):
        engine.add_rule(sample_rule)
        fetched = engine.get_rule(sample_rule.id)
        assert fetched is not None
        assert fetched.name == sample_rule.name

    def test_get_rule_nonexistent(self, engine):
        assert engine.get_rule("bad-id") is None


# ---------------------------------------------------------------------------
# Event Evaluation
# ---------------------------------------------------------------------------


class TestEventEvaluation:
    def test_critical_event_matches_critical_rule(self, engine, sample_rule, sample_event):
        engine.add_rule(sample_rule)
        notifications = engine.evaluate_event(sample_event)
        assert len(notifications) > 0

    def test_low_event_does_not_match_critical_rule(self, engine, sample_rule, low_event):
        engine.add_rule(sample_rule)
        notifications = engine.evaluate_event(low_event)
        assert notifications == []

    def test_high_severity_matches_medium_gte(self, engine, sample_event):
        rule = AlertRule(
            name="Medium+ Rule",
            enabled=True,
            conditions={"severity_gte": "medium"},
            channels=[Channel.IN_APP],
            recipients=["user@example.com"],
        )
        engine.add_rule(rule)
        # high > medium, should match
        high_event = SecurityEvent(
            event_type=EventType.FINDING_CREATED,
            severity=Severity.HIGH,
            source="scanner",
            payload={},
        )
        notifications = engine.evaluate_event(high_event)
        assert len(notifications) == 1

    def test_event_type_condition(self, engine):
        rule = AlertRule(
            name="SLA Breach Rule",
            enabled=True,
            conditions={"event_type": "sla.breach"},
            channels=[Channel.IN_APP],
            recipients=["soc@example.com"],
        )
        engine.add_rule(rule)
        sla_event = SecurityEvent(
            event_type=EventType.SLA_BREACH,
            severity=Severity.HIGH,
            source="aldeci",
            payload={},
        )
        wrong_event = SecurityEvent(
            event_type=EventType.FINDING_CREATED,
            severity=Severity.HIGH,
            source="aldeci",
            payload={},
        )
        assert len(engine.evaluate_event(sla_event)) == 1
        assert len(engine.evaluate_event(wrong_event)) == 0

    def test_source_condition(self, engine):
        rule = AlertRule(
            name="Scanner Rule",
            enabled=True,
            conditions={"source": "nessus"},
            channels=[Channel.IN_APP],
            recipients=["sec@example.com"],
        )
        engine.add_rule(rule)
        nessus_event = SecurityEvent(
            event_type=EventType.FINDING_CREATED,
            severity=Severity.HIGH,
            source="nessus",
            payload={},
        )
        other_event = SecurityEvent(
            event_type=EventType.FINDING_CREATED,
            severity=Severity.HIGH,
            source="qualys",
            payload={},
        )
        assert len(engine.evaluate_event(nessus_event)) == 1
        assert len(engine.evaluate_event(other_event)) == 0

    def test_disabled_rule_not_matched(self, engine, sample_rule, sample_event):
        sample_rule.enabled = False
        engine.add_rule(sample_rule)
        notifications = engine.evaluate_event(sample_event)
        assert notifications == []

    def test_multiple_recipients_generate_multiple_notifications(self, engine, sample_event):
        rule = AlertRule(
            name="Multi Recipient",
            enabled=True,
            conditions={},
            channels=[Channel.EMAIL],
            recipients=["a@example.com", "b@example.com"],
        )
        engine.add_rule(rule)
        notifications = engine.evaluate_event(sample_event)
        assert len(notifications) == 2
        recipients = {n.recipient for n in notifications}
        assert recipients == {"a@example.com", "b@example.com"}

    def test_multiple_channels_generate_multiple_notifications(self, engine, sample_event):
        rule = AlertRule(
            name="Multi Channel",
            enabled=True,
            conditions={},
            channels=[Channel.EMAIL, Channel.IN_APP],
            recipients=["user@example.com"],
        )
        engine.add_rule(rule)
        notifications = engine.evaluate_event(sample_event)
        assert len(notifications) == 2
        channels = {n.channel for n in notifications}
        assert "email" in channels
        assert "in_app" in channels

    def test_no_conditions_matches_all_events(self, engine, low_event):
        rule = AlertRule(
            name="Catch All",
            enabled=True,
            conditions={},
            channels=[Channel.IN_APP],
            recipients=["admin@example.com"],
        )
        engine.add_rule(rule)
        notifications = engine.evaluate_event(low_event)
        assert len(notifications) == 1


# ---------------------------------------------------------------------------
# Channel Dispatch
# ---------------------------------------------------------------------------


class TestChannelDispatch:
    def test_send_email_mock_safe(self, engine):
        """Email send without SMTP_HOST should log, not raise."""
        notif = Notification(
            rule_name="test",
            channel=Channel.EMAIL,
            recipient="user@example.com",
            subject="Test",
            body="Test body",
        )
        engine._persist_notification(notif)
        # Should not raise even without SMTP configured
        result = engine.send_notification(notif)
        assert result.status == "sent"

    def test_send_in_app_stores_notification(self, engine, sample_event):
        rule = AlertRule(
            name="In-App Rule",
            enabled=True,
            conditions={},
            channels=[Channel.IN_APP],
            recipients=["user@example.com"],
        )
        engine.add_rule(rule)
        notifications = engine.evaluate_event(sample_event)
        assert len(notifications) == 1
        # Dispatch
        sent = engine.send_notification(notifications[0])
        assert sent.status == "sent"

    def test_send_slack_mock_safe(self, engine):
        """Slack send without token should log, not raise."""
        notif = Notification(
            rule_name="test",
            channel=Channel.SLACK,
            recipient="#security",
            subject="Test",
            body="Test body",
        )
        engine._persist_notification(notif)
        result = engine.send_notification(notif)
        assert result.status == "sent"

    def test_notification_status_transitions(self, engine):
        notif = Notification(
            rule_name="test",
            channel=Channel.EMAIL,
            recipient="user@example.com",
            subject="Sub",
            body="Body",
            status="pending",
        )
        engine._persist_notification(notif)
        assert notif.status == "pending"
        sent = engine.send_notification(notif)
        assert sent.status == "sent"


# ---------------------------------------------------------------------------
# Digest
# ---------------------------------------------------------------------------


class TestDigest:
    def test_get_pending_digest_hourly(self, engine):
        for i in range(3):
            n = Notification(
                rule_name=f"rule_{i}",
                channel=Channel.EMAIL,
                recipient="user@example.com",
                subject=f"Alert {i}",
                body=f"Body {i}",
                digest_frequency=DigestFrequency.HOURLY,
            )
            engine._persist_notification(n)

        grouped = engine.get_pending_digest(DigestFrequency.HOURLY)
        assert "user@example.com" in grouped
        assert len(grouped["user@example.com"]) == 3

    def test_get_pending_digest_daily(self, engine):
        n = Notification(
            rule_name="daily_rule",
            channel=Channel.EMAIL,
            recipient="daily@example.com",
            subject="Daily Alert",
            body="Body",
            digest_frequency=DigestFrequency.DAILY,
        )
        engine._persist_notification(n)
        grouped = engine.get_pending_digest(DigestFrequency.DAILY)
        assert "daily@example.com" in grouped

    def test_digest_groups_by_recipient(self, engine):
        for recipient in ["a@example.com", "b@example.com"]:
            n = Notification(
                rule_name="rule",
                channel=Channel.EMAIL,
                recipient=recipient,
                subject="Alert",
                body="Body",
                digest_frequency=DigestFrequency.HOURLY,
            )
            engine._persist_notification(n)

        grouped = engine.get_pending_digest(DigestFrequency.HOURLY)
        assert len(grouped) == 2
        assert "a@example.com" in grouped
        assert "b@example.com" in grouped

    def test_send_digest_marks_source_notifications_sent(self, engine):
        n = Notification(
            rule_name="rule",
            channel=Channel.EMAIL,
            recipient="user@example.com",
            subject="Alert",
            body="Body",
            digest_frequency=DigestFrequency.HOURLY,
        )
        engine._persist_notification(n)
        count = engine.send_digest(DigestFrequency.HOURLY)
        assert count == 1


# ---------------------------------------------------------------------------
# User Preferences
# ---------------------------------------------------------------------------


class TestPreferences:
    def test_set_and_get_preference(self, engine):
        pref = NotificationPreference(
            user_email="user@example.com",
            channels=[Channel.EMAIL, Channel.IN_APP],
            digest_frequency=DigestFrequency.DAILY,
            muted_sources=["qualys"],
            quiet_hours_start=22,
            quiet_hours_end=8,
        )
        engine.set_preference(pref)
        fetched = engine.get_preference("user@example.com")
        assert fetched is not None
        assert fetched.digest_frequency == "daily"
        assert "qualys" in fetched.muted_sources
        assert fetched.quiet_hours_start == 22
        assert fetched.quiet_hours_end == 8

    def test_get_preference_nonexistent(self, engine):
        result = engine.get_preference("nobody@example.com")
        assert result is None

    def test_update_preference_upsert(self, engine):
        pref1 = NotificationPreference(
            user_email="user@example.com",
            channels=[Channel.EMAIL],
            digest_frequency=DigestFrequency.IMMEDIATE,
        )
        engine.set_preference(pref1)
        pref2 = NotificationPreference(
            user_email="user@example.com",
            channels=[Channel.IN_APP],
            digest_frequency=DigestFrequency.WEEKLY,
        )
        engine.set_preference(pref2)
        fetched = engine.get_preference("user@example.com")
        assert fetched.digest_frequency == "weekly"
        assert "in_app" in fetched.channels


# ---------------------------------------------------------------------------
# Unread Notifications + Mark Read
# ---------------------------------------------------------------------------


class TestInboxAndMarkRead:
    def test_get_unread_notifications(self, engine, sample_event):
        rule = AlertRule(
            name="In-App Rule",
            enabled=True,
            conditions={},
            channels=[Channel.IN_APP],
            recipients=["user@example.com"],
        )
        engine.add_rule(rule)
        engine.evaluate_event(sample_event)

        unread = engine.get_unread_notifications("user@example.com")
        assert len(unread) == 1
        assert unread[0].read is False

    def test_mark_read(self, engine, sample_event):
        rule = AlertRule(
            name="In-App Rule",
            enabled=True,
            conditions={},
            channels=[Channel.IN_APP],
            recipients=["user@example.com"],
        )
        engine.add_rule(rule)
        engine.evaluate_event(sample_event)

        unread = engine.get_unread_notifications("user@example.com")
        assert len(unread) == 1

        ids = [n.id for n in unread]
        count = engine.mark_read(ids)
        assert count == 1

        still_unread = engine.get_unread_notifications("user@example.com")
        assert len(still_unread) == 0

    def test_mark_read_empty_list(self, engine):
        count = engine.mark_read([])
        assert count == 0

    def test_unread_only_returns_in_app(self, engine, sample_event):
        """Email notifications should not appear in in-app inbox."""
        rule = AlertRule(
            name="Email Rule",
            enabled=True,
            conditions={},
            channels=[Channel.EMAIL],
            recipients=["user@example.com"],
        )
        engine.add_rule(rule)
        engine.evaluate_event(sample_event)

        unread = engine.get_unread_notifications("user@example.com")
        assert len(unread) == 0

    def test_unread_is_user_scoped(self, engine, sample_event):
        rule = AlertRule(
            name="In-App Rule",
            enabled=True,
            conditions={},
            channels=[Channel.IN_APP],
            recipients=["alice@example.com"],
        )
        engine.add_rule(rule)
        engine.evaluate_event(sample_event)

        # Bob should have no notifications
        assert engine.get_unread_notifications("bob@example.com") == []
        # Alice should have one
        assert len(engine.get_unread_notifications("alice@example.com")) == 1


# ---------------------------------------------------------------------------
# API Router
# ---------------------------------------------------------------------------


class TestNotificationRouter:
    @pytest.fixture(autouse=True)
    def setup_client(self, tmp_path):
        """Set up FastAPI test client with a fresh engine."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        import core.notifications as notif_module
        import apps.api.notification_router as router_module

        # Patch engine with temp-db instance
        db = str(tmp_path / "api_test.db")
        test_engine = NotificationEngine(db_path=db)
        router_module._engine = test_engine

        app = FastAPI()
        app.include_router(router_module.router)
        self.client = TestClient(app)
        self.engine = test_engine

    def test_create_rule(self):
        resp = self.client.post("/api/v1/notifications/rules", json={
            "name": "Test Rule",
            "conditions": {"severity_gte": "high"},
            "channels": ["email"],
            "recipients": ["sec@example.com"],
            "digest_frequency": "immediate",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "Test Rule"
        assert "id" in data

    def test_list_rules_empty(self):
        resp = self.client.get("/api/v1/notifications/rules")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_list_rules_after_create(self):
        self.client.post("/api/v1/notifications/rules", json={
            "name": "Rule X",
            "conditions": {},
            "channels": ["in_app"],
            "recipients": ["x@example.com"],
        })
        resp = self.client.get("/api/v1/notifications/rules")
        assert resp.status_code == 200
        assert len(resp.json()) == 1

    def test_update_rule(self):
        create_resp = self.client.post("/api/v1/notifications/rules", json={
            "name": "Old Name",
            "conditions": {},
            "channels": ["in_app"],
            "recipients": ["x@example.com"],
        })
        rule_id = create_resp.json()["id"]
        resp = self.client.put(f"/api/v1/notifications/rules/{rule_id}", json={"name": "New Name"})
        assert resp.status_code == 200
        assert resp.json()["name"] == "New Name"

    def test_update_rule_not_found(self):
        resp = self.client.put("/api/v1/notifications/rules/nonexistent", json={"name": "x"})
        assert resp.status_code == 404

    def test_delete_rule(self):
        create_resp = self.client.post("/api/v1/notifications/rules", json={
            "name": "To Delete",
            "conditions": {},
            "channels": ["in_app"],
            "recipients": ["x@example.com"],
        })
        rule_id = create_resp.json()["id"]
        resp = self.client.delete(f"/api/v1/notifications/rules/{rule_id}")
        assert resp.status_code == 200
        assert resp.json()["status"] == "deleted"

    def test_delete_rule_not_found(self):
        resp = self.client.delete("/api/v1/notifications/rules/nonexistent")
        assert resp.status_code == 404

    def test_get_inbox(self):
        resp = self.client.get("/api/v1/notifications/inbox", params={"user_email": "user@example.com"})
        assert resp.status_code == 200
        assert resp.json() == []

    def test_mark_read(self):
        resp = self.client.post("/api/v1/notifications/read", json={"notification_ids": []})
        assert resp.status_code == 200
        assert resp.json()["marked_read"] == 0

    def test_get_preferences_defaults(self):
        resp = self.client.get("/api/v1/notifications/preferences", params={"user_email": "new@example.com"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["user_email"] == "new@example.com"

    def test_update_preferences(self):
        resp = self.client.put(
            "/api/v1/notifications/preferences",
            params={"user_email": "user@example.com"},
            json={"digest_frequency": "daily", "quiet_hours_start": 22, "quiet_hours_end": 7},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["digest_frequency"] == "daily"
        assert data["quiet_hours_start"] == 22
