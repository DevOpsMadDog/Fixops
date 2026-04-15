"""Tests for IncidentCommsEngine.

Covers communication creation, sending, acknowledgments, templates,
filtering, org isolation, and statistics.

Total: 37 tests.
"""

from __future__ import annotations

import os
import pytest
from core.incident_comms_engine import IncidentCommsEngine


@pytest.fixture()
def engine(tmp_path):
    db = str(tmp_path / "incident_comms_test.db")
    return IncidentCommsEngine(db_path=db)


@pytest.fixture()
def draft_comm(engine):
    return engine.create_comm("org1", {
        "incident_id": "INC-001",
        "comm_type": "initial_notification",
        "channel": "email",
        "subject": "Security Incident Detected",
        "body": "We have detected a critical security incident. Please stand by.",
        "audience": "internal",
        "severity": "critical",
        "author": "soc_lead",
    })


@pytest.fixture()
def slack_comm(engine):
    return engine.create_comm("org1", {
        "incident_id": "INC-002",
        "comm_type": "status_update",
        "channel": "slack",
        "subject": "Incident INC-002 Update",
        "body": "Investigation ongoing. No customer impact confirmed.",
        "audience": "technical",
        "severity": "high",
    })


# ===========================================================================
# 1. Initialization
# ===========================================================================

def test_init_creates_db(tmp_path):
    db = str(tmp_path / "ic_init.db")
    IncidentCommsEngine(db_path=db)
    assert os.path.exists(db)


def test_init_idempotent(tmp_path):
    db = str(tmp_path / "ic_idem.db")
    IncidentCommsEngine(db_path=db)
    IncidentCommsEngine(db_path=db)


# ===========================================================================
# 2. create_comm — validation
# ===========================================================================

def test_create_comm_returns_record(engine, draft_comm):
    assert draft_comm["id"]
    assert draft_comm["comm_type"] == "initial_notification"
    assert draft_comm["channel"] == "email"
    assert draft_comm["comm_status"] == "draft"
    assert draft_comm["delivered_count"] == 0
    assert draft_comm["failed_count"] == 0
    assert draft_comm["sent_at"] is None


def test_create_comm_requires_subject(engine):
    with pytest.raises(ValueError, match="subject"):
        engine.create_comm("org1", {
            "comm_type": "status_update",
            "channel": "email",
            "body": "Body text",
        })


def test_create_comm_requires_body(engine):
    with pytest.raises(ValueError, match="body"):
        engine.create_comm("org1", {
            "comm_type": "status_update",
            "channel": "email",
            "subject": "Subject",
        })


def test_create_comm_invalid_comm_type(engine):
    with pytest.raises(ValueError, match="comm_type"):
        engine.create_comm("org1", {
            "comm_type": "broadcast",
            "channel": "email",
            "subject": "S",
            "body": "B",
        })


def test_create_comm_invalid_channel(engine):
    with pytest.raises(ValueError, match="channel"):
        engine.create_comm("org1", {
            "comm_type": "status_update",
            "channel": "fax",
            "subject": "S",
            "body": "B",
        })


def test_create_comm_invalid_audience(engine):
    with pytest.raises(ValueError, match="audience"):
        engine.create_comm("org1", {
            "comm_type": "status_update",
            "channel": "email",
            "subject": "S",
            "body": "B",
            "audience": "aliens",
        })


def test_create_comm_invalid_severity(engine):
    with pytest.raises(ValueError, match="severity"):
        engine.create_comm("org1", {
            "comm_type": "status_update",
            "channel": "email",
            "subject": "S",
            "body": "B",
            "severity": "catastrophic",
        })


def test_create_comm_default_severity_medium(engine):
    c = engine.create_comm("org1", {
        "comm_type": "status_update",
        "channel": "email",
        "subject": "S",
        "body": "B",
    })
    assert c["severity"] == "medium"


def test_create_comm_default_status_draft(engine):
    c = engine.create_comm("org1", {
        "comm_type": "resolution",
        "channel": "slack",
        "subject": "Resolved",
        "body": "Incident resolved.",
    })
    assert c["comm_status"] == "draft"


# ===========================================================================
# 3. list_comms / get_comm
# ===========================================================================

def test_list_comms_returns_all(engine, draft_comm, slack_comm):
    comms = engine.list_comms("org1")
    assert len(comms) == 2


def test_list_comms_filter_by_incident(engine, draft_comm, slack_comm):
    comms = engine.list_comms("org1", incident_id="INC-001")
    assert len(comms) == 1
    assert comms[0]["incident_id"] == "INC-001"


def test_list_comms_filter_by_comm_type(engine, draft_comm, slack_comm):
    comms = engine.list_comms("org1", comm_type="status_update")
    assert len(comms) == 1
    assert comms[0]["comm_type"] == "status_update"


def test_list_comms_filter_by_status(engine, draft_comm):
    comms = engine.list_comms("org1", comm_status="draft")
    assert len(comms) >= 1


def test_list_comms_org_isolation(engine, draft_comm):
    other = engine.list_comms("org_other")
    assert len(other) == 0


def test_get_comm_returns_record(engine, draft_comm):
    result = engine.get_comm("org1", draft_comm["id"])
    assert result is not None
    assert result["id"] == draft_comm["id"]


def test_get_comm_wrong_org_returns_none(engine, draft_comm):
    assert engine.get_comm("org_x", draft_comm["id"]) is None


def test_get_comm_missing_id_returns_none(engine):
    assert engine.get_comm("org1", "nonexistent") is None


# ===========================================================================
# 4. send_comm
# ===========================================================================

def test_send_comm_sets_status(engine, draft_comm):
    result = engine.send_comm("org1", draft_comm["id"], delivered=45, failed=2)
    assert result["comm_status"] == "sent"
    assert result["sent_at"] is not None
    assert result["delivered_count"] == 45
    assert result["failed_count"] == 2


def test_send_comm_increments_counts(engine, draft_comm):
    engine.send_comm("org1", draft_comm["id"], delivered=10, failed=1)
    engine.send_comm("org1", draft_comm["id"], delivered=5, failed=0)
    updated = engine.get_comm("org1", draft_comm["id"])
    assert updated["delivered_count"] == 15
    assert updated["failed_count"] == 1


def test_send_comm_defaults_zero_counts(engine, draft_comm):
    result = engine.send_comm("org1", draft_comm["id"])
    assert result["delivered_count"] == 0
    assert result["failed_count"] == 0


def test_send_comm_not_found_raises(engine):
    with pytest.raises(KeyError):
        engine.send_comm("org1", "bad-id")


# ===========================================================================
# 5. record_acknowledgment / list_acknowledgments
# ===========================================================================

def test_record_acknowledgment_returns_record(engine, draft_comm):
    ack = engine.record_acknowledgment("org1", draft_comm["id"], {
        "acknowledger_id": "user-42",
        "notes": "Confirmed receipt",
    })
    assert ack["id"]
    assert ack["acknowledger_id"] == "user-42"
    assert ack["comm_id"] == draft_comm["id"]
    assert ack["acknowledged_at"]


def test_record_acknowledgment_requires_acknowledger_id(engine, draft_comm):
    with pytest.raises(ValueError, match="acknowledger_id"):
        engine.record_acknowledgment("org1", draft_comm["id"], {})


def test_list_acknowledgments_returns_records(engine, draft_comm):
    engine.record_acknowledgment("org1", draft_comm["id"], {"acknowledger_id": "u1"})
    engine.record_acknowledgment("org1", draft_comm["id"], {"acknowledger_id": "u2"})
    acks = engine.list_acknowledgments("org1", draft_comm["id"])
    assert len(acks) == 2


def test_list_acknowledgments_empty(engine, draft_comm):
    acks = engine.list_acknowledgments("org1", draft_comm["id"])
    assert acks == []


# ===========================================================================
# 6. create_template / list_templates
# ===========================================================================

def test_create_template_returns_record(engine):
    tmpl = engine.create_template("org1", {
        "template_name": "Initial Notification Email",
        "comm_type": "initial_notification",
        "channel": "email",
        "subject_template": "SECURITY ALERT: {incident_title}",
        "body_template": "An incident has been detected: {description}",
        "audience": "internal",
    })
    assert tmpl["id"]
    assert tmpl["template_name"] == "Initial Notification Email"
    assert tmpl["comm_type"] == "initial_notification"


def test_create_template_requires_name(engine):
    with pytest.raises(ValueError, match="template_name"):
        engine.create_template("org1", {
            "comm_type": "status_update",
            "channel": "slack",
        })


def test_create_template_invalid_comm_type(engine):
    with pytest.raises(ValueError, match="comm_type"):
        engine.create_template("org1", {
            "template_name": "T",
            "comm_type": "invalid",
            "channel": "slack",
        })


def test_create_template_invalid_channel(engine):
    with pytest.raises(ValueError, match="channel"):
        engine.create_template("org1", {
            "template_name": "T",
            "comm_type": "status_update",
            "channel": "carrier_pigeon",
        })


def test_list_templates_filter_by_comm_type(engine):
    engine.create_template("org1", {"template_name": "T1", "comm_type": "resolution", "channel": "email"})
    engine.create_template("org1", {"template_name": "T2", "comm_type": "post_mortem", "channel": "slack"})
    results = engine.list_templates("org1", comm_type="resolution")
    assert len(results) == 1
    assert results[0]["comm_type"] == "resolution"


def test_list_templates_filter_by_channel(engine):
    engine.create_template("org1", {"template_name": "T1", "comm_type": "status_update", "channel": "teams"})
    engine.create_template("org1", {"template_name": "T2", "comm_type": "status_update", "channel": "slack"})
    results = engine.list_templates("org1", channel="teams")
    assert len(results) == 1


# ===========================================================================
# 7. get_comms_stats
# ===========================================================================

def test_stats_empty_org(engine):
    stats = engine.get_comms_stats("empty_org")
    assert stats["total_comms"] == 0
    assert stats["sent_comms"] == 0
    assert stats["total_acknowledgments"] == 0
    assert stats["failed_deliveries"] == 0
    assert stats["avg_delivery_rate"] == 0.0


def test_stats_total_comms(engine, draft_comm, slack_comm):
    stats = engine.get_comms_stats("org1")
    assert stats["total_comms"] == 2


def test_stats_sent_comms(engine, draft_comm, slack_comm):
    engine.send_comm("org1", draft_comm["id"], delivered=10)
    stats = engine.get_comms_stats("org1")
    assert stats["sent_comms"] == 1


def test_stats_by_channel(engine, draft_comm, slack_comm):
    stats = engine.get_comms_stats("org1")
    assert "email" in stats["by_channel"]
    assert "slack" in stats["by_channel"]


def test_stats_by_comm_type(engine, draft_comm, slack_comm):
    stats = engine.get_comms_stats("org1")
    assert "initial_notification" in stats["by_comm_type"]
    assert "status_update" in stats["by_comm_type"]


def test_stats_failed_deliveries(engine, draft_comm):
    engine.send_comm("org1", draft_comm["id"], delivered=8, failed=3)
    stats = engine.get_comms_stats("org1")
    assert stats["failed_deliveries"] == 3


def test_stats_avg_delivery_rate(engine, draft_comm):
    engine.send_comm("org1", draft_comm["id"], delivered=9, failed=1)
    stats = engine.get_comms_stats("org1")
    assert stats["avg_delivery_rate"] == pytest.approx(0.9, abs=0.01)


def test_stats_total_acknowledgments(engine, draft_comm):
    engine.record_acknowledgment("org1", draft_comm["id"], {"acknowledger_id": "u1"})
    engine.record_acknowledgment("org1", draft_comm["id"], {"acknowledger_id": "u2"})
    stats = engine.get_comms_stats("org1")
    assert stats["total_acknowledgments"] == 2
